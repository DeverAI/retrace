"""M11 筛查工作台 — 预设筛查流程，结果可筛选、可标记、可追踪。

与 M10 Agent 不同：这里是"即点即用"的确定性筛查工具，不依赖自由任务规划。
筛查项统一模型：
  {"id","category","name","path","detail","risk","reason","state"}
    category: 可疑APP | 残留 | 指纹 | 追踪
    risk:     高 | 中 | 低 | 无
    state:    未处理 | 已标记 | 忽略

可复用 M10 agent 的只读工具（executor.call），保持轻量。
"""
import hashlib
import json
import os
import re
import shutil
import threading
import time
import uuid

from core import config, db, events, logger

SUSPICIOUS_NAMES = ("crack", "keygen", "patch", "hack", "miner", "adware",
                    "spy", "toolbar", "inject", "loader", "updater", "fake",
                    "stealer", "rat", "proxy", "junk", "optimizer", "bonzi")
_SUS_RE = re.compile(r"(?<![a-z0-9])(?:%s)(?![a-z0-9])" % "|".join(SUSPICIOUS_NAMES), re.I)
EXE_RE = re.compile(r'"([A-Za-z]:[^"]*?\.exe)"|([A-Za-z]:\\[^",]+?\.exe)', re.I)
_MAX_FP_SCAN = 40
_MAX_FP_SIZE = 512 * 1024 * 1024

# ---------------- 已知软件机器指纹文件模式 ----------------
# 每个模式定义一款软件/平台在用户目录中留下的设备唯一标识文件。
# dir 为 APPDATA/LOCALAPPDATA 下的子目录名（大小写不敏感匹配），
# file 为文件名或 glob 模式，desc 说明用途，risk 为风险等级。
FINGERPRINT_FILE_PATTERNS = [
    # Qoder (阿里云 AI IDE，基于 VSCode/Chromium)
    {"vendor": "Alibaba Cloud", "product": "Qoder", "dir": "Qoder",
     "file": "machineid", "desc": "Qoder 设备唯一标识 UUID（36 字节纯文本）",
     "risk": "高", "category": "fingerprint"},
    {"vendor": "Alibaba Cloud", "product": "Qoder", "dir": "Qoder",
     "file": "DIPS", "desc": "Qoder Device Identity Profile（36KB 二进制）",
     "risk": "高", "category": "fingerprint"},
    {"vendor": "Alibaba Cloud", "product": "Qoder", "dir": "Qoder",
     "file": "SharedStorage", "desc": "Qoder 共享持久化存储（4KB 二进制）",
     "risk": "中", "category": "fingerprint"},
    {"vendor": "Alibaba Cloud", "product": "Qoder", "dir": "Qoder",
     "file": "Local State", "desc": "Qoder Chromium 本地状态（含加密密钥元数据）",
     "risk": "中", "category": "state"},
    {"vendor": "Alibaba Cloud", "product": "Qoder", "dir": "Qoder",
     "file": "blob_storage", "desc": "Qoder 二进制大对象存储目录",
     "risk": "中", "category": "storage"},
    # Cursor (AI IDE)
    {"vendor": "Anysphere", "product": "Cursor", "dir": "Cursor",
     "file": "machineid", "desc": "Cursor 设备唯一标识 UUID",
     "risk": "高", "category": "fingerprint"},
    {"vendor": "Anysphere", "product": "Cursor", "dir": "Cursor",
     "file": "machineId", "desc": "Cursor 设备标识（大写 I 变体）",
     "risk": "高", "category": "fingerprint"},
    # Windsurf (Codeium)
    {"vendor": "Codeium", "product": "Windsurf", "dir": "Windsurf",
     "file": "machineid", "desc": "Windsurf 设备唯一标识 UUID",
     "risk": "高", "category": "fingerprint"},
    {"vendor": "Codeium", "product": "Windsurf", "dir": "Windsurf",
     "file": "machineId", "desc": "Windsurf 设备标识（大写 I 变体）",
     "risk": "高", "category": "fingerprint"},
    # Aider
    {"vendor": "Aider-AI", "product": "Aider", "dir": "aider",
     "file": "machine-id", "desc": "Aider 设备唯一标识",
     "risk": "高", "category": "fingerprint"},
    # Cline (vscode-claude)
    {"vendor": "Cline Bot", "product": "Cline", "dir": "cline",
     "file": "machineId", "desc": "Cline 设备标识",
     "risk": "高", "category": "fingerprint"},
    # GitHub Copilot for VSCode
    {"vendor": "GitHub", "product": "Copilot", "dir": "Code",
     "file": "machineid", "desc": "VSCode machineId（Copilot 身份关联）",
     "risk": "中", "category": "fingerprint"},
    {"vendor": "GitHub", "product": "Copilot", "dir": "Code",
     "file": "machineId", "desc": "VSCode machineId 变体",
     "risk": "中", "category": "fingerprint"},
    # 通用 Chromium 系浏览器/应用
    {"vendor": "Google", "product": "Chrome", "dir": "Google\\Chrome\\User Data",
     "file": "Client ID", "desc": "Chrome 客户端唯一标识（Google 账户关联）",
     "risk": "高", "category": "fingerprint"},
    {"vendor": "Google", "product": "Chrome", "dir": "Google\\Chrome\\User Data",
     "file": "Client State", "desc": "Chrome 客户端状态（含设备级标识）",
     "risk": "中", "category": "state"},
    {"vendor": "Microsoft", "product": "Edge", "dir": "Microsoft\\Edge\\User Data",
     "file": "Client ID", "desc": "Edge 客户端唯一标识",
     "risk": "高", "category": "fingerprint"},
    # JetBrains AI Assistant
    {"vendor": "JetBrains", "product": "AI Assistant", "dir": "JetBrains",
     "file": "auth-tokens.dat", "desc": "JetBrains AI 认证令牌",
     "risk": "高", "category": "token"},
    # 通用 VSCode 设备标识
    {"vendor": "Microsoft", "product": "VSCode", "dir": "Code",
     "file": "storage.json", "desc": "VSCode 全局存储（含设备 ID/遥测 ID）",
     "risk": "中", "category": "state"},
    {"vendor": "Microsoft", "product": "VSCode", "dir": "Code",
     "file": "argv.json", "desc": "VSCode 启动参数（可能含设备特征）",
     "risk": "低", "category": "state"},
    # 开发工具通用令牌/指纹
    {"vendor": "OpenAI", "product": "Codex", "dir": "codex",
     "file": "auth.json", "desc": "OpenAI Codex 认证凭证",
     "risk": "高", "category": "token"},
    {"vendor": "Anthropic", "product": "Claude Code", "dir": "claude-code",
     "file": "auth.json", "desc": "Claude Code 认证凭证",
     "risk": "高", "category": "token"},
    {"vendor": "Sourcegraph", "product": "Cody", "dir": "cody",
     "file": "auth.json", "desc": "Cody AI 认证凭证",
     "risk": "高", "category": "token"},
    # Trae (字节跳动 AI IDE)
    {"vendor": "ByteDance", "product": "Trae", "dir": "Trae",
     "file": "machineid", "desc": "Trae 设备唯一标识 UUID",
     "risk": "高", "category": "fingerprint"},
    {"vendor": "ByteDance", "product": "Trae CN", "dir": "TraeCN",
     "file": "machineid", "desc": "Trae CN 设备唯一标识 UUID",
     "risk": "高", "category": "fingerprint"},
    # Zed (AI 编辑器)
    {"vendor": "Zed Industries", "product": "Zed", "dir": "Zed",
     "file": "device-id", "desc": "Zed 设备标识",
     "risk": "高", "category": "fingerprint"},
    # Augment Code
    {"vendor": "Augment Code", "product": "Augment", "dir": "augment",
     "file": "auth.json", "desc": "Augment Code 认证凭证",
     "risk": "高", "category": "token"},
    # Amazon Q Developer
    {"vendor": "Amazon", "product": "Q Developer", "dir": "Amazon Q",
     "file": "auth.json", "desc": "Amazon Q 认证凭证",
     "risk": "高", "category": "token"},
    # Tabnine
    {"vendor": "Tabnine", "product": "Tabnine", "dir": "tabnine",
     "file": "machine-id", "desc": "Tabnine 设备标识",
     "risk": "高", "category": "fingerprint"},
    # Roo Code
    {"vendor": "Roo Code", "product": "Roo", "dir": "roo",
     "file": "machineId", "desc": "Roo Code 设备标识",
     "risk": "高", "category": "fingerprint"},
    # 通用 Windows 遥测/身份
    {"vendor": "Microsoft", "product": "Windows", "dir": "Microsoft\\Windows\\DeviceMetadataCache",
     "file": "device.dat", "desc": "Windows 设备元数据缓存（设备身份）",
     "risk": "低", "category": "state"},
    # Unity / 游戏引擎类（常见指纹）
    {"vendor": "Unity", "product": "Unity", "dir": "Unity",
     "file": "machineId.dat", "desc": "Unity 编辑器机器标识",
     "risk": "高", "category": "fingerprint"},
    # 通用浏览器指纹扩展存储
    {"vendor": "Mozilla", "product": "Firefox", "dir": "Mozilla\\Firefox",
     "file": "profiles.ini", "desc": "Firefox 配置索引（含 profile 路径）",
     "risk": "低", "category": "state"},
]


def _risk_label(score):
    if score >= 0.7:
        return "高"
    if score >= 0.4:
        return "中"
    if score >= 0.2:
        return "低"
    return "无"


def _mk(items):
    for i, it in enumerate(items):
        it.setdefault("id", "%s-%d" % (it.get("category", "x"), i + 1))
        it.setdefault("state", "未处理")
    return items


def _finish(items, category):
    items = _mk(items)
    s = {"total": len(items), "high": 0, "med": 0, "low": 0, "none": 0}
    for it in items:
        if it.get("risk") == "高":
            s["high"] += 1
        elif it.get("risk") == "中":
            s["med"] += 1
        elif it.get("risk") == "低":
            s["low"] += 1
        else:
            s["none"] += 1
    items.sort(key=lambda x: {"高": 0, "中": 1, "低": 2, "无": 3}.get(x.get("risk"), 3))
    db.audit("screen.scan", "category=%s total=%d high=%d" % (category, len(items), s["high"]))
    return {"category": category, "summary": s, "items": items}


def _extract_exe(data):
    m = EXE_RE.search(data or "")
    if m:
        return (m.group(1) or m.group(2) or "").strip()
    return ""


def _file_stats(path):
    """单次流式计算 sha256 与熵，避免重复读文件。"""
    from collections import Counter
    from math import log2
    h = hashlib.sha256()
    cnt = Counter()
    total = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
            cnt.update(b)
            total += len(b)
    ent = 0.0
    if total:
        ent = -sum((c / total) * log2(c / total) for c in cnt.values())
    return h.hexdigest(), ent


# ---------------- 筛查流程 ----------------
def scan_suspicious_apps():
    """扫描可疑 APP：自启动点位 + 可疑命名 + 路径缺失（残留）判定。"""
    from modules import regscan
    items, seen = [], set()
    for root in ("HKLM", "HKCU"):
        try:
            points = regscan.autostart_points(root=root)
        except Exception as e:
            logger.record_err("screen.autostart.%s" % root, e)
            continue
        for it in points:
            key = "%s|%s" % (it.get("key"), it.get("name"))
            if key in seen:
                continue
            seen.add(key)
            data = it.get("data") or ""
            exe = _extract_exe(data)
            risk, reason = 0.2, []
            if it.get("risky"):
                risk += 0.4
                reason.append("风险词")
            base = os.path.basename(exe).lower() if exe else ""
            if base and _SUS_RE.search(base):
                risk += 0.3
                reason.append("可疑命名")
            if exe:
                if not os.path.exists(os.path.expandvars(exe)):
                    risk += 0.3
                    reason.append("路径不存在(残留)")
            if not exe:
                reason.append("非exe/无路径")
            items.append({
                "category": "可疑APP", "name": it.get("name") or it.get("point"),
                "path": exe, "detail": "%s @ %s | %s" % (
                    it.get("point"), it.get("key"), (data or "")[:120]),
                "risk": _risk_label(risk), "reason": ";".join(reason) or "常规",
            })
    return _finish(items, "可疑APP")


def scan_leftover(install_dir):
    """残留筛查：主 exe 缺失 / 空目录 / 注册表悬空引用。"""
    if not install_dir or not os.path.isdir(install_dir):
        return {"category": "残留", "summary": {"total": 0, "high": 0, "med": 0,
                "low": 0, "none": 0}, "items": [], "error": "目录不存在"}
    base = os.path.abspath(install_dir)
    items = []
    exes = [f for _, _, fs in os.walk(base)
            for f in fs if f.lower().endswith(".exe")]
    if not exes:
        items.append({"category": "残留", "name": os.path.basename(base),
                      "path": base, "detail": "安装目录存在但未找到主 exe，疑似卸载残留",
                      "risk": "高", "reason": "主exe缺失", "state": "未处理"})
    for root, dirs, files in os.walk(base):
        raw_dirs = list(dirs)
        dirs[:] = [d for d in raw_dirs if not d.startswith(".")]
        if not files and not raw_dirs and os.path.abspath(root) != base:
            items.append({"category": "残留", "name": os.path.basename(root),
                          "path": root, "detail": "空目录（卸载残留）",
                          "risk": "低", "reason": "空目录", "state": "未处理"})
    # 注册表自启动指向不存在的路径
    try:
        from modules import regscan
        for root_r in ("HKLM", "HKCU"):
            for it in regscan.autostart_points(root=root_r):
                data = it.get("data") or ""
                exe = _extract_exe(data)
                if exe and not os.path.exists(os.path.expandvars(exe)):
                    items.append({"category": "残留", "name": it.get("name"),
                                  "path": exe,
                                  "detail": "自启动指向不存在的文件 %s (%s @ %s)" % (
                                      exe, it.get("point"), it.get("key")),
                                  "risk": "中", "reason": "悬空自启动", "state": "未处理"})
    except Exception as e:
        logger.record_err("screen.leftover.reg", e)
    return _finish(items, "残留")


def scan_fingerprints(base_dir):
    """目录指纹扫描：exe/dll 的哈希/熵/大小，可疑命名与高熵提示。"""
    if not base_dir or not os.path.isdir(base_dir):
        return {"category": "指纹", "summary": {"total": 0, "high": 0, "med": 0,
                "low": 0, "none": 0}, "items": [], "error": "目录不存在"}
    items = []
    base = os.path.abspath(base_dir)
    for root, dirs, files in os.walk(base):
        depth = root[len(base):].count(os.sep)
        if depth >= 6:
            dirs[:] = []
        else:
            dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            if not f.lower().endswith((".exe", ".dll")):
                continue
            p = os.path.join(root, f)
            try:
                if os.path.getsize(p) > _MAX_FP_SIZE:
                    continue
                sha, ent_raw = _file_stats(p)
                ent = round(ent_raw, 3)
            except OSError:
                continue
            fname = f.lower()
            risk = 0.2
            reason = []
            if ent > 7.5:
                risk += 0.3
                reason.append("高熵")
            if _SUS_RE.search(fname):
                risk += 0.3
                reason.append("可疑命名")
            items.append({
                "category": "指纹", "name": f, "path": p,
                "detail": "sha256:%s 大小:%d 熵:%s" % (sha[:16], os.path.getsize(p), ent),
                "risk": _risk_label(risk), "reason": ";".join(reason) or "常规",
            })
            if len(items) >= _MAX_FP_SCAN:
                break
        if len(items) >= _MAX_FP_SCAN:
            break
    return _finish(items, "指纹")


def check_file(path):
    """单文件检查：指纹 + 反编译摘要（若有）。"""
    if not path or not os.path.isfile(path):
        return {"category": "指纹", "summary": {"total": 0, "high": 0, "med": 0,
                "low": 0, "none": 0}, "items": [], "error": "文件不存在"}
    from modules.agent import executor
    r = executor.call("fingerprint", {"path": os.path.abspath(path)})
    if not r.get("ok"):
        return {"category": "指纹", "summary": {"total": 0, "high": 0, "med": 0,
                "low": 0, "none": 0}, "items": [], "error": r.get("error", "指纹检查失败")}
    data = r.get("data") or {}
    if not isinstance(data, dict) or data.get("error"):
        return {"category": "指纹", "summary": {"total": 0, "high": 0, "med": 0,
                "low": 0, "none": 0}, "items": [],
                "error": data.get("error", "指纹数据无效")}
    risk, reason = 0.2, []
    if data.get("entropy", 0) > 7.5:
        risk += 0.3
        reason.append("高熵")
    score = data.get("score") or {}
    if score.get("high"):
        risk += 0.4
        reason.append("高危调用x%d" % score["high"])
    base = os.path.basename(path).lower()
    if _SUS_RE.search(base):
        risk += 0.3
        reason.append("可疑命名")
    detail = "sha256:%s 大小:%s 熵:%s" % (data.get("sha256", "?")[:16],
                                          data.get("size", "?"), data.get("entropy", "?"))
    if data.get("calls"):
        detail += " | 调用: " + ", ".join("%s(%.1f)" % (c.get("name"), c.get("danger"))
                                          for c in data["calls"][:5])
    if data.get("strings"):
        detail += " | 串: " + "; ".join(data["strings"][:5])
    items = [{"category": "指纹", "name": os.path.basename(path), "path": os.path.abspath(path),
              "detail": detail, "risk": _risk_label(risk), "reason": ";".join(reason) or "常规"}]
    return _finish(items, "指纹")


def track_app(name, exe="", pid=None):
    """应用追踪：添加目标 → 启动观察 → 返回快照与时间线。"""
    from modules import watcher
    if not name:
        return {"error": "缺少目标名", "items": [], "summary": {}}
    r = watcher.add_target(name, pid, exe or None)
    ok = bool(isinstance(r, (tuple, list)) and r[0])
    if not ok:
        return {"error": str(r), "items": [], "summary": {}}
    watcher.start()
    snap = watcher.snapshot_target(name) or {}
    tl = watcher.timeline_entries(limit=30)
    items = [
        {"category": "追踪", "name": name, "path": exe or "",
         "detail": "目标已登记: %s | 快照: %s" % (name, json_d(snap)[:300]),
         "risk": "无", "reason": "追踪", "state": "未处理"},
    ]
    for e in tl[-25:]:
        items.append({"category": "追踪", "name": name,
                      "detail": "%s | %s" % (e.get("ts", ""), e.get("type", "")),
                      "risk": "无", "reason": "事件", "state": "未处理"})
    return _finish(items, "追踪")


def json_d(obj):
    import json
    try:
        return json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        return str(obj)


# ---------------- 留样扫描与批量清理 ----------------
_REG_ROOTS = ("HKLM", "HKCU", "HKU", "HKCR")
# 清理仅允许 HKLM/HKCU；HKCR 是合并视图、HKU 含所有用户，均确定性拒绝
_CLEANABLE_ROOTS = ("HKLM", "HKCU")


def _winroot(root_name):
    import winreg
    return {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKU": winreg.HKEY_USERS,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
    }[root_name]


def _protected_fs_paths():
    """返回绝对不可清理的系统/项目目录（黑名单）。"""
    roots = []
    for env in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)"):
        p = os.environ.get(env)
        if p and os.path.isdir(p):
            roots.append(p)
    roots.append(config.ROOT)
    return roots


def _is_protected_fs_path(p):
    p = os.path.normcase(os.path.abspath(p))
    for root in _protected_fs_paths():
        r = os.path.normcase(os.path.abspath(root))
        if p == r or p.startswith(r + "\\"):
            return True
    return False


def _safe_json_value(v):
    """把任意注册表值转成可 JSON 序列化的形式。"""
    if isinstance(v, bytes):
        return {"__bytes_hex__": v.hex()}
    try:
        json.dumps(v)
        return v
    except (TypeError, ValueError):
        return str(v)


_cleanup_lock = threading.Lock()


def _dedup_key(it):
    """去重键：type+target，避免卸载参考项与清理项因共用 target 而互相误删。"""
    return "%s|%s" % (it.get("type", ""), it.get("target", ""))


def _dir_has_no_exe(loc, max_depth=4):
    """深度受限检查目录是否不含 exe（残留判定），找到第一个 exe 即早停。"""
    base = os.path.abspath(loc)
    try:
        for root, dirs, files in os.walk(base):
            depth = root[len(base):].count(os.sep)
            if depth > max_depth:
                dirs[:] = []
                continue
            if any(f.lower().endswith(".exe") for f in files):
                return False
        return True
    except OSError:
        return False


def _user_scan_dirs():
    """扫描根目录：环境变量 APPDATA/LOCALAPPDATA/PROGRAMDATA + 用户目录枚举回退。

    环境变量可能指向 systemprofile（如以 SYSTEM/服务上下文运行或沙箱注入环境），
    此时仅靠环境变量会漏掉真实用户目录。因此追加 C:\\Users\\<用户>\\AppData\\Roaming 与
    \\AppData\\Local 枚举（跳过 Public / Default / 系统账户），保证管理员模式下也能
    扫到所有用户残留。
    """
    dirs = []

    def _skip_system_profile(p):
        """排除 C:\\Windows\\system32\\config 下的系统账户 profile（无真实用户数据）。"""
        norm = os.path.normcase(os.path.abspath(p))
        return norm.startswith(os.path.normcase(
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                         "system32", "config")))
    for env in ("APPDATA", "LOCALAPPDATA", "PROGRAMDATA"):
        p = os.environ.get(env)
        if p and os.path.isdir(p) and not _skip_system_profile(p):
            dirs.append(os.path.abspath(p))
    users_root = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "Users")
    skip = {"public", "default", "default user", "all users", "defaultuser0"}
    try:
        for name in os.listdir(users_root):
            if name.lower() in skip:
                continue
            prof = os.path.join(users_root, name)
            if not os.path.isdir(prof):
                continue
            for sub in ("AppData\\Roaming", "AppData\\Local"):
                p = os.path.join(prof, sub)
                if os.path.isdir(p):
                    absp = os.path.abspath(p)
                    if absp not in dirs:
                        dirs.append(absp)
    except OSError:
        pass
    return dirs


_UNINSTALL_PATHS = (
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
)


def _walk_fs(base, kw, items, seen, depth, max_depth, counter, max_items=300):
    """递归下钻扫描；顶层子目录始终下钻，深层仅下钻命中关键词的目录。"""
    if depth > max_depth or counter[0] >= max_items:
        return
    try:
        entries = os.listdir(base)[:200]
    except OSError:
        return
    for name in entries:
        if counter[0] >= max_items:
            return
        full = os.path.join(base, name)
        if full in seen:
            continue
        seen.add(full)
        matched = kw in name.lower()
        try:
            is_dir = os.path.isdir(full)
        except OSError:
            continue
        if matched:
            items.append({
                "category": "留样", "name": name, "path": full,
                "type": "dir" if is_dir else "file", "target": full,
                "detail": "匹配关键词的%s: %s" % ("目录" if is_dir else "文件", full),
                "risk": "中" if is_dir else "低",
                "reason": "目录留样" if is_dir else "文件留样",
                "state": "未处理"})
            counter[0] += 1
        if is_dir and depth < max_depth and (depth == 0 or matched):
            _walk_fs(full, kw, items, seen, depth + 1, max_depth, counter, max_items)


def _scan_fs_traces(keyword, install_dir, install_locations=None):
    """文件系统留样扫描：精确根（卸载安装路径/install_dir）深扫，用户目录浅扫。"""
    kw = (keyword or "").strip().lower()
    if not kw:
        return []
    deep_bases = []
    for loc in (install_locations or []):
        if loc and os.path.isdir(loc):
            deep_bases.append(os.path.abspath(loc))
    if install_dir and os.path.isdir(install_dir):
        deep_bases.append(os.path.abspath(install_dir))
    items, seen, counter = [], set(), [0]
    for base in deep_bases:
        _walk_fs(base, kw, items, seen, 0, 3, counter)
    for base in _user_scan_dirs():
        _walk_fs(base, kw, items, seen, 0, 2, counter)
    return items


def _scan_uninstall_traces(keyword):
    """卸载信息反查：读 Uninstall 键精确定位；卸载条目在但主 exe 缺失判为残留。"""
    import winreg
    kw = (keyword or "").lower()
    items, seen = [], set()
    for root_name, path in _UNINSTALL_PATHS:
        try:
            with winreg.OpenKey(_winroot(root_name), path, 0, winreg.KEY_READ) as uninst_key:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(uninst_key, i)
                    except OSError:
                        break
                    i += 1
                    try:
                        with winreg.OpenKey(uninst_key, sub, 0, winreg.KEY_READ) as k:
                            def _get(name):
                                try:
                                    v, _ = winreg.QueryValueEx(k, name)
                                    return str(v).strip()
                                except OSError:
                                    return ""
                            disp = _get("DisplayName")
                            loc = _get("InstallLocation")
                            pub = _get("Publisher")
                            uninst = _get("UninstallString")
                    except OSError:
                        continue
                    hay = (disp + " " + pub + " " + loc).lower()
                    if kw and kw not in hay:
                        continue
                    # 残留判定：InstallLocation 存在但无主 exe
                    residual = False
                    if loc and os.path.isdir(loc):
                        residual = _dir_has_no_exe(loc)
                    full_key = "%s\\%s\\%s" % (root_name, path, sub)
                    if full_key in seen:
                        continue
                    seen.add(full_key)
                    # 卸载条目本身（信息项，供参考定位）
                    items.append({
                        "category": "留样", "name": disp or sub,
                        "path": full_key, "type": "uninstall_entry", "target": full_key,
                        "detail": "卸载条目: %s | 安装路径: %s | 发布者: %s%s" % (
                            disp or sub, loc or "(无)", pub or "(无)",
                            " | 残留(主exe缺失)" if residual else ""),
                        "risk": "高" if residual else "中",
                        "reason": "卸载残留" if residual else "卸载条目",
                        "install_location": loc, "residual": residual,
                        "state": "未处理"})
                    # 残留：额外产出可清理的卸载子键 + 安装目录
                    if residual:
                        items.append({
                            "category": "留样", "name": "卸载条目(%s)" % (disp or sub),
                            "path": full_key, "type": "registry_key", "target": full_key,
                            "detail": "残留卸载条目（主 exe 缺失）: %s" % full_key,
                            "risk": "高", "reason": "卸载残留", "state": "未处理"})
                        if loc and os.path.isdir(loc):
                            items.append({
                                "category": "留样", "name": "安装目录(%s)" % (disp or sub),
                                "path": loc, "type": "dir", "target": loc,
                                "detail": "残留安装目录（主 exe 缺失）: %s" % loc,
                                "risk": "高", "reason": "安装目录残留", "state": "未处理"})
        except OSError:
            continue
    return items


def scan_software_traces(keyword, install_dir=""):
    """留样扫描：注册表全树 + 自启动 + 卸载反查 + 文件系统深度下钻。"""
    keyword = (keyword or "").strip()
    if not keyword:
        return {"category": "留样", "summary": {"total": 0, "high": 0, "med": 0,
                "low": 0, "none": 0}, "items": [], "error": "请提供软件关键词（如 Qoder）"}
    from modules import regscan
    from modules import privacy_guard
    items, seen = [], set()
    install_locations = []

    # 0) 卸载反查（优先，拿到精确 InstallLocation）
    try:
        uninst = _scan_uninstall_traces(keyword)
        install_locations = [it["install_location"] for it in uninst
                             if it.get("install_location")]
        for it in uninst:
            dk = _dedup_key(it)
            if it.get("target") and dk not in seen:
                seen.add(dk)
                items.append(it)
    except Exception as e:
        logger.record_err("screen.traces.uninstall", e)

    # 1) 注册表全树搜索
    try:
        res = regscan.search(keyword, root="ALL", mode="contains",
                             max_hits=300, include_values=True, include_data=True)
        for hit in res.get("hits", []):
            key = hit.get("key", "")
            name = hit.get("name", "")
            if hit.get("kind") == "value" and name:
                target = "%s|%s" % (key, name)
                itype = "registry_value"
            else:
                target = key
                itype = "registry_key"
            dk = "%s|%s" % (itype, target)
            if dk in seen:
                continue
            seen.add(dk)
            sensitive = privacy_guard.match_sensitive(key)
            items.append({
                "category": "留样", "name": name or key, "path": key,
                "type": itype, "target": target,
                "detail": "注册表%s: %s | 数据: %s" % (
                    "值" if itype == "registry_value" else "键",
                    key, (hit.get("data") or "")[:120]),
                "risk": "高" if sensitive else ("中" if itype == "registry_value" else "低"),
                "reason": "敏感系统身份" if sensitive else "注册表留样",
                "state": "未处理"})
    except Exception as e:
        logger.record_err("screen.traces.reg", e)

    # 2) 自启动点位
    try:
        for root_r in ("HKLM", "HKCU"):
            for it in regscan.autostart_points(root=root_r):
                hay = ((it.get("data") or "") + " " + (it.get("name") or "")).lower()
                if keyword.lower() not in hay:
                    continue
                key = it.get("key", "")
                target = "%s|%s" % (key, it.get("name", ""))
                dk = "registry_value|%s" % target
                if dk in seen:
                    continue
                seen.add(dk)
                items.append({
                    "category": "留样", "name": it.get("name"),
                    "path": key, "type": "registry_value", "target": target,
                    "detail": "自启动: %s @ %s | %s" % (
                        it.get("point"), key, (it.get("data") or "")[:120]),
                    "risk": "高" if it.get("risky") else "中", "reason": "自启动留样",
                    "state": "未处理"})
    except Exception as e:
        logger.record_err("screen.traces.autostart", e)

    # 3) 文件系统（精确根深扫 + 用户目录浅扫）
    try:
        fs = _scan_fs_traces(keyword, install_dir, install_locations)
        for it in fs:
            dk = _dedup_key(it)
            if it.get("target") and dk not in seen:
                seen.add(dk)
                items.append(it)
    except Exception as e:
        logger.record_err("screen.traces.fs", e)

    return _finish(items, "留样")


def _parse_reg_target(target):
    """解析注册表目标，返回 (root_name, subkey, value_name) 或 None。"""
    target = (target or "").strip()
    path, _, value_name = target.partition("|")
    root_name, _, subkey = path.partition("\\")
    root_name = root_name.upper()
    if root_name not in _REG_ROOTS:
        return None
    subkey = subkey.lstrip("\\")
    return root_name, subkey, value_name


def _backup_reg_value(root_name, subkey, value_name, qdir):
    """备份注册表值。返回 (True, 文件名) / (False, None)=已不存在 / 抛异常=备份失败。"""
    import winreg
    try:
        with winreg.OpenKey(_winroot(root_name), subkey, 0, winreg.KEY_READ) as key:
            data, vtype = winreg.QueryValueEx(key, value_name)
    except FileNotFoundError:
        return (False, None)  # 值已不存在，视为已清理
    payload = {"root": root_name, "subkey": subkey, "value_name": value_name,
               "type": vtype, "data": _safe_json_value(data)}
    fname = "reg_value_%s.json" % uuid.uuid4().hex[:8]
    with open(os.path.join(qdir, fname), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, default=str)
    return (True, fname)


def _backup_reg_key(root_name, subkey, qdir):
    """递归备份注册表键。返回 (True, 文件名) / (False, None)=已不存在 / 抛异常=备份失败。"""
    import winreg

    def walk(key_path, depth=0):
        if depth > 12:
            raise RuntimeError("注册表键过深，中止备份")
        node = {}
        try:
            with winreg.OpenKey(_winroot(root_name), key_path, 0, winreg.KEY_READ) as key:
                vals, i = {}, 0
                while True:
                    try:
                        vname, vdata, vtype = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    vals[vname] = {"type": vtype, "data": _safe_json_value(vdata)}
                    i += 1
                node["values"] = vals
                subs, i = {}, 0
                while True:
                    try:
                        sname = winreg.EnumKey(key, i)
                    except OSError:
                        break
                    subs[sname] = walk(key_path + "\\" + sname, depth + 1)
                    i += 1
                node["subkeys"] = subs
        except OSError:
            return None
        return node

    tree = walk(subkey)
    if tree is None:
        return (False, None)
    payload = {"root": root_name, "subkey": subkey, "tree": tree}
    fname = "reg_key_%s.json" % uuid.uuid4().hex[:8]
    with open(os.path.join(qdir, fname), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, default=str)
    return (True, fname)


def _delete_reg_key_recursive(root_name, subkey):
    import winreg
    if not subkey:
        return False  # 拒绝删根键
    try:
        with winreg.OpenKey(_winroot(root_name), subkey, 0, winreg.KEY_ALL_ACCESS) as key:
            while True:
                try:
                    sname = winreg.EnumKey(key, 0)
                except OSError:
                    break
                _delete_reg_key_recursive(root_name, subkey + "\\" + sname)
        winreg.DeleteKey(_winroot(root_name), subkey)
        return True
    except FileNotFoundError:
        return True  # 已不存在
    except Exception as e:
        logger.record_err("screen.cleanup.delkey", e)
        return False


def _quarantine_fs(path, qroot, manifest):
    p = os.path.abspath(path)
    if _is_protected_fs_path(p):
        return False  # 系统/项目目录拒绝搬移
    base = os.path.basename(p)
    if not base:
        return False  # 盘符根/空 basename 拒绝
    if not os.path.exists(p):
        return True  # 已不存在，视为已清理
    is_dir = os.path.isdir(p)
    dest = os.path.join(qroot, base)
    if os.path.exists(dest):
        dest = dest + "_" + uuid.uuid4().hex[:6]
    shutil.move(p, dest)
    manifest.append({"type": "dir" if is_dir else "file", "target": p, "backup": dest})
    return True


def _cleanup_reg_value(target, qroot, manifest):
    import winreg
    parsed = _parse_reg_target(target)
    if not parsed:
        return False
    root_name, subkey, value_name = parsed
    if not value_name:
        return False
    try:
        backed, fname = _backup_reg_value(root_name, subkey, value_name, qroot)
    except Exception as e:
        logger.record_err("screen.cleanup.backup.regval", e)
        return False  # 备份失败，不删除
    if backed is False:
        return True  # 目标已不存在，视为已清理
    # 备份已生成，先记 manifest（即使删除失败，备份仍可恢复）
    manifest.append({"type": "registry_value", "target": target,
                     "backup": os.path.join(qroot, fname)})
    try:
        with winreg.OpenKey(_winroot(root_name), subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, value_name)
        return True
    except FileNotFoundError:
        return True  # 已不存在
    except Exception as e:
        logger.record_err("screen.cleanup.delval", e)
        return False


def _cleanup_reg_key(target, qroot, manifest):
    parsed = _parse_reg_target(target)
    if not parsed:
        return False
    root_name, subkey, value_name = parsed
    if value_name or not subkey:
        return False  # 值目标或根键，均不按键删除处理
    try:
        backed, fname = _backup_reg_key(root_name, subkey, qroot)
    except Exception as e:
        logger.record_err("screen.cleanup.backup.regkey", e)
        return False  # 备份失败，不删除
    if backed is False:
        return True  # 目标已不存在，视为已清理
    # 备份已生成，先记 manifest（即使删除部分失败，备份仍可恢复）
    manifest.append({"type": "registry_key", "target": target,
                     "backup": os.path.join(qroot, fname)})
    return _delete_reg_key_recursive(root_name, subkey)


def _classify_clean(it):
    """判定单个项可否清理。返回 (True, "") 或 (False, 拒绝原因)。预览与清理共用。"""
    from modules import privacy_guard
    if not isinstance(it, dict):
        return (False, "非法项类型")
    target = (it.get("target") or it.get("path") or "").strip()
    itype = it.get("type", "")
    if privacy_guard.match_sensitive(target):
        return (False, "系统身份/敏感项")
    if itype in ("file", "dir") and _is_protected_fs_path(target):
        return (False, "系统/项目目录")
    if itype.startswith("registry"):
        parsed = _parse_reg_target(target)
        if not parsed:
            return (False, "注册表目标解析失败")
        if parsed[0] not in _CLEANABLE_ROOTS:
            return (False, "HKCR/HKU 合并视图")
        full = privacy_guard._normalize_registry(parsed[0] + "\\" + parsed[1])
        if any(full.startswith(p) for p in privacy_guard._REGISTRY_DENY) or \
                any(seg in full for seg in privacy_guard._REGISTRY_DENY_SEGMENTS):
            return (False, "共享/系统核心范围")
        if itype == "registry_value" and not parsed[2]:
            return (False, "注册表值缺少值名")
        if itype == "registry_key" and not parsed[1]:
            return (False, "拒绝清理注册表根键")
    if itype == "uninstall_entry":
        return (False, "卸载条目（非残留，仅参考）")
    if itype not in ("file", "dir", "registry_value", "registry_key"):
        return (False, "未知类型")
    return (True, "")


def preview_cleanup(items):
    """清理前预览（纯只读）：列出将清理 / 将拒绝的项，不执行、不建还原点。"""
    items = items or []
    will_clean, will_deny = [], []
    for it in items:
        target = (it.get("target") or it.get("path") or "").strip() if isinstance(it, dict) else ""
        name = it.get("name", "") if isinstance(it, dict) else ""
        itype = it.get("type", "") if isinstance(it, dict) else ""
        can, reason = _classify_clean(it)
        if can:
            will_clean.append({"target": target, "name": name, "type": itype,
                               "risk": it.get("risk", "")})
        else:
            will_deny.append({"target": target, "name": name, "reason": reason})
    return {"will_clean": will_clean, "will_deny": will_deny,
            "clean_count": len(will_clean), "deny_count": len(will_deny)}


def cleanup_traces(items, reason=""):
    """批量清理留样项。强制先创建系统还原点，逐项备份后清理，写 manifest。"""
    items = items or []
    if not items:
        return {"ok": False, "error": "没有勾选要清理的项"}
    reason = (reason or "").strip()
    if len(reason) < 12:
        return {"ok": False, "error": "必须说明至少 12 字的清理原因（目的、对象、必要性）"}

    if not _cleanup_lock.acquire(blocking=False):
        return {"ok": False, "error": "已有清理进行中，请稍后再试"}

    try:
        from modules import privacy_guard
        # 1) 强制系统还原点（硬门禁，失败即中止，绝不裸删）
        try:
            restore = privacy_guard._create_restore_point()
        except Exception as e:
            logger.record_err("screen.cleanup.restore", e)
            return {"ok": False, "error": "系统还原点创建失败，已中止清理: %s" % e}

        # 2) 逐项清理
        qroot = os.path.join(config.ROOT, "backups", "quarantine",
                             time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6])
        os.makedirs(qroot, exist_ok=True)
        manifest, results, denied = [], [], []
        for it in items:
            if not isinstance(it, dict):
                results.append({"target": "", "ok": False, "error": "非法项类型"})
                continue
            target = (it.get("target") or it.get("path") or "").strip()
            itype = it.get("type", "")
            name = it.get("name", "")
            can, reason = _classify_clean(it)
            if not can:
                denied.append({"target": target, "name": name, "reason": reason})
                results.append({"target": target, "ok": False, "error": reason + "，已跳过"})
                continue
            try:
                if itype in ("file", "dir"):
                    ok = _quarantine_fs(target, qroot, manifest)
                elif itype == "registry_value":
                    ok = _cleanup_reg_value(target, qroot, manifest)
                elif itype == "registry_key":
                    ok = _cleanup_reg_key(target, qroot, manifest)
                else:
                    ok = False
                if ok:
                    error = None
                elif itype in ("file", "dir"):
                    # _quarantine_fs 拒绝系统/项目目录、盘符根等，消息如实说明
                    error = "清理失败（目标受保护或无法搬移）"
                else:
                    error = "清理失败（未知类型 %s）" % itype
                results.append({"target": target, "ok": ok, "error": error})
            except Exception as e:
                logger.record_err("screen.cleanup.item", e)
                results.append({"target": target, "ok": False, "error": str(e)})

        # 3) 写 manifest（供一键恢复）
        manifest_payload = {"created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "reason": reason, "items": manifest}
        with open(os.path.join(qroot, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest_payload, f, ensure_ascii=False, default=str)

        ok_count = sum(1 for r in results if r.get("ok"))
        db.audit("screen.cleanup", "items=%d ok=%d denied=%d reason=%s" % (
            len(items), ok_count, len(denied), reason[:120]))
        return {"ok": True, "restore_point": restore, "total": len(items),
                "ok_count": ok_count, "denied": denied, "results": results,
                "quarantine": qroot, "manifest": manifest_payload}
    finally:
        _cleanup_lock.release()


# ---------------- 一键恢复 ----------------
def _from_json_value(v):
    if isinstance(v, dict) and "__bytes_hex__" in v:
        return bytes.fromhex(v["__bytes_hex__"])
    return v


def _restore_guard(root_name, subkey):
    """恢复注册表前的安全校验：仅允许 HKLM/HKCU 且非 deny 范围。"""
    from modules import privacy_guard
    root_name = str(root_name or "").upper()
    subkey = str(subkey or "").lstrip("\\")
    if root_name not in _CLEANABLE_ROOTS or not subkey:
        return False
    full = privacy_guard._normalize_registry(root_name + "\\" + subkey)
    if any(full.startswith(p) for p in privacy_guard._REGISTRY_DENY) or \
            any(seg in full for seg in privacy_guard._REGISTRY_DENY_SEGMENTS) or \
            privacy_guard.match_sensitive(full):
        return False
    return True


def _restore_fs(target, backup):
    if not os.path.exists(backup):
        return False
    if _is_protected_fs_path(target):
        return False  # 拒绝恢复到系统/项目目录
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    if os.path.exists(target):
        target = target + "_restored_" + uuid.uuid4().hex[:6]
    shutil.move(backup, target)
    return True


def _restore_reg_value(target, backup):
    import winreg
    if not os.path.isfile(backup):
        return False
    with open(backup, "r", encoding="utf-8") as f:
        payload = json.load(f)
    root_name, subkey = payload["root"], payload["subkey"]
    if not _restore_guard(root_name, subkey):
        return False  # 越界拒绝
    value_name, vtype = payload["value_name"], payload["type"]
    data = _from_json_value(payload["data"])
    with winreg.CreateKeyEx(_winroot(root_name), subkey, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, value_name, 0, vtype, data)
    return True


def _restore_reg_key(target, backup):
    import winreg
    if not os.path.isfile(backup):
        return False
    with open(backup, "r", encoding="utf-8") as f:
        payload = json.load(f)
    root_name, subkey, tree = payload["root"], payload["subkey"], payload["tree"]
    if not _restore_guard(root_name, subkey):
        return False  # 越界拒绝

    def create(key_path, node, depth=0):
        if depth > 12:
            raise RuntimeError("恢复键过深，中止")
        with winreg.CreateKeyEx(_winroot(root_name), key_path, 0, winreg.KEY_SET_VALUE):
            pass
        for vname, vinfo in (node.get("values") or {}).items():
            with winreg.OpenKey(_winroot(root_name), key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, vname, 0, vinfo["type"], _from_json_value(vinfo["data"]))
        for sname, snode in (node.get("subkeys") or {}).items():
            create(key_path + "\\" + sname, snode, depth + 1)

    create(subkey, tree)
    return True


def restore_traces(quarantine_dir):
    """从 quarantine 一键还原被清理的项（依据 manifest.json）。"""
    if not _cleanup_lock.acquire(blocking=False):
        return {"ok": False, "error": "已有清理/恢复进行中，请稍后再试"}
    try:
        qdir = os.path.normcase(os.path.realpath(os.path.abspath(quarantine_dir)))
        qbase = os.path.normcase(os.path.realpath(os.path.abspath(
            os.path.join(config.ROOT, "backups", "quarantine"))))
        if not (qdir == qbase or qdir.startswith(qbase + "\\")):
            return {"ok": False, "error": "仅允许还原 backups/quarantine 内的备份目录"}
        manifest_path = os.path.join(qdir, "manifest.json")
        if not os.path.isfile(manifest_path):
            return {"ok": False, "error": "该目录无 manifest.json，无法还原"}
        with open(manifest_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        entries = payload.get("items", [])
        results = []
        for e in entries:
            if not isinstance(e, dict):
                results.append({"target": "", "ok": False, "error": "非法项"})
                continue
            etype = e.get("type", "")
            target = e.get("target", "")
            backup = e.get("backup", "")
            # 备份文件必须位于 qdir 内（realpath 防符号链接逃逸）
            if not backup:
                results.append({"target": target, "ok": False, "error": "备份路径缺失"})
                continue
            backup_real = os.path.normcase(os.path.realpath(os.path.abspath(backup)))
            if not backup_real.startswith(qdir + "\\"):
                results.append({"target": target, "ok": False, "error": "备份路径越界，已跳过"})
                continue
            try:
                if etype in ("file", "dir"):
                    ok = _restore_fs(target, backup)
                elif etype == "registry_value":
                    ok = _restore_reg_value(target, backup)
                elif etype == "registry_key":
                    ok = _restore_reg_key(target, backup)
                else:
                    ok = False
                results.append({"target": target, "ok": ok})
            except Exception as ex:
                logger.record_err("screen.restore.item", ex)
                results.append({"target": target, "ok": False, "error": str(ex)})
        ok_count = sum(1 for r in results if r.get("ok"))
        db.audit("screen.restore", "qdir=%s ok=%d/%d" % (qdir, ok_count, len(entries)))
        return {"ok": True, "ok_count": ok_count, "total": len(entries), "results": results}
    finally:
        _cleanup_lock.release()


# ---------------- 标记入库 ----------------
def mark_item(name, category, risk, detail, note=""):
    """把筛查项标记为观察记录（入库 observations）。返回 obs id。"""
    oid = db.add_observation(
        title=name or "筛查标记", status="marked", risk=risk or "低",
        category=category or "其他",
        summary=(detail or "")[:300],
        mark=note or "筛查工作台标记",
        evidence=[{"type": category, "data": (detail or "")[:500]}])
    db.audit("screen.mark", "obs=%s name=%s cat=%s risk=%s" % (oid, name, category, risk))
    return oid


def scan_machine_fingerprints(keyword=""):
    """通用软件机器指纹文件扫描。

    遍历用户目录（APPDATA/LOCALAPPDATA），按 FINGERPRINT_FILE_PATTERNS 匹配已知
    软件的机器指纹/设备标识/令牌文件，列出路径、大小、修改时间和风险等级。

    keyword 为空时返回所有命中；非空时按厂商/产品名/描述过滤。
    """
    kw = (keyword or "").strip().lower()
    items, seen = [], set()
    scan_dirs = _user_scan_dirs()

    for base in scan_dirs:
        if not os.path.isdir(base):
            continue
        try:
            level1 = os.listdir(base)
        except OSError:
            continue
        for entry in level1:
            entry_lower = entry.lower()
            entry_path = os.path.join(base, entry)
            if not os.path.isdir(entry_path):
                continue
            for pat in FINGERPRINT_FILE_PATTERNS:
                dir_low = pat["dir"].lower().split("\\")[0]
                if dir_low != entry_lower and not entry_lower.startswith(dir_low):
                    continue
                # 计算子目录：dir 模式可能含多级（如 Google\Chrome\User Data）
                sub_parts = pat["dir"].split("\\")[1:]
                target_dir = entry_path
                for part in sub_parts:
                    candidate = os.path.join(target_dir, part)
                    if os.path.isdir(candidate):
                        target_dir = candidate
                    else:
                        break
                target_file = os.path.join(target_dir, pat["file"])
                # 对 blob_storage 等目录型目标做 glob 式存在性判断
                paths = []
                if os.path.isfile(target_file):
                    paths = [target_file]
                elif os.path.isdir(target_file):
                    paths = [target_file]
                else:
                    # 尝试 glob（处理 machineId/machineid 变体）
                    import glob
                    globbed = glob.glob(os.path.join(target_dir, pat["file"]))
                    paths = [p for p in globbed if os.path.exists(p)]
                for p in paths:
                    key = os.path.normcase(os.path.abspath(p))
                    if key in seen:
                        continue
                    hay = (pat["vendor"] + " " + pat["product"] + " " + pat.get("desc", "") + " " + pat.get("category", "")).lower()
                    if kw and kw not in hay:
                        continue
                    seen.add(key)
                    try:
                        st = os.stat(p)
                        size = int(st.st_size)
                        mtime = time.strftime("%Y-%m-%d %H:%M:%S",
                                             time.localtime(int(st.st_mtime)))
                    except OSError:
                        size, mtime = 0, "未知"
                    # 小文件（<1KB）尝试读取前 64 字节作为预览
                    preview = ""
                    if os.path.isfile(p) and size <= 4096:
                        try:
                            with open(p, "rb") as f:
                                raw = f.read(64)
                            # 尝试 UTF-8 解码，失败则 hex
                            try:
                                preview = raw.decode("utf-8", errors="replace").strip()[:60]
                            except Exception:
                                preview = raw.hex()[:60]
                        except OSError:
                            pass
                    items.append({
                        "category": "机器指纹",
                        "name": "%s %s" % (pat["product"], pat["file"]),
                        "path": p,
                        "type": "fingerprint_file",
                        "target": p,
                        "vendor": pat["vendor"],
                        "product": pat["product"],
                        "fp_category": pat.get("category", "fingerprint"),
                        "detail": "厂商: %s | 产品: %s | 用途: %s | 大小: %s 字节 | 修改: %s%s" % (
                            pat["vendor"], pat["product"], pat.get("desc", ""),
                            size, (mtime if isinstance(mtime, str) else str(mtime)),
                            " | 预览: " + preview if preview else ""),
                        "risk": pat.get("risk", "中"),
                        "reason": "机器指纹/身份文件",
                        "size": size,
                        "mtime": mtime if isinstance(mtime, str) else str(mtime),
                        "state": "未处理",
                    })
    db.audit("screen.fingerprint", "keyword=%s hits=%d" % (keyword or "(all)", len(items)))
    return _finish(items, "机器指纹")


# ---------------- 通用指纹内容检测（模式库外发现） ----------------
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEXID_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
_ID_NAME_RE = re.compile(
    r"(?<![a-z0-9])(machine[\s_-]?id|device[\s_-]?id|install[\s_-]?id|client[\s_-]?id|"
    r"app[\s_-]?id|anon[\s_-]?id|fingerprint|telemetry[\s_-]?id|user[\s_-]?id|"
    r"hardware[\s_-]?id|hwid|uuid)(?![a-z0-9])", re.I)
_MAX_GENERIC_SCAN = 30
_GENERIC_DEPTH = 3


def _looks_like_identifier(path, size):
    """判断小文件内容是否像设备/安装唯一标识（UUID 或长十六进制）。"""
    if size <= 0 or size > 256:
        return False
    try:
        with open(path, "rb") as f:
            raw = f.read(size)
    except OSError:
        return False
    try:
        text = raw.decode("utf-8", errors="replace").strip()
    except Exception:
        return False
    if len(text) < 32 or len(text) > 128:
        return False
    if _UUID_RE.match(text):
        return True
    if _HEXID_RE.match(text):
        return True
    return False


def scan_generic_fingerprints(keyword=""):
    """通用指纹内容检测：在用户目录中扫描模式库之外的隐藏设备标识文件。

    不依赖已知厂商清单，直接按两条独立证据判定：
      1) 文件名命中 machine-id/device-id/client-id/... 等标识类关键词；
      2) 文件内容 ≤256 字节且为 UUID 或 32-64 位十六进制串（典型机器指纹格式）。
    任一命中即列为候选。三重预算护栏（目录数 ≤5000 / 文件检查 ≤60000 / 时间 ≤25s），
    防止多用户 profile 枚举后全盘遍历失控。
    """
    kw = (keyword or "").strip().lower()
    items, seen = [], set()
    counter = [0]
    budget = {"dirs": 0, "files": 0}
    deadline = time.monotonic() + 25
    for base in _user_scan_dirs():
        if counter[0] >= _MAX_GENERIC_SCAN or time.monotonic() >= deadline:
            break
        if not os.path.isdir(base):
            continue
        try:
            level1 = os.listdir(base)
        except OSError:
            continue
        for entry in level1[:200]:
            if counter[0] >= _MAX_GENERIC_SCAN or time.monotonic() >= deadline:
                break
            entry_path = os.path.join(base, entry)
            if not os.path.isdir(entry_path):
                continue
            for root, dirs, files in os.walk(entry_path):
                if counter[0] >= _MAX_GENERIC_SCAN or time.monotonic() >= deadline \
                        or budget["dirs"] >= 5000:
                    break
                budget["dirs"] += 1
                depth = root[len(entry_path):].count(os.sep)
                if depth >= _GENERIC_DEPTH:
                    dirs[:] = []
                else:
                    dirs[:] = [d for d in dirs if not d.startswith(".")][:50]
                for fname in files[:300]:
                    if counter[0] >= _MAX_GENERIC_SCAN or budget["files"] >= 60000 \
                            or time.monotonic() >= deadline:
                        break
                    budget["files"] += 1
                    p = os.path.join(root, fname)
                    key = os.path.normcase(os.path.abspath(p))
                    if key in seen:
                        continue
                    try:
                        size = int(os.path.getsize(p))
                    except OSError:
                        continue
                    name_hit = bool(_ID_NAME_RE.search(fname))
                    content_hit = _looks_like_identifier(p, size)
                    if not name_hit and not content_hit:
                        continue
                    hay = (fname + " " + root).lower()
                    if kw and kw not in hay:
                        continue
                    seen.add(key)
                    counter[0] += 1
                    try:
                        mtime = time.strftime("%Y-%m-%d %H:%M:%S",
                                              time.localtime(int(os.path.getmtime(p))))
                    except OSError:
                        mtime = "未知"
                    preview = ""
                    if size <= 256:
                        try:
                            with open(p, "rb") as f:
                                raw = f.read(64)
                            try:
                                preview = raw.decode("utf-8", errors="replace").strip()[:48]
                            except Exception:
                                preview = raw.hex()[:48]
                        except OSError:
                            pass
                    evidence = []
                    if name_hit:
                        evidence.append("文件名含标识关键词")
                    if content_hit:
                        evidence.append("内容为 UUID/长十六进制")
                    items.append({
                        "category": "机器指纹",
                        "name": fname,
                        "path": p,
                        "type": "fingerprint_file",
                        "target": p,
                        "vendor": "（未知）",
                        "product": os.path.basename(entry_path),
                        "fp_category": "generic",
                        "detail": "未知软件指纹候选 | 目录: %s | 大小: %s 字节 | 修改: %s | 证据: %s%s" % (
                            root, size, mtime, ";".join(evidence),
                            " | 预览: " + preview if preview else ""),
                        "risk": "高" if content_hit else "中",
                        "reason": "通用指纹内容检测",
                        "size": size,
                        "mtime": mtime,
                        "state": "未处理",
                    })
                if counter[0] >= _MAX_GENERIC_SCAN:
                    break
            if counter[0] >= _MAX_GENERIC_SCAN:
                break
        if counter[0] >= _MAX_GENERIC_SCAN:
            break
    db.audit("screen.generic_fp", "hits=%d" % len(items))
    return _finish(items, "机器指纹")


# ---------------- Prefetch 执行痕迹扫描 ----------------
def _prefetch_dir():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(root, "Prefetch")


def scan_prefetch_traces(keyword=""):
    """Prefetch 执行痕迹：扫描 C:\\Windows\\Prefetch\\*.pf。

    Windows 每次运行 exe 都会生成/更新 .pf 文件；软件卸载后该痕迹仍长期保留。
    文件名格式：<EXE名>-<路径哈希8位>.pf。读取内部路径字段可还原完整执行路径
    （.pf 头部存有执行计数与最后执行时间，简单字符串扫描即可取回路径）。
    """
    kw = (keyword or "").strip().lower()
    if not kw:
        return {"category": "执行痕迹", "summary": {"total": 0, "high": 0,
                "med": 0, "low": 0, "none": 0}, "items": [],
                "error": "请提供软件关键词（如 Qoder）"}
    pdir = _prefetch_dir()
    if not os.path.isdir(pdir):
        return {"category": "执行痕迹", "summary": {"total": 0, "high": 0,
                "med": 0, "low": 0, "none": 0}, "items": [],
                "error": "Prefetch 目录不存在（可能被禁用）: %s" % pdir}
    items = []
    try:
        names = sorted(os.listdir(pdir))
    except OSError as e:
        return {"category": "执行痕迹", "summary": {"total": 0, "high": 0,
                "med": 0, "low": 0, "none": 0}, "items": [],
                "error": "Prefetch 目录不可读: %s" % e}
    for name in names:
        if not name.lower().endswith(".pf"):
            continue
        if kw not in name.lower():
            continue
        p = os.path.join(pdir, name)
        exe_path = ""
        try:
            with open(p, "rb") as f:
                head = f.read(4096)
            # .pf 内嵌 UTF-16LE 完整执行路径，提取第一段盘符路径
            m = re.search(rb"([A-Za-z]:\\(?:[^\x00]{1,200}\\)*[^\x00]{1,120}\.exe)",
                          head.replace(b"\x00", b"", 1))
            if not m:
                m = re.search(
                    rb"([A-Za-z]:\\[^\x00]{1,300}\.exe)",
                    re.sub(rb"\x00([a-zA-Z0-9_.\\\- ])", rb"\1", head))
            if m:
                try:
                    exe_path = m.group(1).decode("utf-8", errors="replace")
                except Exception:
                    exe_path = m.group(1).decode("mbcs", errors="replace")
        except OSError:
            pass
        try:
            mtime = time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.localtime(int(os.path.getmtime(p))))
        except OSError:
            mtime = "未知"
        try:
            size = int(os.path.getsize(p))
        except OSError:
            size = 0
        items.append({
            "category": "执行痕迹",
            "name": name,
            "path": p,
            "type": "prefetch_file",
            "target": p,
            "detail": "Prefetch 执行痕迹 | 还原路径: %s | 最后执行: %s | 大小: %s 字节" % (
                exe_path or "（未能还原，可能为旧格式）", mtime, size),
            "risk": "中",
            "reason": "软件曾在本机执行（卸载后仍残留）",
            "size": size,
            "mtime": mtime,
            "exe_path": exe_path,
            "state": "未处理",
        })
    return _finish(items, "执行痕迹")


# ---------------- 注册表使用历史扫描（MuiCache/UserAssist/AppCompat/BAM） ----------------
_USERASSIST_PATHS = (
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"),
)
_MUICACHE_PATH = (r"HKCU", r"SOFTWARE\Classes\Local Settings\Software"
                 r"\Microsoft\Windows\Shell\MuiCache")
_APPCOMPAT_PATH = (r"HKCU", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                  r"\AppCompatFlags\Compatibility Assistant\Store")


def _rot13(s):
    return "".join(
        chr((ord(c) - 97 + 13) % 26 + 97) if "a" <= c <= "z" else
        chr((ord(c) - 65 + 13) % 26 + 65) if "A" <= c <= "Z" else c
        for c in s)


def _iter_reg_values(root_name, subkey):
    """遍历某注册表键的全部值，返回 [(值名, 值字符串, 类型)]。"""
    import winreg
    try:
        with winreg.OpenKey(_winroot(root_name), subkey, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    vname, vdata, vtype = winreg.EnumValue(k, i)
                except OSError:
                    break
                i += 1
                if vtype in (winreg.REG_NONE, winreg.REG_LINK):
                    continue
                if isinstance(vdata, bytes):
                    try:
                        vdata = vdata.decode("utf-16-le", errors="replace")
                    except Exception:
                        continue
                yield str(vname), str(vdata), int(vtype)
    except OSError:
        return


def _scan_muicache(keyword):
    """MuiCache：每个曾经运行过的 exe 都有一条 FriendlyName（含完整路径）值。"""
    items = []
    root_name, subkey = _MUICACHE_PATH
    for vname, vdata, _vtype in _iter_reg_values(root_name, subkey):
        if keyword in (vname + " " + vdata).lower():
            items.append({
                "category": "使用历史",
                "name": vname,
                "path": vname,
                "type": "muicache_value",
                "target": "%s\\%s|%s" % (root_name, subkey, vname),
                "detail": "MuiCache 应用名缓存 | 值名(路径): %s | FriendlyName: %s" % (
                    vname, vdata[:200]),
                "risk": "低",
                "reason": "软件曾在本机运行（Shell 应用名缓存）",
                "state": "未处理",
            })
    return items


def _scan_userassist(keyword):
    """UserAssist：值名为 ROT13 编码的 exe 路径，记录运行次数与最后运行时间。"""
    import winreg
    items = []
    for root_name, subkey in _USERASSIST_PATHS:
        try:
            with winreg.OpenKey(_winroot(root_name), subkey, 0, winreg.KEY_READ) as parent:
                guids = []
                i = 0
                while True:
                    try:
                        guids.append(winreg.EnumKey(parent, i))
                    except OSError:
                        break
                    i += 1
                for guid in guids:
                    for vname, _vdata, _vtype in _iter_reg_values(
                            root_name, subkey + "\\" + guid + "\\Count"):
                        decoded = _rot13(vname)
                        if keyword in (vname + " " + decoded).lower():
                            items.append({
                                "category": "使用历史",
                                "name": decoded or vname,
                                "path": decoded,
                                "type": "userassist_value",
                                "target": "%s\\%s\\%s\\Count|%s" % (root_name, subkey, guid, vname),
                                "detail": "UserAssist 程序运行历史 | 解码路径: %s | 原始值名: %s" % (
                                    decoded, vname),
                                "risk": "中",
                                "reason": "软件运行次数/最后运行时间被系统记录（ROT13 解码）",
                                "state": "未处理",
                            })
        except OSError:
            continue
    return items


def _scan_appcompat(keyword):
    """AppCompatFlags Compatibility Assistant Store：记录被兼容性助手处理的程序路径。"""
    items = []
    root_name, subkey = _APPCOMPAT_PATH
    for vname, _vdata, _vtype in _iter_reg_values(root_name, subkey):
        if keyword in vname.lower():
            items.append({
                "category": "使用历史",
                "name": vname,
                "path": vname,
                "type": "appcompat_value",
                "target": "%s\\%s|%s" % (root_name, subkey, vname),
                "detail": "AppCompat 兼容性助手记录 | 程序路径: %s" % vname,
                "risk": "低",
                "reason": "软件运行触发了兼容性助手处理",
                "state": "未处理",
            })
    return items


def _scan_bam(keyword):
    """BAM（Background Activity Moderator）：HKLM\\SYSTEM\\...\\Services\\bam\\State\\UserSettings\\<SID> 记录每个 exe 的最后执行时间（FILETIME）。"""
    items = []
    import winreg
    sids = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                            0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    sids.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        return items  # BAM 键不可读（需管理员）或不存在
    for sid in sids:
        for vname, vdata, _vtype in _iter_reg_values(
                "HKLM", r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" + "\\" + sid):
            if keyword in (vname + " " + vdata).lower():
                # vdata 是 REG_BINARY FILETIME（8 字节小端），还原时间
                last_run = ""
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                        r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" + "\\" + sid,
                                        0, winreg.KEY_READ) as k:
                        raw, _t = winreg.QueryValueEx(k, vname)
                        if isinstance(raw, bytes) and len(raw) >= 8:
                            ft = int.from_bytes(raw[:8], "little")
                            if ft > 0:
                                epoch = (ft - 116444736000000000) // 10000000
                                last_run = time.strftime(
                                    "%Y-%m-%d %H:%M:%S", time.localtime(epoch))
                except OSError:
                    pass
                items.append({
                    "category": "使用历史",
                    "name": vname,
                    "path": vname,
                    "type": "bam_value",
                    "target": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\%s|%s" % (sid, vname),
                    "detail": "BAM 后台活动记录 | 程序: %s | 最后执行: %s | SID: %s" % (
                        vname, last_run or "（无记录）", sid),
                    "risk": "中",
                    "reason": "Windows 系统级程序执行时间戳（卸载后仍保留）",
                    "last_run": last_run,
                    "state": "未处理",
                })
    return items


def scan_usage_history(keyword=""):
    """注册表使用历史扫描：MuiCache / UserAssist / AppCompatFlags / BAM 四源并查。"""
    kw = (keyword or "").strip().lower()
    if not kw:
        return {"category": "使用历史", "summary": {"total": 0, "high": 0,
                "med": 0, "low": 0, "none": 0}, "items": [],
                "error": "请提供软件关键词（如 Qoder）"}
    items, seen = [], set()
    scanners = (("MuiCache", _scan_muicache),
                ("UserAssist", _scan_userassist),
                ("AppCompat", _scan_appcompat),
                ("BAM", _scan_bam))
    for label, fn in scanners:
        try:
            found = fn(kw)
        except Exception as e:
            logger.record_err("screen.usage.%s" % label, e)
            continue
        for it in found:
            dk = "%s|%s" % (it.get("type"), it.get("target"))
            if dk in seen:
                continue
            seen.add(dk)
            it["source"] = label
            items.append(it)
    db.audit("screen.usage_history", "keyword=%s hits=%d" % (keyword, len(items)))
    return _finish(items, "使用历史")


# ---------------- WER 崩溃报告扫描 ----------------
def scan_wer_traces(keyword=""):
    """WER 崩溃报告：扫描用户与全机 Windows 错误报告的残留。

    ReportArchive/ReportQueue 目录按 <应用名>_<版本>_<哈希> 命名，
    软件卸载后其崩溃报告仍保留，可证明软件曾在本机运行与崩溃。
    """
    kw = (keyword or "").strip().lower()
    if not kw:
        return {"category": "崩溃痕迹", "summary": {"total": 0, "high": 0,
                "med": 0, "low": 0, "none": 0}, "items": [],
                "error": "请提供软件关键词（如 Qoder）"}
    bases = []
    local = os.environ.get("LOCALAPPDATA")
    if local:
        bases.append(os.path.join(local, "Microsoft", "Windows", "WER"))
    prog = os.environ.get("ProgramData")
    if prog:
        bases.append(os.path.join(prog, "Microsoft", "Windows", "WER"))
    items, seen = [], set()
    for base in bases:
        if not os.path.isdir(base):
            continue
        for sub in ("ReportArchive", "ReportQueue"):
            root = os.path.join(base, sub)
            if not os.path.isdir(root):
                continue
            try:
                names = sorted(os.listdir(root))
            except OSError:
                continue
            for name in names:
                if kw not in name.lower():
                    continue
                p = os.path.join(root, name)
                key = os.path.normcase(os.path.abspath(p))
                if key in seen:
                    continue
                seen.add(key)
                try:
                    mtime = time.strftime("%Y-%m-%d %H:%M:%S",
                                          time.localtime(int(os.path.getmtime(p))))
                except OSError:
                    mtime = "未知"
                is_dir = os.path.isdir(p)
                items.append({
                    "category": "崩溃痕迹",
                    "name": name,
                    "path": p,
                    "type": "wer_report",
                    "target": p,
                    "detail": "WER %s %s | %s | 修改: %s" % (
                        sub, "目录" if is_dir else "文件", p, mtime),
                    "risk": "低",
                    "reason": "软件崩溃报告残留（卸载后仍保留）",
                    "mtime": mtime,
                    "state": "未处理",
                })
    db.audit("screen.wer", "keyword=%s hits=%d" % (keyword, len(items)))
    return _finish(items, "崩溃痕迹")


# ---------------- 指纹编码格式逆向（可信改写支持） ----------------
# 背景：指纹文件若被"不合创建规则"地修改（类型/长度/编码/加密错误），软件会判定
# 不信任并重新生成新指纹，导致"去除/更新"失败。逆向解析常见编码格式，输出该文件的
# 创建规则与可信改写指导，并支持生成符合规则的替换值预览（只读，不写盘）。
_UUID_FULL_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX32_RE = re.compile(r"^[0-9a-f]{32}$", re.I)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.I)
_DPAPI_MAGIC = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf"
_ID_HINT_RE = re.compile(
    r"(id|uuid|guid|machine|device|install|serial|hwid|salt|token|fingerprint"
    r"|installation|registration)", re.I)
_TIMESTAMP_HINT_RE = re.compile(
    r"(date|time|last|first|timer|created|expires)", re.I)
_MAX_FORMAT_PARSE = 2 * 1024 * 1024


def _parse_leaf(value):
    """对 JSON 叶子值做指纹语义分类，返回 (kind, creation_rule, replacement)。"""
    if isinstance(value, bool) or isinstance(value, (int, float)):
        if isinstance(value, bool):
            return ("bool", "布尔值：true/false", None)
        s = str(int(value))
        if len(s) == 10 and 946684800 <= int(s) <= 4102444800:
            return ("unix_timestamp", "10 位 Unix 秒级时间戳", None)
        if len(s) == 13 and 946684800000 <= int(s) <= 4102444800000:
            return ("unix_timestamp_ms", "13 位 Unix 毫秒级时间戳", None)
        return ("number", "数值", None)
    if not isinstance(value, str):
        return ("container", "容器", None)
    v = value.strip()
    if not v:
        return ("string_empty", "空字符串", None)
    if _UUID_FULL_RE.match(v):
        return ("uuid", "36 字符 UUID（8-4-4-4-12，小写十六进制+连字符）",
                str(uuid.uuid4()))
    if _HEX32_RE.match(v):
        return ("hex32", "32 字符十六进制（16 字节）", uuid.uuid4().hex)
    if _HEX64_RE.match(v):
        return ("hex64", "64 字符十六进制（32 字节，常为哈希）",
                hashlib.sha256(uuid.uuid4().bytes).hexdigest())
    compact = v.replace("-", "")
    if len(compact) == 32 and all(c in "0123456789abcdefABCDEF" for c in compact):
        return ("hex_uuid", "32 字符十六进制 UUID（可带连字符）",
                uuid.uuid4().hex)
    try:
        import base64
        raw = base64.b64decode(v, validate=False)
        # DPAPI blob 的 base64 形如 "DPAPI\x01\x00..."，magic 8 字节可能位于
        # 开头（纯 blob）或偏移 5（ASCII "DPAPI" 前缀 + \x01 后）。取前 40 字节内搜索。
        if len(raw) >= 13 and _DPAPI_MAGIC in raw[:40]:
            return ("dpapi_blob", "DPAPI 加密 blob（机器+用户绑定，无法直接伪造）", None)
    except Exception:
        pass
    if len(v) >= 24 and all(c in "0123456789abcdefABCDEF" for c in v):
        n = len(v)
        import secrets
        return ("hex", "任意十六进制串（长度 %d 字符）" % n,
                secrets.token_hex((n + 1) // 2)[:n])
    if len(v) >= 10 and v.isdigit():
        if len(v) == 10 and 946684800 <= int(v) <= 4102444800:
            return ("unix_timestamp", "10 位 Unix 秒级时间戳（字符串形式）", None)
        return ("numeric_string", "数字字符串（长度 %d）" % len(v), None)
    return ("string", "字符串", None)


def _walk_json(obj, out, path="$", depth=0):
    """递归遍历 JSON，分类叶子值，收集身份字段与格式规则。"""
    if depth > 8:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            child = "%s.%s" % (path, k)
            if isinstance(v, (dict, list)):
                _walk_json(v, out, child, depth + 1)
                continue
            kind, rule, repl = _parse_leaf(v)
            is_identity = bool(_ID_HINT_RE.search(str(k)))
            is_timestamp = bool(_TIMESTAMP_HINT_RE.search(str(k)))
            if kind in ("uuid", "hex32", "hex64", "hex_uuid", "dpapi_blob") \
                    or is_identity or is_timestamp:
                entry = {"field": child, "kind": kind, "rule": rule,
                         "identity_hint": is_identity,
                         "timestamp_hint": is_timestamp}
                if kind == "dpapi_blob":
                    entry["value_preview"] = "[DPAPI 加密，长度 %d 字符]" % len(str(v))
                elif kind in ("uuid", "hex32", "hex64", "hex_uuid"):
                    entry["value_preview"] = "%s...（%s）" % (str(v)[:12], kind)
                else:
                    entry["value_preview"] = str(v)[:40]
                if repl is not None:
                    entry["replacement"] = repl
                out.append(entry)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:20]):
            _walk_json(v, out, "%s[%d]" % (path, i), depth + 1)


def analyze_fingerprint_format(path):
    """逆向解析指纹文件的编码格式与创建规则（只读）。

    支持格式：SQLite 数据库 / JSON / DPAPI base64 / 纯文本 UUID / hex 编码 UUID /
    通用十六进制 / 未知二进制。输出该文件"创建规则"（软件信任判据）与"可信改写
    指导"——让用户知道怎么改才不会被判定损坏并重新生成指纹。
    """
    import base64
    import sqlite3
    path = os.path.abspath(os.path.expandvars(str(path or "")))
    if not os.path.isfile(path):
        return {"ok": False, "error": "文件不存在: %s" % path}
    try:
        size = int(os.path.getsize(path))
    except OSError as e:
        return {"ok": False, "error": "无法读取文件大小: %s" % e}
    if size > _MAX_FORMAT_PARSE:
        return {"ok": False, "error": "文件过大（>2MB），不做格式解析"}
    try:
        with open(path, "rb") as f:
            head = f.read(65536)
    except OSError as e:
        return {"ok": False, "error": "读取失败: %s" % e}

    result = {"ok": True, "path": path, "size": size,
              "format": "unknown", "format_rules": [], "identity_fields": [],
              "rewrite_guidance": [], "risk": "未知"}

    # ---- 1) SQLite ----
    if head[:16] == b"SQLite format 3\x00":
        result["format"] = "sqlite"
        result["format_rules"] = [
            "SQLite 数据库文件（magic: SQLite format 3）",
            "必须保持有效 SQLite 页结构，直接字节改写会破坏库",
            "修改须经 SQL UPDATE/DELETE，或整体删除文件让软件重建",
        ]
        sidecars = [os.path.isfile(path + suf) for suf in ("-wal", "-shm")]
        if any(sidecars):
            result["format_rules"].append(
                "存在 -wal/-shm 侧车文件：修改前软件须已退出（WAL 未合并直接改主库会丢数据）")
        try:
            con = sqlite3.connect(
                "file:%s?mode=ro" % path.replace("\\", "/"), uri=True, timeout=3)
            cur = con.cursor()
            cur.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
            tables = cur.fetchall()
            for tname, tsql in tables:
                cur.execute("PRAGMA table_info(%s)" % tname)
                cols = [(r[1], str(r[2]).upper()) for r in cur.fetchall()]
                ident_cols = [c for c, t in cols
                              if _ID_HINT_RE.search(c) or "TIME" in c]
                try:
                    cur.execute("SELECT COUNT(*) FROM %s" % tname)
                    cnt = cur.fetchone()[0]
                except Exception:
                    cnt = -1
                result["identity_fields"].append({
                    "table": tname, "columns": cols, "identity_columns": ident_cols,
                    "row_count": cnt,
                    "note": "表含身份/时间列：%s（行级 UPDATE/DELETE 可改写）" %
                            ", ".join(ident_cols) if ident_cols else "无身份类列"})
            con.close()
        except Exception as e:
            result["identity_fields"].append({"sqlite_error": str(e)})
        result["rewrite_guidance"] = [
            "行级改写：sqlite3 打开后 UPDATE/DELETE 目标行（保持 schema 不变）",
            "整体重置：删除本文件 + 侧车文件，软件下次启动按自身规则重建（重建=新指纹，"
            "若目标就是'让软件失忆'则此路径最简单可靠）",
            "注意：直接文本编辑器修改会触发 SQLITE_CORRUPT，软件必重建",
        ]
        result["risk"] = "高（直接字节修改必致损坏→软件重建指纹）"
        db.audit("screen.format", "path=%s format=sqlite" % path)
        return result

    # ---- 2) 文本 / JSON / DPAPI / UUID / hex ----
    try:
        text = head.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text = None

    if text is not None:
        stripped = text.strip()
        # 2a) JSON
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                result["format"] = "json"
                result["format_rules"] = [
                    "JSON 对象（UTF-8）",
                    "必须保持合法 JSON 语法与现有键结构",
                    "改写字段值须保持原类型/长度/编码，否则软件可能整体重写文件",
                ]
                _walk_json(obj, result["identity_fields"])
                result["rewrite_guidance"] = [
                    "逐字段替换：对每个 identity_fields 按其 kind 的 rule 生成同格式新值",
                    "dpapi_blob 字段不可伪造（机器+用户绑定加密）；清除方式为删除该键，"
                    "软件会按自身逻辑重建或重登录",
                    "unix_timestamp 字段一般不影响身份信任，篡改会暴露异常",
                ]
                result["risk"] = "中（结构合法即可信；值须符合字段规则）"
                db.audit("screen.format", "path=%s format=json" % path)
                return result
        except (ValueError, TypeError):
            pass
        # 2b) DPAPI base64（magic 可能带 ASCII "DPAPI\x01" 前缀，取前 40 字节内搜索）
        try:
            raw = base64.b64decode(stripped, validate=False)
            if len(raw) >= 13 and _DPAPI_MAGIC in raw[:40]:
                result["format"] = "dpapi_blob"
                result["format_rules"] = [
                    "DPAPI 加密 blob（base64）",
                    "密文与当前 Windows 用户+机器绑定，无法凭空伪造有效密文",
                ]
                result["rewrite_guidance"] = [
                    "改写密文=必失败（解密不通过→软件判损坏并重建）",
                    "正确路径：①用 CryptProtectData 重新加密新值；②删除本文件让软件重建；"
                    "③若值在 JSON 键内（如 os_crypt.encrypted_key），删除该键",
                ]
                result["risk"] = "高（直接改写必致重建）"
                db.audit("screen.format", "path=%s format=dpapi" % path)
                return result
        except Exception:
            pass
        # 2c) 纯文本 UUID
        if _UUID_FULL_RE.match(stripped):
            result["format"] = "uuid_text"
            result["format_rules"] = [
                "36 字符 UUID 纯文本（8-4-4-4-12，小写十六进制）",
                "替换值必须同为 36 字符 UUID，且版本位（第 3 组首位）与变体位合法",
            ]
            result["identity_fields"] = [{
                "field": "$", "kind": "uuid", "rule": "UUID 纯文本",
                "value_preview": "%s..." % stripped[:12],
                "replacement": str(uuid.uuid4())}]
            result["rewrite_guidance"] = [
                "用生成的新 UUID 整体替换文件内容（保持小写、无换行差异）",
                "软件通常只校验格式+版本位，合法 UUID v4 即可被信任",
            ]
            result["risk"] = "低（格式正确即可信）"
            db.audit("screen.format", "path=%s format=uuid_text" % path)
            return result
        # 2d) hex 编码 UUID（如 Qoder cache/id：32 hex + 连字符）
        compact = stripped.replace("-", "")
        if len(compact) == 32 and all(c in "0123456789abcdefABCDEF"
                                      for c in compact):
            result["format"] = "hex_uuid"
            result["format_rules"] = [
                "32 字符十六进制标识（%d 字节），可能带连字符装饰" % 16,
                "替换值必须同为 32 字符十六进制；连字符位置若存在须保持一致",
            ]
            result["identity_fields"] = [{
                "field": "$", "kind": "hex_uuid", "rule": "hex 编码 UUID",
                "value_preview": "%s..." % stripped[:12],
                "replacement": uuid.uuid4().hex}]
            result["rewrite_guidance"] = [
                "用 32 字符 hex 替换内容（保持原连字符格式）",
                "若软件把该值 hex-decode 为 16 字节 UUID，新值版本位 4/变体位合法即可",
            ]
            result["risk"] = "低（格式正确即可信）"
            db.audit("screen.format", "path=%s format=hex_uuid" % path)
            return result
        # 2e) 其他文本
        result["format"] = "text"
        result["format_rules"] = ["UTF-8 文本（未识别为已知指纹格式）"]
        result["rewrite_guidance"] = ["无已知创建规则；修改前建议人工确认软件读取逻辑"]
        result["risk"] = "未知"
        db.audit("screen.format", "path=%s format=text" % path)
        return result

    # ---- 3) 二进制 ----
    result["format"] = "binary"
    result["format_rules"] = [
        "二进制内容（无法按文本解释）",
        "可能含结构头部/校验和/长度前缀，直接修改风险高",
    ]
    result["rewrite_guidance"] = [
        "不建议字节级改写；优先走'删除文件→软件重建'或软件内重置路径",
    ]
    result["risk"] = "高（未知二进制结构，改写大概率触发重建）"
    db.audit("screen.format", "path=%s format=binary" % path)
    return result


def generate_trusted_fingerprint(path):
    """生成符合创建规则的指纹替换预览（只读，不写盘）。

    对 UUID/hex-UUID 直接给出新值；对 JSON 逐字段给出同格式替换值并输出整份
    替换后 JSON 预览；对 SQLite/DPAPI/二进制不生成内容，给出操作路径指导。
    """
    analysis = analyze_fingerprint_format(path)
    if not analysis.get("ok"):
        return analysis
    fmt = analysis.get("format")
    if fmt in ("uuid_text", "hex_uuid"):
        newval = analysis["identity_fields"][0]["replacement"]
        return {"ok": True, "path": path, "format": fmt,
                "replacement_value": newval,
                "apply_hint": "用该值整体替换文件内容（保持原编码/连字符格式）",
                "note": "预览未写盘；写盘请使用受控工具或人工操作"}
    if fmt == "json":
        fields = analysis.get("identity_fields") or []
        repls = [{"field": f["field"], "kind": f["kind"],
                  "replacement": f.get("replacement")}
                 for f in fields if f.get("replacement")]
        note = []
        for f in fields:
            if f.get("kind") == "dpapi_blob":
                note.append("%s 为 DPAPI 加密，不可伪造；清除=删除该键" % f["field"])
        return {"ok": True, "path": path, "format": "json",
                "field_replacements": repls,
                "special_cases": note or None,
                "apply_hint": "按 field 路径替换各值（类型/长度保持不变）；"
                              "整体重写文件须保持 JSON 结构",
                "note": "预览未写盘；写盘请使用受控工具或人工操作"}
    return {"ok": True, "path": path, "format": fmt,
            "replacement_value": None,
            "apply_hint": "; ".join(analysis.get("rewrite_guidance") or []),
            "note": "该格式不生成内容预览，请按改写指导操作"}


# ---------------- 指纹修改 AI 指导（带安全门槛） ----------------
_FP_GUIDANCE_DENY_HINTS = ("付费", "vip", "license", "许可证", "授权", "注册码",
                            "破解", "激活", "激活码", "序列号", "绕过付费", "绕过授权",
                            "bypass payment", "crack", "keygen", "serial key")


def _fp_guidance_pre_check(path):
    """LLM 调用前的确定性前置检查。返回 (blocked, reason)。"""
    if not path:
        return False, ""
    p = os.path.abspath(os.path.expandvars(path))
    if _is_protected_fs_path(p):
        return True, "路径在系统/受保护目录（SystemRoot/ProgramFiles/项目根），拒绝指导"
    if not os.path.exists(p):
        return True, "文件不存在: %s" % p
    # 运行中的 exe 不允许指导修改（会被锁定，且改运行中进程文件极危险）
    if p.lower().endswith(".exe") and os.path.isfile(p):
        try:
            import subprocess
            out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq %s" % os.path.basename(p),
                                  "/FO", "CSV", "/NH"], capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=10).stdout
            if os.path.basename(p).lower() in out.lower():
                return True, "该 exe 正在运行，修改运行中的可执行文件极危险且会被锁定"
        except Exception:
            pass
    return False, ""


def _build_fp_guidance_prompt(analysis, replacement, path):
    """构造带强制安全自检的指纹修改指导系统提示词。"""
    ctx_parts = []
    if path:
        ctx_parts.append("目标文件路径：%s" % path)
    if analysis and analysis.get("ok"):
        ctx_parts.append("格式逆向分析结果：\n%s" % json.dumps(analysis, ensure_ascii=False,
                                                              default=str)[:6000])
    if replacement and replacement.get("ok"):
        ctx_parts.append("合法替换值参考（已通过格式校验，可直接使用）：\n%s" % json.dumps(
            replacement, ensure_ascii=False, default=str)[:4000])
    context_block = "\n\n".join(ctx_parts) if ctx_parts else "（未提供文件分析上下文）"

    return (
        "你是 ReTrace 指纹修改指导助手。用户正在尝试修改一个软件指纹文件的值，"
        "使其仍被原软件信任（避免软件因格式不符而重新制造新指纹）。\n\n"
        "════════════════════════════════════\n"
        "⚠️ 强制安全自检（第一步，不可跳过）\n"
        "════════════════════════════════════\n"
        "在生成任何回答之前，你必须先评估：\n"
        "1. 用户的操作目的是否为【绕过付费墙/授权许可/许可证验证】"
        "（即'不劳而获'——不付费就使用付费功能）？\n"
        "2. 该操作是否会对【系统稳定性】造成损害？"
        "（如修改运行中进程锁定的文件、破坏系统文件、删除关键配置导致软件崩溃）\n\n"
        "判定规则：\n"
        "● 若(1)成立 → 拒绝给出任何操作指导，仅回复："
        "'该请求涉及绕过付费/授权许可，出于合规考虑不予指导。'\n"
        "   然后立即结束，不输出任何操作步骤。\n"
        "● 若(2)成立 → 在回答开头用 ⚠️ 标注具体风险，并给出缓解建议"
        "（如先关闭目标进程、备份原文件到 quarantine）。\n"
        "● 若(1)(2)均不成立 → 在回答开头输出：【已检查】\n"
        "  （对于支持 thinking/reasoning 的模型，在思考过程中输出；"
        "  对于普通模型，在可见回答的第一行输出）\n\n"
        "════════════════════════════════════\n"
        "硬行为边界\n"
        "════════════════════════════════════\n"
        "● 绝不自动执行任何命令、脚本、写盘操作。所有步骤均为人工审查后手动执行。\n"
        "● 绝不提供可用于绕过付费功能、授权验证、许可证检查的具体操作方法。\n"
        "● 仅提供：格式规则解释、合法替换值、受控的手动修改步骤、验证方法。\n"
        "● 涉及写盘步骤时，必须包含：①备份原文件 ②具体命令/操作 ③回滚方法。\n"
        "● 涉及注册表/系统文件时，必须提醒创建系统还原点。\n\n"
        "════════════════════════════════════\n"
        "上下文（由 ReTrace 指纹分析模块提供）\n"
        "════════════════════════════════════\n"
        "%s\n\n"
        "如果用户未给出具体问题，主动给出：\n"
        "1) 该指纹文件的作用与格式创建规则；\n"
        "2) 当前检测到的身份字段及其可改写性（可改写/需同步/不可伪造）；\n"
        "3) 安全修改步骤（备份→修改→验证→回滚）；\n"
        "4) 修改后仍被软件信任的关键注意事项。\n"
        "用中文回答，结构清晰，关键风险点用 ⚠️ 标注。"
    ) % context_block


def fingerprint_guidance(question, path=""):
    """带强制安全自检的指纹修改 AI 指导（只读，不自动执行）。

    流程：确定性前置检查 → 格式逆向分析 → 生成合法替换值 → 构造安全提示词
    → 调用 LLM → 验证【已检查】标记。
    """
    from modules import ai
    if not ai.configured():
        return {"ok": False, "error": "AI 未配置：请在设置页填写 base_url / api_key / model"}

    # 1) 确定性前置检查
    abs_path = os.path.abspath(os.path.expandvars(path)) if path else ""
    blocked, reason = _fp_guidance_pre_check(abs_path)
    if blocked:
        return {"ok": False, "error": "安全前置检查未通过: %s" % reason}

    # 2) 快速意图关键词拦截（绕过付费墙类）
    q = (question or "").lower()
    for hint in _FP_GUIDANCE_DENY_HINTS:
        if hint in q:
            return {"ok": False,
                    "error": "该请求涉及绕过付费/授权许可，出于合规考虑不予指导。",
                    "blocked_reason": "payment_bypass"}

    # 3) 收集上下文
    analysis, replacement = None, None
    if abs_path and os.path.isfile(abs_path):
        try:
            analysis = analyze_fingerprint_format(abs_path)
            replacement = generate_trusted_fingerprint(abs_path)
        except Exception as e:
            logger.record_err("screen.fp_guidance.analyze", e)

    # 4) 构造安全提示词 + 调用 LLM（prepend_safety=False，我们已自带安全边界）
    sys_prompt = _build_fp_guidance_prompt(analysis, replacement, abs_path)
    user_q = (question or "").strip()
    if not user_q:
        user_q = "请告诉我这个指纹文件的作用、格式规则，以及如何安全地修改它（保持软件信任）。"
    result = ai.chat(
        [{"role": "system", "content": sys_prompt},
         {"role": "user", "content": user_q}],
        temperature=0.2, max_tokens=2500, prepend_safety=False)

    # 5) 验证【已检查】标记（普通模型可见输出中；thinking 模型在 reasoning 中）
    if result.get("ok"):
        text = result.get("text", "")
        has_marker = "【已检查】" in text
        result["safety_check_passed"] = has_marker
        if not has_marker:
            result["text"] = (
                "⚠️ 安全自检标记缺失——以下回答未经过完整安全审查，请谨慎参考。"
                "建议重新提问或人工复核。\n\n") + text
        db.audit("screen.fp_guidance", "path=%s check=%s blocked=%s" % (
            abs_path, has_marker, False))
    return result


def analyze_with_ai(result, question="分析以下筛查结果，指出最可疑的几项并给出人工复核建议"):
    """AI 辅助分析筛查结果（只读，不执行任何操作）。人机协作：人类筛查 → AI 辅助理解。"""
    from modules import ai
    if not ai.configured():
        return {"ok": False, "error": "AI 未配置：请在设置页填写 base_url / api_key / model"}
    items = (result or {}).get("items", [])
    if not items:
        return {"ok": False, "error": "无筛查项可分析"}
    text = json_d(items[:30])
    prompt = ("你是安全筛查辅助分析助手。以下是筛查工作台的结果，请用中文输出：\n"
              "1) 总体风险概述（含高危/中危数量）；\n"
              "2) 按可疑度列出 Top 3 并说明理由；\n"
              "3) 对每一条给出人工复核与处置建议（不执行任何操作）。\n"
              "问题：%s\n数据：%s" % (question, text[:5000]))
    db.audit("screen.ai", "items=%d" % len(items))
    return ai.chat([{"role": "system",
                     "content": "你是只读的安全分析助手，输出简洁实用，不执行任何操作。"},
                    {"role": "user", "content": prompt}],
                   temperature=0.2, max_tokens=1200)


def register(bus, cfg):
    pass


def shutdown():
    pass
