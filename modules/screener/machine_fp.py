"""筛查工作台——机器指纹文件扫描（已知模式库 + 未知通用检测）。"""
import glob
import os
import re
import time

from core import db
from modules.screener.common import _finish, _user_scan_dirs

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
