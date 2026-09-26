"""Agent 工具白名单 + 风险分级。

风险分级：
  read    只读/检索/分析 —— reviewer 放行即执行
  cmd     运行本地命令/控制系统状态 —— reviewer 审核；deny 则用户审批
  high    删除/联网等副作用 —— 必须用户确认（隔离备份/逐次确认）

命令安全：argv 列表执行（无 shell）、超时、黑名单永拒。
删除安全：先复制到 backups/quarantine/<ts>/ 再删，仅精确匹配文件路径。

2026-09-14 增强（读取&控制能力）：
  - 读取组新增：read_file（脱敏限额文本读取）/ list_dir / read_registry_value /
    query_observations / tracking_status / watcher_status / browser_status
  - 新增 control 工具组：capture_control / tracking_control / watcher_control /
    process_control —— 全部 cmd 级（reviewer + 用户逐次确认 + ≥12 字 reason），
    不改注册表、不写系统配置；无人工通道时与其它读写工具同样自动拒绝。
"""
import csv
import hashlib
import json
import locale
import os
import re
import shlex
import shutil
import subprocess
import time
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from math import log2

from core import config, db, logger

RISK_READ = "read"
RISK_CMD = "cmd"
RISK_HIGH = "high"

TOOLS = {}


def tool(name, desc, risk, params):
    def deco(fn):
        TOOLS[name] = {"desc": desc, "risk": risk, "params": params, "run": fn}
        return fn
    return deco


# ---- 工具组（2026-08-27 检修：集中化能力面）----
# 52 个工具全量注入系统提示词会使每次模型调用多付 ~1500 token 且稀释注意力。
# 以组为单位在 config.agent.tool_groups（逗号分隔或列表）里勾选启用面；
# 空/未配置 = 全启用（向后兼容）。执行器对未启用组 fail-closed。
GROUP_ORDER = ("core", "fingerprint", "identity", "investigation", "control")
TOOL_GROUPS = {
    # 核心：检索/系统观察/命令/联网/文件与库读取
    "reference": "core", "search_registry": "core", "autostart_points": "core",
    "search_files": "core", "fingerprint": "core", "inspect_process": "core",
    "leftover_scan": "core", "decompile": "core", "inspect_privacy": "core",
    "run_command": "core", "web_search": "core", "hunt_string": "core",
    "file_compare": "core", "privacy_plan": "core",
    "read_file": "core", "list_dir": "core", "read_registry_value": "core",
    "query_observations": "core", "tracking_status": "core",
    "watcher_status": "core", "browser_status": "core",
    # 指纹工作流：扫描/逆向/实验
    "scan_fingerprints": "fingerprint", "scan_software_traces": "fingerprint",
    "analyze_fingerprint_format": "fingerprint",
    "generate_trusted_fingerprint": "fingerprint",
    "scan_prefetch_traces": "fingerprint", "scan_usage_history": "fingerprint",
    "scan_wer_traces": "fingerprint", "scan_ai_tool_traces": "fingerprint",
    "fingerprint_drift_report": "fingerprint", "sandbox_test_plan": "fingerprint",
    "capture_status": "fingerprint", "modify_fingerprint": "fingerprint",
    "remove_file": "fingerprint", "recycle_file": "fingerprint",
    "json_identity_fields": "fingerprint", "derive_probe": "fingerprint",
    "experiment_backup": "fingerprint", "json_edit_field": "fingerprint",
    # 动态身份排查
    "hunt_software_fingerprint": "identity", "deep_registry_scan": "identity",
    "scan_system_anchors": "identity", "extract_identity_semantics": "identity",
    "correlate_identity_sources": "identity", "monitor_identity_access": "identity",
    "assess_identity_impact": "identity",
    # 调查案例管理
    "create_investigation_case": "investigation",
    "list_investigation_cases": "investigation",
    "get_investigation_case": "investigation",
    "add_investigation_evidence": "investigation",
    "list_investigation_evidence": "investigation",
    "update_evidence_status": "investigation",
    "record_investigation_action": "investigation",
    "list_investigation_actions": "investigation",
    "update_investigation_progress": "investigation",
    "get_investigation_progress": "investigation",
    "generate_investigation_report": "investigation",
    "close_investigation_case": "investigation",
    "run_full_investigation": "investigation",
    # 控制面（2026-09-14）：抓包/追踪/观察器/进程启停 —— 全部 cmd 级
    "capture_control": "control", "tracking_control": "control",
    "watcher_control": "control", "process_control": "control",
}


def enabled_tool_groups():
    """读 config.agent.tool_groups 决定启用组；空 = 全启用。
    检修（2026-09-19）：非空但全部无法识别时返回 []（fail-closed）——
    旧兜底 `groups or list(GROUP_ORDER)` 让 "controll"/"false" 这类拼写错误
    静默打开全部五组，与 Design §21/executor 承诺的 fail-closed 相反。"""
    raw = config.section("agent", {}).get("tool_groups")
    if not raw:
        return list(GROUP_ORDER)
    if isinstance(raw, str):
        raw = [g.strip() for g in raw.split(",") if g.strip()]
    wanted = {str(g) for g in raw}
    groups = [g for g in GROUP_ORDER if g in wanted]
    if not groups:
        logger.warn("agent.tool_groups 配置 %r 无任何有效组，按全禁用处理" % (raw,))
    return groups


def tool_enabled(name):
    return TOOL_GROUPS.get(name, "core") in set(enabled_tool_groups())


def tool_manifest():
    """按启用组过滤的工具清单（供系统提示词与 GUI 展示）。"""
    groups = set(enabled_tool_groups())
    return {k: {"desc": v["desc"], "risk": v["risk"], "params": v["params"]}
            for k, v in TOOLS.items() if TOOL_GROUPS.get(k, "core") in groups}


def _cap(obj, n=200):
    """限制返回体量，防止把上下文撑爆。"""
    if isinstance(obj, list):
        return obj[:n]
    if isinstance(obj, dict):
        return {k: (v[:n] if isinstance(v, list) else v) for k, v in obj.items()}
    return obj


# ---------------- read：参照/搜索/检查 ----------------
@tool("reference", "检索经验库/知识库（语义相似观察与规则）", RISK_READ, ["query"])
def _reference(query):
    from modules import embedding
    hits = []
    try:
        hits = embedding.search(query or "", 8, 0.0)
    except Exception as e:
        logger.record_err("agent.tool.reference", e)
    rules = db.list_knowledge(enabled_only=True, limit=20)
    return {"hits": _cap(hits, 8), "rules_sample": _cap(rules, 10)}


@tool("search_registry", "按关键词搜索注册表（默认 HKLM，root 可换 HKCU/HKU）", RISK_READ, ["keyword", "root"])
def _search_registry(keyword, root="HKLM"):
    from modules import regscan
    res = regscan.search(keyword=keyword or "", root=root, path="",
                         mode="contains", max_hits=300)
    rows = (res or {}).get("hits", []) if isinstance(res, dict) else []
    return {"hits": len(rows), "sample": _cap(rows, 30)}


@tool("autostart_points", "列出注册表自启动常驻点位（Run/服务/IFEO 等），供可疑 APP 排查", RISK_READ, [])
def _autostart_points():
    from modules import regscan
    return _cap(regscan.autostart_points(root="HKLM"), 100)


@tool("search_files", "按文件名模式（正则，忽略大小写）搜索目录内文件，返回路径与大小", RISK_READ, ["pattern", "base_dir"])
def _search_files(pattern, base_dir=None):
    base = os.path.abspath(base_dir or os.path.expandvars("%LOCALAPPDATA%"))
    if not os.path.isdir(base):
        return {"error": "目录不存在: %s" % base}
    # 检修（2026-09-19）：与 list_dir 同法接 ReDoS 守卫——RISK_READ 自动
    # 放行工具不得留指数回溯正则的门（os.walk 无超时，挂死 agent 线程）。
    from modules.regscan import MAX_REGEX_LEN, _NESTED_QUANT_RE
    pattern = str(pattern or "")
    if len(pattern) > MAX_REGEX_LEN:
        return {"error": "正则过长（>%d）拒绝" % MAX_REGEX_LEN}
    if _NESTED_QUANT_RE.search(pattern):
        return {"error": "正则含嵌套量词/组内交替形态（ReDoS 风险）拒绝: %s" % pattern}
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return {"error": "正则无效: %s" % e}
    out = []
    for root, dirs, files in os.walk(base):
        depth = root[len(base):].count(os.sep)
        if depth >= 6:
            dirs[:] = []
        else:
            dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            try:
                if rx.search(f):
                    p = os.path.join(root, f)
                    out.append({"path": p, "size": os.path.getsize(p)})
            except OSError:
                continue
            if len(out) >= 100:
                return {"count": len(out), "results": out}
    return {"count": len(out), "results": out}


def _file_hashes(p):
    sha, md5 = hashlib.sha256(), hashlib.md5()
    cnt = Counter()
    total = 0
    with open(p, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            sha.update(b)
            md5.update(b)
            total += len(b)
            cnt.update(b)
    ent = 0.0
    if total:
        ent = -sum((c / total) * log2(c / total) for c in cnt.values())
    return sha.hexdigest(), md5.hexdigest(), ent


MAX_HASH_SIZE = 512 * 1024 * 1024


@tool("fingerprint", "计算文件指纹（≤512MB；py/exe/dll/class 附加反编译摘要）", RISK_READ, ["path"])
def _fingerprint(path):
    p = os.path.abspath(path)
    if not os.path.isfile(p):
        return {"error": "文件不存在: %s" % p}
    st = os.stat(p)
    if st.st_size > MAX_HASH_SIZE:
        return {"error": "文件过大(>512MB)，跳过哈希", "path": p, "size": st.st_size}
    sha, md5, ent = _file_hashes(p)
    info = {
        "path": p, "size": st.st_size,
        "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
        "sha256": sha, "md5": md5, "entropy": round(ent, 3),
    }
    if p.lower().endswith((".exe", ".dll", ".py", ".pyc", ".class")):
        try:
            from modules import decompile
            r = decompile.analyze(p)
            if isinstance(r, dict) and not r.get("error"):
                info["kind"] = r.get("kind")
                info["strings"] = _cap(r.get("strings") or [], 20)
                info["calls"] = _cap(r.get("calls") or [], 15)
                info["score"] = r.get("score")
        except Exception as e:
            logger.record_err("agent.tool.fingerprint.decompile", e)
    return info


def _run_cmd(argv, timeout=20, encoding=None):
    # 检修（2026-09-19）：中文 Windows 控制台命令（tasklist/netstat/ipconfig）输出
    # GBK，硬编码 utf-8 使非 ASCII 进程名/表头变 U+FFFD——kill 永拒判定与
    # "配置项是否真生效"整链路失真（FreqErr §30 同坑，watcher/tracking 已修）。
    # tshark 是显式 utf-8 输出，由调用方传 encoding="utf-8"。
    flags = 0
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        flags = subprocess.CREATE_NO_WINDOW
    proc = subprocess.run(argv, capture_output=True, text=True,
                          encoding=encoding or locale.getpreferredencoding(False) or "utf-8",
                          errors="replace",
                          timeout=timeout, creationflags=flags)
    return proc


@tool("inspect_process", "列出进程及 TCP/UDP 连接；可按进程名过滤", RISK_READ, ["name"])
def _inspect_process(name=None):
    try:
        p = _run_cmd(["tasklist", "/FO", "CSV", "/NH"], timeout=20)
        procs = []
        for row in csv.reader(p.stdout.splitlines()):
            if len(row) >= 2 and row[0].strip():
                procs.append({"name": row[0].strip(), "pid": row[1].strip(),
                              "session": row[2].strip() if len(row) > 2 else "",
                              "mem": row[4].strip() if len(row) > 4 else ""})
        if name:
            procs = [x for x in procs if name.lower() in x["name"].lower()]
    except Exception as e:
        logger.record_err("agent.tool.tasklist", e)
        procs = [{"error": str(e)}]
    try:
        n = _run_cmd(["netstat", "-ano"], timeout=20)
        conns = []
        for line in n.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] in ("TCP", "UDP"):
                conns.append({"proto": parts[0], "local": parts[1],
                              "remote": parts[2] if parts[0] == "TCP" else "",
                              "state": parts[3] if parts[0] == "TCP" else "",
                              "pid": parts[-1]})
    except Exception as e:
        logger.record_err("agent.tool.netstat", e)
        conns = [{"error": str(e)}]
    return {"processes": _cap(procs, 50), "connections": _cap(conns, 80),
            "filter": name}


@tool("leftover_scan", "检测 APP 卸载残留：主 exe 缺失、空目录、注册表指向不存在的路径", RISK_READ, ["install_dir"])
def _leftover_scan(install_dir):
    base = os.path.abspath(install_dir)
    if not os.path.isdir(base):
        return {"error": "目录不存在: %s" % base}
    report = {"install_dir": base, "issues": []}
    exes = [f for f in os.listdir(base) if f.lower().endswith(".exe")]
    if not exes:
        report["issues"].append({"type": "missing_main_exe", "detail": "未找到主 exe，疑似残留目录"})
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        if not files and not dirs and os.path.abspath(root) != base:
            report["issues"].append({"type": "empty_dir", "detail": root})
    # 注册表 Run 项指向不存在的路径（检修 2026-08-27：旧正则 [^",\s]+ 不吃
    # 空格，"C:\Program Files\..." 形态永远匹配失败 → 带空格悬空项静默漏检；
    # 复用 screener.apps._extract_exe 单一实现，并补 HKCU 侧扫描）
    try:
        from modules import regscan
        from modules.screener.common import _extract_exe
        for root_r in ("HKLM", "HKCU"):
            for it in regscan.autostart_points(root=root_r):
                data = it.get("data") or ""
                exe = _extract_exe(data)
                if exe and not os.path.exists(os.path.expandvars(exe)):
                    report["issues"].append({"type": "dangling_autostart",
                                             "detail": "%s -> %s" % (it.get("key"), exe)})
    except Exception as e:
        logger.record_err("agent.tool.leftover.reg", e)
    return report


@tool("decompile", "反编译分析 py/exe/dll/class，输出符号/字符串/可疑调用", RISK_READ, ["path"])
def _decompile(path):
    from modules import decompile
    return decompile.analyze(os.path.abspath(path))


@tool("inspect_privacy", "检查追踪任务中的敏感标识访问与 APP 注册表依赖（只读）",
      RISK_READ, ["task_id"])
def _inspect_privacy(task_id):
    from modules import privacy_guard
    return privacy_guard.task_report(int(task_id))


# ---------------- read：指纹扫描 / 逆向分析 ----------------
@tool("scan_fingerprints", "扫描已知/未知软件指纹文件（machineid/DIPS/Client ID 等）",
      RISK_READ, ["keyword"])
def _scan_fingerprints(keyword=""):
    from modules import screener
    if keyword:
        return screener.scan_machine_fingerprints(keyword=keyword)
    return screener.scan_generic_fingerprints()


@tool("scan_software_traces", "留样扫描：注册表+自启动+卸载反查+文件系统深度下钻",
      RISK_READ, ["keyword", "install_dir"])
def _scan_software_traces(keyword, install_dir=""):
    from modules import screener
    return screener.scan_software_traces(keyword=keyword, install_dir=install_dir)


@tool("analyze_fingerprint_format", "逆向指纹文件编码格式（SQLite/JSON/DPAPI/UUID/hex），输出创建规则与改写指导",
      RISK_READ, ["path"])
def _analyze_fingerprint_format(path):
    from modules import screener
    return screener.analyze_fingerprint_format(path)


@tool("generate_trusted_fingerprint", "生成符合创建规则的合法替换值预览（只读不写盘）",
      RISK_READ, ["path"])
def _generate_trusted_fingerprint(path):
    from modules import screener
    return screener.generate_trusted_fingerprint(path)


@tool("scan_prefetch_traces", "扫描 Prefetch .pf 执行痕迹（卸载后仍残留）", RISK_READ, ["keyword"])
def _scan_prefetch_traces(keyword):
    from modules import screener
    return screener.scan_prefetch_traces(keyword=keyword)


@tool("scan_usage_history", "注册表使用历史四源并查（MuiCache/UserAssist/AppCompat/BAM）",
      RISK_READ, ["keyword"])
def _scan_usage_history(keyword):
    from modules import screener
    return screener.scan_usage_history(keyword=keyword)


@tool("scan_wer_traces", "扫描 WER 崩溃报告残留", RISK_READ, ["keyword"])
def _scan_wer_traces(keyword):
    from modules import screener
    return screener.scan_wer_traces(keyword=keyword)


@tool("scan_ai_tool_traces", "扫描 AI 编码工具痕迹（Claude Code/Codex/Gemini CLI 等；身份字段仅哈希预览）",
      RISK_READ, ["keyword"])
def _scan_ai_tool_traces(keyword=""):
    from modules import screener
    return screener.scan_ai_tool_traces(keyword=keyword)


@tool("fingerprint_drift_report", "指纹再生监测：对比上次基线，识别清理后被软件原样复活的文件"
      "（recreated_same_value=有云端恢复）。只读报告，不改基线",
      RISK_READ, ["keyword"])
def _fingerprint_drift_report(keyword=""):
    from modules import screener
    # 安全考量：commit=True 会覆写漂移基线、销毁"清理前后"对比证据，
    # 故 Agent 通道强制只读；基线管理走 GUI/Web 的人工确认路径。
    return screener.fingerprint_drift_report(keyword=keyword, commit=False)


@tool("sandbox_test_plan", "生成沙箱对照实验材料：可直接保存的 .wsb 配置 + 六步操作清单（纯规划不执行）",
      RISK_READ, ["exe_path", "network"])
def _sandbox_test_plan(exe_path, network=False):
    from modules import privacy_guard
    from core.coerce import strict_bool
    return privacy_guard.build_sandbox_test_plan(exe_path,
                                                 strict_bool(network) if network is not None else False)


@tool("capture_status", "查看抓包实例状态与最近数据包计数（name 默认 main）", RISK_READ, ["name"])
def _capture_status(name="main"):
    from modules import pcap
    snap = pcap.capture_status(name=name)
    snap["recent_sample"] = _cap(pcap.get_recent(name=name, limit=10), 10)
    return snap


@tool("privacy_plan", "生成带原因、精确参数、回滚/备份步骤的系统操作预案；不执行变更",
      RISK_CMD, ["action", "args", "reason"])
def _privacy_plan(action, args, reason):
    from modules import privacy_guard
    return privacy_guard.plan_system_action(action, args, reason)


# ---------------- read：文件/目录/注册表值/库与运行状态（2026-09-14 增强） ----------------
# 红线：read_file 绝不回显明文密钥（core.redact 双模式脱敏），敏感文件类型直接拒绝；
# 二进制文件不冒充文本读取，交回 fingerprint/decompile 专用通道。

# 检修（2026-09-14）：补 SQLite 旁檐文件（WAL/SHM 含最近写入明文）、备份变体、
# 无扩展名 SSH 私钥与 .env——红线"敏感文件类型直接拒绝"的名单缺口。
READ_FILE_DENY_SUFFIX = (".pem", ".key", ".pfx", ".p12", ".kdbx", ".jks",
                         ".keystore", ".sqlite", ".sqlite3", ".env")
READ_FILE_DENY_NAME = {"config.json", "retrace.db", "id_rsa", "id_ed25519",
                       "id_ecdsa", "authorized_keys"}


def _win_longpath(p):
    """展开 8.3 短名（CONFIG~1.JSO → config.json）——检修（2026-09-19）：
    敏感名单只按 basename 字面匹配时，短名/链接形态可整读 config.json 明文。"""
    if os.name != "nt" or not p:
        return p
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(1024)
        n = ctypes.windll.kernel32.GetLongPathNameW(p, buf, len(buf))
        if 0 < n < len(buf):
            return buf.value
    except Exception:
        pass
    return p


def _is_sensitive_path(p):
    p = _win_longpath(p)
    bn = os.path.basename(p).lower()
    if (bn in READ_FILE_DENY_NAME or
            bn.startswith(("retrace.db", "config.json")) or
            bn.endswith(READ_FILE_DENY_SUFFIX)):
        return True
    # 链接/短名归一后仍指向受保护文件本体也算命中
    try:
        rp = os.path.normcase(os.path.realpath(p))
        for guard in (_config_protected_paths()):
            if rp == os.path.normcase(os.path.realpath(guard)):
                return True
    except OSError:
        pass
    return False


def _config_protected_paths():
    from core import config
    paths = [config.CONFIG_PATH]
    try:
        from core.db.connection import DB_PATH
        paths.append(DB_PATH)
    except Exception:
        pass
    return paths


@tool("read_file", "读取文本文件内容（自动脱敏密钥/令牌；二进制与密钥类文件拒绝）；offset/max_chars 可分页",
      RISK_READ, ["path", "offset", "max_chars"])
def _read_file(path, offset=0, max_chars=4000):
    from core.redact import redact_secrets
    p = _win_longpath(os.path.abspath(os.path.expandvars(path or "")))
    if not os.path.isfile(p):
        return {"error": "文件不存在: %s" % p}
    if _is_sensitive_path(p):
        return {"error": "拒绝读取敏感文件（配置/密钥库）: %s" % os.path.basename(p)}
    try:
        # 检修（2026-09-19）：整读前设体积预算——数百 MB 日志会整档进内存，
        # RISK_READ 自动放行路径可把 agent 线程挂死（fingerprint 有同规约先例）。
        if os.path.getsize(p) > 8 * 1024 * 1024:
            return {"error": "文件超过 8MB 文本读取预算: %s；"
                             "请用 list_dir/fingerprint/decompile 或对副本分段" % p}
    except OSError as e:
        return {"error": "读取失败: %s" % e}
    try:
        with open(p, "rb") as f:
            head = f.read(8192)
    except OSError as e:
        return {"error": "读取失败: %s" % e}
    if b"\x00" in head:
        return {"error": "二进制文件，不做文本读取；请改用 fingerprint / decompile 工具",
                "path": p, "size": os.path.getsize(p)}
    try:
        with open(p, "r", encoding="utf-8-sig", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return {"error": "读取失败: %s" % e}
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0
    try:
        max_chars = max(200, min(int(max_chars or 4000), 8000))
    except (TypeError, ValueError):
        max_chars = 4000
    chunk = text[offset:offset + max_chars]
    out = {"path": p, "total_chars": len(text), "offset": offset,
           "returned_chars": len(chunk),
           "truncated": offset + len(chunk) < len(text),
           "content": redact_secrets(chunk),
           "hint": "还有更多内容时用 offset=已读末尾 续读；密钥/令牌已自动脱敏"}
    if not chunk and offset > len(text):
        out["hint"] = "offset 超出文件末尾（total_chars=%d），无内容返回" % len(text)
    return out


@tool("list_dir", "列出目录内容（名称/类型/大小/mtime，目录在前；pattern 可选正则过滤文件名）",
      RISK_READ, ["path", "pattern"])
def _list_dir(path, pattern=""):
    p = os.path.abspath(os.path.expandvars(path or ""))
    if not os.path.isdir(p):
        return {"error": "目录不存在: %s" % p}
    rx = None
    if pattern:
        # 检修（2026-09-19）：RISK_READ 自动放行工具不得给指数回溯正则留门——
        # 复用 regscan 的 ReDoS 守卫（长度封顶 + 量化组内含交替/嵌套量词拒入）。
        from modules.regscan import MAX_REGEX_LEN, _NESTED_QUANT_RE
        if len(pattern) > MAX_REGEX_LEN:
            return {"error": "正则过长（>%d）拒绝" % MAX_REGEX_LEN}
        if _NESTED_QUANT_RE.search(pattern):
            return {"error": "正则含嵌套量词/组内交替形态（ReDoS 风险）拒绝: %s" % pattern}
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return {"error": "正则无效: %s" % e}
    entries = []
    try:
        names = os.listdir(p)
    except OSError as e:
        return {"error": "列举失败: %s" % e}
    for n in names:
        fp = os.path.join(p, n)
        is_dir = os.path.isdir(fp)
        if rx is not None and not is_dir and not rx.search(n):
            continue
        try:
            st = os.stat(fp)
            size, mtime = st.st_size, time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
        except OSError:
            size, mtime = 0, ""
        entries.append({"name": n, "type": "dir" if is_dir else "file",
                        "size": size, "mtime": mtime})
    entries.sort(key=lambda e: (0 if e["type"] == "dir" else 1, e["name"].lower()))
    total = len(entries)
    return {"path": p, "total": total, "entries": _cap(entries, 200),
            "truncated": total > 200}


@tool("read_registry_value", "精确读取单个注册表值（只读；key_path 如 HKLM\\SOFTWARE\\...，name 为空读默认值）",
      RISK_READ, ["key_path", "name"])
def _read_registry_value(key_path, name=""):
    from core.redact import key_is_secret, redact_secrets
    from modules import regscan
    out = regscan.read_value(key_path, name or "")
    # 检修（2026-09-14）：出参统一脱敏——软件常把 token/口令以 REG_SZ 存 HKCU，
    # 明文进模型会话/审计即违反"密钥绝不回显"红线（与 read_file 同规约）。
    if isinstance(out, dict) and "data" in out:
        try:
            # 检修（2026-09-19）：值名命中敏感键名提示时整体掩码——
            # 短口令（<40 字符）不触发值形状规则，只按值形状脱敏会漏。
            if key_is_secret(name):
                out["data"] = "<secret:%d:%s>" % (
                    len(str(out.get("data") or "")),
                    hashlib.sha256(str(out.get("data") or "").encode(
                        "utf-8")).hexdigest()[:10])
            else:
                out["data"] = redact_secrets(out.get("data"))
        except Exception:
            out["data"] = "[REDACTED]"
    return out


@tool("query_observations", "查询观察库（observations 表，可按 status 过滤：open/analyzing/done 等）",
      RISK_READ, ["status", "limit"])
def _query_observations(status=None, limit=50):
    try:
        limit = max(1, min(int(limit or 50), 200))
    except (TypeError, ValueError):
        limit = 50
    rows = db.get_observations(status=status or None, limit=limit)
    return {"count": len(rows), "status_filter": status or "全部",
            "observations": _cap(rows, limit)}


@tool("tracking_status", "查询追踪任务状态（不传 task_id 列出全部+守护状态；传入则返回任务详情+最近事件+运行记录）",
      RISK_READ, ["task_id", "limit"])
def _tracking_status(task_id=None, limit=20):
    from modules import tracking
    if task_id not in (None, ""):
        tid = int(task_id)
        detail = tracking.get_task(tid)
        detail["recent_events"] = _cap(tracking.task_events(tid, 50), 50)
        detail["runs"] = _cap(tracking.task_runs(tid, 20), 20)
        return detail
    try:
        limit = max(1, min(int(limit or 20), 100))
    except (TypeError, ValueError):
        limit = 20
    return {"tasks": _cap(tracking.list_tasks(limit=limit), limit),
            "daemon": tracking.daemon_status()}


@tool("watcher_status", "查询观察器状态与最近时间线（进程树/网络/DNS/文件/注册表事件）",
      RISK_READ, ["limit"])
def _watcher_status(limit=30):
    from modules import watcher
    from core.redact import redact_secrets
    try:
        limit = max(1, min(int(limit or 30), 200))
    except (TypeError, ValueError):
        limit = 30
    # 检修（2026-09-19）：时间线里"注册表变化 old -> new"含值明文（可达
    # 300 字符）——与其它注册表出口同规则，redact 后才出边界。
    return {"status": watcher.status(),
            "timeline": _cap(redact_secrets(watcher.timeline_entries(limit)),
                             limit)}


@tool("browser_status", "查询浏览器中枢状态（连接/标签页/DOM 事件样例；只读）",
      RISK_READ, [])
def _browser_status():
    from modules import browser
    return {"status": browser.status(),
            "tabs": _cap(browser.list_tabs(), 10),
            "dom_events_sample": _cap(browser.dom_events(10), 10)}


# ---------------- cmd：运行白名单命令 ----------------
CMD_WHITELIST = {"tasklist", "netstat", "ipconfig", "where", "reg", "tshark",
                 "systeminfo", "driverquery", "ping"}
CMD_BLACKLIST = {"del", "erase", "rm", "rmdir", "rd", "deltree", "format",
                 "shutdown", "taskkill", "sc", "psexec", "powershell", "pwsh",
                 "cmd", "start", "net", "subst", "attrib", "cscript", "wscript",
                 "wmic"}
CMD_FORBIDDEN = {"|", ">", "<", "&", ";", "`", "$(", ".."}


# tshark 仅放行只读分析参数；-X（lua_script 任意代码执行）、-w/-F/-G（写文件）、
# -C（配置）、--export-*（批量落盘）等一律确定性拒绝
TSHARK_SAFE = {"-r", "-i", "-f", "-Y", "-T", "-e", "-E", "-D", "-q", "-l",
               "-n", "-N", "-d", "-s", "-c", "-B", "-p", "-S", "-t", "-u", "-V"}


def _vet_tshark(argv):
    for a in argv[1:]:
        if a.startswith("--"):
            return "tshark 长选项被禁止: %s" % a
        if a.startswith("-") and a != "-":
            if a in ("-w", "-F", "-G", "-X", "-C") or a.startswith(("-w", "-X")):
                return "tshark 写文件/Lua/导出参数被禁止: %s" % a
            if a not in TSHARK_SAFE:
                return "tshark 参数不在安全白名单: %s" % a
    return None


def _split_command(command):
    """命令行拆分（2026-08-27 检修 T2）：裸 .split() 会把含空格的引号参数拆碎
    （"C:\\Program Files\\x.exe" → 两个残缺 token，命令必然失败）。
    shlex(posix=False) 保留 Windows 反斜杠字面量与引号边界，再逐 token 剥外层引号；
    引号不闭合等病态输入回退旧行为（裸 split）。"""
    try:
        raw = shlex.split(command or "", posix=False)
    except ValueError:
        raw = (command or "").split()
    return [t.strip().strip('"').strip() for t in raw if t.strip()]


@tool("run_command", "运行白名单系统命令（必须说明可审查原因）", RISK_CMD, ["command", "reason"])
def _run_command(command, reason=""):
    argv = _split_command(command)
    if not argv:
        return {"error": "命令为空"}
    first = argv[0]
    if "/" in first or "\\" in first or first in (".", ".."):
        return {"error": "命令必须为纯命令名（不允许路径/相对引用）: %s" % first}
    base = os.path.basename(first).lower()
    if base in CMD_BLACKLIST:
        return {"error": "命令在黑名单，禁止执行: %s" % base}
    if base not in CMD_WHITELIST:
        return {"error": "命令不在白名单: %s（可用: %s）" % (base, sorted(CMD_WHITELIST))}
    for a in argv[1:]:
        if any(f in a for f in CMD_FORBIDDEN):
            return {"error": "参数含禁止字符（重定向/管道/换行等）: %s" % a}
    if base == "reg" and len(argv) >= 2 and argv[1].lower() in ("delete", "add", "copy", "save", "restore", "load", "unload", "flags", "import", "export"):
        return {"error": "reg 写操作被禁止，仅允许 query"}
    if base == "reg" and len(argv) == 1:
        argv = [argv[0], "query"]
    if base == "ipconfig":
        # 所有开关参数逐一校验（防 /all /release 夹带破坏性动词）。
        # 检修（2026-09-14）：`-` 开头此前两分支都不拦——Windows 接受 dash 形态，
        # `-release`/`-flushdns` 等可原样逃逸（FreqErr §5 argv[0] 坑的残留变体）。
        IPCONFIG_SAFE = {"all", "displaydns"}
        for a in argv[1:]:
            if not (a.startswith("/") or a.startswith("-")):
                return {"error": "ipconfig 不接受位置参数: %s" % a}
            sub = a.lstrip("/-").lower()
            if sub not in IPCONFIG_SAFE:
                return {"error": "ipconfig 仅允许查询开关（/all /displaydns），拒绝 %s" % a}
    if base == "ping":
        # 防滥用封顶：仅放行只读探测开关；次数/包长/超时设上限（防 -n 无限刷包）
        PING_SWITCH_CAPS = {"-n": (1, 20), "-l": (0, 1500), "-w": (1, 10000)}
        PING_SAFE = set(PING_SWITCH_CAPS) | {"-4", "-6", "-S"}
        i = 1
        while i < len(argv):
            a = argv[i]
            if a.startswith("-"):
                if a not in PING_SAFE:
                    return {"error": "ping 开关不在安全白名单: %s" % a}
                if a in PING_SWITCH_CAPS:
                    if i + 1 >= len(argv) or not argv[i + 1].isdigit():
                        return {"error": "ping %s 需要数字参数" % a}
                    lo, hi = PING_SWITCH_CAPS[a]
                    v = int(argv[i + 1])
                    if not lo <= v <= hi:
                        return {"error": "ping %s 超限(%d)，允许 %d~%d"
                                % (a, v, lo, hi)}
                    i += 1
            i += 1
    if base == "tshark":
        err = _vet_tshark(argv)
        if err:
            return {"error": err}
    try:
        p = _run_cmd(argv, timeout=int(config.section("agent", {}).get("cmd_timeout", 30)),
                     encoding="utf-8" if base == "tshark" else None)
        result = {"command": " ".join(argv), "returncode": p.returncode,
                  "stdout": p.stdout[-4000:], "stderr": p.stderr[-1000:]}
        if p.returncode != 0:
            result["error"] = "命令退出码非零(%d): %s" % (p.returncode, p.stderr[-200:].strip())
        return result
    except subprocess.TimeoutExpired:
        return {"error": "命令执行超时"}
    except Exception as e:
        logger.record_err("agent.tool.run_command", e)
        return {"error": str(e)}


# ---------------- cmd：控制系统状态（2026-09-14 增强，control 组） ----------------
# 与 run_command 同级风险：reviewer 模型审核 + 用户逐次确认 + ≥12 字 reason。
# 红线：不写注册表、不改系统配置、不杀系统关键进程；无人工通道时自动拒绝（默认安全）。

@tool("capture_control", "控制抓包实例（action=start/stop/stop_all；start 可带 interface 编号与 bpf 过滤）",
      RISK_CMD, ["action", "name", "interface", "bpf", "reason"])
def _capture_control(action, name="main", interface=None, bpf=None, reason=""):
    from modules import pcap
    action = str(action or "").strip().lower()
    name = str(name or "main").strip() or "main"
    if action == "start":
        if interface is not None:
            try:
                interface = int(interface)
            except (TypeError, ValueError):
                return {"error": "interface 必须是接口编号（先用 capture_status 查询）"}
        if bpf is not None:
            bpf = str(bpf).strip()
            # 检修（2026-09-19）：bpf 以单个 argv 传给 tshark -f，以 "-" 开头的
            # 串（"-w x.pcap"）会被 getopt 解析成选项，绕过 _vet_tshark 的
            # -w/-X 禁令实现任意落盘——BPF 过滤器不得是选项形态。
            if bpf.startswith("-"):
                return {"error": "bpf 不得以 - 开头（防选项注入）: %s" % bpf}
            if len(bpf) > 256:
                return {"error": "bpf 过滤器过长（>256 字符）"}
            if not bpf:
                bpf = None
        ok, snap = pcap.start_capture(name=name, interface=interface, bpf=bpf)
        # 检修（2026-09-19）：Capture.start() 对 running/starting 返回 False 是
        # 幂等门语义（已在抓包），不是失败——与 watcher_control 同法如实上报
        # 状态；仅真正的启动失败才回 error 封套（executor 以 error 键判审计）。
        if not ok:
            if (snap or {}).get("state") in ("running", "starting"):
                return {"ok": True, "action": "start",
                        "detail": "抓包已在运行（无需重复启动）",
                        "snapshot": snap}
            return {"ok": False, "action": "start", "snapshot": snap,
                    "error": "抓包启动失败: %s"
                             % ((snap or {}).get("last_error")
                                or "tshark 不可用或接口编号错误")}
        return {"ok": True, "action": "start", "snapshot": snap}
    if action == "stop":
        return {"ok": True, "action": "stop", "snapshot": pcap.stop_capture(name=name)}
    if action == "stop_all":
        return {"ok": True, "action": "stop_all", "result": pcap.stop_all()}
    return {"error": "action 只支持 start/stop/stop_all"}


_TRACKING_UPDATE_KEYS = ("name", "exe_path", "process_name", "pid",
                         "watch_paths", "interval_sec", "ai_enabled")


@tool("tracking_control", "控制追踪任务（action=create/start/pause/update/delete；create 需 name+目标，"
      "update 经 fields 传字段；create 不自动启动，启动用 start）",
      RISK_CMD, ["action", "task_id", "name", "exe_path", "process_name", "pid",
                 "watch_paths", "fields", "reason"])
def _tracking_control(action, task_id=None, name=None, exe_path="", process_name="",
                      pid=None, watch_paths=None, fields=None, reason=""):
    from modules import tracking
    action = str(action or "").strip().lower()
    if action == "create":
        if not str(name or "").strip():
            return {"error": "create 必须提供 name"}
        if isinstance(watch_paths, str):
            watch_paths = [watch_paths]
        return tracking.create_task(str(name), exe_path=exe_path or "",
                                    process_name=process_name or "",
                                    pid=pid, watch_paths=watch_paths,
                                    auto_start=False)
    if task_id in (None, ""):
        return {"error": "%s 必须提供 task_id" % action}
    try:
        tid = int(task_id)
    except (TypeError, ValueError):
        return {"error": "task_id 必须是数字，收到: %r" % (task_id,)}
    if action == "start":
        return tracking.start_task(tid)
    if action == "pause":
        return tracking.pause_task(tid)
    if action == "delete":
        return tracking.delete_task(tid)
    if action == "update":
        if not isinstance(fields, dict):
            return {"error": "update 必须提供 fields 对象（可编辑键：%s）"
                             % ", ".join(_TRACKING_UPDATE_KEYS)}
        kwargs = {k: fields[k] for k in fields if k in _TRACKING_UPDATE_KEYS}
        if isinstance(kwargs.get("watch_paths"), str):
            kwargs["watch_paths"] = [kwargs["watch_paths"]]
        if not kwargs:
            return {"error": "fields 无可编辑字段（白名单：%s）"
                             % ", ".join(_TRACKING_UPDATE_KEYS)}
        return tracking.update_task(tid, **kwargs)
    return {"error": "action 只支持 create/start/pause/update/delete"}


@tool("watcher_control", "控制观察器（action=add_target/remove_target/start/stop；"
      "add_target 需 name，可选 pid/exe）",
      RISK_CMD, ["action", "name", "pid", "exe", "reason"])
def _watcher_control(action, name=None, pid=None, exe=None, reason=""):
    from modules import watcher
    action = str(action or "").strip().lower()
    if action == "add_target":
        if not str(name or "").strip():
            return {"error": "add_target 必须提供 name（观察目标显示名）"}
        # 检修（2026-09-19）：pid 非数字在此显式拒绝——watcher 内部 int(pid)
        # 抛的 ValueError 会走 executor 异常路径污染 Err.log 且报错晦涩。
        if pid not in (None, ""):
            try:
                pid = int(pid)
            except (TypeError, ValueError):
                return {"error": "pid 必须是整数，收到: %r" % (pid,)}
        # 检修（2026-09-14）：解包 (ok, msg)——失败也报 ok:True 会让模型以为
        # 目标已加入观察，实验链路静默空转、审计 outcome 失真。
        ok, info = watcher.add_target(str(name), pid=pid or None, exe=exe)
        if not ok:
            return {"error": str(info)}
        return {"ok": True, "action": "add_target", "name": str(name),
                "detail": str(info)}
    if action == "remove_target":
        if not str(name or "").strip():
            return {"error": "remove_target 必须提供 name"}
        if not watcher.remove_target(str(name)):
            return {"error": "目标不存在，无法移除: %s" % name}
        return {"ok": True, "action": "remove_target", "name": str(name)}
    if action == "start":
        # 检修（2026-09-19）：watcher.start() 返回 False 的语义是"已在运行/
        # 旧线程未退"（幂等门），不是失败——如实上报状态而非 error 封套。
        started = bool(watcher.start())
        return {"ok": True, "action": "start",
                "detail": "已启动" if started else "采集线程已在运行（无需重复启动）",
                "state": (watcher.status() or {}).get("state", "")}
    if action == "stop":
        watcher.stop()
        return {"ok": True, "action": "stop"}
    return {"error": "action 只支持 add_target/remove_target/start/stop"}


# 杀进程永拒清单：不可再生的系统关键进程（名字取 tasklist 输出的小写形态）
_KILL_DENY_NAMES = {"smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
                    "services.exe", "lsass.exe", "system", "registry",
                    "memory compression", "idle"}
# 启动永拒清单：等价于给 Agent 造一把 shell/改注册表钥匙的程序。
# 检修（2026-09-14）：补解释器/脚本宿主/持久化载体——python -c、node -e、
# wsl/bash、schtasks/installutil 等与 cmd 同级危险（红线点名"等价于交出 shell"）。
_LAUNCH_DENY_NAMES = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                      "cscript.exe", "mshta.exe", "rundll32.exe", "reg.exe",
                      "regsvr32.exe", "regedit.exe", "python.exe", "pythonw.exe",
                      "node.exe", "deno.exe", "bun.exe", "wsl.exe", "bash.exe",
                      "sh.exe", "schtasks.exe", "msbuild.exe", "installutil.exe",
                      "certutil.exe", "bitsadmin.exe", "netsh.exe", "diskpart.exe"}
# 参数级静态 deny：即便永拒名单漏掉某个便携版解释器（如 python3.14.exe），
# "执行字符串"类标志也让 launch 等价于代码执行，双保险拦截。
_LAUNCH_DENY_ARGS = {"-c", "-e", "-m", "-x", "--eval", "-command",
                     "-encodedcommand", "/c", "/k", "/r"}

# launch 句柄保活列表：Popen 对象被 GC 时若子进程仍存活会发 ResourceWarning；
# 保留句柄并在 kill/再次 launch 时统一 poll 回收已退出者
_LAUNCHED = []


def _reap_launched():
    for p in _LAUNCHED:
        try:
            p.poll()
        except Exception:
            pass
    _LAUNCHED[:] = [p for p in _LAUNCHED if p.returncode is None]


def _process_image_name(pid):
    try:
        p = _run_cmd(["tasklist", "/FI", "PID eq %d" % int(pid),
                      "/FO", "CSV", "/NH"], timeout=15)
        for row in csv.reader(p.stdout.splitlines()):
            # 仅数据行（≥2 列且第二列为数字 PID）才算命中；
            # 未命中时 tasklist 输出 INFO:/信息: 提示行，不得误当映像名
            if len(row) >= 2 and row[0].strip() and row[1].strip().isdigit():
                return row[0].strip().lower()
    except Exception as e:
        logger.record_err("agent.tool.process_control.image", e)
    return ""


@tool("process_control", "启动或停止进程（action=launch/kill；launch 需 exe_path 可选 args；"
      "kill 需 pid，/T 连子进程 —— 用于指纹实验的「重启目标软件」闭环）",
      RISK_CMD, ["action", "exe_path", "args", "pid", "cwd", "reason"])
def _process_control(action, exe_path="", args=None, pid=None, cwd="", reason=""):
    action = str(action or "").strip().lower()
    if action == "launch":
        exe = os.path.abspath(os.path.expandvars(str(exe_path or "")))
        if not os.path.isfile(exe):
            return {"error": "exe 不存在: %s" % exe}
        base = os.path.basename(exe).lower()
        if base in _LAUNCH_DENY_NAMES:
            return {"error": "拒绝启动 %s：该程序等价于交出 shell/注册表写权限" % base}
        if cwd:
            cwd = os.path.abspath(os.path.expandvars(str(cwd)))
            if not os.path.isdir(cwd):
                return {"error": "cwd 目录不存在: %s" % cwd}
        arg_list = []
        if isinstance(args, str):
            # 检修（2026-09-14）：字符串 args 此前被静默丢弃成 []，进程按无参启动
            # 且模型不知情——显式报错要求 argv 数组。
            return {"error": "args 必须是字符串数组（如 [\"--flag\"]），不要传整条命令行字符串"}
        if isinstance(args, (list, tuple)):
            arg_list = [str(a) for a in args]
        for a in arg_list:
            if a.strip().lower() in _LAUNCH_DENY_ARGS:
                return {"error": "拒绝启动：参数 %r 属于脚本执行类标志，等价于交出代码执行" % a}
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        try:
            proc = subprocess.Popen([exe] + arg_list, cwd=cwd or None,
                                    creationflags=flags)
        except OSError as e:
            return {"error": "启动失败: %s" % e}
        _LAUNCHED.append(proc)
        _reap_launched()
        db.audit("agent.process_control", "action=launch exe=%s pid=%s" % (exe, proc.pid))
        return {"ok": True, "action": "launch", "pid": proc.pid, "exe": exe,
                "hint": "进程已启动；停止请用 kill 传该 pid"}
    if action == "kill":
        if pid in (None, ""):
            return {"error": "kill 必须提供 pid"}
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return {"error": "pid 必须为整数"}
        if pid <= 4:
            return {"error": "拒绝 kill：系统保留 PID (%d)" % pid}
        if pid == os.getpid():
            return {"error": "拒绝 kill：不能停止 ReTrace 自身进程"}
        image = _process_image_name(pid)
        if not image:
            return {"error": "PID %d 不存在或已退出" % pid}
        if image in _KILL_DENY_NAMES:
            return {"error": "拒绝 kill：系统关键进程 %s 不可停止" % image}
        p = _run_cmd(["taskkill", "/PID", str(pid), "/T", "/F"], timeout=20)
        _reap_launched()
        db.audit("agent.process_control", "action=kill pid=%d image=%s rc=%d"
                 % (pid, image, p.returncode))
        out = {"ok": p.returncode == 0, "action": "kill", "pid": pid,
               "image": image, "returncode": p.returncode,
               "stdout": p.stdout[-500:], "stderr": p.stderr[-300:]}
        if p.returncode != 0:
            out["error"] = "taskkill 失败(rc=%d): %s" % (p.returncode, p.stderr[-200:].strip())
        return out
    return {"error": "action 只支持 launch/kill"}


# ---------------- high：联网 / 删除 ----------------
@tool("web_search", "联网查询公开信息（需用户确认并说明原因）", RISK_HIGH, ["query", "reason"])
def _web_search(query, reason=""):
    url = "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(query or "")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        html = urllib.request.urlopen(req, timeout=15).read().decode("utf-8", "replace")
    except Exception as e:
        logger.record_err("agent.tool.web_search", e)
        return {"error": "联网失败: %s" % e}
    results = []
    for m in re.finditer(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', html):
        title = re.sub(r"<[^>]+>", "", m.group(2))
        results.append({"title": title, "url": m.group(1)})
        if len(results) >= 8:
            break
    return {"query": query, "results": results}


@tool("modify_fingerprint", "修改指纹文件为合法新值（先备份原文件；文本文件直接写，二进制文件必须 encoding='base64' 传 base64 内容；必须确认并说明原因）",
      RISK_HIGH, ["path", "new_value", "reason", "encoding"])
def _modify_fingerprint(path, new_value="", reason="", encoding="text"):
    """修改指纹文件为新值（先隔离备份，再写盘，最后回读验证）。

    检修（2026-08-27 T3）：旧实现一律文本模式写盘——对 DIPS/SharedStorage 等
    SQLite 二进制指纹文件会把整库写坏。现检测到内容含 NUL 时拒绝 text 写入，
    二进制改写必须显式 encoding='base64' 并传 base64 编码的新内容。"""
    import shutil
    p = os.path.abspath(path)
    from modules import screener
    if screener._is_protected_fs_path(p):
        return {"error": "拒绝修改系统/项目目录内的文件: %s" % p}
    if not os.path.isfile(p):
        return {"error": "文件不存在: %s" % p}
    if not new_value:
        return {"error": "必须提供 new_value（合法替换值）"}
    encoding = str(encoding or "text").strip().lower()
    if encoding not in ("text", "base64"):
        return {"error": "encoding 只支持 text 或 base64"}
    # 二进制防线：已有内容含 NUL 视为二进制
    binary_like = False
    try:
        with open(p, "rb") as f:
            binary_like = b"\x00" in f.read(8192)
    except OSError:
        pass
    if encoding == "text" and binary_like:
        return {"error": "目标是二进制文件（内容含 NUL，如 SQLite 库）：text 写入会损毁；"
                         "确需改写请 encoding='base64' 且 new_value 传 base64 内容",
                "path": p}
    if encoding == "base64":
        import base64 as _b64
        try:
            payload = _b64.b64decode(new_value, validate=True)
        except Exception as e:
            return {"error": "base64 解码失败: %s" % e}
        if not payload:
            return {"error": "base64 内容为空"}
    # 备份
    qdir = os.path.join(config.ROOT, "backups", "quarantine",
                        time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6])
    os.makedirs(qdir, exist_ok=True)
    backup = os.path.join(qdir, os.path.basename(p))
    shutil.copy2(p, backup)
    # 写盘
    try:
        if encoding == "base64":
            with open(p, "wb") as f:
                f.write(payload)
        else:
            with open(p, "w", encoding="utf-8") as f:
                f.write(new_value)
    except Exception as e:
        return {"error": "写盘失败: %s" % e, "backup": backup}
    # 回读验证
    try:
        if encoding == "base64":
            with open(p, "rb") as f:
                written = f.read()
            written_match = written == payload
        else:
            with open(p, "r", encoding="utf-8") as f:
                written_match = f.read() == new_value
    except Exception:
        written_match = None
    db.audit("agent.modify_fingerprint", "path=%s backup=%s enc=%s" % (p, backup, encoding))
    return {"ok": True, "path": p, "backup": backup, "encoding": encoding,
            "written_match": written_match,
            "hint": "修改完成；如软件不信任，可从备份恢复: %s" % backup}


@tool("remove_file", "删除文件（先隔离备份；必须确认并说明原因）", RISK_HIGH, ["path", "reason"])
def _remove_file(path, reason=""):
    p = os.path.abspath(path)
    from modules import screener
    if screener._is_protected_fs_path(p):
        return {"error": "拒绝删除系统/项目目录内的文件: %s" % p}
    if not os.path.isfile(p):
        return {"error": "文件不存在: %s" % p}
    qdir = os.path.join(config.ROOT, "backups", "quarantine",
                        time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6])
    os.makedirs(qdir, exist_ok=True)
    shutil.copy2(p, os.path.join(qdir, os.path.basename(p)))
    os.remove(p)
    db.audit("agent.remove_file", "path=%s quarantine=%s" % (p, qdir))
    return {"ok": True, "removed": p, "quarantine": qdir}


@tool("recycle_file", "将文件移入系统回收站（可随时从回收站还原；必须确认并说明原因）",
      RISK_HIGH, ["path", "reason"])
def _recycle_file(path, reason=""):
    """移入回收站（FOF_ALLOWUNDO），比硬删多一层系统级撤销保障。

    说明：若目标盘未启用回收站或被策略禁用，该调用会显式失败而非静默硬删；
    需要确定性删除时请改用 remove_file（带项目内隔离备份）。
    """
    import ctypes
    from ctypes import wintypes
    p = os.path.abspath(path)
    from modules import screener
    if screener._is_protected_fs_path(p):
        return {"error": "拒绝移除系统/项目目录内的文件: %s" % p}
    if not os.path.isfile(p):
        return {"error": "文件不存在: %s" % p}

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", ctypes.c_uint),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_uint16),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    FO_DELETE = 3
    flags = (0x40 |   # FOF_ALLOWUNDO —— 进回收站而非物理删除
             0x10 |   # FOF_NOCONFIRMATION
             0x04 |   # FOF_SILENT
             0x400)   # FOF_NOERRORUI
    op = SHFILEOPSTRUCTW()
    op.hwnd = None
    op.wFunc = FO_DELETE
    # 检修（2026-08-27 T1）：SHFileOperationW 的 pFrom 契约是「双 \0 终止」的
    # 路径列表；旧实现单 \0 让 API 读越界到堆上相邻内存（经典碰巧能跑），
    # 轻则操作失败、重则把垃圾字符串当路径处理。ctypes 会再补一个终止符，
    # 此处写两个 \0 后缓冲为 p\0\0\0，符合契约且多余终止符无害。
    op.pFrom = p + "\0\0"
    op.pTo = None
    op.fFlags = flags
    code = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    if code != 0 or op.fAnyOperationsAborted:
        return {"error": "移入回收站失败(code=%d aborted=%s)"
                        % (code, bool(op.fAnyOperationsAborted)),
                "hint": "可能被占用/保护/盘未启用回收站；需要强删请用 remove_file"}
    db.audit("agent.recycle_file", "path=%s" % p)
    return {"ok": True, "recycled": p,
            "hint": "已进回收站，如需找回请在回收站搜索原路径后还原"}


# ---------------- 指纹溯源实验组（变量消去法工作流） ----------------
# 方法论：快照 → 删除/篡改目标字段 → 重启目标软件 → 对比重建值。
#   重建值 = 原值 → ID 由幸存锚点确定性派生（用 derive_probe 继续找派生链）
#   重建值 ≠ 原值 → 随机生成或云端下发；再用"篡改后是否被接受"判定文件持久化 vs 服务器侧
_EXPERIMENT_ROOT = os.path.join(config.ROOT, "backups", "experiments")
_ID_KEY_HINTS = ("machineid", "machine_id", "deviceid", "device_id", "devdeviceid",
                 "installationid", "installation_id", "sqmid", "clientid",
                 "client_id", "userid", "user_id", "uuid", "token", "auth",
                 "session", "license", "machineguid")


def _walk_limited(root, max_depth):
    for base, dirs, files in os.walk(root):
        depth = base[len(root):].count(os.sep)
        if depth > max_depth:
            dirs[:] = []
            continue
        yield base, dirs, files


@tool("hunt_string", "在目录树内搜索身份字符串（自动尝试 UTF-8 与 UTF-16LE 双编码），返回命中文件清单——用于定位某 ID 还缓存在哪些文件里", RISK_READ,
      ["needles", "roots", "max_depth"])
def _hunt_string(needles, roots=None, max_depth=4):
    if isinstance(needles, str):
        needles = [n.strip() for n in needles.split(",") if n.strip()]
    needles = [str(n) for n in (needles or []) if str(n)]
    if not needles:
        return {"error": "必须提供 needles（字符串或逗号分隔列表）"}
    if not roots:
        # 默认含主目录根：点目录（~/.qoder 等）是常见盲区
        roots = [os.path.expanduser("~"),
                 os.environ.get("APPDATA", ""), os.environ.get("LOCALAPPDATA", ""),
                 os.environ.get("PROGRAMDATA", "")]
    elif isinstance(roots, str):
        roots = [roots]
    hits = {n: [] for n in needles}
    scanned = 0
    skip_dirs = {"node_modules", ".git", "__pycache__", "Cache", "Code Cache",
                 "GPUCache", "CachedData", "DawnGraphiteCache", "DawnWebGPUCache"}
    for root in roots:
        root = os.path.abspath(os.path.expandvars(os.path.expanduser(root or "")))
        if not os.path.isdir(root) or scanned > 20000:
            continue
        for base, dirs, files in _walk_limited(root, int(max_depth or 4)):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for f in files:
                if scanned >= 20000:
                    break
                p = os.path.join(base, f)
                try:
                    if os.path.getsize(p) > 20 * 1024 * 1024:
                        continue
                    with open(p, "rb") as fh:
                        blob = fh.read()
                except OSError:
                    continue
                scanned += 1
                low = blob.lower()
                utf16 = blob.decode("utf-16-le", errors="ignore").lower() \
                    .encode("utf-8", errors="ignore")
                for n in needles:
                    nl = n.lower().encode()
                    if (nl in low or nl in utf16) and len(hits[n]) < 12:
                        hits[n].append(p)
    db.audit("agent.hunt_string", "needles=%d scanned=%d" % (len(needles), scanned))
    return {"ok": True, "scanned_files": scanned, "hits": hits,
            "hint": "命中为空说明该字符串不在这些目录的明文/UTF16 内容中——"
                    "考虑派生生成或仅存服务器侧"}


@tool("json_identity_fields", "解析 JSON 文件，列出疑似身份字段的路径与形状预览（令牌类只给哈希前缀，不回显明文）", RISK_READ, ["path"])
def _json_identity_fields(path):
    p = os.path.abspath(path)
    if not os.path.isfile(p):
        return {"error": "文件不存在: %s" % p}
    try:
        with open(p, encoding="utf-8-sig", errors="replace") as f:
            text = f.read()
        data = json.loads(text)
    except Exception as e:
        return {"error": "JSON 解析失败: %s" % e}

    def shape(v):
        s = str(v)
        if len(s) > 24:
            return "%s...(%d字符, sha:%s)" % (s[:8], len(s),
                                             hashlib.sha256(s.encode()).hexdigest()[:10])
        return s

    fields = []

    def dig(obj, prefix=""):
        if not isinstance(obj, dict):
            return
        for k, v in obj.items():
            kp = k if not prefix else prefix + "." + k
            # VSCode 族 storage.json 用扁平点号键名：键名本身即 telemetry.machineId
            probe = kp.lower().replace("_", "")
            if any(h in probe for h in _ID_KEY_HINTS):
                if isinstance(v, (str, int, float)):
                    fields.append({"key_path": kp, "shape": shape(str(v))})
            elif isinstance(v, dict):
                dig(v, kp)

    dig(data)
    db.audit("agent.json_identity_fields", "path=%s fields=%d" % (p, len(fields)))
    return {"ok": True, "path": p, "fields": fields,
            "note": "扁平点号键(如 telemetry.machineId)是完整键名而非嵌套层级"}


@tool("file_compare", "比较多个文件的大小/sha256/md5/mtime——判定'删除后被重建的值'与'原值'是否相同（相同=确定性派生，不同=随机/云端）", RISK_READ, ["paths"])
def _file_compare(paths):
    if isinstance(paths, str):
        paths = [paths]
    rows = []
    for p in paths or []:
        p = os.path.abspath(os.path.expandvars(p))
        try:
            st = os.stat(p)
            if st.st_size <= MAX_HASH_SIZE:
                sha, md5, _ent = _file_hashes(p)
            else:
                sha, md5 = "", ""
            rows.append({"path": p, "size": st.st_size,
                         "mtime": time.strftime("%Y-%m-%d %H:%M:%S",
                                                time.localtime(st.st_mtime)),
                         "sha256": sha, "md5": md5})
        except OSError as e:
            rows.append({"path": p, "error": str(e)})
    same = None
    shas = {r.get("sha256") for r in rows if r.get("sha256")}
    if len(rows) >= 2 and not any(r.get("error") for r in rows):
        same = len(shas) == 1
    verdict = ("全部同值 -> 确定性派生或原样恢复（ID 不是这个文件本身产生的）"
               if same else
               "存在差异 -> 随机重建或云端重发" if same is not None else "")
    return {"files": rows, "identical": same, "verdict": verdict}


@tool("derive_probe", "指纹派生源探测：用常见哈希族(md5/sha1/sha256/sha512/uuid5 x 多编码大小写变体)把源字符串派生成候选并与目标 ID 比对；sources 传 'auto' 自动收集本机锚点(MachineGuid/SQM/SID/主机名等)", RISK_READ,
      ["target", "sources"])
def _derive_probe(target, sources=None):
    target = str(target or "").strip().lower()
    if not target:
        return {"error": "必须提供 target（待溯源的 ID 值）"}

    def reg_read(path, name):
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
            v, _t = winreg.QueryValueEx(k, name)
            winreg.CloseKey(k)
            return str(v).strip()
        except Exception:
            return ""

    if isinstance(sources, dict):
        src_items = list(sources.items())
    elif isinstance(sources, str) and sources.strip().lower() == "auto":
        sid_raw = ""
        try:
            out = _run_cmd(["whoami", "/user", "/fo", "csv", "/nh"], timeout=15).stdout
            parts = out.strip().split('","')
            if len(parts) >= 2:
                sid_raw = parts[1].strip('"')
        except Exception:
            pass
        src_items = [
            ("MachineGuid", reg_read(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid")),
            ("SQM_MachineId", reg_read(r"SOFTWARE\Microsoft\SQMClient", "MachineId")),
            ("ProductId", reg_read(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                                   "ProductId")),
            ("SID", sid_raw),
            ("hostname", os.environ.get("COMPUTERNAME", "")),
            ("username", os.environ.get("USERNAME", "")),
        ]
    elif isinstance(sources, list):
        src_items = [("s%d" % i, str(s)) for i, s in enumerate(sources)]
    else:
        src_items = [("source", str(sources or ""))]
    src_items = [(lbl, v) for lbl, v in src_items if v]

    def variants(s):
        s = str(s)
        stripped = s.strip("{}").strip()
        out = {}
        for label, val in (("原文", s), ("去花括号", stripped),
                           ("大写", stripped.upper()), ("小写", stripped.lower()),
                           ("去横线", stripped.replace("-", ""))):
            for enc in ("utf-8", "utf-16-le"):
                out["%s|%s" % (label, enc)] = val.encode(enc, errors="ignore")
        return out

    matches = []
    tried = 0
    for lbl, raw in src_items:
        for vlabel, data_bytes in variants(raw).items():
            for algo in ("md5", "sha1", "sha256", "sha512"):
                tried += 1
                hv = hashlib.new(algo, data_bytes).hexdigest().lower()
                if hv == target:
                    matches.append("%s 的 %s(%s)" % (lbl, algo, vlabel))
        plain = raw.strip("{}")
        for ns_name, ns in (("dns", uuid.NAMESPACE_DNS), ("oid", uuid.NAMESPACE_OID)):
            tried += 1
            try:
                if str(uuid.uuid5(ns, plain)).lower() == target:
                    matches.append("%s 的 uuid5_%s" % (lbl, ns_name))
            except Exception:
                pass
    db.audit("agent.derive_probe", "target_len=%d sources=%d tried=%d hit=%d" % (
        len(target), len(src_items), tried, len(matches)))
    return {"ok": True, "tried_variants": tried, "matches": matches,
            "verdict": ("找到派生链: " + "; ".join(matches)) if matches
            else "常见哈希族未命中 -> 派生源可能是加盐组合/WMI 硬件信息/服务器下发"}


@tool("experiment_backup", "实验前快照：把若干文件复制到 backups/experiments/<时间戳>/ 并写 manifest，绝不改动原文件。做任何篡改/删除实验前必须先调用", RISK_CMD,
      ["paths", "reason"])
def _experiment_backup(paths, reason=""):
    if isinstance(paths, str):
        paths = [paths]
    if not paths:
        return {"error": "必须提供 paths"}
    if len((reason or "").strip()) < 12:
        return {"error": "必须说明至少 12 字的实验原因"}
    exp_dir = os.path.join(_EXPERIMENT_ROOT,
                           time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6])
    os.makedirs(exp_dir, exist_ok=True)
    saved = []
    for p in paths or []:
        p = os.path.abspath(os.path.expandvars(p))
        if not os.path.isfile(p):
            saved.append({"path": p, "error": "不存在"})
            continue
        dest = os.path.join(exp_dir, uuid.uuid4().hex[:8] + "_" + os.path.basename(p))
        shutil.copy2(p, dest)
        saved.append({"path": p, "backup": dest, "sha256": _file_hashes(p)[0]})
    manifest = {"created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "reason": reason, "items": saved}
    mpath = os.path.join(exp_dir, "manifest.json")
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    db.audit("agent.experiment_backup", "dir=%s items=%d" % (exp_dir, len(saved)))
    return {"ok": True, "experiment_dir": exp_dir, "manifest": mpath, "items": saved}


@tool("json_edit_field", "JSON 字段手术（篡改实验核心）：field 支持扁平点号键名(telemetry.devDeviceId)或嵌套路径(a.b.c)；mode=delete 删除该键 / mode=set 设为新值。安全门：同一文件必须先前已 experiment_backup 过", RISK_HIGH,
      ["path", "field", "mode", "value", "reason"])
def _json_edit_field(path, field, mode="set", value="", reason=""):
    p = os.path.abspath(os.path.expandvars(path))
    if mode not in ("delete", "set"):
        return {"error": "mode 只能是 delete 或 set"}
    if mode == "set" and str(value) == "":
        return {"error": "mode=set 必须提供 value"}
    if not field:
        return {"error": "必须提供 field"}
    if len((reason or "").strip()) < 12:
        return {"error": "必须说明至少 12 字的实验原因"}
    # 安全门：查 experiments 备份清单确认此文件做过快照
    backed = False
    exp_root = _EXPERIMENT_ROOT
    if os.path.isdir(exp_root):
        for dirpath, _dirs, files in os.walk(exp_root):
            if "manifest.json" not in files:
                continue
            try:
                mf = json.load(open(os.path.join(dirpath, "manifest.json"),
                                    encoding="utf-8"))
            except Exception:
                continue
            for it in mf.get("items", []):
                if os.path.normcase(str(it.get("path", ""))) == os.path.normcase(p):
                    backed = True
                    break
            if backed:
                break
    if not backed:
        return {"error": "安全门：该文件尚未 experiment_backup 快照，拒绝篡改。"
                         "请先调用 experiment_backup"}
    from modules import screener as _scr
    if _scr._is_protected_fs_path(p):
        return {"error": "拒绝修改系统/项目目录内的文件: %s" % p}
    try:
        with open(p, encoding="utf-8-sig", errors="replace") as f:
            text = f.read()
        data = json.loads(text)
    except Exception as e:
        return {"error": "JSON 解析失败: %s" % e}
    # 检修（2026-09-14）：set 分支此前只会写字面量扁平键——嵌套路径 (a.b.c) 会在
    # 顶层造出一个 "a.b.c" 假键，嵌套值原封不动，后续对比实验结论全部作废。
    # 语义与 delete 分支对齐：扁平键优先，缺失时按嵌套路径回退。
    # 检修（2026-09-19）：三个 nested 助手必须先于 existed_before 探测定义——
    # 旧顺序在 field 非顶层键时调 get_nested 抛 UnboundLocalError，
    # set 嵌套回退从未生效，delete 嵌套分支也被一并打死。
    def get_nested(obj, parts):
        cur = obj
        for part in parts[:-1]:
            if not isinstance(cur, dict) or part not in cur:
                return False, None
            cur = cur[part]
        if isinstance(cur, dict) and parts[-1] in cur:
            return True, cur[parts[-1]]
        return False, None

    def set_nested(obj, parts, val):
        # 检修（2026-09-14）：加标量父级守卫——原实现对标量调 .get 会 AttributeError。
        cur = obj
        for part in parts[:-1]:
            if not isinstance(cur, dict):
                return False
            if not isinstance(cur.get(part), dict):
                cur[part] = {}
            cur = cur[part]
        if not isinstance(cur, dict):
            return False
        cur[parts[-1]] = val
        return True

    def del_nested(obj, parts):
        cur = obj
        for part in parts[:-1]:
            if not isinstance(cur, dict) or part not in cur:
                return False
            cur = cur[part]
        if isinstance(cur, dict) and parts[-1] in cur:
            del cur[parts[-1]]
            return True
        return False

    existed_before = field in data
    if not existed_before:
        existed_before = get_nested(data, field.split("."))[0]

    changed = False
    if mode == "delete":
        if field in data:  # 扁平键优先（VSCode 族 storage.json 形态）
            del data[field]
            changed = True
        else:
            changed = del_nested(data, field.split("."))
        if not changed and not existed_before:
            return {"error": "字段不存在（无论扁平或嵌套）: %s" % field}
    else:
        parts = field.split(".")
        if field in data:  # 扁平键优先（VSCode 族 storage.json 形态，与 delete 分支一致）
            old = data[field]
            data[field] = value
        else:
            found, nested_old = get_nested(data, parts)
            old = nested_old if found else "(不存在)"
            if not set_nested(data, parts, value):
                return {"error": "嵌套路径的父级不是对象，无法按嵌套写入: %s" % field}
        changed = True
    try:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
    except Exception as e:
        return {"error": "写盘失败(可从 experiment 目录恢复): %s" % e}
    db.audit("agent.json_edit_field", "path=%s field=%s mode=%s" % (p, field, mode))
    return {"ok": True, "path": p, "field": field, "mode": mode,
            "existed_before": existed_before,
            "old_shape": ("已删除" if mode == "delete" else str(old)[:40] if mode == "set"
                          else ""),
            "hint": "下一步：重启目标软件后再用 file_compare / json_identity_fields "
                    "对比重建值——同值=派生，异值=随机/云端"}


# ========== 软件指纹深度排查工具集 ==========

@tool("hunt_software_fingerprint", "动态发现任意软件在机器上留下的所有身份指纹（不依赖模式库；"
      "monitor_duration>0 会启动观察器监控，需用户确认）", RISK_CMD,
      ["keyword", "monitor_duration", "reason"])
def _hunt_software_fingerprint(keyword, monitor_duration=0, reason=""):
    """对任意软件，自动产出类似 Qoder目录说明.md 级别的完整排查报告。

    流程：注册表深度扫描 → 文件痕迹发现 → 身份语义提取 → 跨来源关联 → 影响评估。
    """
    from modules.screener.identity_hunt import hunt_software_fingerprint
    from core.redact import redact_secrets
    try:
        monitor_duration = max(0, min(int(monitor_duration or 0), 300))
    except (TypeError, ValueError):
        monitor_duration = 0
    # 检修（2026-09-19）：registry_hits 是注册表原始值明文——工具输出直接进
    # LLM 会话/审计，与"值脱敏才出边界"自家承诺冲突（FreqErr §30 同坑残留出口，
    # redact 本轮补 UUID/GUID 形状规则后对 36 字符锚点真正生效）。
    return redact_secrets(hunt_software_fingerprint(keyword, monitor_duration))


@tool("deep_registry_scan", "注册表深度扫描（全根键，不止 Software）", RISK_READ,
      ["keyword"])
def _deep_registry_scan(keyword):
    """遍历 HKCU/HKLM/HKU/HKCR 下的关键路径，找含关键词的键值。
    包括 DeveloperTools、SQMClient、Run、Services 等。
    """
    from modules.screener.identity_hunt import deep_registry_scan
    from core.redact import redact_secrets
    return redact_secrets(deep_registry_scan(keyword))


@tool("scan_system_anchors", "系统锚点扫描：不依赖关键词，扫描已知的系统级注册表路径", RISK_READ, [])
def _scan_system_anchors():
    """扫描 DeveloperTools、SQMClient、Cryptography 等系统级锚点。
    这些锚点跨重装存活，是"主犯"级别的标识来源。
    """
    from modules.screener.identity_hunt import scan_system_anchors
    from core.redact import redact_secrets
    return redact_secrets(scan_system_anchors())


@tool("extract_identity_semantics", "从文件列表中提取身份标识并分类语义", RISK_READ,
      ["paths"])
def _extract_identity_semantics(paths):
    """不止提取 UUID，还识别登录态、遥测、安装标识等。
    
    paths: 文件路径列表（JSON 数组或逗号分隔字符串）。
    """
    from modules.screener.identity_hunt import extract_identity_semantics, sanitize_findings
    from core.redact import redact_secrets
    if isinstance(paths, str):
        paths = json.loads(paths) if paths.startswith("[") else paths.split(",")
    # 检修（2026-09-19）：findings 里 values[].raw 是文件原文身份值——模块契约
    # （identity_hunt:270）明确"raw 仅模块内使用，sanitize 后才出边界"，
    # 此前工具出口直接透传，raw 明文进了 LLM 会话。
    return redact_secrets(sanitize_findings(extract_identity_semantics(paths)))


@tool("correlate_identity_sources", "跨来源关联：文件↔注册表，判定谁是主谁是从", RISK_READ,
      ["file_findings", "reg_findings"])
def _correlate_identity_sources(file_findings, reg_findings):
    """判定注册表值与文件内容的关系：注册表是主，文件是从（缓存）。
    
    file_findings: extract_identity_semantics 的输出。
    reg_findings: deep_registry_scan 的输出。
    """
    from modules.screener.identity_hunt import correlate_identity_sources
    if isinstance(file_findings, str):
        file_findings = json.loads(file_findings)
    if isinstance(reg_findings, str):
        reg_findings = json.loads(reg_findings)
    return correlate_identity_sources(file_findings, reg_findings)


# 检修（2026-09-14）：从 RISK_READ 升级 RISK_CMD——monitor_duration>0 会真实启动
# 观察器监控进程行为（红线："观察器控制"属读写工具，须用户逐次确认）；
# duration 钳制 0~300s，防模型传 999999 永久挂死 run_task 工作线程。
@tool("monitor_identity_access", "运行时监控：监控进程对文件/注册表的访问，发现动态身份标识（需用户确认）",
      RISK_CMD, ["process_name", "duration", "reason"])
def _monitor_identity_access(process_name, duration=30, reason=""):
    """使用 watcher 监控进程行为，发现运行时才读取/写入的身份标识。

    process_name: 进程名（如 Qoder.exe）。
    duration: 监控时长（秒，上限 300）。
    """
    from modules.screener.identity_hunt import monitor_identity_access
    from core.redact import redact_secrets
    try:
        duration = max(0, min(int(duration or 0), 300))
    except (TypeError, ValueError):
        duration = 0
    # 检修（2026-09-19）：identity_access 条目 detail 含注册表变化值明文，
    # 与 watcher_status 同规则出口脱敏。
    return redact_secrets(monitor_identity_access(process_name, duration))


@tool("assess_identity_impact", "影响评估 + 处理建议", RISK_READ,
      ["findings", "correlation"])
def _assess_identity_impact(findings, correlation):
    """评分逻辑：语义权重 + 跨来源一致性 + 动态访问频率。
    处理建议：可删/可篡改/谨慎/不动。
    """
    from modules.screener.identity_hunt import assess_identity_impact
    if isinstance(findings, str):
        findings = json.loads(findings)
    if isinstance(correlation, str):
        correlation = json.loads(correlation)
    return assess_identity_impact(findings, correlation)


# ========== 调查案例管理工具集 ==========

@tool("create_investigation_case", "创建新的软件指纹调查案件", RISK_READ,
      ["software_name", "description"])
def _create_investigation_case(software_name, description=""):
    """创建新的调查案件，开始一次完整的软件指纹排查。
    返回 case_id，后续所有证据/动作/进度都关联到此案件。
    """
    from modules.screener.investigation_case import create_case
    return create_case(software_name, description)


@tool("list_investigation_cases", "列出所有调查案件", RISK_READ, ["status"])
def _list_investigation_cases(status=None):
    """列出所有调查案件，可按状态过滤（active/closed）。
    """
    from modules.screener.investigation_case import list_cases
    return list_cases(status)


@tool("get_investigation_case", "获取案件详情", RISK_READ, ["case_id"])
def _get_investigation_case(case_id):
    """获取案件详情，包括证据数量、动作数量、进度等。
    """
    from modules.screener.investigation_case import get_case
    return get_case(int(case_id))


@tool("add_investigation_evidence", "添加线索/证据到案件", RISK_READ,
      ["case_id", "evidence_type", "path", "name"])
def _add_investigation_evidence(case_id, evidence_type, path, name,
                                 value_preview="", source="", semantic_type="",
                                 impact_score=0.5, status="pending"):
    """添加一条线索/证据到案件。
    
    evidence_type: file/registry/process/content
    source: deep_registry_scan/hunt_string/monitor/manual
    semantic_type: device_id/machine_id/login_state/telemetry/...
    impact_score: 0-1 影响力评分
    status: pending/confirmed/false_positive/cleaned
    """
    from modules.screener.investigation_case import add_evidence
    return add_evidence(int(case_id), evidence_type, path, name, value_preview,
                        source, semantic_type, float(impact_score), status)


@tool("list_investigation_evidence", "列出案件的所有证据", RISK_READ,
      ["case_id", "status"])
def _list_investigation_evidence(case_id, status=None):
    """列出案件的所有证据，可按状态过滤。
    """
    from modules.screener.investigation_case import list_evidence
    return list_evidence(int(case_id), status)


@tool("update_evidence_status", "更新证据状态", RISK_READ,
      ["case_id", "evidence_id", "status"])
def _update_evidence_status(case_id, evidence_id, status, notes=""):
    """更新证据状态（pending/confirmed/false_positive/cleaned）。
    """
    from modules.screener.investigation_case import update_evidence_status
    return update_evidence_status(int(case_id), int(evidence_id), status, notes)


@tool("record_investigation_action", "记录处理动作及其效果", RISK_READ,
      ["case_id", "evidence_id", "action_type"])
def _record_investigation_action(case_id, evidence_id, action_type, action_detail="",
                                  result="", effect="", snapshot_path=""):
    """记录对证据的处理动作及其效果。
    
    action_type: delete/modify/monitor/backup/restore
    result: success/failure
    effect: rebuilt/unchanged/crashed/regenerated
    """
    from modules.screener.investigation_case import record_action
    return record_action(int(case_id), int(evidence_id), action_type, action_detail,
                         result, effect, snapshot_path)


@tool("list_investigation_actions", "列出案件的所有处理动作", RISK_READ, ["case_id"])
def _list_investigation_actions(case_id):
    """列出案件的所有处理动作。
    """
    from modules.screener.investigation_case import list_actions
    return list_actions(int(case_id))


@tool("update_investigation_progress", "更新排查进度", RISK_READ,
      ["case_id", "step_name", "status"])
def _update_investigation_progress(case_id, step_name, status, result_summary=""):
    """更新案件排查进度。
    
    step_name: registry_scan/file_scan/monitor/cleanup/...
    status: pending/running/done
    """
    from modules.screener.investigation_case import update_progress
    return update_progress(int(case_id), step_name, status, result_summary)


@tool("get_investigation_progress", "获取案件排查进度", RISK_READ, ["case_id"])
def _get_investigation_progress(case_id):
    """获取案件排查进度。
    """
    from modules.screener.investigation_case import get_progress
    return get_progress(int(case_id))


@tool("generate_investigation_report", "生成完整的排查报告", RISK_READ, ["case_id"])
def _generate_investigation_report(case_id):
    """生成完整的排查报告（类似 Qoder目录说明.md）。
    包括：案件摘要、排查进度、证据链、处理效果。
    """
    from modules.screener.investigation_case import generate_report
    return generate_report(int(case_id))


@tool("close_investigation_case", "关闭调查案件", RISK_READ,
      ["case_id", "conclusion"])
def _close_investigation_case(case_id, conclusion=""):
    """关闭案件，记录结论。
    """
    from modules.screener.investigation_case import close_case
    return close_case(int(case_id), conclusion)


@tool("run_full_investigation", "运行完整的软件指纹调查（一键流程）", RISK_READ,
      ["software_name", "keyword"])
def _run_full_investigation(software_name, keyword=None):
    """一键运行完整的软件指纹调查流程。

    流程：建案 → 注册表深度扫描 → 系统锚点 → 文件管线 → 跨来源关联
    → 影响评估 → 证据入库 → 报告。

    检修（2026-08-27 T10）：旧实现先自跑 deep_registry_scan 又调
    hunt_software_fingerprint（内部再跑一次注册表扫描）——同一关键词扫两遍；
    且 file 证据的 value_preview 取不存在的字段恒为空。现改用
    file_identity_pipeline 单次扫描 + 评估后分数 + masked 值预览。
    """
    from modules.screener import identity_hunt as ih
    from modules.screener.investigation_case import (
        create_case, add_evidence, update_progress, generate_report
    )

    if keyword is None:
        keyword = software_name
    # 检修（2026-09-19）：keyword<2 时 deep_registry_scan 返回 {"error":...}——
    # 旧代码直接对错误封套迭代崩在 h.get，且案件已建→遗留 running 孤儿。
    # 守卫必须在 create_case 之前。
    if len(str(keyword or "").strip().lower()) < 2:
        return {"error": "关键词至少 2 字符（空/单字符会把整树值当命中倾倒）"}

    case = create_case(software_name, "自动生成的 %s 指纹调查" % software_name)
    case_id = case["case_id"]

    update_progress(case_id, "registry_scan", "running")
    reg_results = ih.deep_registry_scan(keyword)
    from core.redact import redact_secrets
    for path, hits in reg_results.items():
        if not isinstance(hits, list):
            continue  # 预留键（truncated 等）
        for h in hits:
            # 检修（2026-09-14）：注册表原始值不再明文入库（value_preview 契约
            # 是"脱敏预览"，与文件侧 sanitize_findings 对齐）。
            add_evidence(case_id, "registry", path, h.get("name", ""),
                         redact_secrets(h.get("data", "")), "deep_registry_scan",
                         "device_id" if h.get("is_uuid") else "",
                         0.9 if h.get("is_uuid") else 0.7, "pending")
    update_progress(case_id, "registry_scan", "done",
                    "发现 %d 个注册表痕迹%s" % (
                        sum(len(v) for v in reg_results.values()
                            if isinstance(v, list)),
                        "（预算截断，非全量）" if reg_results.get("truncated")
                        else ""))

    update_progress(case_id, "system_anchor_scan", "running")
    anchors = ih.scan_system_anchors()
    for path, info in anchors.items():
        add_evidence(case_id, "registry", path, info.get("name", ""),
                     redact_secrets(info.get("data", "")), "scan_system_anchors",
                     "device_id", 1.0, "pending")
    update_progress(case_id, "system_anchor_scan", "done",
                    "发现 %d 个系统锚点" % len(anchors))

    update_progress(case_id, "file_scan", "running")
    # 检修：锚点并入关联输入——deviceid↔telemetry.devDeviceId 同值关系
    # 只有把锚点喂进 correlate 才能现形
    reg_all = dict(reg_results)
    reg_all.update({k: [v] for k, v in anchors.items()})
    pipe = ih.file_identity_pipeline(keyword)
    correlation = ih.correlate_identity_sources(pipe["findings"], reg_all)
    assessed = ih.sanitize_findings(
        ih.assess_identity_impact(pipe["findings"], correlation))
    for f in assessed[:50]:
        vals = f.get("values") or []
        preview = vals[0].get("masked", "") if vals else ""
        add_evidence(case_id, "file", f.get("path", ""), f.get("semantic", ""),
                     preview, "file_identity_pipeline", f.get("semantic", ""),
                     f.get("impact_score", 0.5), "pending")
    update_progress(case_id, "file_scan", "done",
                    "扫描 %d 文件，语义命中 %d，跨来源同值 %d" % (
                        pipe["scanned_files"], len(assessed),
                        len((correlation or {}).get("cross_references") or [])))

    update_progress(case_id, "report_generation", "running")
    report = generate_report(case_id)
    update_progress(case_id, "report_generation", "done", "报告已生成")

    return {
        "ok": True,
        "case_id": case_id,
        "software_name": software_name,
        "summary": report["summary"],
        "report": report,
    }
