"""Agent 工具白名单 + 风险分级。

风险分级：
  read  只读/检索/分析 —— reviewer 放行即执行
  cmd   运行本地命令    —— reviewer 审核；deny 则用户审批
  high  删除/联网等副作用 —— 必须用户确认（隔离备份/逐次确认）

命令安全：argv 列表执行（无 shell）、超时、黑名单永拒。
删除安全：先复制到 backups/quarantine/<ts>/ 再删，仅精确匹配文件路径。
"""
import csv
import hashlib
import json
import os
import re
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
    try:
        rx = re.compile(pattern or "", re.IGNORECASE)
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


def _run_cmd(argv, timeout=20):
    flags = 0
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        flags = subprocess.CREATE_NO_WINDOW
    proc = subprocess.run(argv, capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
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
    # 注册表 Run 项指向不存在的路径
    try:
        from modules import regscan
        for it in regscan.autostart_points(root="HKLM"):
            data = it.get("data") or ""
            m = re.search(r'"?([A-Za-z]:[^",\s]+\.exe)?"?', data, re.I)
            if m and m.group(1):
                target = m.group(1).strip('"')
                if not os.path.exists(target):
                    report["issues"].append({"type": "dangling_autostart",
                                             "detail": "%s -> %s" % (it.get("key"), target)})
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


@tool("run_command", "运行白名单系统命令（必须说明可审查原因）", RISK_CMD, ["command", "reason"])
def _run_command(command, reason=""):
    argv = (command or "").split()
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
        # 所有开关参数逐一校验（防 /all /release 夹带破坏性动词）
        IPCONFIG_SAFE = {"all", "displaydns"}
        for a in argv[1:]:
            if a.startswith("/"):
                sub = a[1:].lower()
                if sub not in IPCONFIG_SAFE:
                    return {"error": "ipconfig 仅允许查询开关（/all /displaydns），拒绝 %s" % a}
            elif not a.startswith("-"):
                return {"error": "ipconfig 不接受位置参数: %s" % a}
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
        p = _run_cmd(argv, timeout=int(config.section("agent", {}).get("cmd_timeout", 30)))
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


@tool("modify_fingerprint", "修改指纹文件为合法新值（先备份原文件；必须确认并说明原因）",
      RISK_HIGH, ["path", "new_value", "reason"])
def _modify_fingerprint(path, new_value="", reason=""):
    """修改指纹文件为新值（先隔离备份，再写盘，最后回读验证）。"""
    import shutil
    p = os.path.abspath(path)
    from modules import screener
    if screener._is_protected_fs_path(p):
        return {"error": "拒绝修改系统/项目目录内的文件: %s" % p}
    if not os.path.isfile(p):
        return {"error": "文件不存在: %s" % p}
    if not new_value:
        return {"error": "必须提供 new_value（合法替换值）"}
    # 备份
    qdir = os.path.join(config.ROOT, "backups", "quarantine",
                        time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6])
    os.makedirs(qdir, exist_ok=True)
    backup = os.path.join(qdir, os.path.basename(p))
    shutil.copy2(p, backup)
    # 写盘
    try:
        with open(p, "w", encoding="utf-8") as f:
            f.write(new_value)
    except Exception as e:
        return {"error": "写盘失败: %s" % e, "backup": backup}
    # 回读验证
    try:
        with open(p, "r", encoding="utf-8") as f:
            written = f.read()
    except Exception:
        written = None
    db.audit("agent.modify_fingerprint", "path=%s backup=%s" % (p, backup))
    return {"ok": True, "path": p, "backup": backup,
            "written_match": written == new_value if written is not None else None,
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
    op.pFrom = p + "\0"
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
    existed_before = field in data

    def set_nested(obj, parts, val):
        cur = obj
        for part in parts[:-1]:
            if not isinstance(cur.get(part), dict):
                cur[part] = {}
            cur = cur[part]
        cur[parts[-1]] = val

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
        old = data.get(field, "(不存在)")
        data[field] = value
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
