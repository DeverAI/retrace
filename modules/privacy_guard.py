"""Privacy Guard: observable isolation and recoverable system-change controls.

This module deliberately avoids DLL injection, global user-mode hooks and any
modification of third-party application binaries. Host-side Event Log evidence
is detection-after-access; actual prevention is provided by Windows Sandbox.
"""
import ctypes
import base64
import csv
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from ctypes import wintypes

from core import audit, config, db, logger
from core.coerce import strict_bool as _strict_bool

SUB_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)
CONFIRMATION_PHRASE = "我已审查并批准"
PLAN_TTL_SEC = 600
MAX_STAGE_FILES = 5000
MAX_STAGE_BYTES = 2 * 1024 * 1024 * 1024

_plan_lock = threading.Lock()
_scope_lock = threading.Lock()  # registry_scopes 读-改-写 + config.save() 的串行化
_plans = {}
_approvals = {}
_sid_cache = ""
_maintenance_stop = threading.Event()
_maintenance_thread = None

PROTECTED_RULES = [
    {"id": "machine_guid", "category": "system_identifier", "severity": "high",
     "label": "Windows MachineGuid", "needles": ("SOFTWARE\\MICROSOFT\\CRYPTOGRAPHY\\MACHINEGUID",)},
    {"id": "bios_identity", "category": "hardware_identifier", "severity": "high",
     "label": "BIOS/主板身份", "needles": ("HARDWARE\\DESCRIPTION\\SYSTEM\\BIOS", "SYSTEMSERIALNUMBER")},
    {"id": "disk_identity", "category": "hardware_identifier", "severity": "high",
     "label": "磁盘身份/挂载映射", "needles": ("SYSTEM\\MOUNTEDDEVICES", "PHYSICALDRIVE", "HARDDISKVOLUME")},
    {"id": "computer_name", "category": "system_identifier", "severity": "medium",
     "label": "计算机名", "needles": ("CONTROL\\COMPUTERNAME", "TCPIP\\PARAMETERS\\HOSTNAME")},
    {"id": "network_identity", "category": "network_identifier", "severity": "high",
     "label": "网卡身份/MAC 覆盖值", "needles": ("CONTROL\\CLASS\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
                                              "NETWORKADDRESS")},
    {"id": "windows_product", "category": "system_identifier", "severity": "high",
     "label": "Windows 产品身份", "needles": ("DIGITALPRODUCTID", "PRODUCTID")},
]

_REGISTRY_DENY = (
    "HKLM\\SYSTEM", "HKLM\\HARDWARE", "HKLM\\SAM", "HKLM\\SECURITY",
    "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS", "HKLM\\SOFTWARE\\CLASSES",
    "HKLM\\SOFTWARE\\POLICIES", "HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS",
    "HKCU\\SOFTWARE\\CLASSES", "HKCU\\SOFTWARE\\POLICIES",
)
_REGISTRY_DENY_SEGMENTS = (
    "\\CLASSES", "\\POLICIES", "\\WINDOWS", "\\RUN", "\\RUNONCE",
    "\\APP PATHS", "\\CLSID", "\\INTERFACE", "\\TYPELIB", "\\PROTOCOLS",
)


def _run(argv, timeout=30, hidden=True):
    return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout,
                          creationflags=SUB_FLAGS if hidden else 0)


def _normalize_registry(value):
    text = str(value or "").strip().strip('"').replace("/", "\\").upper()
    if text.startswith("\\REGISTRY\\MACHINE\\"):
        text = "HKLM\\" + text[len("\\REGISTRY\\MACHINE\\"):]
    elif text.startswith("HKEY_LOCAL_MACHINE\\"):
        text = "HKLM\\" + text[len("HKEY_LOCAL_MACHINE\\"):]
    elif text.startswith("HKEY_CURRENT_USER\\"):
        text = "HKCU\\" + text[len("HKEY_CURRENT_USER\\"):]
    return re.sub(r"\\+", r"\\", text)


def protected_rules():
    return [{k: v for k, v in rule.items() if k != "needles"}
            for rule in PROTECTED_RULES]


def match_sensitive(value):
    normalized = _normalize_registry(value)
    matches = []
    for rule in PROTECTED_RULES:
        if any(needle in normalized for needle in rule["needles"]):
            matches.append({k: v for k, v in rule.items() if k != "needles"})
    return matches


def _event_fingerprint(kind, detail, data):
    stable = json.dumps({"type": kind, "detail": detail, "data": data},
                        ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def annotate_events(task, source_events):
    """Create explicit alerts from sensitive registry/file evidence."""
    alerts = []
    for event in source_events:
        data = event.get("data") or {}
        target = data.get("key") or data.get("path") or event.get("detail", "")
        rules = match_sensitive(target)
        if not rules:
            continue
        confidence = data.get("confidence", "unknown")
        operation = data.get("operation") or data.get("action") or "access"
        for rule in rules:
            detail = "APP 涉及受保护内容: %s (%s)" % (rule["label"], operation)
            payload = {
                "rule_id": rule["id"], "category": rule["category"],
                "protected_label": rule["label"], "operation": operation,
                "target": target, "pid": data.get("pid"),
                "image": data.get("image") or data.get("process") or task.get("exe_path", ""),
                "provider": data.get("provider") or event.get("source", ""),
                "confidence": confidence, "blocked": False,
                "protection_state": "detected_after_access",
                "reason": ("宿主审计日志是访问后证据；只有隔离容器/AppContainer/签名过滤驱动"
                           "能在访问前可靠阻止"),
                "source_fingerprint": event.get("fingerprint", ""),
            }
            alerts.append({"type": "privacy.alert", "detail": detail, "data": payload,
                           "severity": rule["severity"], "source": "privacy_guard",
                           "fingerprint": _event_fingerprint("privacy.alert", detail, payload)})
    return alerts


def _is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _sandbox_executable():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    path = os.path.join(root, "System32", "WindowsSandbox.exe")
    return path if os.path.isfile(path) else ""


def _powershell_executable():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    path = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return path if os.path.isfile(path) else ""


def capabilities():
    from modules import activity
    sandbox = _sandbox_executable()
    appcontainer = False
    if os.name == "nt":
        try:
            userenv = ctypes.WinDLL("userenv.dll")
            appcontainer = bool(getattr(userenv, "CreateAppContainerProfile", None))
        except (OSError, AttributeError):
            pass
    event_caps = activity.capabilities()
    return {
        "sandbox": {"available": bool(sandbox), "path": sandbox,
                    "isolates_host_registry_and_files": bool(sandbox),
                    "guest_telemetry": False, "full_hardware_anonymity": False,
                    "note": "强隔离模式不声称隐藏全部 CPU/GPU/计时特征"},
        "appcontainer": {"api_available": appcontainer,
                         "implemented": False,
                         "note": "兼容性验证后再开放；传统桌面 APP 可能无法直接运行"},
        "host_registry_driver": {"implemented": False,
                                 "note": "需签名内核 RegistryCallback 驱动，本版本不安装"},
        "registry_observation": {
            "exact_read": bool(event_caps.get("exact_registry_read")),
            "exact_write": bool(event_caps.get("exact_registry_write")),
            "summary": event_caps.get("summary", ""),
        },
        "system_restore": {"available": bool(_powershell_executable()),
                           "elevated": _is_admin(),
                           "note": "Windows 每 24 小时通常只允许创建一个 Checkpoint-Computer 还原点"},
        "canvas_guard": {"available": os.path.isfile(os.path.join(
            config.ROOT, "extension", "canvas_guard.js")), "default": "off",
            "scope": "ReTrace Chrome/Edge 扩展"},
        "mac_privacy": {"mode": "windows_random_hardware_address",
                        "direct_driver_override": False,
                        "note": "仅打开 Windows 官方设置，不自动写 NetworkAddress"},
        "limitations": [
            "宿主 Event Log 告警发生在访问之后，不等同于事前阻断",
            "WMI/IOCTL 磁盘序列号读取无法仅靠 Security 4663 完整观察",
            "不注入第三方 APP，不修改其二进制，不篡改 BIOS/磁盘/MachineGuid",
            "Sandbox 强隔离下宿主追踪看不到 guest 内访问；不把它声称为内部审计",
            "管理员 ACL + 拒写共享句柄保护 staging；无法防御已获得同等管理员权限的宿主进程",
        ],
    }


def task_report(task_id, limit=1000):
    task = db.get_tracking_task(int(task_id))
    if not task:
        raise KeyError("任务不存在: %s" % task_id)
    rows = db.tracking_events(int(task_id), min(max(int(limit), 1), 2000))
    sensitive, dependencies = [], {}
    for row in rows:
        data = row.get("data") or {}
        target = data.get("key") or data.get("path") or ""
        if row.get("type") == "privacy.alert" or match_sensitive(target):
            sensitive.append(row)
        if str(row.get("type", "")).startswith("registry") and target:
            item = dependencies.setdefault(target, {"key": target, "operations": set(),
                                                     "confidence": set(), "count": 0})
            item["operations"].add(data.get("operation") or data.get("action") or "access")
            item["confidence"].add(data.get("confidence", "unknown"))
            item["count"] += int(row.get("count") or 1)
    dep_rows = []
    for item in dependencies.values():
        item["operations"] = sorted(item["operations"])
        item["confidence"] = sorted(item["confidence"])
        dep_rows.append(item)
    dep_rows.sort(key=lambda x: (-x["count"], x["key"]))
    return {"task": {"id": task["id"], "name": task["name"],
                     "target": task.get("exe_path") or task.get("process_name")},
            "sensitive_access": sensitive[:300], "registry_dependencies": dep_rows[:500],
            "warning": "依赖报告是审计证据/关联线索，不应据此自动删除系统项"}


def mac_randomization_status():
    """Read-only WLAN capability hint; never writes a driver MAC override."""
    if os.name != "nt":
        return {"supported_os": False, "changed": False}
    try:
        proc = _run(["netsh.exe", "wlan", "show", "drivers"], timeout=15)
        output = (proc.stdout or proc.stderr)[-8000:]
        return {"supported_os": proc.returncode == 0, "changed": False,
                "official_mode": "Windows random hardware addresses (Wi-Fi only)",
                "driver_report": output,
                "limitations": ["不覆盖以太网、VPN、蓝牙或永久地址读取",
                                "设备/驱动/组策略可能不支持，企业 NAC 可能限制"]}
    except Exception as exc:
        return {"supported_os": False, "changed": False, "error": str(exc)}


def _sandbox_preview(exe_path, network=False, clipboard=False, memory_mb=4096,
                     mapped_folder=""):
    exe = os.path.abspath(os.path.expandvars(str(exe_path or "")))
    if not os.path.isfile(exe) or not exe.lower().endswith(".exe"):
        raise ValueError("必须指定存在的 EXE 文件")
    name = os.path.basename(exe)
    if any(ch in name for ch in "&|<>^%!\r\n"):
        raise ValueError("EXE 文件名含 Sandbox 启动命令不支持的字符")
    memory_mb = max(2048, min(int(memory_mb), 16384))
    root = ET.Element("Configuration")
    for tag, value in (("VGpu", "Disable"),
                       ("Networking", "Enable" if network else "Disable"),
                       ("AudioInput", "Disable"), ("VideoInput", "Disable"),
                       ("PrinterRedirection", "Disable"),
                       ("ClipboardRedirection", "Enable" if clipboard else "Disable"),
                       ("ProtectedClient", "Enable"), ("MemoryInMB", str(memory_mb))):
        ET.SubElement(root, tag).text = value
    mapped = ET.SubElement(ET.SubElement(root, "MappedFolders"), "MappedFolder")
    ET.SubElement(mapped, "HostFolder").text = mapped_folder or "[启动时创建的 ReTrace staging 副本]"
    ET.SubElement(mapped, "SandboxFolder").text = r"C:\ReTraceSource"
    ET.SubElement(mapped, "ReadOnly").text = "true"
    command = ('cmd.exe /d /s /c "robocopy C:\\ReTraceSource C:\\ReTraceWork /E /R:0 /W:0 '
               '/NFL /NDL /NJH /NJS >nul &amp; start "" /wait "C:\\ReTraceWork\\%s""' % name)
    # ElementTree escapes XML metacharacters; keep the actual command unescaped here.
    command = command.replace("&amp;", "&")
    logon = ET.SubElement(root, "LogonCommand")
    ET.SubElement(logon, "Command").text = command
    ET.indent(root, space="  ")
    xml = ET.tostring(root, encoding="unicode")
    return {"exe_path": exe, "network": bool(network), "clipboard": bool(clipboard),
            "memory_mb": memory_mb, "xml": xml,
            "mode": "strong_isolation_no_guest_telemetry",
            "guarantees": ["只读映射专用 staging 副本", "在沙箱内部副本运行", "不修改第三方 APP 文件"],
            "limitations": ["宿主追踪看不到 guest 内注册表/DNS/文件访问，不能列举沙箱内部访问尝试",
                            "未验证隐藏所有 CPU/GPU/计时特征", "APP 可能检测到虚拟化环境",
                            "依赖驱动/服务/宿主安装状态的 APP 可能无法运行"]}


# _strict_bool 已统一至 core.coerce.strict_bool（模块顶部导入）


def sandbox_preview(exe_path, network=False, clipboard=False, memory_mb=4096):
    return _sandbox_preview(exe_path, _strict_bool(network), _strict_bool(clipboard),
                            memory_mb)


def build_sandbox_test_plan(exe_path, network=False, memory_mb=4096):
    """生成"沙箱指纹对照实验"的完整材料：可直接保存的 .wsb + 分步操作清单。

    目的：验证目标 APP 在隔离环境中会留下哪些身份产物、宿主清理后是否会再生。
    纯只读规划函数，不执行任何操作；运行沙箱由用户手动双击 .wsb 完成。
    """
    preview = _sandbox_preview(exe_path, _strict_bool(network), False,
                               memory_mb)
    exe_name = os.path.basename(preview["exe_path"])
    checklist = [
        {"step": 1, "phase": "host_baseline",
         "action": "在宿主记录基线：运行 screener.scan_machine_fingerprints 与 "
                   "scan_ai_tool_traces，再调用 screener.fingerprint_drift_report(commit=True)。",
         "why": "没有宿主基线就无法判定哪些痕迹是本实验新产生的"},
        {"step": 2, "phase": "guest_setup",
         "action": "把下方 wsb_xml 保存为 test.wsb 并双击启动 Windows Sandbox"
                   "（需专业版；首次启动约 1-3 分钟）。",
         "why": "guest 内的所有写入在关闭时销毁，宿主零污染"},
        {"step": 3, "phase": "guest_run",
         "action": "在沙箱内安装并运行 %s，正常使用 5-10 分钟（登录/联网按实验目的决定，"
                   "network=%s）。" % (exe_name, preview["network"]),
         "why": "部分身份产物只在首次登录/激活后才写出"},
        {"step": 4, "phase": "guest_scan",
         "action": "在 guest 内用同一份 ReTrace 源码目录运行 "
                   "python -c \"from modules.screener import scan_machine_fingerprints, scan_ai_tool_traces; print(scan_ai_tool_traces()['summary'], scan_machine_fingerprints()['summary'])\" "
                   "并导出 JSON 结果到 C:\\ReTraceSource\\..\\guest_result.json（映射目录可带出）。",
         "why": "对照 guest 命中清单与宿主基线，识别 APP 的全部身份写入点"},
        {"step": 5, "phase": "regen_probe",
         "action": "在 guest 内删除命中的指纹文件 → 重启 APP → 再次扫描。"
                   "若文件以相同内容回来 = 存在云端恢复机制（本地清理无效的铁证）。",
         "why": "这正是 fingerprint_drift_report 的 recreated_same_value 信号的手工验证版"},
        {"step": 6, "phase": "teardown",
         "action": "关闭沙箱（全部丢弃）→ 宿主再次运行 fingerprint_drift_report() 确认无新增漂移。",
         "why": "闭环验证实验本身没有向宿主引入新痕迹"},
    ]
    return {"ok": True, "exe_path": preview["exe_path"],
            "network": preview["network"], "memory_mb": preview["memory_mb"],
            "wsb_xml": preview["xml"], "checklist": checklist,
            "mode": preview["mode"], "limitations": preview["limitations"]}


def _require_reason(reason):
    text = str(reason or "").strip()
    if len(text) < 12 or len(text) > 1000:
        raise ValueError("系统操作原因必须为 12-1000 字符，供用户明确审查")
    return text


def _registry_evidence(task_id, root, subkey, value_name=""):
    """子树级精确证据门：近 24h 内该任务有 exact Security/Sysmon 对该子树（含其下
    值）的注册表事件即放行。当前事件数据不携带值名，无法做"精确值级"证明，
    故门禁语义如实表述为子树级（value_name 参数保留供未来事件带值名时收紧）。"""
    wanted = _normalize_registry(root + "\\" + subkey)
    wanted_tail = wanted.split("\\", 1)[-1]
    current_sid = _current_user_sid()
    task = db.get_tracking_task(int(task_id))
    if not task:
        return False
    for row in db.tracking_events(int(task_id), 2000):
        data = row.get("data") or {}
        if not str(row.get("type", "")).startswith("registry."):
            continue
        if data.get("confidence") != "exact" or str(data.get("provider", "")).lower() not in (
                "security", "sysmon"):
            continue
        try:
            observed_at = time.mktime(time.strptime(row.get("last_seen", ""), "%Y-%m-%d %H:%M:%S"))
        except (TypeError, ValueError):
            continue
        if time.time() - observed_at > 24 * 3600:
            continue
        operation = str(data.get("operation") or data.get("action") or "").lower()
        if operation not in ("read", "query", "enumerate", "write", "set", "create", "delete"):
            continue
        target = _normalize_registry(data.get("key") or data.get("path") or row.get("detail", ""))
        same_hkcu = target == wanted or target.startswith(wanted + "\\")
        native_prefix = "\\REGISTRY\\USER\\%s\\%s" % (current_sid, wanted_tail)
        hku_prefix = "HKU\\%s\\%s" % (current_sid, wanted_tail)
        user_native = (root == "HKCU" and current_sid and
                       (target == native_prefix or target.startswith(native_prefix + "\\") or
                        target == hku_prefix or target.startswith(hku_prefix + "\\")))
        if same_hkcu or user_native:
            return True
    return False


def _current_user_sid():
    global _sid_cache
    if _sid_cache:
        return _sid_cache
    try:
        proc = _run(["whoami.exe", "/user", "/fo", "csv", "/nh"], timeout=10)
        for row in csv.reader(io.StringIO(proc.stdout or "")):
            for item in row:
                item = item.strip().upper()
                if re.fullmatch(r"S-1-(?:\d+-)+\d+", item):
                    _sid_cache = item
                    return item
    except Exception:
        pass
    return ""


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _directory_manifest(root):
    entries, total = [], 0
    root = os.path.abspath(root)
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in list(dirs):
            path = os.path.join(current, name)
            st = os.stat(path, follow_symlinks=False)
            if os.path.islink(path) or getattr(st, "st_file_attributes", 0) & 0x400:
                raise PermissionError("Sandbox staging 拒绝目录重解析点/junction: %s" % path)
        for name in files:
            path = os.path.join(current, name)
            st = os.stat(path, follow_symlinks=False)
            if os.path.islink(path) or getattr(st, "st_file_attributes", 0) & 0x400:
                raise PermissionError("Sandbox staging 拒绝文件重解析点: %s" % path)
            total += int(st.st_size)
            entries.append((os.path.relpath(path, root).replace("/", "\\"),
                            int(st.st_size), _file_sha256(path)))
            if len(entries) > MAX_STAGE_FILES or total > MAX_STAGE_BYTES:
                raise ValueError("APP 目录超过 staging 配额（5000 文件 / 2 GiB）")
    stable = json.dumps(sorted(entries), ensure_ascii=False, separators=(",", ":"))
    return {"directory_manifest_sha256": hashlib.sha256(stable.encode("utf-8")).hexdigest(),
            "stage_file_count": len(entries), "stage_total_bytes": total}


def registry_scopes():
    scopes = (config.section("privacy_guard", {}) or {}).get("registry_scopes", [])
    return [dict(item) for item in scopes if isinstance(item, dict)]


def register_registry_scope(task_id, root, subkey, publisher="", ownership_note="",
                            reason="", confirmation=""):
    """Register an exact human-reviewed HKCU vendor/product subtree; no write occurs."""
    reason = _require_reason(reason)
    if confirmation != CONFIRMATION_PHRASE:
        raise PermissionError("确认短语不匹配，授权范围未登记")
    task = db.get_tracking_task(int(task_id))
    if not task:
        raise KeyError("任务不存在")
    root = str(root or "").upper()
    subkey = str(subkey or "").strip().strip("\\")
    full = _normalize_registry(root + "\\" + subkey)
    parts = subkey.split("\\")
    if root != "HKCU" or len(parts) < 3 or parts[0].upper() != "SOFTWARE":
        raise PermissionError("首版仅允许登记 HKCU\\Software\\厂商\\产品 及更深子树")
    if (any(full.startswith(prefix) for prefix in _REGISTRY_DENY) or
            any(segment in full for segment in _REGISTRY_DENY_SEGMENTS) or
            match_sensitive(full)):
        raise PermissionError("启动、COM、策略、Windows 核心或系统身份范围禁止登记")
    ownership_note = str(ownership_note or "").strip()
    if len(ownership_note) < 12:
        raise ValueError("必须说明厂商/产品所有权证据及为何可安全修改")
    exe_path = task.get("exe_path") or ""
    if not exe_path or not os.path.isfile(exe_path):
        raise ValueError("任务必须绑定存在的 EXE，才能固定授权对象指纹")
    scope = {"task_id": int(task_id), "root": root, "subkey": subkey,
             "publisher": str(publisher or "").strip(),
             "ownership_note": ownership_note, "reason": reason,
             "exe_path": os.path.abspath(exe_path), "exe_sha256": _file_sha256(exe_path),
             "registered_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    cfg = config.get()
    section = cfg.setdefault("privacy_guard", {})
    # 读-改-写与 config.save() 必须持锁串行：Web 为 ThreadingHTTPServer 多线程，
    # 两个并发登记（或与撤销/开关保存并发）会丢更新或撕裂 deepcopy 快照。
    with _scope_lock:
        scopes = section.setdefault("registry_scopes", [])
        scopes[:] = [item for item in scopes if not (
            int(item.get("task_id", 0)) == int(task_id) and
            _normalize_registry(item.get("root", "") + "\\" + item.get("subkey", "")) == full)]
        scopes.append(scope)
        config.save()
    audit.record("privacy.registry_scope", scope, actor="user",
                 resource="task:%s" % task_id, risk="high")
    return {"ok": True, "scope": scope, "writes_performed": False}


def _matching_scope(task_id, root, subkey):
    wanted = _normalize_registry(root + "\\" + subkey)
    task = db.get_tracking_task(int(task_id))
    for scope in registry_scopes():
        prefix = _normalize_registry(scope.get("root", "") + "\\" + scope.get("subkey", ""))
        if int(scope.get("task_id", 0)) != int(task_id) or not (
                wanted == prefix or wanted.startswith(prefix + "\\")):
            continue
        exe = task.get("exe_path") if task else ""
        if exe and os.path.isfile(exe) and _file_sha256(exe) == scope.get("exe_sha256"):
            return scope
    return None


def remove_registry_scope(task_id, subkey, reason="", confirmation=""):
    """撤销已登记的 HKCU 厂商/产品注册表授权范围（人工确认 + 审计）。"""
    reason = _require_reason(reason)
    if confirmation != CONFIRMATION_PHRASE:
        raise PermissionError("确认短语不匹配，授权范围未撤销")
    task = db.get_tracking_task(int(task_id))
    if not task:
        raise KeyError("任务不存在")
    subkey = str(subkey or "").strip().strip("\\")
    wanted = _normalize_registry("HKCU\\" + subkey)
    cfg = config.get()
    section = cfg.setdefault("privacy_guard", {})
    with _scope_lock:
        scopes = section.get("registry_scopes", []) or []
        remaining = []
        removed = None
        for scope in scopes:
            if not isinstance(scope, dict):
                continue
            prefix = _normalize_registry(scope.get("root", "") + "\\" + scope.get("subkey", ""))
            if (int(scope.get("task_id", 0)) == int(task_id) and prefix == wanted):
                removed = scope
            else:
                remaining.append(scope)
        if removed is None:
            raise KeyError("未找到匹配的登记范围")
        section["registry_scopes"] = remaining
        config.save()
    audit.record("privacy.registry_scope_remove",
                 {"task_id": int(task_id), "subkey": subkey, "reason": reason},
                 actor="user", resource="task:%s" % task_id, risk="high")
    return {"ok": True, "removed": removed}


def _validate_registry_args(args):
    root = str(args.get("root") or "").upper()
    subkey = str(args.get("subkey") or "").strip().strip("\\")
    value_name = str(args.get("value_name") or "")
    task_id = int(args.get("task_id") or 0)
    if root != "HKCU" or not subkey.upper().startswith("SOFTWARE\\"):
        raise PermissionError("首版默认禁止 HKLM；只允许已登记的 HKCU APP 私有 Software 子树")
    full = _normalize_registry(root + "\\" + subkey)
    if any(full.startswith(prefix) for prefix in _REGISTRY_DENY) or match_sensitive(full + "\\" + value_name):
        raise PermissionError("系统身份/Windows 核心/网络驱动注册表项禁止修改")
    if any(segment in full for segment in _REGISTRY_DENY_SEGMENTS):
        raise PermissionError("启动、COM、协议、策略等共享注册表范围禁止修改")
    if not value_name or len(value_name) > 260 or len(subkey) > 1000:
        raise ValueError("必须指定合法的精确值名和子键")
    if not _registry_evidence(task_id, root, subkey, value_name):
        raise PermissionError("该 APP 任务近 24 小时没有 exact Security/Sysmon 注册表证据，拒绝修改")
    if not _matching_scope(task_id, root, subkey):
        raise PermissionError("该精确厂商/产品子树尚未由用户登记，或 APP 指纹已变化")
    state = _registry_value_state(root, subkey, value_name)
    return {"root": root, "subkey": subkey, "value_name": value_name,
            "task_id": task_id, "registry_view": "64", "before_state": state}


def _registry_value_state(root, subkey, value_name):
    if os.name != "nt":
        return {"exists": False, "unsupported_os": True}
    import winreg
    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    try:
        with winreg.OpenKey(_registry_root(root), subkey, 0, access) as key:
            return _registry_value_state_from_key(key, value_name)
    except FileNotFoundError:
        return {"exists": False}


def _registry_value_state_from_key(key, value_name):
    import winreg
    try:
        value, value_type = winreg.QueryValueEx(key, value_name)
    except FileNotFoundError:
        return {"exists": False}
    last_write = winreg.QueryInfoKey(key)[2]
    stable = json.dumps({"value": value, "type": value_type, "last_write": last_write},
                        ensure_ascii=False, sort_keys=True, default=str)
    return {"exists": True, "type": value_type, "value": value,
            "last_write": last_write,
            "sha256": hashlib.sha256(stable.encode("utf-8")).hexdigest()}


def _validate_action(action, args):
    args = dict(args or {})
    if action == "launch_sandbox":
        preview = sandbox_preview(args.get("exe_path"), args.get("network"),
                                  args.get("clipboard"), args.get("memory_mb", 4096))
        manifest = _directory_manifest(os.path.dirname(preview["exe_path"]))
        clean = {k: preview[k] for k in ("exe_path", "network", "clipboard", "memory_mb")}
        clean.update({"exe_sha256": _file_sha256(preview["exe_path"]), **manifest})
        return clean
    if action in ("registry_delete_value", "registry_set_string"):
        clean = _validate_registry_args(args)
        if action == "registry_set_string":
            value = str(args.get("new_value") or "")
            if len(value) > 4000:
                raise ValueError("新值过长")
            clean["new_value"] = value
        return clean
    if action in ("create_restore_point", "open_wifi_privacy_settings"):
        return {}
    raise ValueError("不支持的系统操作: %s" % action)


def _action_steps(action):
    if action == "launch_sandbox":
        return ["生成只读映射 WSB profile", "启动 Windows Sandbox", "APP 在沙箱内部副本运行"]
    if action in ("registry_delete_value", "registry_set_string"):
        return ["创建 Windows 系统还原点", "DPAPI 加密备份精确目标值（30 天保留）",
                "重验值类型/内容/键时间避免计划过期", "执行单个注册表值变更并回读验证", "写入审计链"]
    if action == "create_restore_point":
        return ["请求 Windows 创建 MODIFY_SETTINGS 系统还原点"]
    return ["打开 Windows Wi-Fi 随机硬件地址设置；由用户手动选择"]


def _safe_action_args(args):
    safe = json.loads(json.dumps(args or {}, ensure_ascii=False, default=str))
    state = safe.get("before_state")
    if isinstance(state, dict):
        state.pop("value", None)
    if "new_value" in safe:
        raw = str(args.get("new_value") or "")
        safe["new_value"] = {"length": len(raw),
                             "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest()}
    return safe


def _public_plan(plan):
    public = dict(plan)
    public.pop("confirmation_phrase", None)
    public["args"] = json.loads(json.dumps(plan.get("args", {}),
                                            ensure_ascii=False, default=str))
    state = public["args"].get("before_state")
    if isinstance(state, dict):
        state.pop("value", None)
    return public


def plan_system_action(action, args=None, reason=""):
    reason = _require_reason(reason)
    clean = _validate_action(str(action), args or {})
    token = secrets.token_urlsafe(24)
    now = time.time()
    plan = {"token": token, "action": str(action), "args": clean, "reason": reason,
            "steps": _action_steps(str(action)), "created_at": now,
            "expires_at": now + PLAN_TTL_SEC, "confirmation_phrase": CONFIRMATION_PHRASE,
            "status": "pending"}
    with _plan_lock:
        _plans[token] = plan
        for old_token, old in list(_plans.items()):
            if old["expires_at"] < now:
                _plans.pop(old_token, None)
    audit.record("privacy.plan", {"action": action, "args": _safe_action_args(clean), "reason": reason,
                                  "expires_at": plan["expires_at"]}, actor="user",
                 resource="privacy_guard", risk="high")
    return _public_plan(plan)


def _plan_digest(plan):
    stable = json.dumps({"action": plan["action"], "args": plan["args"],
                         "reason": plan["reason"], "expires_at": plan["expires_at"]},
                        ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def approve_system_action(token, confirmation="", reason="", approval_context="gui"):
    """Convert a proposal into a one-use capability after trusted UI interaction."""
    if confirmation != CONFIRMATION_PHRASE:
        raise PermissionError("确认短语不匹配，系统操作未批准")
    now = time.time()
    with _plan_lock:
        plan = _plans.get(str(token))
        if not plan or plan["expires_at"] < now:
            _plans.pop(str(token), None)
            raise PermissionError("审批计划不存在或已过期")
        if str(reason or "").strip() != plan["reason"]:
            raise PermissionError("批准原因与预案不一致")
        approval = secrets.token_urlsafe(32)
        _approvals[approval] = {"plan": dict(plan), "digest": _plan_digest(plan),
                                "approved_at": now, "expires_at": plan["expires_at"],
                                "approval_context": str(approval_context or "gui")[:100]}
        _plans.pop(str(token), None)
    audit.record("privacy.approve", {"action": plan["action"], "reason": plan["reason"],
                                      "digest": _plan_digest(plan),
                                      "approval_context": approval_context},
                 actor="user", resource="privacy_guard", risk="high")
    return {"approval_token": approval, "action": plan["action"],
            "reason": plan["reason"], "expires_at": plan["expires_at"],
            "one_use": True}


def _create_restore_point():
    powershell = _powershell_executable()
    if not powershell:
        raise RuntimeError("Windows PowerShell/System Restore 不可用")
    if not _is_admin():
        raise PermissionError("创建系统还原点需要以管理员身份运行 ReTrace")
    description = "ReTrace Privacy Guard %s" % time.strftime("%Y-%m-%d %H:%M")
    script = "Checkpoint-Computer -Description '%s' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop" % description
    proc = _run([powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=120)
    if proc.returncode != 0:
        raise RuntimeError("系统还原点创建失败: %s" % (proc.stderr or proc.stdout)[-1000:])
    return {"description": description, "created": True}


def _registry_root(root):
    import winreg
    return winreg.HKEY_CURRENT_USER if root == "HKCU" else winreg.HKEY_LOCAL_MACHINE


def _harden_dir_acl(path, include_current_user=True):
    username = os.environ.get("USERNAME", "").strip()
    domain = os.environ.get("USERDOMAIN", "").strip()
    principal = (domain + "\\" + username) if domain and username else username
    if include_current_user and not principal:
        raise RuntimeError("无法确定当前 Windows 用户，拒绝创建可能泄露数据的注册表备份")
    argv = ["icacls.exe", path, "/inheritance:r"]
    if include_current_user:
        argv.extend(["/grant:r", principal + ":(OI)(CI)F"])
    argv.extend(["/grant:r", "*S-1-5-32-544:(OI)(CI)F",
                 "/grant:r", "*S-1-5-18:(OI)(CI)F"])
    acl = _run(argv, timeout=30)
    if acl.returncode != 0:
        raise RuntimeError("无法收紧隐私材料 ACL，操作已终止: %s" %
                           (acl.stderr or acl.stdout)[-1000:])
    return True


def _dpapi_protect(payload):
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_uint32),
                    ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
    raw = bytes(payload)
    buf = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
    source = DATA_BLOB(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
    protected = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(source), "ReTrace registry recovery", None, None, None,
        0x01, ctypes.byref(protected))
    if not ok:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(protected.pbData, protected.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(protected.pbData)


def _prune_registry_backups(root, retention_days=30):
    cutoff = time.time() - int(retention_days) * 86400
    if not os.path.isdir(root):
        return
    root = os.path.abspath(root)
    for name in os.listdir(root):
        if not name.startswith("reg_"):
            continue
        path = os.path.abspath(os.path.join(root, name))
        if os.path.commonpath((root, path)) != root or path == root:
            continue
        try:
            if os.path.getmtime(path) < cutoff:
                shutil.rmtree(path)
        except OSError as exc:
            logger.record_err("privacy.registry.prune", exc)


def _registry_backup(root, subkey, value_name, state):
    backup_root = os.path.join(config.ROOT, "backups", "registry")
    os.makedirs(backup_root, exist_ok=True)
    _prune_registry_backups(backup_root, 30)
    backup_id = "reg_%s_%s" % (time.strftime("%Y%m%d_%H%M%S"), secrets.token_hex(3))
    backup_dir = os.path.join(backup_root, backup_id)
    os.makedirs(backup_dir, exist_ok=False)
    _harden_dir_acl(backup_dir, include_current_user=False)
    value = state.get("value")
    if isinstance(value, bytes):
        value = {"encoding": "base64", "data": base64.b64encode(value).decode("ascii")}
    material = {"root": root, "subkey": subkey, "value_name": value_name,
                "registry_view": "64", "exists": bool(state.get("exists")),
                "type": state.get("type"), "value": value,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    encrypted = _dpapi_protect(json.dumps(material, ensure_ascii=False,
                                          separators=(",", ":")).encode("utf-8"))
    outfile = os.path.join(backup_dir, "before.dpapi")
    with open(outfile, "wb") as stream:
        stream.write(encrypted)
    return {"backup_id": backup_id, "encrypted": "Windows DPAPI current user",
            "scope": "single registry value", "retention_days": 30,
            "sha256": hashlib.sha256(encrypted).hexdigest()}


def _execute_registry(action, args):
    import winreg
    current = _registry_value_state(args["root"], args["subkey"], args["value_name"])
    if current != args.get("before_state"):
        raise PermissionError("注册表值在预案创建后发生变化（TOCTOU），拒绝执行")
    if action == "registry_delete_value" and not current.get("exists"):
        raise FileNotFoundError("计划删除的注册表值不存在")
    restore = _create_restore_point()
    backup = _registry_backup(args["root"], args["subkey"], args["value_name"], current)
    access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
    mutated = False
    try:
        with winreg.OpenKey(_registry_root(args["root"]), args["subkey"], 0, access) as key:
            second_check = _registry_value_state_from_key(key, args["value_name"])
            if second_check != current:
                raise PermissionError("注册表值在备份期间发生变化（TOCTOU），拒绝执行")
            if action == "registry_delete_value":
                winreg.DeleteValue(key, args["value_name"])
                change = "deleted"
            else:
                winreg.SetValueEx(key, args["value_name"], 0, winreg.REG_SZ, args["new_value"])
                change = "set_string"
            mutated = True
        after = _registry_value_state(args["root"], args["subkey"], args["value_name"])
        if action == "registry_delete_value" and after.get("exists"):
            raise RuntimeError("删除后回读验证失败")
        if action == "registry_set_string" and (
                not after.get("exists") or after.get("type") != winreg.REG_SZ or
                after.get("value") != args["new_value"]):
            raise RuntimeError("写入后回读验证失败")
    except Exception as main_exc:
        if mutated:
            try:
                with winreg.OpenKey(_registry_root(args["root"]), args["subkey"], 0, access) as key:
                    if current.get("exists"):
                        winreg.SetValueEx(key, args["value_name"], 0,
                                          current["type"], current["value"])
                    else:
                        try:
                            winreg.DeleteValue(key, args["value_name"])
                        except FileNotFoundError:
                            pass
            except Exception as rollback_exc:
                # 回滚失败必须如实上报：此时目标值处于"已变更且未恢复"状态，
                # 只写日志会让用户误以为"操作失败=值未动"。
                logger.record_err("privacy.registry.rollback", rollback_exc)
                raise RuntimeError(
                    "注册表变更失败且自动回滚同样失败（%s）。目标值当前状态未知；"
                    "恢复材料：DPAPI 备份 %s / 系统还原点 %s（backups/registry 与还原点可人工恢复）"
                    % (rollback_exc, backup.get("backup_id", "?"),
                       restore.get("description", "?"))) from rollback_exc
        raise main_exc
    return {"ok": True, "change": change, "backup": backup, "restore_point": restore,
            "target": args["root"] + "\\" + args["subkey"] + "\\" + args["value_name"],
            "verified": True, "registry_view": "64"}


def _execute_sandbox(args):
    sandbox = _sandbox_executable()
    if not sandbox:
        raise RuntimeError("Windows Sandbox 不可用（需要受支持的 Windows 版本并启用可选功能）")
    if not _is_admin():
        raise PermissionError("安全 staging 需要管理员完整性级别，以隔离普通同用户 APP 的写入")
    source_dir = os.path.dirname(args["exe_path"])
    current_manifest = _directory_manifest(source_dir)
    planned_manifest = {k: args[k] for k in (
        "directory_manifest_sha256", "stage_file_count", "stage_total_bytes")}
    if current_manifest != planned_manifest or _file_sha256(args["exe_path"]) != args["exe_sha256"]:
        raise PermissionError("APP 文件或依赖目录在批准后发生变化，拒绝隔离启动")
    run_root = os.path.join(config.ROOT, "backups", "privacy_guard", "runs")
    os.makedirs(run_root, exist_ok=True)
    action_dir = os.path.join(run_root, "%s_%s" % (
        time.strftime("%Y%m%d_%H%M%S"), secrets.token_hex(3)))
    os.makedirs(action_dir, exist_ok=False)
    _harden_dir_acl(action_dir, include_current_user=False)
    staging = os.path.join(action_dir, "staging")
    os.makedirs(staging, exist_ok=False)
    # copytree/_lock_staging_files 任一步失败都要清理整份 staging 副本（配额上限
    # 2 GiB），否则异常一路冒泡后 action_dir 成为无人接管的磁盘残留。
    locked_handles = None
    try:
        shutil.copytree(source_dir, staging, dirs_exist_ok=True)
        if _directory_manifest(staging) != planned_manifest:
            raise PermissionError("staging 内容与批准的逐文件哈希不一致，拒绝启动")
        locked_handles = _lock_staging_files(staging)
        if _directory_manifest(staging) != planned_manifest:
            raise PermissionError("staging 加锁后内容发生变化，拒绝启动")
    except Exception:
        try:
            _close_handles(locked_handles)
        except Exception:
            pass
        try:
            shutil.rmtree(action_dir, ignore_errors=True)
        except Exception:
            pass
        raise
    staged_exe = os.path.join(staging, os.path.basename(args["exe_path"]))
    preview = _sandbox_preview(staged_exe, args["network"], args["clipboard"],
                               args["memory_mb"], mapped_folder=staging)
    profile = os.path.join(action_dir, "sandbox.wsb")
    with open(profile, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(preview["xml"])
    try:
        proc = subprocess.Popen([sandbox, profile])
    except Exception:
        _close_handles(locked_handles)
        shutil.rmtree(action_dir)
        raise
    threading.Thread(target=_cleanup_sandbox_run, args=(proc, action_dir, locked_handles), daemon=True,
                     name="privacy-sandbox-cleanup").start()
    return {"ok": True, "profile": profile, "staging": staging, "launched": True,
            "host_mapping": "read_only_staging_copy", "network": args["network"],
            "guest_telemetry": False, "cleanup": "after Windows Sandbox exits"}


def _lock_staging_files(staging):
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    handles = []
    invalid = ctypes.c_void_p(-1).value
    try:
        for current, _, files in os.walk(staging, followlinks=False):
            for name in files:
                path = os.path.join(current, name)
                handle = kernel32.CreateFileW(path, 0x80000000, 0x00000001,
                                              None, 3, 0x00200000, None)
                if handle == invalid or not handle:
                    raise ctypes.WinError()
                handles.append(handle)
        return handles
    except Exception:
        _close_handles(handles)
        raise


def _close_handles(handles):
    for handle in handles or []:
        try:
            ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            pass


def _cleanup_sandbox_run(proc, action_dir, locked_handles=None):
    try:
        proc.wait()
        _close_handles(locked_handles)
        root = os.path.abspath(os.path.join(config.ROOT, "backups", "privacy_guard", "runs"))
        target = os.path.abspath(action_dir)
        if os.path.commonpath((root, target)) != root or target == root:
            raise RuntimeError("拒绝清理越界 Sandbox staging 路径")
        for _ in range(10):
            try:
                shutil.rmtree(target)
                return
            except OSError:
                time.sleep(1)
        logger.warn("Sandbox staging 未能自动清理: %s" % target)
    except Exception as exc:
        _close_handles(locked_handles)
        logger.record_err("privacy.sandbox.cleanup", exc)


def execute_system_action(approval_token, reason=""):
    now = time.time()
    with _plan_lock:
        approved = _approvals.get(str(approval_token))
        if not approved:
            raise KeyError("一次性批准能力不存在或已使用")
        plan = approved["plan"]
        if approved["expires_at"] < now or approved["digest"] != _plan_digest(plan):
            _approvals.pop(str(approval_token), None)
            raise PermissionError("批准能力已过期或预案摘要不一致")
        if str(reason or "").strip() != plan["reason"]:
            raise PermissionError("执行原因与已审查计划不一致，系统操作未执行")
        _approvals.pop(str(approval_token), None)
    action, args, reason = plan["action"], plan["args"], plan["reason"]
    try:
        if action == "launch_sandbox":
            result = _execute_sandbox(args)
        elif action in ("registry_delete_value", "registry_set_string"):
            result = _execute_registry(action, args)
        elif action == "create_restore_point":
            result = {"ok": True, "restore_point": _create_restore_point()}
        elif action == "open_wifi_privacy_settings":
            os.startfile("ms-settings:network-wifi")
            result = {"ok": True, "opened": "ms-settings:network-wifi",
                      "changed": False, "user_action_required": True}
        else:
            raise ValueError("未知操作")
        audit.record("privacy.execute", {"action": action, "args": _safe_action_args(args), "reason": reason,
                                         "result": result}, actor="user",
                     resource="privacy_guard", risk="high")
        return {"action": action, "reason": reason, **result}
    except Exception as exc:
        logger.record_err("privacy.execute.%s" % action, exc)
        audit.record("privacy.execute", {"action": action, "args": _safe_action_args(args), "reason": reason,
                                         "error": str(exc)}, actor="user",
                     resource="privacy_guard", outcome="error", risk="high")
        return {"ok": False, "action": action, "reason": reason, "error": str(exc)}


def set_canvas_guard(site, enabled=False, reason=""):
    """Toggle the opt-in extension guard; this never edits a website or APP binary."""
    reason = _require_reason(reason)
    enabled = _strict_bool(enabled)
    from modules import browser
    site = str(site or "").strip()
    if not re.match(r"^https?://[^/]+$", site, re.I):
        raise ValueError("必须指定完整顶级站点 origin，例如 https://example.com")
    delivered = browser.send_command("canvas_guard", site=site,
                                     enabled=enabled, reason=reason)
    result = {"ok": bool(delivered), "enabled": bool(enabled), "reason": reason,
              "site": site, "scope": "ReTrace browser extension", "persistent": True,
              "warning": "确定性按站点噪声可能被检测；仅用于降低跨站 Canvas 关联"}
    if not delivered:
        # ok:false 时补可读 error，避免前端 bizErr 落到 String(r) 显示 [object Object]
        result["error"] = "无浏览器扩展连接在线，Canvas 设置未投递"
    audit.record("privacy.canvas_guard", result, actor="user",
                 resource="privacy_guard", risk="medium")
    return result


def register(bus, cfg):
    global _maintenance_thread
    backup_root = os.path.join(config.ROOT, "backups", "registry")
    _prune_registry_backups(backup_root, 30)
    if _maintenance_thread and _maintenance_thread.is_alive():
        return
    _maintenance_stop.clear()
    _maintenance_thread = threading.Thread(target=_maintenance_loop, daemon=True,
                                           name="privacy-backup-retention")
    _maintenance_thread.start()


def _maintenance_loop():
    while not _maintenance_stop.wait(3600):
        _prune_registry_backups(os.path.join(config.ROOT, "backups", "registry"), 30)


def shutdown():
    global _maintenance_thread
    _maintenance_stop.set()
    thread = _maintenance_thread
    _maintenance_thread = None
    if thread and thread is not threading.current_thread():
        thread.join(timeout=2)
    with _plan_lock:
        _plans.clear()
        _approvals.clear()
