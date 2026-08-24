"""Windows process-attributed file, registry and DNS activity collection.

Exact evidence comes from Sysmon/Security event logs. Portable fallbacks are
explicitly labelled correlated so a global machine change is never presented
as a proven action of the tracked process.
"""
import hashlib
import json
import os
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from core import logger

SUB_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"
DNS_CHANNEL = "Microsoft-Windows-DNS-Client/Operational"
SYSMON_IDS = (2, 11, 12, 13, 14, 15, 22, 23, 26)
MAX_EVENTS = 1000
MAX_PAGES_PER_SOURCE = 20

_cap_lock = threading.Lock()
_cap_cache = {"at": 0.0, "value": None}
_query_lock = threading.Lock()
_query_cache = {}


def _decode(data):
    if not data:
        return ""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")) or data[:200].count(b"\x00") > 20:
        try:
            return data.decode("utf-16")
        except UnicodeError:
            pass
    for enc in ("utf-8-sig", "mbcs"):
        try:
            return data.decode(enc)
        except (UnicodeError, LookupError):
            continue
    return data.decode("utf-8", "replace")


def _run_bytes(argv, timeout=20):
    return subprocess.run(argv, capture_output=True, timeout=timeout,
                          creationflags=SUB_FLAGS)


def _event_channels():
    try:
        proc = _run_bytes(["wevtutil", "el"], 20)
        if proc.returncode != 0:
            return set()
        return {line.strip().lower() for line in _decode(proc.stdout).splitlines()
                if line.strip()}
    except (OSError, subprocess.SubprocessError) as exc:
        logger.record_err("activity.channels", exc)
        return set()


def _channel_readable(channel):
    try:
        proc = _run_bytes(["wevtutil", "qe", channel, "/rd:true", "/f:xml", "/c:1"], 12)
        return proc.returncode == 0, _decode(proc.stderr).strip()[:300]
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)[:300]


def _event_is_fresh(row, seconds=900):
    raw = str(row.get("created") or "").strip()
    if not raw:
        return False
    try:
        created = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - created).total_seconds() <= seconds
    except (ValueError, OverflowError):
        return False


def _channel_has_events(channel, event_ids, object_type=""):
    """Return whether the readable channel contains at least one required event."""
    system = "(" + " or ".join(
        "EventID=%d" % int(event_id) for event_id in event_ids) + ")"
    query = "*[System[%s]" % system
    if object_type:
        query += " and EventData[Data[@Name='ObjectType']='%s']" % object_type
    query += "]"
    try:
        proc = _run_bytes(["wevtutil", "qe", channel, "/rd:true", "/f:xml", "/c:1",
                           "/q:%s" % query], 12)
        if proc.returncode != 0:
            return False, _decode(proc.stderr).strip()[:300]
        rows = parse_windows_events(_decode(proc.stdout))
        fresh = any(_event_is_fresh(row) for row in rows)
        return fresh, "" if fresh else ("required_events_not_recent" if rows else "")
    except (OSError, subprocess.SubprocessError, ET.ParseError) as exc:
        return False, str(exc)[:300]


def _channel_registry_operations(channel):
    query = "*[System[(EventID=4663)] and EventData[Data[@Name='ObjectType']='Key']]"
    try:
        proc = _run_bytes(["wevtutil", "qe", channel, "/rd:true", "/f:xml", "/c:30",
                           "/q:%s" % query], 12)
        if proc.returncode != 0:
            return set()
        operations = set()
        for row in parse_windows_events(_decode(proc.stdout)):
            if not _event_is_fresh(row):
                continue
            operation, _labels = _registry_access((row.get("data") or {}).get("AccessMask"))
            operations.add(operation)
        return operations
    except (OSError, subprocess.SubprocessError, ET.ParseError):
        return set()


def capabilities(refresh=False):
    now = time.time()
    with _cap_lock:
        if not refresh and _cap_cache["value"] is not None and now - _cap_cache["at"] < 60:
            return dict(_cap_cache["value"])
    channels = _event_channels()
    result = {}
    for key, channel in (("sysmon", SYSMON_CHANNEL), ("security", SECURITY_CHANNEL),
                         ("dns_log", DNS_CHANNEL)):
        present = channel.lower() in channels
        readable, error = _channel_readable(channel) if present else (False, "channel_not_found")
        result[key] = {"channel": channel, "present": present,
                       "readable": readable, "error": error,
                       "observed_required_events": False}
    probes = {
        "sysmon_file": ("sysmon", (2, 11, 15, 23, 26), ""),
        "sysmon_registry": ("sysmon", (12, 13, 14), ""),
        "sysmon_dns": ("sysmon", (22,), ""),
        "security_file_access": ("security", (4663,), "File"),
        "security_registry_access": ("security", (4663,), "Key"),
    }
    observed = {}
    for probe, (source, event_ids, object_type) in probes.items():
        if result[source]["readable"]:
            found, probe_error = _channel_has_events(result[source]["channel"], event_ids,
                                                      object_type)
        else:
            found, probe_error = False, result[source]["error"]
        observed[probe] = {"event_ids": list(event_ids), "observed": found,
                           "error": probe_error}
    result["observed"] = observed
    registry_operations = (_channel_registry_operations(SECURITY_CHANNEL)
                           if result["security"]["readable"] else set())
    registry_read_observed = "read" in registry_operations
    registry_write_observed = bool(registry_operations.intersection({"write", "delete"}))
    result["observed"]["security_registry_read"] = {
        "event_ids": [4663], "observed": registry_read_observed, "error": ""}
    result["observed"]["security_registry_write"] = {
        "event_ids": [4663], "observed": registry_write_observed, "error": ""}
    result["sysmon"]["observed_required_events"] = any(
        observed[name]["observed"] for name in
        ("sysmon_file", "sysmon_registry", "sysmon_dns"))
    result["security"]["observed_required_events"] = any(
        observed[name]["observed"] for name in
        ("security_file_access", "security_registry_access"))
    result["exact_file"] = bool(observed["sysmon_file"]["observed"] or
                                observed["security_file_access"]["observed"])
    result["exact_registry_write"] = bool(observed["sysmon_registry"]["observed"] or
                                          registry_write_observed)
    result["exact_registry_read"] = registry_read_observed
    result["exact_registry"] = result["exact_registry_write"]
    result["exact_dns"] = bool(observed["sysmon_dns"]["observed"])
    result["fallback_dns"] = True
    result["fallback_registry"] = True
    result["requirements"] = {
        "registry_read": ("精确列出读取/枚举需要管理员可读的 Security 4663、启用 Audit Registry，"
                          "并通过注册表对象 SACL 或全局对象访问审计生成 Key 访问事件；程序不会自动改策略"),
        "registry_write": "Sysmon 12/13/14 或 Security 4663 Key 对象访问事件",
        "dns": "Sysmon 22（含 Image/ProcessId）",
        "file": "Sysmon 文件事件或 Security 4663 File 对象访问事件",
    }
    exact = [name for name, enabled in (
        ("文件", result["exact_file"]), ("注册表写入", result["exact_registry_write"]),
        ("注册表读取", result["exact_registry_read"]), ("DNS", result["exact_dns"])) if enabled]
    readable = [name for name in ("sysmon", "security", "dns_log")
                if result[name]["readable"]]
    if exact:
        result["summary"] = "已观察到精确事件: %s" % ", ".join(exact)
    elif readable:
        result["summary"] = "日志可读但尚未观察到所需事件；当前结果仅作关联推断"
    else:
        result["summary"] = "当前仅关联推断：Sysmon/Security 进程级对象访问日志不可用"
    with _cap_lock:
        _cap_cache.update({"at": now, "value": result})
    return dict(result)


def _query_events(channel, event_ids=None, limit=MAX_EVENTS, after_record=None):
    key = (channel, tuple(event_ids or ()), int(limit), after_record)
    now = time.time()
    if after_record is None:
        # 仅缓存"最新一页"基线查询；分页查询每页 after_record 不同，缓存必失配且
        # 堆积大对象，不做缓存。
        with _query_lock:
            cached = _query_cache.get(key)
            if cached and now - cached[0] < 0.8:
                return None if cached[1] is None else list(cached[1])
    argv = ["wevtutil", "qe", channel,
            "/rd:%s" % ("false" if after_record is not None else "true"),
            "/f:xml", "/c:%d" % limit]
    clauses = []
    if event_ids:
        clauses.append("(" + " or ".join("EventID=%d" % int(i) for i in event_ids) + ")")
    if after_record is not None:
        clauses.append("EventRecordID>%d" % max(0, int(after_record)))
    if clauses:
        argv.insert(3, "/q:*[System[%s]]" % " and ".join(clauses))
    try:
        proc = _run_bytes(argv, 25)
        if proc.returncode != 0:
            message = _decode(proc.stderr).strip()[:500] or "wevtutil exit %d" % proc.returncode
            logger.record_err("activity.query.%s" % channel, RuntimeError(message))
            rows = None
        else:
            rows = parse_windows_events(_decode(proc.stdout))
    except (OSError, subprocess.SubprocessError, ValueError, ET.ParseError) as exc:
        logger.record_err("activity.query.%s" % channel, exc)
        rows = None
    if after_record is None:
        with _query_lock:
            if len(_query_cache) > 500:
                _query_cache.clear()  # 防无界增长（缓存 0.8s TTL，清空影响极小）
            _query_cache[key] = (now, rows)
    return None if rows is None else list(rows)


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def parse_windows_events(xml_text):
    """Parse wevtutil XML into stable dictionaries (also used by fixtures)."""
    text = (xml_text or "").strip().lstrip("\ufeff")
    if not text:
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        cleaned = re.sub(r"<\?xml[^>]*\?>", "", text).strip()
        root = ET.fromstring("<Events>%s</Events>" % cleaned)
    nodes = [root] if _local(root.tag) == "Event" else [n for n in root.iter()
                                                            if _local(n.tag) == "Event"]
    rows = []
    for node in nodes:
        system = next((x for x in node if _local(x.tag) == "System"), None)
        if system is None:
            continue
        values = {}
        event_id = record_id = 0
        created = ""
        provider = ""
        execution_pid = ""
        for item in system:
            tag = _local(item.tag)
            if tag == "EventID":
                try: event_id = int((item.text or "0").strip())
                except ValueError: event_id = 0
            elif tag == "EventRecordID":
                try: record_id = int((item.text or "0").strip())
                except ValueError: record_id = 0
            elif tag == "TimeCreated":
                created = item.attrib.get("SystemTime", "")
            elif tag == "Provider":
                provider = item.attrib.get("Name", "")
            elif tag == "Execution":
                execution_pid = item.attrib.get("ProcessID", "")
        for item in node.iter():
            tag = _local(item.tag)
            if tag == "Data":
                name = item.attrib.get("Name", "")
                if name:
                    values[name] = (item.text or "").strip()
            elif item is not node and item.text and not list(item) and tag not in (
                    "EventID", "EventRecordID", "TimeCreated", "Provider", "Execution"):
                values.setdefault(tag, item.text.strip())
        rows.append({"event_id": event_id, "record_id": record_id, "created": created,
                     "provider": provider, "execution_pid": execution_pid, "data": values})
    return rows


def _int_pid(value):
    try:
        return int(str(value or "0"), 0)
    except ValueError:
        try: return int(str(value or "0"))
        except ValueError: return 0


def _target_identity(task, pids):
    exe = _normalize_image_path(task.get("exe_path") or "")
    name = (task.get("process_name") or os.path.basename(exe)).lower()
    return exe.lower(), os.path.basename(name).lower(), {int(x) for x in pids}


def _normalize_image_path(value):
    path = str(value or "").strip().strip('"')
    if path.startswith("\\??\\"):
        path = path[4:]
    if not path:
        return ""
    return os.path.normcase(os.path.abspath(path)).lower()


def _matches_target(record, task, pids):
    data = record.get("data") or {}
    exe, name, pid_set = _target_identity(task, pids)
    image = (data.get("Image") or data.get("ProcessName") or "").strip().strip('"')
    image_low = _normalize_image_path(image)
    event_pid = _int_pid(data.get("ProcessId") or data.get("ProcessID") or
                         record.get("execution_pid"))
    if exe:
        # A configured full path is the identity boundary. Never accept another
        # binary merely because it has the same basename or a reused PID.
        return bool(image_low and image_low == exe)
    if image_low and name and os.path.basename(image_low).lower() == name:
        return True
    return bool(event_pid and event_pid in pid_set)


def _make_event(kind, detail, data, provider, severity="info", confidence="exact"):
    payload = dict(data or {})
    payload.update({"provider": provider, "confidence": confidence})
    stable = json.dumps({"type": kind, "detail": detail, "data": payload},
                        ensure_ascii=False, sort_keys=True, default=str)
    return {"type": kind, "detail": str(detail)[:2000], "data": payload,
            "severity": severity, "source": provider,
            "fingerprint": hashlib.sha256(stable.encode("utf-8")).hexdigest()}


def _sysmon_event(record):
    eid, data = record["event_id"], record.get("data") or {}
    common = {"record_id": record["record_id"], "time": record.get("created", ""),
              "pid": _int_pid(data.get("ProcessId")), "image": data.get("Image", "")}
    if eid in (2, 11, 15):
        path = data.get("TargetFilename", "")
        return _make_event("file.changed" if eid == 2 else "file.created",
                           "文件活动: %s" % path, {**common, "path": path,
                           "event_id": eid}, "sysmon", "medium")
    if eid in (23, 26):
        path = data.get("TargetFilename", "")
        return _make_event("file.removed", "文件删除: %s" % path,
                           {**common, "path": path, "event_id": eid}, "sysmon", "medium")
    if eid in (12, 13, 14):
        target = data.get("TargetObject", "")
        action = data.get("EventType", "registry")
        action_low = action.lower()
        operation = "delete" if "delete" in action_low else "write"
        return _make_event("registry.%s" % operation,
                           "注册表%s: %s %s" % ("删除" if operation == "delete" else "写入",
                                                action, target),
                           {**common, "key": target, "action": action,
                            "operation": operation,
                            "details": data.get("Details", ""), "event_id": eid},
                           "sysmon", "medium")
    if eid == 22:
        query = data.get("QueryName", "")
        return _make_event("dns", "DNS 查询: %s" % query,
                           {**common, "query": query, "result": data.get("QueryResults", ""),
                            "status": data.get("QueryStatus", ""), "event_id": eid}, "sysmon")
    return None


def _registry_access(access_mask):
    try:
        mask = int(str(access_mask or "0"), 0)
    except ValueError:
        mask = 0
    labels = []
    for bit, label in ((0x0001, "query_value"), (0x0002, "set_value"),
                       (0x0004, "create_subkey"), (0x0008, "enumerate_subkeys"),
                       (0x0010, "notify"), (0x0020, "create_link"),
                       (0x10000, "delete"), (0x20000, "read_control"),
                       (0x40000, "write_dac"), (0x80000, "write_owner")):
        if mask & bit:
            labels.append(label)
    if mask & 0x10000:
        operation = "delete"
    elif mask & (0x0002 | 0x0004 | 0x0020 | 0x40000 | 0x80000):
        operation = "write"
    elif mask & (0x0001 | 0x0008 | 0x0010 | 0x20000):
        operation = "read"
    else:
        operation = "access"
    return operation, labels


def _security_event(record):
    data = record.get("data") or {}
    obj = data.get("ObjectName", "")
    obj_type = (data.get("ObjectType") or "").lower()
    registry = "key" in obj_type or obj.upper().startswith("\\REGISTRY\\")
    mask = data.get("AccessMask", "")
    operation, labels = _registry_access(mask) if registry else ("access", [])
    kind = "registry.%s" % operation if registry else "file.access"
    action_text = {"read": "读取/枚举", "write": "写入", "delete": "删除",
                   "access": "访问"}.get(operation, "访问")
    return _make_event(kind, "%s%s: %s" % (
        "注册表" if registry else "文件", action_text if registry else "访问", obj),
        {"record_id": record["record_id"], "time": record.get("created", ""),
         "key" if registry else "path": obj, "object_type": data.get("ObjectType", ""),
         "operation": operation, "access_labels": labels,
         "access_list": data.get("AccessList", ""), "access_mask": mask,
         "process": data.get("ProcessName", ""),
         "pid": _int_pid(data.get("ProcessId")), "event_id": record.get("event_id")},
        "security", "info" if operation == "read" else "medium")


def _downgrade_identity(event):
    event = dict(event)
    payload = dict(event.get("data") or {})
    payload["confidence"] = "correlated"
    payload["warning"] = ("任务未配置完整 exe 路径，仅按进程名/PID 关联；"
                          "同名进程或 PID 复用可能造成误报")
    event["data"] = payload
    stable = json.dumps({"type": event.get("type"), "detail": event.get("detail"),
                         "data": payload}, ensure_ascii=False, sort_keys=True, default=str)
    event["fingerprint"] = hashlib.sha256(stable.encode("utf-8")).hexdigest()
    return event


def _dns_log_event(record):
    data = record.get("data") or {}
    query = (data.get("QueryName") or data.get("Name") or data.get("HostName") or
             data.get("Query") or "")
    if not query:
        return None
    return _make_event("dns", "DNS 查询: %s" % query,
                       {"record_id": record["record_id"], "time": record.get("created", ""),
                        "query": query, "result": data.get("QueryResults") or data.get("Address", ""),
                        "pid": _int_pid(data.get("ProcessId") or data.get("ProcessID")),
                        "image": data.get("Image") or data.get("ProcessName", "")},
                       "dns_eventlog")


def exact_events(task, pids, checkpoint, caps=None):
    caps = caps or capabilities()
    out, updates, any_backlog = [], {}, False
    sources = []
    if caps["sysmon"]["readable"]:
        sources.append(("sysmon", SYSMON_CHANNEL, SYSMON_IDS, _sysmon_event))
    if caps["security"]["readable"]:
        sources.append(("security", SECURITY_CHANNEL, (4663,), _security_event))
    if caps["dns_log"]["readable"]:
        sources.append(("dns_log", DNS_CHANNEL, None, _dns_log_event))
    for key, channel, ids, convert in sources:
        checkpoint_key = "event_record_%s" % key
        initialized = checkpoint_key in checkpoint
        previous = int(checkpoint.get(checkpoint_key) or 0)
        if not initialized:
            records = _query_events(channel, ids)
            if records is None:
                out.append(_make_event(
                    "collector.warning", "Windows 事件日志查询失败，未建立检查点: %s" % key,
                    {"channel": channel, "warning": "本轮精确行为事件不可用；下轮重试"},
                    "windows_eventlog", "medium", "correlated"))
                continue
            updates[checkpoint_key] = max([r["record_id"] for r in records] or [0])
            continue  # establish a baseline; do not replay old machine history
        cursor = previous
        for page in range(MAX_PAGES_PER_SOURCE):
            records = _query_events(channel, ids, after_record=cursor)
            if records is None:
                out.append(_make_event(
                    "collector.warning", "Windows 事件日志查询失败，未推进当前分页: %s" % key,
                    {"channel": channel, "checkpoint": cursor,
                     "warning": "本轮可能缺少精确行为事件；守护进程将在下轮重试"},
                    "windows_eventlog", "medium", "correlated"))
                break
            if not records:
                # Event logs can be cleared and restart RecordID from a lower value.
                latest = _query_events(channel, ids, limit=1)
                latest_id = max([r["record_id"] for r in (latest or [])] or [0])
                if latest is not None and latest_id and latest_id < cursor:
                    # Restart from zero and process the currently retained records;
                    # treating latest_id as a baseline would drop the first events
                    # written after the log was cleared.
                    cursor = 0
                    updates[checkpoint_key] = 0
                    out.append(_make_event(
                        "collector.warning", "检测到事件日志重置，正在从头续采: %s" % key,
                        {"channel": channel, "before": previous, "latest": latest_id,
                         "warning": "日志清理期间的历史事件可能无法恢复"},
                        "windows_eventlog", "medium", "correlated"))
                    continue
                break
            maximum = max(r["record_id"] for r in records)
            updates[checkpoint_key] = maximum
            for record in sorted(records, key=lambda x: x["record_id"]):
                if record["record_id"] <= cursor or not _matches_target(record, task, pids):
                    continue
                event = convert(record)
                if event:
                    if not task.get("exe_path"):
                        event = _downgrade_identity(event)
                    out.append(event)
            cursor = maximum
            if len(records) < MAX_EVENTS:
                break
        else:
            any_backlog = True
            out.append(_make_event(
                "collector.warning", "Windows 事件日志积压超过单轮追赶上限: %s" % key,
                {"channel": channel, "checkpoint": cursor,
                 "warning": "已安排快速续采；若日志覆盖速度高于消费速度，无法保证零漏采"},
                "windows_eventlog", "high", "correlated"))
    updates["activity_backlog"] = any_backlog
    return out, updates


def dns_snapshot():
    try:
        proc = _run_bytes(["ipconfig", "/displaydns"], 20)
        text = _decode(proc.stdout)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.record_err("activity.dns_cache", exc)
        return None  # 采集失败：调用方必须保留旧基线，不得当作"空缓存"
    names = []
    for raw in text.splitlines():
        line = raw.strip()
        if ":" not in line:
            continue
        low = line.lower()
        if low.startswith("record name") or low.startswith("记录名称"):
            value = line.split(":", 1)[1].strip().rstrip(".").lower()
            if value:
                names.append(value)
    return sorted(set(names))[:5000]


def _registry_matcher(task):
    exe = str(task.get("exe_path") or "").lower().strip().strip('"').replace("/", "\\")
    base = os.path.basename(exe) or str(task.get("process_name") or "").lower().strip()
    base = os.path.basename(base)
    stem = os.path.splitext(base)[0]
    patterns = []
    if base:
        patterns.append(re.compile(r"(?<![\w.-])%s(?![\w.-])" % re.escape(base), re.I))
    if len(stem) >= 5:
        patterns.append(re.compile(r"(?<!\w)%s(?!\w)" % re.escape(stem), re.I))

    def matches(value):
        haystack = str(value or "").lower().replace("/", "\\")
        if exe and exe in haystack:
            return True
        return any(pattern.search(haystack) for pattern in patterns)
    return matches


def registry_snapshot(task):
    """Snapshot target-related values in common persistence/configuration loci."""
    try:
        from modules import regscan
        winreg = regscan.winreg
    except Exception as exc:
        logger.record_err("activity.registry.import", exc)
        return {"values": {}, "truncated": False, "nodes": 0}
    matches = _registry_matcher(task)
    loci = [
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 0),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 0),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 1),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 1),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths", 1),
        ("HKLM", r"SYSTEM\CurrentControlSet\Services", 1),
        ("HKCR", r"Applications", 1),
    ]
    result, nodes, entries, truncated = {}, 0, 0, False
    deadline = time.monotonic() + 2.5

    def visit(root_name, path, depth):
        nonlocal nodes, entries, truncated
        if nodes >= 4000 or time.monotonic() >= deadline:
            truncated = True
            return
        nodes += 1
        try:
            key = regscan._open_key(root_name, path)
        except (OSError, PermissionError):
            return
        try:
            index = 0
            while True:
                if entries >= 20000 or time.monotonic() >= deadline:
                    truncated = True
                    break
                try:
                    name, value, vtype = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                entries += 1
                text = regscan._value_to_str(value)
                haystack = (path + " " + name + " " + text).lower()
                if matches(haystack):
                    result["%s\\%s\\%s" % (root_name, path, name or "(Default)")] = {
                        "sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
                        "length": len(text), "value_type": int(vtype),
                        # Values may contain licenses, credentials or identifiers that
                        # cannot be recognized reliably; persist evidence, not plaintext.
                        "preview": "[REDACTED]",
                    }
            if depth <= 0:
                return
            sub_index = 0
            while True:
                if time.monotonic() >= deadline:
                    truncated = True
                    break
                try: sub = winreg.EnumKey(key, sub_index)
                except OSError: break
                sub_index += 1
                visit(root_name, path + "\\" + sub, depth - 1)
        finally:
            key.Close()

    for root_name, path, depth in loci:
        visit(root_name, path, depth)
    return {"values": result, "truncated": truncated, "nodes": nodes,
            "entries": entries}


def correlated_events(task, pids, checkpoint, use_dns=True, use_registry=True):
    out, updates = [], {}
    if use_dns:
        current = dns_snapshot()
        if current is None:
            # 采集失败：保留旧基线，绝不把失败当"空缓存"制造全量假事件
            if checkpoint.get("dns_cache") and pids:
                out.append(_make_event(
                    "collector.warning", "DNS 缓存采集失败，本轮放弃对比（基线保留）",
                    {"warning": "ipconfig /displaydns 超时或不可用"},
                    "dns_cache", "info", "correlated"))
        else:
            old = set(checkpoint.get("dns_cache") or [])
            if "dns_cache" in checkpoint and pids:
                for name in current:
                    if name not in old:
                        out.append(_make_event("dns", "APP 运行期间出现 DNS 缓存记录: %s" % name,
                                               {"query": name, "warning": "关联推断非确证"},
                                               "dns_cache", "info", "correlated"))
            updates["dns_cache"] = current
    last_registry = float(checkpoint.get("registry_checked_epoch") or 0)
    if use_registry and time.time() - last_registry >= 30:
        snapshot = registry_snapshot(task)
        if isinstance(snapshot, dict) and "values" in snapshot:
            current_reg = snapshot.get("values") or {}
            truncated = bool(snapshot.get("truncated"))
            nodes = int(snapshot.get("nodes") or 0)
            entries = int(snapshot.get("entries") or 0)
        else:  # compatibility with older checkpoints/tests
            current_reg, truncated, nodes, entries = snapshot or {}, False, 0, 0
        old_snapshot = checkpoint.get("registry_related") or {}
        old_reg = old_snapshot.get("values", old_snapshot) if isinstance(old_snapshot, dict) else {}
        # 全空且未截断 = 采集失败（AV/EDR 拦截、权限变更）：
        # 保留旧基线原样写回，绝不清空——否则下一轮会爆"全部消失/全部新增"双向假事件
        scan_failed = (not current_reg and nodes == 0 and entries == 0 and not truncated)
        if scan_failed:
            checkpoint_values = dict(old_reg)
            updates.update({"registry_related": {"values": checkpoint_values,
                                                 "truncated": truncated, "nodes": nodes,
                                                 "entries": entries},
                            "registry_checked_epoch": time.time()})
            if old_reg and pids:
                out.append(_make_event(
                    "collector.warning", "注册表快照采集失败，本轮放弃对比（基线保留）",
                    {"warning": "读取被拦截或键范围不可用"},
                    "registry_snapshot", "medium", "correlated"))
            return out, updates
        if "registry_related" in checkpoint and pids:
            for key, value in current_reg.items():
                if key not in old_reg:
                    out.append(_make_event("registry.related", "发现新的 APP 相关注册表项: %s" % key,
                                           {"key": key, "value": value,
                                            "warning": "相关项变化，不等同于已证明由 APP 写入"},
                                           "registry_snapshot", "medium", "correlated"))
                elif old_reg[key] != value:
                    out.append(_make_event("registry.related", "APP 相关注册表项发生变化: %s" % key,
                                           {"key": key, "before": old_reg[key], "after": value,
                                            "warning": "相关项变化，不等同于已证明由 APP 写入"},
                                           "registry_snapshot", "medium", "correlated"))
            for key in old_reg:
                if not truncated and key not in current_reg:
                    out.append(_make_event("registry.related", "APP 相关注册表项消失: %s" % key,
                                           {"key": key, "warning": "相关项变化，不等同于已证明由 APP 写入"},
                                           "registry_snapshot", "medium", "correlated"))
        if truncated:
            out.append(_make_event("collector.warning", "注册表关联扫描达到资源上限",
                                   {"nodes": nodes, "entries": entries,
                                    "warning": "关联快照可能不完整，不代表未列出的项未被访问"},
                                   "registry_snapshot", "medium", "correlated"))
        checkpoint_values = dict(old_reg) if truncated else {}
        checkpoint_values.update(current_reg)
        updates.update({"registry_related": {"values": checkpoint_values,
                                               "truncated": truncated, "nodes": nodes,
                                               "entries": entries},
                        "registry_checked_epoch": time.time()})
    return out, updates


def collect(task, pids, checkpoint, exact_only=False):
    caps = capabilities()
    exact, updates = exact_events(task, pids, checkpoint, caps)
    if exact_only:
        return exact, updates
    fallback, fallback_updates = correlated_events(
        task, pids, checkpoint, use_dns=True,
        # Keep the relationship baseline even when write telemetry exists: it
        # provides discoverability, but remains explicitly non-attributed.
        use_registry=True)
    updates.update(fallback_updates)
    return exact + fallback, updates
