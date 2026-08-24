"""M2 regscan — 注册表搜索与漏洞常驻点位专项检查。

能力：
  search(keyword, root, path_filter, mode)   关键词/路径/值/数据搜索
  autostart_points()                         漏洞常驻点位专项检查
  read_value(path, name)                     读取单值
  add_watch(key) / list_watches()            观察目标（供 M7 联动）

事件：
  registry.hit   {key, hit:{key,name,type,data,matched}}
"""
import re
import threading
import winreg

from core import events, logger

MAX_HITS = 2000
MAX_DEPTH = 12
MAX_NODES = 120000
SCAN_SEM = threading.BoundedSemaphore(2)
# regex 模式防线：注册表值可达数百 KB，恶意/失误的回溯爆炸正则会
# 单核打满并占死 SCAN_SEM。限制模式长度 + 匹配文本截断 + 拒绝嵌套量词。
MAX_REGEX_LEN = 256
MAX_REGEX_TEXT = 64 * 1024
_NESTED_QUANT_RE = re.compile(r"\([^()]*[+*][^()]*\)[+*{]")

ROOTS = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKU": winreg.HKEY_USERS,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
}

OPEN_FLAGS = winreg.KEY_READ
if hasattr(winreg, "KEY_WOW64_64KEY"):
    OPEN_FLAGS |= winreg.KEY_WOW64_64KEY

AUTOSTART_POINTS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "自启动-Run(HKLM)", 0.8),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "自启动-RunOnce(HKLM)", 0.8),
    ("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "自启动-Run(32bit HKLM)", 0.8),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "自启动-Run(HKCU)", 0.8),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "自启动-RunOnce(HKCU)", 0.8),
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon-Userinit/Shell", 0.9),
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
     "IFEO-映像劫持", 0.9),
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs 注入", 1.0),
    ("HKLM", r"SYSTEM\CurrentControlSet\Services", "服务(全量，高风险项另筛选)", 0.6),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
     "ShellExecuteHooks", 0.8),
    ("HKLM", r"SOFTWARE\Classes\CLSID", "COM 组件注册(全量)", 0.6),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", "RunServices(旧)", 0.7),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "Shell Folders", 0.5),
]

RISK_KEYWORDS = (
    r"\.dll\b|cmd\.exe|powershell|rundll32|regsvr32|mshta|wscript|cscript|"
    r"certutil|bitsadmin|msiexec|schtasks|net user|net localgroup"
)
RISK_RE = re.compile(RISK_KEYWORDS, re.IGNORECASE)

REGEX_CACHE = {}
REGEX_CACHE_LOCK = threading.Lock()

INVALID_TYPES = (winreg.REG_NONE, winreg.REG_BINARY, winreg.REG_LINK)

_watches = []
_watches_lock = threading.Lock()


def _open_key(root_name, path, flags=None):
    root = ROOTS[root_name]
    return winreg.OpenKey(root, path, 0, flags or OPEN_FLAGS)


def _display_root(root_name, path):
    return "%s\\%s" % (root_name, path)


def _value_key(val, vtype):
    if isinstance(val, bytes):
        return "hex:" + val.hex()
    return _value_to_str(val) + "|t%d" % (vtype if isinstance(vtype, int) else 0)


def _value_to_str(val):
    if val is None:
        return ""
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="replace")
        except Exception:
            return repr(val)
    try:
        return str(val)
    except Exception:
        return repr(val)


def _match_mode(text, keyword, mode):
    if not keyword:
        return False
    low = text.lower()
    kw = keyword.lower()
    if mode == "contains":
        return kw in low
    if mode == "exact":
        return text.lower() == kw
    if mode == "regex":
        with REGEX_CACHE_LOCK:
            rx = REGEX_CACHE.get(keyword)
            if rx is None:
                if len(keyword) > MAX_REGEX_LEN:
                    rx = False
                elif _NESTED_QUANT_RE.search(keyword):
                    rx = False  # 嵌套量词：ReDoS 风险，确定性拒绝
                else:
                    try:
                        rx = re.compile(keyword, re.IGNORECASE)
                    except re.error:
                        rx = False
                REGEX_CACHE[keyword] = rx
        if not rx:
            return False
        try:
            return rx.search(text[:MAX_REGEX_TEXT]) is not None
        except re.error:
            return False
    return kw in low


def _iter_subkeys(root_name, base_path, depth, callback, cancel=None):
    if depth > MAX_DEPTH:
        return
    if cancel is not None and cancel():
        raise _AbortWalk()
    try:
        key = _open_key(root_name, base_path)
    except (OSError, PermissionError):
        return
    try:
        index = 0
        while True:
            if cancel is not None and cancel():
                raise _AbortWalk()
            try:
                name = winreg.EnumKey(key, index)
            except OSError:
                break
            index += 1
            sub = base_path + "\\" + name if base_path else name
            callback(root_name, sub, depth)
            _iter_subkeys(root_name, sub, depth + 1, callback, cancel)
    finally:
        key.Close()


class _AbortWalk(Exception):
    pass


def _search_impl(keyword, root, path, mode, max_hits, include_values,
                 include_data):
    hits = []
    state = {"stop": False, "nodes": 0, "aborted": False}

    def cancel():
        if state["nodes"] > MAX_NODES:
            state["aborted"] = True
            return True
        return state["stop"]

    def check_key(root_name, full_path, depth):
        if cancel():
            raise _AbortWalk()
        state["nodes"] += 1
        node = None
        try:
            node = _open_key(root_name, full_path)
        except (OSError, PermissionError):
            return
        try:
            path_ok = not path or _match_mode(full_path, path, "contains")
            key_hit = path_ok and (not keyword
                                   or _match_mode(full_path, keyword, mode))
            if key_hit and not path_ok:
                key_hit = False
            if key_hit:
                with state["lock"]:
                    if len(hits) < max_hits:
                        hits.append({"key": _display_root(root_name, full_path),
                                     "kind": "key", "name": full_path,
                                     "reason": "路径命中", "data": ""})
                    else:
                        state["stop"] = True
                        raise _AbortWalk()
            if not include_values and not include_data:
                return
            if state["stop"]:
                raise _AbortWalk()
            index = 0
            while True:
                try:
                    vname, vdata, vtype = winreg.EnumValue(node, index)
                except OSError:
                    break
                index += 1
                if vtype in INVALID_TYPES:
                    continue
                vtext = _value_to_str(vdata)
                if keyword and (include_values and _match_mode(vname, keyword, mode)):
                    matched = "值名"
                elif keyword and (include_data
                                  and _match_mode(vtext, keyword, mode)):
                    matched = "数据"
                else:
                    matched = ""
                if not matched and not key_hit:
                    continue
                with state["lock"]:
                    if len(hits) >= max_hits:
                        state["stop"] = True
                        raise _AbortWalk()
                    hits.append({
                        "key": _display_root(root_name, full_path), "kind": "value",
                        "name": vname, "reason": "值命中(%s)" % matched if matched
                        else "键命中值", "type": str(vtype),
                        "data": vtext[:500]})
        finally:
            node.Close()

    def scan_root(rname):
        base = path
        if base:
            if base.upper().startswith(rname + "\\"):
                base = base[len(rname) + 1:]
            base = base.rstrip("\\")
        with state["lock"]:
            pass
        try:
            check_key(rname, base or "", 0)
            if not state["stop"]:
                _iter_subkeys(rname, base or "", 1, check_key, cancel)
        except _AbortWalk:
            pass

    state["lock"] = threading.Lock()
    if root == "ALL":
        for rname in ("HKLM", "HKCU"):
            if state["stop"]:
                break
            scan_root(rname)
    else:
        scan_root(root)
    return {"hits": hits, "truncated": bool(state["stop"]),
            "aborted": bool(state["aborted"]),
            "nodes": state["nodes"], "total": len(hits)}


def search(keyword="", root="HKLM", path="", mode="contains", max_hits=MAX_HITS,
           include_values=True, include_data=True):
    if root not in ROOTS and root != "ALL":
        return {"hits": [], "error": "未知 root: %s" % root}
    # Web 端提供"路径"模式：只按键路径匹配、不匹配值名/值数据。
    # 此前 "path" 不在合法集合内会被静默降级为 contains（值与键都匹配），名实不符。
    path_only = False
    if mode == "path":
        path_only = True
        mode = "contains"
    if mode not in ("contains", "exact", "regex"):
        mode = "contains"
    if max_hits <= 0:
        max_hits = MAX_HITS
    if not SCAN_SEM.acquire(blocking=False):
        return {"hits": [], "busy": True,
                "error": "已有扫描进行中，请稍后再试"}
    try:
        return _search_impl(keyword, root, path, mode, max_hits,
                            False if path_only else include_values,
                            False if path_only else include_data)
    except Exception as e:
        logger.record_err("regscan.search", e)
        return {"hits": [], "error": "搜索异常: %s" % e}
    finally:
        SCAN_SEM.release()


def autostart_points(root="HKLM"):
    results = []
    for rname, path, label, risk in AUTOSTART_POINTS:
        if root != "ALL" and rname != root:
            continue
        try:
            node = _open_key(rname, path)
        except (OSError, PermissionError):
            continue
        try:
            index = 0
            seen_bin = {}
            while True:
                try:
                    vname, vdata, vtype = winreg.EnumValue(node, index)
                except OSError:
                    break
                index += 1
                if vtype in INVALID_TYPES:
                    continue
                vtext = _value_to_str(vdata)
                if isinstance(vdata, bytes):
                    hkey = vdata.hex()
                    if hkey in seen_bin:
                        continue
                    seen_bin[hkey] = True
                risky = bool(RISK_RE.search(vtext))
                item = {
                    "point": label, "key": _display_root(rname, path),
                    "name": vname, "data": vtext[:500], "risk": 1.0 if risky else risk,
                    "risky": risky, "type": str(vtype),
                }
                results.append(item)
                events.bus.publish("registry.hit", {
                    "key": _display_root(rname, path),
                    "hit": {"name": vname, "data": vtext[:500],
                            "point": label, "risky": risky}})
        except OSError:
            pass
        finally:
            node.Close()
    return results


def read_value(key_path, name=""):
    parts = key_path.split("\\", 1)
    if len(parts) != 2 or parts[0] not in ROOTS:
        return {"error": "键路径需形如 HKLM\\...\\子键（根键仅支持 HKLM/HKCU/HKU/HKCR）"}
    try:
        node = _open_key(parts[0], parts[1])
    except (OSError, PermissionError) as e:
        return {"error": str(e)}
    try:
        try:
            vdata, vtype = winreg.QueryValueEx(node, name)
            return {"key": key_path, "name": name or "(default)",
                    "type": str(vtype), "data": _value_to_str(vdata)}
        except (FileNotFoundError, OSError) as e:
            return {"error": str(e)}
    finally:
        node.Close()


def add_watch(key_path):
    parts = key_path.split("\\", 1)
    if len(parts) != 2 or parts[0] not in ROOTS:
        return False
    try:
        node = _open_key(parts[0], parts[1])
        node.Close()
    except (OSError, PermissionError):
        return False
    with _watches_lock:
        if key_path not in _watches:
            _watches.append(key_path)
    return True


def remove_watch(key_path):
    with _watches_lock:
        if key_path in _watches:
            _watches.remove(key_path)
            return True
        return False


def list_watches():
    with _watches_lock:
        return list(_watches)


def snapshot_watches():
    with _watches_lock:
        keys = list(_watches)
    snap = {}
    for kp in keys:
        parts = kp.split("\\", 1)
        if len(parts) != 2 or parts[0] not in ROOTS:
            continue
        vals = {}
        try:
            node = _open_key(parts[0], parts[1])
        except (OSError, PermissionError):
            continue
        try:
            index = 0
            while True:
                try:
                    vname, vdata, vtype = winreg.EnumValue(node, index)
                except OSError:
                    break
                index += 1
                if vtype in INVALID_TYPES:
                    continue
                vals[_value_to_str(vname)] = _value_key(vdata, vtype)
        finally:
            node.Close()
        snap[kp] = vals
    return snap


def diff_watches(before, after):
    diffs = []
    for kp, av in before.items():
        bv = after.get(kp, {})
        for name, data in av.items():
            if name not in bv:
                diffs.append({"key": kp, "name": name, "old": str(data)[:300],
                              "new": "(已删除)"})
            elif bv[name] != data:
                diffs.append({"key": kp, "name": name, "old": str(data)[:300],
                              "new": str(bv[name])[:300]})
        for name in bv:
            if name not in av:
                diffs.append({"key": kp, "name": name, "old": "",
                              "new": str(bv[name])[:300]})
    for kp, bv in after.items():
        if kp not in before:
            diffs.append({"key": kp, "name": "(新键)", "old": "", "new": str(bv)[:300]})
    return diffs


def register(bus, cfg):
    bus.subscribe("regscan.watch.add",
                  lambda d: add_watch(d.get("key", "")) if d else None)
    bus.subscribe("regscan.watch.remove",
                  lambda d: remove_watch(d.get("key", "")) if d else None)


def shutdown():
    pass