"""筛查工作台——深潜扫描：Prefetch 执行痕迹 / 注册表使用历史 / WER 崩溃报告。"""
import os
import re
import time

from core import db, logger
from modules.screener.common import _finish, _winroot


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
