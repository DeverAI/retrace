"""筛查工作台——文件夹 & 注册表扫描（宽泛扫描 / 定向细扫 / 关联分析与处置指导）。

三段式工作流：
  1. broad_scan()          宽泛扫描：文件系统 + 注册表无差别列举可疑项，
                           低门槛宁可错杀不可放过；带时间预算与条目上限防止拖死调用方。
  2. deep_dir_scan(d)      定向细扫：对单独目录做指纹级深挖（哈希/熵/伪装命名），
                           并联动注册表自启动、MuiCache/UserAssist/BAM、Prefetch 执行痕迹。
  3. correlate_findings(r) 关联分析：把任意筛查结果按"同一可疑主体"聚类成证据组，
                           输出确定性处置建议与总体行动计划（纯函数，可回归测试）。

设计红线：
  - 只读：全部为枚举 / 哈希 / 读注册表，绝不写盘改注册表（清理必须走 cleanup 门禁）；
  - 有界：所有遍历带 deadline 与条目上限，超限在结果 notes 里如实标注（不静默截断）；
  - 联动：细扫自动反查注册表与 Prefetch，关联器跨来源归并，避免逐项孤立看。
"""
import os
import re
import stat as stat_mod
import time

from core import db, logger
from modules.screener.common import (
    _extract_exe, _file_stats, _finish, _risk_label, _SUS_RE,
    _user_scan_dirs, _winroot,
)

# ---------------- 共享常量 ----------------
_EXEC_EXTS = (".exe", ".dll", ".scr", ".pif", ".com", ".cpl", ".msi", ".ocx", ".sys")
_SCRIPT_EXTS = (".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".bat", ".cmd")
_DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|gif|txt|mp[34]|avi|zip|rar)"
    r"\.(exe|scr|pif|com|bat|cmd|js|vbs|jar)$", re.I)
# 预算内跳过的高噪声目录名（包管理缓存等，信号密度极低）
_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv",
              "site-packages", ".cache", "pip", "npm-cache"}
_MAX_BROAD_ITEMS = 600
_MAX_VISITED = 40000


def _norm(p):
    """路径规范化：环境变量展开 + 绝对化 + 小写。空值返回空串。"""
    if not p or not isinstance(p, str):
        return ""
    p = p.strip()
    if not p:
        return ""
    try:
        return os.path.normcase(os.path.abspath(os.path.expandvars(
            os.path.expanduser(p))))
    except Exception:
        return ""


def _open_flags():
    import winreg
    return winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)


def _is_hidden(path):
    """Windows 隐藏属性检测（非 Windows 平台恒 False）。"""
    try:
        st = os.stat(path)
    except OSError:
        return False
    hidden_bit = getattr(stat_mod, "FILE_ATTRIBUTE_HIDDEN", 0)
    fa = getattr(st, "st_file_attributes", 0)
    return bool(hidden_bit and (fa & hidden_bit))


def _is_reparse(path):
    """junction/符号链接检测：跳过以防环路与越出根目录。"""
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return True
    rp_bit = getattr(stat_mod, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    fa = getattr(st, "st_file_attributes", 0)
    return bool(rp_bit and (fa & rp_bit))


_TEMP_PREFIXES = None


def _temp_prefixes():
    global _TEMP_PREFIXES
    if _TEMP_PREFIXES is None:
        ps = []
        for env in ("TEMP", "TMP"):
            p = os.environ.get(env)
            if p:
                ps.append(_norm(p))
        ps.append(_norm(os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "Temp")))
        _TEMP_PREFIXES = [p for p in ps if p]
    return _TEMP_PREFIXES


def _zone_of(npath):
    """路径落点分区：临时目录/下载/桌面/启动文件夹/AppData/回收站 等。"""
    n = npath or ""
    for t in _temp_prefixes():
        if n == t or n.startswith(t + os.sep):
            return "temp"
    home = _norm(os.path.expanduser("~"))
    for label, sub in (("downloads", "Downloads"), ("desktop", "Desktop")):
        d = os.path.join(home, sub)
        if n.startswith(_norm(d) + os.sep):
            return label
    for env, label in (("APPDATA", "appdata"), ("LOCALAPPDATA", "appdata"),
                       ("PROGRAMDATA", "programdata")):
        base = _norm(os.environ.get(env))
        if base and (n == base or n.startswith(base + os.sep)):
            return "startup" if n.endswith("\\startup") else label
    rec = _norm(os.environ.get("SystemDrive", "C:") + os.sep + "$Recycle.Bin")
    if n.startswith(rec + os.sep):
        return "recycle"
    return "other"


# ---------------- 宽泛扫描：文件系统 ----------------
def _default_fs_roots():
    roots = []
    for p in _user_scan_dirs():
        roots.append((p, 5))
    home = os.path.expanduser("~")
    for sub in ("Desktop", "Downloads", "Documents"):
        p = os.path.join(home, sub)
        if os.path.isdir(p):
            roots.append((p, 4))
    for env in ("TEMP", "TMP"):
        p = os.environ.get(env)
        if p and os.path.isdir(p):
            roots.append((p, 4))
    wt = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp")
    if os.path.isdir(wt):
        roots.append((wt, 3))
    rec = os.environ.get("SystemDrive", "C:") + os.sep + "$Recycle.Bin"
    if os.path.isdir(rec):
        roots.append((rec, 3))
    seen = set()
    out = []
    for p, d in roots:
        n = _norm(p)
        if n and n not in seen:
            seen.add(n)
            out.append((p, d))
    return out


def _score_fs_entry(name, full, is_dir, hidden):
    """文件系统条目打分。返回 (score, reasons, flags)；不达列举阈值的返回 None。"""
    low = name.lower()
    ext = os.path.splitext(low)[1]
    flags, reasons = [], []
    if low == "autorun.inf":
        return 0.8, ["autorun.inf 自动运行配置（U 盘病毒经典手法）"], ["autorun"]
    is_exec = ext in _EXEC_EXTS
    is_script = ext in _SCRIPT_EXTS
    if not (is_exec or is_script or _DOUBLE_EXT_RE.search(low)):
        return None
    zone = _zone_of(_norm(full))
    if _DOUBLE_EXT_RE.search(low):
        score = 0.78
        reasons.append("双扩展名伪装（文档后缀+可执行后缀）")
        flags.append("double_ext")
    elif is_exec:
        score = {"temp": 0.6, "downloads": 0.48, "desktop": 0.42,
                 "recycle": 0.5, "startup": 0.55,
                 "appdata": 0.35, "programdata": 0.3}.get(zone, 0.22)
        reasons.append({"temp": "可执行文件落在临时目录（恶意软件常见落脚点）",
                        "downloads": "可执行文件在下载目录",
                        "desktop": "可执行文件在桌面",
                        "recycle": "回收站中的可执行文件",
                        "startup": "启动文件夹中的可执行文件",
                        }.get(zone, "可执行文件"))
        if zone in ("temp", "downloads", "recycle", "startup"):
            flags.append("temp_loc" if zone == "temp" else zone)
    else:
        score = 0.5 if zone in ("temp", "startup") else 0.25
        reasons.append("脚本文件落在%s" % ("临时/启动目录" if zone in ("temp", "startup")
                                          else "用户目录"))
        if zone in ("temp", "startup"):
            flags.append("temp_loc" if zone == "temp" else zone)
    if _SUS_RE.search(low):
        score += 0.25
        reasons.append("可疑命名")
        flags.append("sus_name")
    if hidden and (is_exec or is_script):
        score += 0.15
        reasons.append("隐藏属性")
        flags.append("hidden")
    if is_dir:
        score = min(score, 0.5)
        reasons.insert(0, "可疑命名的目录")
    return score, reasons, flags


def _mk_fs_item(name, full, score, reasons, flags, cat):
    zlabel = _zone_of(_norm(full))
    return {
        "category": cat, "name": name, "path": full,
        "type": "fs_suspicious", "target": full,
        "detail": "%s | %s" % (os.path.dirname(full) or full,
                               ";".join(reasons)),
        "risk": _risk_label(score), "reason": ";".join(reasons),
        "flags": flags, "zone": zlabel, "state": "未处理",
    }


class _Budget:
    """扫描预算：deadline + 已访问条目计数 + 截断标注。"""

    def __init__(self, deadline_sec):
        self.deadline = time.time() + max(1.0, float(deadline_sec))
        self.visited = 0
        self.notes = []

    def expired(self):
        return time.time() > self.deadline

    def exhausted(self):
        return self.visited >= _MAX_VISITED or self.expired()


def _walk_broad(base, max_depth, items, budget, cat):
    """有界迭代下钻：列目录条目并打分；命中目录也继续下钻（宁可错杀）。"""
    stack = [(os.path.abspath(base), 0)]
    while stack:
        cur, depth = stack.pop()
        if budget.exhausted():
            budget.notes.append("扫描预算耗尽（时间/条目上限），更深层未覆盖: %s" % cur)
            return
        try:
            with os.scandir(cur) as it:
                entries = list(it)[:3000]
        except OSError:
            continue
        for entry in entries:
            budget.visited += 1
            if budget.exhausted():
                budget.notes.append("扫描预算耗尽（时间/条目上限），后续未覆盖")
                return
            name = entry.name
            if name in _SKIP_DIRS:
                continue
            try:
                full = entry.path
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if entry.is_symlink() or (is_dir and _is_reparse(full)):
                continue
            if is_dir:
                scored = _score_fs_entry(name, full, True, False)
                if scored and _broad_worthy(scored):
                    items.append(_mk_fs_item(name, full, *scored, cat))
                if depth < max_depth:
                    stack.append((full, depth + 1))
            else:
                scored = _score_fs_entry(name, full, False, _is_hidden(full))
                if scored and _broad_worthy(scored):
                    items.append(_mk_fs_item(name, full, *scored, cat))


def _broad_worthy(scored):
    """宽泛扫描列举门槛：分数达标或带任何信号旗标。

    宁可错杀不放过 ≠ 全量倾倒：AppData 里数以千计的正常 exe/dll 会把
    真信号淹没。无旗标且低分的纯清单项留给「定向细扫」去逐个列。
    """
    score, _reasons, flags = scored
    return bool(flags) or score >= 0.4


def _pf_shallow_pass(items, budget, cat):
    """Program Files 浅扫：仅前两层找可疑命名目录/文件（全量扫噪声会淹没信号）。"""
    for env in ("ProgramFiles", "ProgramFiles(x86)"):
        pf = os.environ.get(env)
        if not pf or not os.path.isdir(pf):
            continue
        _walk_broad(pf, 2, items, budget, cat)


def _startup_folder_items(cat):
    """启动文件夹（用户 + 公共）：其中的脚本/exe 即登录自启项。"""
    items = []
    bases = []
    appdata = os.environ.get("APPDATA")
    progdata = os.environ.get("PROGRAMDATA")
    tail = r"Microsoft\Windows\Start Menu\Programs\Startup"
    if appdata:
        bases.append(os.path.join(appdata, tail))
    if progdata:
        bases.append(os.path.join(progdata, tail))
    for base in bases:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            for f in files:
                full = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()
                if ext in _EXEC_EXTS or ext in _SCRIPT_EXTS or ext == ".lnk":
                    score = 0.55 if ext != ".lnk" else 0.3
                    if _SUS_RE.search(f.lower()):
                        score += 0.25
                    items.append({
                        "category": cat, "name": f, "path": full,
                        "type": "startup_folder", "target": full,
                        "detail": "启动文件夹条目（登录即执行/加载）: %s" % full,
                        "risk": _risk_label(score),
                        "reason": "启动文件夹驻留",
                        "flags": ["autostart", "startup_folder"],
                        "state": "未处理",
                    })
    return items


# ---------------- 宽泛扫描：注册表常驻点位 ----------------
_REG_RUN_KEYS = (
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "自启动-Run(HKLM)"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "自启动-RunOnce(HKLM)"),
    ("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "自启动-Run(32bit HKLM)"),
    ("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
     "自启动-RunOnce(32bit HKLM)"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "自启动-Run(HKCU)"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "自启动-RunOnce(HKCU)"),
)
_WINLOGON_VALUE_NAMES = ("Userinit", "Shell")
_APPINIT_KEYS = (
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"),
    ("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
     "AppInit_DLLs"),
)
_IFEO_PARENT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
_ACTIVE_SETUP = r"SOFTWARE\Microsoft\Active Setup\Installed Components"
_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"


def _reg_read_value(root_name, path, name):
    import winreg
    try:
        with winreg.OpenKey(_winroot(root_name), path, 0, _open_flags()) as k:
            v, _t = winreg.QueryValueEx(k, name)
            if isinstance(v, bytes):
                try:
                    v = v.decode("utf-16-le", errors="replace")
                except Exception:
                    return ""
            return str(v).strip()
    except OSError:
        return ""


def _iter_reg_values(root_name, path):
    import winreg
    try:
        with winreg.OpenKey(_winroot(root_name), path, 0, _open_flags()) as k:
            i = 0
            while True:
                try:
                    vname, vdata, vtype = winreg.EnumValue(k, i)
                except OSError:
                    break
                i += 1
                if vtype in (getattr(winreg, "REG_NONE", 0),
                             getattr(winreg, "REG_LINK", 0)):
                    continue
                if isinstance(vdata, bytes):
                    try:
                        vdata = vdata.decode("utf-16-le", errors="replace")
                    except Exception:
                        continue
                yield str(vname), str(vdata)
    except OSError:
        return


def _iter_reg_subkeys(root_name, path, cap=4000):
    import winreg
    try:
        with winreg.OpenKey(_winroot(root_name), path, 0, _open_flags()) as k:
            i = 0
            while i < cap:
                try:
                    yield winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
    except OSError:
        return


def _collect_reg_persistence():
    """收集注册表常驻点位原始条目（宽泛扫描与定向细扫共用）。

    返回列表，每项：{type, root, key, name, data, point}。
    """
    out = []
    for root_name, path, label in _REG_RUN_KEYS:
        for vname, vdata in _iter_reg_values(root_name, path):
            out.append({"type": "reg_run", "root": root_name, "key": path,
                        "name": vname, "data": vdata, "point": label})
    wn_root, wn_key = "HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    for vname in _WINLOGON_VALUE_NAMES:
        vdata = _reg_read_value(wn_root, wn_key, vname)
        if vdata:
            out.append({"type": "reg_winlogon", "root": wn_root, "key": wn_key,
                        "name": vname, "data": vdata, "point": "Winlogon-%s" % vname})
    for root_name, path, vname in _APPINIT_KEYS:
        vdata = _reg_read_value(root_name, path, vname)
        if vdata:
            out.append({"type": "reg_appinit", "root": root_name, "key": path,
                        "name": vname, "data": vdata, "point": "AppInit_DLLs 注入"})
    for sub in _iter_reg_subkeys("HKLM", _IFEO_PARENT, cap=1500):
        dbg = _reg_read_value("HKLM", _IFEO_PARENT + "\\" + sub, "Debugger")
        if dbg:
            out.append({"type": "reg_ifeo", "root": "HKLM",
                        "key": _IFEO_PARENT + "\\" + sub, "name": "Debugger",
                        "data": dbg, "point": "IFEO 映像劫持(Debugger)"})
    for sub in _iter_reg_subkeys("HKLM", _ACTIVE_SETUP, cap=1200):
        stub = _reg_read_value("HKLM", _ACTIVE_SETUP + "\\" + sub, "StubPath")
        if stub:
            out.append({"type": "reg_activesetup", "root": "HKLM",
                        "key": _ACTIVE_SETUP + "\\" + sub, "name": "StubPath",
                        "data": stub, "point": "Active Setup 登录执行"})
    sys32 = _norm(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                               "system32")).lower()
    for sub in _iter_reg_subkeys("HKLM", _SERVICES_KEY, cap=4500):
        image = _reg_read_value("HKLM", _SERVICES_KEY + "\\" + sub, "ImagePath")
        if not image:
            continue
        img_norm = _norm(image.replace('"', ""))
        if img_norm.startswith(sys32 + os.sep):
            continue  # 系统目录内的服务镜像属常规，避免淹没信号
        out.append({"type": "reg_service", "root": "HKLM",
                    "key": _SERVICES_KEY + "\\" + sub, "name": sub,
                    "data": image, "point": "服务(ImagePath 非系统目录)"})
    return out


def _score_reg_entry(e):
    """常驻点位条目打分。返回 (score, reasons, flags)。"""
    from modules import regscan
    score = {"reg_run": 0.4, "reg_service": 0.3, "reg_ifeo": 0.85,
             "reg_appinit": 0.8, "reg_winlogon": 0.35,
             "reg_activesetup": 0.45}.get(e["type"], 0.3)
    reasons, flags = [], []
    data = e.get("data") or ""
    exe = os.path.expandvars(_extract_exe(data) or "")
    if exe:
        nz = _norm(exe)
        z = _zone_of(nz)
        if z in ("temp", "downloads", "recycle"):
            score += 0.35
            reasons.append("指向临时/下载/回收站目录")
            flags.append("temp_loc")
        if not os.path.exists(nz):
            score += 0.3
            reasons.append("指向的文件不存在（悬空残留）")
            flags.append("dangling")
    if e["type"] == "reg_winlogon":
        expected = {"userinit": "userinit.exe", "shell": "explorer.exe"}
        base = expected.get(e["name"].lower())
        extra = []
        for seg in data.split(","):
            seg = seg.strip()
            if not seg:
                continue
            # 默认值可能是全路径（如 C:\Windows\system32\userinit.exe），按基名比对
            if base and os.path.basename(seg).lower() == base:
                continue
            extra.append(seg)
        if extra:
            score += 0.4
            reasons.append("Winlogon 含非默认附加项: %s" % ",".join(extra[:3]))
            flags.append("winlogon_extra")
    if regscan.RISK_RE.search(data):
        score += 0.2
        reasons.append("风险关键词(cmd/powershell/rundll32 等)")
        flags.append("risky_kw")
    hay = "%s %s" % (e.get("name", ""), data)
    if _SUS_RE.search(hay.lower()):
        score += 0.2
        reasons.append("可疑命名")
        flags.append("sus_name")
    return score, reasons, flags


def _broad_registry_items():
    items = []
    for e in _collect_reg_persistence():
        score, reasons, flags = _score_reg_entry(e)
        # 服务仅在有实际信号（悬空/临时落点/可疑命名/风险命令行）时列举：
        # Program Files 下正规软件的服务镜像数以百计，全量列出会淹没真信号
        if e["type"] == "reg_service" and not (
                {"dangling", "temp_loc", "sus_name", "risky_kw"} & set(flags)):
            continue
        flags.append("autostart")
        target = "%s\\%s|%s" % (e["root"], e["key"], e["name"])
        exe = os.path.expandvars(_extract_exe(e.get("data") or "") or "")
        items.append({
            "category": "宽泛扫描", "name": e["name"], "path": exe or target,
            "type": e["type"], "target": target,
            "detail": "%s @ %s | %s" % (e["point"], target, (e["data"] or "")[:150]),
            "risk": _risk_label(score), "reason": ";".join(reasons) or "常驻点位",
            "flags": flags, "exe_path": exe, "state": "未处理",
        })
    return items


def _scheduled_task_items(budget, cat):
    """计划任务 XML 扫描：Command 指向临时/用户目录或可疑命名即列举。"""
    tasks_root = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                              "System32", "Tasks")
    if not os.path.isdir(tasks_root):
        return []
    cmd_re = re.compile(r"<Command[^>]*>([^<]{1,500})</Command>", re.I)
    items, visited = [], 0
    for root, dirs, files in os.walk(tasks_root):
        rel = os.path.relpath(root, tasks_root)
        top = rel.split(os.sep)[0].lower()
        if top == "microsoft":
            dirs[:] = []
            continue  # 微软自带任务属常规噪声，整支剪除
        for f in files:
            visited += 1
            if visited > 2500 or budget.exhausted():
                budget.notes.append("计划任务扫描达到上限，部分任务未覆盖")
                return items
            full = os.path.join(root, f)
            try:
                with open(full, "rb") as fh:
                    raw = fh.read(65536)
            except OSError:
                continue
            if raw.count(b"\x00") > len(raw) // 4:
                text = raw.decode("utf-16-le", errors="replace")
            else:
                text = raw.decode("utf-8", errors="replace")
            m = cmd_re.search(text)
            if not m:
                continue
            cmd = m.group(1).strip()
            exe = os.path.expandvars(_extract_exe(cmd) or cmd.strip('"'))
            nz = _norm(exe)
            z = _zone_of(nz)
            score, reasons, flags = 0.3, [], ["scheduled_task"]
            if z in ("temp", "downloads", "recycle"):
                score += 0.35
                reasons.append("计划任务指向临时/下载目录")
                flags.append("temp_loc")
            elif z in ("appdata", "programdata"):
                score += 0.15
                reasons.append("计划任务指向用户数据目录")
            if _SUS_RE.search((f + " " + exe).lower()):
                score += 0.25
                reasons.append("可疑命名")
                flags.append("sus_name")
            if reasons:
                items.append({
                    "category": cat, "name": f, "path": exe or full,
                    "type": "scheduled_task", "target": full,
                    "detail": "计划任务 %s | Command: %s" % (rel, cmd[:150]),
                    "risk": _risk_label(score),
                    "reason": ";".join(reasons) or "计划任务",
                    "flags": flags, "exe_path": exe, "state": "未处理",
                })
    return items


def broad_scan(roots=None, deadline_sec=25.0):
    """宽泛扫描：文件系统 + 注册表 + 计划任务无差别列举可疑项（宁错杀不放过）。

    roots 可注入（测试用）；缺省覆盖 用户目录群/下载桌面/TEMP/回收站/
    Program Files 浅层。结果按风险排序，notes 如实记录预算截断情况。
    """
    budget = _Budget(deadline_sec)
    items = []
    fs_roots = roots if roots is not None else _default_fs_roots()
    for base, depth in fs_roots:
        if budget.exhausted():
            break
        if not os.path.isdir(base):
            continue
        _walk_broad(base, depth, items, budget, "宽泛扫描")
    if not budget.exhausted():
        _pf_shallow_pass(items, budget, "宽泛扫描")
    reg_items = []
    try:
        reg_items = _broad_registry_items()
    except Exception as e:
        logger.record_err("screen.fsreg.broad_reg", e)
    task_items = []
    try:
        task_items = _scheduled_task_items(budget, "宽泛扫描")
    except Exception as e:
        logger.record_err("screen.fsreg.broad_tasks", e)
    startup_items = _startup_folder_items("宽泛扫描")
    items.extend(reg_items)
    items.extend(task_items)
    items.extend(startup_items)
    seen = set()
    dedup = []
    for it in items:
        key = "%s|%s" % (it.get("type"), it.get("target"))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(it)
    db.audit("screen.fsreg.broad", "items=%d visited=%d" % (len(dedup), budget.visited))
    res = _finish(dedup, "宽泛扫描")
    res["scope"] = {"roots": [p for p, _d in fs_roots],
                    "visited_entries": budget.visited}
    if budget.notes:
        res["notes"] = budget.notes
    return res


# ---------------- 定向细扫 ----------------
def deep_dir_scan(dir_path, deadline_sec=30.0):
    """对单个目录做指纹级细扫，并联动注册表/Prefetch 反查相关项。

    文件系统侧：全量清单 + 可执行文件哈希/熵 + 伪装命名/隐藏属性检测；
    联动侧：以目录路径与可执行文件名为线索，反查注册表常驻点位、
    MuiCache/UserAssist/AppCompat/BAM 使用历史与 Prefetch 执行痕迹。
    """
    if not dir_path or not os.path.isdir(dir_path):
        return {"category": "细扫分析", "summary": {"total": 0, "high": 0, "med": 0,
                "low": 0, "none": 0}, "items": [], "error": "目录不存在: %s" % dir_path}
    base_abs = os.path.abspath(dir_path)
    budget = _Budget(deadline_sec)
    files, ext_counter, total_size = [], {}, 0
    truncated_files = False
    for root, dirs, fnames in os.walk(base_abs):
        if budget.exhausted():
            budget.notes.append("目录遍历预算耗尽，未完整覆盖: %s" % root)
            break
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not _is_reparse(
            os.path.join(root, d))]
        for f in fnames:
            full = os.path.join(root, f)
            try:
                sz = os.path.getsize(full)
            except OSError:
                continue
            total_size += sz
            ext_counter[os.path.splitext(f)[1].lower() or "(无扩展名)"] = \
                ext_counter.get(os.path.splitext(f)[1].lower() or "(无扩展名)", 0) + 1
            files.append((full, sz))
            if len(files) >= 8000:
                truncated_files = True
                budget.notes.append("文件数超过 8000 上限，清单截断")
                break
        if truncated_files:
            break
    items, hashed, hashed_bytes = [], 0, 0
    _MAX_HASH_TOTAL = 1536 * 1024 * 1024  # 哈希总字节预算：防止大体积 DLL 集群拖穿 deadline
    exec_entries = []
    for full, sz in files:
        low = os.path.basename(full).lower()
        ext = os.path.splitext(low)[1]
        if ext in _EXEC_EXTS or ext in _SCRIPT_EXTS or _DOUBLE_EXT_RE.search(low):
            exec_entries.append((full, sz))
    exec_entries.sort(key=lambda x: -x[1])
    hash_truncated = False
    for full, sz in exec_entries:
        if budget.expired():
            budget.notes.append("细扫时间预算耗尽，其余可执行文件未逐个打分")
            break
        name = os.path.basename(full)
        ext = os.path.splitext(name)[1]
        scored = _score_fs_entry(name, full, False, _is_hidden(full))
        if not scored:
            continue
        score, reasons, flags = scored
        sha16, ent = "", ""
        if (sz <= 512 * 1024 * 1024 and hashed < 160
                and hashed_bytes + sz <= _MAX_HASH_TOTAL):
            try:
                sha, ent_raw = _file_stats(full)
                sha16, ent = sha[:16], round(ent_raw, 3)
                hashed += 1
                hashed_bytes += sz
                if ent_raw > 7.5 and ext in _EXEC_EXTS:
                    score += 0.2
                    reasons.append("高熵内容(%.2f)" % ent_raw)
                    flags.append("high_entropy")
            except OSError:
                pass
        elif not hash_truncated and (hashed >= 160 or hashed_bytes >= _MAX_HASH_TOTAL):
            hash_truncated = True
            budget.notes.append("哈希配额（数量/总字节）已用尽，其余文件仅做命名/属性判定")
        items.append({
            "category": "细扫分析", "name": name, "path": full,
            "type": "fs_suspicious", "target": full,
            "detail": "%s | 大小:%d | %s%s" % (
                os.path.relpath(full, base_abs), sz, ";".join(reasons),
                (" | sha256:%s 熵:%s" % (sha16, ent)) if sha16 else ""),
            "risk": _risk_label(min(score, 1.0)), "reason": ";".join(reasons),
            "flags": flags, "sha256_16": sha16, "state": "未处理",
        })
    linked = _link_registry_traces(base_abs, items, budget)
    items.extend(linked)
    db.audit("screen.fsreg.deep", "dir=%s items=%d linked=%d hashed=%d" % (
        base_abs, len(items), len(linked), hashed))
    res = _finish(items, "细扫分析")
    res["dir_report"] = {
        "dir": base_abs, "files_total": len(files),
        "size_total": total_size,
        "ext_top": sorted(ext_counter.items(), key=lambda kv: -kv[1])[:12],
        "hashed": hashed, "truncated": truncated_files,
    }
    if budget.notes:
        res["notes"] = budget.notes
    return res


def _link_registry_traces(base_abs, fs_items, budget, max_names=30):
    """联动反查：目录路径 + 可执行基名 → 注册表常驻/使用历史/Prefetch。"""
    from modules.screener import deep_scan
    linked, seen = [], set()
    base_low = base_abs.lower().rstrip("\\")
    names = []
    for it in fs_items:
        stem = os.path.splitext(os.path.basename(it["path"]))[0].lower()
        if stem and stem not in names:
            names.append(stem)
        if len(names) >= max_names:
            break
    def _push(src_items, src_label):
        for it in src_items:
            dk = "%s|%s" % (it.get("type"), it.get("target"))
            if dk in seen:
                continue
            seen.add(dk)
            it.setdefault("source", src_label)
            linked.append(it)
    try:
        reg_hits = [e for e in _collect_reg_persistence()
                    if base_low in (e.get("data") or "").lower()
                    or any(n in ("%s %s" % (e.get("name", ""),
                                            e.get("data") or "")).lower()
                           for n in names)]
        for e in reg_hits[:80]:
            score, reasons, flags = _score_reg_entry(e)
            flags.extend(["autostart", "linked_to_dir"])
            target = "%s\\%s|%s" % (e["root"], e["key"], e["name"])
            linked.append({
                "category": "使用历史" if e["type"] == "reg_run" else "常驻联动",
                "name": e["name"], "path": target, "type": e["type"],
                "target": target,
                "detail": "与本目录联动的常驻点位 %s @ %s | %s" % (
                    e["point"], target, (e["data"] or "")[:150]),
                "risk": _risk_label(score),
                "reason": ";".join(reasons) or "引用本目录",
                "flags": flags, "source": "注册表联动", "state": "未处理",
            })
    except Exception as e:
        logger.record_err("screen.fsreg.link_reg", e)
    if budget.expired():
        return linked
    scanners = (("MuiCache", deep_scan._scan_muicache),
                ("UserAssist", deep_scan._scan_userassist),
                ("AppCompat", deep_scan._scan_appcompat),
                ("BAM", deep_scan._scan_bam))
    for stem in names:
        if budget.expired() or len(linked) >= 120:
            break
        for label, fn in scanners:
            try:
                found = fn(stem)
            except Exception as e:
                logger.record_err("screen.fsreg.link.%s" % label, e)
                continue
            _push(found, "%s联动(%s)" % (label, stem))
    try:
        pf = deep_scan.scan_prefetch_traces(names[0] if names else "")
        if isinstance(pf, dict):
            _push(pf.get("items", []), "Prefetch联动")
    except Exception as e:
        logger.record_err("screen.fsreg.link_pf", e)
    return linked


# ---------------- 关联分析与处置指导（纯函数） ----------------
_EVIDENCE_LABELS = {
    "autostart": "注册表自启动", "service": "服务驻留", "scheduled_task": "计划任务",
    "startup_folder": "启动文件夹", "fs_present": "文件在盘", "fs_missing": "文件已缺失",
    "prefetch": "Prefetch 执行痕迹", "usage_history": "使用历史(MuiCache/UserAssist/BAM)",
    "wer": "崩溃报告残留", "sus_name": "可疑命名", "double_ext": "双扩展名伪装",
    "high_entropy": "高熵内容", "temp_loc": "临时目录落脚", "hidden": "隐藏属性",
    "dangling": "悬空引用", "autorun": "autorun.inf", "risky_kw": "风险命令行",
}
_PERSISTENCE_SET = {"autostart", "service", "scheduled_task", "startup_folder"}
_RISK_ORDER = {"高": 3, "中": 2, "低": 1, "无": 0}


def _evidence_of(it):
    """从单条筛查项提取证据类型集合 + 关联用可执行路径。"""
    t = it.get("type", "")
    flags = set(it.get("flags") or [])
    ev = set()
    exe = _norm(it.get("exe_path") or "")
    if t == "fs_suspicious":
        ev.add("fs_present" if os.path.exists(_norm(it.get("path"))) else "fs_missing")
    elif t.startswith("reg_"):
        ev.add("autostart")
        if t == "reg_service":
            ev.add("service")
        if not exe:
            exe = _norm(_extract_exe("%s %s" % (it.get("path", ""),
                                                it.get("detail", ""))))
    elif t == "scheduled_task":
        ev.add("scheduled_task")
        exe = exe or _norm(_extract_exe(it.get("detail", "")))
    elif t == "startup_folder":
        ev.update(("autostart", "startup_folder"))
    elif t == "prefetch_file":
        ev.add("prefetch")
        exe = exe or _norm(it.get("exe_path") or it.get("detail", ""))
    elif t in ("muicache_value", "userassist_value", "appcompat_value", "bam_value"):
        ev.add("usage_history")
        exe = exe or _norm(it.get("path") or it.get("detail", ""))
    elif t == "wer_report":
        ev.add("wer")
    for fl in ("sus_name", "double_ext", "high_entropy", "temp_loc", "hidden",
               "dangling", "autorun", "risky_kw"):
        if fl in flags:
            ev.add(fl)
    if not exe or os.path.splitext(exe)[1] not in _EXEC_EXTS:
        p = _norm(it.get("path"))
        if p and os.path.splitext(p)[1] in _EXEC_EXTS:
            exe = exe or p
    return ev, exe


def _advices_for(ev, risk_score):
    """确定性处置建议规则矩阵：证据组合 → 有序建议列表。"""
    advices = []
    persist = ev & _PERSISTENCE_SET
    if "dangling" in ev or ("fs_missing" in ev and persist):
        advices.append("疑似卸载残留或被杀软清除后的悬空驻留：确认软件确已不再使用后，"
                       "先备份再删除该注册表值（cleanup 流程自带还原点）")
    if "temp_loc" in ev:
        advices.append("可执行文件落在临时/下载/回收站属于高危落脚行为：不要直接双击；"
                       "先取 SHA-256 上传威胁情报平台判定，确认后再隔离删除")
    if "double_ext" in ev or "sus_name" in ev:
        advices.append("命名高度可疑：结合哈希与数字签名核查来源；确认恶意后断网隔离备份"
                       "再删除，并复查同目录、计划任务与其余驻留点")
    if "autorun" in ev:
        # 检修（2026-08-27）：原文案引导"直接删除"，与项目备份→修改→回滚链冲突；
        # 补前置留证红线
        advices.append("autorun.inf 为 U 盘病毒典型手法：先复制/隔离备份到 "
                       "backups/quarantine 留证，再删除该文件并检查同盘其他卷"
                       "的 autorun 与根目录可疑 exe")
    if "high_entropy" in ev:
        advices.append("高熵可执行文件可能是加壳/加密载荷：建议送反编译模块（M6）做危险 API 预筛")
    if "winlogon_extra" in ev or "reg_ifeo" in ev or "reg_appinit" in ev:
        advices.append("劫持类驻留点（Winlogon/IFEO/AppInit）：先记档原值再恢复默认，"
                       "误改会导致登录异常，务必保留回滚路径")
    if len(persist) >= 2:
        advices.append("多点驻留（%s）：逐点禁用而非直接删除，观察数日无复活后再清理" %
                       "、".join(sorted(_EVIDENCE_LABELS[p] for p in persist)))
    elif persist and "fs_present" in ev:
        advices.append("常规自启动项：核对发布者数字签名与业务必要性，不需要的先备份再移除，"
                       "并在 24-72 小时后复查是否复活")
    if not advices:
        advices.append("人工复核：核对路径发布者、文件哈希与数字签名后再决定处置")
    return advices


_PLAN_STEPS = [
    "1. 先处置「高」风险聚类：临时落脚/双扩展名/劫持类驻留优先，低风险痕迹类放最后；",
    "2. 每个动作前留证：记录文件 SHA-256 与注册表原值（截图或导出），便于溯源与回滚；",
    "3. 清理顺序：先禁用驻留点（注册表值/计划任务/服务）→ 再隔离文件本体，"
    "防止看门狗进程原地重建；",
    "4. 用「留样清理」执行删除：流程自带系统还原点 + backups/quarantine 备份，可一键恢复；",
    "5. 复查闭环：24-72 小时后重跑本宽泛扫描 + 指纹再生监测；出现 recreated_same_value "
    "即存在云端/备份恢复机制，本地清理无效，需转向账号侧注销或沙箱隔离。",
]


def correlate_findings(result):
    """把任意筛查结果（宽泛/细扫/留样等）按可疑主体聚类，输出证据组与处置指导。

    输入：{"items":[...]} 或裸列表；输出：{ok, summary, plan, clusters=[...]}。
    聚类键优先级：同一可执行文件 > 同一注册表键 > 同一父目录 > 独立项。
    纯函数：不读系统状态（仅 fs_present 判存在），可直接回归测试。
    """
    items = result.get("items") if isinstance(result, dict) else result
    if not items:
        return {"ok": False, "error": "无筛查项可关联（请先执行一次扫描）"}
    clusters = {}
    order = []
    for idx, it in enumerate(items):
        ev, exe = _evidence_of(it)
        key = None
        if exe:
            key = ("exe", exe)
        elif str(it.get("type", "")).startswith("reg_"):
            key = ("reg", str(it.get("target", "")).split("|")[0].lower())
        else:
            p = _norm(it.get("path") or it.get("target"))
            key = ("dir", os.path.dirname(p)) if p else ("item", str(idx))
        if key not in clusters:
            clusters[key] = {"ev": set(), "members": [], "paths": [],
                             "max_risk": 0, "labels": []}
            order.append(key)
        c = clusters[key]
        c["ev"] |= ev
        c["members"].append(idx)
        c["labels"].append(str(it.get("name") or it.get("type") or "?"))
        pr = it.get("path") or it.get("target") or ""
        if pr and len(c["paths"]) < 6 and pr not in c["paths"]:
            c["paths"].append(pr)
        c["max_risk"] = max(c["max_risk"], _RISK_ORDER.get(it.get("risk"), 0))
    out = []
    for n, key in enumerate(order, 1):
        c = clusters[key]
        ev = c["ev"]
        risk_score = c["max_risk"]
        if (ev & _PERSISTENCE_SET) and ({"fs_present"} & ev):
            risk_score = min(risk_score + 1, 3)
        if "temp_loc" in ev and ("fs_present" in ev or "autostart" in ev):
            risk_score = 3
        risk = {3: "高", 2: "中", 1: "低", 0: "无"}[risk_score]
        kind, subject = key
        label = {"exe": subject, "reg": "注册表: %s" % subject,
                 "dir": "目录: %s" % subject}.get(kind, "独立项: " +
                                                  (c["labels"][0] if c["labels"] else "?"))
        out.append({
            "id": "C%d" % n, "label": label,
            "kind": {"exe": "可执行主体", "reg": "注册表主体",
                     "dir": "目录主体"}.get(kind, "单项"),
            "risk": risk,
            "persist": bool(ev & _PERSISTENCE_SET),
            "evidence": sorted(_EVIDENCE_LABELS[e] for e in ev if e in _EVIDENCE_LABELS),
            "members": c["members"][:20],
            "sample_paths": c["paths"],
            "advice": _advices_for(ev, risk_score),
        })
    out.sort(key=lambda c: (-_RISK_ORDER[c["risk"]], c["id"]))
    # 折叠：低/无风险且无任何驻留证据的孤立痕迹项不单独成条（避免数百个
    # "仅一个文件"的碎片淹没高/中信号），汇总为一条 CFOLD 供留样清理时顺手处理
    kept, folded = [], 0
    for c in out:
        if c["risk"] in ("高", "中") or c["persist"]:
            kept.append(c)
        else:
            folded += 1
    if folded:
        kept.append({
            "id": "CFOLD", "label": "另有 %d 个低风险独立痕迹项（无驻留证据，已折叠）" % folded,
            "kind": "折叠项", "risk": "低", "persist": False,
            "evidence": ["folded"],
            "members": [], "sample_paths": [],
            "advice": ["属历史痕迹类：可在「留样扫描与批量清理」中一并处理，无需逐项排查"],
        })
    out = kept
    summary = {"items_in": len(items), "clusters": len(out),
               "high": sum(1 for c in out if c["risk"] == "高"),
               "med": sum(1 for c in out if c["risk"] == "中"),
               "folded": folded}
    db.audit("screen.fsreg.correlate", "items=%d clusters=%d high=%d" % (
        len(items), len(out), summary["high"]))
    return {"ok": True, "summary": summary, "clusters": out,
            "plan": list(_PLAN_STEPS)}
