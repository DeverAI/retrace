"""筛查工作台共享基元：常量、结果封装、安全谓词、扫描根目录。

历史背景：本包前身为 2200+ 行单文件 screener.py，按域拆分为
apps / traces / cleanup / machine_fp / deep_scan / fmt_reverse / guidance。
"""
import hashlib
import json
import os
import re
from collections import Counter
from math import log2

from core import config, db

SUSPICIOUS_NAMES = ("crack", "keygen", "patch", "hack", "miner", "adware",
                    "spy", "toolbar", "inject", "loader", "updater", "fake",
                    "stealer", "rat", "proxy", "junk", "optimizer", "bonzi")
_SUS_RE = re.compile(r"(?<![a-z0-9])(?:%s)(?![a-z0-9])" % "|".join(SUSPICIOUS_NAMES), re.I)
EXE_RE = re.compile(r'"([A-Za-z]:[^"]*?\.exe)"|([A-Za-z]:\\[^",]+?\.exe)', re.I)
_MAX_FP_SCAN = 40
_MAX_FP_SIZE = 512 * 1024 * 1024

_REG_ROOTS = ("HKLM", "HKCU", "HKU", "HKCR")
# 清理仅允许 HKLM/HKCU；HKCR 是合并视图、HKU 含所有用户，均确定性拒绝
_CLEANABLE_ROOTS = ("HKLM", "HKCU")


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


def json_d(obj):
    try:
        return json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        return str(obj)


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
