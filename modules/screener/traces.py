"""筛查工作台——软件留样扫描（注册表全树 + 自启动 + 卸载反查 + 文件系统下钻）。"""
import os

from core import logger
from modules.screener.common import _dedup_key, _dir_has_no_exe, _finish, \
    _user_scan_dirs, _winroot

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
    """文件系统留样扫描：精确根（卸载安装路径/install_dir）深扫，用户目录浅扫。

    额外对主目录根做一层点名（如 ~/.qoder、~/.claude 等点目录）——
    历史盲区：仅扫 AppData 会漏掉全部主目录根下的厂商点目录。
    """
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
    home = os.path.expanduser("~")
    if os.path.isdir(home):
        _walk_fs(home, kw, items, seen, 0, 1, counter)
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
                    except OSError as e:
                        # 检修（2026-08-27）：只有 259(NO_MORE_ITEMS) 是正常遍历结束；
                        # 其余 OSError（权限抖动等）记档后仍终止本键，绝不静默吞掉
                        if getattr(e, "winerror", None) != 259:
                            logger.record_err("screen.traces.enumkey", e)
                        break
                    i += 1
                    try:
                        with winreg.OpenKey(uninst_key, sub, 0, winreg.KEY_READ) as k:
                            def _get(name):
                                try:
                                    v, _ = winreg.QueryValueEx(k, name)
                                    return str(v).strip()
                                except FileNotFoundError:
                                    return ""  # 值不存在：确定性的空
                                except OSError as e:
                                    # 检修：ACL/Wow64 视图打不开不是"值不存在"；
                                    # 记档避免真残留项因读失败被误判为普通条目
                                    logger.record_err(
                                        "screen.traces.qval.%s" % name, e)
                                    return ""
                            disp = _get("DisplayName")
                            loc = _get("InstallLocation")
                            pub = _get("Publisher")
                    except FileNotFoundError:
                        continue  # 子键刚被卸载删掉：正常消失
                    except OSError as e:
                        logger.record_err("screen.traces.openkey", e)
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
                    # 残留：额外产出卸载子键定位（注意：HKLM\SOFTWARE\Microsoft\Windows
                    # 前缀在清理端属确定性拒绝范围，此项仅作精确定位参考，
                    # 实际清理须经 privacy_guard 预案或手动操作）
                    if residual:
                        items.append({
                            "category": "留样", "name": "卸载条目(%s)" % (disp or sub),
                            "path": full_key, "type": "registry_key", "target": full_key,
                            "detail": "残留卸载条目（主 exe 缺失）: %s ｜ 系统范围写保护，"
                                      "仅定位参考，批量清理会拒绝该项" % full_key,
                            "risk": "高", "reason": "卸载残留（定位参考）", "state": "未处理"})
                        if loc and os.path.isdir(loc):
                            items.append({
                                "category": "留样", "name": "安装目录(%s)" % (disp or sub),
                                "path": loc, "type": "dir", "target": loc,
                                "detail": "残留安装目录（主 exe 缺失）: %s" % loc,
                                "risk": "高", "reason": "安装目录残留", "state": "未处理"})
        except FileNotFoundError:
            pass  # 卸载根键不存在：正常
        except OSError as e:
            # 检修：权限拒绝打不开卸载根键时如实记档，不再与"枚举完"混同
            logger.record_err("screen.traces.uninst_root", e)
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
