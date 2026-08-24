"""筛查工作台——可疑 APP / 残留 / 指纹 / 追踪四类基础筛查。"""
import os

from core import logger
from modules.screener.common import (
    _MAX_FP_SCAN, _MAX_FP_SIZE, _SUS_RE, _extract_exe, _file_stats,
    _finish, _risk_label, json_d)


def scan_suspicious_apps():
    """扫描可疑 APP：自启动点位 + 可疑命名 + 路径缺失（残留）判定。"""
    from modules import regscan
    items, seen = [], set()
    for root in ("HKLM", "HKCU"):
        try:
            points = regscan.autostart_points(root=root)
        except Exception as e:
            logger.record_err("screen.autostart.%s" % root, e)
            continue
        for it in points:
            key = "%s|%s" % (it.get("key"), it.get("name"))
            if key in seen:
                continue
            seen.add(key)
            data = it.get("data") or ""
            exe = _extract_exe(data)
            risk, reason = 0.2, []
            if it.get("risky"):
                risk += 0.4
                reason.append("风险词")
            base = os.path.basename(exe).lower() if exe else ""
            if base and _SUS_RE.search(base):
                risk += 0.3
                reason.append("可疑命名")
            if exe:
                if not os.path.exists(os.path.expandvars(exe)):
                    risk += 0.3
                    reason.append("路径不存在(残留)")
            if not exe:
                reason.append("非exe/无路径")
            items.append({
                "category": "可疑APP", "name": it.get("name") or it.get("point"),
                "path": exe, "detail": "%s @ %s | %s" % (
                    it.get("point"), it.get("key"), (data or "")[:120]),
                "risk": _risk_label(risk), "reason": ";".join(reason) or "常规",
            })
    return _finish(items, "可疑APP")


def scan_leftover(install_dir):
    """残留筛查：主 exe 缺失 / 空目录 / 注册表悬空引用。"""
    if not install_dir or not os.path.isdir(install_dir):
        return {"category": "残留", "summary": {"total": 0, "high": 0, "med": 0,
                "low": 0, "none": 0}, "items": [], "error": "目录不存在"}
    base = os.path.abspath(install_dir)
    items = []
    exes = [f for _, _, fs in os.walk(base)
            for f in fs if f.lower().endswith(".exe")]
    if not exes:
        items.append({"category": "残留", "name": os.path.basename(base),
                      "path": base, "detail": "安装目录存在但未找到主 exe，疑似卸载残留",
                      "risk": "高", "reason": "主exe缺失", "state": "未处理"})
    for root, dirs, files in os.walk(base):
        raw_dirs = list(dirs)
        dirs[:] = [d for d in raw_dirs if not d.startswith(".")]
        if not files and not raw_dirs and os.path.abspath(root) != base:
            items.append({"category": "残留", "name": os.path.basename(root),
                          "path": root, "detail": "空目录（卸载残留）",
                          "risk": "低", "reason": "空目录", "state": "未处理"})
    # 注册表自启动指向不存在的路径
    try:
        from modules import regscan
        for root_r in ("HKLM", "HKCU"):
            for it in regscan.autostart_points(root=root_r):
                data = it.get("data") or ""
                exe = _extract_exe(data)
                if exe and not os.path.exists(os.path.expandvars(exe)):
                    items.append({"category": "残留", "name": it.get("name"),
                                  "path": exe,
                                  "detail": "自启动指向不存在的文件 %s (%s @ %s)" % (
                                      exe, it.get("point"), it.get("key")),
                                  "risk": "中", "reason": "悬空自启动", "state": "未处理"})
    except Exception as e:
        logger.record_err("screen.leftover.reg", e)
    return _finish(items, "残留")


def scan_fingerprints(base_dir):
    """目录指纹扫描：exe/dll 的哈希/熵/大小，可疑命名与高熵提示。"""
    if not base_dir or not os.path.isdir(base_dir):
        return {"category": "指纹", "summary": {"total": 0, "high": 0, "med": 0,
                "low": 0, "none": 0}, "items": [], "error": "目录不存在"}
    items = []
    base = os.path.abspath(base_dir)
    for root, dirs, files in os.walk(base):
        depth = root[len(base):].count(os.sep)
        if depth >= 6:
            dirs[:] = []
        else:
            dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            if not f.lower().endswith((".exe", ".dll")):
                continue
            p = os.path.join(root, f)
            try:
                if os.path.getsize(p) > _MAX_FP_SIZE:
                    continue
                sha, ent_raw = _file_stats(p)
                ent = round(ent_raw, 3)
            except OSError:
                continue
            fname = f.lower()
            risk = 0.2
            reason = []
            if ent > 7.5:
                risk += 0.3
                reason.append("高熵")
            if _SUS_RE.search(fname):
                risk += 0.3
                reason.append("可疑命名")
            items.append({
                "category": "指纹", "name": f, "path": p,
                "detail": "sha256:%s 大小:%d 熵:%s" % (sha[:16], os.path.getsize(p), ent),
                "risk": _risk_label(risk), "reason": ";".join(reason) or "常规",
            })
            if len(items) >= _MAX_FP_SCAN:
                break
        if len(items) >= _MAX_FP_SCAN:
            break
    return _finish(items, "指纹")


def check_file(path):
    """单文件检查：指纹 + 反编译摘要（若有）。"""
    if not path or not os.path.isfile(path):
        return {"category": "指纹", "summary": {"total": 0, "high": 0, "med": 0,
                "low": 0, "none": 0}, "items": [], "error": "文件不存在"}
    from modules.agent import executor
    r = executor.call("fingerprint", {"path": os.path.abspath(path)})
    if not r.get("ok"):
        return {"category": "指纹", "summary": {"total": 0, "high": 0, "med": 0,
                "low": 0, "none": 0}, "items": [], "error": r.get("error", "指纹检查失败")}
    data = r.get("data") or {}
    if not isinstance(data, dict) or data.get("error"):
        return {"category": "指纹", "summary": {"total": 0, "high": 0, "med": 0,
                "low": 0, "none": 0}, "items": [],
                "error": data.get("error", "指纹数据无效")}
    risk, reason = 0.2, []
    if data.get("entropy", 0) > 7.5:
        risk += 0.3
        reason.append("高熵")
    score = data.get("score") or {}
    if score.get("high"):
        risk += 0.4
        reason.append("高危调用x%d" % score["high"])
    base = os.path.basename(path).lower()
    if _SUS_RE.search(base):
        risk += 0.3
        reason.append("可疑命名")
    detail = "sha256:%s 大小:%s 熵:%s" % (data.get("sha256", "?")[:16],
                                          data.get("size", "?"), data.get("entropy", "?"))
    if data.get("calls"):
        detail += " | 调用: " + ", ".join("%s(%.1f)" % (c.get("name"), c.get("danger"))
                                          for c in data["calls"][:5])
    if data.get("strings"):
        detail += " | 串: " + "; ".join(data["strings"][:5])
    items = [{"category": "指纹", "name": os.path.basename(path), "path": os.path.abspath(path),
              "detail": detail, "risk": _risk_label(risk), "reason": ";".join(reason) or "常规"}]
    return _finish(items, "指纹")


def track_app(name, exe="", pid=None):
    """应用追踪：添加目标 → 启动观察 → 返回快照与时间线。"""
    from modules import watcher
    if not name:
        return {"error": "缺少目标名", "items": [], "summary": {}}
    r = watcher.add_target(name, pid, exe or None)
    ok = bool(isinstance(r, (tuple, list)) and r[0])
    if not ok:
        return {"error": str(r), "items": [], "summary": {}}
    watcher.start()
    snap = watcher.snapshot_target(name) or {}
    tl = watcher.timeline_entries(limit=30)
    items = [
        {"category": "追踪", "name": name, "path": exe or "",
         "detail": "目标已登记: %s | 快照: %s" % (name, json_d(snap)[:300]),
         "risk": "无", "reason": "追踪", "state": "未处理"},
    ]
    for e in tl[-25:]:
        items.append({"category": "追踪", "name": name,
                      "detail": "%s | %s" % (e.get("ts", ""), e.get("type", "")),
                      "risk": "无", "reason": "事件", "state": "未处理"})
    return _finish(items, "追踪")
