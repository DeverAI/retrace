"""筛查工作台——指纹再生监测（漂移对比）。

回答一个关键问题：清理/改写指纹文件之后，软件是否悄悄重建了它？
状态分类（两次观测粒度）：
  - unchanged            值未变
  - value_changed        值变了（软件重新生成 → 本地"失忆"成功）
  - gone                 已消失
  - new                  新出现
  - recreated_same_value 曾在基线中出现、消失后以**相同内容**回来
                         → 软件有云端/备份恢复机制，本地清理无效。这是最关键信号。
实现：evolve_state 里存 {"baseline": 快照, "history": 全部见过的哈希}。
纯函数 classify_paths 可回归测试。
"""
import hashlib
import json
import os
import threading

from core import db
from modules.screener.ai_tools import scan_ai_tool_traces
from modules.screener.machine_fp import scan_machine_fingerprints

_STATE_KEY = "fp_drift.state.v1"
# 检修（2026-08-27）：load→modify→save 临界区互斥（与 cleanup/_plan_lock 同惯例，
# 防并发两次 commit 交错覆盖丢 history/回退基线）
_state_lock = threading.Lock()


def _file_sig(path):
    try:
        st = os.stat(path)
        with open(path, "rb") as f:
            h = hashlib.sha256(f.read(1024 * 1024)).hexdigest()[:16]
        return {"sha16": h, "size": int(st.st_size)}
    except OSError:
        return None


def build_snapshot(paths):
    """路径列表 → {norm_path: {sha16,size}}；仅文件型产物参与，已消失的不出现。"""
    out = {}
    for p in paths or []:
        if not p or not os.path.isfile(p):
            continue
        sig = _file_sig(p)
        if sig is not None:
            out[os.path.normcase(os.path.abspath(p))] = sig
    return out


def classify_paths(baseline, history, current):
    """纯函数：按 (baseline, history, current) 三方给每条路径定状态。

    history 为 {path: [{sha16,size}, ...]} 的累积集合（每路径保留多个历史态），
    使"删除后以任意历史值复活"都可被识别：
      - 在 baseline：当前也在 → 同值 unchanged / 异值 value_changed；当前不在 → gone
      - 不在 baseline：当前在 → history 中存在 (sha,size) 完全相同条目 →
        recreated_same_value；history 有该路径但值都不同 → regenerated_new_value；
        无记录 → new
    """
    baseline = baseline or {}
    history = history or {}
    rows = []
    for path in sorted(set(baseline) | set(current)):
        b, c = baseline.get(path), current.get(path)
        if b and not c:
            rows.append({"path": path, "status": "gone",
                         "baseline_sha": b.get("sha16", ""), "current_sha": ""})
        elif b and c:
            same = b.get("sha16") == c.get("sha16") and b.get("size") == c.get("size")
            rows.append({"path": path,
                         "status": "unchanged" if same else "value_changed",
                         "baseline_sha": b.get("sha16", ""),
                         "current_sha": c.get("sha16", "")})
        elif c:
            hist_entries = history.get(path) or []
            sig = {"sha16": c.get("sha16"), "size": c.get("size")}
            if any(e.get("sha16") == sig["sha16"] and e.get("size") == sig["size"]
                   for e in hist_entries if isinstance(e, dict)):
                status = "recreated_same_value"
            elif hist_entries:
                status = "regenerated_new_value"
            else:
                status = "new"
            rows.append({"path": path, "status": status,
                         "baseline_sha": "", "current_sha": c.get("sha16", "")})
    return rows


def load_state():
    raw = db.evolve_get(_STATE_KEY, "")
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                baseline = data.get("baseline") or {}
                history = data.get("history") or {}
                # 兼容 v1 单对象格式 {path: {sha16,size}} → 包装为列表
                for p, v in list(history.items()):
                    if isinstance(v, dict):
                        history[p] = [v]
                return (baseline, history)
        except ValueError:
            pass
    return None, None


def save_state(baseline, history):
    db.evolve_set(_STATE_KEY, json.dumps(
        {"baseline": baseline, "history": history}, ensure_ascii=False))


def collect_fingerprint_paths(keyword=""):
    """汇总机器指纹 + AI 痕迹两类扫描命中的文件路径（仅 file 型）。"""
    paths = []
    for res in (scan_machine_fingerprints(keyword),
                scan_ai_tool_traces(keyword)):
        for it in res.get("items", []):
            p = it.get("path") or ""
            if p and os.path.isfile(p):
                paths.append(p)
    return paths


def fingerprint_drift_report(keyword="", commit=False):
    """当前扫描 vs 存储基线 → 漂移报告。

    commit=True 时把本次快照并入基线，并把当前内容并入 history
    （首次调用自动建立基线）。history 只增不减，才能捕捉"删除又回来"。
    检修（2026-08-27）：
      1) 关键词过滤视图绝不允许塌缩全局基线——历史缺陷：commit 用本次
         过滤快照整体替换基线，之后无过滤运行时全部原路径被误判
         recreated_same_value，监测功能失效。现改为 merge（旧键保留）；
         且首次运行+keyword+commit 组合直接拒绝（子集没有资格当初始基线）。
      2) 全程持 _state_lock，消除读改写竞态。
    """
    with _state_lock:
        return _drift_report_locked(keyword, bool(commit))


def _drift_report_locked(keyword, commit):
    paths = collect_fingerprint_paths(keyword)
    current = build_snapshot(paths)
    baseline, history = load_state()
    first_run = baseline is None
    if first_run and keyword and commit:
        return {"ok": False,
                "error": "首次基线必须全量建立：带关键词的过滤视图不可作为全局基线"
                         "（请去掉关键词重试，或先无过滤 commit 一次）"}
    if first_run:
        rows = [{"path": p, "status": "new", "baseline_sha": "",
                 "current_sha": s["sha16"]}
                for p, s in sorted(current.items())]
        report = {"ok": True, "first_run": True,
                  "message": "首次运行：当前状态已记录为基线；之后再次运行即可看到漂移。",
                  "tracked_files": len(current), "changes": [],
                  "summary": {"tracked": len(current), "changed": 0}}
    else:
        rows = classify_paths(baseline, history, current)
        changed = [r for r in rows if r["status"] not in ("unchanged",)]
        report = {"ok": True, "first_run": False,
                  "tracked_files": len(current),
                  "summary": {
                      "tracked": len(current),
                      "unchanged": sum(1 for r in rows if r["status"] == "unchanged"),
                      "changed": len(changed),
                      "recreated_same_value": sum(
                          1 for r in rows if r["status"] == "recreated_same_value"),
                  },
                  "changes": changed}
        # 关键告警语义：存在"原样复活"时在报告顶部显式提示
        if any(r["status"] == "recreated_same_value" for r in rows):
            report["warning"] = (
                "检测到指纹文件被删除后以相同内容复活——软件具备云端/备份恢复机制，"
                "仅本地清理无效；需配合账号侧注销或沙箱隔离。")
    if commit or first_run:
        # history 每路径累积历史态集合（上限 8 条/路径，FIFO），只增不减：
        # 这样"值 A → 值 B → 删除 → 软件用 A 复活"仍能识别 recreated_same_value
        merged_history = dict(history or {})
        for p, sig in current.items():
            entries = [e for e in merged_history.get(p, []) if isinstance(e, dict)]
            if sig not in entries:
                entries.append(dict(sig))
                merged_history[p] = entries[-8:]
            else:
                merged_history[p] = entries  # 已见过的态：保持原序
        # 基线同样只增不塌缩：过滤视图 commit 时 merge 进全局基线，
        # 未被本次扫描覆盖的旧条目原样保留（gone 语义依赖它们存在）
        if keyword:
            merged_baseline = dict(baseline or {})
            merged_baseline.update(current)
        else:
            merged_baseline = current
        save_state(merged_baseline, merged_history)
        report["baseline_committed"] = True
    db.audit("screen.drift", "keyword=%s tracked=%d first=%s commit=%s" % (
        keyword or "(all)", len(current), first_run, bool(commit)))
    return report


if __name__ == "__main__":  # 自检
    r = fingerprint_drift_report(commit=True)
    print(json.dumps(r["summary"], ensure_ascii=False))
