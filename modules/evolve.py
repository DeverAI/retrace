"""M5 evolve — 自我进化：规则挖掘 / 权重调整 / 进化报告。

数据闭环：
  observations(knowledge) -> mine_rules() -> candidate rules
  audit_log + observations -> adjust_weights() -> evolve_state
  report() -> 周期报告（供 UI 展示与人工确认）

事件：
  evolve.rules_ready  {rules: [...]}
"""
import json
import re
import time
from collections import Counter

from core import config, db, events, logger
from core.coerce import strict_bool as _strict_bool

RISK_MAP = {"高": 1.0, "中": 0.6, "低": 0.3, "无": 0.0, "HIGH": 1.0,
            "MED": 0.6, "LOW": 0.3, "NONE": 0.0}

TOKEN_RE = re.compile(r"[A-Za-z0-9_.:\\-]{3,}")
NOISE = {"none", "null", "true", "false", "http", "https", "www", "com",
         "exe", "dll", "system32", "windows", "software", "microsoft",
         "currentversion", "key", "name", "data", "value"}


def _tokens(text):
    text = text or ""
    return [t for t in TOKEN_RE.findall(text.lower())
            if t not in NOISE and not t.isdigit()]


def _risk_score(category, risk):
    r = (risk or "").strip()
    for k, v in RISK_MAP.items():
        if k.lower() == r.lower() or k in r:
            return v
    if category and "高危" in category:
        return 1.0
    return 0.5


def _evidence_text(obs):
    parts = []
    for ev in obs.get("evidence") or []:
        if isinstance(ev, dict):
            for k in ("detail", "data", "reason", "summary", "name"):
                if ev.get(k):
                    parts.append(str(ev[k]))
        else:
            parts.append(str(ev))
    parts.append(obs.get("mark") or obs.get("conclusion") or "")
    return " ".join(parts)


# _strict_bool 已统一至 core.coerce.strict_bool（模块顶部导入）


def mine_rules(min_obs=3, top_tokens=6, auto_apply=None):
    sec = config.section("evolve")
    if auto_apply is None:
        auto_apply = bool(sec.get("auto_apply", False))
    else:
        auto_apply = _strict_bool(auto_apply)
    if min_obs is None:
        min_obs = int(sec.get("min_obs_to_mine", 3))
    try:
        min_obs = int(min_obs)
        top_tokens = int(top_tokens)
    except (TypeError, ValueError):
        raise ValueError("min_obs/top_tokens 必须为整数")
    min_obs = max(1, min_obs)
    top_tokens = max(1, min(top_tokens, 20))
    obs_all = db.get_observations(limit=5000)
    obs = [o for o in obs_all if o.get("status") in ("analyzed", "marked", "closed")
           or (o.get("mark") and o["mark"].strip())]
    if len(obs) < min_obs:
        return {"ok": True, "rules": [], "reason": "观察样本不足 "
                "(%d < %d)" % (len(obs), min_obs)}
    groups = {}
    for o in obs:
        key = (o.get("category") or "未分类", _risk_score(o.get("category"),
                                                          o.get("risk")))
        groups.setdefault(key, []).append(o)
    existing = {k["title"] for k in db.list_knowledge(limit=5000)}
    rules = []
    for (category, weight), items in groups.items():
        if len(items) < min_obs:
            continue
        counter = Counter()
        for o in items:
            counter.update(_tokens(_evidence_text(o)))
        top = [t for t, _ in counter.most_common(top_tokens)]
        if len(top) < 2:
            continue
        title = "%s 关联 %s" % (category, " / ".join(top[:3]))
        if title in existing:
            continue
        pattern = " AND ".join(top[:4])
        item = {
            "category": category, "title": title,
            "pattern": pattern[:300],
            "keywords": ", ".join(top),
            "risk_weight": round(min(1.0, weight + 0.1), 2),
            "source_obs": len(items),
        }
        rules.append(item)
    if auto_apply:
        for item in rules:
            db.add_knowledge(item["category"], item["title"], item["pattern"],
                             item["keywords"], item["risk_weight"], item["source_obs"])
            existing.add(item["title"])  # 同一次调用内去重：防止另一分组生成相同 title 再写一遍
        db.audit("evolve.mine_apply", "rules=%d auto_apply=%s" % (len(rules), auto_apply))
    result = {"ok": True, "rules": rules, "auto_apply": auto_apply}
    events.bus.publish("evolve.rules_ready", {"rules": rules})
    return result


def adjust_weights(auto_apply=None):
    """按历史命中统计，对"热点类别"的启用经验规则做权重微调。

    - auto_apply=False（默认，受 config.evolve.auto_apply 约束）：只计算候选调整并写入
      evolve_state 的 weight_state（供 report 展示），不落库；
    - auto_apply=True：真正回写 knowledge.risk_weight（+0.05，上限 1.0，下限 0.0），
      并记审计。返回结构与候选调整供前端展示。
    """
    sec = config.section("evolve")
    if auto_apply is None:
        auto_apply = bool(sec.get("auto_apply", False))
    else:
        auto_apply = _strict_bool(auto_apply)
    stats = {"high": 0, "med": 0, "low": 0, "none": 0, "total": 0}
    cat_count = Counter()
    cat_high = Counter()
    for o in db.get_observations(limit=5000):
        score = _risk_score(o.get("category"), o.get("risk"))
        key = {1.0: "high", 0.6: "med", 0.3: "low"}.get(score, "none")
        stats[key] += 1
        stats["total"] += 1
        cat = o.get("category") or "未分类"
        cat_count[cat] += 1
        if score >= 0.8:
            cat_high[cat] += 1
    hot = None
    for cat, n in cat_count.items():
        if n >= 2 and cat_high[cat] / n >= 0.5:
            hot = cat
            break
    # 候选调整：热点类别的启用规则 +0.05（≤1.0）
    adjustments = []
    if hot:
        for k in db.list_knowledge(limit=5000):
            if not k.get("enabled") or k.get("category") != hot:
                continue
            try:
                before = max(0.0, min(1.0, float(k.get("risk_weight") or 0.5)))
            except (TypeError, ValueError):
                before = 0.5
            after = round(min(1.0, before + 0.05), 2)
            if after == before:
                continue
            entry = {"id": k["id"], "title": k.get("title", ""),
                     "category": hot, "before": before, "after": after}
            if auto_apply:
                try:
                    db.set_knowledge_weight(k["id"], after)
                    entry["applied"] = True
                except (TypeError, ValueError) as exc:
                    logger.record_err("evolve.adjust.%s" % k["id"], exc)
                    entry["applied"] = False
                    entry["error"] = str(exc)
            adjustments.append(entry)
        if auto_apply and adjustments:
            db.audit("evolve.adjust_apply",
                     "category=%s rules=%d" % (hot, len(adjustments)))
    state = {
        "stats": stats,
        "hot_category": hot,
        "auto_apply": bool(auto_apply),
        "adjustments": adjustments,
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    db.evolve_set("weight_state", json.dumps(state, ensure_ascii=False))
    return state


def report():
    rules = db.list_knowledge(limit=500)
    try:
        stats = json.loads(db.evolve_get("weight_state", "{}") or "{}")
    except (ValueError, TypeError):
        stats = {}
    enabled = sum(1 for r in rules if r.get("enabled"))
    obs_count = len(db.get_observations(limit=5000))
    report = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "knowledge_rules": len(rules),
        "knowledge_enabled": enabled,
        "observations": obs_count,
        "risk_stats": stats.get("stats", {}),
        "hot_category": stats.get("hot_category"),
        "top_rules": rules[:10],
    }
    return report


def register(bus, cfg):
    pass


def shutdown():
    pass