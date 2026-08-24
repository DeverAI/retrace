"""M9 hunt — 漏洞主流程：观察-标记-沉淀闭环。

流程：
  create_agent -> start_hunt(选定目标观察)
    -> 联动 watcher/pcap/regscan 集中观察
  finish_observation(标记风险/类别/结论)
    -> 写入观察库 + 经验回流 (knowledge + embedding)
  analyze_with_ai(观察卡片)  大模型辅助分析/报告草稿

事件：
  hunt.started {agent_id, title}
  hunt.finished {observation_id}
"""
import json
import os
import re

from core import config, db, events, logger
from modules import ai, decompile, embedding, pcap, regscan, watcher


def create_agent(name="", path="", kind=""):
    if not path or not os.path.exists(path):
        return {"ok": False, "error": "目标路径无效"}
    kind = kind or (decompile.detect_kind(path) or "unknown")
    agent_id = db.add_agent(name or os.path.basename(path), path, kind, "")
    db.audit("agent.create", "%s (%s)" % (name or path, kind))
    return {"ok": True, "agent_id": agent_id}


def list_agents():
    return db.list_agents()


def start_hunt(agent_id, title="", options=None):
    agent = _agent(agent_id)
    if not agent:
        return {"ok": False, "error": "目标不存在"}
    options = options or {}
    obs_id = db.add_observation(agent_id, title or ("观察 %s" % agent["name"]))
    items = []
    if options.get("watch_process", True):
        if agent["kind"] in ("pe", "unknown"):
            base = os.path.basename(agent["path"])
            ok, info = watcher.add_target(base, exe=agent["path"])
            if ok:
                items.append("watcher: %s (PID %s)" % (base, info["pid"]))
                # 联动观察的关键一步：仅 add_target 不会启动采集线程，
                # 必须显式 start（幂等，已运行时返回 False）
                watcher.start()
    if options.get("capture", True):
        sec = config.section("pcap")
        iface = options.get("interface") or sec.get("interface") or ""
        ok, snap = pcap.start_capture("hunt", interface=iface or None)
        items.append("pcap: %s" % ("运行中" if ok else "启动失败"))
    if options.get("reg_watch", True):
        regscan.add_watch(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
        regscan.add_watch(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        items.append("regscan: 2 个自启动键已盯守")
    evidence = [{"type": "hunt", "detail": "; ".join(items)}]
    db.update_observation(obs_id, evidence=evidence)
    db.audit("hunt.start", "obs=%d agent=%s" % (obs_id, agent["name"]))
    events.bus.publish("hunt.started",
                       {"observation_id": obs_id, "agent_id": agent_id})
    if options.get("auto_collect", True):
        collect_evidence(obs_id)
    return {"ok": True, "observation_id": obs_id}


def _agent(agent_id):
    try:
        return db.get_agent(agent_id)
    except (TypeError, ValueError):
        return None


def collect_evidence(obs_id):
    obs = db.get_observation(obs_id)
    if not obs:
        return {"ok": False, "error": "观察不存在"}
    agent = _agent(obs.get("agent_id")) or {}
    evidence = obs.get("evidence") or []

    def _block(etype, fn):
        """单证据块异常隔离：任一采集源失败不拖垮其余证据与状态流转。"""
        try:
            return fn()
        except Exception as e:
            logger.record_err("hunt.collect.%s" % etype, e)
            return {"type": etype + ".error", "detail": "采集失败: %s" % e}

    def _decompile_block():
        res = decompile.analyze(agent.get("path", ""))
        if "error" not in res:
            return {"type": "decompile", "detail": "评分: 高危%d 中危%d 可疑串%d"
                    % (res["score"]["high"], res["score"]["med"],
                       res["score"]["suspicious"]),
                    "data": json.dumps(res, ensure_ascii=False)[:4000]}
        return None

    def _timeline_block():
        tline = watcher.timeline_entries(100)
        return {"type": "timeline", "detail": "%d 条行为事件" % len(tline),
                "data": json.dumps(tline, ensure_ascii=False)[:4000]} if tline else None

    def _reg_block():
        pts = regscan.autostart_points()
        risky = [p for p in pts if p.get("risky")]
        if risky:
            return {"type": "reg_autostart",
                    "detail": "%d 个自启动项，其中 %d 疑似高危" % (len(pts), len(risky)),
                    "data": json.dumps(risky[:20], ensure_ascii=False)}
        return None

    def _pcap_block():
        pkts = pcap.get_recent("hunt", 100)
        return {"type": "packets", "detail": "%d 个数据包快照" % len(pkts),
                "data": json.dumps(pkts[:50], ensure_ascii=False)} if pkts else None

    for etype, fn in (("decompile", _decompile_block), ("timeline", _timeline_block),
                      ("reg_autostart", _reg_block), ("packets", _pcap_block)):
        if not agent and etype == "decompile":
            continue
        block = _block(etype, fn)
        if block:
            evidence.append(block)

    db.update_observation(obs_id, evidence=evidence, status="analyzed")
    db.audit("hunt.collect", "obs=%d evidence=%d" % (obs_id, len(evidence)))
    return {"ok": True, "evidence_blocks": len(evidence)}


def analyze_with_ai(obs_id):
    obs = db.get_observation(obs_id)
    if not obs:
        return {"ok": False, "error": "观察不存在"}
    if not ai.configured():
        return {"ok": False, "error": "AI 未配置"}
    short = {"title": obs.get("title"), "evidence_count": len(obs.get("evidence") or [])}
    res = ai.analyze(short)
    if not res.get("ok"):
        return res
    hint = res["text"]
    db.update_observation(obs_id, ai_hint=hint)
    return {"ok": True, "ai_hint": hint}


def finish_observation(obs_id, risk="低", category="其他", mark="", conclusion=""):
    obs = db.get_observation(obs_id)
    if not obs:
        return {"ok": False, "error": "观察不存在"}
    mark = str(mark or "")
    conclusion = str(conclusion or "")
    category = str(category or "其他")
    risk = str(risk or "低")
    db.update_observation(obs_id, status="marked", risk=risk,
                          category=category, mark=mark, conclusion=conclusion)
    text = " ".join((category or "", risk or "", mark or "", conclusion or ""))
    if mark.strip():
        db.add_knowledge(category or "未分类",
                         "%s 观察经验" % (mark[:24]),
                         text[:300],
                         ", ".join(_keywords(text[:600])), _risk_weight(risk), 1)
        embedding.remember(text[:600], {"cat": category, "risk": risk,
                                        "obs": obs_id})
    db.audit("hunt.finish", "obs=%d risk=%s cat=%s" % (obs_id, risk, category))
    events.bus.publish("hunt.finished", {"observation_id": obs_id})
    return {"ok": True}


def _keywords(text):
    return re.findall(r"[A-Za-z0-9_.:\\-]{3,}", text or "")[:6]


def _risk_weight(risk):
    return {"高": 1.0, "中": 0.6, "低": 0.3}.get(risk, 0.5)


def recent_hunts(limit=50):
    return db.get_observations(limit=limit)


def get_hunt(obs_id):
    return db.get_observation(obs_id)


def register(bus, cfg):
    pass


def shutdown():
    pass