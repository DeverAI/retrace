"""狩猎域存储：agents / observations / knowledge / evolve_state / audit 读取。"""
import json

from core.db.connection import _delete, _exec, _fetch


# ---------- 审计（写入在 core.audit，此处仅提供读取） ----------

def audit_rows(limit=200):
    limit = max(1, min(int(limit), 1000))
    return _fetch("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))


def last_audit_hash():
    rows = _fetch("SELECT entry_hash FROM audit_log WHERE entry_hash<>'' "
                  "ORDER BY id DESC LIMIT 1")
    return rows[0]["entry_hash"] if rows else ""


# ---------- agents ----------

def add_agent(name="", path="", kind="", fingerprint=""):
    return _exec(
        "INSERT INTO agents(name, path, kind, fingerprint) VALUES(?,?,?,?)",
        (name, path, kind, fingerprint))


def list_agents(limit=200):
    return _fetch("SELECT * FROM agents ORDER BY id DESC LIMIT ?", (limit,))


def get_agent(agent_id):
    rows = _fetch("SELECT * FROM agents WHERE id=?", (int(agent_id),))
    return rows[0] if rows else None


# ---------- observations ----------

def add_observation(agent_id=None, title="", status="open", risk="", category="",
                    summary="", evidence=None, mark="", conclusion="", ai_hint=""):
    return _exec(
        "INSERT INTO observations(agent_id,title,status,risk,category,summary,"
        "evidence,mark,conclusion,ai_hint) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (agent_id, title, status, risk, category, summary,
         json.dumps(evidence or [], ensure_ascii=False),
         mark, conclusion, ai_hint))


def update_observation(oid, **fields):
    allowed = ("title", "status", "risk", "category", "summary", "mark",
               "conclusion", "ai_hint", "evidence")
    updates = {}
    for k in fields:
        if k in allowed:
            v = fields[k]
            if k == "evidence":
                v = json.dumps(v or [], ensure_ascii=False)
            updates[k] = v
    sets = [k + "=?" for k in updates]
    vals = list(updates.values())
    if not sets:
        return
    sets.append("updated_at=datetime('now','localtime')")
    _exec("UPDATE observations SET %s WHERE id=?" % ", ".join(sets), vals + [oid])


def get_observations(status=None, limit=200):
    sql = "SELECT * FROM observations"
    params = ()
    if status:
        sql += " WHERE status=?"
        params = (status,)
    sql += " ORDER BY id DESC LIMIT ?"
    rows = _fetch(sql, params + (limit,))
    for r in rows:
        try:
            r["evidence"] = json.loads(r["evidence"])
        except (ValueError, TypeError):
            r["evidence"] = []
    return rows


def get_observation(oid):
    rows = _fetch("SELECT * FROM observations WHERE id=?", (oid,))
    if not rows:
        return None
    r = rows[0]
    try:
        r["evidence"] = json.loads(r["evidence"])
    except (ValueError, TypeError):
        r["evidence"] = []
    return r


def delete_observation(oid):
    oid = int(oid)
    if oid <= 0:
        raise ValueError("无效的观察条目 id: %s" % oid)
    return _delete("DELETE FROM observations WHERE id=?", (oid,))


# ---------- knowledge ----------

def add_knowledge(category, title, pattern, keywords="", risk_weight=0.5,
                  source_obs=0):
    return _exec(
        "INSERT INTO knowledge(category,title,pattern,keywords,risk_weight,"
        "source_obs) VALUES(?,?,?,?,?,?)",
        (category, title, pattern, keywords, risk_weight, source_obs))


def list_knowledge(enabled_only=False, limit=500):
    sql = "SELECT * FROM knowledge"
    params = ()
    if enabled_only:
        sql += " WHERE enabled=1"
    sql += " ORDER BY risk_weight DESC LIMIT ?"
    return _fetch(sql, params + (limit,))


def set_knowledge_enabled(kid, enabled):
    kid = int(kid)
    if kid <= 0:
        raise ValueError("无效的经验条目 id: %s" % kid)
    if not _fetch("SELECT 1 FROM knowledge WHERE id=?", (kid,)):
        return False
    _exec("UPDATE knowledge SET enabled=? WHERE id=?", (1 if enabled else 0, kid))
    return True


def set_knowledge_weight(kid, weight):
    """调整经验规则风险权重（evolve.adjust_weights 的落库通道）。返回是否存在。"""
    kid = int(kid)
    if kid <= 0:
        raise ValueError("无效的经验条目 id: %s" % kid)
    try:
        weight = max(0.0, min(1.0, float(weight)))
    except (TypeError, ValueError):
        raise ValueError("无效的风险权重: %r" % weight)
    if not _fetch("SELECT 1 FROM knowledge WHERE id=?", (kid,)):
        return False
    _exec("UPDATE knowledge SET risk_weight=? WHERE id=?", (weight, kid))
    return True


def delete_knowledge(kid):
    kid = int(kid)
    if kid <= 0:
        raise ValueError("无效的经验条目 id: %s" % kid)
    return _delete("DELETE FROM knowledge WHERE id=?", (kid,))


# ---------- evolve_state ----------

def evolve_get(key, default=""):
    rows = _fetch("SELECT value FROM evolve_state WHERE key=?", (key,))
    return rows[0]["value"] if rows else default


def evolve_set(key, value):
    _exec("INSERT OR REPLACE INTO evolve_state(key,value) VALUES(?,?)",
          (key, str(value)))
