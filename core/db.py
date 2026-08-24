"""SQLite 数据层：观察库、经验库、目标档案、审计日志。"""
import json
import os
import sqlite3
import threading
import time

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "retrace.db")

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  path TEXT,
  kind TEXT,
  fingerprint TEXT,
  created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id INTEGER,
  title TEXT,
  status TEXT DEFAULT 'open',
  risk TEXT DEFAULT '',
  category TEXT DEFAULT '',
  summary TEXT DEFAULT '',
  evidence TEXT DEFAULT '[]',
  mark TEXT DEFAULT '',
  conclusion TEXT DEFAULT '',
  ai_hint TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now','localtime')),
  updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS knowledge (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT DEFAULT '',
  title TEXT,
  pattern TEXT,
  keywords TEXT DEFAULT '',
  risk_weight REAL DEFAULT 0.5,
  source_obs INTEGER DEFAULT 0,
  enabled INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT DEFAULT (datetime('now','localtime')),
  op TEXT,
  detail TEXT,
  actor TEXT DEFAULT 'system',
  resource TEXT DEFAULT '',
  outcome TEXT DEFAULT 'success',
  risk TEXT DEFAULT 'info',
  request_id TEXT DEFAULT '',
  prev_hash TEXT DEFAULT '',
  entry_hash TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS evolve_state (
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS tracking_tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  exe_path TEXT DEFAULT '',
  process_name TEXT DEFAULT '',
  pid INTEGER,
  watch_paths TEXT DEFAULT '[]',
  interval_sec REAL DEFAULT 5,
  status TEXT DEFAULT 'paused',
  enabled INTEGER DEFAULT 0,
  ai_enabled INTEGER DEFAULT 0,
  checkpoint TEXT DEFAULT '{}',
  last_run_at TEXT DEFAULT '',
  next_run_at REAL DEFAULT 0,
  last_error TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now','localtime')),
  updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS tracking_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  ts TEXT DEFAULT (datetime('now','localtime')),
  type TEXT NOT NULL,
  severity TEXT DEFAULT 'info',
  source TEXT DEFAULT 'daemon',
  detail TEXT DEFAULT '',
  data TEXT DEFAULT '{}',
  fingerprint TEXT NOT NULL,
  count INTEGER DEFAULT 1,
  last_seen TEXT DEFAULT (datetime('now','localtime')),
  UNIQUE(task_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_tracking_events_task ON tracking_events(task_id, id DESC);
CREATE TABLE IF NOT EXISTS task_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  started_at TEXT DEFAULT (datetime('now','localtime')),
  finished_at TEXT DEFAULT '',
  outcome TEXT DEFAULT 'running',
  event_count INTEGER DEFAULT 0,
  error TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS daemon_leases (
  name TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  heartbeat REAL NOT NULL
);
"""


def conn():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=30000")
    return con


def init():
    with _lock:
        con = conn()
        try:
            con.executescript(SCHEMA)
            _migrate(con)
            con.commit()
        finally:
            con.close()


def _migrate(con):
    """Additive migrations for databases created by older ReTrace builds."""
    cols = {r[1] for r in con.execute("PRAGMA table_info(audit_log)")}
    wanted = {
        "actor": "TEXT DEFAULT 'system'", "resource": "TEXT DEFAULT ''",
        "outcome": "TEXT DEFAULT 'success'", "risk": "TEXT DEFAULT 'info'",
        "request_id": "TEXT DEFAULT ''", "prev_hash": "TEXT DEFAULT ''",
        "entry_hash": "TEXT DEFAULT ''",
    }
    for name, ddl in wanted.items():
        if name not in cols:
            con.execute("ALTER TABLE audit_log ADD COLUMN %s %s" % (name, ddl))


def _fetch(sql, params=()):
    with _lock:
        con = conn()
        try:
            cur = con.execute(sql, params)
            rows = cur.fetchall()
            return [dict(r) for r in rows]
        finally:
            con.close()


def _exec(sql, params=()):
    with _lock:
        con = conn()
        try:
            cur = con.execute(sql, params)
            con.commit()
            return cur.lastrowid
        finally:
            con.close()


def _delete(sql, params=()):
    """删除/更新类语句：返回是否实际影响了行（区别于 lastrowid 恒 0）。"""
    with _lock:
        con = conn()
        try:
            cur = con.execute(sql, params)
            con.commit()
            return cur.rowcount > 0
        finally:
            con.close()


def audit(op, detail=""):
    try:
        from core import audit as security_audit
        security_audit.record(op, detail)
    except Exception as e:
        from core import logger
        logger.record_err("db.audit", e)


def audit_rows(limit=200):
    limit = max(1, min(int(limit), 1000))
    return _fetch("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))


def last_audit_hash():
    rows = _fetch("SELECT entry_hash FROM audit_log WHERE entry_hash<>'' ORDER BY id DESC LIMIT 1")
    return rows[0]["entry_hash"] if rows else ""


def add_agent(name="", path="", kind="", fingerprint=""):
    return _exec(
        "INSERT INTO agents(name, path, kind, fingerprint) VALUES(?,?,?,?)",
        (name, path, kind, fingerprint))


def list_agents(limit=200):
    return _fetch("SELECT * FROM agents ORDER BY id DESC LIMIT ?", (limit,))


def get_agent(agent_id):
    rows = _fetch("SELECT * FROM agents WHERE id=?", (int(agent_id),))
    return rows[0] if rows else None


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


def evolve_get(key, default=""):
    rows = _fetch("SELECT value FROM evolve_state WHERE key=?", (key,))
    return rows[0]["value"] if rows else default


def evolve_set(key, value):
    _exec("INSERT OR REPLACE INTO evolve_state(key,value) VALUES(?,?)",
          (key, str(value)))


def create_tracking_task(name, exe_path="", process_name="", pid=None,
                         watch_paths=None, interval_sec=5, ai_enabled=False):
    return _exec(
        "INSERT INTO tracking_tasks(name,exe_path,process_name,pid,watch_paths,"
        "interval_sec,ai_enabled) VALUES(?,?,?,?,?,?,?)",
        (name, exe_path, process_name, pid,
         json.dumps(watch_paths or [], ensure_ascii=False),
         max(1.0, float(interval_sec)), 1 if ai_enabled else 0))


def _decode_task(row):
    if not row:
        return row
    for key, fallback in (("watch_paths", []), ("checkpoint", {})):
        try:
            row[key] = json.loads(row.get(key) or "")
        except (ValueError, TypeError):
            row[key] = fallback
    row["enabled"] = bool(row.get("enabled"))
    row["ai_enabled"] = bool(row.get("ai_enabled"))
    return row


def list_tracking_tasks(limit=500):
    rows = _fetch("SELECT * FROM tracking_tasks ORDER BY id DESC LIMIT ?",
                  (max(1, min(int(limit), 2000)),))
    return [_decode_task(r) for r in rows]


def get_tracking_task(task_id):
    rows = _fetch("SELECT * FROM tracking_tasks WHERE id=?", (int(task_id),))
    return _decode_task(rows[0]) if rows else None


def update_tracking_task(task_id, **fields):
    allowed = {"name", "exe_path", "process_name", "pid", "watch_paths",
               "interval_sec", "status", "enabled", "ai_enabled", "checkpoint",
               "last_run_at", "next_run_at", "last_error"}
    updates = {}
    for key, value in fields.items():
        if key not in allowed:
            continue
        if key in ("watch_paths", "checkpoint"):
            value = json.dumps(value or ([] if key == "watch_paths" else {}),
                               ensure_ascii=False, default=str)
        if key in ("enabled", "ai_enabled"):
            value = 1 if value else 0
        updates[key] = value
    if not updates:
        return False
    sets = ["%s=?" % key for key in updates]
    sets.append("updated_at=datetime('now','localtime')")
    _exec("UPDATE tracking_tasks SET %s WHERE id=?" % ",".join(sets),
          list(updates.values()) + [int(task_id)])
    return True


def delete_tracking_task(task_id):
    task_id = int(task_id)
    with _lock:
        con = conn()
        try:
            con.execute("DELETE FROM tracking_events WHERE task_id=?", (task_id,))
            con.execute("DELETE FROM task_runs WHERE task_id=?", (task_id,))
            cur = con.execute("DELETE FROM tracking_tasks WHERE id=?", (task_id,))
            con.commit()
            return cur.rowcount > 0
        finally:
            con.close()


def upsert_tracking_event(task_id, event):
    payload = _tracking_payload(event.get("data") or {})
    fingerprint = event.get("fingerprint") or ""
    with _lock:
        con = conn()
        try:
            con.execute(
                "INSERT INTO tracking_events(task_id,type,severity,source,detail,data,fingerprint) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(task_id,fingerprint) DO UPDATE SET "
                "count=count+1,last_seen=datetime('now','localtime'),detail=excluded.detail,data=excluded.data",
                (int(task_id), event.get("type", "event"), event.get("severity", "info"),
                 event.get("source", "daemon"), str(event.get("detail", ""))[:2000],
                 payload, fingerprint))
            con.commit()
            return con.execute("SELECT changes()").fetchone()[0]
        finally:
            con.close()


def tracking_events(task_id, limit=300):
    rows = _fetch("SELECT * FROM tracking_events WHERE task_id=? ORDER BY id DESC LIMIT ?",
                  (int(task_id), max(1, min(int(limit), 2000))))
    for row in rows:
        try:
            row["data"] = json.loads(row.get("data") or "{}")
        except (ValueError, TypeError):
            row["data"] = {}
    return rows


def count_tracking_events(task_id):
    rows = _fetch("SELECT COUNT(*) AS total FROM tracking_events WHERE task_id=?",
                  (int(task_id),))
    return int(rows[0]["total"]) if rows else 0


def start_task_run(task_id):
    return _exec("INSERT INTO task_runs(task_id) SELECT id FROM tracking_tasks WHERE id=?",
                 (int(task_id),))


def finish_task_run(run_id, outcome, event_count=0, error=""):
    _exec("UPDATE task_runs SET finished_at=datetime('now','localtime'),outcome=?,"
          "event_count=?,error=? WHERE id=?",
          (outcome, int(event_count), str(error)[:2000], int(run_id)))


def _tracking_payload(data, max_chars=16000):
    """Encode valid JSON while retaining attribution fields under the size limit."""
    if not isinstance(data, dict):
        data = {}
    payload = json.dumps(data, ensure_ascii=False, default=str)
    if len(payload) <= max_chars:
        return payload
    keep = ("provider", "confidence", "warning", "record_id", "event_id", "time",
            "pid", "image", "process", "operation", "action", "key", "path", "query",
            "access_mask", "access_list", "access_labels", "object_type", "status")
    reduced = {key: data.get(key) for key in keep if key in data}
    for key, value in list(reduced.items()):
        if isinstance(value, str):
            reduced[key] = value[:1200]
        elif isinstance(value, (list, tuple)):
            reduced[key] = list(value)[:50]
    reduced["payload_truncated"] = True
    reduced["original_json_chars"] = len(payload)
    payload = json.dumps(reduced, ensure_ascii=False, default=str)
    if len(payload) > max_chars:
        # 末级兜底：original_json_chars 记录的是真·原始长度（第一级里已保存），
        # 不能用缩减版字符串自身的长度，否则字段语义失真。
        payload = json.dumps({"provider": str(data.get("provider", ""))[:200],
                              "confidence": data.get("confidence", "unknown"),
                              "payload_truncated": True,
                              "original_json_chars": reduced.get(
                                  "original_json_chars", len(payload))}, ensure_ascii=False)
    return payload


def commit_tracking_batch(task_id, run_id, events, checkpoint, interval_sec,
                          retention=5000, lease_owner=""):
    """Atomically commit a collection batch if the task is still runnable.

    Re-checking enabled/status under BEGIN IMMEDIATE closes the pause/delete race:
    a worker that finished after a user pause cannot publish stale state or advance
    the event checkpoint.
    """
    task_id, run_id = int(task_id), int(run_id)
    retention = max(100, min(int(retention), 100000))
    with _lock:
        con = conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            task = con.execute(
                "SELECT enabled,status FROM tracking_tasks WHERE id=?", (task_id,)).fetchone()
            lease_ok = True
            if lease_owner:
                lease = con.execute(
                    "SELECT owner,heartbeat FROM daemon_leases WHERE name='tracking'").fetchone()
                lease_ok = bool(lease and lease["owner"] == lease_owner and
                                time.time() - float(lease["heartbeat"]) < 15)
            if (not task or not bool(task["enabled"]) or task["status"] == "paused" or
                    not lease_ok):
                con.execute(
                    "UPDATE task_runs SET finished_at=datetime('now','localtime'),"
                    "outcome='skipped',event_count=0 WHERE id=?", (run_id,))
                con.commit()
                return False
            for event in events:
                payload = _tracking_payload(event.get("data") or {})
                con.execute(
                    "INSERT INTO tracking_events(task_id,type,severity,source,detail,data,fingerprint) "
                    "VALUES(?,?,?,?,?,?,?) ON CONFLICT(task_id,fingerprint) DO UPDATE SET "
                    "count=count+1,last_seen=datetime('now','localtime'),"
                    "detail=excluded.detail,data=excluded.data",
                    (task_id, event.get("type", "event"), event.get("severity", "info"),
                     event.get("source", "daemon"), str(event.get("detail", ""))[:2000],
                     payload, event["fingerprint"]))
            con.execute(
                "UPDATE tracking_tasks SET checkpoint=?,status='running',"
                "last_run_at=datetime('now','localtime'),next_run_at=?,last_error='',"
                "updated_at=datetime('now','localtime') WHERE id=?",
                (json.dumps(checkpoint or {}, ensure_ascii=False, default=str),
                 time.time() + max(0.1, float(interval_sec)), task_id))
            con.execute(
                "UPDATE task_runs SET finished_at=datetime('now','localtime'),outcome='success',"
                "event_count=?,error='' WHERE id=?", (len(events), run_id))
            con.execute(
                "DELETE FROM tracking_events WHERE task_id=? AND id NOT IN "
                "(SELECT id FROM tracking_events WHERE task_id=? "
                "ORDER BY last_seen DESC,id DESC LIMIT ?)",
                (task_id, task_id, retention))
            con.execute(
                "DELETE FROM task_runs WHERE task_id=? AND id NOT IN "
                "(SELECT id FROM task_runs WHERE task_id=? ORDER BY id DESC LIMIT 1000)",
                (task_id, task_id))
            con.commit()
            return True
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()


def fail_tracking_batch(task_id, run_id, error, retry_at, lease_owner=""):
    """Record a failed run without reviving a task paused during collection."""
    with _lock:
        con = conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            lease_ok = True
            if lease_owner:
                lease = con.execute(
                    "SELECT owner,heartbeat FROM daemon_leases WHERE name='tracking'").fetchone()
                lease_ok = bool(lease and lease["owner"] == lease_owner and
                                time.time() - float(lease["heartbeat"]) < 15)
            if lease_ok:
                con.execute(
                    "UPDATE tracking_tasks SET status='error',last_error=?,next_run_at=?,"
                    "updated_at=datetime('now','localtime') "
                    "WHERE id=? AND enabled=1 AND status<>'paused'",
                    (str(error)[:2000], float(retry_at), int(task_id)))
            con.execute(
                "UPDATE task_runs SET finished_at=datetime('now','localtime'),outcome='error',"
                "error=? WHERE id=?", (str(error)[:2000], int(run_id)))
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()


def task_runs(task_id, limit=100):
    return _fetch("SELECT * FROM task_runs WHERE task_id=? ORDER BY id DESC LIMIT ?",
                  (int(task_id), max(1, min(int(limit), 500))))


def acquire_daemon_lease(name, owner, ttl=15):
    now = time.time()
    with _lock:
        con = conn()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT owner,heartbeat FROM daemon_leases WHERE name=?",
                              (name,)).fetchone()
            if row and row["owner"] != owner and now - float(row["heartbeat"]) < ttl:
                con.rollback()
                return False
            con.execute("INSERT OR REPLACE INTO daemon_leases(name,owner,heartbeat) VALUES(?,?,?)",
                        (name, owner, now))
            con.commit()
            return True
        finally:
            con.close()


def refresh_daemon_lease(name, owner):
    with _lock:
        con = conn()
        try:
            cur = con.execute("UPDATE daemon_leases SET heartbeat=? WHERE name=? AND owner=?",
                              (time.time(), name, owner))
            con.commit()
            return cur.rowcount > 0
        finally:
            con.close()


def release_daemon_lease(name, owner):
    _exec("DELETE FROM daemon_leases WHERE name=? AND owner=?", (name, owner))


def daemon_lease(name):
    rows = _fetch("SELECT * FROM daemon_leases WHERE name=?", (name,))
    return rows[0] if rows else None
