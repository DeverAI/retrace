"""任务追踪域存储：tracking_tasks / tracking_events / task_runs / daemon_leases。

含批量提交的事务协议（commit_tracking_batch）：暂停/删除与采集线程的
竞态在 BEGIN IMMEDIATE 内复核，杜绝僵尸批次复活已暂停任务。
"""
import json
import time

from core.db.connection import _delete, _exec, _fetch, transaction


# ---------- 行解码 ----------

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


# ---------- tasks ----------

def create_tracking_task(name, exe_path="", process_name="", pid=None,
                         watch_paths=None, interval_sec=5, ai_enabled=False):
    return _exec(
        "INSERT INTO tracking_tasks(name,exe_path,process_name,pid,watch_paths,"
        "interval_sec,ai_enabled) VALUES(?,?,?,?,?,?,?)",
        (name, exe_path, process_name, pid,
         json.dumps(watch_paths or [], ensure_ascii=False),
         max(1.0, float(interval_sec)), 1 if ai_enabled else 0))


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
    with transaction() as con:
        con.execute("DELETE FROM tracking_events WHERE task_id=?", (task_id,))
        con.execute("DELETE FROM task_runs WHERE task_id=?", (task_id,))
        cur = con.execute("DELETE FROM tracking_tasks WHERE id=?", (task_id,))
        return cur.rowcount > 0


# ---------- events ----------

def upsert_tracking_event(task_id, event):
    payload = _tracking_payload(event.get("data") or {})
    fingerprint = event.get("fingerprint") or ""
    with transaction() as con:
        con.execute(
            "INSERT INTO tracking_events(task_id,type,severity,source,detail,data,fingerprint) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(task_id,fingerprint) DO UPDATE SET "
            "count=count+1,last_seen=datetime('now','localtime'),detail=excluded.detail,data=excluded.data",
            (int(task_id), event.get("type", "event"), event.get("severity", "info"),
             event.get("source", "daemon"), str(event.get("detail", ""))[:2000],
             payload, fingerprint))
        return con.execute("SELECT changes()").fetchone()[0]


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


# ---------- runs ----------

def start_task_run(task_id):
    return _exec("INSERT INTO task_runs(task_id) SELECT id FROM tracking_tasks WHERE id=?",
                 (int(task_id),))


def finish_task_run(run_id, outcome, event_count=0, error=""):
    _exec("UPDATE task_runs SET finished_at=datetime('now','localtime'),outcome=?,"
          "event_count=?,error=? WHERE id=?",
          (outcome, int(event_count), str(error)[:2000], int(run_id)))


def task_runs(task_id, limit=100):
    return _fetch("SELECT * FROM task_runs WHERE task_id=? ORDER BY id DESC LIMIT ?",
                  (int(task_id), max(1, min(int(limit), 500))))


# ---------- 批量提交事务协议 ----------

def commit_tracking_batch(task_id, run_id, events, checkpoint, interval_sec,
                          retention=5000, lease_owner=""):
    """Atomically commit a collection batch if the task is still runnable.

    Re-checking enabled/status under BEGIN IMMEDIATE closes the pause/delete race:
    a worker that finished after a user pause cannot publish stale state or advance
    the event checkpoint.
    """
    task_id, run_id = int(task_id), int(run_id)
    retention = max(100, min(int(retention), 100000))
    with transaction() as con:
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
        return True


def fail_tracking_batch(task_id, run_id, error, retry_at, lease_owner=""):
    """Record a failed run without reviving a task paused during collection."""
    with transaction() as con:
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


# ---------- daemon 租约 ----------

def acquire_daemon_lease(name, owner, ttl=15):
    now = time.time()
    with transaction() as con:
        row = con.execute("SELECT owner,heartbeat FROM daemon_leases WHERE name=?",
                          (name,)).fetchone()
        if row and row["owner"] != owner and now - float(row["heartbeat"]) < ttl:
            con.rollback()  # transaction 上下文退出时会再 commit 空事务，无害
            return False
        con.execute("INSERT OR REPLACE INTO daemon_leases(name,owner,heartbeat) VALUES(?,?,?)",
                    (name, owner, now))
        return True


def refresh_daemon_lease(name, owner):
    # _delete 返回 rowcount>0，恰好匹配“租约仍归属本 owner 才算刷新成功”
    return _delete("UPDATE daemon_leases SET heartbeat=? WHERE name=? AND owner=?",
                   (time.time(), name, owner))


def release_daemon_lease(name, owner):
    _exec("DELETE FROM daemon_leases WHERE name=? AND owner=?", (name, owner))


def daemon_lease(name):
    rows = _fetch("SELECT * FROM daemon_leases WHERE name=?", (name,))
    return rows[0] if rows else None
