"""Structured, redacted and hash-chained security audit records."""
import hashlib
import json
import re
import threading
import uuid

from core import db, logger

_lock = threading.Lock()
_SECRET = re.compile(r"(api[_-]?key|authorization|token|cookie|secret|password)", re.I)


def _redact(value, key=""):
    if _SECRET.search(str(key)):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value[:200]]
    text = str(value)
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)((?:api[_-]?key|token|password|secret)\s*[=:]\s*)[^\s,;]+",
                  r"\1[REDACTED]", text)
    return text[:4000]


def redact(value):
    """Public deep-redaction helper for AI-bound or externally rendered context."""
    return _redact(value)


def record(action, detail=None, actor="system", resource="", outcome="success",
           risk="info", request_id=""):
    request_id = request_id or uuid.uuid4().hex
    try:
        safe = _redact(detail or {})
        body = json.dumps(safe, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))[:12000]
    except Exception as e:
        # 脱敏/序列化失败（循环引用、超深嵌套等）不得打断业务主流程
        body = json.dumps({"_redact_error": str(e)[:200]}, ensure_ascii=False)
    last_error = None
    for attempt in range(2):
        try:
            with _lock:
                con = db.conn()
                try:
                    con.execute("BEGIN IMMEDIATE")
                    row = con.execute("SELECT entry_hash FROM audit_log WHERE entry_hash<>'' ORDER BY id DESC LIMIT 1").fetchone()
                    prev = row["entry_hash"] if row else ""
                    material = "|".join((prev, str(action), str(actor), str(resource),
                                         str(outcome), str(risk), request_id, body))
                    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
                    con.execute(
                        "INSERT INTO audit_log(op,detail,actor,resource,outcome,risk,request_id,prev_hash,entry_hash) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        (action, body, actor, resource, outcome, risk,
                         request_id, prev, digest))
                    con.commit()
                finally:
                    con.close()
            return request_id
        except Exception as exc:
            # 数据库锁竞争（BEGIN IMMEDIATE 拿不到写锁）等瞬时失败重试一次；
            # 仍失败则写 Err.log（可检测），但不得打断业务主流程。
            last_error = exc
            continue
    logger.record_err("audit.record", last_error)
    return request_id


def list_entries(limit=200):
    return db.audit_rows(limit)


def verify(limit=None):
    """Verify the complete chained portion and report unchained legacy records."""
    rows = db._fetch("SELECT * FROM audit_log WHERE entry_hash<>'' ORDER BY id ASC")
    legacy = db._fetch("SELECT COUNT(*) AS n FROM audit_log WHERE entry_hash='' OR entry_hash IS NULL")
    prev = ""
    for index, row in enumerate(rows):
        material = "|".join((prev, row.get("op") or "", row.get("actor") or "",
                             row.get("resource") or "", row.get("outcome") or "",
                             row.get("risk") or "", row.get("request_id") or "",
                             row.get("detail") or ""))
        expected = hashlib.sha256(material.encode("utf-8")).hexdigest()
        if row.get("prev_hash") != prev or row.get("entry_hash") != expected:
            # 用 enumerate 定位断裂点，避免 rows.index(row) 的 dict 相等性 O(n²)
            return {"ok": False, "complete": False, "checked": index,
                    "broken_id": row["id"], "legacy_unchained": legacy[0]["n"]}
        prev = row["entry_hash"]
    return {"ok": True, "complete": legacy[0]["n"] == 0, "checked": len(rows),
            "head": prev, "legacy_unchained": legacy[0]["n"]}
