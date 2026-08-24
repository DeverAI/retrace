"""连接管理、初始化迁移与通用执行原语。"""
import contextlib
import os
import sqlite3
import threading

from core.db.schema import SCHEMA

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "retrace.db")

_lock = threading.Lock()


def conn():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=30000")
    return con


@contextlib.contextmanager
def transaction(immediate=True):
    """单连接事务上下文：BEGIN( IMMEDIATE ) → yield → commit / 异常 rollback。

    统一原先散落在 tracking_store / audit 里的
    BEGIN IMMEDIATE + commit + rollback 样板代码。
    """
    con = conn()
    try:
        con.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield con
        except Exception:
            con.rollback()
            raise
        con.commit()
    finally:
        con.close()


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
