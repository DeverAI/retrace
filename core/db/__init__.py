"""SQLite 数据层：观察库、经验库、目标档案、审计日志。

按域拆分实现（connection / schema / hunt_store / tracking_store），
本包入口平面再导出全部公共 API，调用方继续 `from core import db` 即可。
"""
from core.db.connection import (DB_PATH, conn, init, transaction,
                                _delete, _exec, _fetch, _migrate)
from core.db.schema import SCHEMA
from core.db.hunt_store import (
    add_agent, add_knowledge, add_observation, audit_rows, delete_knowledge,
    delete_observation, evolve_get, evolve_set, get_agent, get_observation,
    get_observations, last_audit_hash, list_agents, list_knowledge,
    set_knowledge_enabled, set_knowledge_weight, update_observation)
from core.db.tracking_store import (
    acquire_daemon_lease, commit_tracking_batch, count_tracking_events,
    create_tracking_task, daemon_lease, delete_tracking_task,
    fail_tracking_batch, finish_task_run, get_tracking_task,
    list_tracking_tasks, refresh_daemon_lease, release_daemon_lease,
    start_task_run, task_runs, tracking_events, update_tracking_task,
    upsert_tracking_event)


def audit(op, detail=""):
    """兼容垫片：转发到 core.audit.record（延迟导入避免环）。"""
    try:
        from core import audit as security_audit
        security_audit.record(op, detail)
    except Exception as e:
        from core import logger
        logger.record_err("db.audit", e)
