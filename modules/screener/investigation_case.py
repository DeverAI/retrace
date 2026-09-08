"""调查案例管理系统——记录排查进度、线索来源、处理效果。

本模块的目标：对每次软件指纹排查，建立完整的"案件档案"，包括：
  - 排查进度（哪些步骤已完成，哪些待处理）
  - 线索来源（怎么发现的：注册表扫描？文件内容？动态监控？）
  - 处理效果（删了/改了之后的结果：重建？不变？崩溃？）

类似于法医的"案件档案"——每个案件都有完整的证据链和处理记录。
"""
import json
import os
import time
from core import db


# ========== 案件管理 ==========

def create_case(software_name, description=""):
    """创建新的调查案件"""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db.transaction() as c:
        cur = c.execute("""INSERT INTO investigation_cases 
                     (software_name, description, status, created_at, updated_at)
                     VALUES (?, ?, 'active', ?, ?)""",
                  (software_name, description, now, now))
        case_id = cur.lastrowid
    db.audit("investigation.create", "case=%d software=%s" % (case_id, software_name))
    return {"ok": True, "case_id": case_id, "software_name": software_name}


def list_cases(status=None):
    """列出所有调查案件"""
    with db.transaction() as c:
        if status:
            rows = c.execute("""SELECT id, software_name, description, status, 
                                created_at, updated_at, evidence_count, action_count
                                FROM investigation_cases WHERE status = ?
                                ORDER BY updated_at DESC""", (status,)).fetchall()
        else:
            rows = c.execute("""SELECT id, software_name, description, status,
                                created_at, updated_at, evidence_count, action_count
                                FROM investigation_cases
                                ORDER BY updated_at DESC""").fetchall()
    return [{"id": r[0], "software_name": r[1], "description": r[2], "status": r[3],
             "created_at": r[4], "updated_at": r[5], "evidence_count": r[6], "action_count": r[7]}
            for r in rows]


def get_case(case_id):
    """获取案件详情"""
    with db.transaction() as c:
        row = c.execute("""SELECT id, software_name, description, status,
                           created_at, updated_at, evidence_count, action_count
                           FROM investigation_cases WHERE id = ?""", (case_id,)).fetchone()
    if not row:
        return None
    return {"id": row[0], "software_name": row[1], "description": row[2], "status": row[3],
            "created_at": row[4], "updated_at": row[5], "evidence_count": row[6], "action_count": row[7]}


def close_case(case_id, conclusion=""):
    """关闭案件"""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db.transaction() as c:
        c.execute("""UPDATE investigation_cases SET status='closed', conclusion=?, updated_at=?
                     WHERE id=?""", (conclusion, now, case_id))
    db.audit("investigation.close", "case=%d" % case_id)
    return {"ok": True, "case_id": case_id, "status": "closed"}


# ========== 证据/线索管理 ==========

def add_evidence(case_id, evidence_type, path, name, value_preview="",
                 source="", semantic_type="", impact_score=0.5, status="pending"):
    """添加线索/证据
    
    Args:
        case_id: 案件 ID
        evidence_type: 类型（file/registry/process/content）
        path: 文件路径或注册表路径
        name: 标识名称
        value_preview: 值预览（脱敏）
        source: 来源（怎么发现的）：deep_registry_scan/hunt_string/monitor/manual
        semantic_type: 语义类型（device_id/machine_id/login_state/telemetry...）
        impact_score: 影响力评分（0-1）
        status: 状态（pending/confirmed/false_positive/cleaned）
    """
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db.transaction() as c:
        cur = c.execute("""INSERT INTO investigation_evidence
                     (case_id, type, path, name, value_preview, source, semantic_type,
                      impact_score, status, discovered_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                  (case_id, evidence_type, path, name, value_preview, source,
                   semantic_type, impact_score, status, now))
        evidence_id = cur.lastrowid
        # 更新案件证据计数
        c.execute("UPDATE investigation_cases SET evidence_count = evidence_count + 1 WHERE id=?",
                  (case_id,))
    db.audit("investigation.add_evidence", "case=%d evidence=%d type=%s" % (case_id, evidence_id, evidence_type))
    return {"ok": True, "evidence_id": evidence_id}


def list_evidence(case_id, status=None):
    """列出案件的所有证据"""
    with db.transaction() as c:
        if status:
            rows = c.execute("""SELECT id, type, path, name, value_preview, source,
                                semantic_type, impact_score, status, discovered_at
                                FROM investigation_evidence WHERE case_id=? AND status=?
                                ORDER BY impact_score DESC""", (case_id, status)).fetchall()
        else:
            rows = c.execute("""SELECT id, type, path, name, value_preview, source,
                                semantic_type, impact_score, status, discovered_at
                                FROM investigation_evidence WHERE case_id=?
                                ORDER BY impact_score DESC""", (case_id,)).fetchall()
    return [{"id": r[0], "type": r[1], "path": r[2], "name": r[3], "value_preview": r[4],
             "source": r[5], "semantic_type": r[6], "impact_score": r[7], "status": r[8],
             "discovered_at": r[9]} for r in rows]


def update_evidence_status(case_id, evidence_id, status, notes=""):
    """更新证据状态"""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db.transaction() as c:
        c.execute("""UPDATE investigation_evidence SET status=?, notes=?, updated_at=?
                     WHERE id=? AND case_id=?""", (status, notes, now, evidence_id, case_id))
    db.audit("investigation.update_evidence", "case=%d evidence=%d status=%s" % (case_id, evidence_id, status))
    return {"ok": True}


# ========== 处理动作管理 ==========

def record_action(case_id, evidence_id, action_type, action_detail="",
                  result="", effect="", snapshot_path=""):
    """记录处理动作及其效果
    
    Args:
        case_id: 案件 ID
        evidence_id: 证据 ID
        action_type: 动作类型（delete/modify/monitor/backup/restore）
        action_detail: 动作详情（改了什么值？删了什么文件？）
        result: 执行结果（success/failure）
        effect: 效果（rebuilt/unchanged/crashed/regenerated）
        snapshot_path: 快照/备份路径
    """
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db.transaction() as c:
        cur = c.execute("""INSERT INTO investigation_actions
                     (case_id, evidence_id, action_type, action_detail, result, effect,
                      snapshot_path, executed_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                  (case_id, evidence_id, action_type, action_detail, result, effect,
                   snapshot_path, now))
        action_id = cur.lastrowid
        # 更新案件动作计数
        c.execute("UPDATE investigation_cases SET action_count = action_count + 1 WHERE id=?",
                  (case_id,))
    db.audit("investigation.record_action", "case=%d action=%d type=%s" % (case_id, action_id, action_type))
    return {"ok": True, "action_id": action_id}


def list_actions(case_id):
    """列出案件的所有处理动作"""
    with db.transaction() as c:
        rows = c.execute("""SELECT id, evidence_id, action_type, action_detail, result,
                            effect, snapshot_path, executed_at
                            FROM investigation_actions WHERE case_id=?
                            ORDER BY executed_at DESC""", (case_id,)).fetchall()
    return [{"id": r[0], "evidence_id": r[1], "action_type": r[2], "action_detail": r[3],
             "result": r[4], "effect": r[5], "snapshot_path": r[6], "executed_at": r[7]}
            for r in rows]


# ========== 进度管理 ==========

def update_progress(case_id, step_name, status, result_summary=""):
    """更新排查进度
    
    Args:
        case_id: 案件 ID
        step_name: 步骤名称（registry_scan/file_scan/monitor/cleanup）
        status: 状态（pending/running/done）
        result_summary: 结果摘要
    """
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db.transaction() as c:
        # 检查是否已有该步骤
        row = c.execute("""SELECT id FROM investigation_progress 
                          WHERE case_id=? AND step_name=?""", (case_id, step_name)).fetchone()
        if row:
            c.execute("""UPDATE investigation_progress SET status=?, result_summary=?,
                         updated_at=? WHERE id=?""",
                      (status, result_summary, now, row[0]))
        else:
            c.execute("""INSERT INTO investigation_progress
                         (case_id, step_name, status, result_summary, started_at, updated_at)
                         VALUES (?, ?, ?, ?, ?, ?)""",
                      (case_id, step_name, status, result_summary, now, now))
    db.audit("investigation.update_progress", "case=%d step=%s status=%s" % (case_id, step_name, status))
    return {"ok": True}


def get_progress(case_id):
    """获取案件排查进度"""
    with db.transaction() as c:
        rows = c.execute("""SELECT step_name, status, result_summary, started_at, updated_at
                            FROM investigation_progress WHERE case_id=?
                            ORDER BY updated_at""", (case_id,)).fetchall()
    return [{"step_name": r[0], "status": r[1], "result_summary": r[2],
             "started_at": r[3], "updated_at": r[4]} for r in rows]


# ========== 报告生成 ==========

def generate_report(case_id):
    """生成完整的排查报告（类似 Qoder目录说明.md）"""
    case = get_case(case_id)
    if not case:
        return {"error": "案件不存在"}
    
    evidence = list_evidence(case_id)
    actions = list_actions(case_id)
    progress = get_progress(case_id)
    
    # 按类型分组
    by_type = {}
    for e in evidence:
        by_type.setdefault(e["type"], []).append(e)
    
    # 按来源分组
    by_source = {}
    for e in evidence:
        by_source.setdefault(e["source"], []).append(e)
    
    # 按效果分组
    by_effect = {}
    for a in actions:
        by_effect.setdefault(a["effect"], []).append(a)
    
    report = {
        "case": case,
        "summary": {
            "total_evidence": len(evidence),
            "total_actions": len(actions),
            "high_impact": len([e for e in evidence if e["impact_score"] >= 0.9]),
            "confirmed": len([e for e in evidence if e["status"] == "confirmed"]),
            "cleaned": len([e for e in evidence if e["status"] == "cleaned"]),
            "false_positive": len([e for e in evidence if e["status"] == "false_positive"]),
        },
        "progress": progress,
        "evidence_by_type": by_type,
        "evidence_by_source": by_source,
        "actions_by_effect": by_effect,
        "evidence": evidence,
        "actions": actions,
    }
    return report


# ========== 数据库表初始化 ==========

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigation_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    software_name TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    conclusion TEXT DEFAULT '',
    evidence_count INTEGER DEFAULT 0,
    action_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS investigation_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    type TEXT DEFAULT 'file',
    path TEXT DEFAULT '',
    name TEXT DEFAULT '',
    value_preview TEXT DEFAULT '',
    source TEXT DEFAULT '',
    semantic_type TEXT DEFAULT '',
    impact_score REAL DEFAULT 0.5,
    status TEXT DEFAULT 'pending',
    notes TEXT DEFAULT '',
    discovered_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS investigation_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    evidence_id INTEGER,
    action_type TEXT DEFAULT '',
    action_detail TEXT DEFAULT '',
    result TEXT DEFAULT '',
    effect TEXT DEFAULT '',
    snapshot_path TEXT DEFAULT '',
    executed_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS investigation_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    step_name TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    result_summary TEXT DEFAULT '',
    started_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE INDEX IF NOT EXISTS idx_evidence_case ON investigation_evidence(case_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_actions_case ON investigation_actions(case_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_progress_case ON investigation_progress(case_id);
"""


def init_db():
    """初始化调查案例数据库表"""
    with db.transaction() as c:
        for stmt in SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                c.execute(stmt)
    return {"ok": True}
