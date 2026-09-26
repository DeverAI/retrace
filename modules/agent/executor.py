"""工具执行引擎：白名单校验、异常捕获、耗时统计、审计。"""
import time

from core import logger
from modules.agent import tools


def call(name, args, context=None):
    t = tools.TOOLS.get(name)
    if t is None:
        return {"ok": False, "error": "未知工具: %s" % name}
    # 工具组门禁（2026-08-27 检修）：未启用组的工具 fail-closed，
    # 与系统提示词的清单过滤共用同一 enabled_tool_groups 来源
    if not tools.tool_enabled(name):
        return {"ok": False, "error": "工具 %s 所在组未在 config.agent.tool_groups 启用" % name}
    if not isinstance(args, dict):
        return {"ok": False, "error": "参数必须为对象"}
    # 只透传声明过的参数，丢弃多余键（防注入额外参数）
    kwargs = {k: args[k] for k in args if k in t["params"]}
    if t["risk"] in (tools.RISK_CMD, tools.RISK_HIGH):
        reason = str(kwargs.get("reason") or "").strip()
        if len(reason) < 12:
            return {"ok": False, "tool": name,
                    "error": "系统/联网/删除操作必须附带至少 12 字的明确原因供用户审查"}
    try:
        t0 = time.time()
        data = t["run"](**kwargs)
        dur = round(time.time() - t0, 2)
    except Exception as e:
        logger.record_err("agent.tool.%s" % name, e)
        try:
            from core import audit
            from core.redact import redact_secrets
            audit.record("agent.tool", {"tool": name,
                                        "args": redact_secrets(kwargs),
                                        "context": context or {}, "error": redact_secrets(str(e))},
                         actor="agent",
                         resource="task:%s" % context["task_id"] if context and context.get("task_id") else "agent",
                         outcome="error", risk=t["risk"])
        except Exception:
            pass
        return {"ok": False, "tool": name, "error": str(e)}
    # 检修（2026-09-14）：审计段独立 try——审计若抛异常不得把"已实际执行"的
    # 工具误报为失败，否则模型会重试已生效的读写操作。
    outcome = "error" if isinstance(data, dict) and data.get("error") else "success"
    try:
        from core import audit
        from core.redact import redact_secrets
        # 审计载荷脱敏（2026-08-27）：参数中的密钥形状值只存哈希指纹占位
        audit.record("agent.tool", {"tool": name, "duration": dur,
                                    "args": redact_secrets(kwargs),
                                    "context": context or {},
                                    "result_type": type(data).__name__,
                                    "result_error": redact_secrets(
                                        str(data.get("error") or ""))[:200]
                                    if isinstance(data, dict) and outcome == "error" else ""},
                     actor="agent",
                     resource="task:%s" % context["task_id"] if context and context.get("task_id") else "agent",
                     outcome=outcome, risk=t["risk"])
    except Exception as audit_exc:
        logger.record_err("agent.tool.audit.%s" % name, audit_exc)
    return {"ok": outcome == "success", "tool": name, "data": data,
            "error": data.get("error") if outcome == "error" else None, "dur": dur}
