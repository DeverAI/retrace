"""M10 LLM Agent 子系统。

- tools.py     工具白名单 + 风险分级（read/cmd/high）
- executor.py  执行引擎（白名单/参数校验/超时/审计）
- reviewer.py  空上下文独立审核模型（allow/deny，防会话污染）
- agent.py     主循环：规划 → 审核 → 执行/审批 → 回填
- cli.py       命令行入口（python -m modules.agent.cli 或 main.py --agent）
"""
from core import config, logger


def register(bus, cfg):
    """Agent 是命令入口而非常驻服务；注册无副作用，纳入模块清单以便开关管理。"""
    pass


def shutdown():
    pass
