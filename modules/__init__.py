"""能力模块包：按模块开关注册到事件总线。

每个模块文件提供：
  register(bus, cfg) — 订阅事件、启动后台线程
  shutdown()         — 优雅停止（可选）
模块开关关闭时，main.py 不 import 该模块，UI 亦不展示入口。
"""
import importlib
import os

from core import events, logger

MODULES = [
    ("tracking", "任务追踪", "持久任务与后台守护监控"),
    ("privacy_guard", "隐私保护", "敏感访问告警、Sandbox 隔离与系统变更门禁"),
    ("pcap", "网络抓包", "Wireshark/tshark 抓包解析"),
    ("regscan", "注册表搜索", "winreg 递归搜索与常驻点位检查"),
    ("embedding", "高效检索", "本地/API embedding 语义检索"),
    ("decompile", "多类别反编译", "Python/PE/Java 三类解析"),
    ("watcher", "APP 集中观察", "目标行为时间线"),
    ("browser", "浏览器控制", "Chrome/Edge 插件中枢"),
    ("ai", "大模型集成", "OpenAI 兼容 API 帮助"),
    ("evolve", "自我进化", "规则挖掘与权重调整"),
    ("hunt", "漏洞主流程", "观察-标记-沉淀闭环"),
    ("agent", "LLM Agent", "可选高级功能：任务式Agent(需AI配置)"),
    ("screener", "筛查工作台", "一键筛查可疑APP/残留/指纹/追踪"),
]

_registered = []
_running = []


def register_all(bus, cfg):
    _registered.clear()
    _running.clear()
    for name, label, desc in MODULES:
        if not cfg["switches"].get(name, True):
            continue
        # 模块可能是 .py 文件或包目录（如 agent）
        mod_path_py = os.path.join(os.path.dirname(__file__), name + ".py")
        mod_path_pkg = os.path.join(os.path.dirname(__file__), name, "__init__.py")
        try:
            mod = importlib.import_module("modules.%s" % name)
            if hasattr(mod, "register"):
                mod.register(bus, cfg)
                _registered.append(name)
                _running.append(mod)
        except ImportError as e:
            if os.path.exists(mod_path_py) or os.path.exists(mod_path_pkg):
                logger.record_err("modules.register.%s" % name, e)
            else:
                logger.warn("模块 %s 尚未提供（开关已开启，跳过）" % name)
        except Exception as e:
            logger.record_err("modules.register.%s" % name, e)
            logger.error("模块 %s 注册失败，已跳过" % name)


def active():
    return list(_registered)


def shutdown():
    for mod in _running:
        try:
            if hasattr(mod, "shutdown"):
                mod.shutdown()
        except Exception as e:
            logger.record_err("modules.shutdown", e)
    events.bus.clear()
    _running.clear()
    _registered.clear()
