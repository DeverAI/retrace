"""全局配置与模块开关管理。"""
import copy
import json
import os
import threading

from core import logger
from core.coerce import parse_bool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT, "config.json")

DEFAULT_SWITCHES = {
    "pcap": True,
    "regscan": True,
    "embedding": True,
    "browser": True,
    "evolve": True,
    "decompile": True,
    "watcher": True,
    "ai": True,
    "hunt": True,
    "agent": True,
    "screener": True,
    "tracking": True,
    "privacy_guard": True,
    "ui": True,
}

DEFAULTS = {"switches": DEFAULT_SWITCHES}

_cfg = None
_lock = threading.RLock()
_save_sem = threading.Lock()

# 兼容别名：历史代码直接引用 config._parse_bool
_parse_bool = parse_bool


def load():
    global _cfg
    with _lock:
        loaded = {}
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                if isinstance(raw, dict):
                    loaded = raw
            except Exception as e:
                logger.record_err("config.load", e)
        switches = loaded.get("switches")
        if not isinstance(switches, dict):
            switches = {}
        merged = {}
        for key, default in DEFAULT_SWITCHES.items():
            if key in switches:
                val = parse_bool(switches[key])
                merged[key] = default if val is None else val
            else:
                merged[key] = default
        loaded["switches"] = merged
        _cfg = loaded
        return _cfg


def get():
    with _lock:
        if _cfg is None:
            return load()
        return _cfg


def enabled(name):
    return bool(get()["switches"].get(name, False))


def save():
    """原子落盘：锁内深拷贝快照，杜绝并发修改导致的序列化异常。

    写盘用独立信号量串行（避免长 IO 阻塞读路径）；_lock 为 RLock，
    允许 set_switches/update_section 持锁期间安全调用本函数。
    序列化失败（如调用方塞入不可 JSON 化对象）不得炸穿调用方，也不得残留 .tmp。
    """
    if _cfg is None:
        return
    tmp = CONFIG_PATH + ".tmp"
    with _lock:
        try:
            snapshot = copy.deepcopy(_cfg)
        except Exception as e:
            logger.record_err("config.snapshot", e)
            return
    with _save_sem:
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, ensure_ascii=False, indent=2)
            os.replace(tmp, CONFIG_PATH)
        except (OSError, TypeError, ValueError) as e:
            logger.record_err("config.save", e)
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass


def set_switches(**kwargs):
    with _lock:
        if _cfg is None:
            load()
        for k, v in kwargs.items():
            if k in DEFAULT_SWITCHES:
                val = parse_bool(v)
                if val is not None:
                    _cfg["switches"][k] = val
    save()


def update_section(name, values):
    """统一的安全段落更新入口：原地合并 dict 并立即落盘。

    取代各 UI 直接改 get()[name] 再 save() 的裸操作，
    消除 FreqErr §15 记录的并发写竞态；原地修改保持 _cfg
    对象身份稳定，外部持有的引用不会失效。
    """
    if not isinstance(values, dict):
        raise TypeError("update_section 需要 dict，得到 %r" % type(values))
    with _lock:
        cfg = get()
        target = cfg.get(name)
        if not isinstance(target, dict):
            target = {}
            cfg[name] = target
        for k, v in values.items():
            if name == "switches":
                # 开关段白名单 + 严格布尔解析
                val = parse_bool(v)
                if val is None or k not in DEFAULT_SWITCHES:
                    continue
                target[k] = val
            else:
                target[k] = v
    save()
    return cfg.get(name)


def sections():
    return get()


def section(name, default=None):
    val = get().get(name)
    if isinstance(val, dict):
        return val
    return default if default is not None else {}
