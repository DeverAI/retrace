"""全局配置与模块开关管理。"""
import copy
import json
import os
import threading
import time

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
    检修（2026-08-27）：tmp 名加入 PID——旧的固定 CONFIG_PATH+".tmp" 在
    双实例并存时会被两进程交叉截断/replace，把混合半截 JSON 提升为正式
    配置；进程唯一名从根上消除该交错（本项目本就单实例纪律：
    web 端口用 SO_EXCLUSIVEADDRUSE）。os.replace 在目标正被其他进程
    读取时会抛共享冲突，加小步重试避免整次保存静默丢失。
    """
    if _cfg is None:
        return
    tmp = "%s.%d.tmp" % (CONFIG_PATH, os.getpid())
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
            replaced = False
            for _ in range(3):  # 目标被别的进程短暂占住句柄时小步重试
                try:
                    os.replace(tmp, CONFIG_PATH)
                    replaced = True
                    break
                except OSError:
                    time.sleep(0.05)
            if not replaced:
                raise OSError("config.json 持续被占用，本次保存放弃")
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


# ---- 密钥安全助手（2026-08-27 加固：掩码回显 + 保存语义统一）----
SECRET_CLEAR_TOKENS = ("(clear)", "(清除)")


def mask_secret(value):
    """密钥掩码预览：只保留前 4 后 4，其余以 … 折叠；空串原样。

    用于 GUI/Web 展示层，任何明文回显接口都应改走本函数。
    """
    s = str(value or "").strip()
    if not s:
        return ""
    if len(s) <= 8:
        return "*" * len(s)
    return "%s…%s" % (s[:4], s[-4:])


def resolve_secret_update(new_value, current_value):
    """统一的密钥保存语义（GUI/Web 共用）：

    - 提交为空   -> 保留旧值（防手滑清空已保存的 key）
    - 输入清除哨兵 -> 返回 ""（显式清除）
    - 其他非空   -> 原样采用（覆盖或首次写入）
    - 无旧值且提交为空 -> None 表示无需写盘
    """
    nv = str(new_value if new_value is not None else "").strip()
    cur = str(current_value or "")
    if nv == "":
        return cur if cur else None
    if nv.lower() in SECRET_CLEAR_TOKENS:
        # 清除已空 -> 无需写盘(None)；清除非空 -> 显式置 ""
        return "" if cur else None
    return nv
