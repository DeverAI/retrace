"""全局配置与模块开关管理。"""
import copy
import json
import os
import threading

from core import logger

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
_lock = threading.Lock()
_save_lock = threading.Lock()


def _parse_bool(val):
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        v = val.strip().lower()
        if v in ("true", "1", "on", "yes"):
            return True
        if v in ("false", "0", "off", "no", ""):
            return False
    return None


def load():
    global _cfg
    _cfg = {"switches": {}, "sections": {}}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                _cfg = raw
        except Exception as e:
            logger.record_err("config.load", e)
    switches = _cfg.get("switches")
    if not isinstance(switches, dict):
        switches = {}
    merged = {}
    for key, default in DEFAULT_SWITCHES.items():
        if key in switches:
            val = _parse_bool(switches[key])
            merged[key] = default if val is None else val
        else:
            merged[key] = default
    _cfg["switches"] = merged
    return _cfg


def get():
    if _cfg is None:
        return load()
    return _cfg


def enabled(name):
    return bool(get()["switches"].get(name, False))


def save():
    if _cfg is None:
        return
    tmp = CONFIG_PATH + ".tmp"
    with _save_lock:
        try:
            # 序列化快照而非活字典，避免并发修改 _cfg 导致
            # "dictionary changed size during iteration"。
            snapshot = copy.deepcopy(_cfg)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, ensure_ascii=False, indent=2)
            os.replace(tmp, CONFIG_PATH)
        except OSError as e:
            logger.record_err("config.save", e)


def set_switches(**kwargs):
    with _lock:
        if _cfg is None:
            load()
        for k, v in kwargs.items():
            if k in DEFAULT_SWITCHES:
                val = _parse_bool(v)
                if val is not None:
                    _cfg["switches"][k] = val
        save()


def sections():
    return get()


def section(name, default=None):
    val = get().get(name)
    if isinstance(val, dict):
        return val
    return default if default is not None else {}
