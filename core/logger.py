"""统一日志：控制台输出 + Err.log 自动存错机制。"""
import os
import sys
import threading
import time
import traceback

ERR_LOG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "Err.log")
ERR_MAX = 1024 * 1024
_lock = threading.Lock()


def _utf8_console():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


_utf8_console()


def _ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def info(msg):
    print("[INFO] %s %s" % (_ts(), msg))


def warn(msg):
    print("[WARN] %s %s" % (_ts(), msg))


def error(msg):
    print("[ERROR] %s %s" % (_ts(), msg))


def _write_err(text):
    with _lock:
        try:
            if os.path.exists(ERR_LOG) and os.path.getsize(ERR_LOG) > ERR_MAX:
                os.replace(ERR_LOG, ERR_LOG + ".old")
            with open(ERR_LOG, "a", encoding="utf-8") as f:
                f.write(text + "-" * 60 + "\n")
            return True
        except OSError:
            try:
                with open(ERR_LOG, "a", encoding="utf-8") as f:
                    f.write(text + "-" * 60 + "\n")
                return True
            except OSError:
                return False


_last_full_log = [0.0]


def record_err(context="", exc=None):
    text = _ts() + "\n"
    if context:
        text += "Context: %s\n" % context
    tb = getattr(exc, "__traceback__", None)
    if exc is not None:
        text += "Exception: %r\n" % (exc,)
    if tb is not None:
        text += "".join(traceback.format_exception(type(exc), exc, tb))
    else:
        text += "(no traceback)\n"
    now = time.time()
    if now - _last_full_log[0] < 2.0:
        if exc is not None:
            _write_err(text.splitlines()[0] + " (同 2s 内重复错误，详情已限频)")
        else:
            _write_err(text.splitlines()[0])
    else:
        _last_full_log[0] = now
        written = _write_err(text)
        if not written:
            error("Err.log 写入失败: %s" % (str(exc) if exc else context))
    error("recorded to Err.log :: " + (str(exc) if exc else context))
    return text


def read_err():
    try:
        with open(ERR_LOG, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def has_err():
    try:
        return os.path.getsize(ERR_LOG) > 0
    except OSError:
        return False


def clear_err():
    try:
        with open(ERR_LOG, "w", encoding="utf-8") as f:
            f.write("")
        return True
    except OSError:
        return False


def install_hook():
    def hook(etype, value, tb):
        text = _ts() + "\nException: %r\n" % (value,)
        text += "".join(traceback.format_exception(etype, value, tb)) + "\n"
        if not _write_err(text):
            pass
        sys.__excepthook__(etype, value, tb)

    def thread_hook(args):
        text = _ts() + "\nThread: %s\nException: %r\n" % (args.thread.name, args.exc_value)
        text += "".join(traceback.format_exception(args.exc_type, args.exc_value,
                                                   args.exc_traceback)) + "\n"
        _write_err(text)
        sys.__excepthook__(args.exc_type, args.exc_value, args.exc_traceback)

    sys.excepthook = hook
    threading.excepthook = thread_hook