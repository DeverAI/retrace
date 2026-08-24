"""开机自启管理：HKCU Run 注册表项。

用户 2026-08-12 确认允许；写入与关闭均记 audit_log 审计。
自启命令带 --minimized，启动后直接最小化到托盘。
"""
import os
import sys
import winreg

from core import db, logger

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "ReTrace"


def _command():
    """返回自启命令行。打包(frozen)时用 exe 路径，开发态用 pythonw + main.py。"""
    if getattr(sys, "frozen", False):
        return '"%s" --minimized' % sys.executable
    py = sys.executable.replace("python.exe", "pythonw.exe")
    if not os.path.exists(py):
        py = sys.executable
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main.py")
    return '"%s" "%s" --minimized' % (py, script)


def is_enabled():
    """当前是否已开启开机自启。"""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.QueryValueEx(k, VALUE_NAME)
            return True
    except OSError:
        return False


def get_command():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            val, _ = winreg.QueryValueEx(k, VALUE_NAME)
            return val
    except OSError:
        return ""


def set_enabled(enable):
    """开启/关闭开机自启。返回是否成功，敏感操作记审计。"""
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            if enable:
                winreg.SetValueEx(k, VALUE_NAME, 0, winreg.REG_SZ, _command())
            else:
                try:
                    winreg.DeleteValue(k, VALUE_NAME)
                except OSError:
                    pass
        db.audit("autostart", "set_enabled=%s cmd=%s" % (enable, get_command()))
        return True
    except OSError as e:
        logger.record_err("autostart.set_enabled", e)
        return False
