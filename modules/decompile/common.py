"""反编译共享基元：常量、危险 API 特征库、文件读取与字符串/熵提取。"""
import json
import math
import os
import re
import sys

from core import logger

MAX_STRINGS = 2000
MAX_CALLS = 500
MAX_FILE_SIZE = 256 * 1024 * 1024
CP_DEPTH = 32

# .pyc 反编译在受限子进程执行：marshal.loads 反序列化不可信字节码存在
# 解释器崩溃/恶意对象风险（官方明确警告不可用于不可信来源）。子进程隔离
# 崩溃，仅回传 LOAD_CONST 字符串列表，超时兜底，主进程不再持有 code 对象。
_PYC_EXTRACT = "\n".join([
    "import sys, marshal, dis, json",
    "p = sys.argv[1]",
    "data = open(p, 'rb').read()",
    "d = data",
    "if d[:4] == bytes(4) and len(d) >= 16:",
    "    d = d[16:]",
    "    if d[:4] != bytes([0xE3]):",
    "        off = d.find(bytes([0xE3, 0, 0, 0]))",
    "        if off > 0:",
    "            d = d[off:]",
    "try:",
    "    code = marshal.loads(d)",
    "except Exception:",
    "    code = marshal.loads(data[16:] if len(data) > 16 else data)",
    "out = []",
    "for insn in dis.get_instructions(code):",
    "    if insn.opname == 'LOAD_CONST':",
    "        v = insn.argval",
    "        if isinstance(v, str) and len(v) >= 4:",
    "            out.append(v)",
    "            if len(out) >= %d:" % MAX_STRINGS,
    "                break",
    "print(json.dumps(out, ensure_ascii=False))",
])


def pyc_interpreter():
    """返回可执行 -c 的 Python 解释器；frozen 时探测系统解释器，无则返回 None。"""
    if getattr(sys, "frozen", False):
        import shutil
        return shutil.which("python") or shutil.which("python3")
    return sys.executable


PY_DANGER = {
    "eval": (1.0, "动态求值，可被注入"),
    "exec": (1.0, "动态执行代码"),
    "compile": (0.7, "编译动态代码"),
    "__import__": (0.6, "动态导入"),
    "importlib.import_module": (0.6, "动态导入"),
    "os.system": (0.9, "系统命令执行"),
    "os.popen": (0.9, "命令管道执行"),
    "subprocess.Popen": (0.7, "子进程(需检查参数来源)"),
    "subprocess.run": (0.7, "子进程(需检查参数来源)"),
    "subprocess.call": (0.7, "子进程(需检查参数来源)"),
    "subprocess.check_output": (0.7, "子进程(需检查参数来源)"),
    "pickle.loads": (0.9, "反序列化任意代码"),
    "marshal.loads": (0.9, "反序列化任意代码"),
    "ctypes.CDLL": (0.8, "加载任意 DLL"),
    "ctypes.windll": (0.8, "加载任意 DLL"),
    "urllib.request.urlopen": (0.5, "外联请求"),
    "requests.get": (0.5, "外联请求"),
    "telnetlib.open": (0.7, "终端协议"),
    "ftplib.FTP": (0.4, "文件传输协议"),
    "smtplib.SMTP": (0.4, "邮件发送"),
    "winreg.SetValueEx": (0.8, "写注册表"),
    "socket.socket": (0.4, "原始套接字"),
}

PY_PREFIX = ("os.", "subprocess.", "socket.", "urllib.", "requests.",
             "importlib.", "ctypes.", "pickle.", "marshal.", "telnetlib.",
             "ftplib.", "smtplib.", "winreg.")

PE_DANGER = {
    "InternetOpenA": 0.6, "InternetOpenW": 0.6, "InternetOpenUrlA": 0.7,
    "HttpSendRequestA": 0.6, "URLDownloadToFileA": 0.9, "URLDownloadToFileW": 0.9,
    "WinExec": 0.8, "ShellExecuteA": 0.6, "ShellExecuteW": 0.6,
    "ShellExecuteExA": 0.7, "ShellExecuteExW": 0.7,
    "CreateProcessA": 0.6, "CreateProcessW": 0.6, "system": 0.8,
    "WSAStartup": 0.4, "socket": 0.4, "connect": 0.5, "send": 0.4, "recv": 0.4,
    "RegOpenKeyExA": 0.5, "RegOpenKeyExW": 0.5, "RegSetValueExA": 0.8,
    "RegCreateKeyExA": 0.7, "RegSetValueExW": 0.8,
    "OpenProcess": 0.7, "VirtualAllocEx": 0.9, "WriteProcessMemory": 0.9,
    "CreateRemoteThread": 0.95, "QueueUserAPC": 0.9,
    "SetWindowsHookExA": 0.9, "SetWindowsHookExW": 0.9,
    "SetWinEventHook": 0.8, "LoadLibraryA": 0.5, "LoadLibraryW": 0.5,
    "LoadLibraryExA": 0.5, "GetProcAddress": 0.5, "CryptEncrypt": 0.5,
    "CryptDecrypt": 0.5, "NtWriteVirtualMemory": 0.95,
}

JAVA_DANGER = {
    "java.lang.Runtime": (0.8, "Runtime 使用"),
    "org.apache.commons.lang3.SystemUtils": (0.3, "系统信息获取"),
    "java.lang.ProcessBuilder": (0.7, "进程构建(需检查参数)"),
    "javax.naming": (0.8, "JNDI 远程类加载"),
    "java.io.ObjectInputStream": (0.8, "反序列化流"),
    "java.lang.Class.forName": (0.6, "反射类加载"),
    "java.lang.reflect": (0.5, "反射包使用"),
    "java.lang.ClassLoader.defineClass": (0.9, "动态类定义"),
    "javax.script": (0.7, "脚本引擎"),
    "java.net.URLClassLoader": (0.8, "远程类加载"),
    "java.net.URL": (0.4, "URL 使用"),
    "java.util.Base64": (0.3, "编码使用"),
    "javax.crypto.Cipher": (0.4, "加密使用"),
}

JAVA_TOKEN_RULES = [
    ("readObject", 0.9, "Java 反序列化入口"),
    ("getMethod", 0.6, "反射方法调用"),
    ("invoke", 0.4, "反射调用"),
    ("cipher", 0.3, "加密使用"),
]

SUS_STR_REGEX = (
    re.compile(r"(?i)(api[-_]?key|password|secret|token|passwd|pwd)\W*[:,=]"),
    re.compile(r"(?i)https?://\S+"),
    re.compile(r"(?i)(cmd\.exe|powershell|regsvr32|rundll32|mshta)"),
)

TEXT_CHARS = set(range(0x20, 0x7F))


def is_printable(b):
    return b in TEXT_CHARS


def read_file(path):
    try:
        size = os.path.getsize(path)
    except OSError as e:
        logger.record_err("decompile.stat", e)
        return None, None, "文件不可访问: %s" % e
    if size > MAX_FILE_SIZE:
        return None, None, "文件过大(>256MB)，拒绝分析"
    try:
        with open(path, "rb") as f:
            return f.read(), size, None
    except OSError as e:
        logger.record_err("decompile.read", e)
        return None, None, "读取失败: %s" % e


def printable_strings(data, min_len=4, max_count=MAX_STRINGS):
    out = []
    cur = []
    for ch in data:
        if is_printable(ch):
            cur.append(chr(ch))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
                if len(out) >= max_count:
                    break
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)


def mark_strings(strings):
    marks = []
    for s in strings:
        for rx in SUS_STR_REGEX:
            if rx.search(s):
                marks.append(s[:300])
                break
    return marks


def susp_extra(s):
    for rx in SUS_STR_REGEX:
        if rx.search(s):
            return True
    return False


def dedupe_calls(result):
    seen = set()
    kept = []
    for c in result["calls"]:
        key = (c["name"], c.get("line", 0))
        if key not in seen:
            seen.add(key)
            kept.append(c)
    result["calls"] = kept
