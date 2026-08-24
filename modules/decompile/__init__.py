"""M6 decompile — 多类别反编译与静态预筛。

三类解析器（纯标准库）：
  Python: ast 危险调用扫描 + dis 字节码/常量提取 + 源码字符串提取
  PE:     自实现 PE32/PE32+ 头/节表/导入导出表/字符串/熵/混淆标记
  Java:   .class 常量池/字段/方法 + 危险 API 特征

统一入口 analyze(path) 自动探测类型。
事件：decompile.done {kind, file, info, calls, strings, suspicious}
"""
import os

from core import events
from modules.decompile.audit import ai_audit  # noqa: F401 (对外兼容)
from modules.decompile.common import (  # noqa: F401 (特征库供外部复用)
    JAVA_DANGER, MAX_CALLS, MAX_FILE_SIZE, MAX_STRINGS, PE_DANGER,
    PY_DANGER, SUS_STR_REGEX, dedupe_calls, entropy, mark_strings,
    printable_strings, read_file)
from modules.decompile.java_parser import analyze_java  # noqa: F401
from modules.decompile.pe_parser import analyze_pe  # noqa: F401
from modules.decompile.py_parser import analyze_python  # noqa: F401


def detect_kind(path):
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return None
    if head.startswith(b"\xca\xfe\xba\xbe"):
        return "java"
    if head.startswith(b"MZ"):
        return "pe"
    ext = os.path.splitext(path)[1].lower()
    if ext in (".py", ".pyc", ".pyw"):
        return "python"
    return None


def analyze(path, publish=True):
    kind = detect_kind(path)
    if kind is None:
        return {"error": "无法识别的文件类型", "file": path}
    if kind == "python":
        result = analyze_python(path)
    elif kind == "pe":
        result = analyze_pe(path)
    else:
        result = analyze_java(path)
    sus_total = len(result["suspicious"])
    high = sum(1 for c in result["calls"] if c["danger"] >= 0.8)
    med = sum(1 for c in result["calls"] if 0.5 <= c["danger"] < 0.8)
    result["score"] = {"high": high, "med": med, "suspicious": sus_total}
    if publish:
        events.bus.publish("decompile.done", {
            "kind": kind, "file": path, "score": result.get("score", {})})
    return result


def register(bus, cfg):
    pass


def shutdown():
    pass
