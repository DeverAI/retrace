"""Python 源码/.pyc 解析：ast 危险调用扫描 + 受限子进程字节码常量提取。"""
import ast
import json
import os
import subprocess

from core import logger
from modules.decompile.common import (
    MAX_CALLS, MAX_STRINGS, PY_DANGER, PY_PREFIX, _PYC_EXTRACT,
    dedupe_calls, is_printable, mark_strings, pyc_interpreter, read_file,
    susp_extra)


def analyze_python(path):
    result = {"kind": "python", "file": path, "info": {}, "calls": [],
              "strings": [], "suspicious": []}
    data, size, err = read_file(path)
    if err:
        result["info"]["error"] = err
        return result
    result["info"]["size"] = size
    low = path.lower()
    if low.endswith(".pyc"):
        interp = pyc_interpreter()
        if not interp:
            result["info"]["parse_error"] = "打包环境无 Python 解释器，跳过 .pyc 反编译"
            result["suspicious"] = mark_strings(result["strings"])
            dedupe_calls(result)
            return result
        try:
            p = subprocess.run([interp, "-c", _PYC_EXTRACT, path],
                               capture_output=True, timeout=15,
                               encoding="utf-8", errors="replace")
            if p.returncode == 0:
                try:
                    result["strings"] = json.loads(p.stdout.strip() or "[]")
                except ValueError:
                    result["strings"] = []
                result["info"]["bytecode"] = True
                result["info"]["constants"] = len(result["strings"])
            else:
                result["info"]["parse_error"] = (
                    "pyc 反编译失败(exit %d): %s"
                    % (p.returncode, (p.stderr or "").strip()[:200]))
        except subprocess.TimeoutExpired:
            result["info"]["parse_error"] = "pyc 反编译超时"
        except Exception as e:
            result["info"]["parse_error"] = str(e)
            logger.record_err("decompile.pyc", e)
        result["suspicious"] = mark_strings(result["strings"])
        dedupe_calls(result)
        return result
    try:
        src = data.decode("utf-8", errors="replace")
    except Exception:
        src = data.decode("latin-1", errors="replace")
    result["info"]["lines"] = src.count("\n") + 1
    try:
        tree = ast.parse(src)
    except Exception as e:
        result["info"]["parse_error"] = str(e)
        return result
    seen_str = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and len(node.value) >= 4:
            s = node.value
            if s not in seen_str and not is_printable(s.encode("utf-8", "replace")[0]):
                s = repr(s)
            if s not in seen_str:
                seen_str.add(s)
                if len(result["strings"]) < MAX_STRINGS:
                    result["strings"].append(s)
                    if susp_extra(s):
                        result["suspicious"].append(s[:300])
        if isinstance(node, ast.Call):
            func = ""
            if isinstance(node.func, ast.Name):
                func = node.func.id
            elif isinstance(node.func, ast.Attribute):
                parts = []
                cur = node.func
                while isinstance(cur, ast.Attribute):
                    parts.append(cur.attr)
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    parts.append(cur.id)
                func = ".".join(reversed(parts))
            if func:
                _match_py_call(result, func, getattr(node, "lineno", 0), "call")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                _match_py_call(result, alias.name, getattr(node, "lineno", 0), "import")
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                _match_py_call(result, (node.module or "") + "." + alias.name,
                               getattr(node, "lineno", 0), "import")
    result["calls"] = result["calls"][:MAX_CALLS]
    dedupe_calls(result)
    return result


def _match_py_call(result, func, line, kind):
    if not func:
        return
    for key, (weight, reason) in PY_DANGER.items():
        if key == func or (key in PY_PREFIX and func.startswith(key)):
            result["calls"].append({
                "name": func, "line": line, "danger": weight, "reason": reason,
                "kind": kind})
            return
