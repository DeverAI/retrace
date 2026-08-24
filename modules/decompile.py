"""M6 decompile — 多类别反编译与静态预筛。

三类解析器（纯标准库）：
  Python: ast 危险调用扫描 + dis 字节码/常量提取 + 源码字符串提取
  PE:     自实现 PE32/PE32+ 头/节表/导入导出表/字符串/熵/混淆标记
  Java:   .class 常量池/字段/方法 + 危险 API 特征

统一入口 analyze(path) 自动探测类型。
事件：decompile.done {kind, file, info, calls, strings, suspicious}
"""
import ast
import json
import math
import os
import re
import struct
import subprocess
import sys

from core import events, logger

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


def _pyc_interpreter():
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


def _is_printable(b):
    return b in TEXT_CHARS


def _read_file(path):
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


def _printable_strings(data, min_len=4, max_count=MAX_STRINGS):
    out = []
    cur = []
    for ch in data:
        if _is_printable(ch):
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


def _entropy(data):
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


def _susp_extra(s):
    for rx in SUS_STR_REGEX:
        if rx.search(s):
            return True
    return False


def analyze_python(path):
    result = {"kind": "python", "file": path, "info": {}, "calls": [],
              "strings": [], "suspicious": []}
    data, size, err = _read_file(path)
    if err:
        result["info"]["error"] = err
        return result
    result["info"]["size"] = size
    low = path.lower()
    if low.endswith(".pyc"):
        interp = _pyc_interpreter()
        if not interp:
            result["info"]["parse_error"] = "打包环境无 Python 解释器，跳过 .pyc 反编译"
            result["suspicious"] = mark_strings(result["strings"])
            _dedupe_calls(result)
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
        _dedupe_calls(result)
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
            if s not in seen_str and not _is_printable(s.encode("utf-8", "replace")[0]):
                s = repr(s)
            if s not in seen_str:
                seen_str.add(s)
                if len(result["strings"]) < MAX_STRINGS:
                    result["strings"].append(s)
                    if _susp_extra(s):
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
    _dedupe_calls(result)
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


def _dedupe_calls(result):
    seen = set()
    kept = []
    for c in result["calls"]:
        key = (c["name"], c.get("line", 0))
        if key not in seen:
            seen.add(key)
            kept.append(c)
    result["calls"] = kept


def rva_to_offset(sections, rva):
    for name, vsize, vaddr, rawsize, rawptr in sections:
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawptr + (rva - vaddr)
    return None


def _cstr(data, off, limit):
    if off is None or off >= limit:
        return None
    end = data.find(b"\x00", off, limit)
    if end < 0:
        return None
    if end - off > 512:
        end = off + 512
    return data[off:end].decode("ascii", errors="replace")


def _parse_thunk_array(sections, data, thunk_rva, is64):
    """解析 IMAGE_THUNK_DATA 数组，返回函数名列表；按序号导入记为 '#ordinal'。"""
    thunk_off = rva_to_offset(sections, thunk_rva)
    funcs = []
    thunk_limit = 8192
    ordinal_flag = 1 << 63 if is64 else 1 << 31
    step = 8 if is64 else 4
    while thunk_off is not None \
            and thunk_off + step <= len(data) \
            and thunk_limit > 0:
        thunk_limit -= 1
        val = struct.unpack_from("<Q" if is64 else "<I", data, thunk_off)[0]
        if val == 0:
            break
        if not (val & ordinal_flag):
            # IMAGE_IMPORT_BY_NAME: WORD Hint + NUL 结尾 Name
            name_off = rva_to_offset(sections, val)
            name = _cstr(data, (name_off + 2) if name_off is not None else None,
                         len(data))
            if name is None:
                thunk_off += step
                continue
            funcs.append(name)
        else:
            funcs.append("#%d" % (val & 0xFFFF))
        thunk_off += step
    return funcs


def analyze_pe(path):
    result = {"kind": "pe", "file": path, "info": {}, "calls": [],
              "strings": [], "suspicious": []}
    data, size, err = _read_file(path)
    if err:
        result["info"]["error"] = err
        return result
    result["info"]["size"] = size
    result["info"]["entropy"] = _entropy(data)
    if len(data) < 2 or data[:2] != b"MZ":
        result["info"]["error"] = "不是 PE 文件 (无 MZ 头)"
        return result
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew < 0x40 or e_lfanew + 24 > len(data) \
                or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            result["info"]["error"] = "PE 签名缺失"
            return result
        machine, num_sections, ts, ptr_sym, num_sym, opt_size, characteristics = \
            struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
        opt_off = e_lfanew + 24
        magic = struct.unpack_from("<H", data, opt_off)[0]
        is64 = magic == 0x20B
        result["info"]["machine"] = "x64" if machine == 0x8664 else \
            ("x86" if machine == 0x14C else "0x%04X" % machine)
        result["info"]["bits"] = 64 if is64 else 32
        addr_off = opt_off + (24 if is64 else 28)
        image_base = struct.unpack_from("<Q" if is64 else "<I", data, addr_off)[0]
        dd_off = opt_off + (112 if is64 else 96)
        exp_rva, exp_size = struct.unpack_from("<II", data, dd_off)
        imp_rva, imp_size = struct.unpack_from("<II", data, dd_off + 8)
        result["info"]["image_base"] = hex(image_base)
        if opt_off + 16 + 4 <= len(data):
            result["info"]["entry"] = hex(struct.unpack_from(
                "<I", data, opt_off + 16)[0])
        sec_off = opt_off + opt_size
        sections = []
        for i in range(num_sections):
            off = sec_off + i * 40
            if off + 40 > len(data):
                result["info"]["truncated_sections"] = True
                break
            name = data[off:off + 8].rstrip(b"\x00").decode("ascii",
                                                            errors="replace")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from(
                "<IIII", data, off + 8)
            sections.append([name, vsize, vaddr, rawsize, rawptr])
        result["info"]["sections"] = [
            {"name": s[0], "va": hex(s[2]), "vsize": s[1], "rawsize": s[3]}
            for s in sections]
        imports = {}
        obfuscated = False
        if imp_rva:
            imp_off = rva_to_offset(sections, imp_rva)
            desc_limit = 4096
            while imp_off is not None and imp_off + 20 <= len(data) \
                    and desc_limit > 0:
                desc_limit -= 1
                oft, ts2, fwd_chain, name_rva, first_thunk = struct.unpack_from(
                    "<IIIII", data, imp_off)
                if not (name_rva or oft or first_thunk):
                    break
                if name_rva == 0:
                    obfuscated = True
                name_off = rva_to_offset(sections, name_rva) if name_rva else None
                dll_name = _cstr(data, name_off, len(data)) or ""
                if not dll_name:
                    base = "(hidden)"
                    dll_name = base
                    n = 2
                    while dll_name in imports:
                        dll_name = "%s_%d" % (base, n)
                        n += 1
                imports[dll_name] = _parse_thunk_array(
                    sections, data, oft or first_thunk, is64)
                imp_off += 20
        # 延迟导入表（DataDirectory 第 13 项，恶意样本常用以规避静态分析）
        if dd_off + 108 <= len(data):
            delay_rva = struct.unpack_from("<I", data, dd_off + 104)[0]
            if delay_rva:
                delay_off = rva_to_offset(sections, delay_rva)
                delay_limit = 512
                while delay_off is not None and delay_off + 32 <= len(data) \
                        and delay_limit > 0:
                    delay_limit -= 1
                    grattrs, rva_dllname, rva_hmod, rva_iat, rva_int, \
                        rva_bound, rva_unload, ts_delay = struct.unpack_from(
                            "<IIIIIIII", data, delay_off)
                    if not (rva_dllname or rva_int or rva_iat):
                        break
                    if not (grattrs & 1):
                        # VA 模式：减 image_base 转 RVA
                        rva_dllname = rva_dllname - image_base \
                            if rva_dllname >= image_base else rva_dllname
                        rva_int = rva_int - image_base \
                            if rva_int >= image_base else rva_int
                        rva_iat = rva_iat - image_base \
                            if rva_iat >= image_base else rva_iat
                    dname_off = rva_to_offset(sections, rva_dllname) \
                        if rva_dllname else None
                    dll_name = _cstr(data, dname_off, len(data)) or ""
                    if dll_name:
                        int_rva = rva_int or rva_iat
                        if int_rva:
                            funcs = _parse_thunk_array(sections, data, int_rva, is64)
                            if dll_name in imports:
                                imports[dll_name].extend(funcs)
                            else:
                                imports[dll_name] = funcs
                    delay_off += 32
        exports = []
        if exp_rva:
            exp_off = rva_to_offset(sections, exp_rva)
            if exp_off is not None and exp_off + 40 <= len(data):
                n_names = min(struct.unpack_from("<I", data, exp_off + 24)[0],
                              5000)
                names_rva = struct.unpack_from("<I", data, exp_off + 32)[0]
                names_off = rva_to_offset(sections, names_rva)
                if names_off is not None:
                    for i in range(n_names):
                        off = names_off + i * 4
                        if off + 4 > len(data):
                            break
                        n_rva = struct.unpack_from("<I", data, off)[0]
                        en = _cstr(data, rva_to_offset(sections, n_rva), len(data))
                        if en:
                            exports.append(en)
        odd_sections = [s[0] for s in sections
                        if len(s[0]) > 0 and not s[0].startswith(".")]
        if odd_sections:
            obfuscated = True
            result["info"]["odd_sections"] = odd_sections[:10]
        if obfuscated:
            result["info"]["obfuscated"] = True
        result["info"]["imports"] = imports
        result["info"]["exports"] = exports[:200]
        for dll in sorted(imports):
            for fn in imports[dll]:
                w = PE_DANGER.get(fn)
                if w is not None:
                    result["calls"].append({
                        "name": "%s!%s" % (dll, fn), "line": 0,
                        "danger": w, "reason": "导入高危 API", "kind": "import"})
        flat_str = _printable_strings(data)
        result["strings"] = flat_str
        result["suspicious"] = mark_strings(flat_str)
    except (struct.error, IndexError, ValueError) as e:
        logger.record_err("decompile.pe", e)
        result.setdefault("info", {})["error"] = "解析异常: %s" % e
    _dedupe_calls(result)
    return result


def analyze_java(path):
    result = {"kind": "java", "file": path, "info": {}, "calls": [],
              "strings": [], "suspicious": []}
    data, size, err = _read_file(path)
    if err:
        result["info"]["error"] = err
        return result
    result["info"]["size"] = size
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        result["info"]["error"] = "不是 .class 文件 (缺 CAFEBABE)"
        return result
    try:
        minor, major = struct.unpack_from(">HH", data, 4)
        result["info"]["major"] = major
        result["info"]["java_version"] = max(0, major - 44)
        cp_count = struct.unpack_from(">H", data, 8)[0]
        cp = {}
        pos = 10
        warn = None
        for idx in range(1, cp_count):
            if pos >= len(data):
                warn = "常量池截断 at %d" % pos
                break
            tag = data[pos]
            pos += 1
            if tag == 1:
                if pos + 2 > len(data):
                    warn = "Utf8 头越界"; break
                ln = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                if pos + ln > len(data):
                    warn = "Utf8 数据越界"; break
                cp[idx] = data[pos:pos + ln].decode("utf-8", errors="replace")
                pos += ln
            elif tag in (7, 8, 16, 19, 20):
                if pos + 2 > len(data):
                    warn = "ref 越界"; break
                cp[idx] = (tag, struct.unpack_from(">H", data, pos)[0])
                pos += 2
            elif tag in (9, 10, 11, 12, 17, 18):
                if pos + 4 > len(data):
                    warn = "member ref 越界"; break
                cp[idx] = (tag, struct.unpack_from(">HH", data, pos))
                pos += 4
            elif tag in (3, 4):
                if pos + 4 > len(data):
                    warn = "int/float 越界"; break
                pos += 4
            elif tag in (5, 6):
                if pos + 8 > len(data):
                    warn = "long/double 越界"; break
                pos += 8
                if idx + 1 < cp_count:
                    cp[idx + 1] = ("wide",)
                    idx += 1
            elif tag == 15:
                if pos + 3 > len(data):
                    warn = "mh 越界"; break
                pos += 3
            else:
                warn = "未知常量池 tag=%d at %d" % (tag, pos - 1)
                break
        if warn:
            result["info"]["parse_warn"] = warn
        access_flags = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        this_class = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        super_class = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        result["info"]["access"] = hex(access_flags)
        n_ifaces = struct.unpack_from(">H", data, pos)[0]
        pos += 2 + n_ifaces * 2

        def utf(entry):
            steps = 0
            seen = set()
            while isinstance(entry, tuple) and entry and entry[0] in (7, 8, 9, 10, 11, 12, 16, 17, 18, 19, 20):
                if entry[0] in (9, 10, 11, 12, 17, 18):
                    ref1, ref2 = entry[1]
                    entry = cp.get(ref2)
                else:
                    entry = cp.get(entry[1])
                if entry is None or entry in seen or steps > CP_DEPTH:
                    return ""
                seen.add(entry if not isinstance(entry, tuple) else entry[:1] + (id(entry),))
                steps += 1
            return entry if isinstance(entry, str) else ""

        result["info"]["class"] = utf(cp.get(this_class, "")).replace("/", ".")
        result["info"]["super"] = utf(cp.get(super_class, "")).replace("/", ".")
        if pos + 2 > len(data):
            result["info"]["error"] = "字段表越界"
            return result
        n_fields = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        fields = []
        for _ in range(min(n_fields, 5000)):
            if pos + 6 > len(data):
                result["info"]["parse_warn"] = (result["info"].get("parse_warn", "")
                                                + " 字段表截断")
                break
            pos += 2
            name_idx = struct.unpack_from(">H", data, pos)[0]
            pos += 4
            fname = utf(cp.get(name_idx, ""))
            if fname:
                fields.append(fname)
            if pos + 2 > len(data):
                break
            n_attrs = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            pos = _skip_attrs(data, pos, n_attrs)
        if pos + 2 > len(data):
            result["info"]["error"] = "方法表越界"
            return result
        n_methods = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        methods = []
        for _ in range(min(n_methods, 5000)):
            if pos + 2 > len(data):
                break
            pos += 2
            if pos + 4 > len(data):
                result["info"]["parse_warn"] = (result["info"].get("parse_warn", "")
                                                + " 方法表截断")
                break
            name_idx = struct.unpack_from(">H", data, pos)[0]
            pos += 4
            mname = utf(cp.get(name_idx, ""))
            if mname:
                methods.append(mname)
            if pos + 2 > len(data):
                break
            n_attrs = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            pos = _skip_attrs(data, pos, n_attrs)
        result["info"]["fields"] = fields[:200]
        result["info"]["methods"] = methods[:300]
        strings = [v for v in cp.values() if isinstance(v, str)
                   and len(v) >= 3]
        result["strings"] = strings[:MAX_STRINGS]
        full = [v for v in cp.values() if isinstance(v, str)]
        dots = [s.replace("/", ".") for s in full]
        joined = "\n" + "\n".join(dots) + "\n"
        seen_calls = set()
        for key, (weight, reason) in JAVA_DANGER.items():
            if key in joined:
                if key not in seen_calls:
                    seen_calls.add(key)
                    result["calls"].append({
                        "name": key, "line": 0, "danger": weight,
                        "reason": reason, "kind": "string"})
        if "java.lang.Runtime" in joined and "exec" in dots:
            item = ("Runtime.exec", 0.9, "Runtime 与 exec 并存")
            if item[0] not in seen_calls:
                seen_calls.add(item[0])
                result["calls"].append({
                    "name": item[0], "line": 0, "danger": item[1],
                    "reason": item[2], "kind": "string"})
        for rule, weight, reason in JAVA_TOKEN_RULES:
            if any(t == rule for t in dots):
                if rule not in seen_calls:
                    seen_calls.add(rule)
                    result["calls"].append({
                        "name": rule, "line": 0, "danger": weight,
                        "reason": reason, "kind": "string"})
        result["suspicious"] = mark_strings(full)
        result["info"]["cp_size"] = cp_count
    except (struct.error, IndexError) as e:
        logger.record_err("decompile.java", e)
        result.setdefault("info", {})["error"] = "解析异常: %s" % e
    _dedupe_calls(result)
    return result


def _skip_attrs(data, pos, n_attrs):
    for _ in range(n_attrs):
        if pos + 6 > len(data):
            return pos
        ln = struct.unpack_from(">I", data, pos + 2)[0]
        pos += 6 + ln
    return pos


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


_DECOMPILE_AUDIT_PROMPT = (
    "你是静态反编译结果的安全审核员。下面给出反编译扫描出的高危 API 调用清单（JSON 数组）。"
    "每个调用含 api（调用名）、danger（0~1 静态风险权重）、reason（静态规则给出的理由）、"
    "kind（call/import/string）、line（源码行号，PE/Java 为 0）。\n"
    "请逐条判断该调用在本文件上下文中是否构成真实风险，输出严格 JSON 数组（禁止其他任何文字），"
    "每项形如：\n"
    '{"api":"...","verdict":"真危险|疑似误报|常规使用","reason":"一句话理由","verify":"建议的验证步骤"}。\n'
    "判定准则：只读/信息收集/编码类调用多为误报或常规使用；写注册表、命令/进程执行、代码注入、"
    "远程加载、反序列化且参数来源不可控为真危险；仅凭静态清单无法确定参数来源时标疑似误报并给出验证点。"
)


_INJECTION_MARKERS = ("ignore previous", "ignore above", "忽略上述", "忽略以上",
                      "跳过审核", "直接执行", "disable security", "bypass")


def _contains_injection(text):
    t = (text or "").lower()
    return any(m in t for m in _INJECTION_MARKERS)


def ai_audit(path):
    """对反编译静态扫描得到的高危调用做一次只读 LLM 语义审计（增强信号，不替代静态规则）。

    注意：审计会把调用名/静态理由发送给外部 LLM API（不含源码常量/字符串正文）。
    """
    import json as _json
    from core import config as _config
    from modules import ai as _ai

    if not os.path.isfile(path):
        return {"ok": False, "error": "文件不存在: %s" % path, "file": path}
    if not _config.enabled("ai"):
        return {"ok": False, "error": "AI 模块已关闭，请先在设置中启用", "file": path}
    result = analyze(path, publish=False)
    if "error" in result:
        return {"ok": False, "error": result["error"], "file": path}
    info = result.get("info", {}) or {}
    if info.get("error"):
        return {"ok": False, "error": info["error"], "file": path}
    if info.get("parse_error"):
        return {"ok": False, "error": "解析失败: %s" % info["parse_error"], "file": path}
    incomplete = info.get("truncated_sections") or info.get("parse_warn")
    score = result.get("score", {})
    calls = [c for c in result.get("calls", []) if c.get("danger", 0) >= 0.5]
    if not calls:
        if incomplete:
            return {"ok": False,
                    "error": "文件解析不完整（截断/警告），无法判定是否存在高危调用",
                    "file": path, "static_score": score, "review": []}
        return {"ok": True, "file": path, "static_score": score, "review": [],
                "note": "无高危调用，无需 LLM 审计"}
    if not _ai.configured():
        return {"ok": False, "error": "AI 未配置：请设置 ai.base_url / ai.api_key",
                "file": path, "static_score": score, "review": []}
    call_list = []
    for c in calls[:30]:
        api = str(c.get("name", ""))[:200]
        reason = str(c.get("reason", ""))[:200]
        item = {"api": api, "danger": c.get("danger"), "reason": reason,
                "kind": c.get("kind"), "line": c.get("line", 0)}
        if _contains_injection(api) or _contains_injection(reason):
            item["flagged"] = "疑似注入，已按不可信数据处理"
        call_list.append(item)
    sec = _config.section("agent", {}) or {}
    model = (sec.get("reviewer_model") or "").strip() or None
    msgs = [
        {"role": "system", "content": _DECOMPILE_AUDIT_PROMPT},
        {"role": "user", "content": _json.dumps(call_list, ensure_ascii=False)},
    ]
    try:
        res = _ai.chat(msgs, temperature=0.1, max_tokens=1500, model=model)
    except Exception as e:
        logger.record_err("decompile.ai_audit", e)
        return {"ok": False, "error": "AI 审计调用失败: %s" % e, "file": path,
                "static_score": score, "review": []}
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error"), "file": path,
                "static_score": score, "review": []}
    review = _parse_audit_json(res.get("text", ""))
    return {"ok": True, "file": path, "static_score": score,
            "review": review, "ai_text": res.get("text", "")}


def _parse_audit_json(text):
    """从 LLM 输出提取 JSON 数组；仅保留 dict 元素，失败降级为原始文本单项。"""
    import json as _json

    def _norm(v):
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
        if isinstance(v, dict):
            return [v]
        return []

    if not text:
        return []
    try:
        return _norm(_json.loads(text.strip()))
    except Exception:
        pass
    try:
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end > start:
            return _norm(_json.loads(text[start:end + 1]))
    except Exception:
        pass
    return [{"api": "", "verdict": "未知", "reason": "", "verify": text[:1000]}]


def register(bus, cfg):
    pass


def shutdown():
    pass