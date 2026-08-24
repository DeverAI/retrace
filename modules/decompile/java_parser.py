"""Java .class 解析：常量池/字段/方法表 + 危险 API 字符串特征。"""
import struct

from core import logger
from modules.decompile.common import (
    CP_DEPTH, JAVA_DANGER, JAVA_TOKEN_RULES, MAX_STRINGS, dedupe_calls,
    mark_strings, read_file)


def _skip_attrs(data, pos, n_attrs):
    for _ in range(n_attrs):
        if pos + 6 > len(data):
            return pos
        ln = struct.unpack_from(">I", data, pos + 2)[0]
        pos += 6 + ln
    return pos


def analyze_java(path):
    result = {"kind": "java", "file": path, "info": {}, "calls": [],
              "strings": [], "suspicious": []}
    data, size, err = read_file(path)
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
    dedupe_calls(result)
    return result
