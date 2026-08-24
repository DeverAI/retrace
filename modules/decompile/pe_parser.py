"""PE32/PE32+ 解析：自实现头/节表/导入导出表/延迟导入表/字符串/熵/混淆标记。"""
import struct

from core import logger
from modules.decompile.common import (
    PE_DANGER, dedupe_calls, entropy, mark_strings, printable_strings,
    read_file)


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
    data, size, err = read_file(path)
    if err:
        result["info"]["error"] = err
        return result
    result["info"]["size"] = size
    result["info"]["entropy"] = entropy(data)
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
        flat_str = printable_strings(data)
        result["strings"] = flat_str
        result["suspicious"] = mark_strings(flat_str)
    except (struct.error, IndexError, ValueError) as e:
        logger.record_err("decompile.pe", e)
        result.setdefault("info", {})["error"] = "解析异常: %s" % e
    dedupe_calls(result)
    return result
