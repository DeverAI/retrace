"""筛查工作台——指纹编码格式逆向与可信替换值生成（只读，不写盘）。

背景：指纹文件若被"不合创建规则"地修改（类型/长度/编码/加密错误），软件会判定
不信任并重新生成新指纹，导致"去除/更新"失败。逆向解析常见编码格式，输出该文件的
创建规则与可信改写指导，并支持生成符合规则的替换值预览。
"""
import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import uuid

from core import db

_UUID_FULL_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX32_RE = re.compile(r"^[0-9a-f]{32}$", re.I)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.I)
_DPAPI_MAGIC = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf"
_ID_HINT_RE = re.compile(
    r"(id|uuid|guid|machine|device|install|serial|hwid|salt|token|fingerprint"
    r"|installation|registration)", re.I)
_TIMESTAMP_HINT_RE = re.compile(
    r"(date|time|last|first|timer|created|expires)", re.I)
_MAX_FORMAT_PARSE = 2 * 1024 * 1024


def _parse_leaf(value):
    """对 JSON 叶子值做指纹语义分类，返回 (kind, creation_rule, replacement)。"""
    if isinstance(value, bool) or isinstance(value, (int, float)):
        if isinstance(value, bool):
            return ("bool", "布尔值：true/false", None)
        s = str(int(value))
        if len(s) == 10 and 946684800 <= int(s) <= 4102444800:
            return ("unix_timestamp", "10 位 Unix 秒级时间戳", None)
        if len(s) == 13 and 946684800000 <= int(s) <= 4102444800000:
            return ("unix_timestamp_ms", "13 位 Unix 毫秒级时间戳", None)
        return ("number", "数值", None)
    if not isinstance(value, str):
        return ("container", "容器", None)
    v = value.strip()
    if not v:
        return ("string_empty", "空字符串", None)
    if _UUID_FULL_RE.match(v):
        return ("uuid", "36 字符 UUID（8-4-4-4-12，小写十六进制+连字符）",
                str(uuid.uuid4()))
    if _HEX32_RE.match(v):
        return ("hex32", "32 字符十六进制（16 字节）", uuid.uuid4().hex)
    if _HEX64_RE.match(v):
        return ("hex64", "64 字符十六进制（32 字节，常为哈希）",
                hashlib.sha256(uuid.uuid4().bytes).hexdigest())
    compact = v.replace("-", "")
    if len(compact) == 32 and all(c in "0123456789abcdefABCDEF" for c in compact):
        return ("hex_uuid", "32 字符十六进制 UUID（可带连字符）",
                uuid.uuid4().hex)
    try:
        raw = base64.b64decode(v, validate=False)
        # DPAPI blob 的 base64 形如 "DPAPI\x01\x00..."，magic 8 字节可能位于
        # 开头（纯 blob）或偏移 5（ASCII "DPAPI" 前缀 + \x01 后）。取前 40 字节内搜索。
        if len(raw) >= 13 and _DPAPI_MAGIC in raw[:40]:
            return ("dpapi_blob", "DPAPI 加密 blob（机器+用户绑定，无法直接伪造）", None)
    except Exception:
        pass
    if len(v) >= 24 and all(c in "0123456789abcdefABCDEF" for c in v):
        n = len(v)
        return ("hex", "任意十六进制串（长度 %d 字符）" % n,
                secrets.token_hex((n + 1) // 2)[:n])
    if len(v) >= 10 and v.isdigit():
        if len(v) == 10 and 946684800 <= int(v) <= 4102444800:
            return ("unix_timestamp", "10 位 Unix 秒级时间戳（字符串形式）", None)
        return ("numeric_string", "数字字符串（长度 %d）" % len(v), None)
    return ("string", "字符串", None)


def _walk_json(obj, out, path="$", depth=0):
    """递归遍历 JSON，分类叶子值，收集身份字段与格式规则。"""
    if depth > 8:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            child = "%s.%s" % (path, k)
            if isinstance(v, (dict, list)):
                _walk_json(v, out, child, depth + 1)
                continue
            kind, rule, repl = _parse_leaf(v)
            is_identity = bool(_ID_HINT_RE.search(str(k)))
            is_timestamp = bool(_TIMESTAMP_HINT_RE.search(str(k)))
            if kind in ("uuid", "hex32", "hex64", "hex_uuid", "dpapi_blob") \
                    or is_identity or is_timestamp:
                entry = {"field": child, "kind": kind, "rule": rule,
                         "identity_hint": is_identity,
                         "timestamp_hint": is_timestamp}
                if kind == "dpapi_blob":
                    entry["value_preview"] = "[DPAPI 加密，长度 %d 字符]" % len(str(v))
                elif kind in ("uuid", "hex32", "hex64", "hex_uuid"):
                    entry["value_preview"] = "%s...（%s）" % (str(v)[:12], kind)
                else:
                    entry["value_preview"] = str(v)[:40]
                if repl is not None:
                    entry["replacement"] = repl
                out.append(entry)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:20]):
            _walk_json(v, out, "%s[%d]" % (path, i), depth + 1)


def analyze_fingerprint_format(path):
    """逆向解析指纹文件的编码格式与创建规则（只读）。

    支持格式：SQLite 数据库 / JSON / DPAPI base64 / 纯文本 UUID / hex 编码 UUID /
    通用十六进制 / 未知二进制。输出该文件"创建规则"（软件信任判据）与"可信改写
    指导"——让用户知道怎么改才不会被判定损坏并重新生成指纹。
    """
    path = os.path.abspath(os.path.expandvars(str(path or "")))
    if not os.path.isfile(path):
        return {"ok": False, "error": "文件不存在: %s" % path}
    try:
        size = int(os.path.getsize(path))
    except OSError as e:
        return {"ok": False, "error": "无法读取文件大小: %s" % e}
    if size > _MAX_FORMAT_PARSE:
        return {"ok": False, "error": "文件过大（>2MB），不做格式解析"}
    try:
        with open(path, "rb") as f:
            head = f.read(65536)
    except OSError as e:
        return {"ok": False, "error": "读取失败: %s" % e}

    result = {"ok": True, "path": path, "size": size,
              "format": "unknown", "format_rules": [], "identity_fields": [],
              "rewrite_guidance": [], "risk": "未知"}

    # ---- 1) SQLite ----
    if head[:16] == b"SQLite format 3\x00":
        result["format"] = "sqlite"
        result["format_rules"] = [
            "SQLite 数据库文件（magic: SQLite format 3）",
            "必须保持有效 SQLite 页结构，直接字节改写会破坏库",
            "修改须经 SQL UPDATE/DELETE，或整体删除文件让软件重建",
        ]
        sidecars = [os.path.isfile(path + suf) for suf in ("-wal", "-shm")]
        if any(sidecars):
            result["format_rules"].append(
                "存在 -wal/-shm 侧车文件：修改前软件须已退出（WAL 未合并直接改主库会丢数据）")
        try:
            con = sqlite3.connect(
                "file:%s?mode=ro" % path.replace("\\", "/"), uri=True, timeout=3)
            cur = con.cursor()
            cur.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
            tables = cur.fetchall()
            for tname, tsql in tables:
                cur.execute("PRAGMA table_info(%s)" % tname)
                cols = [(r[1], str(r[2]).upper()) for r in cur.fetchall()]
                ident_cols = [c for c, t in cols
                              if _ID_HINT_RE.search(c) or "TIME" in c]
                try:
                    cur.execute("SELECT COUNT(*) FROM %s" % tname)
                    cnt = cur.fetchone()[0]
                except Exception:
                    cnt = -1
                result["identity_fields"].append({
                    "table": tname, "columns": cols, "identity_columns": ident_cols,
                    "row_count": cnt,
                    "note": "表含身份/时间列：%s（行级 UPDATE/DELETE 可改写）" %
                            ", ".join(ident_cols) if ident_cols else "无身份类列"})
            con.close()
        except Exception as e:
            result["identity_fields"].append({"sqlite_error": str(e)})
        result["rewrite_guidance"] = [
            "行级改写：sqlite3 打开后 UPDATE/DELETE 目标行（保持 schema 不变）",
            "整体重置：删除本文件 + 侧车文件，软件下次启动按自身规则重建（重建=新指纹，"
            "若目标就是'让软件失忆'则此路径最简单可靠）",
            "注意：直接文本编辑器修改会触发 SQLITE_CORRUPT，软件必重建",
        ]
        result["risk"] = "高（直接字节修改必致损坏→软件重建指纹）"
        db.audit("screen.format", "path=%s format=sqlite" % path)
        return result

    # ---- 2) 文本 / JSON / DPAPI / UUID / hex ----
    try:
        text = head.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text = None

    if text is not None:
        stripped = text.strip()
        # 2a) JSON
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                result["format"] = "json"
                result["format_rules"] = [
                    "JSON 对象（UTF-8）",
                    "必须保持合法 JSON 语法与现有键结构",
                    "改写字段值须保持原类型/长度/编码，否则软件可能整体重写文件",
                ]
                _walk_json(obj, result["identity_fields"])
                result["rewrite_guidance"] = [
                    "逐字段替换：对每个 identity_fields 按其 kind 的 rule 生成同格式新值",
                    "dpapi_blob 字段不可伪造（机器+用户绑定加密）；清除方式为删除该键，"
                    "软件会按自身逻辑重建或重登录",
                    "unix_timestamp 字段一般不影响身份信任，篡改会暴露异常",
                ]
                result["risk"] = "中（结构合法即可信；值须符合字段规则）"
                db.audit("screen.format", "path=%s format=json" % path)
                return result
        except (ValueError, TypeError):
            pass
        # 2b) DPAPI base64（magic 可能带 ASCII "DPAPI\x01" 前缀，取前 40 字节内搜索）
        try:
            raw = base64.b64decode(stripped, validate=False)
            if len(raw) >= 13 and _DPAPI_MAGIC in raw[:40]:
                result["format"] = "dpapi_blob"
                result["format_rules"] = [
                    "DPAPI 加密 blob（base64）",
                    "密文与当前 Windows 用户+机器绑定，无法凭空伪造有效密文",
                ]
                result["rewrite_guidance"] = [
                    "改写密文=必失败（解密不通过→软件判损坏并重建）",
                    "正确路径：①用 CryptProtectData 重新加密新值；②删除本文件让软件重建；"
                    "③若值在 JSON 键内（如 os_crypt.encrypted_key），删除该键",
                ]
                result["risk"] = "高（直接改写必致重建）"
                db.audit("screen.format", "path=%s format=dpapi" % path)
                return result
        except Exception:
            pass
        # 2c) 纯文本 UUID
        if _UUID_FULL_RE.match(stripped):
            result["format"] = "uuid_text"
            result["format_rules"] = [
                "36 字符 UUID 纯文本（8-4-4-4-12，小写十六进制）",
                "替换值必须同为 36 字符 UUID，且版本位（第 3 组首位）与变体位合法",
            ]
            result["identity_fields"] = [{
                "field": "$", "kind": "uuid", "rule": "UUID 纯文本",
                "value_preview": "%s..." % stripped[:12],
                "replacement": str(uuid.uuid4())}]
            result["rewrite_guidance"] = [
                "用生成的新 UUID 整体替换文件内容（保持小写、无换行差异）",
                "软件通常只校验格式+版本位，合法 UUID v4 即可被信任",
            ]
            result["risk"] = "低（格式正确即可信）"
            db.audit("screen.format", "path=%s format=uuid_text" % path)
            return result
        # 2d) hex 编码 UUID（如 Qoder cache/id：32 hex + 连字符）
        compact = stripped.replace("-", "")
        if len(compact) == 32 and all(c in "0123456789abcdefABCDEF"
                                      for c in compact):
            result["format"] = "hex_uuid"
            result["format_rules"] = [
                "32 字符十六进制标识（%d 字节），可能带连字符装饰" % 16,
                "替换值必须同为 32 字符十六进制；连字符位置若存在须保持一致",
            ]
            result["identity_fields"] = [{
                "field": "$", "kind": "hex_uuid", "rule": "hex 编码 UUID",
                "value_preview": "%s..." % stripped[:12],
                "replacement": uuid.uuid4().hex}]
            result["rewrite_guidance"] = [
                "用 32 字符 hex 替换内容（保持原连字符格式）",
                "若软件把该值 hex-decode 为 16 字节 UUID，新值版本位 4/变体位合法即可",
            ]
            result["risk"] = "低（格式正确即可信）"
            db.audit("screen.format", "path=%s format=hex_uuid" % path)
            return result
        # 2e) 其他文本
        result["format"] = "text"
        result["format_rules"] = ["UTF-8 文本（未识别为已知指纹格式）"]
        result["rewrite_guidance"] = ["无已知创建规则；修改前建议人工确认软件读取逻辑"]
        result["risk"] = "未知"
        db.audit("screen.format", "path=%s format=text" % path)
        return result

    # ---- 3) 二进制 ----
    result["format"] = "binary"
    result["format_rules"] = [
        "二进制内容（无法按文本解释）",
        "可能含结构头部/校验和/长度前缀，直接修改风险高",
    ]
    result["rewrite_guidance"] = [
        "不建议字节级改写；优先走'删除文件→软件重建'或软件内重置路径",
    ]
    result["risk"] = "高（未知二进制结构，改写大概率触发重建）"
    db.audit("screen.format", "path=%s format=binary" % path)
    return result


def generate_trusted_fingerprint(path):
    """生成符合创建规则的指纹替换预览（只读，不写盘）。

    对 UUID/hex-UUID 直接给出新值；对 JSON 逐字段给出同格式替换值并输出整份
    替换后 JSON 预览；对 SQLite/DPAPI/二进制不生成内容，给出操作路径指导。
    """
    analysis = analyze_fingerprint_format(path)
    if not analysis.get("ok"):
        return analysis
    fmt = analysis.get("format")
    if fmt in ("uuid_text", "hex_uuid"):
        newval = analysis["identity_fields"][0]["replacement"]
        return {"ok": True, "path": path, "format": fmt,
                "replacement_value": newval,
                "apply_hint": "用该值整体替换文件内容（保持原编码/连字符格式）",
                "note": "预览未写盘；写盘请使用受控工具或人工操作"}
    if fmt == "json":
        fields = analysis.get("identity_fields") or []
        repls = [{"field": f["field"], "kind": f["kind"],
                  "replacement": f.get("replacement")}
                 for f in fields if f.get("replacement")]
        note = []
        for f in fields:
            if f.get("kind") == "dpapi_blob":
                note.append("%s 为 DPAPI 加密，不可伪造；清除=删除该键" % f["field"])
        return {"ok": True, "path": path, "format": "json",
                "field_replacements": repls,
                "special_cases": note or None,
                "apply_hint": "按 field 路径替换各值（类型/长度保持不变）；"
                              "整体重写文件须保持 JSON 结构",
                "note": "预览未写盘；写盘请使用受控工具或人工操作"}
    return {"ok": True, "path": path, "format": fmt,
            "replacement_value": None,
            "apply_hint": "; ".join(analysis.get("rewrite_guidance") or []),
            "note": "该格式不生成内容预览，请按改写指导操作"}
