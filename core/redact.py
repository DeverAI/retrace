"""审计字段脱敏：落审计库前抹掉疑似密钥/长令牌的明文。

原则：不阻止任何工具真正拿到原始参数；只在进入持久化审计记录前，
把「形状像秘密」的值替换为 前缀+长度+哈希指纹 的占位符，
保证事后仍可核对一致性（同一密钥得同一占位符），但无法还原原文。
"""
import hashlib
import re

# 键名命中即整值脱敏（值非平凡长度时）
_SECRET_KEY_HINTS = ("token", "secret", "api_key", "authorization",
                     "credential", "passwd", "password")

# 值形态：常见供应商标记开头的长令牌（sk-/tp-/ghp_/xoxb- 等）
_BRANDED_RE = re.compile(
    r"\b(?:sk|tp|rk|bp|ghp|gho|xoxb|xoxp|AKIA)[-_][A-Za-z0-9_\-]{16,}\b")
# 泛化超长高熵串（≥40 连续 base64/hex 形态字符），兜住自定义网关 token
_LONG_RUN_RE = re.compile(r"\b[A-Za-z0-9+/=_\-]{40,}\b")
# UUID/GUID 形态（含花括号包裹）：MachineGuid/deviceid/SQM MachineId 等身份锚点
# 只有 36 字符，≥40 兜底拦不住——上一轮 redact 修复对 GUID 实际无效（FreqErr §31）。
_UUID_SHAPE_RE = re.compile(
    r"\{?[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\}?", re.I)
# 32 位无横杠 hex（md5 形态）：machineid/HwProfile 派生值等身份锚点常量大写
# 存法各异（大小写不敏感），同 UUID 同理 <40 兜底拦不住（检修 2026-09-19）；
# 与 identity_hunt.HEX32_RE 的锚点认定对齐。
_HEX32_SHAPE_RE = re.compile(r"\b[0-9a-f]{32}\b", re.I)


def key_is_secret(key) -> bool:
    """键名是否命中敏感提示（与 redact_secrets 的 dict 键判定同源）。"""
    kl = str(key).lower()
    return any(h in kl.replace("-", "_") for h in _SECRET_KEY_HINTS)


def _fingerprint(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:10]


def _redact_string(s):
    out = _BRANDED_RE.sub(
        lambda m: "<secret:%d:%s>" % (len(m.group(0)), _fingerprint(m.group(0))),
        s)
    out = _LONG_RUN_RE.sub(
        lambda m: "<token:%d:%s>" % (len(m.group(0)), _fingerprint(m.group(0))),
        out)
    out = _HEX32_SHAPE_RE.sub(
        lambda m: "<id32:%s>" % _fingerprint(m.group(0).lower()),
        out)
    return _UUID_SHAPE_RE.sub(
        # UUID 大小写不敏感：注册表存大写、文件存小写须得同一占位符，
        # 否则跨来源"同值同占位符"关联断裂（检修 2026-09-19）。
        lambda m: "<uuid:%d:%s>" % (
            len(m.group(0)),
            _fingerprint(m.group(0).lower().strip("{}"))),
        out)


def redact_secrets(obj):
    """递归处理 dict/list/tuple/str，返回脱敏后的新结构（不修改入参）。"""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if key_is_secret(k) and isinstance(v, str) and len(v) >= 8:
                out[k] = "<secret:%d:%s>" % (len(v), _fingerprint(v))
            else:
                out[k] = redact_secrets(v)
        return out
    if isinstance(obj, (list, tuple)):
        seq = [redact_secrets(x) for x in obj]
        return type(obj)(seq) if isinstance(obj, tuple) else seq
    if isinstance(obj, str):
        return _redact_string(obj)
    return obj
