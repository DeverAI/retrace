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


def _fingerprint(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:10]


def _redact_string(s):
    out = _BRANDED_RE.sub(
        lambda m: "<secret:%d:%s>" % (len(m.group(0)), _fingerprint(m.group(0))),
        s)
    out = _LONG_RUN_RE.sub(
        lambda m: "<token:%d:%s>" % (len(m.group(0)), _fingerprint(m.group(0))),
        out)
    return out


def redact_secrets(obj):
    """递归处理 dict/list/tuple/str，返回脱敏后的新结构（不修改入参）。"""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            hit_key = any(h in kl.replace("-", "_") for h in _SECRET_KEY_HINTS)
            if hit_key and isinstance(v, str) and len(v) >= 8:
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
