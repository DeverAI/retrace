"""统一基础类型强转。

全库唯一的布尔解析实现（此前在 config / evolve / privacy_guard / tracking
四处置有四份近似拷贝，是历史上 string-"false" 蠕虫 bug 的温床）。
"""
_TRUTHY = ("true", "1", "on", "yes")
_FALSY = ("false", "0", "off", "no", "")


def parse_bool(val):
    """宽容解析布尔：非法输入返回 None（由调用方决定默认值）。"""
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        v = val.strip().lower()
        if v in _TRUTHY:
            return True
        if v in _FALSY:
            return False
    return None


def as_bool(val, default=False):
    """永不返回 None 的布尔解析：非法输入取 default。"""
    result = parse_bool(val)
    return default if result is None else result


def strict_bool(val):
    """HTTP 边界专用：非法布尔输入直接抛 ValueError（拒收而非猜默认）。"""
    result = parse_bool(val)
    if result is None:
        raise ValueError("布尔值格式无效: %r" % (val,))
    return result
