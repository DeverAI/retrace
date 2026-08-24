"""反编译结果的 LLM 语义审计（增强信号，只读，不替代静态规则）。"""
import json
import os

from core import config, logger
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


def _parse_audit_json(text):
    """从 LLM 输出提取 JSON 数组；仅保留 dict 元素，失败降级为原始文本单项。"""

    def _norm(v):
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
        if isinstance(v, dict):
            return [v]
        return []

    if not text:
        return []
    try:
        return _norm(json.loads(text.strip()))
    except Exception:
        pass
    try:
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end > start:
            return _norm(json.loads(text[start:end + 1]))
    except Exception:
        pass
    return [{"api": "", "verdict": "未知", "reason": "", "verify": text[:1000]}]


def ai_audit(path):
    """对反编译静态扫描得到的高危调用做一次只读 LLM 语义审计（增强信号，不替代静态规则）。

    注意：审计会把调用名/静态理由发送给外部 LLM API（不含源码常量/字符串正文）。
    """
    from modules import ai
    # 运行时导入：包 __init__ 顶层加载本模块，此处延迟到调用期规避环
    from modules.decompile import analyze

    if not os.path.isfile(path):
        return {"ok": False, "error": "文件不存在: %s" % path, "file": path}
    if not config.enabled("ai"):
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
    if not ai.configured():
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
    sec = config.section("agent", {}) or {}
    model = (sec.get("reviewer_model") or "").strip() or None
    msgs = [
        {"role": "system", "content": _DECOMPILE_AUDIT_PROMPT},
        {"role": "user", "content": json.dumps(call_list, ensure_ascii=False)},
    ]
    try:
        res = ai.chat(msgs, temperature=0.1, max_tokens=1500, model=model)
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
