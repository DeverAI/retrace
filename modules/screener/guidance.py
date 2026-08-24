"""筛查工作台——AI 辅助分析与指纹修改指导（带三层安全防线，只读不执行）。

安全防线：确定性前置检查 → 关键词拦截（绕过付费墙）→ LLM 强制【已检查】自检。
"""
import json
import os
import subprocess

from core import db, logger
from modules.screener.common import _is_protected_fs_path, json_d
from modules.screener.fmt_reverse import (
    analyze_fingerprint_format, generate_trusted_fingerprint)

_FP_GUIDANCE_DENY_HINTS = ("付费", "vip", "license", "许可证", "授权", "注册码",
                            "破解", "激活", "激活码", "序列号", "绕过付费", "绕过授权",
                            "bypass payment", "crack", "keygen", "serial key")


def _fp_guidance_pre_check(path):
    """LLM 调用前的确定性前置检查。返回 (blocked, reason)。"""
    if not path:
        return False, ""
    p = os.path.abspath(os.path.expandvars(path))
    if _is_protected_fs_path(p):
        return True, "路径在系统/受保护目录（SystemRoot/ProgramFiles/项目根），拒绝指导"
    if not os.path.exists(p):
        return True, "文件不存在: %s" % p
    # 运行中的 exe 不允许指导修改（会被锁定，且改运行中进程文件极危险）
    if p.lower().endswith(".exe") and os.path.isfile(p):
        try:
            out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq %s" % os.path.basename(p),
                                  "/FO", "CSV", "/NH"], capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=10).stdout
            if os.path.basename(p).lower() in out.lower():
                return True, "该 exe 正在运行，修改运行中的可执行文件极危险且会被锁定"
        except Exception:
            pass
    return False, ""


def _build_fp_guidance_prompt(analysis, replacement, path):
    """构造带强制安全自检的指纹修改指导系统提示词。"""
    ctx_parts = []
    if path:
        ctx_parts.append("目标文件路径：%s" % path)
    if analysis and analysis.get("ok"):
        ctx_parts.append("格式逆向分析结果：\n%s" % json.dumps(analysis, ensure_ascii=False,
                                                              default=str)[:6000])
    if replacement and replacement.get("ok"):
        ctx_parts.append("合法替换值参考（已通过格式校验，可直接使用）：\n%s" % json.dumps(
            replacement, ensure_ascii=False, default=str)[:4000])
    context_block = "\n\n".join(ctx_parts) if ctx_parts else "（未提供文件分析上下文）"

    return (
        "你是 ReTrace 指纹修改指导助手。用户正在尝试修改一个软件指纹文件的值，"
        "使其仍被原软件信任（避免软件因格式不符而重新制造新指纹）。\n\n"
        "════════════════════════════════════\n"
        "⚠️ 强制安全自检（第一步，不可跳过）\n"
        "════════════════════════════════════\n"
        "在生成任何回答之前，你必须先评估：\n"
        "1. 用户的操作目的是否为【绕过付费墙/授权许可/许可证验证】"
        "（即'不劳而获'——不付费就使用付费功能）？\n"
        "2. 该操作是否会对【系统稳定性】造成损害？"
        "（如修改运行中进程锁定的文件、破坏系统文件、删除关键配置导致软件崩溃）\n\n"
        "判定规则：\n"
        "● 若(1)成立 → 拒绝给出任何操作指导，仅回复："
        "'该请求涉及绕过付费/授权许可，出于合规考虑不予指导。'\n"
        "   然后立即结束，不输出任何操作步骤。\n"
        "● 若(2)成立 → 在回答开头用 ⚠️ 标注具体风险，并给出缓解建议"
        "（如先关闭目标进程、备份原文件到 quarantine）。\n"
        "● 若(1)(2)均不成立 → 在回答开头输出：【已检查】\n"
        "  （对于支持 thinking/reasoning 的模型，在思考过程中输出；"
        "  对于普通模型，在可见回答的第一行输出）\n\n"
        "════════════════════════════════════\n"
        "硬行为边界\n"
        "════════════════════════════════════\n"
        "● 绝不自动执行任何命令、脚本、写盘操作。所有步骤均为人工审查后手动执行。\n"
        "● 绝不提供可用于绕过付费功能、授权验证、许可证检查的具体操作方法。\n"
        "● 仅提供：格式规则解释、合法替换值、受控的手动修改步骤、验证方法。\n"
        "● 涉及写盘步骤时，必须包含：①备份原文件 ②具体命令/操作 ③回滚方法。\n"
        "● 涉及注册表/系统文件时，必须提醒创建系统还原点。\n\n"
        "════════════════════════════════════\n"
        "上下文（由 ReTrace 指纹分析模块提供）\n"
        "════════════════════════════════════\n"
        "%s\n\n"
        "如果用户未给出具体问题，主动给出：\n"
        "1) 该指纹文件的作用与格式创建规则；\n"
        "2) 当前检测到的身份字段及其可改写性（可改写/需同步/不可伪造）；\n"
        "3) 安全修改步骤（备份→修改→验证→回滚）；\n"
        "4) 修改后仍被软件信任的关键注意事项。\n"
        "用中文回答，结构清晰，关键风险点用 ⚠️ 标注。"
    ) % context_block


def fingerprint_guidance(question, path=""):
    """带强制安全自检的指纹修改 AI 指导（只读，不自动执行）。

    流程：确定性前置检查 → 格式逆向分析 → 生成合法替换值 → 构造安全提示词
    → 调用 LLM → 验证【已检查】标记。
    """
    from modules import ai
    if not ai.configured():
        return {"ok": False, "error": "AI 未配置：请在设置页填写 base_url / api_key / model"}

    # 1) 确定性前置检查
    abs_path = os.path.abspath(os.path.expandvars(path)) if path else ""
    blocked, reason = _fp_guidance_pre_check(abs_path)
    if blocked:
        return {"ok": False, "error": "安全前置检查未通过: %s" % reason}

    # 2) 快速意图关键词拦截（绕过付费墙类）
    q = (question or "").lower()
    for hint in _FP_GUIDANCE_DENY_HINTS:
        if hint in q:
            return {"ok": False,
                    "error": "该请求涉及绕过付费/授权许可，出于合规考虑不予指导。",
                    "blocked_reason": "payment_bypass"}

    # 3) 收集上下文
    analysis, replacement = None, None
    if abs_path and os.path.isfile(abs_path):
        try:
            analysis = analyze_fingerprint_format(abs_path)
            replacement = generate_trusted_fingerprint(abs_path)
        except Exception as e:
            logger.record_err("screen.fp_guidance.analyze", e)

    # 4) 构造安全提示词 + 调用 LLM（prepend_safety=False，我们已自带安全边界）
    sys_prompt = _build_fp_guidance_prompt(analysis, replacement, abs_path)
    user_q = (question or "").strip()
    if not user_q:
        user_q = "请告诉我这个指纹文件的作用、格式规则，以及如何安全地修改它（保持软件信任）。"
    result = ai.chat(
        [{"role": "system", "content": sys_prompt},
         {"role": "user", "content": user_q}],
        temperature=0.2, max_tokens=2500, prepend_safety=False)

    # 5) 验证【已检查】标记（普通模型可见输出中；thinking 模型在 reasoning 中）
    if result.get("ok"):
        text = result.get("text", "")
        has_marker = "【已检查】" in text
        result["safety_check_passed"] = has_marker
        if not has_marker:
            result["text"] = (
                "⚠️ 安全自检标记缺失——以下回答未经过完整安全审查，请谨慎参考。"
                "建议重新提问或人工复核。\n\n") + text
        db.audit("screen.fp_guidance", "path=%s check=%s blocked=%s" % (
            abs_path, has_marker, False))
    return result


def analyze_with_ai(result, question="分析以下筛查结果，指出最可疑的几项并给出人工复核建议"):
    """AI 辅助分析筛查结果（只读，不执行任何操作）。人机协作：人类筛查 → AI 辅助理解。"""
    from modules import ai
    if not ai.configured():
        return {"ok": False, "error": "AI 未配置：请在设置页填写 base_url / api_key / model"}
    items = (result or {}).get("items", [])
    if not items:
        return {"ok": False, "error": "无筛查项可分析"}
    text = json_d(items[:30])
    prompt = ("你是安全筛查辅助分析助手。以下是筛查工作台的结果，请用中文输出：\n"
              "1) 总体风险概述（含高危/中危数量）；\n"
              "2) 按可疑度列出 Top 3 并说明理由；\n"
              "3) 对每一条给出人工复核与处置建议（不执行任何操作）。\n"
              "问题：%s\n数据：%s" % (question, text[:5000]))
    db.audit("screen.ai", "items=%d" % len(items))
    return ai.chat([{"role": "system",
                     "content": "你是只读的安全分析助手，输出简洁实用，不执行任何操作。"},
                    {"role": "user", "content": prompt}],
                   temperature=0.2, max_tokens=1200)
