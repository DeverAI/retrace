"""筛查工作台——AI 编码工具痕迹深扫。

与 machine_fp（通用设备指纹）互补：本模块针对 AI CLI/IDE 在用户主目录留下的
配置/身份/遥测产物，提取已知身份字段的"格式化哈希预览"用于比对与漂移监测，
绝不回显明文令牌。模式库保守：只收录公开文档可验证的路径。
"""
import hashlib
import json
import os
import time

from core import db
from modules.screener.common import _finish

# 每条目：
#   path   相对主目录的路径（文件或目录；存在即命中）
#   kind   file | dir
#   vendor/product/desc/risk 同机器指纹模式库
#   keys   JSON 内已知身份字段路径（点号分层）；命中则给出哈希预览而非明文
AI_TOOL_PATTERNS = [
    {"vendor": "Anthropic", "product": "Claude Code",
     "path": ".claude.json", "kind": "file",
     "desc": "Claude Code 全局配置（含 userID 稳定标识）",
     "risk": "高", "keys": ["userID"]},
    {"vendor": "Anthropic", "product": "Claude Code",
     "path": ".claude", "kind": "dir",
     "desc": "Claude Code 数据目录（会话/统计缓存等）",
     "risk": "中", "keys": []},
    {"vendor": "OpenAI", "product": "Codex CLI",
     "path": ".codex/auth.json", "kind": "file",
     "desc": "Codex CLI 认证凭证（含账号标识）",
     "risk": "高", "keys": ["account_id", "tokens.account_id"]},
    {"vendor": "OpenAI", "product": "Codex CLI",
     "path": ".codex", "kind": "dir",
     "desc": "Codex CLI 数据目录（会话历史等）",
     "risk": "中", "keys": []},
    {"vendor": "Google", "product": "Gemini CLI",
     "path": ".gemini", "kind": "dir",
     "desc": "Gemini CLI 数据目录（设置/临时状态）",
     "risk": "中", "keys": []},
    {"vendor": "Aider-AI", "product": "Aider",
     "path": ".aider.conf.yml", "kind": "file",
     "desc": "Aider 配置文件",
     "risk": "低", "keys": []},
    {"vendor": "Aider-AI", "product": "Aider",
     "path": ".aider.chat.history.md", "kind": "file",
     "desc": "Aider 对话历史（含代码上下文）",
     "risk": "中", "keys": []},
    {"vendor": "Continue.dev", "product": "Continue",
     "path": ".continue", "kind": "dir",
     "desc": "Continue 插件数据目录（索引/会话）",
     "risk": "中", "keys": []},
]


def _home():
    return os.path.expanduser("~")


def _hash_preview(raw, length=12):
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:length]


def _extract_key_fields(abs_path, key_paths):
    """读取小 JSON 文件，按点号路径取身份字段，返回 [{field,kind,preview}]。

    只输出哈希预览 + 长度 + 形状判定，绝不输出明文。
    """
    out = []
    if not key_paths or not os.path.isfile(abs_path):
        return out
    try:
        if os.path.getsize(abs_path) > 1024 * 1024:
            return out  # 超大配置不解析，防拖慢
        with open(abs_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return out
    for kp in key_paths:
        node = data
        ok = True
        for part in kp.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                ok = False
                break
        if not ok:
            continue
        text = node if isinstance(node, str) else json.dumps(node, ensure_ascii=False)
        shape = ("uuid" if len(text) == 36 and text.count("-") == 4 else
                 "hex32" if len(text) == 32 and all(c in "0123456789abcdef" for c in text.lower())
                 else "string")
        out.append({"field": kp, "shape": shape,
                    "len": len(text), "sha256_12": _hash_preview(text)})
    return out


def scan_ai_tool_traces(keyword=""):
    """扫描主目录下 AI 编码工具的身份/配置/遥测产物。

    keyword 非空时按厂商/产品/描述过滤。每项附 key_fields 哈希预览，
    可与 fingerprint_drift_report 联动监测"清理后是否再生"。
    """
    kw = (keyword or "").strip().lower()
    items, seen = [], set()
    home = _home()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    for pat in AI_TOOL_PATTERNS:
        hay = (pat["vendor"] + " " + pat["product"] + " " + pat["desc"]).lower()
        if kw and kw not in hay:
            continue
        abs_path = os.path.join(home, *pat["path"].split("/"))
        if not os.path.exists(abs_path):
            continue
        key = os.path.normcase(os.path.abspath(abs_path))
        if key in seen:
            continue
        seen.add(key)
        try:
            st = os.stat(abs_path)
            size = int(st.st_size)
            mtime = time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.localtime(int(st.st_mtime)))
        except OSError:
            size, mtime = 0, "未知"
        fields = (_extract_key_fields(abs_path, pat["keys"])
                  if pat["kind"] == "file" else [])
        preview = "; ".join(
            "%s=%s(len %d, sha:%s)" % (f["field"], f["shape"], f["len"],
                                       f["sha256_12"])
            for f in fields) if fields else ""
        items.append({
            "category": "AI 痕迹",
            "name": "%s %s" % (pat["product"], pat["path"]),
            "path": abs_path,
            "type": "ai_artifact",
            "target": abs_path,
            "artifact_kind": pat["kind"],
            "vendor": pat["vendor"],
            "product": pat["product"],
            "detail": "AI 工具产物: %s | 大小: %s 字节 | 修改: %s%s" % (
                pat["desc"], size,
                (mtime if isinstance(mtime, str) else str(mtime)),
                " | 身份字段: " + preview if preview else ""),
            "key_fields": fields,
            "risk": pat.get("risk", "中"),
            "reason": "AI 工具在本机留存的配置/身份产物",
            "size": size,
            "mtime": mtime if isinstance(mtime, str) else str(mtime),
            "state": "未处理",
        })
    db.audit("screen.ai_traces", "keyword=%s hits=%d" % (keyword or "(all)", len(items)))
    return _finish(items, "AI 痕迹")


if __name__ == "__main__":  # 自检
    import sys
    r = scan_ai_tool_traces(sys.argv[1] if len(sys.argv) > 1 else "")
    print(json.dumps(r["summary"], ensure_ascii=False))
