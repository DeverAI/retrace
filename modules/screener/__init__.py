"""M11 筛查工作台 — 预设筛查流程，结果可筛选、可标记、可追踪。

与 M10 Agent 不同：这里是"即点即用"的确定性筛查工具，不依赖自由任务规划。
筛查项统一模型：
  {"id","category","name","path","detail","risk","reason","state"}
    category: 可疑APP | 残留 | 指纹 | 追踪
    risk:     高 | 中 | 低 | 无
    state:    未处理 | 已标记 | 忽略

按职责拆分为子模块；本入口平面再导出全部公共 API，
调用方（GUI 动态 getattr / Web 字符串路由 / Agent 工具）无需感知包结构。
"""
from modules.screener.ai_tools import (
    AI_TOOL_PATTERNS,  # noqa: F401 (对外兼容)
    scan_ai_tool_traces)
from modules.screener.apps import (
    check_file, scan_fingerprints, scan_leftover, scan_suspicious_apps,
    track_app)
from modules.screener.cleanup import (
    cleanup_traces, preview_cleanup, restore_traces)
from modules.screener.common import (  # noqa: F401 (_is_protected_fs_path/json_d 供外部兼容)
    SUSPICIOUS_NAMES, _is_protected_fs_path, json_d, mark_item)
from modules.screener.deep_scan import (
    scan_prefetch_traces, scan_usage_history, scan_wer_traces)
from modules.screener.drift import (
    classify_paths, fingerprint_drift_report)
from modules.screener.fmt_reverse import (
    analyze_fingerprint_format, generate_trusted_fingerprint)
from modules.screener.fsreg import (
    broad_scan, correlate_findings, deep_dir_scan)
from modules.screener.guidance import analyze_with_ai, fingerprint_guidance
from modules.screener.machine_fp import (
    FINGERPRINT_FILE_PATTERNS,  # noqa: F401 (对外兼容)
    scan_generic_fingerprints, scan_machine_fingerprints)
from modules.screener.traces import scan_software_traces


def register(bus, cfg):
    pass


def shutdown():
    pass
