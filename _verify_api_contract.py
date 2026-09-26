# -*- coding: utf-8 -*-
"""Web API 契约核对器（只读，零第三方依赖）。

对应 FreqErr §18「有口没码清零」：逐条核对 ui/web_main.ALLOWED 白名单里的
"module.func" 在目标模块上真实存在且可调用。注意两个特例：
  - agent 是包，run_task 位于 modules.agent.agent（web_main._call 有同名分支）；
  - config/db/autostart 走 _call 内置分支，不按 module.func 解析。
另扫描 ui/pages/*.py 的 _mod("module", "func") 调用点，核对 GUI 动态取函数
的 (module, func) 组合同样存在（FreqErr §17：白名单与页面按钮脱节教训）。

2026-09-19 加强项（FreqErr §31"同类出口必须全扫"的机械化）：
  A. 封套消费闭合——返回 {"error":...} 的函数，凡"调用+迭代同函数"必须带
     error 处理或 isinstance 过滤；
  B. 守卫覆盖表——脱敏/ReDoS/locale/幂等门/截断标记等锚点逐文件核对；
  C. 普查——tools.py 用户正则入口、bool 幂等门调用点、winreg 枚举甄别位，
     新增未守卫实例立即报红（豁免清单 = Future 已登记待修项）。

运行：python _verify_api_contract.py   （在项目根目录）
输出：逐项 OK / MISSING 列表；有缺失时退出码 1。
"""
import ast
import importlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 内置分支（_call 特判），不按 module.func 在模块上找属性
_BUILTIN_MODULES = ("config", "db", "autostart")
# agent 包特例：真正的可调用面在 modules.agent.agent
_PACKAGE_FUNC_HOSTS = {"agent": "modules.agent.agent"}


def _load_allowed():
    """从 ui/web_main.py 源码提取 ALLOWED 字面量，避免 import 拖起 http 服务依赖。"""
    src = open(os.path.join("ui", "web_main.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", None) == "ALLOWED" for t in node.targets):
            return {e.value for e in node.value.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    raise SystemExit("未在 ui/web_main.py 找到 ALLOWED 定义")


def resolve(module, func):
    """按 web_main._call 的解析规则取函数；返回 callable 或 None。"""
    host = _PACKAGE_FUNC_HOSTS.get(module, "modules." + module)
    try:
        mod = importlib.import_module(host)
    except ImportError:
        return None
    return getattr(mod, func, None)


# —————————————————————————————— A. 封套消费闭合 ——————————————————————————————
# 返回 {"error": ...} 形态封套的"生产者"（新增返回错误封套的函数必须登记）
ENVELOPE_PRODUCERS = ("deep_registry_scan", "hunt_software_fingerprint",
                      "run_full_investigation")


def _iter_py_files(dirs):
    for d in dirs:
        for dirpath, dirnames, files in os.walk(d):
            dirnames[:] = [x for x in dirnames
                           if x not in ("__pycache__", "backups")]
            for f in sorted(files):
                if f.endswith(".py"):
                    yield os.path.join(dirpath, f)


def _func_segments(src):
    """AST 取每个函数的源码段（含嵌套函数各算一份）。"""
    lines = src.splitlines()
    tree = ast.parse(src)
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = max(getattr(n, "end_lineno", n.lineno), n.lineno)
            yield n.name, "\n".join(lines[n.lineno - 1:end])


def check_envelope_consumers():
    """调用封套生产者且同函数内迭代其结果 → 必须有 error 处理/isinstance 过滤。"""
    problems = []
    sites = 0
    for path in _iter_py_files(("modules", "core")):
        try:
            src = open(path, encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        if not any(p in src for p in ENVELOPE_PRODUCERS):
            continue
        for name, seg in _func_segments(src):
            called = [p for p in ENVELOPE_PRODUCERS
                      if re.search(r"\b%s\s*\(" % re.escape(p), seg)]
            if not called:
                continue
            if not re.search(r"\.(items|values)\s*\(", seg):
                continue  # 不迭代结果（直接透传/仅计数）无形状风险
            sites += 1
            if ('"error"' not in seg and "isinstance" not in seg):
                problems.append("%s::%s 迭代 %s 结果但无 error/isinstance 闭合"
                                % (path, name, called))
    print("\n[A] 封套消费点 %d 处（生产者：%s）" % (sites, ", ".join(ENVELOPE_PRODUCERS)))
    for p in problems:
        print("  [ENV-GAP] %s" % p)
    return problems


# —————————————————————————————— B. 守卫覆盖锚点表 ——————————————————————————————
# (守卫名, 文件, [必须存在的锚点正则])——本轮修复定案的出口/守卫清单，
# 任何一处被回退/挪走即报红（FreqErr §31"修复声明≠修复生效"的机械兜底）。
GUARD_ANCHORS = [
    ("注册表/身份工具出口脱敏", os.path.join("modules", "agent", "tools.py"), [
        r"redact_secrets\(deep_registry_scan\(",
        r"redact_secrets\(scan_system_anchors\(\)\)",
        r"redact_secrets\(hunt_software_fingerprint\(",
        r"redact_secrets\(sanitize_findings\(extract_identity_semantics\(",
        r"redact_secrets\(monitor_identity_access\(",
        r"redact_secrets\(watcher\.timeline_entries",
        r"redact_secrets\(chunk\)",                      # read_file 分页出口
        r'out\["data"\] = redact_secrets',               # read_registry_value 出口
    ]),
    ("ReDoS 守卫（用户正则入参）", os.path.join("modules", "agent", "tools.py"), [
        r"MAX_REGEX_LEN", r"_NESTED_QUANT_RE",
    ]),
    ("命令通道编码与注入防线", os.path.join("modules", "agent", "tools.py"), [
        r"locale\.getpreferredencoding",
        r'encoding="utf-8"',                             # tshark 专用
        r"bpf\.startswith\(\"-\"\)",                     # 防选项注入
    ]),
    ("幂等门如实上报", os.path.join("modules", "agent", "tools.py"), [
        r"抓包已在运行", r"采集线程已在运行",
    ]),
    ("工具组 fail-closed", os.path.join("modules", "agent", "tools.py"), [
        r"无任何有效组",
    ]),
    ("敏感路径短名归一", os.path.join("modules", "agent", "tools.py"), [
        r"_win_longpath", r"_is_sensitive_path",
    ]),
    ("注册表枚举 259 甄别（删除侧）", os.path.join("modules", "screener", "cleanup.py"), [
        r"winerror == 259",
    ]),
    ("注册表枚举 259 甄别 + 截断标记（扫描侧）",
     os.path.join("modules", "screener", "identity_hunt.py"), [
        r"winerror != 259", r"files_truncated", r"registry_truncated",
        r"_reg_value_text",
    ]),
    ("脱敏形状规则", os.path.join("core", "redact.py"), [
        r"_UUID_SHAPE_RE", r"_HEX32_SHAPE_RE", r"def key_is_secret",
    ]),
]


def check_guard_anchors():
    problems = []
    for name, path, anchors in GUARD_ANCHORS:
        try:
            src = open(path, encoding="utf-8").read()
        except OSError:
            problems.append("%s: 文件缺失 %s" % (name, path))
            print("  [ANCHOR-MISS] %s （%s 读不到）" % (name, path))
            continue
        missing = [a for a in anchors if not re.search(a, src)]
        if missing:
            problems.append("%s 缺锚点 %s（%s）" % (name, missing, path))
            print("  [ANCHOR-MISS] %s ← %s" % (name, missing))
        else:
            print("  [OK] %-28s %d 锚点（%s）" % (name, len(anchors), path))
    return problems


# —————————————————————————————— C. 同类位普查 ——————————————————————————————
# 用户正则入参：tools.py 内函数级 re.compile 必须同函数带 MAX_REGEX_LEN
_REDOSS_EXEMPT_FUNCS = set()  # 新增无守卫编译位须进 Future 再登记豁免


def check_redoss_census():
    problems = []
    path = os.path.join("modules", "agent", "tools.py")
    src = open(path, encoding="utf-8").read()
    for name, seg in _func_segments(src):
        if "re.compile(" in seg and "MAX_REGEX_LEN" not in seg \
                and name not in _REDOSS_EXEMPT_FUNCS:
            problems.append("tools.py::%s 含 re.compile 但无 ReDoS 守卫" % name)
    print("\n[C1] tools.py 函数级 re.compile 普查：%s"
          % ("干净" if not problems else "发现 %d 处未守卫" % len(problems)))
    return problems


# winreg 枚举结束甄别：生产码含 EnumKey/EnumValue 的文件必须处理 winerror；
# 豁免清单 = Future.md 2026-09-19 §4 已登记的待修位（修好后从这里删）
_ENUM_EXEMPT = {
    os.path.join("modules", "regscan.py"),
    os.path.join("modules", "activity.py"),
    os.path.join("modules", "screener", "fsreg.py"),
}


def check_enum_census():
    problems = []
    hit_files = 0
    for path in _iter_py_files(("modules", "core")):
        try:
            src = open(path, encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        if not re.search(r"\bEnum(?:Key|Value)\s*\(", src):
            continue
        hit_files += 1
        if "winerror" not in src and path not in _ENUM_EXEMPT:
            problems.append("%s 枚举 OSError 未按 winerror 甄别（且不在 Future 豁免）"
                            % path)
    print("[C2] winreg 枚举文件 %d 个（豁免 %d，Future §4 待修）"
          % (hit_files, len(_ENUM_EXEMPT)))
    for p in problems:
        print("  [ENUM-GAP] %s" % p)
    return problems


# 幂等门：tools.py 内调用 watcher.start/pcap.start_capture 的函数必须区分"已运行"
_IDEMPOTENT_GATE_CALL = re.compile(r"\b(?:watcher|pcap)\.start(?:_capture)?\s*\(")


def check_idempotent_census():
    problems = []
    path = os.path.join("modules", "agent", "tools.py")
    src = open(path, encoding="utf-8").read()
    for name, seg in _func_segments(src):
        if _IDEMPOTENT_GATE_CALL.search(seg) and "已在运行" not in seg:
            problems.append("tools.py::%s 调 bool-start 但未区分幂等门 False"
                            % name)
    print("[C3] tools.py 幂等门调用普查：%s"
          % ("干净" if not problems else "发现 %d 处" % len(problems)))
    for p in problems:
        print("  [GATE-GAP] %s" % p)
    return problems


def main():
    allowed = _load_allowed()
    missing = []
    for entry in sorted(allowed):
        module, func = entry.split(".", 1)
        if module in _BUILTIN_MODULES:
            print("  [SKIP] %-50s （_call 内置分支）" % entry)
            continue
        fn = resolve(module, func)
        if callable(fn):
            print("  [OK]   %s" % entry)
        else:
            missing.append(entry)
            print("  [MISS] %s  ← 白名单有口，模块无码" % entry)

    # GUI 页面 _mod("m", "f") 调用点扫描（不去重，逐调用点核对——FreqErr §18）
    pages_dir = os.path.join("ui", "pages")
    call_re = re.compile(r"""_mod\(\s*["']([a-z_]+)["']\s*,\s*["']([a-z_]+)["']\s*\)""")
    gui_missing = []
    checked = 0
    for name in sorted(os.listdir(pages_dir)):
        if not name.endswith(".py"):
            continue
        src = open(os.path.join(pages_dir, name), encoding="utf-8").read()
        for m in call_re.finditer(src):
            checked += 1
            module, func = m.group(1), m.group(2)
            if module in _BUILTIN_MODULES:
                continue
            if not callable(resolve(module, func)):
                gui_missing.append((name, module, func))
                print("  [GUI-MISS] %s: _mod(%r, %r) ← 页面有按钮，模块无函数"
                      % (name, module, func))
    print("\n白名单 %d 项（内置分支除外 %d 项核对），GUI 调用点 %d 处核对"
          % (len(allowed), len(allowed) - sum(
              1 for e in allowed if e.split(".", 1)[0] in _BUILTIN_MODULES), checked))

    env_problems = check_envelope_consumers()
    print("[B] 守卫覆盖锚点表：")
    anchor_problems = check_guard_anchors()
    print()
    redoss_problems = check_redoss_census()
    enum_problems = check_enum_census()
    gate_problems = check_idempotent_census()

    if missing or gui_missing:
        print("契约缺失 %d 项，GUI 缺失 %d 处" % (len(missing), len(gui_missing)))
        return 1
    extra = (env_problems + anchor_problems + redoss_problems
             + enum_problems + gate_problems)
    if extra:
        print("加强项检查失败 %d 条（封套/锚点/ReDoS/枚举/幂等门）" % len(extra))
        return 1
    print("契约全部成立。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
