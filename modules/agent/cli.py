"""Agent 命令行入口。

用法：
  python main.py --agent "找出可疑APP并检查指纹"
  python main.py --agent ""        交互式（逐行输入任务）
  python -m modules.agent.cli "任务"
"""
import json
import sys

from core import config, logger
from modules import ai
from modules.agent import agent


def _confirm(name, args, verdict, forced):
    prefix = "[高危·必须人工审批]" if forced else "[需人工审批]"
    v = (verdict or {}).get("verdict", "?")
    reason = (" 理由: %s" % verdict["reason"]) if verdict and verdict.get("reason") else ""
    print("\n%s 审核结果=%s 工具=%s 参数=%s%s" % (
        prefix, v, name, json.dumps(args, ensure_ascii=False), reason))
    try:
        ans = input("放行执行? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("已取消")
        return False
    return ans in ("y", "yes")


def _notify(msg):
    print(msg)


def _print_result(r):
    if r.get("final"):
        print("\n========== 结果 ==========")
        print(r["final"])
    elif r.get("error"):
        print("错误: %s" % r["error"])
    if r.get("transcript"):
        print("\n--- 执行过程 ---")
        for t in r["transcript"]:
            if t.get("denied"):
                print("  [被拒] %s %s" % (t["tool"], json.dumps(t.get("args", {}), ensure_ascii=False)[:120]))
            else:
                ok = "OK" if t.get("result", {}).get("ok") else "FAIL"
                print("  [%s] %s" % (ok, t["tool"]))
    print("(步数 %d)" % r.get("steps", 0))


def run_cli(task=None):
    if not config.enabled("agent"):
        print("agent 模块开关未开启（config.json switches.agent=false）。")
        return 1
    if task:
        logger.info("Agent 任务: %s" % task)
        r = agent.run_task(task, confirm_cb=_confirm, notify_cb=_notify)
        _print_result(r)
        return 0 if r.get("ok") else 1
    print("ReTrace Agent 命令行（输入任务；exit 退出）")
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        if line.lower() in ("exit", "quit"):
            break
        r = agent.run_task(line, confirm_cb=_confirm, notify_cb=_notify)
        _print_result(r)
    return 0


if __name__ == "__main__":
    sys.path.insert(0, ".")
    from core import db
    config.load()
    db.init()
    sys.exit(run_cli(sys.argv[1] if len(sys.argv) > 1 else None))
