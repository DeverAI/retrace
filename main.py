"""ReTrace 漏洞查找分析反向工具 — 入口。

用法：
  python main.py                    启动 PyQt6 桌面 + Web 控制台
  python main.py --minimized       启动后最小化到托盘（开机自启使用）
  python main.py --no-web          仅桌面 GUI
  python main.py --no-gui          仅 Web 控制台
  python main.py --selfcheck       环境自检（不开界面）
"""
import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import config, db, events, logger


def main():
    parser = argparse.ArgumentParser(description="ReTrace 漏洞查找分析反向工具")
    parser.add_argument("--no-web", action="store_true", help="不启动 Web 控制台")
    parser.add_argument("--no-gui", action="store_true", help="不启动桌面 GUI")
    parser.add_argument("--minimized", action="store_true", help="启动后最小化到托盘")
    parser.add_argument("--port", type=int, default=8080, help="Web 端口")
    parser.add_argument("--selfcheck", action="store_true", help="环境自检后退出")
    parser.add_argument("--daemon", action="store_true",
                        help="仅运行持久任务后台守护（无 Web/GUI）")
    parser.add_argument("--agent", metavar="TASK", nargs="?", const="",
                        help="以命令行方式运行 LLM Agent（留空进入交互式）")
    args = parser.parse_args()

    logger.install_hook()
    cfg = config.load()
    logger.info("ReTrace 启动，工作目录=%s" % config.ROOT)
    db.init()

    if logger.has_err():
        logger.warn("检测到 Err.log 有未修复错误，请先查看处理：")
        logger.warn(logger.read_err()[:500])

    from modules import register_all, shutdown as modules_shutdown
    register_all(events.bus, cfg)
    logger.info("已启用模块: %s" % ", ".join(modules_active()))

    if args.selfcheck:
        try:
            run_selfcheck(cfg)
        finally:
            modules_shutdown()
        return

    if args.agent is not None:
        from modules.agent.cli import run_cli
        try:
            return run_cli(args.agent)
        finally:
            modules_shutdown()

    if args.daemon:
        logger.info("持久任务守护进程已启动（Ctrl+C 退出）")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            modules_shutdown()
        return 0

    need_web = cfg["switches"].get("ui", True) and not args.no_web
    # GUI 只由启动参数控制，不受 config 开关影响（避免被配置成"无任何界面"）。
    need_gui = not args.no_gui

    # Web 控制台在后台线程运行；PyQt6 必须驻留主线程。
    web_thread = None
    if need_web:
        from ui.web_main import start_web
        web_thread = threading.Thread(target=start_web,
                                      kwargs={"port": args.port}, daemon=True)
        web_thread.start()

    if need_gui:
        try:
            from ui.gui import launch_gui
            app = launch_gui(args)
        except Exception as e:
            logger.record_err("gui.start", e)
            logger.warn("桌面 GUI 启动失败，已降级")
            app = None
        if app is not None:
            code = 0
            try:
                code = app.exec()
            except KeyboardInterrupt:
                pass
            finally:
                modules_shutdown()
            return code

    if web_thread is not None:
        logger.info("Web 控制台运行于 http://127.0.0.1:%d/ （Ctrl+C 退出）" % args.port)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            modules_shutdown()
    else:
        logger.info("没有界面可用，输入 Ctrl+C 退出")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            modules_shutdown()


def modules_active():
    from modules import active
    return active()


def run_selfcheck(cfg):
    from modules import MODULES
    from modules.pcap import find_tshark
    for name, label, desc in MODULES:
        state = "ON" if cfg["switches"].get(name, True) else "off"
        print("  [%s] %-24s %s" % (state, label, desc))
    tshark = find_tshark()
    print("  tshark 可用: %s" % (tshark if tshark else "未找到"))
    print("  Python: %s" % sys.version.split()[0])
    print("自检完成。")


if __name__ == "__main__":
    sys.exit(main())
