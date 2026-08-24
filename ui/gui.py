"""PyQt6 桌面主界面。

- 左导航 + 堆叠页；页签按 config 模块开关动态生成（关闭的模块不显示入口）。
- 阻塞操作一律走 QThread 后台执行，界面不卡死。
- 关闭窗口 = 隐藏到托盘；托盘菜单"退出"才真正退出。
- 暗色安全控制台风格 QSS，与 Web 控制台色板统一。

页面实现见 ui/pages/（每页一文件）；主题/QThread 设施/控件工厂见 ui/gui_common.py。
"""
import sys
import webbrowser

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QListWidget,
    QStackedWidget, QLabel, QMessageBox, QSystemTrayIcon,
)

from core import logger
from ui.gui_common import QSS
from ui.pages import build_pages


# ============================================================================
#  主窗口
# ============================================================================
class MainWindow(QMainWindow):
    def __init__(self, app, port=8080, minimized=False):
        super().__init__()
        self._app = app
        self._port = port
        self._threads = []
        self._quitting = False
        self.setWindowTitle("ReTrace 漏洞查找分析反向工具")
        self.resize(1080, 720)

        # ---- 侧栏 + 内容区 ----
        central = QWidget()
        central.setObjectName("central")
        self.setCentralWidget(central)
        main_lay = QHBoxLayout(central)
        main_lay.setContentsMargins(0, 0, 0, 0)
        main_lay.setSpacing(0)

        # 侧栏
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(200)
        sb_lay = QVBoxLayout(sidebar)
        sb_lay.setContentsMargins(12, 16, 12, 8)
        sb_lay.setSpacing(8)

        # 品牌头
        brand_name = QLabel("ReTrace")
        brand_name.setObjectName("brand-name")
        brand_sub = QLabel("漏洞分析控制台")
        brand_sub.setObjectName("brand-sub")
        sb_lay.addWidget(brand_name)
        sb_lay.addWidget(brand_sub)
        sb_lay.addSpacing(8)

        # 导航列表
        self.nav = QListWidget()
        self.nav.setObjectName("navlist")
        sb_lay.addWidget(self.nav, 1)

        # 底部状态
        nav_foot = QLabel("● 本地控制台")
        nav_foot.setObjectName("nav-footer")
        sb_lay.addWidget(nav_foot)

        main_lay.addWidget(sidebar)

        # 内容堆叠
        self.stack = QStackedWidget()
        main_lay.addWidget(self.stack, 1)

        # ---- 页面注册 ----
        pages = build_pages(self)

        self._pages = {}
        for i, (label, page) in enumerate(pages):
            self.stack.addWidget(page)
            self.nav.addItem(label)
            self._pages[label] = i
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)

        # ---- 托盘 ----
        from ui.tray import Tray
        self.tray = Tray(self, self.show_window, self._real_quit, self.open_console)

        app.setQuitOnLastWindowClosed(False)
        self._minimized = minimized
        if minimized:
            if QSystemTrayIcon.isSystemTrayAvailable():
                self.hide()
                self.tray.showMessage("ReTrace", "已最小化到托盘运行",
                                      QSystemTrayIcon.MessageIcon.Information, 2000)
            else:
                self.show()
        else:
            self.show()

    # ---- 事件 ----
    def closeEvent(self, ev):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            # 无托盘环境：退出被后台任务否决时必须保留窗口，
            # 否则 setQuitOnLastWindowClosed(False) 会留下无界面僵尸进程
            if not self._real_quit():
                ev.ignore()
                return
            ev.accept()
            return
        self.hide()
        self.tray.showMessage("ReTrace", "已最小化到托盘，退出请右键托盘图标",
                              QSystemTrayIcon.MessageIcon.Information, 2000)
        ev.ignore()

    def show_window(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def open_console(self):
        webbrowser.open("http://127.0.0.1:%d/" % self._port)

    def _real_quit(self):
        """尝试真正退出。返回 True=已批准退出；False=被后台任务否决（窗口须保留）。"""
        self.tray.hide()
        self._quitting = True
        all_done = True
        for t in list(getattr(self, "_threads", [])):
            try:
                if t.isRunning():
                    t.requestInterruption()
                    if not t.wait(65000):
                        all_done = False
            except RuntimeError:
                pass
        if not all_done:
            self._quitting = False
            self.tray.show()
            QMessageBox.warning(self, "后台任务仍在收尾",
                                "为避免中断数据库或配置写入，本次退出已取消。请稍后再试。")
            return False
        self._app.quit()
        return True


def launch_gui(args):
    """创建 QApplication + 主窗口 + 托盘；返回 QApplication（mainloop=app.exec）。"""
    try:
        from PyQt6.QtWidgets import QApplication
    except Exception as e:
        logger.record_err("gui.pyqt_import", e)
        return None
    app = QApplication(sys.argv[:1])
    app.setApplicationName("ReTrace")
    app.setStyleSheet(QSS)
    win = MainWindow(app, port=getattr(args, "port", 8080),
                     minimized=bool(getattr(args, "minimized", False)))
    app._retrace_mainwin = win
    return app
