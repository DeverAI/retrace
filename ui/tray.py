"""系统托盘：QSystemTrayIcon。

菜单：显示主界面 / 开机自启(勾选) / 打开数据目录 / 退出。
图标为程序化绘制的黑白放大镜，不依赖外部图片资源。
"""
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QColor, QGuiApplication, QIcon, QPainter, QPen, QPixmap
from PyQt6.QtWidgets import QMenu, QSystemTrayIcon

from ui import autostart


def _icon():
    """程序化绘制的黑白放大镜（筛查/查找语义），无外部图片依赖。

    高分辨率渲染（2x + 自动缩放），抗锯齿描边 + 镜片渐变。
    """
    dpr = QGuiApplication.primaryScreen().devicePixelRatio() if QGuiApplication.primaryScreen() else 1.0
    base = 32
    pm = QPixmap(int(base * dpr), int(base * dpr))
    pm.setDevicePixelRatio(dpr)
    pm.fill(QColor(0, 0, 0, 0))  # 透明底，适配深浅色托盘
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

    # 镜框：空心圆 + 粗描边
    pen = QPen(QColor(255, 255, 255), 3)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    p.setBrush(QColor(0, 0, 0, 0))
    p.drawEllipse(5, 5, 17, 17)

    # 镜片：淡色填充
    p.setBrush(QColor(255, 255, 255, 30))
    p.setPen(QPen(QColor(0, 0, 0, 0), 0))
    p.drawEllipse(5, 5, 17, 17)

    # 手柄：斜线 + 描边
    p.setPen(pen)
    p.setBrush(QColor(255, 255, 255))
    p.drawLine(19, 19, 27, 27)

    p.end()
    return QIcon(pm)


class Tray(QSystemTrayIcon):
    """托盘图标。show_cb 显示主界面，quit_cb 真正退出。"""

    def __init__(self, parent, show_cb, quit_cb, open_console_cb=None):
        super().__init__(_icon(), parent)
        self._show_cb = show_cb
        self._quit_cb = quit_cb
        self.setToolTip("ReTrace 漏洞查找分析反向工具")

        menu = QMenu()
        self._act_show = QAction("显示主界面", menu)
        self._act_show.triggered.connect(lambda: show_cb())
        menu.addAction(self._act_show)

        if open_console_cb:
            act = QAction("打开 Web 控制台", menu)
            act.triggered.connect(lambda: open_console_cb())
            menu.addAction(act)

        self._act_auto = QAction("开机自启", menu)
        self._act_auto.setCheckable(True)
        self._act_auto.setChecked(autostart.is_enabled())
        self._act_auto.triggered.connect(self._toggle_autostart)
        menu.addAction(self._act_auto)

        menu.addSeparator()
        act_quit = QAction("退出", menu)
        act_quit.triggered.connect(lambda: quit_cb())
        menu.addAction(act_quit)

        self.setContextMenu(menu)
        self.activated.connect(self._on_activated)
        self.show()

    def _toggle_autostart(self, checked):
        ok = autostart.set_enabled(bool(checked))
        if not ok:
            self._act_auto.setChecked(autostart.is_enabled())

    def _on_activated(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.Trigger,
                      QSystemTrayIcon.ActivationReason.DoubleClick):
            self._show_cb()
