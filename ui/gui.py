"""PyQt6 桌面主界面。

- 左导航 + 堆叠页；页签按 config 模块开关动态生成（关闭的模块不显示入口）。
- 阻塞操作一律走 QThread 后台执行，界面不卡死。
- 关闭窗口 = 隐藏到托盘；托盘菜单"退出"才真正退出。
- 暗色安全控制台风格 QSS，与 Web 控制台色板统一。
"""
import os
import sys
import threading
import webbrowser

from PyQt6.QtCore import QMetaObject, Qt, QThread, QObject, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QStackedWidget, QLabel, QPushButton,
    QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QPlainTextEdit,
    QCheckBox, QFileDialog, QMessageBox, QGroupBox, QHeaderView,
    QSpinBox, QSystemTrayIcon, QGridLayout, QInputDialog, QAbstractItemView,
    QDialog, QDialogButtonBox, QTabWidget, QSplitter,
)

from core import config, db, logger
from modules import active as active_modules

# ============================================================================
#  QSS 暗色主题 — 与 Web 控制台色板统一
# ============================================================================
QSS = """
QWidget {
    background-color: #0b0f17;
    color: #e6edf3;
    font-family: "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
    font-size: 13px;
}
QMainWindow { background-color: #0b0f17; }

/* ---- 侧栏 ---- */
#sidebar {
    background-color: #111722;
    border-right: 1px solid #283449;
}
#brand-name { font-size: 16px; font-weight: bold; color: #e6edf3; }
#brand-sub { font-size: 11px; color: #6b7689; }
#nav-footer {
    color: #6b7689; font-size: 11px;
    padding: 10px 16px;
    border-top: 1px solid #1f2937;
}
#navlist {
    background-color: transparent;
    border: none;
    outline: none;
    padding: 6px 8px;
}
#navlist::item {
    padding: 9px 12px;
    margin: 1px 0;
    border-radius: 6px;
    color: #9aa7bd;
    border: 1px solid transparent;
}
#navlist::item:hover { background-color: #151c28; color: #e6edf3; }
#navlist::item:selected {
    background-color: #0f3a3a;
    color: #2dd4bf;
    border: 1px solid rgba(45,212,191,0.25);
}

/* ---- 内容区 ---- */
QStackedWidget { background-color: #0b0f17; }

/* ---- 页头 ---- */
#page-title { font-size: 18px; font-weight: 650; color: #e6edf3; }
#page-tag {
    font-size: 11px; font-weight: 600; color: #2dd4bf;
    background-color: #0f3a3a;
    border: 1px solid rgba(45,212,191,0.25);
    border-radius: 10px;
    padding: 1px 8px;
}

/* ---- 卡片 ---- */
QGroupBox {
    background-color: #151c28;
    border: 1px solid #283449;
    border-radius: 10px;
    padding: 14px 16px;
    margin-top: 14px;
    font-weight: normal;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px; top: 2px;
    padding: 0 6px;
    color: #9aa7bd;
    font-size: 11px;
    font-weight: bold;
}

/* ---- 按钮 ---- */
QPushButton {
    background-color: #1b2433;
    color: #e6edf3;
    border: 1px solid #283449;
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #151c28;
    border-color: #2dd4bf;
    color: #2dd4bf;
}
QPushButton:pressed { background-color: #111722; }
QPushButton:disabled {
    color: #6b7689;
    background-color: #1b2433;
    border-color: #1f2937;
}
QPushButton#primary {
    background-color: #2dd4bf;
    color: #06231f;
    border: 1px solid #2dd4bf;
    font-weight: 600;
}
QPushButton#primary:hover {
    background-color: #3de9d3;
    border-color: #3de9d3;
    color: #06231f;
}

/* ---- 输入 ---- */
QLineEdit, QComboBox, QSpinBox {
    background-color: #111722;
    border: 1px solid #283449;
    border-radius: 6px;
    padding: 7px 10px;
    color: #e6edf3;
    selection-background-color: #2dd4bf;
    selection-color: #06231f;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border: 1px solid #2dd4bf; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView {
    background-color: #151c28;
    border: 1px solid #283449;
    border-radius: 6px;
    padding: 4px;
    selection-background-color: #0f3a3a;
    selection-color: #2dd4bf;
    outline: none;
}
QPlainTextEdit {
    background-color: #111722;
    border: 1px solid #283449;
    border-radius: 6px;
    padding: 8px 10px;
    color: #e6edf3;
    font-family: "JetBrains Mono", "Cascadia Code", Consolas, monospace;
    font-size: 12px;
    selection-background-color: #2dd4bf;
    selection-color: #06231f;
}
QPlainTextEdit:focus { border: 1px solid #2dd4bf; }

/* ---- 表格 ---- */
QTableWidget {
    background-color: #151c28;
    border: 1px solid #283449;
    border-radius: 10px;
    gridline-color: #1f2937;
    outline: none;
}
QTableWidget::item { padding: 5px 8px; border-bottom: 1px solid #1f2937; }
QTableWidget::item:selected { background-color: #0f3a3a; color: #2dd4bf; }
QHeaderView::section {
    background-color: #1b2433;
    color: #9aa7bd;
    padding: 7px 8px;
    border: none;
    border-bottom: 1px solid #283449;
    font-size: 11px;
    font-weight: bold;
}
QTableCornerButton::section { background-color: #1b2433; border: none; }

/* ---- 复选框 ---- */
QCheckBox { color: #e6edf3; spacing: 8px; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #283449;
    border-radius: 4px;
    background-color: #111722;
}
QCheckBox::indicator:checked { background-color: #2dd4bf; border-color: #2dd4bf; }

/* ---- 滚动条 ---- */
QScrollBar:vertical { background: transparent; width: 10px; border: none; }
QScrollBar::handle:vertical { background: #283449; border-radius: 5px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #6b7689; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QScrollBar:horizontal { background: transparent; height: 10px; border: none; }
QScrollBar::handle:horizontal { background: #283449; border-radius: 5px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: #6b7689; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ---- 分隔线 ---- */
QSplitter::handle { background-color: #283449; }
QSplitter::handle:horizontal { width: 1px; }

/* ---- 菜单 ---- */
QMenu {
    background-color: #151c28;
    border: 1px solid #283449;
    border-radius: 6px;
    padding: 4px;
}
QMenu::item { padding: 6px 24px; border-radius: 4px; color: #e6edf3; }
QMenu::item:selected { background-color: #1b2433; color: #2dd4bf; }
QMenu::separator { height: 1px; background-color: #283449; margin: 4px 8px; }
"""

# 状态色（运行时动态 setStyleSheet 用）
_STATUS_COLOR = {
    "ok": "color: #3fb950;",
    "err": "color: #f85149;",
    "run": "color: #e3b341;",
    "info": "color: #9aa7bd;",
    "": "",
}


# ============================================================================
#  后台任务：QThread 执行任意函数，结果经信号回主线程
# ============================================================================
class _Worker(QObject):
    done = pyqtSignal(object)

    def __init__(self, fn, args, kwargs):
        super().__init__()
        self._fn, self._args, self._kwargs = fn, args, kwargs

    def run(self):
        try:
            self.done.emit(self._fn(*self._args, **self._kwargs))
        except Exception as e:
            logger.record_err("gui.worker", e)
            self.done.emit({"error": str(e)})


class _Invoker(QObject):
    """跨线程回调中继：worker 线程 emit，主线程以 QueuedConnection 执行。"""

    sig = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self.sig.connect(self._run, Qt.ConnectionType.QueuedConnection)

    def emit_run(self, fn):
        self.sig.emit(fn)

    def _run(self, fn):
        try:
            fn()
        except Exception as e:
            logger.record_err("gui.invoker", e)


_INV = _Invoker()


def _run_async(owner, fn, cb, *args, **kwargs):
    """在后台线程执行 fn，结果(可能 dict)回调 cb。返回 thread 对象。"""
    if not hasattr(owner, "_threads"):
        owner._threads = []
    win = owner.window() if isinstance(owner, QWidget) else None
    thread = QThread(owner)
    w = _Worker(fn, args, kwargs)
    thread._w = w  # 持有 Worker 强引用，防止函数返回后被 Python GC
    w.moveToThread(thread)
    thread.started.connect(w.run)
    w.done.connect(lambda v: _INV.emit_run(lambda: cb(v)))
    # quit 是线程安全的；DirectConnection 让 worker 完成时立即结束其事件循环，
    # 避免 GUI 退出阶段主线程 wait() 阻塞 queued quit。
    w.done.connect(thread.quit, Qt.ConnectionType.DirectConnection)
    w.done.connect(w.deleteLater)

    def _cleanup():
        # 线程结束后从锚定列表移除自身并释放 Worker 引用，防内存驻留
        for lst in (owner._threads, win._threads if win is not None else None):
            if lst is not None:
                try:
                    if thread in lst:
                        lst.remove(thread)
                except (ValueError, RuntimeError):
                    pass
        try:
            del thread._w
        except (AttributeError, RuntimeError):
            pass

    thread.finished.connect(_cleanup)
    thread.finished.connect(thread.deleteLater)
    thread.start()
    owner._threads.append(thread)
    # 同时锚到主窗口，保证退出时能统一等待收尾
    if win is not None and hasattr(win, "_threads"):
        win._threads.append(thread)
    # 防线程对象堆积：仅弹出已结束的，运行中的不得弹出（避免引用丢失被 GC）
    while len(owner._threads) > 32:
        old = owner._threads[0]
        try:
            running = old.isRunning()
        except RuntimeError:
            running = False
        if running and old is not thread:
            break
        owner._threads.pop(0)
    return thread


# ============================================================================
#  UI helpers
# ============================================================================
def _fill_table(table, rows, max_rows=500):
    """把 list[dict] 渲染进表格；非该结构返回 False。"""
    if not isinstance(rows, list):
        return False
    rows = rows[:max_rows]
    if not rows or not isinstance(rows[0], dict):
        table.clear()
        table.setRowCount(0)
        return False
    headers = list(rows[0].keys())
    table.clear()
    table.setColumnCount(len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, h in enumerate(headers):
            v = row.get(h)
            table.setItem(r, c, QTableWidgetItem("" if v is None else str(v)))
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    return True


def _label(text, muted=False):
    lb = QLabel(text)
    lb.setWordWrap(True)
    if muted:
        lb.setStyleSheet("color: #6b7689; font-size: 12px;")
    return lb


def _status_label(text="", kind=""):
    lb = QLabel(text)
    lb.setWordWrap(True)
    lb.setStyleSheet(_STATUS_COLOR.get(kind, ""))
    return lb


def _set_status(label, text, kind=""):
    label.setText(text)
    label.setStyleSheet(_STATUS_COLOR.get(kind, ""))


def _page_header(title, tag=None):
    """页面标题行：标题 + 可选标签。"""
    bar = QHBoxLayout()
    bar.setContentsMargins(0, 0, 0, 4)
    bar.setSpacing(10)
    lbl = QLabel(title)
    lbl.setObjectName("page-title")
    bar.addWidget(lbl)
    if tag:
        tg = QLabel(tag)
        tg.setObjectName("page-tag")
        bar.addWidget(tg)
    bar.addStretch(1)
    return bar


def _card(title=None):
    """卡片容器（QGroupBox），可选标题，自带 QVBoxLayout。"""
    g = QGroupBox(title) if title else QGroupBox()
    g.setLayout(QVBoxLayout())
    g.layout().setContentsMargins(14, 18, 14, 14)
    g.layout().setSpacing(10)
    return g


def _row(*items):
    """快捷水平行，返回 QHBoxLayout。"""
    r = QHBoxLayout()
    r.setSpacing(8)
    for i in items:
        if i:
            r.addWidget(i)
    return r


def _form_row(*pairs):
    """栅格化的"标签 / 控件"行（pairs = [("标签", widget), ("标签", widget), ...]）。
    用于把同类字段横排在卡片顶部，避免按钮和输入项挤在 _row() 里混乱。"""
    r = QHBoxLayout()
    r.setSpacing(8)
    for label, widget in pairs:
        if label and widget:
            wrap = QWidget(); lay = QHBoxLayout(wrap)
            lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(4)
            lbl = _label(label); lbl.setMinimumWidth(56)
            lay.addWidget(lbl); lay.addWidget(widget, 1)
            r.addWidget(wrap, 1)
        elif widget:
            r.addWidget(widget, 1)
    return r


def _toolbar(*items, spacing=6):
    """按钮栏——常驻顶部"操作区"，与 _form_row 区分配对。"""
    bar = QHBoxLayout()
    bar.setSpacing(spacing)
    for i in items:
        if i is None:
            bar.addStretch(1)
        elif i:
            bar.addWidget(i)
    return bar


def _placeholder(text):
    """空状态控件：表格没数据 / 还未加载时显示。"""
    e = QPlainTextEdit()
    e.setReadOnly(True)
    e.setPlainText(text)
    e.setMaximumHeight(80)
    return e


def _section(title, hint=None):
    """分组小标题（页面内部分区），一般用于卡片内 section。"""
    wrap = QWidget()
    lay = QVBoxLayout(wrap); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(2)
    lay.addWidget(_label(title, True))
    if hint:
        lay.addWidget(_label(hint, True))
    return wrap


def _hint(text):
    """细粒度提示（灰字小号），与 _label(True) 提示区分。"""
    e = QLabel(text)
    e.setObjectName("hint")
    e.setWordWrap(True)
    e.setStyleSheet("color:#6b7689; font-size:11px;")
    return e


def _btn(text, fn=None, primary=False):
    b = QPushButton(text)
    if primary:
        b.setObjectName("primary")
    if fn:
        b.clicked.connect(fn)
    return b


# ============================================================================
#  可复用对话框
# ============================================================================
class _TaskEditDialog(QDialog):
    """追踪任务编辑对话框（仅显示可编辑字段；name/exe/process/paths/interval/ai_enabled）。"""

    def __init__(self, parent, task):
        super().__init__(parent)
        self.setWindowTitle("编辑任务")
        self.setMinimumWidth(460)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 18, 18, 18); lay.setSpacing(12)

        self.name = QLineEdit(task.get("name") or "")
        self.name.setPlaceholderText("任务名（必填）")
        self.exe = QLineEdit(task.get("exe_path") or "")
        self.exe.setPlaceholderText("可执行文件完整路径")
        self.process = QLineEdit(task.get("process_name") or "")
        self.process.setPlaceholderText("进程名（如 app.exe）")
        self.paths = QLineEdit("; ".join(task.get("watch_paths") or []))
        self.paths.setPlaceholderText("补充观察目录；多个用分号分隔")
        self.interval = QSpinBox(); self.interval.setRange(1, 3600); self.interval.setValue(int(task.get("interval_sec") or 5))
        self.ai_enabled = QCheckBox("启用 AI 摘要"); self.ai_enabled.setChecked(bool(task.get("ai_enabled")))

        for w, lbl in ((self.name, "任务名"), (self.exe, "可执行文件"),
                       (self.process, "进程名"), (self.paths, "观察目录"),
                       (self.interval, "采样间隔（秒）")):
            row = QHBoxLayout(); l = _label(lbl); l.setMinimumWidth(92)
            row.addWidget(l); row.addWidget(w, 1)
            lay.addLayout(row)
        row2 = QHBoxLayout(); row2.addWidget(self.ai_enabled); row2.addStretch(1)
        lay.addLayout(row2)

        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept); bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def values(self):
        return {
            "name": self.name.text().strip(),
            "exe_path": self.exe.text().strip(),
            "process_name": self.process.text().strip(),
            "watch_paths": [p.strip() for p in self.paths.text().split(";") if p.strip()],
            "interval_sec": int(self.interval.value()),
            "ai_enabled": self.ai_enabled.isChecked(),
        }


# ============================================================================
#  各模块页
# ============================================================================
class OverviewPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        self._loaded = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("总览", "OVERVIEW"))

        c = _card("系统信息")
        self._info = QPlainTextEdit()
        self._info.setReadOnly(True)
        self._info.setMaximumHeight(200)
        c.layout().addWidget(self._info)
        lay.addWidget(c)

        c2 = _card("快捷操作")
        c2.layout().addLayout(_row(
            _btn("打开 Web 控制台", self._w.open_console, primary=True),
            _btn("打开数据目录", lambda: os.startfile(config.ROOT)),
        ))
        lay.addWidget(c2)
        lay.addStretch(1)

    def showEvent(self, ev):
        super().showEvent(ev)
        if not self._loaded:
            self._loaded = True
            self.refresh()

    def refresh(self):
        def load():
            obs = db.get_observations(limit=500)
            know = db.list_knowledge(limit=500)
            agents = db.list_agents(limit=500)
            return (len(obs), len(know), len(agents), logger.has_err())

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                self._info.setPlainText("概览获取失败: %s" % r["error"])
                return
            if isinstance(r, Exception):
                self._info.setPlainText("概览获取失败: %s" % r)
                return
            nobs, nknow, nagents, err = r
            text = "已启用模块: %s\n" % ", ".join(active_modules())
            text += "观察记录: %d  |  经验规则: %d  |  目标档案: %d\n" % (
                nobs, nknow, nagents)
            text += "Err.log: %s" % ("有未修复错误，见数据目录" if err else "干净")
            self._info.setPlainText(text)

        _run_async(self, load, cb)


class AiHelperPage(QWidget):
    """AI 助手：告诉 AI 你想做什么，AI 选工具执行（白名单命令 + 独立审核 + 人工审批）。"""

    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("AI 助手", "M10 · AGENT"))

        c = _card("任务输入")
        self.input = QLineEdit()
        self.input.setPlaceholderText("例如：列出可疑进程 / 检查 D:\\x.exe 的指纹 / 查看网络连接")
        self.input.returnPressed.connect(self._run)
        c.layout().addLayout(_row(self.input, _btn("发送给 AI", self._run, primary=True)))
        lay.addWidget(c)

        c2 = _card("结果")
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        c2.layout().addWidget(self.out)
        lay.addWidget(c2)

    def _run(self):
        task = self.input.text().strip()
        if not task:
            return
        self.out.setPlainText("AI 处理中（工具执行需经审核）...")

        def cb(r):
            if not isinstance(r, dict):
                r = {}
            if r.get("final"):
                self.out.setPlainText("== 结果 ==\n" + r["final"])
            elif r.get("error"):
                self.out.setPlainText("错误: %s" % r["error"])
            else:
                self.out.setPlainText(str(r))
            tr = r.get("transcript") or []
            if tr:
                lines = ["", "-- 执行过程 --"]
                for t in tr:
                    if t.get("denied"):
                        lines.append("  [被拒] %s" % t["tool"])
                    else:
                        res = t.get("result", {}) or {}
                        lines.append("  [%s] %s (%.2fs)" % (
                            "OK" if res.get("ok") else "FAIL", t["tool"], res.get("dur", 0)))
                self.out.appendPlainText("\n".join(lines))

        _run_async(self, _agent_run_task, cb, task, self._confirm)

    def _confirm(self, name, args, verdict, forced):
        """审批回调（worker 线程调用）：排队到 GUI 线程弹框，阻塞等待用户。"""
        import json as _json
        import threading as _t
        ev = _t.Event()
        result = {"ok": False}

        def ask():
            if ev.is_set():
                return  # 审批已结束（超时/退出放弃），迟到事件不再弹框
            if not self.isVisible():
                self._w.showNormal()
                self._w.raise_()
            if getattr(self._w, "_quitting", False):
                ev.set()
                return
            v = (verdict or {}).get("verdict", "?")
            reason = (verdict or {}).get("reason", "") or ""
            head = "[高危·必须人工审批]" if forced else "[需人工审批]"
            text = "%s\n工具: %s\n参数: %s\n审核结果: %s%s" % (
                head, name, _json.dumps(args, ensure_ascii=False),
                v, ("\n理由: " + reason) if reason else "")
            ret = QMessageBox.question(
                self, "AI 工具审批", text + "\n\n放行执行?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            result["ok"] = ret == QMessageBox.StandardButton.Yes
            ev.set()

        _INV.emit_run(ask)
        while not ev.wait(0.1):
            if getattr(self._w, "_quitting", False):
                ev.set()
                return False
        return result["ok"]


def _agent_run_task(task, confirm_cb):
    from modules.agent import agent
    return agent.run_task(task, confirm_cb=confirm_cb, notify_cb=None)


class ScreenerPage(QWidget):
    """筛查工作台：一键筛查 + 筛选 + 标记 + AI 辅助分析（人机协作）。
    布局：①通用扫描 ②文件/追踪分析 ③留样扫描与清理（独立大卡）④筛选与主结果表 ⑤标记 & AI 操作。
    """

    def __init__(self, window):
        super().__init__()
        self._w = window
        self._result = None
        self._items = []
        self._viewed = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("筛查工作台", "SCREENER"))
        self.status = _status_label("就绪", "info")
        lay.addWidget(self.status)

        # ---- ① 通用扫描 ----
        c1 = _card("① 通用扫描")
        self.dir1 = QLineEdit()
        self.dir1.setPlaceholderText("残留/指纹扫描目录")
        c1.layout().addLayout(_form_row(("扫描目录", self.dir1)))
        c1.layout().addLayout(_toolbar(
            _btn("扫描可疑 APP", lambda: self._scan(_mod("screener", "scan_suspicious_apps")), primary=True),
            _btn("扫描残留", lambda: self._scan(_mod("screener", "scan_leftover"), self.dir1.text().strip())),
            _btn("指纹扫描", lambda: self._scan(_mod("screener", "scan_fingerprints"), self.dir1.text().strip())),
        ))
        c1.layout().addLayout(_toolbar(
            _btn("已知指纹文件", lambda: self._scan(_mod("screener", "scan_machine_fingerprints"), "")),
            _btn("未知指纹内容", lambda: self._scan(_mod("screener", "scan_generic_fingerprints"), "")),
        ))
        c1.layout().addWidget(_hint("扫描可疑 APP：自启动点位+风险词；扫描残留：双根 HKLM+HKCU 悬空引用+空目录；"
                                    "指纹：深度≤6、≤512MB；已知指纹文件：按模式库匹配 machineid/DIPS/Client ID 等；"
                                    "未知指纹内容：按文件名关键词+UUID/长十六进制内容判定。"))
        lay.addWidget(c1)

        # ---- ② 单文件分析 / 启动追踪 ----
        c2 = _card("② 文件 / 追踪 / 格式逆向")
        self.filepath = QLineEdit(); self.filepath.setPlaceholderText("文件路径（py / exe / dll / class / 指纹文件）")
        self.tname = QLineEdit(); self.tname.setPlaceholderText("追踪目标名")
        self.texe = QLineEdit(); self.texe.setPlaceholderText("目标 exe 路径（可选）")
        c2.layout().addLayout(_form_row(("文件", self.filepath), ("目标名", self.tname), ("exe", self.texe)))
        c2.layout().addLayout(_toolbar(
            _btn("检查文件", lambda: self._scan(_mod("screener", "check_file"), self.filepath.text().strip())),
            _btn("追踪 APP", lambda: self._scan(_mod("screener", "track_app"),
                                              self.tname.text().strip(), self.texe.text().strip()), primary=True),
        ))
        c2.layout().addLayout(_toolbar(
            _btn("逆向解析指纹格式", self._fmt_analyze),
            _btn("生成可信替换预览", self._fmt_preview),
        ))
        self.fp_q = QLineEdit(); self.fp_q.setPlaceholderText("AI 指纹修改指导问题（可选）")
        c2.layout().addLayout(_form_row(("AI 问题", self.fp_q)))
        c2.layout().addLayout(_toolbar(
            _btn("AI 指导（安全自检）", self._fp_guidance),
        ))
        c2.layout().addWidget(_hint("逆向解析：SQLite/JSON/DPAPI/UUID/hex 指纹文件的创建规则与改写指导；"
                                    "替换预览：生成符合规则的替换值（只读不写盘），防改坏后软件不信任重建。"
                                    " AI 指导：带强制【已检查】安全自检，绝不自动执行。"))
        lay.addWidget(c2)

        # ---- ②½ 深潜扫描（Prefetch / 使用历史 / WER） ----
        cdeep = _card("②½ 深潜扫描（卸载后仍残留的隐藏痕迹，需软件关键词）")
        self.deep_kw = QLineEdit(); self.deep_kw.setPlaceholderText("软件关键词（如 Qoder）")
        cdeep.layout().addLayout(_form_row(("关键词", self.deep_kw)))
        cdeep.layout().addLayout(_toolbar(
            _btn("Prefetch 执行痕迹", lambda: self._scan_kw(_mod("screener", "scan_prefetch_traces")), primary=True),
            _btn("注册表使用历史", lambda: self._scan_kw(_mod("screener", "scan_usage_history"))),
            _btn("WER 崩溃报告", lambda: self._scan_kw(_mod("screener", "scan_wer_traces"))),
        ))
        cdeep.layout().addWidget(_hint("Prefetch：程序每次运行的 .pf 执行痕迹；使用历史：MuiCache + UserAssist（ROT13）"
                                       " + AppCompat + BAM 系统级执行时间戳；WER：崩溃报告残留。卸载后仍保留。"))
        lay.addWidget(cdeep)

        # ---- ③ 留样扫描与批量清理（独立大卡） ----
        self._trace_items = []
        ct = _card("③ 留样扫描与批量清理（不依赖安装目录）")
        self.trace_kw = QLineEdit(); self.trace_kw.setPlaceholderText("软件关键词（如 Qoder）")
        self.restore_dir = QLineEdit(); self.restore_dir.setPlaceholderText("恢复目录（清理结果里的 quarantine）")
        ct.layout().addLayout(_form_row(("关键词", self.trace_kw), ("恢复目录", self.restore_dir)))
        ct.layout().addLayout(_toolbar(
            _btn("留样扫描", self._trace_scan, primary=True),
            _btn("预览清理（不执行）", self._trace_preview),
        ))
        ct.layout().addLayout(_toolbar(
            _btn("批量清理勾选", self._trace_cleanup),
            _btn("一键恢复", self._trace_restore),
        ))
        self.trace_table = QTableWidget()
        self.trace_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.trace_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        ct.layout().addWidget(self.trace_table, 1)
        self.trace_out = QPlainTextEdit(); self.trace_out.setReadOnly(True)
        self.trace_out.setMaximumHeight(120)
        ct.layout().addWidget(self.trace_out)
        ct.layout().addWidget(_hint("清理会先创建系统还原点；系统身份范围（MachineGuid/BIOS/网卡）确定性拒绝。"))
        lay.addWidget(ct, 1)

        # ---- ④ 筛选与主结果表 ----
        c4 = _card("④ 主结果（可筛选后标记入库）")
        filt_bar = QHBoxLayout()
        self.f_cat = QComboBox(); self.f_cat.addItem("全部")
        self.f_risk = QComboBox(); self.f_risk.addItems(["全部", "高", "中", "低", "无"])
        filt_bar.addWidget(_label("类别")); filt_bar.addWidget(self.f_cat)
        filt_bar.addSpacing(12); filt_bar.addWidget(_label("风险")); filt_bar.addWidget(self.f_risk)
        filt_bar.addStretch(1)
        c4.layout().addLayout(filt_bar)
        self.table = QTableWidget()
        c4.layout().addWidget(self.table, 1)
        # 标记 & AI
        sub = QHBoxLayout()
        self.m_risk = QComboBox(); self.m_risk.addItems(["高", "中", "低", "无"])
        self.m_note = QLineEdit(); self.m_note.setPlaceholderText("备注（可选）")
        sub.addWidget(_label("标记风险")); sub.addWidget(self.m_risk); sub.addSpacing(12)
        sub.addWidget(self.m_note, 1)
        sub.addWidget(_btn("标记选中入库", self._mark, primary=True))
        sub.addWidget(_btn("AI 辅助分析", self._ai))
        c4.layout().addLayout(sub)
        self.ai_out = QPlainTextEdit(); self.ai_out.setReadOnly(True)
        self.ai_out.setMaximumHeight(140)
        c4.layout().addWidget(self.ai_out)
        lay.addWidget(c4, 1)

        self.f_cat.currentTextChanged.connect(self._filter)
        self.f_risk.currentTextChanged.connect(self._filter)

    def _scan(self, fn, *args):
        self.status.setText("扫描中...")
        self.status.setStyleSheet(_STATUS_COLOR["run"])
        self.ai_out.clear()

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "错误: %s" % r["error"], "err")
                return
            self._result = r
            self._items = (r or {}).get("items", []) or []
            s = (r or {}).get("summary") or {}
            _set_status(self.status, "%s：共%d 高%d 中%d 低%d" % (
                (r or {}).get("category", "扫描"), s.get("total", 0),
                s.get("high", 0), s.get("med", 0), s.get("low", 0)), "ok")
            cats = sorted({it.get("category", "?") for it in self._items})
            self.f_cat.blockSignals(True)
            self.f_cat.clear()
            self.f_cat.addItem("全部")
            for cat in cats:
                self.f_cat.addItem(cat)
            self.f_cat.blockSignals(False)
            self._filter()

        _run_async(self, fn, cb, *args)

    def _scan_kw(self, fn):
        """深潜扫描专用：校验软件关键词非空后发起扫描。"""
        kw = self.deep_kw.text().strip()
        if not kw:
            QMessageBox.warning(self, "提示", "请输入软件关键词（如 Qoder）")
            return
        self._scan(fn, kw)

    def _fmt_path(self):
        p = self.filepath.text().strip()
        if not p:
            QMessageBox.warning(self, "提示", "请先在「文件」框填写指纹文件路径")
            return ""
        return p

    def _fmt_analyze(self):
        """逆向解析指纹文件编码格式（只读）。"""
        p = self._fmt_path()
        if not p:
            return
        _set_status(self.status, "格式逆向解析中…", "run")

        def cb(r):
            if not isinstance(r, dict):
                _set_status(self.status, "解析失败: %s" % r, "err")
                return
            if r.get("error"):
                _set_status(self.status, "解析失败: %s" % r["error"], "err")
                return
            text = json_dump(r)
            self.ai_out.setPlainText(text)
            _set_status(self.status, "格式: %s | 风险: %s" % (
                r.get("format", "?"), r.get("risk", "?")), "ok")

        _run_async(self, _mod("screener", "analyze_fingerprint_format"), cb, p)

    def _fmt_preview(self):
        """生成可信替换预览（只读不写盘）。"""
        p = self._fmt_path()
        if not p:
            return
        _set_status(self.status, "生成替换预览中…", "run")

        def cb(r):
            if not isinstance(r, dict):
                _set_status(self.status, "预览失败: %s" % r, "err")
                return
            if r.get("error"):
                _set_status(self.status, "预览失败: %s" % r["error"], "err")
                return
            self.ai_out.setPlainText(json_dump(r))
            _set_status(self.status, "替换预览已生成（未写盘）", "ok")

        _run_async(self, _mod("screener", "generate_trusted_fingerprint"), cb, p)

    def _fp_guidance(self):
        """AI 指纹修改指导（带强制安全自检，只读不执行）。"""
        p = self._fmt_path()
        if not p:
            return
        q = self.fp_q.text().strip() or "请告诉我这个指纹文件的作用、格式规则，以及如何安全修改它（保持软件信任）。"
        _set_status(self.status, "AI 安全自检与指导生成中…", "run")

        def cb(r):
            if not isinstance(r, dict):
                _set_status(self.status, "AI 指导失败: %s" % r, "err")
                return
            if r.get("error"):
                _set_status(self.status, "AI 指导失败: %s" % r["error"], "err")
                return
            text = json_dump(r)
            self.ai_out.setPlainText(text)
            passed = r.get("safety_check_passed")
            _set_status(self.status,
                        "AI 指导完成（%s）" % ("已通过【已检查】" if passed else "⚠️ 安全自检未通过"),
                        "ok" if passed else "warn")

        _run_async(self, _mod("screener", "fingerprint_guidance"), cb, q, p)

    def _filter(self):
        cat = self.f_cat.currentText()
        risk = self.f_risk.currentText()
        rows = self._items
        if cat != "全部":
            rows = [i for i in rows if i.get("category") == cat]
        if risk != "全部":
            rows = [i for i in rows if i.get("risk") == risk]
        self._viewed = rows
        _fill_table(self.table, rows, 1000)

    def _selected(self):
        r = self.table.currentRow()
        return self._viewed[r] if 0 <= r < len(self._viewed) else None

    def _mark(self):
        it = self._selected()
        if not it:
            QMessageBox.warning(self, "提示", "请先选中一行")
            return
        _set_status(self.status, "标记入库中…", "run")

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "标记失败: %s" % r["error"], "err")
                QMessageBox.warning(self, "标记失败", r["error"])
                return
            it["state"] = "已标记"
            self._filter()
            _set_status(self.status, "已标记入库 obs#%s" % r, "ok")
        # 走 _run_async：mark_item 内含 SQLite 写库，不得阻塞 GUI 线程
        _run_async(self, _mod("screener", "mark_item"), cb,
                   it.get("name", "?"), it.get("category", "其他"),
                   self.m_risk.currentText(), it.get("detail", ""),
                   self.m_note.text().strip())

    def _ai(self):
        if not self._result or not self._items:
            QMessageBox.warning(self, "提示", "请先执行一次筛查")
            return
        self.ai_out.setPlainText("AI 分析中（只读辅助）...")

        def cb(r):
            if isinstance(r, dict) and r.get("ok"):
                self.ai_out.setPlainText(r["text"])
            elif isinstance(r, dict) and r.get("error"):
                self.ai_out.setPlainText("错误: %s" % r["error"])
            else:
                self.ai_out.setPlainText(str(r))

        _run_async(self, _mod("screener", "analyze_with_ai"), cb, self._result)

    def _trace_scan(self):
        kw = self.trace_kw.text().strip()
        if not kw:
            QMessageBox.warning(self, "提示", "请输入软件关键词")
            return
        self._trace_items = []
        _set_status(self.status, "留样扫描中（不依赖安装目录）…", "run")

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "错误: %s" % r["error"], "err")
                return
            self._trace_items = (r or {}).get("items", []) or []
            rows = [{"type": it.get("type"), "name": it.get("name"),
                     "target": it.get("target"), "risk": it.get("risk"),
                     "detail": it.get("detail")} for it in self._trace_items]
            _fill_table(self.trace_table, rows, 2000)
            s = (r or {}).get("summary") or {}
            _set_status(self.status, "留样：共%d 高%d 中%d 低%d" % (
                s.get("total", 0), s.get("high", 0), s.get("med", 0), s.get("low", 0)), "ok")

        _run_async(self, _mod("screener", "scan_software_traces"), cb,
                   kw, self.dir1.text().strip())

    def _trace_preview(self):
        """只读预览清理清单（不执行、不建还原点）。"""
        if not self._trace_items:
            QMessageBox.warning(self, "提示", "请先执行留样扫描")
            return
        _set_status(self.status, "只读预览中…", "run")

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "预览失败: %s" % r["error"], "err")
                return
            if not isinstance(r, dict):
                _set_status(self.status, "预览失败: %s" % r, "err")
                return
            will_clean = (r or {}).get("will_clean", [])
            will_deny = (r or {}).get("will_deny", [])
            lines = ["将清理 %d 项 | 将拒绝 %d 项" % (len(will_clean), len(will_deny)), ""]
            lines.append("—— 将清理 ——")
            for x in will_clean[:50]:
                lines.append("  [%s] %s" % (x.get("type", "?"), x.get("target", "")))
            if len(will_clean) > 50:
                lines.append("  … 还有 %d 项" % (len(will_clean) - 50))
            lines.append("")
            lines.append("—— 将拒绝 ——")
            for x in will_deny[:30]:
                lines.append("  [%s] %s" % (x.get("reason", "?"), x.get("target", "")))
            self.trace_out.setPlainText("\n".join(lines))
            _set_status(self.status, "预览完成：将清理 %d 项，拒绝 %d 项" % (
                len(will_clean), len(will_deny)), "ok")

        _run_async(self, _mod("screener", "preview_cleanup"), cb, self._trace_items)

    def _trace_cleanup(self):
        if not self._trace_items:
            QMessageBox.warning(self, "提示", "请先执行留样扫描")
            return
        rows = self.trace_table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.warning(self, "提示", "请先勾选要清理的项（可多选）")
            return
        items = [self._trace_items[r.row()] for r in rows
                 if 0 <= r.row() < len(self._trace_items)]
        reason, ok = QInputDialog.getText(self, "清理原因",
                                          "清理原因（至少 12 字：目的、对象、必要性）")
        if not ok or len(reason.strip()) < 12:
            QMessageBox.warning(self, "原因不足", "必须填写至少 12 字的清理原因")
            return

        def preview_cb(pv):
            if not isinstance(pv, dict):
                self._do_cleanup(items, reason.strip())
                return
            clean_lines = "\n".join("  [清理] %s  %s" % (x.get("type"), x.get("target"))
                                    for x in pv.get("will_clean", []))
            deny_lines = "\n".join("  [拒绝] %s  %s" % (x.get("reason"), x.get("target"))
                                   for x in pv.get("will_deny", []))
            msg = ("即将清理 %d 项，拒绝 %d 项：\n\n%s\n\n将拒绝（系统身份/核心范围等）：\n%s\n\n"
                   "清理前会先创建系统还原点，删除项备份到 backups/quarantine。确认继续？" % (
                       pv.get("clean_count", 0), pv.get("deny_count", 0),
                       clean_lines or "（无）", deny_lines or "（无）"))
            if QMessageBox.question(self, "清理前预览", msg) == QMessageBox.StandardButton.Yes:
                self._do_cleanup(items, reason.strip())
            else:
                _set_status(self.status, "已取消", "info")

        _run_async(self, _mod("screener", "preview_cleanup"), preview_cb, items)

    def _do_cleanup(self, items, reason):
        _set_status(self.status, "正在创建系统还原点并清理…", "run")

        def cb(r):
            if isinstance(r, dict) and r.get("ok"):
                self.trace_out.setPlainText(json_dump(r))
                denied = len((r or {}).get("denied") or [])
                _set_status(self.status, "清理完成：成功 %d/%d%s；备份目录 %s" % (
                    r.get("ok_count", 0), r.get("total", 0),
                    "，已拒绝 %d 项" % denied if denied else "",
                    r.get("quarantine", "")), "ok")
            else:
                _set_status(self.status, "清理失败: %s" % r.get("error", r), "err")

        _run_async(self, _mod("screener", "cleanup_traces"), cb, items, reason)

    def _trace_restore(self):
        qd = self.restore_dir.text().strip()
        if not qd:
            QMessageBox.warning(self, "提示", "请输入备份目录（清理结果里的 quarantine）")
            return
        if QMessageBox.question(self, "确认恢复",
                "将从 %s 恢复被清理的项。确认继续？" % qd) != QMessageBox.StandardButton.Yes:
            return
        _set_status(self.status, "正在从备份恢复…", "run")

        def cb(r):
            if isinstance(r, dict) and r.get("ok"):
                self.trace_out.setPlainText(json_dump(r))
                _set_status(self.status, "恢复完成：成功 %d/%d" % (
                    r.get("ok_count", 0), r.get("total", 0)), "ok")
            else:
                _set_status(self.status, "恢复失败: %s" % r.get("error", r), "err")

        _run_async(self, _mod("screener", "restore_traces"), cb, qd)


class PcapPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("网络抓包", "M1 · PCAP"))

        c = _card("抓包控制")
        self.iface = QComboBox()
        self.limit = QSpinBox()
        self.limit.setRange(50, 2000)
        self.limit.setValue(200)
        self.btn_start = _btn("开始抓包", self.toggle)
        c.layout().addLayout(_row(
            _label("接口"), self.iface,
            _btn("刷新接口", self.load_ifaces),
            self.btn_start,
            _label("条数"), self.limit,
        ))
        lay.addWidget(c)

        # ---- 离线解析 / 维护（补齐后端能力入口） ----
        c2 = _card("离线解析 / 状态 / 维护")
        self.offline_path = QLineEdit()
        self.offline_path.setPlaceholderText("pcap / pcapng 文件路径")
        c2.layout().addLayout(_form_row(("文件", self.offline_path)))
        c2.layout().addLayout(_toolbar(
            _btn("离线解析", self.parse_offline, primary=True),
            _btn("抓包状态", self._status),
            _btn("流量统计", self._stats),
            None,
            _btn("清理已停抓包", self._prune),
            _btn("停止全部抓包", self._stop_all),
        ))
        lay.addWidget(c2)

        self.table = QTableWidget()
        lay.addWidget(self.table, 1)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setMaximumHeight(150)
        lay.addWidget(self.out)
        self._loaded = False

    def showEvent(self, ev):
        super().showEvent(ev)
        if not self._loaded:
            self._loaded = True
            self.load_ifaces()

    def _show_text(self, text):
        self.out.setPlainText(str(text)[:8000])

    def load_ifaces(self):
        def cb(rows):
            if isinstance(rows, list):
                self.iface.clear()
                for it in rows:
                    if isinstance(it, dict):
                        self.iface.addItem(str(it.get("name", it)), it)
        _run_async(self, _mod("pcap", "list_interfaces"), cb)

    def toggle(self):
        if self.btn_start.text() == "开始抓包":
            self.btn_start.setEnabled(False)
            iface = self.iface.currentData() if self.iface.count() else None
            name = (iface.get("name") if isinstance(iface, dict) else None) or str(self.iface.currentText())

            def cb(r):
                self.btn_start.setEnabled(True)
                ok = bool(isinstance(r, (tuple, list)) and r[0])
                self.btn_start.setText("停止抓包" if ok else "开始抓包")
                if ok:
                    self._poll()
                else:
                    QMessageBox.warning(self, "抓包失败", str(r))
            _run_async(self, _mod("pcap", "start_capture"), cb, "main", name, None)
        else:
            self.btn_start.setText("开始抓包")
            _run_async(self, _mod("pcap", "stop_capture"), lambda r: None, "main")

    def _poll(self):
        def cb(rows):
            ok = _fill_table(self.table, rows, self.limit.value())
            if not ok:
                self.table.setRowCount(1)
                self.table.setColumnCount(1)
                self.table.setHorizontalHeaderLabels(["info"])
                self.table.setItem(0, 0, QTableWidgetItem(str(rows)[:2000]))
        _run_async(self, _mod("pcap", "get_recent"), cb, "main", self.limit.value())

    def parse_offline(self):
        p = self.offline_path.text().strip()
        if not p:
            QMessageBox.warning(self, "路径为空", "请填写 pcap/pcapng 文件路径")
            return
        self._show_text("离线解析中（大文件较慢）...")

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                self._show_text("解析失败: %s" % r["error"])
                return
            n = len(r) if isinstance(r, list) else 0
            self._show_text("解析到 %d 个数据包\n%s" % (n, json_dump(r)[:6000]))
            _fill_table(self.table, r if isinstance(r, list) else [], 300)
        _run_async(self, _mod("pcap", "parse_offline"), cb, p)

    def _status(self):
        def cb(r):
            self._show_text(json_dump(r))
        _run_async(self, _mod("pcap", "capture_status"), cb, "main")

    def _stats(self):
        def load():
            rows = _mod("pcap", "get_recent")("main", 500)
            return _mod("pcap", "stat_summary")(rows or [])
        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                self._show_text("流量统计失败: %s" % r["error"])
            else:
                self._show_text(json_dump(r))
        _run_async(self, load, cb)

    def _prune(self):
        def cb(r):
            n = r if isinstance(r, int) else 0
            self._show_text("已清理 %d 个已停/空闲的抓包实例" % n)
        _run_async(self, _mod("pcap", "prune"), cb)

    def _stop_all(self):
        if QMessageBox.question(self, "停止全部", "确认停止全部抓包任务？") \
                != QMessageBox.StandardButton.Yes:
            return
        def cb(r):
            self.btn_start.setText("开始抓包")
            n = r if isinstance(r, int) else 0
            self._show_text("已停止全部抓包（%d 个运行中）" % n)
        _run_async(self, _mod("pcap", "stop_all"), cb)


class RegscanPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("注册表搜索", "M2 · REGSCAN"))
        self.status = _status_label("就绪", "info")
        lay.addWidget(self.status)

        c = _card("搜索")
        self.keyword = QLineEdit()
        self.keyword.setPlaceholderText("关键词")
        self.root = QComboBox()
        self.root.addItems(["HKLM", "HKCU", "HKU"])
        self.btn = _btn("搜索", self.search, primary=True)
        c.layout().addLayout(_row(self.keyword, self.root, self.btn))
        c.layout().addLayout(_toolbar(
            _btn("扫描自启动/COM/服务点位", self.autostart_points)))
        c.layout().addWidget(_hint("常驻点位：Run/RunOnce/IFEO/AppInit_DLLs/服务/ShellExecuteHooks/COM 等。"))
        lay.addWidget(c)

        # ---- 观察键管理 / 精确值（补齐后端能力入口） ----
        c2 = _card("观察键 / 精确值")
        self.watch_key = QLineEdit()
        self.watch_key.setPlaceholderText("观察键（如 HKLM\\SOFTWARE\\...\\Run）")
        self.value_key = QLineEdit()
        self.value_key.setPlaceholderText("键路径（如 HKCU\\Software\\X）")
        self.value_name = QLineEdit()
        self.value_name.setPlaceholderText("值名（可空）")
        c2.layout().addLayout(_form_row(("观察键", self.watch_key)))
        c2.layout().addLayout(_form_row(("键路径", self.value_key), ("值名", self.value_name)))
        c2.layout().addLayout(_toolbar(
            _btn("添加观察", self.add_watch, primary=True),
            _btn("移除观察", self.remove_watch),
            _btn("查看观察", self.list_watches),
            _btn("读精确值", self.read_value),
        ))
        c2.layout().addLayout(_toolbar(
            _btn("快照观察键", self.snapshot_watches),
            _btn("对比两次快照", self.diff_watches),
        ))
        c2.layout().addWidget(_hint("观察键与 M7 集中观察联动：快照 → APP 运行 → 再快照 → 对比得到值变化。"))
        lay.addWidget(c2)

        self.table = QTableWidget()
        lay.addWidget(self.table, 1)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setMaximumHeight(140)
        lay.addWidget(self.out)
        self._last_snap = None

    def _show_text(self, text):
        self.out.setPlainText(str(text)[:8000])

    def search(self):
        self.btn.setEnabled(False)

        def cb(rows):
            self.btn.setEnabled(True)
            if isinstance(rows, dict) and rows.get("error"):
                _set_status(self.status, "搜索失败: %s" % rows["error"], "err")
                self._err(rows["error"])
                return
            if isinstance(rows, dict) and rows.get("busy"):
                _set_status(self.status, "搜索失败: %s" % rows.get("error", "扫描进行中"), "err")
                self._err(rows.get("error", "扫描进行中"))
                return
            hits = rows.get("hits", []) if isinstance(rows, dict) else rows
            if isinstance(rows, dict):
                total = rows.get("total", len(hits))
                _set_status(self.status, "搜索完成: %d 命中（节点 %s%s）" % (
                    total, rows.get("nodes", "?"),
                    "，已截断" if rows.get("truncated") else ""), "ok")
            else:
                _set_status(self.status, "搜索完成: %d 命中" % len(hits), "ok")
            if not _fill_table(self.table, hits, 500):
                # 空结果/异常结构：给出友好提示而非把整个返回 dict 塞进表格
                self.table.setRowCount(1)
                self.table.setColumnCount(1)
                self.table.setHorizontalHeaderLabels(["info"])
                self.table.setItem(0, 0, QTableWidgetItem(
                    "0 命中（可尝试其它关键词/根键）"))
        _run_async(self, _mod("regscan", "search"), cb,
                   self.keyword.text().strip(), self.root.currentText(), "", "contains")

    def autostart_points(self):
        _set_status(self.status, "扫描常驻点位中…", "run")

        def cb(rows):
            if isinstance(rows, dict) and rows.get("error"):
                _set_status(self.status, "扫描失败: %s" % rows["error"], "err")
                self._err(rows["error"])
                return
            pts = rows if isinstance(rows, list) else []
            _set_status(self.status, "常驻点位: %d 项" % len(pts), "ok")
            if not _fill_table(self.table, pts, 500):
                self.table.setRowCount(1)
                self.table.setColumnCount(1)
                self.table.setHorizontalHeaderLabels(["info"])
                self.table.setItem(0, 0, QTableWidgetItem("未发现可读点位"))
        _run_async(self, _mod("regscan", "autostart_points"), cb, "ALL")

    def _err(self, rows):
        self.table.setRowCount(1)
        self.table.setColumnCount(1)
        self.table.setHorizontalHeaderLabels(["info"])
        self.table.setItem(0, 0, QTableWidgetItem(str(rows)[:2000]))

    def _watch_key_text(self):
        k = self.watch_key.text().strip()
        if not k:
            QMessageBox.warning(self, "参数缺失", "请填写观察键")
            return ""
        return k

    def add_watch(self):
        k = self._watch_key_text()
        if not k:
            return
        def cb(r):
            if bool(r):
                _set_status(self.status, "已添加观察: %s" % k, "ok")
            else:
                _set_status(self.status, "添加失败（键不存在或无权限）: %s" % k, "err")
        _run_async(self, _mod("regscan", "add_watch"), cb, k)

    def remove_watch(self):
        k = self._watch_key_text()
        if not k:
            return
        def cb(r):
            if bool(r):
                _set_status(self.status, "已移除观察: %s" % k, "ok")
            else:
                _set_status(self.status, "移除失败: %s（可能本就不在观察列表）" % k, "err")
        _run_async(self, _mod("regscan", "remove_watch"), cb, k)

    def list_watches(self):
        def cb(rows):
            _set_status(self.status, "观察键 %d 个" % (len(rows) if isinstance(rows, list) else 0), "ok")
            self._show_text(json_dump(rows))
        _run_async(self, _mod("regscan", "list_watches"), cb)

    def read_value(self):
        k = self.value_key.text().strip()
        if not k:
            QMessageBox.warning(self, "参数缺失", "请填写键路径（如 HKCU\\Software\\X）")
            return
        def cb(r):
            self._show_text(json_dump(r))
        _run_async(self, _mod("regscan", "read_value"), cb, k, self.value_name.text().strip())

    def snapshot_watches(self):
        def cb(r):
            self._last_snap = r
            _set_status(self.status, "已快照（可再点「对比两次快照」）", "ok")
            self._show_text(json_dump(r))
        _run_async(self, _mod("regscan", "snapshot_watches"), cb)

    def diff_watches(self):
        if self._last_snap is None:
            QMessageBox.warning(self, "无快照", "请先点「快照观察键」做一次快照")
            return
        before = self._last_snap

        def load():
            after = _mod("regscan", "snapshot_watches")()
            diffs = _mod("regscan", "diff_watches")(before, after or {})
            return {"diffs": diffs, "after": after}

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                self._show_text(r["error"])
                return
            diffs, after = (r or {}).get("diffs"), (r or {}).get("after")
            self._last_snap = after
            _set_status(self.status, "观察键变化 %d 处" % (len(diffs) if isinstance(diffs, list) else 0), "ok")
            _fill_table(self.table, diffs if isinstance(diffs, list) else [], 500)
            self._show_text(json_dump(diffs)[:4000])
        _run_async(self, load, cb)


class EmbedPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("经验检索", "M3 · EMBEDDING"))
        self.status = _status_label("就绪", "info")
        lay.addWidget(self.status)

        c = _card("① 语义检索")
        self.query = QLineEdit(); self.query.setPlaceholderText("检索关键词（如 '可疑驱动加载'）")
        self.query.returnPressed.connect(self.search)
        self.result = QTableWidget()
        c.layout().addLayout(_form_row(("关键词", self.query)))
        c.layout().addLayout(_toolbar(
            _btn("检索", self.search, primary=True),
            _btn("清空", lambda: self.result.clear()),
        ))
        c.layout().addWidget(self.result, 1)
        lay.addWidget(c, 1)

        c2 = _card("② 写入新经验（回车入库）")
        self.memo = QLineEdit(); self.memo.setPlaceholderText("新经验文本")
        self.memo.returnPressed.connect(self.remember)
        c2.layout().addLayout(_form_row(("文本", self.memo)))
        c2.layout().addLayout(_toolbar(
            _btn("记住入库", self.remember),
            _btn("编码单条文本", self.embed_one),
            _btn("保存索引到磁盘", self.save_index),
        ))
        c2.layout().addWidget(_hint("语义检索按词频-哈希向量 + 余弦相似度；可在 settings 切换为 OpenAI 兼容 embedding。"))
        lay.addWidget(c2)
        self._loaded = False

    def showEvent(self, ev):
        super().showEvent(ev)
        if not self._loaded:
            self._loaded = True
            self._refresh_status()

    def _refresh_status(self):
        def cb(s):
            if isinstance(s, dict):
                _set_status(self.status, "provider=%s · 经验=%s · 维度=%s" % (
                    s.get("provider", "?"), s.get("docs", "?"), s.get("dim", "?")), "ok")
            else:
                _set_status(self.status, "经验索引状态不可用: %s" % s, "err")
        # embedding.stats() 返回 {provider, docs, dim}；provider() 只返回字符串，勿再误用。
        _run_async(self, _mod("embedding", "stats"), cb)

    def search(self):
        q = self.query.text().strip()
        if not q:
            return
        _set_status(self.status, "检索中…", "run")
        def cb(rows):
            count = len(rows) if isinstance(rows, list) else 0
            _set_status(self.status, "命中 %d 条" % count, "ok")
            _fill_table(self.result, rows if isinstance(rows, list) else [], 100)
        _run_async(self, _mod("embedding", "search"), cb, q, 10, 0.0)

    def remember(self):
        text = self.memo.text().strip()
        if not text:
            return

        def cb(r):
            if r is None or r is False or (isinstance(r, dict) and (r.get("ok") is False or r.get("error"))):
                _set_status(self.status, "入库失败: %s" % text, "err")
                return
            self.memo.clear()
            _set_status(self.status, "已入库: %s" % text[:60], "ok")
            self._refresh_status()
        _run_async(self, _mod("embedding", "remember"), cb, text, {"source": "gui"})

    def embed_one(self):
        text = self.memo.text().strip()
        if not text:
            QMessageBox.information(self, "提示", "请先在文本框输入要编码的内容")
            return
        _set_status(self.status, "编码中…", "run")

        def cb(vec):
            if isinstance(vec, dict) and vec.get("error"):
                _set_status(self.status, "编码失败: %s" % vec["error"], "err")
                return
            n = len(vec) if isinstance(vec, list) else 0
            head = (vec[:8] if isinstance(vec, list) else [])
            _set_status(self.status, "已编码 %s 维（前 8 维: %s）" % (n, head), "ok")
        _run_async(self, _mod("embedding", "embed"), cb, text)

    def save_index(self):
        def cb(r):
            if bool(r):
                _set_status(self.status, "索引已写入 embedding_index.json", "ok")
            else:
                _set_status(self.status, "索引保存失败（详见 Err.log）", "err")
        _run_async(self, _mod("embedding", "save_index"), cb)


class DecompilePage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("多类别反编译", "M6 · DECOMPILE"))
        self.status = _status_label("就绪", "info")
        lay.addWidget(self.status)

        c = _card("目标文件")
        self.path = QLineEdit(); self.path.setPlaceholderText("文件路径（py / exe / dll / class）")
        c.layout().addLayout(_form_row(("文件", self.path)))
        c.layout().addLayout(_toolbar(
            _btn("选择文件", self.pick),
            _btn("反编译分析", self.run, primary=True),
            _btn("AI 审计（danger≥0.5 调用）", self.audit),
        ))
        lay.addWidget(c)

        # 结果三栏
        self.tabs = QTabWidget()
        # 概览（统计 + 可疑调用）
        overview = QWidget(); ov_lay = QVBoxLayout(overview); ov_lay.setContentsMargins(0, 0, 0, 0); ov_lay.setSpacing(6)
        self.summary = QPlainTextEdit(); self.summary.setReadOnly(True); self.summary.setMaximumHeight(120)
        self.calls = QTableWidget()
        ov_lay.addWidget(self.summary); ov_lay.addWidget(self.calls, 1)
        self.tabs.addTab(overview, "概览 / 可疑调用")
        # 原始 JSON
        raw = QWidget(); raw_lay = QVBoxLayout(raw); raw_lay.setContentsMargins(0, 0, 0, 0); raw_lay.setSpacing(6)
        self.out = QPlainTextEdit(); self.out.setReadOnly(True)
        copy = _btn("复制 JSON", lambda: self._copy(self.out.toPlainText()))
        cp_bar = _toolbar(copy, _btn("清空", lambda: self.out.clear()))
        raw_lay.addLayout(cp_bar); raw_lay.addWidget(self.out, 1)
        self.tabs.addTab(raw, "原始 JSON")
        # AI 审计
        ai = QWidget(); ai_lay = QVBoxLayout(ai); ai_lay.setContentsMargins(0, 0, 0, 0); ai_lay.setSpacing(6)
        self.ai_out = QPlainTextEdit(); self.ai_out.setReadOnly(True)
        ai_lay.addWidget(self.ai_out, 1)
        self.tabs.addTab(ai, "AI 审计")
        lay.addWidget(self.tabs, 1)
        lay.addWidget(_hint("三栏分别：概览统计 + 可疑调用清单 / 完整 JSON / AI 语义审计结果。"))

    def _copy(self, text):
        QApplication.clipboard().setText(text)
        _set_status(self.status, "已复制 %s 字符到剪贴板" % len(text), "ok")

    def pick(self):
        p, _ = QFileDialog.getOpenFileName(self, "选择目标文件")
        if p:
            self.path.setText(p)

    def run(self):
        p = self.path.text().strip()
        if not p or not os.path.exists(p):
            QMessageBox.warning(self, "路径无效", "请选择存在的文件")
            return
        _set_status(self.status, "反编译分析中…", "run")

        def cb(r):
            if not isinstance(r, dict):
                _set_status(self.status, "分析失败（非预期返回）", "err")
                self.summary.setPlainText(str(r)[:200])
                self.out.setPlainText(json_dump(r))
                return
            err = r.get("error") or (r.get("info") or {}).get("error") \
                if isinstance(r.get("info"), dict) else r.get("error")
            if err:
                _set_status(self.status, "分析失败: %s" % err, "err")
                self.summary.setPlainText("错误: %s" % err)
                self.out.setPlainText(json_dump(r))
                return
            _set_status(self.status, "分析完成", "ok")
            self.out.setPlainText(json_dump(r))
            # score 是 dict（high/med/suspicious 计数），不能当浮点直接 %.2f 格式化
            score = r.get("score") or {}
            score = score if isinstance(score, dict) else {}
            self.summary.setPlainText(
                "kind=%s · 高危%d 中危%d 可疑串%d · strings=%d · calls=%d"
                % (r.get("kind"), score.get("high", 0), score.get("med", 0),
                   score.get("suspicious", 0), len(r.get("strings") or []),
                   len(r.get("calls") or [])))
            _fill_table(self.calls, r.get("calls") or [], 200)
        _run_async(self, _mod("decompile", "analyze"), cb, p)

    def audit(self):
        p = self.path.text().strip()
        if not p or not os.path.exists(p):
            QMessageBox.warning(self, "路径无效", "请选择存在的文件")
            return
        _set_status(self.status, "AI 语义审计中…", "run")
        self.tabs.setCurrentIndex(2)

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "审计失败: %s" % r["error"], "err")
                self.ai_out.setPlainText("错误: %s" % r["error"])
            else:
                _set_status(self.status, "审计完成", "ok")
                self.ai_out.setPlainText(json_dump(r))
        _run_async(self, _mod("decompile", "ai_audit"), cb, p)


class WatcherPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("APP 集中观察", "M7 · WATCHER"))

        c = _card("目标管理")
        self.name = QLineEdit(); self.name.setPlaceholderText("目标名")
        self.exe = QLineEdit(); self.exe.setPlaceholderText("exe 路径（可选）")
        c.layout().addLayout(_form_row(("目标名", self.name), ("exe", self.exe)))
        # 操作分两组：①添加+控制 ②维护
        c.layout().addLayout(_toolbar(
            _btn("添加目标", self.add, primary=True),
            _btn("启动观察", self._start),
            _btn("停止观察", self._stop),
        ))
        c.layout().addLayout(_toolbar(
            _btn("删除目标", self.remove),
            _btn("刷新时间线", self.timeline),
            _btn("查看状态", self._status),
            _btn("目标快照", self._snapshot),
        ))
        self.status = _status_label("就绪", "info")
        c.layout().addWidget(self.status)
        c.layout().addWidget(_hint("删除目标前请先停止观察；时间线包含已注册的事件（最近 ≤500 条）。"))
        lay.addWidget(c)

        self.table = QTableWidget()
        lay.addWidget(self.table, 1)

    def _start(self):
        _set_status(self.status, "正在启动观察…", "run")
        def cb(r):
            # watcher.start() 返回纯 bool（非 tuple），必须用 bool(r) 判断，
            # 否则 bool 永远不满足 isinstance(tuple/list) → 假"启动失败"。
            if bool(r):
                _set_status(self.status, "观察已启动", "ok")
            else:
                _set_status(self.status, "启动失败: %s" % r, "err")
        _run_async(self, _mod("watcher", "start"), cb)

    def _stop(self):
        _set_status(self.status, "正在停止观察…", "run")
        def cb(r):
            _set_status(self.status, "已停止", "info")
        _run_async(self, _mod("watcher", "stop"), cb)

    def _status(self):
        def cb(r):
            _set_status(self.status, "状态: %s" % json_dump(r)[:200], "ok")
        _run_async(self, _mod("watcher", "status"), cb)

    def _snapshot(self):
        target = self.name.text().strip()

        def cb(r):
            if r is None:
                _set_status(self.status, "快照失败: %s（无此目标或未登记）" % target, "err")
            else:
                _set_status(self.status, "快照完成: %s" % json_dump(r)[:200], "ok")
        _run_async(self, _mod("watcher", "snapshot_target"), cb, target or None)

    def add(self):
        def cb(r):
            ok = bool(isinstance(r, (tuple, list)) and r[0])
            if ok:
                self.timeline()
            else:
                QMessageBox.warning(self, "添加目标失败", str(r))
        _run_async(self, _mod("watcher", "add_target"), cb,
                   self.name.text().strip(), None, self.exe.text().strip() or None)

    def remove(self):
        target = self.name.text().strip()
        if not target:
            QMessageBox.warning(self, "提示", "请输入要删除的目标名")
            return
        if QMessageBox.question(self, "删除目标",
                "确认删除观察目标 %s？" % target) != QMessageBox.StandardButton.Yes:
            return
        def cb(r):
            if bool(r):
                _set_status(self.status, "已删除目标: %s" % target, "ok")
                self.timeline()
            else:
                _set_status(self.status, "删除目标失败: %s" % target, "err")
        _run_async(self, _mod("watcher", "remove_target"), cb, target)

    def timeline(self):
        def cb(rows):
            _fill_table(self.table, rows, 500) or self._err(rows)
        _run_async(self, _mod("watcher", "timeline_entries"), cb, 500)

    def _err(self, rows):
        self.table.setRowCount(1)
        self.table.setColumnCount(1)
        self.table.setHorizontalHeaderLabels(["info"])
        self.table.setItem(0, 0, QTableWidgetItem(str(rows)[:2000]))


class TrackingPage(QWidget):
    """Persistent task UI backed by the same tracking facade as the HTML console.
    布局：三栏 —— 创建任务 / 任务列表（含操作工具栏）/ 详情面板（事件/运行/审计/AI）
    """
    def __init__(self, window):
        super().__init__()
        self._w = window
        self._loaded = False
        self._tasks = []
        outer = QVBoxLayout(self); outer.setContentsMargins(20, 20, 20, 20); outer.setSpacing(12)
        outer.addLayout(_page_header("软件追踪任务", "DAEMON · TASKS"))

        # ---- 全局状态栏 ----
        status_row = QHBoxLayout()
        self.status = _status_label("正在连接后台守护进程…", "run")
        status_row.addWidget(self.status, 1)
        self.btn_refresh = _btn("刷新", self.refresh)
        self.btn_verify = _btn("验证审计链", self.verify_audit)
        self.btn_audit_log = _btn("审计日志", self.show_audit)
        status_row.addWidget(self.btn_refresh)
        status_row.addWidget(self.btn_verify)
        status_row.addWidget(self.btn_audit_log)
        outer.addLayout(status_row)

        # ---- 创建任务卡 ----
        create = _card("创建任务")
        self.name = QLineEdit(); self.name.setPlaceholderText("任务名（必填）")
        self.exe = QLineEdit(); self.exe.setPlaceholderText("可执行文件完整路径")
        self.process = QLineEdit(); self.process.setPlaceholderText("进程名（如 app.exe）")
        self.paths = QLineEdit(); self.paths.setPlaceholderText("补充观察目录（可选）；多个用分号分隔")
        self.interval = QSpinBox(); self.interval.setRange(1, 3600); self.interval.setValue(5)
        self.ai_enabled = QCheckBox("启用 AI 摘要")
        create.layout().addLayout(_form_row(("任务名", self.name), ("进程名", self.process)))
        create.layout().addLayout(_form_row(("可执行文件", self.exe), ("间隔(秒)", self.interval), ("AI 摘要", self.ai_enabled)))
        create.layout().addLayout(_form_row(("观察目录", self.paths)))
        create.layout().addLayout(_toolbar(_btn("创建并启动", self.create, primary=True)))
        create.layout().addWidget(_hint("创建后立即进入运行队列；后台守护进程按 interval_sec 周期性采集。"))
        outer.addWidget(create)

        # ---- 列表 + 详情 分栏（左右两栏，比例 5:7） ----
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        # 左：列表
        left = QWidget(); llay = QVBoxLayout(left); llay.setContentsMargins(0, 0, 0, 0); llay.setSpacing(8)
        self.tasks = QTableWidget()
        self.tasks.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tasks.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tasks.itemSelectionChanged.connect(self.load_events)
        llay.addWidget(self.tasks, 1)
        self.tasks_toolbar = _card("任务操作（请先在表中选中一行）")
        self.btn_start = _btn("启动", self.start_selected)
        self.btn_pause = _btn("暂停", self.pause_selected)
        self.btn_edit = _btn("编辑", self.edit_selected)
        self.btn_delete = _btn("删除", self.delete_selected)
        self.btn_runs = _btn("运行历史", self.show_runs)
        self.tasks_toolbar.layout().addLayout(_toolbar(self.btn_start, self.btn_pause, None))
        self.tasks_toolbar.layout().addLayout(_toolbar(self.btn_edit, self.btn_delete, None))
        self.tasks_toolbar.layout().addLayout(_toolbar(self.btn_runs))
        llay.addWidget(self.tasks_toolbar)
        splitter.addWidget(left)

        # 右：详情 tabs
        right = QWidget(); rlay = QVBoxLayout(right); rlay.setContentsMargins(0, 0, 0, 0); rlay.setSpacing(8)
        self.detail_tabs = QTabWidget()
        # 事件
        self.events = QTableWidget()
        ewrap = QWidget(); elay = QVBoxLayout(ewrap); elay.setContentsMargins(0, 0, 0, 0); elay.setSpacing(6)
        ebar = _toolbar(_btn("刷新事件", self.load_events)); elay.addLayout(ebar)
        elay.addWidget(self.events, 1)
        self.detail_tabs.addTab(ewrap, "事件")
        # 运行历史
        self.runs_table = QTableWidget()
        rwrap = QWidget(); rlay2 = QVBoxLayout(rwrap); rlay2.setContentsMargins(0, 0, 0, 0); rlay2.setSpacing(6)
        rlbar = _toolbar(_btn("加载运行历史", self.show_runs)); rlay2.addLayout(rlbar)
        rlay2.addWidget(self.runs_table, 1)
        self.detail_tabs.addTab(rwrap, "运行历史")
        # 审计
        self.audit_table = QTableWidget()
        awrap = QWidget(); alay = QVBoxLayout(awrap); alay.setContentsMargins(0, 0, 0, 0); alay.setSpacing(6)
        albar = _toolbar(_btn("查看最近审计", lambda: self._show_audit(100)),
                          _btn("验证审计链", self.verify_audit))
        alay.addLayout(albar); alay.addWidget(self.audit_table, 1)
        self.detail_tabs.addTab(awrap, "审计")
        # AI 摘要
        self.ai_out = QPlainTextEdit(); self.ai_out.setReadOnly(True)
        awrap2 = QWidget(); alay2 = QVBoxLayout(awrap2); alay2.setContentsMargins(0, 0, 0, 0); alay2.setSpacing(6)
        ai_btn = _btn("生成 AI 风险摘要", self.analyze, primary=True)
        ai_clear = _btn("清空", lambda: self.ai_out.clear())
        alay2.addLayout(_toolbar(ai_btn, ai_clear)); alay2.addWidget(self.ai_out, 1)
        self.detail_tabs.addTab(awrap2, "AI 摘要")
        rlay.addWidget(self.detail_tabs, 1)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 5); splitter.setStretchFactor(1, 7)

        outer.addWidget(splitter, 1)

    def showEvent(self, event):
        super().showEvent(event)
        if not self._loaded:
            self._loaded = True
            self.refresh()

    def _selected(self):
        row = self.tasks.currentRow()
        return self._tasks[row] if 0 <= row < len(self._tasks) else None

    def create(self):
        if not self.name.text().strip():
            QMessageBox.information(self, "任务名必填", "请填写任务名后创建")
            return
        payload = dict(name=self.name.text().strip(), exe_path=self.exe.text().strip(),
                       process_name=self.process.text().strip(),
                       watch_paths=[p.strip() for p in self.paths.text().split(";") if p.strip()],
                       interval_sec=self.interval.value(), ai_enabled=self.ai_enabled.isChecked(),
                       auto_start=True)
        _set_status(self.status, "正在创建任务…", "run")
        def cb(result):
            if isinstance(result, dict) and result.get("id"):
                self.name.clear(); self.refresh()
                _set_status(self.status, "任务创建成功（已自动启动）", "ok")
            else:
                _set_status(self.status, "创建失败: %s" % result, "err")
        _run_async(self, _mod("tracking", "create_task"), cb, **payload)

    def refresh(self):
        def cb(result):
            if not isinstance(result, (tuple, list)) or len(result) < 3:
                _set_status(self.status, "加载失败：%s" % str(result)[:200], "err")
                return
            tasks, daemon, caps = result
            if not isinstance(daemon, dict) or not isinstance(caps, dict):
                _set_status(self.status, "加载失败：守护状态异常", "err")
                return
            self._tasks = tasks if isinstance(tasks, list) else []
            _fill_table(self.tasks, [{"id": t.get("id"), "name": t.get("name"),
                                      "target": t.get("process_name") or t.get("exe_path") or t.get("pid"),
                                      "status": t.get("status"), "enabled": t.get("enabled"),
                                      "last_run_at": t.get("last_run_at"),
                                      "last_error": t.get("last_error")} for t in self._tasks])
            note = ""
            if not caps.get("exact_registry_read"):
                note = "；注册表读取需 Security 4663 + Audit Registry/SACL"
            _set_status(self.status,
                        "守护进程%s · %d 个任务持续监控 · %s%s" % (
                            "在线" if daemon.get("running") else "离线",
                            daemon.get("enabled_tasks", 0),
                            caps.get("summary", ""), note),
                        "ok" if daemon.get("running") else "err")
        def load():
            from modules import tracking
            return tracking.list_tasks(), tracking.daemon_status(), tracking.capabilities()
        _run_async(self, load, cb)

    def start_selected(self):
        task = self._selected()
        if task:
            _set_status(self.status, "正在启动任务 #%d…" % task["id"], "run")
            _run_async(self, _mod("tracking", "start_task"), lambda r: self.refresh(), task["id"])

    def pause_selected(self):
        task = self._selected()
        if task:
            _set_status(self.status, "正在暂停任务 #%d…" % task["id"], "run")
            _run_async(self, _mod("tracking", "pause_task"), lambda r: self.refresh(), task["id"])

    def load_events(self):
        task = self._selected()
        if not task:
            return
        def cb(rows):
            compact = [{"time": r.get("last_seen") or r.get("ts"), "type": r.get("type"),
                        "operation": (r.get("data") or {}).get("operation") or
                                     (r.get("data") or {}).get("action", ""),
                        "target": (r.get("data") or {}).get("key") or
                                  (r.get("data") or {}).get("path") or
                                  (r.get("data") or {}).get("query", ""),
                        "app": (r.get("data") or {}).get("image") or
                               (r.get("data") or {}).get("process", ""),
                        "pid": (r.get("data") or {}).get("pid", ""),
                        "confidence": (r.get("data") or {}).get("confidence", "unknown"),
                        "provider": (r.get("data") or {}).get("provider", r.get("source")),
                        "severity": r.get("severity"), "count": r.get("count"),
                        "detail": r.get("detail")} for r in rows]
            _fill_table(self.events, compact)
        _run_async(self, _mod("tracking", "task_events"), cb, task["id"], 300)

    def analyze(self):
        task = self._selected()
        if not task:
            QMessageBox.information(self, "未选择任务", "请先选择一个任务")
            return
        self.detail_tabs.setCurrentIndex(3)  # 切到 AI 摘要 tab
        _set_status(self.status, "AI 正在读取受限任务快照…", "run")
        def cb(result):
            if isinstance(result, dict) and result.get("text"):
                self.ai_out.setPlainText(result["text"])
                _set_status(self.status, "AI 摘要完成，工具调用已审计", "ok")
            else:
                _set_status(self.status, "AI 分析失败: %s" % result, "err")
        _run_async(self, _mod("tracking", "analyze_task"), cb, task["id"])

    def verify_audit(self):
        def cb(result):
            if isinstance(result, dict) and result.get("ok"):
                legacy = result.get("legacy_unchained", 0)
                suffix = "；%s 条升级前日志未纳入链" % legacy if legacy else ""
                _set_status(self.status, "审计链完整：已验证 %s 条%s" %
                            (result.get("checked", 0), suffix),
                            "ok" if result.get("complete") else "info")
            else:
                _set_status(self.status, "审计链异常: %s" % result, "err")
        _run_async(self, _mod("tracking", "audit_verify"), cb)

    def edit_selected(self):
        task = self._selected()
        if not task:
            QMessageBox.information(self, "未选择任务", "请先选择一个任务")
            return
        dlg = _TaskEditDialog(self, task)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        v = dlg.values()
        if not v["name"]:
            QMessageBox.information(self, "任务名必填", "任务名不能为空")
            return
        _set_status(self.status, "正在保存修改…", "run")
        def cb(result):
            if isinstance(result, dict) and result.get("id"):
                self.refresh()
                _set_status(self.status, "任务已更新", "ok")
            else:
                _set_status(self.status, "更新失败: %s" % result, "err")
        _run_async(self, _mod("tracking", "update_task"), cb, task["id"], **v)

    def delete_selected(self):
        task = self._selected()
        if not task:
            QMessageBox.information(self, "未选择任务", "请先选择一个任务")
            return
        if QMessageBox.question(self, "删除任务",
                "确认删除任务 %s？其事件与运行历史将一并删除。" % task.get("name", "")) \
                != QMessageBox.StandardButton.Yes:
            return
        _set_status(self.status, "正在删除任务…", "run")
        def cb(result):
            if isinstance(result, dict) and result.get("ok"):
                self.refresh()
                _set_status(self.status, "任务已删除", "ok")
            else:
                _set_status(self.status, "删除失败: %s" % result, "err")
        _run_async(self, _mod("tracking", "delete_task"), cb, task["id"])

    def show_runs(self):
        task = self._selected()
        if not task:
            QMessageBox.information(self, "未选择任务", "请先选择一个任务")
            return
        self.detail_tabs.setCurrentIndex(1)  # 切到运行历史
        def cb(rows):
            if not isinstance(rows, list):
                _set_status(self.status, "运行历史加载失败: %s" % rows, "err")
                return
            compact = [{"id": r.get("id"), "started_at": r.get("started_at"),
                        "finished_at": r.get("finished_at"), "outcome": r.get("outcome"),
                        "event_count": r.get("event_count"), "error": r.get("error")}
                       for r in rows]
            _fill_table(self.runs_table, compact, 100)
            _set_status(self.status, "已加载运行历史 %d 条" % len(compact), "ok")
        _run_async(self, _mod("tracking", "task_runs"), cb, task["id"], 100)

    def _show_audit(self, limit):
        self.detail_tabs.setCurrentIndex(2)  # 切到审计 tab
        def cb(rows):
            if not isinstance(rows, list):
                _set_status(self.status, "审计日志加载失败: %s" % rows, "err")
                return
            compact = [{"id": r.get("id"), "ts": r.get("ts"), "op": r.get("op"),
                        "actor": r.get("actor"), "resource": r.get("resource"),
                        "outcome": r.get("outcome"), "risk": r.get("risk")} for r in rows]
            _fill_table(self.audit_table, compact, 100)
            _set_status(self.status, "已加载审计 %d 条" % len(compact), "ok")
        _run_async(self, _mod("tracking", "audit_entries"), cb, limit)

    def show_audit(self):
        # 顶部按钮：直接打开 audit tab 看全局最近审计
        self._show_audit(100)
        self.detail_tabs.setCurrentIndex(2)


class PrivacyGuardPage(QWidget):
    """Human approval surface for isolation and recoverable privacy actions."""
    def __init__(self, window):
        super().__init__()
        self._w = window
        self._loaded = False
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 20); lay.setSpacing(12)
        lay.addLayout(_page_header("隐私保护", "PRIVACY GUARD"))
        self.status = _status_label("系统操作须显示明确原因并由用户批准", "info")
        lay.addWidget(self.status)

        # 全局原因（所有系统操作都要读，所以放最上面）
        self.reason = QLineEdit()
        self.reason.setPlaceholderText("明确原因（至少 12 字：目的、对象、必要性）")
        lay.addLayout(_form_row(("统一原因", self.reason)))

        # 四区栅格化（左右两列）
        split = QSplitter(Qt.Orientation.Horizontal); split.setChildrenCollapsible(False)

        # ---- 左：强隔离 + 注册表登记 ----
        left = QWidget(); llay = QVBoxLayout(left); llay.setContentsMargins(0, 0, 0, 0); llay.setSpacing(12)

        iso = _card("① 强隔离运行（无 guest 内部遥测）")
        iso.layout().addWidget(_hint("禁用 vGPU；专用 staging 副本只读映射。宿主时间线看不到沙箱内部注册表/DNS/文件访问。"))
        self.exe = QLineEdit(); self.exe.setPlaceholderText("EXE 完整路径")
        self.net = QCheckBox("允许联网"); self.clip = QCheckBox("允许剪贴板")
        iso.layout().addLayout(_form_row(("EXE", self.exe)))
        iso.layout().addLayout(_toolbar(self.net, self.clip, None))
        iso.layout().addLayout(_toolbar(_btn("预览 WSB", self.preview_sandbox),
                                         _btn("审查并启动", self.launch_sandbox, primary=True)))
        llay.addWidget(iso)

        reg = _card("② APP 注册表关联（仅已登记 HKCU 厂商/产品子树）")
        self.task_id = QSpinBox(); self.task_id.setRange(1, 2_000_000_000)
        self.subkey = QLineEdit(); self.subkey.setPlaceholderText("Software\\厂商\\产品")
        self.value_name = QLineEdit(); self.value_name.setPlaceholderText("精确值名")
        self.new_value = QLineEdit(); self.new_value.setPlaceholderText("新 REG_SZ 值")
        self.publisher = QLineEdit(); self.publisher.setPlaceholderText("签名发布者/厂商（记录用）")
        self.owner_note = QLineEdit(); self.owner_note.setPlaceholderText("所有权证据与安全修改说明（≥12字）")
        reg.layout().addLayout(_form_row(("任务 ID", self.task_id), ("厂商/产品子树", self.subkey)))
        reg.layout().addLayout(_form_row(("值名", self.value_name), ("新值", self.new_value)))
        reg.layout().addLayout(_form_row(("发布者", self.publisher), ("所有权说明", self.owner_note)))
        reg.layout().addLayout(_toolbar(_btn("查看依赖", self.report),
                                          _btn("登记子树", self.register_scope),
                                          _btn("撤销登记", self.remove_scope),
                                          None,
                                          _btn("审查设置值", self.set_registry, primary=True),
                                          _btn("审查删除值", self.delete_registry)))
        reg.layout().addWidget(_hint("系统身份范围（HKLM/MachineGuid/网卡）确定性拒绝；HKCU 须先登记再修改。"))
        llay.addWidget(reg)
        llay.addStretch(1)
        split.addWidget(left)

        # ---- 右：浏览 + 系统执行回显 + 输出区 ----
        right = QWidget(); rlay = QVBoxLayout(right); rlay.setContentsMargins(0, 0, 0, 0); rlay.setSpacing(12)

        web = _card("③ Canvas API 缓解 / Windows WLAN 隐私")
        self.site = QLineEdit(); self.site.setPlaceholderText("https://example.com")
        web.layout().addWidget(_hint("Canvas 默认关闭且按顶级站点启用；仅尽力在文档早期缓解 2D Canvas，不能保证阻止最早脚本。MAC 仅打开 Windows 官方 Wi-Fi 设置。"))
        web.layout().addLayout(_form_row(("目标站点", self.site)))
        web.layout().addLayout(_toolbar(_btn("启用 Canvas", lambda: self.canvas(True)),
                                          _btn("停用 Canvas", lambda: self.canvas(False)),
                                          None,
                                          _btn("WLAN 能力", self.mac_status),
                                          _btn("审查后打开设置", self.open_wifi, primary=True)))
        rlay.addWidget(web)

        # 系统执行回显
        echo = _card("④ 系统操作结果（最近一次计划/批准/执行回显）")
        self.out = QPlainTextEdit(); self.out.setReadOnly(True)
        echo.layout().addLayout(_toolbar(
            _btn("刷新能力", self._caps),
            _btn("查看保护规则", self._rules),
            _btn("查看已登记 HKCU 范围", self._scopes),
        ))
        echo.layout().addWidget(self.out, 1)
        rlay.addWidget(echo, 1)

        split.addWidget(right)
        split.setStretchFactor(0, 5); split.setStretchFactor(1, 5)
        lay.addWidget(split, 1)

    def showEvent(self, event):
        super().showEvent(event)
        if not self._loaded:
            self._loaded = True
            self._caps()

    def _caps(self):
        _run_async(self, _mod("privacy_guard", "capabilities"), self._show)
    def _rules(self):
        def cb(r):
            if isinstance(r, list):
                _set_status(self.status, "保护规则 %d 条" % len(r), "ok")
            else:
                _set_status(self.status, "已加载保护规则", "ok")
            self._show(r)
        _run_async(self, _mod("privacy_guard", "protected_rules"), cb)
    def _scopes(self):
        def cb(r):
            if isinstance(r, list):
                _set_status(self.status, "已登记范围 %d 项" % len(r), "ok")
            else:
                _set_status(self.status, "已加载范围", "ok")
            self._show(r)
        _run_async(self, _mod("privacy_guard", "registry_scopes"), cb)

    def _show(self, value):
        self.out.setPlainText(json_dump(value))

    def _reason(self):
        text = self.reason.text().strip()
        if len(text) < 12:
            QMessageBox.warning(self, "原因不足", "请写明至少 12 字的目的、对象和必要性")
            return ""
        return text

    def _system_action(self, action, args):
        reason = self._reason()
        if not reason: return
        def planned(plan):
            if not isinstance(plan, dict) or not plan.get("token"):
                self._show(plan); return
            text = "操作：%s\n\n参数：%s\n\n原因：%s\n\n步骤：\n- %s" % (
                plan["action"], json_dump(plan.get("args", {})), plan["reason"],
                "\n- ".join(plan.get("steps", [])))
            if QMessageBox.question(self, "审查系统操作预案", text) != QMessageBox.StandardButton.Yes:
                _set_status(self.status, "用户取消，未执行", "info"); return
            def approved(cap):
                if not isinstance(cap, dict) or not cap.get("approval_token"):
                    self._show(cap); return
                _run_async(self, _mod("privacy_guard", "execute_system_action"), self._show,
                           cap["approval_token"], reason)
            _run_async(self, _mod("privacy_guard", "approve_system_action"), approved,
                       plan["token"], "我已审查并批准", reason, "pyqt_dialog")
        _run_async(self, _mod("privacy_guard", "plan_system_action"), planned,
                   action, args, reason)

    def preview_sandbox(self):
        _run_async(self, _mod("privacy_guard", "sandbox_preview"), self._show,
                   self.exe.text().strip(), self.net.isChecked(), self.clip.isChecked(), 4096)

    def launch_sandbox(self):
        self._system_action("launch_sandbox", {"exe_path": self.exe.text().strip(),
                            "network": self.net.isChecked(), "clipboard": self.clip.isChecked(),
                            "memory_mb": 4096})

    def report(self):
        _run_async(self, _mod("privacy_guard", "task_report"), self._show, self.task_id.value())

    def register_scope(self):
        reason = self._reason()
        if not reason: return
        if QMessageBox.question(self, "登记精确范围",
                "只登记范围，不写注册表。确认该子树属于目标 APP？") != QMessageBox.StandardButton.Yes:
            return
        _run_async(self, _mod("privacy_guard", "register_registry_scope"), self._show,
                   self.task_id.value(), "HKCU", self.subkey.text().strip(), self.publisher.text().strip(),
                   self.owner_note.text().strip(), reason, "我已审查并批准")

    def remove_scope(self):
        reason = self._reason()
        if not reason: return
        subkey = self.subkey.text().strip()
        if not subkey:
            QMessageBox.warning(self, "提示", "请输入要撤销的子树（Software\\厂商\\产品）")
            return
        if QMessageBox.question(self, "撤销授权范围",
                "确认撤销任务 %d 的登记范围 %s？撤销后该子树将不再允许修改。" % (
                    self.task_id.value(), subkey)) != QMessageBox.StandardButton.Yes:
            return
        _run_async(self, _mod("privacy_guard", "remove_registry_scope"), self._show,
                   self.task_id.value(), subkey, reason, "我已审查并批准")

    def set_registry(self):
        if not self.subkey.text().strip() or not self.value_name.text().strip():
            QMessageBox.warning(self, "参数缺失", "请填写 HKCU\\子键 与 值名 后再修改")
            return
        self._system_action("registry_set_string", {"task_id":self.task_id.value(), "root":"HKCU",
                            "subkey":self.subkey.text().strip(), "value_name":self.value_name.text(),
                            "new_value":self.new_value.text()})

    def delete_registry(self):
        if not self.subkey.text().strip() or not self.value_name.text().strip():
            QMessageBox.warning(self, "参数缺失", "请填写 HKCU\\子键 与 值名 后再删除")
            return
        self._system_action("registry_delete_value", {"task_id":self.task_id.value(), "root":"HKCU",
                            "subkey":self.subkey.text().strip(), "value_name":self.value_name.text()})

    def canvas(self, enabled):
        reason = self._reason()
        if reason:
            _run_async(self, _mod("privacy_guard", "set_canvas_guard"), self._show,
                       self.site.text().strip(), enabled, reason)

    def mac_status(self):
        _run_async(self, _mod("privacy_guard", "mac_randomization_status"), self._show)

    def open_wifi(self):
        self._system_action("open_wifi_privacy_settings", {})


class BrowserPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("浏览器控制", "M4 · BROWSER"))
        self.status = _status_label("未连接", "info")
        lay.addWidget(self.status)

        # ---- 列表能力 ----
        c1 = _card("① 列表（状态 / 标签页 / DOM 事件 / 隐私告警）")
        self.tabs = QTableWidget()
        c1.layout().addWidget(self.tabs, 1)
        c1.layout().addLayout(_toolbar(
            _btn("刷新状态", self.refresh_status),
            _btn("查看标签页", self.refresh_tabs),
            _btn("查看 DOM 事件", self.refresh_dom),
            _btn("查看隐私告警", self.refresh_privacy),
        ))
        lay.addWidget(c1, 1)

        # ---- 操作能力 ----
        c2 = _card("② 操作（向已连扩展发送命令）")
        self.cmd = QLineEdit(); self.cmd.setPlaceholderText("命令（list_tabs / snapshot / ping）")
        self.tabid = QLineEdit(); self.tabid.setPlaceholderText("标签页 ID（activate 用）")
        c2.layout().addLayout(_form_row(("命令", self.cmd), ("标签页 ID", self.tabid)))
        c2.layout().addLayout(_toolbar(
            _btn("发送", self._send, primary=True),
            _btn("激活标签", self._activate),
            _btn("DOM 观察开", self._observe_on),
            _btn("DOM 观察关", self._observe_off),
            _btn("查看中枢状态", self.refresh_status),
        ))
        c2.layout().addWidget(_hint("activate/observe_dom 需带参数，用上方专用按钮；canvas_guard 请在隐私保护页按站点操作。"))
        lay.addWidget(c2)

        self._loaded = False

    def showEvent(self, ev):
        super().showEvent(ev)
        if not self._loaded:
            self._loaded = True
            self.refresh_status()

    def _set_status_from(self, r, ok_label="完成"):
        if isinstance(r, dict) and r.get("error"):
            _set_status(self.status, "错误: %s" % r["error"], "err")
        else:
            _set_status(self.status, ok_label, "ok")

    def refresh_status(self):
        def cb(r):
            self._set_status_from(r, "已连接" if (isinstance(r, dict) and r.get("connected"))
                                  else "扩展未连接")
        _run_async(self, _mod("browser", "status"), cb)

    def refresh_tabs(self):
        def cb(rows):
            _fill_table(self.tabs, rows or [], 200)
            _set_status(self.status, "标签页: %d 条" % (len(rows) if isinstance(rows, list) else 0), "ok")
        _run_async(self, _mod("browser", "list_tabs"), cb)

    def refresh_dom(self):
        def cb(r):
            _fill_table(self.tabs, r if isinstance(r, list) else [], 200)
            _set_status(self.status, "DOM 事件: %d 条" % (
                len(r) if isinstance(r, list) else 0), "ok")
        _run_async(self, _mod("browser", "dom_events"), cb)

    def refresh_privacy(self):
        def cb(r):
            _fill_table(self.tabs, r if isinstance(r, list) else [], 200)
            _set_status(self.status, "隐私告警: %d 条" % (
                len(r) if isinstance(r, list) else 0), "ok")
        _run_async(self, _mod("browser", "privacy_events"), cb)

    def _send(self):
        cmd = self.cmd.text().strip() or "list_tabs"
        if cmd not in ("list_tabs", "snapshot", "ping"):
            _set_status(self.status, "仅支持 list_tabs/snapshot/ping（带参数命令请用专用按钮）", "err")
            return
        _set_status(self.status, "发送中: %s" % cmd, "run")
        def cb(r):
            # send_command 返回已投递的扩展连接数（int）：0 表示没有扩展在线
            if isinstance(r, int):
                if r > 0:
                    _set_status(self.status, "已发送 %s（%d 个扩展连接收到）" % (cmd, r), "ok")
                else:
                    _set_status(self.status, "发送失败: 无扩展连接在线（命令未投递）", "err")
            elif isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "错误: %s" % r["error"], "err")
            else:
                _set_status(self.status, "已发送 %s" % cmd, "ok")
        _run_async(self, _mod("browser", "send_command"), cb, cmd)

    def _activate(self):
        raw = self.tabid.text().strip()
        if not raw.isdigit():
            _set_status(self.status, "请填写数字标签页 ID", "err")
            return
        _set_status(self.status, "激活标签中…", "run")
        def cb(r):
            if isinstance(r, int):
                _set_status(self.status,
                            "已发送 activate（%d 个扩展连接收到）" % r if r > 0
                            else "发送失败: 无扩展连接在线", "ok" if r > 0 else "err")
            elif isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "错误: %s" % r["error"], "err")
            else:
                _set_status(self.status, "已发送 activate", "ok")
        _run_async(self, _mod("browser", "send_command"), cb, "activate", tabId=int(raw))

    def _observe(self, enabled):
        _set_status(self.status, "切换 DOM 观察中…", "run")
        def cb(r):
            if isinstance(r, int):
                _set_status(self.status,
                            "已发送 observe_dom=%s（%d 个扩展连接收到）" % (enabled, r)
                            if r > 0 else "发送失败: 无扩展连接在线",
                            "ok" if r > 0 else "err")
            elif isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "错误: %s" % r["error"], "err")
            else:
                _set_status(self.status, "已发送 observe_dom=%s" % enabled, "ok")
        _run_async(self, _mod("browser", "send_command"), cb, "observe_dom", enabled=enabled)

    def _observe_on(self):
        self._observe(True)

    def _observe_off(self):
        self._observe(False)

class AiPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("大模型集成", "M8 · AI"))
        self.status = _status_label("未检测", "info")
        lay.addWidget(self.status)

        # ---- 上下问答 ----
        c1 = _card("① 问答（带上下文）")
        self.q = QLineEdit(); self.q.setPlaceholderText("向大模型提问（自动叠加只读顾问边界）")
        self.q.returnPressed.connect(self.ask)
        self.answer = QPlainTextEdit(); self.answer.setReadOnly(True)
        c1.layout().addLayout(_form_row(("问题", self.q)))
        c1.layout().addLayout(_toolbar(
            _btn("提问", self.ask, primary=True),
            _btn("清空", lambda: self.answer.clear()),
        ))
        c1.layout().addWidget(self.answer)
        lay.addWidget(c1, 1)

        # ---- 分析/摘要/规则 ----
        c2 = _card("② 单项能力")
        self.in_text = QPlainTextEdit(); self.in_text.setPlaceholderText(
            "在此粘贴要分析/摘要/提炼规则的内容（analyze 也可用 findings 列表 / summarize 也可粘贴已建好的观察）。")
        self.in_text.setMaximumHeight(120)
        c2.layout().addWidget(self.in_text)
        c2.layout().addLayout(_toolbar(
            _btn("AI 风险分析", self._analyze),
            _btn("AI 摘要", self._summarize),
            _btn("AI 规则提炼", self._extract_rules),
            _btn("直连对话(chat)", self._chat),
        ))
        self.out_text = QPlainTextEdit(); self.out_text.setReadOnly(True)
        self.out_text.setMaximumHeight(160)
        c2.layout().addWidget(self.out_text)
        c2.layout().addWidget(_hint("将选中的列表/CSV 文本粘贴进文本框；AI 会按 SAFETY_SYS 安全边界返回结构化文本。"))
        lay.addWidget(c2, 1)
        self._loaded = False

    def showEvent(self, ev):
        super().showEvent(ev)
        if not self._loaded:
            self._loaded = True
            self.refresh()

    def refresh(self):
        def cb(cfg):
            _set_status(self.status, "AI 状态: %s" % (
                "已配置" if cfg else "未配置（请在设置或 config.json 填 base_url/api_key/model）"),
                "ok" if cfg else "err")
        _run_async(self, _mod("ai", "configured"), cb)

    def ask(self):
        q = self.q.text().strip()
        if not q:
            return
        _set_status(self.status, "向 AI 提问中…", "run")
        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "错误: %s" % r["error"], "err")
                self.answer.setPlainText("错误: %s" % r["error"])
            else:
                _set_status(self.status, "完成", "ok")
                self.answer.setPlainText(str(r))
        _run_async(self, _mod("ai", "answer"), cb, q, "ReTrace 漏洞分析助手")

    def _analyze(self):
        text = self.in_text.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "提示", "请粘贴待分析的文本")
            return
        _set_status(self.status, "AI 风险分析中…", "run")
        def cb(r):
            if isinstance(r, dict) and (r.get("error") or r.get("ok") is False):
                _set_status(self.status, "分析失败: %s" % r.get("error", "未知错误"), "err")
                self.out_text.setPlainText(json_dump(r))
            else:
                _set_status(self.status, "完成", "ok")
                self.out_text.setPlainText(json_dump(r))
        _run_async(self, _mod("ai", "analyze"), cb, text)

    def _summarize(self):
        text = self.in_text.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "提示", "请粘贴观察文本")
            return
        _set_status(self.status, "AI 摘要生成中…", "run")
        def cb(r):
            if isinstance(r, dict) and (r.get("error") or r.get("ok") is False):
                _set_status(self.status, "摘要失败: %s" % r.get("error", "未知错误"), "err")
                self.out_text.setPlainText(json_dump(r))
            else:
                _set_status(self.status, "完成", "ok")
                self.out_text.setPlainText(json_dump(r))
        _run_async(self, _mod("ai", "summarize"), cb, text)

    def _extract_rules(self):
        text = self.in_text.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "提示", "请粘贴观察列表（每行一条）")
            return
        obs = [line for line in text.splitlines() if line.strip()]
        _set_status(self.status, "AI 提炼规则中…", "run")
        def cb(r):
            if isinstance(r, dict) and (r.get("error") or r.get("ok") is False):
                _set_status(self.status, "提炼失败: %s" % r.get("error", "未知错误"), "err")
                self.out_text.setPlainText(json_dump(r))
            else:
                _set_status(self.status, "完成", "ok")
                self.out_text.setPlainText(json_dump(r))
        _run_async(self, _mod("ai", "extract_rules"), cb, obs)

    def _chat(self):
        """直连对话：按空行切片自动分配 user/assistant 角色（与 Web vAi 一致）。"""
        text = self.in_text.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "提示", "请粘贴对话内容（空行分隔的段落，user/assistant 交替）")
            return
        parts = [p.strip() for p in text.split("\n\n") if p.strip()]
        messages = [{"role": "user" if i % 2 == 0 else "assistant", "content": p}
                    for i, p in enumerate(parts)]
        _set_status(self.status, "直连对话中…", "run")
        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "错误: %s" % r["error"], "err")
                self.out_text.setPlainText("错误: %s" % r["error"])
            else:
                _set_status(self.status, "完成", "ok")
                self.out_text.setPlainText(json_dump(r))
        _run_async(self, _mod("ai", "chat"), cb, messages)


class EvolvePage(QWidget):
    """M5 自我进化：规则挖掘 / 权重调整 / 进化报告（与 Web vEvolve 走同一 facade）。"""

    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("自我进化", "M5 · EVOLVE"))
        self.status = _status_label("就绪", "info")
        lay.addWidget(self.status)

        c = _card("① 进化操作")
        c.layout().addLayout(_toolbar(
            _btn("挖掘候选规则", lambda: self._run("evolve", "mine_rules", (), "挖掘完成"),
                 primary=True),
            _btn("挖掘并确认写入", self._mine_apply),
            _btn("调整观察权重", lambda: self._run("evolve", "adjust_weights", (False,), "已统计（候选未落库）")),
            _btn("调整并确认应用", self._adjust_apply),
            _btn("查看进化报告", lambda: self._run("evolve", "report", (), "报告已生成")),
        ))
        c.layout().addWidget(_hint("默认 auto_apply=false；「确认」类按钮是显式人工确认入口（全程审计）。"))
        lay.addWidget(c)

        c2 = _card("② 结果")
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        c2.layout().addWidget(self.out)
        lay.addWidget(c2, 1)

    def _run(self, module, fn, args, ok_msg):
        _set_status(self.status, "执行中…", "run")

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "错误: %s" % r["error"], "err")
            else:
                _set_status(self.status, ok_msg, "ok")
            self.out.setPlainText(json_dump(r))

        _run_async(self, _mod(module, fn), cb, *args)

    def _mine_apply(self):
        if QMessageBox.question(self, "确认写入",
                "确认把候选规则直接写入经验库（mine_rules auto_apply=true）？") \
                != QMessageBox.StandardButton.Yes:
            return
        self._run("evolve", "mine_rules", (3, 6, True), "已按确认写入")

    def _adjust_apply(self):
        if QMessageBox.question(self, "确认应用",
                "确认把热点类别规则的 risk_weight 上调 0.05 并落库？") \
                != QMessageBox.StandardButton.Yes:
            return
        self._run("evolve", "adjust_weights", (True,), "已按确认应用")


class HuntPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("漏洞主流程", "M9 · HUNT"))
        self.status = _status_label("就绪", "info")
        lay.addWidget(self.status)

        c1 = _card("① 登记目标")
        self.aname = QLineEdit(); self.aname.setPlaceholderText("目标名（如 我的APP）")
        self.apath = QLineEdit(); self.apath.setPlaceholderText("可执行文件路径")
        c1.layout().addLayout(_form_row(("目标名", self.aname), ("路径", self.apath)))
        c1.layout().addLayout(_toolbar(_btn("登记目标", self.add_agent, primary=True)))
        lay.addWidget(c1)

        c2 = _card("② 开始观察")
        self.agents = QComboBox()
        self.title = QLineEdit(); self.title.setPlaceholderText("观察标题（默认 Web 集中观察）")
        c2.layout().addLayout(_form_row(("选择目标", self.agents), ("标题", self.title)))
        c2.layout().addLayout(_toolbar(
            _btn("开始观察", self.start, primary=True),
            _btn("刷新列表", self.refresh),
            _btn("加载最近观察", self._recent_only),
        ))
        lay.addWidget(c2)

        c3 = _card("③ 最近观察（最近 ≤100 条）")
        self.table = QTableWidget()
        c3.layout().addLayout(_toolbar(
            _btn("刷新", self.refresh),
            _btn("加载最近", self._recent_only),
        ))
        c3.layout().addWidget(self.table, 1)
        lay.addWidget(c3, 1)

        # ---- ④ 观察收尾（收集 → AI 分析 → 标记入库，M9 闭环） ----
        c4 = _card("④ 观察收尾")
        self.obs_id = QLineEdit(); self.obs_id.setPlaceholderText("观察 ID（最近观察列表里的 id）")
        self.m_risk = QComboBox(); self.m_risk.addItems(["低", "中", "高", "无"])
        self.m_category = QLineEdit(); self.m_category.setPlaceholderText("类别（如 自启动）")
        self.m_mark = QLineEdit(); self.m_mark.setPlaceholderText("标记")
        self.m_conclusion = QLineEdit(); self.m_conclusion.setPlaceholderText("结论")
        c4.layout().addLayout(_form_row(("观察 ID", self.obs_id),
                                        ("风险", self.m_risk), ("类别", self.m_category)))
        c4.layout().addLayout(_form_row(("标记", self.m_mark), ("结论", self.m_conclusion)))
        c4.layout().addLayout(_toolbar(
            _btn("收集证据", self._collect, primary=True),
            _btn("AI 分析观察", self._analyze),
            _btn("查看详情", self._detail),
            None,
            _btn("标记完成", self._finish),
        ))
        c4.layout().addWidget(_hint("标记完成会写入 observations 并回流 knowledge/embedding 经验库。"))
        lay.addWidget(c4)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setMaximumHeight(130)
        lay.addWidget(self.out)
        self._loaded = False

    def showEvent(self, ev):
        super().showEvent(ev)
        if not self._loaded:
            self._loaded = True
            self.refresh()

    def refresh(self):
        def cb_agents(rows):
            self.agents.clear()
            if isinstance(rows, list):
                for a in rows:
                    if isinstance(a, dict):
                        self.agents.addItem("%s (%s)" % (a.get("name", "?"), a.get("id", "")), a)
            _set_status(self.status, "已加载 %d 个目标" % (len(rows) if isinstance(rows, list) else 0), "ok")
        _run_async(self, _mod("hunt", "list_agents"), cb_agents)

        def cb_hunts(rows):
            _fill_table(self.table, rows, 100)
        _run_async(self, _mod("hunt", "recent_hunts"), cb_hunts, 100)

    def _recent_only(self):
        _set_status(self.status, "加载最近观察…", "run")
        def cb(rows):
            n = len(rows) if isinstance(rows, list) else 0
            _set_status(self.status, "最近观察: %d 条" % n, "ok")
            _fill_table(self.table, rows if isinstance(rows, list) else [], 100)
        _run_async(self, _mod("hunt", "recent_hunts"), cb, 100)

    def add_agent(self):
        if not self.aname.text().strip():
            QMessageBox.information(self, "目标名必填", "请填写目标名")
            return
        _set_status(self.status, "登记目标中…", "run")
        def cb(r):
            if isinstance(r, dict) and r.get("ok") is False:
                QMessageBox.warning(self, "登记目标失败", str(r))
                _set_status(self.status, "登记失败", "err")
                return
            self.aname.clear(); self.apath.clear()
            self.refresh()
            _set_status(self.status, "已登记", "ok")
        _run_async(self, _mod("hunt", "create_agent"), cb,
                   self.aname.text().strip(), self.apath.text().strip(), "")

    def start(self):
        a = self.agents.currentData()
        if not isinstance(a, dict):
            QMessageBox.warning(self, "无目标", "请先登记目标")
            return
        _set_status(self.status, "开始观察中…", "run")
        def cb(r):
            if isinstance(r, dict) and r.get("ok") is False:
                self.refresh()
                _set_status(self.status, "开始观察失败: %s" % r.get("error", r), "err")
                QMessageBox.warning(self, "开始观察失败", str(r))
                return
            self.refresh()
            _set_status(self.status, "已开始观察 #%s" % (
                r.get("observation_id") if isinstance(r, dict) else ""), "ok")
        _run_async(self, _mod("hunt", "start_hunt"), cb,
                   a.get("id"), self.title.text().strip() or "集中观察", None)

    def _obs_id(self):
        raw = self.obs_id.text().strip()
        if not raw.isdigit() or int(raw) <= 0:
            QMessageBox.warning(self, "观察 ID", "请输入有效的观察 ID（正整数）")
            return None
        return int(raw)

    def _collect(self):
        oid = self._obs_id()
        if oid is None:
            return
        _set_status(self.status, "收集证据中…", "run")
        def cb(r):
            if isinstance(r, dict) and r.get("ok"):
                _set_status(self.status, "已收集 %s 个证据块" % r.get("evidence_blocks", 0), "ok")
            else:
                _set_status(self.status, "收集失败: %s" % r, "err")
            self.out.setPlainText(json_dump(r))
        _run_async(self, _mod("hunt", "collect_evidence"), cb, oid)

    def _analyze(self):
        oid = self._obs_id()
        if oid is None:
            return
        _set_status(self.status, "AI 分析中…", "run")
        def cb(r):
            if isinstance(r, dict) and r.get("ok"):
                _set_status(self.status, "AI 分析完成（已写入 ai_hint）", "ok")
            else:
                _set_status(self.status, "AI 分析失败: %s" % r, "err")
            self.out.setPlainText(json_dump(r))
        _run_async(self, _mod("hunt", "analyze_with_ai"), cb, oid)

    def _detail(self):
        oid = self._obs_id()
        if oid is None:
            return
        def cb(r):
            if r is None:
                _set_status(self.status, "观察 #%s 不存在" % oid, "err")
                self.out.setPlainText("观察不存在")
            else:
                _set_status(self.status, "已加载观察 #%s" % oid, "ok")
                self.out.setPlainText(json_dump(r))
        _run_async(self, _mod("hunt", "get_hunt"), cb, oid)

    def _finish(self):
        oid = self._obs_id()
        if oid is None:
            return
        risk = self.m_risk.currentText()
        category = self.m_category.text().strip() or "其他"
        mark = self.m_mark.text().strip()
        conclusion = self.m_conclusion.text().strip()
        if QMessageBox.question(self, "标记完成",
                "确认把观察 #%s 标记为 %s/%s 并回流经验库？" % (oid, risk, category)) \
                != QMessageBox.StandardButton.Yes:
            return
        _set_status(self.status, "标记入库中…", "run")
        def cb(r):
            if isinstance(r, dict) and r.get("ok"):
                _set_status(self.status, "已标记完成并回流经验", "ok")
            else:
                _set_status(self.status, "标记失败: %s" % r, "err")
            self.out.setPlainText(json_dump(r))
        _run_async(self, _mod("hunt", "finish_observation"), cb,
                   oid, risk, category, mark, conclusion)


class SettingsPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("设置", "CONFIG"))

        # ---- 开机自启 ----
        c1 = _card("系统集成")
        self.auto = QCheckBox("开机自动启动（最小化到托盘）")
        self.auto.setChecked(_autostart_enabled())
        self.auto.toggled.connect(self._toggle_auto)
        c1.layout().addWidget(self.auto)
        lay.addWidget(c1)

        # ---- 模块开关 ----
        c2 = _card("模块开关（保存后重启生效）")
        self.sw_boxes = {}
        grid = QGridLayout()
        grid.setSpacing(8)
        for i, k in enumerate(("pcap", "regscan", "embedding", "decompile",
                               "watcher", "browser", "ai", "evolve",
                               "hunt", "agent", "screener", "tracking",
                               "privacy_guard")):
            cb = QCheckBox(k)
            cb.setChecked(bool(config.enabled(k)))
            self.sw_boxes[k] = cb
            grid.addWidget(cb, i // 3, i % 3)
        c2.layout().addLayout(grid)
        c2.layout().addLayout(_row(_btn("保存模块开关", self.save_switches, primary=True)))
        lay.addWidget(c2)

        # ---- AI 配置 ----
        c3 = _card("大模型配置（AI 辅助分析 / Agent 使用）")
        cfg = config.section("ai", {})
        self.base = QLineEdit(cfg.get("base_url", ""))
        self.base.setPlaceholderText("base_url (如 https://api.deepseek.com/v1)")
        self.key = QLineEdit(cfg.get("api_key", ""))
        self.key.setEchoMode(QLineEdit.EchoMode.Password)
        self.model = QLineEdit(cfg.get("model", ""))
        self.model.setPlaceholderText("model (如 deepseek-chat)")
        c3.layout().addLayout(_row(_label("base_url"), self.base))
        c3.layout().addLayout(_row(_label("api_key"), self.key))
        c3.layout().addLayout(_row(_label("model"), self.model))
        c3.layout().addLayout(_row(_btn("保存 AI 配置", self.save_ai, primary=True)))
        lay.addWidget(c3)

        # ---- 数据库 ----
        c4 = _card("数据库")
        self.db_out = QPlainTextEdit()
        self.db_out.setReadOnly(True)
        self.db_out.setMaximumHeight(250)
        c4.layout().addLayout(_row(
            _btn("观察库", lambda: self._load_db("observations")),
            _btn("经验库", lambda: self._load_db("knowledge")),
        ))
        self.obs_id = QLineEdit()
        self.obs_id.setPlaceholderText("观察条目 id")
        self.kid = QLineEdit()
        self.kid.setPlaceholderText("经验条目 id")
        c4.layout().addLayout(_row(
            _label("观察 id"), self.obs_id,
            _btn("删除观察", self._del_observation),
        ))
        c4.layout().addLayout(_row(
            _label("经验 id"), self.kid,
            _btn("删除经验", self._del_knowledge),
            _btn("停用经验", lambda: self._set_knowledge(False)),
            _btn("启用经验", lambda: self._set_knowledge(True)),
        ))
        c4.layout().addWidget(self.db_out)
        lay.addWidget(c4)
        lay.addStretch(1)

    def _toggle_auto(self, checked):
        def cb(ok):
            if not ok:
                self.auto.setChecked(_autostart_enabled())
                QMessageBox.warning(self, "开机自启", "写入注册表失败")
        _run_async(self, _autostart_set, cb, bool(checked))

    def save_switches(self):
        kw = {k: cb.isChecked() for k, cb in self.sw_boxes.items()}

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                QMessageBox.warning(self, "保存失败", r["error"])
                return
            QMessageBox.information(self, "已保存", "模块开关已保存，重启后生效。")
        _run_async(self, config.set_switches, cb, **kw)

    def save_ai(self):
        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                QMessageBox.warning(self, "保存失败", r["error"])
                return
            QMessageBox.information(self, "已保存", "AI 配置已写入 config.json。")
        _run_async(self, _save_ai, cb,
                   self.base.text().strip(), self.key.text().strip(),
                   self.model.text().strip())

    def _load_db(self, kind):
        def cb(rows):
            self.db_out.setPlainText(json_dump(rows))
        if kind == "observations":
            _run_async(self, db.get_observations, cb, limit=100)
        else:
            _run_async(self, db.list_knowledge, cb, limit=200)

    def _del_observation(self):
        oid = self.obs_id.text().strip()
        if not oid.isdigit():
            QMessageBox.warning(self, "删除观察", "请输入有效的观察条目 id。")
            return
        if QMessageBox.question(self, "删除观察", "确定删除观察条目 #%s 吗？此操作不可撤销。" % oid) != QMessageBox.StandardButton.Yes:
            return
        _run_async(self, db.delete_observation,
                   lambda r: self._db_done("观察条目 #%s" % oid, r, "observations"), int(oid))

    def _del_knowledge(self):
        kid = self.kid.text().strip()
        if not kid.isdigit():
            QMessageBox.warning(self, "删除经验", "请输入有效的经验条目 id。")
            return
        if QMessageBox.question(self, "删除经验", "确定删除经验条目 #%s 吗？此操作不可撤销。" % kid) != QMessageBox.StandardButton.Yes:
            return
        _run_async(self, db.delete_knowledge,
                   lambda r: self._db_done("经验条目 #%s" % kid, r, "knowledge"), int(kid))

    def _set_knowledge(self, enabled):
        kid = self.kid.text().strip()
        if not kid.isdigit():
            QMessageBox.warning(self, "经验开关", "请输入有效的经验条目 id。")
            return
        _run_async(self, db.set_knowledge_enabled,
                   lambda r: self._db_done("经验条目 #%s %s" % (kid, "启用" if enabled else "停用"), r, "knowledge"),
                   int(kid), bool(enabled))

    def _db_done(self, what, res, kind="knowledge"):
        if isinstance(res, dict) and res.get("error"):
            QMessageBox.warning(self, "数据库操作", "%s 失败：%s" % (what, res["error"]))
            return
        if res is False:
            QMessageBox.warning(self, "数据库操作", "%s 未生效（目标不存在）。" % what)
            return
        QMessageBox.information(self, "数据库操作", "%s 完成。" % what)
        self._load_db(kind)


def _save_ai(base, key, model):
    cfg = config.get()
    if not isinstance(cfg.get("ai"), dict):
        cfg["ai"] = {}
    cfg["ai"]["base_url"] = base
    cfg["ai"]["api_key"] = key
    cfg["ai"]["model"] = model
    config.save()


def _autostart_enabled():
    from ui import autostart
    try:
        return autostart.is_enabled()
    except Exception as e:
        logger.record_err("gui.autostart.is", e)
        return False


def _autostart_set(enable):
    from ui import autostart
    return autostart.set_enabled(bool(enable))


def _mod(module, fn):
    """延迟取模块函数（返回可调用），未实现时返回无害函数。"""
    try:
        mod = __import__("modules.%s" % module, fromlist=["x"])
        return getattr(mod, fn)
    except Exception as e:
        logger.record_err("gui.mod.%s.%s" % (module, fn), e)
        def _fail(*a, **k):
            return {"error": "%s.%s 不可用: %s" % (module, fn, e)}
        return _fail


def json_dump(obj):
    import json
    try:
        return json.dumps(obj, ensure_ascii=False, indent=1, default=str)
    except Exception:
        return str(obj)


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
        pages = [("总览", OverviewPage(self))]
        if config.enabled("tracking"):
            pages.append(("追踪任务", TrackingPage(self)))
        if config.enabled("privacy_guard"):
            pages.append(("隐私保护", PrivacyGuardPage(self)))
        if config.enabled("screener"):
            pages.append(("筛查工作台", ScreenerPage(self)))
        if config.enabled("agent"):
            pages.append(("AI 助手", AiHelperPage(self)))
        if config.enabled("pcap"):
            pages.append(("M1 抓包", PcapPage(self)))
        if config.enabled("regscan"):
            pages.append(("M2 注册表", RegscanPage(self)))
        if config.enabled("embedding"):
            pages.append(("M3 经验检索", EmbedPage(self)))
        if config.enabled("decompile"):
            pages.append(("M6 反编译", DecompilePage(self)))
        if config.enabled("watcher"):
            pages.append(("M7 观察", WatcherPage(self)))
        if config.enabled("browser"):
            pages.append(("M4 浏览器", BrowserPage(self)))
        if config.enabled("ai"):
            pages.append(("M8 大模型", AiPage(self)))
        if config.enabled("evolve"):
            pages.append(("M5 进化", EvolvePage(self)))
        if config.enabled("hunt"):
            pages.append(("M9 主流程", HuntPage(self)))
        pages.append(("设置", SettingsPage(self)))

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
            self._real_quit()
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
            return
        self._app.quit()


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
