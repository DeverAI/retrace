"""GUI 基础设施层：QSS 主题、QThread 异步设施、控件工厂、共享助手。

页面实现在 ui/pages/ 包；本模块只放跨页面复用的稳定基元。
FreqErr 三坑备忘：
  1) Worker 必须持有强引用（thread._w），否则函数返回即被 GC；
  2) 跨线程回调必须走 QueuedConnection（_Invoker）；
  3) 线程退出阶段用 DirectConnection quit 防止 queued 指令饿死。
"""
import json

from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QPlainTextEdit, QCheckBox, QGroupBox, QHeaderView, QSpinBox,
    QDialog, QDialogButtonBox, QTableWidgetItem,
)

from core import config, logger

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
    from PyQt6.QtWidgets import QWidget  # 局部导入避免模块级环

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
        # 统一经 _INV 排回主线程执行：finished 信号在 worker 线程触发，
        # 直接操作锚定列表会与主线程 append 竞态；owner 页面可能已销毁，
        # 全程 RuntimeError 容忍。
        def _do():
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
        _INV.emit_run(_do)

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
#  UI 控件工厂
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
#  共享助手
# ============================================================================
def _save_ai(base, key, model):
    """保存 AI 配置（GUI 通道）。

    密钥语义与 Web 端一致：空提交=保留已存密钥；输入 (clear)/(清除)=显式清除；
    其余非空覆盖。同时保证 timeout 段不被此入口误清。
    """
    current = (config.section("ai", {}) or {}).get("api_key", "")
    resolved = config.resolve_secret_update(key, current)
    values = {"base_url": base, "model": model}
    if resolved is not None and resolved != current:
        values["api_key"] = resolved
    config.update_section("ai", values)


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
        # 立即格式化错误串：except 块退出后 e 被解释器删除，
        # 闭包延迟引用会触发 NameError（原实现的真实 bug）。
        msg = "%s.%s 不可用: %s" % (module, fn, e)

        def _fail(*a, **k):
            return {"error": msg}
        return _fail


def json_dump(obj):
    try:
        return json.dumps(obj, ensure_ascii=False, indent=1, default=str)
    except Exception:
        return str(obj)


__all__ = [
    # 主题与常量
    "QSS", "_STATUS_COLOR",
    # 异步设施
    "_Worker", "_Invoker", "_INV", "_run_async",
    # 控件工厂
    "_fill_table", "_label", "_status_label", "_set_status", "_page_header",
    "_card", "_row", "_form_row", "_toolbar", "_placeholder", "_section",
    "_hint", "_btn",
    # 对话框
    "_TaskEditDialog",
    # 共享助手
    "_save_ai", "_autostart_enabled", "_autostart_set", "_mod", "json_dump",
]
