"""M7 观察页"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QTableWidget, QTableWidgetItem,
    QMessageBox,
)

from ui.gui_common import (
    _btn, _card, _fill_table, _form_row, _hint,
    _mod, _page_header, _run_async, _set_status, _status_label, _toolbar, json_dump,
)



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
