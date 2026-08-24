"""M1 抓包页"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QComboBox, QTableWidget,
    QTableWidgetItem, QPlainTextEdit, QMessageBox, QSpinBox,
)

from ui.gui_common import (
    _btn, _card, _fill_table, _form_row, _label,
    _mod, _page_header, _row, _run_async, _toolbar, json_dump,
)



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
