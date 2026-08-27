"""M2 注册表页"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QComboBox, QTableWidget,
    QTableWidgetItem, QPlainTextEdit, QMessageBox,
)

from ui.gui_common import (
    _btn, _card, _fill_table, _form_row, _hint,
    _mod, _page_header, _row, _run_async, _set_status, _status_label, _toolbar, json_dump,
)



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
            # 失败/降级 dict 不得写入 _last_snap，否则后续对比全部 AttributeError
            if not isinstance(r, dict) or r.get("error"):
                self._show_text("快照失败: %s" % (r.get("error") if isinstance(r, dict) else r))
                _set_status(self.status, "快照失败", "err")
                return
            self._last_snap = r
            _set_status(self.status, "已快照（再点『对比两次快照』查看差异）", "ok")
            self._show_text(json_dump(r))
        _run_async(self, _mod("regscan", "snapshot_watches"), cb)

    def diff_watches(self):
        if self._last_snap is None:
            QMessageBox.warning(self, "无快照", "请先点「快照观察键」做一次快照")
            return
        before = self._last_snap

        def load():
            after = _mod("regscan", "snapshot_watches")()
            # 检修（2026-08-27）：重快照降级/失败时不得把含 error 的 dict 当基线，
            # 否则与上方快照路径的守卫（172-176）自相矛盾，污染对比起点
            if not isinstance(after, dict) or after.get("error"):
                return {"error": "重新快照失败：%s"
                        % (after.get("error") if isinstance(after, dict) else after)}
            diffs = _mod("regscan", "diff_watches")(before, after)
            return {"diffs": diffs, "after": after}

        def cb(r):
            if not isinstance(r, dict) or r.get("error"):
                self._show_text(r.get("error") if isinstance(r, dict) else r)
                _set_status(self.status, "对比失败", "err")
                return
            diffs, after = r.get("diffs"), r.get("after")
            if not isinstance(after, dict) or after.get("error"):
                # 双保险：异常路径产物绝不清空/污染既有快照
                _set_status(self.status, "对比结果异常，已保留原快照", "err")
                return
            self._last_snap = after
            _set_status(self.status, "观察键变化 %d 处" % (len(diffs) if isinstance(diffs, list) else 0), "ok")
            _fill_table(self.table, diffs if isinstance(diffs, list) else [], 500)
            self._show_text(json_dump(diffs)[:4000])
        _run_async(self, load, cb)
