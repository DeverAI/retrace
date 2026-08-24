"""M4 浏览器控制页"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QTableWidget,
)

from ui.gui_common import (
    _btn, _card, _fill_table, _form_row, _hint,
    _mod, _page_header, _run_async, _set_status, _status_label, _toolbar,
)



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
