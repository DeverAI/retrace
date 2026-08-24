"""追踪任务页"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QTableWidget,
    QPlainTextEdit, QCheckBox, QMessageBox, QSpinBox,
    QAbstractItemView, QDialog, QTabWidget, QSplitter,
)

from ui.gui_common import (
    _TaskEditDialog, _btn, _card, _fill_table, _form_row,
    _hint, _mod, _page_header, _run_async, _set_status, _status_label, _toolbar,
)



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

            def cb_start(r):
                if isinstance(r, dict) and r.get("error"):
                    _set_status(self.status, "启动失败: %s" % r["error"], "err")
                self.refresh()
            _run_async(self, _mod("tracking", "start_task"), cb_start, task["id"])

    def pause_selected(self):
        task = self._selected()
        if task:
            _set_status(self.status, "正在暂停任务 #%d…" % task["id"], "run")

            def cb_pause(r):
                if isinstance(r, dict) and r.get("error"):
                    _set_status(self.status, "暂停失败: %s" % r["error"], "err")
                self.refresh()
            _run_async(self, _mod("tracking", "pause_task"), cb_pause, task["id"])

    def load_events(self):
        task = self._selected()
        if not task:
            return
        def cb(rows):
            # 任务被并发删除时 _Worker 会把异常转成 {"error":...} dict，
            # 必须与 show_runs/show_audit 一致做结构守卫，否则静默失败
            if not isinstance(rows, list):
                _set_status(self.status, "事件加载失败：%s" %
                            (rows.get("error", "未知错误") if isinstance(rows, dict) else rows),
                            "err")
                return
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
