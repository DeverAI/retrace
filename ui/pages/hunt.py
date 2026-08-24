"""M9 主流程页"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QComboBox, QTableWidget,
    QPlainTextEdit, QMessageBox,
)

from ui.gui_common import (
    _btn, _card, _fill_table, _form_row, _hint,
    _mod, _page_header, _run_async, _set_status, _status_label, _toolbar, json_dump,
)



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
            if not isinstance(rows, list):
                _set_status(self.status, "读取失败: %s" % (rows.get("error") if isinstance(rows, dict) else rows), "err")
                return
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
