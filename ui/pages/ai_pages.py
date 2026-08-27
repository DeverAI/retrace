"""AI 助手页（Agent 运行器）与 M8 大模型设置页"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QPlainTextEdit, QMessageBox,
    QTextBrowser,
)

from ui.gui_common import (
    _INV, _btn, _card, _form_row, _hint, _mod,
    _page_header, _row, _run_async, _set_status, _status_label, _toolbar, json_dump,
)



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
        self._btn_run = _btn("发送给 AI", self._run, primary=True)
        c.layout().addLayout(_row(self.input, self._btn_run))
        lay.addWidget(c)

        c2 = _card("实时步骤")
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setMaximumHeight(180)
        c2.layout().addWidget(self.out)
        c2.layout().addWidget(_hint(
            "运行期间实时显示每一步：模型思考 → 工具调用 → 安全审批 → 执行结果。"))
        lay.addWidget(c2)

        c3 = _card("结果")
        self.md_view = QTextBrowser()
        self.md_view.setReadOnly(True)
        self.md_view.setOpenExternalLinks(False)
        c3.layout().addWidget(self.md_view)
        c3.layout().addWidget(_hint(
            "AI 答复按 Markdown 渲染（标题/表格/代码高亮样式）。"))
        lay.addWidget(c3, 1)

    def _run(self):
        task = self.input.text().strip()
        if not task:
            return
        self.out.setPlainText("== 任务 ==\n%s\n" % task)
        self.md_view.setPlainText("")
        self._send_btn_dis()

        def notify(msg):
            # worker 线程调用 → 排队到 GUI 线程追加，实时显示中间步骤
            _INV.emit_run(lambda: self._append_line(msg))

        def cb(r):
            self._send_btn_en()
            if not isinstance(r, dict):
                r = {}
            if r.get("final"):
                self._append_line("== 结果 ==")
                try:
                    # final 是 Markdown 文本 → 渲染展示（表格/加粗/代码）
                    self.md_view.setMarkdown(r["final"])
                except Exception:
                    self.md_view.setPlainText(str(r["final"]))
                self._append_line("(结果已渲染到下方「结果」区)")
            elif r.get("error"):
                self._append_line("== 错误 == %s" % r["error"])
                self.md_view.setPlainText("错误: %s" % r["error"])
            tr = r.get("transcript") or []
            if tr:
                self._append_line("-- 执行过程（%d 次工具调用）--" % len(tr))
                denied = sum(1 for t in tr if t.get("denied"))
                okk = sum(1 for t in tr if not t.get("denied")
                          and (t.get("result") or {}).get("ok"))
                self._append_line("  成功 %d / 失败 %d / 被拒 %d" % (
                    okk, len(tr) - denied - okk, denied))
            self._append_line("(共 %s 步)" % r.get("steps", 0))

        _run_async(self, _agent_run_task, cb, task, self._confirm, notify)

    def _append_line(self, text):
        try:
            self.out.appendPlainText(text)
        except RuntimeError:
            pass

    def _send_btn_dis(self):
        self._btn_run.setEnabled(False)
        self._running = True

    def _send_btn_en(self):
        self._btn_run.setEnabled(True)
        self._running = False

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


def _agent_run_task(task, confirm_cb, notify_cb=None):
    from modules.agent import agent
    return agent.run_task(task, confirm_cb=confirm_cb, notify_cb=notify_cb)


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
        self.answer = QTextBrowser(); self.answer.setReadOnly(True)
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
            # worker 异常/_mod 降级时 cb 收到 {"error":...}（truthy），
            # 不得误报为"已配置"
            if isinstance(cfg, dict) and cfg.get("error"):
                _set_status(self.status, "AI 状态: 读取失败（%s）" % cfg["error"], "err")
                return
            _set_status(self.status, "AI 状态: %s" % (
                "已配置" if cfg else "未配置（请在设置页 config.json 填 base_url/api_key/model）"),
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
            elif isinstance(r, dict) and r.get("text"):
                _set_status(self.status, "完成", "ok")
                try:
                    self.answer.setMarkdown(str(r["text"]))
                except Exception:
                    self.answer.setPlainText(str(r["text"]))
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
            elif isinstance(r, dict) and r.get("text"):
                _set_status(self.status, "完成", "ok")
                try:
                    self.out_text.setMarkdown(str(r["text"]))
                except Exception:
                    self.out_text.setPlainText(str(r["text"]))
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
            elif isinstance(r, dict) and r.get("text"):
                _set_status(self.status, "完成", "ok")
                try:
                    self.out_text.setMarkdown(str(r["text"]))
                except Exception:
                    self.out_text.setPlainText(str(r["text"]))
            else:
                _set_status(self.status, "完成", "ok")
                self.out_text.setPlainText(json_dump(r))
        _run_async(self, _mod("ai", "chat"), cb, messages)
