"""AI 助手页（Agent 运行器）与 M8 大模型设置页"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QPlainTextEdit, QMessageBox,
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
