"""M6 反编译页"""
import os

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLineEdit, QTableWidget,
    QPlainTextEdit, QFileDialog, QMessageBox, QTabWidget,
)

from ui.gui_common import (
    _btn, _card, _fill_table, _form_row, _hint,
    _mod, _page_header, _run_async, _set_status, _status_label, _toolbar, json_dump,
)



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
