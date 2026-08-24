"""M5 进化页"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPlainTextEdit, QMessageBox,
)

from ui.gui_common import (
    _btn, _card, _hint, _mod, _page_header,
    _run_async, _set_status, _status_label, _toolbar, json_dump,
)



class EvolvePage(QWidget):
    """M5 自我进化：规则挖掘 / 权重调整 / 进化报告（与 Web vEvolve 走同一 facade）。"""

    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("自我进化", "M5 · EVOLVE"))
        self.status = _status_label("就绪", "info")
        lay.addWidget(self.status)

        c = _card("① 进化操作")
        c.layout().addLayout(_toolbar(
            _btn("挖掘候选规则", lambda: self._run("evolve", "mine_rules", (), "挖掘完成"),
                 primary=True),
            _btn("挖掘并确认写入", self._mine_apply),
            _btn("调整观察权重", lambda: self._run("evolve", "adjust_weights", (False,), "已统计（候选未落库）")),
            _btn("调整并确认应用", self._adjust_apply),
            _btn("查看进化报告", lambda: self._run("evolve", "report", (), "报告已生成")),
        ))
        c.layout().addWidget(_hint("默认 auto_apply=false；「确认」类按钮是显式人工确认入口（全程审计）。"))
        lay.addWidget(c)

        c2 = _card("② 结果")
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        c2.layout().addWidget(self.out)
        lay.addWidget(c2, 1)

    def _run(self, module, fn, args, ok_msg):
        _set_status(self.status, "执行中…", "run")

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "错误: %s" % r["error"], "err")
            else:
                _set_status(self.status, ok_msg, "ok")
            self.out.setPlainText(json_dump(r))

        _run_async(self, _mod(module, fn), cb, *args)

    def _mine_apply(self):
        if QMessageBox.question(self, "确认写入",
                "确认把候选规则直接写入经验库（mine_rules auto_apply=true）？") \
                != QMessageBox.StandardButton.Yes:
            return
        self._run("evolve", "mine_rules", (3, 6, True), "已按确认写入")

    def _adjust_apply(self):
        if QMessageBox.question(self, "确认应用",
                "确认把热点类别规则的 risk_weight 上调 0.05 并落库？") \
                != QMessageBox.StandardButton.Yes:
            return
        self._run("evolve", "adjust_weights", (True,), "已按确认应用")
