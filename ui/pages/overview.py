"""总览页"""
import os

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPlainTextEdit,
)

from core import config, db, logger
from modules import active as active_modules
from ui.gui_common import (
    _btn, _card, _page_header, _row, _run_async,
)



class OverviewPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        self._loaded = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("总览", "OVERVIEW"))

        c = _card("系统信息")
        self._info = QPlainTextEdit()
        self._info.setReadOnly(True)
        self._info.setMaximumHeight(200)
        c.layout().addWidget(self._info)
        lay.addWidget(c)

        c2 = _card("快捷操作")
        c2.layout().addLayout(_row(
            _btn("打开 Web 控制台", self._w.open_console, primary=True),
            _btn("打开数据目录", lambda: os.startfile(config.ROOT)),
        ))
        lay.addWidget(c2)
        lay.addStretch(1)

    def showEvent(self, ev):
        super().showEvent(ev)
        if not self._loaded:
            self._loaded = True
            self.refresh()

    def refresh(self):
        def load():
            obs = db.get_observations(limit=500)
            know = db.list_knowledge(limit=500)
            agents = db.list_agents(limit=500)
            return (len(obs), len(know), len(agents), logger.has_err())

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                self._info.setPlainText("概览获取失败: %s" % r["error"])
                return
            if isinstance(r, Exception):
                self._info.setPlainText("概览获取失败: %s" % r)
                return
            nobs, nknow, nagents, err = r
            text = "已启用模块: %s\n" % ", ".join(active_modules())
            text += "观察记录: %d  |  经验规则: %d  |  目标档案: %d\n" % (
                nobs, nknow, nagents)
            text += "Err.log: %s" % ("有未修复错误，见数据目录" if err else "干净")
            self._info.setPlainText(text)

        _run_async(self, load, cb)
