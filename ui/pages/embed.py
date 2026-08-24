"""M3 经验检索页"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QTableWidget, QMessageBox,
)

from ui.gui_common import (
    _btn, _card, _fill_table, _form_row, _hint,
    _mod, _page_header, _run_async, _set_status, _status_label, _toolbar,
)



class EmbedPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("经验检索", "M3 · EMBEDDING"))
        self.status = _status_label("就绪", "info")
        lay.addWidget(self.status)

        c = _card("① 语义检索")
        self.query = QLineEdit(); self.query.setPlaceholderText("检索关键词（如 '可疑驱动加载'）")
        self.query.returnPressed.connect(self.search)
        self.result = QTableWidget()
        c.layout().addLayout(_form_row(("关键词", self.query)))
        c.layout().addLayout(_toolbar(
            _btn("检索", self.search, primary=True),
            _btn("清空", lambda: self.result.clear()),
        ))
        c.layout().addWidget(self.result, 1)
        lay.addWidget(c, 1)

        c2 = _card("② 写入新经验（回车入库）")
        self.memo = QLineEdit(); self.memo.setPlaceholderText("新经验文本")
        self.memo.returnPressed.connect(self.remember)
        c2.layout().addLayout(_form_row(("文本", self.memo)))
        c2.layout().addLayout(_toolbar(
            _btn("记住入库", self.remember),
            _btn("编码单条文本", self.embed_one),
            _btn("保存索引到磁盘", self.save_index),
        ))
        c2.layout().addWidget(_hint("语义检索按词频-哈希向量 + 余弦相似度；可在 settings 切换为 OpenAI 兼容 embedding。"))
        lay.addWidget(c2)
        self._loaded = False

    def showEvent(self, ev):
        super().showEvent(ev)
        if not self._loaded:
            self._loaded = True
            self._refresh_status()

    def _refresh_status(self):
        def cb(s):
            if isinstance(s, dict):
                _set_status(self.status, "provider=%s · 经验=%s · 维度=%s" % (
                    s.get("provider", "?"), s.get("docs", "?"), s.get("dim", "?")), "ok")
            else:
                _set_status(self.status, "经验索引状态不可用: %s" % s, "err")
        # embedding.stats() 返回 {provider, docs, dim}；provider() 只返回字符串，勿再误用。
        _run_async(self, _mod("embedding", "stats"), cb)

    def search(self):
        q = self.query.text().strip()
        if not q:
            return
        _set_status(self.status, "检索中…", "run")
        def cb(rows):
            count = len(rows) if isinstance(rows, list) else 0
            _set_status(self.status, "命中 %d 条" % count, "ok")
            _fill_table(self.result, rows if isinstance(rows, list) else [], 100)
        _run_async(self, _mod("embedding", "search"), cb, q, 10, 0.0)

    def remember(self):
        text = self.memo.text().strip()
        if not text:
            return

        def cb(r):
            if r is None or r is False or (isinstance(r, dict) and (r.get("ok") is False or r.get("error"))):
                _set_status(self.status, "入库失败: %s" % text, "err")
                return
            self.memo.clear()
            _set_status(self.status, "已入库: %s" % text[:60], "ok")
            self._refresh_status()
        _run_async(self, _mod("embedding", "remember"), cb, text, {"source": "gui"})

    def embed_one(self):
        text = self.memo.text().strip()
        if not text:
            QMessageBox.information(self, "提示", "请先在文本框输入要编码的内容")
            return
        _set_status(self.status, "编码中…", "run")

        def cb(vec):
            if isinstance(vec, dict) and vec.get("error"):
                _set_status(self.status, "编码失败: %s" % vec["error"], "err")
                return
            n = len(vec) if isinstance(vec, list) else 0
            head = (vec[:8] if isinstance(vec, list) else [])
            _set_status(self.status, "已编码 %s 维（前 8 维: %s）" % (n, head), "ok")
        _run_async(self, _mod("embedding", "embed"), cb, text)

    def save_index(self):
        def cb(r):
            if bool(r):
                _set_status(self.status, "索引已写入 embedding_index.json", "ok")
            else:
                _set_status(self.status, "索引保存失败（详见 Err.log）", "err")
        _run_async(self, _mod("embedding", "save_index"), cb)
