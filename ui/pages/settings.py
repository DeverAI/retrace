"""设置页"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QPlainTextEdit, QCheckBox,
    QMessageBox, QGridLayout,
)

from core import config, db
from ui.gui_common import (
    _autostart_enabled, _autostart_set, _btn, _card, _label,
    _page_header, _row, _run_async, _save_ai, json_dump,
)



class SettingsPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("设置", "CONFIG"))

        # ---- 开机自启 ----
        c1 = _card("系统集成")
        self.auto = QCheckBox("开机自动启动（最小化到托盘）")
        self.auto.setChecked(_autostart_enabled())
        self.auto.toggled.connect(self._toggle_auto)
        c1.layout().addWidget(self.auto)
        lay.addWidget(c1)

        # ---- 模块开关 ----
        c2 = _card("模块开关（保存后重启生效）")
        self.sw_boxes = {}
        grid = QGridLayout()
        grid.setSpacing(8)
        for i, k in enumerate(("pcap", "regscan", "embedding", "decompile",
                               "watcher", "browser", "ai", "evolve",
                               "hunt", "agent", "screener", "tracking",
                               "privacy_guard")):
            cb = QCheckBox(k)
            cb.setChecked(bool(config.enabled(k)))
            self.sw_boxes[k] = cb
            grid.addWidget(cb, i // 3, i % 3)
        c2.layout().addLayout(grid)
        c2.layout().addLayout(_row(_btn("保存模块开关", self.save_switches, primary=True)))
        lay.addWidget(c2)

        # ---- AI 配置 ----
        c3 = _card("大模型配置（AI 辅助分析 / Agent 使用）")
        cfg = config.section("ai", {})
        self.base = QLineEdit(cfg.get("base_url", ""))
        self.base.setPlaceholderText("base_url (如 https://api.deepseek.com/v1)")
        self.key = QLineEdit(cfg.get("api_key", ""))
        self.key.setEchoMode(QLineEdit.EchoMode.Password)
        self.model = QLineEdit(cfg.get("model", ""))
        self.model.setPlaceholderText("model (如 deepseek-chat)")
        c3.layout().addLayout(_row(_label("base_url"), self.base))
        c3.layout().addLayout(_row(_label("api_key"), self.key))
        c3.layout().addLayout(_row(_label("model"), self.model))
        c3.layout().addLayout(_row(_btn("保存 AI 配置", self.save_ai, primary=True)))
        lay.addWidget(c3)

        # ---- 数据库 ----
        c4 = _card("数据库")
        self.db_out = QPlainTextEdit()
        self.db_out.setReadOnly(True)
        self.db_out.setMaximumHeight(250)
        c4.layout().addLayout(_row(
            _btn("观察库", lambda: self._load_db("observations")),
            _btn("经验库", lambda: self._load_db("knowledge")),
        ))
        self.obs_id = QLineEdit()
        self.obs_id.setPlaceholderText("观察条目 id")
        self.kid = QLineEdit()
        self.kid.setPlaceholderText("经验条目 id")
        c4.layout().addLayout(_row(
            _label("观察 id"), self.obs_id,
            _btn("删除观察", self._del_observation),
        ))
        c4.layout().addLayout(_row(
            _label("经验 id"), self.kid,
            _btn("删除经验", self._del_knowledge),
            _btn("停用经验", lambda: self._set_knowledge(False)),
            _btn("启用经验", lambda: self._set_knowledge(True)),
        ))
        c4.layout().addWidget(self.db_out)
        lay.addWidget(c4)
        lay.addStretch(1)

    def _toggle_auto(self, checked):
        def cb(ok):
            if not ok:
                self.auto.setChecked(_autostart_enabled())
                QMessageBox.warning(self, "开机自启", "写入注册表失败")
        _run_async(self, _autostart_set, cb, bool(checked))

    def save_switches(self):
        kw = {k: cb.isChecked() for k, cb in self.sw_boxes.items()}

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                QMessageBox.warning(self, "保存失败", r["error"])
                return
            QMessageBox.information(self, "已保存", "模块开关已保存，重启后生效。")
        _run_async(self, config.set_switches, cb, **kw)

    def save_ai(self):
        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                QMessageBox.warning(self, "保存失败", r["error"])
                return
            QMessageBox.information(self, "已保存", "AI 配置已写入 config.json。")
        _run_async(self, _save_ai, cb,
                   self.base.text().strip(), self.key.text().strip(),
                   self.model.text().strip())

    def _load_db(self, kind):
        def cb(rows):
            self.db_out.setPlainText(json_dump(rows))
        if kind == "observations":
            _run_async(self, db.get_observations, cb, limit=100)
        else:
            _run_async(self, db.list_knowledge, cb, limit=200)

    def _del_observation(self):
        oid = self.obs_id.text().strip()
        if not oid.isdigit():
            QMessageBox.warning(self, "删除观察", "请输入有效的观察条目 id。")
            return
        if QMessageBox.question(self, "删除观察", "确定删除观察条目 #%s 吗？此操作不可撤销。" % oid) != QMessageBox.StandardButton.Yes:
            return
        _run_async(self, db.delete_observation,
                   lambda r: self._db_done("观察条目 #%s" % oid, r, "observations"), int(oid))

    def _del_knowledge(self):
        kid = self.kid.text().strip()
        if not kid.isdigit():
            QMessageBox.warning(self, "删除经验", "请输入有效的经验条目 id。")
            return
        if QMessageBox.question(self, "删除经验", "确定删除经验条目 #%s 吗？此操作不可撤销。" % kid) != QMessageBox.StandardButton.Yes:
            return
        _run_async(self, db.delete_knowledge,
                   lambda r: self._db_done("经验条目 #%s" % kid, r, "knowledge"), int(kid))

    def _set_knowledge(self, enabled):
        kid = self.kid.text().strip()
        if not kid.isdigit():
            QMessageBox.warning(self, "经验开关", "请输入有效的经验条目 id。")
            return
        _run_async(self, db.set_knowledge_enabled,
                   lambda r: self._db_done("经验条目 #%s %s" % (kid, "启用" if enabled else "停用"), r, "knowledge"),
                   int(kid), bool(enabled))

    def _db_done(self, what, res, kind="knowledge"):
        if isinstance(res, dict) and res.get("error"):
            QMessageBox.warning(self, "数据库操作", "%s 失败：%s" % (what, res["error"]))
            return
        if res is False:
            QMessageBox.warning(self, "数据库操作", "%s 未生效（目标不存在）。" % what)
            return
        QMessageBox.information(self, "数据库操作", "%s 完成。" % what)
        self._load_db(kind)
