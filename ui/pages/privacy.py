"""隐私保护页"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QPlainTextEdit, QCheckBox,
    QMessageBox, QSpinBox, QSplitter,
)

from ui.gui_common import (
    _btn, _card, _form_row, _hint, _mod,
    _page_header, _run_async, _set_status, _status_label, _toolbar, json_dump,
)



class PrivacyGuardPage(QWidget):
    """Human approval surface for isolation and recoverable privacy actions."""
    def __init__(self, window):
        super().__init__()
        self._w = window
        self._loaded = False
        lay = QVBoxLayout(self); lay.setContentsMargins(20, 20, 20, 20); lay.setSpacing(12)
        lay.addLayout(_page_header("隐私保护", "PRIVACY GUARD"))
        self.status = _status_label("系统操作须显示明确原因并由用户批准", "info")
        lay.addWidget(self.status)

        # 全局原因（所有系统操作都要读，所以放最上面）
        self.reason = QLineEdit()
        self.reason.setPlaceholderText("明确原因（至少 12 字：目的、对象、必要性）")
        lay.addLayout(_form_row(("统一原因", self.reason)))

        # 四区栅格化（左右两列）
        split = QSplitter(Qt.Orientation.Horizontal); split.setChildrenCollapsible(False)

        # ---- 左：强隔离 + 注册表登记 ----
        left = QWidget(); llay = QVBoxLayout(left); llay.setContentsMargins(0, 0, 0, 0); llay.setSpacing(12)

        iso = _card("① 强隔离运行（无 guest 内部遥测）")
        iso.layout().addWidget(_hint("禁用 vGPU；专用 staging 副本只读映射。宿主时间线看不到沙箱内部注册表/DNS/文件访问。"))
        self.exe = QLineEdit(); self.exe.setPlaceholderText("EXE 完整路径")
        self.net = QCheckBox("允许联网"); self.clip = QCheckBox("允许剪贴板")
        iso.layout().addLayout(_form_row(("EXE", self.exe)))
        iso.layout().addLayout(_toolbar(self.net, self.clip, None))
        iso.layout().addLayout(_toolbar(_btn("预览 WSB", self.preview_sandbox),
                                         _btn("审查并启动", self.launch_sandbox, primary=True)))
        llay.addWidget(iso)

        reg = _card("② APP 注册表关联（仅已登记 HKCU 厂商/产品子树）")
        self.task_id = QSpinBox(); self.task_id.setRange(1, 2_000_000_000)
        self.subkey = QLineEdit(); self.subkey.setPlaceholderText("Software\\厂商\\产品")
        self.value_name = QLineEdit(); self.value_name.setPlaceholderText("精确值名")
        self.new_value = QLineEdit(); self.new_value.setPlaceholderText("新 REG_SZ 值")
        self.publisher = QLineEdit(); self.publisher.setPlaceholderText("签名发布者/厂商（记录用）")
        self.owner_note = QLineEdit(); self.owner_note.setPlaceholderText("所有权证据与安全修改说明（≥12字）")
        reg.layout().addLayout(_form_row(("任务 ID", self.task_id), ("厂商/产品子树", self.subkey)))
        reg.layout().addLayout(_form_row(("值名", self.value_name), ("新值", self.new_value)))
        reg.layout().addLayout(_form_row(("发布者", self.publisher), ("所有权说明", self.owner_note)))
        reg.layout().addLayout(_toolbar(_btn("查看依赖", self.report),
                                          _btn("登记子树", self.register_scope),
                                          _btn("撤销登记", self.remove_scope),
                                          None,
                                          _btn("审查设置值", self.set_registry, primary=True),
                                          _btn("审查删除值", self.delete_registry)))
        reg.layout().addWidget(_hint("系统身份范围（HKLM/MachineGuid/网卡）确定性拒绝；HKCU 须先登记再修改。"))
        llay.addWidget(reg)
        llay.addStretch(1)
        split.addWidget(left)

        # ---- 右：浏览 + 系统执行回显 + 输出区 ----
        right = QWidget(); rlay = QVBoxLayout(right); rlay.setContentsMargins(0, 0, 0, 0); rlay.setSpacing(12)

        web = _card("③ Canvas API 缓解 / Windows WLAN 隐私")
        self.site = QLineEdit(); self.site.setPlaceholderText("https://example.com")
        web.layout().addWidget(_hint("Canvas 默认关闭且按顶级站点启用；仅尽力在文档早期缓解 2D Canvas，不能保证阻止最早脚本。MAC 仅打开 Windows 官方 Wi-Fi 设置。"))
        web.layout().addLayout(_form_row(("目标站点", self.site)))
        web.layout().addLayout(_toolbar(_btn("启用 Canvas", lambda: self.canvas(True)),
                                          _btn("停用 Canvas", lambda: self.canvas(False)),
                                          None,
                                          _btn("WLAN 能力", self.mac_status),
                                          _btn("审查后打开设置", self.open_wifi, primary=True)))
        rlay.addWidget(web)

        # 系统执行回显
        echo = _card("④ 系统操作结果（最近一次计划/批准/执行回显）")
        self.out = QPlainTextEdit(); self.out.setReadOnly(True)
        echo.layout().addLayout(_toolbar(
            _btn("刷新能力", self._caps),
            _btn("查看保护规则", self._rules),
            _btn("查看已登记 HKCU 范围", self._scopes),
        ))
        echo.layout().addWidget(self.out, 1)
        rlay.addWidget(echo, 1)

        split.addWidget(right)
        split.setStretchFactor(0, 5); split.setStretchFactor(1, 5)
        lay.addWidget(split, 1)

    def showEvent(self, event):
        super().showEvent(event)
        if not self._loaded:
            self._loaded = True
            self._caps()

    def _caps(self):
        _run_async(self, _mod("privacy_guard", "capabilities"), self._show)
    def _rules(self):
        def cb(r):
            if isinstance(r, list):
                _set_status(self.status, "保护规则 %d 条" % len(r), "ok")
            else:
                _set_status(self.status, "已加载保护规则", "ok")
            self._show(r)
        _run_async(self, _mod("privacy_guard", "protected_rules"), cb)
    def _scopes(self):
        def cb(r):
            if isinstance(r, list):
                _set_status(self.status, "已登记范围 %d 项" % len(r), "ok")
            else:
                _set_status(self.status, "已加载范围", "ok")
            self._show(r)
        _run_async(self, _mod("privacy_guard", "registry_scopes"), cb)

    def _show(self, value):
        self.out.setPlainText(json_dump(value))

    def _reason(self):
        text = self.reason.text().strip()
        if len(text) < 12:
            QMessageBox.warning(self, "原因不足", "请写明至少 12 字的目的、对象和必要性")
            return ""
        return text

    def _system_action(self, action, args):
        reason = self._reason()
        if not reason: return
        def planned(plan):
            if not isinstance(plan, dict) or not plan.get("token"):
                self._show(plan); return
            text = "操作：%s\n\n参数：%s\n\n原因：%s\n\n步骤：\n- %s" % (
                plan["action"], json_dump(plan.get("args", {})), plan["reason"],
                "\n- ".join(plan.get("steps", [])))
            if QMessageBox.question(self, "审查系统操作预案", text) != QMessageBox.StandardButton.Yes:
                _set_status(self.status, "用户取消，未执行", "info"); return
            def approved(cap):
                if not isinstance(cap, dict) or not cap.get("approval_token"):
                    self._show(cap); return
                _run_async(self, _mod("privacy_guard", "execute_system_action"), self._show,
                           cap["approval_token"], reason)
            _run_async(self, _mod("privacy_guard", "approve_system_action"), approved,
                       plan["token"], "我已审查并批准", reason, "pyqt_dialog")
        _run_async(self, _mod("privacy_guard", "plan_system_action"), planned,
                   action, args, reason)

    def preview_sandbox(self):
        _run_async(self, _mod("privacy_guard", "sandbox_preview"), self._show,
                   self.exe.text().strip(), self.net.isChecked(), self.clip.isChecked(), 4096)

    def launch_sandbox(self):
        self._system_action("launch_sandbox", {"exe_path": self.exe.text().strip(),
                            "network": self.net.isChecked(), "clipboard": self.clip.isChecked(),
                            "memory_mb": 4096})

    def report(self):
        _run_async(self, _mod("privacy_guard", "task_report"), self._show, self.task_id.value())

    def register_scope(self):
        reason = self._reason()
        if not reason: return
        if QMessageBox.question(self, "登记精确范围",
                "只登记范围，不写注册表。确认该子树属于目标 APP？") != QMessageBox.StandardButton.Yes:
            return
        _run_async(self, _mod("privacy_guard", "register_registry_scope"), self._show,
                   self.task_id.value(), "HKCU", self.subkey.text().strip(), self.publisher.text().strip(),
                   self.owner_note.text().strip(), reason, "我已审查并批准")

    def remove_scope(self):
        reason = self._reason()
        if not reason: return
        subkey = self.subkey.text().strip()
        if not subkey:
            QMessageBox.warning(self, "提示", "请输入要撤销的子树（Software\\厂商\\产品）")
            return
        if QMessageBox.question(self, "撤销授权范围",
                "确认撤销任务 %d 的登记范围 %s？撤销后该子树将不再允许修改。" % (
                    self.task_id.value(), subkey)) != QMessageBox.StandardButton.Yes:
            return
        _run_async(self, _mod("privacy_guard", "remove_registry_scope"), self._show,
                   self.task_id.value(), subkey, reason, "我已审查并批准")

    def set_registry(self):
        if not self.subkey.text().strip() or not self.value_name.text().strip():
            QMessageBox.warning(self, "参数缺失", "请填写 HKCU\\子键 与 值名 后再修改")
            return
        self._system_action("registry_set_string", {"task_id":self.task_id.value(), "root":"HKCU",
                            "subkey":self.subkey.text().strip(), "value_name":self.value_name.text(),
                            "new_value":self.new_value.text()})

    def delete_registry(self):
        if not self.subkey.text().strip() or not self.value_name.text().strip():
            QMessageBox.warning(self, "参数缺失", "请填写 HKCU\\子键 与 值名 后再删除")
            return
        self._system_action("registry_delete_value", {"task_id":self.task_id.value(), "root":"HKCU",
                            "subkey":self.subkey.text().strip(), "value_name":self.value_name.text()})

    def canvas(self, enabled):
        reason = self._reason()
        if reason:
            _run_async(self, _mod("privacy_guard", "set_canvas_guard"), self._show,
                       self.site.text().strip(), enabled, reason)

    def mac_status(self):
        _run_async(self, _mod("privacy_guard", "mac_randomization_status"), self._show)

    def open_wifi(self):
        self._system_action("open_wifi_privacy_settings", {})
