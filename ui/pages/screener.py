"""筛查工作台页"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QComboBox,
    QTableWidget, QPlainTextEdit, QMessageBox, QInputDialog,
    QAbstractItemView,
)

from ui.gui_common import (
    _STATUS_COLOR, _btn, _card, _fill_table, _form_row,
    _hint, _label, _mod, _page_header, _run_async, _set_status, _status_label, _toolbar,
    json_dump,
)



class ScreenerPage(QWidget):
    """筛查工作台：一键筛查 + 筛选 + 标记 + AI 辅助分析（人机协作）。
    布局：①通用扫描 ②文件/追踪分析 ③留样扫描与清理（独立大卡）④筛选与主结果表 ⑤标记 & AI 操作。
    """

    def __init__(self, window):
        super().__init__()
        self._w = window
        self._result = None
        self._items = []
        self._viewed = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        lay.addLayout(_page_header("筛查工作台", "SCREENER"))
        self.status = _status_label("就绪", "info")
        lay.addWidget(self.status)

        # ---- ① 通用扫描 ----
        c1 = _card("① 通用扫描")
        self.dir1 = QLineEdit()
        self.dir1.setPlaceholderText("残留/指纹扫描目录")
        c1.layout().addLayout(_form_row(("扫描目录", self.dir1)))
        c1.layout().addLayout(_toolbar(
            _btn("扫描可疑 APP", lambda: self._scan(_mod("screener", "scan_suspicious_apps")), primary=True),
            _btn("扫描残留", lambda: self._scan(_mod("screener", "scan_leftover"), self.dir1.text().strip())),
            _btn("指纹扫描", lambda: self._scan(_mod("screener", "scan_fingerprints"), self.dir1.text().strip())),
        ))
        c1.layout().addLayout(_toolbar(
            _btn("已知指纹文件", lambda: self._scan(_mod("screener", "scan_machine_fingerprints"), "")),
            _btn("未知指纹内容", lambda: self._scan(_mod("screener", "scan_generic_fingerprints"), "")),
        ))
        c1.layout().addWidget(_hint("扫描可疑 APP：自启动点位+风险词；扫描残留：双根 HKLM+HKCU 悬空引用+空目录；"
                                    "指纹：深度≤6、≤512MB；已知指纹文件：按模式库匹配 machineid/DIPS/Client ID 等；"
                                    "未知指纹内容：按文件名关键词+UUID/长十六进制内容判定。"))
        lay.addWidget(c1)

        # ---- ② 单文件分析 / 启动追踪 ----
        c2 = _card("② 文件 / 追踪 / 格式逆向")
        self.filepath = QLineEdit(); self.filepath.setPlaceholderText("文件路径（py / exe / dll / class / 指纹文件）")
        self.tname = QLineEdit(); self.tname.setPlaceholderText("追踪目标名")
        self.texe = QLineEdit(); self.texe.setPlaceholderText("目标 exe 路径（可选）")
        c2.layout().addLayout(_form_row(("文件", self.filepath), ("目标名", self.tname), ("exe", self.texe)))
        c2.layout().addLayout(_toolbar(
            _btn("检查文件", lambda: self._scan(_mod("screener", "check_file"), self.filepath.text().strip())),
            _btn("追踪 APP", lambda: self._scan(_mod("screener", "track_app"),
                                              self.tname.text().strip(), self.texe.text().strip()), primary=True),
        ))
        c2.layout().addLayout(_toolbar(
            _btn("逆向解析指纹格式", self._fmt_analyze),
            _btn("生成可信替换预览", self._fmt_preview),
        ))
        self.fp_q = QLineEdit(); self.fp_q.setPlaceholderText("AI 指纹修改指导问题（可选）")
        c2.layout().addLayout(_form_row(("AI 问题", self.fp_q)))
        c2.layout().addLayout(_toolbar(
            _btn("AI 指导（安全自检）", self._fp_guidance),
        ))
        c2.layout().addWidget(_hint("逆向解析：SQLite/JSON/DPAPI/UUID/hex 指纹文件的创建规则与改写指导；"
                                    "替换预览：生成符合规则的替换值（只读不写盘），防改坏后软件不信任重建。"
                                    " AI 指导：带强制【已检查】安全自检，绝不自动执行。"))
        lay.addWidget(c2)

        # ---- ②½ 深潜扫描（Prefetch / 使用历史 / WER / AI 痕迹 / 再生监测） ----
        cdeep = _card("②½ 深潜扫描（卸载后仍残留的隐藏痕迹，需软件关键词）")
        self.deep_kw = QLineEdit(); self.deep_kw.setPlaceholderText("软件关键词（如 Qoder）")
        cdeep.layout().addLayout(_form_row(("关键词", self.deep_kw)))
        cdeep.layout().addLayout(_toolbar(
            _btn("Prefetch 执行痕迹", lambda: self._scan_kw(_mod("screener", "scan_prefetch_traces")), primary=True),
            _btn("注册表使用历史", lambda: self._scan_kw(_mod("screener", "scan_usage_history"))),
            _btn("WER 崩溃报告", lambda: self._scan_kw(_mod("screener", "scan_wer_traces"))),
            _btn("AI 工具痕迹", lambda: self._scan_kw(_mod("screener", "scan_ai_tool_traces"))),
        ))
        cdeep.layout().addLayout(_toolbar(
            _btn("指纹再生监测（对比上次基线）", self._drift_report, primary=True),
            _btn("记录当前为基线",
                 lambda: self._run_async_drift(True)),
        ))
        cdeep.layout().addWidget(_hint("Prefetch：程序每次运行的 .pf 执行痕迹；使用历史：MuiCache + UserAssist（ROT13）"
                                       " + AppCompat + BAM 系统级执行时间戳；WER：崩溃报告残留。卸载后仍保留。"
                                       "AI 痕迹：Claude Code/Codex/Gemini CLI 等身份产物（密钥仅显示哈希预览）。"
                                       "再生监测：清理后复查是否被软件原样复活（recreated_same_value = 有云端恢复，本地清理无效）。"))
        lay.addWidget(cdeep)

        # ---- ③ 留样扫描与批量清理（独立大卡） ----
        self._trace_items = []
        ct = _card("③ 留样扫描与批量清理（不依赖安装目录）")
        self.trace_kw = QLineEdit(); self.trace_kw.setPlaceholderText("软件关键词（如 Qoder）")
        self.restore_dir = QLineEdit(); self.restore_dir.setPlaceholderText("恢复目录（清理结果里的 quarantine）")
        ct.layout().addLayout(_form_row(("关键词", self.trace_kw), ("恢复目录", self.restore_dir)))
        ct.layout().addLayout(_toolbar(
            _btn("留样扫描", self._trace_scan, primary=True),
            _btn("预览清理（不执行）", self._trace_preview),
        ))
        ct.layout().addLayout(_toolbar(
            _btn("批量清理勾选", self._trace_cleanup),
            _btn("一键恢复", self._trace_restore),
        ))
        self.trace_table = QTableWidget()
        self.trace_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.trace_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        ct.layout().addWidget(self.trace_table, 1)
        self.trace_out = QPlainTextEdit(); self.trace_out.setReadOnly(True)
        self.trace_out.setMaximumHeight(120)
        ct.layout().addWidget(self.trace_out)
        ct.layout().addWidget(_hint("清理会先创建系统还原点；系统身份范围（MachineGuid/BIOS/网卡）确定性拒绝。"))
        lay.addWidget(ct, 1)

        # ---- ④ 筛选与主结果表 ----
        c4 = _card("④ 主结果（可筛选后标记入库）")
        filt_bar = QHBoxLayout()
        self.f_cat = QComboBox(); self.f_cat.addItem("全部")
        self.f_risk = QComboBox(); self.f_risk.addItems(["全部", "高", "中", "低", "无"])
        filt_bar.addWidget(_label("类别")); filt_bar.addWidget(self.f_cat)
        filt_bar.addSpacing(12); filt_bar.addWidget(_label("风险")); filt_bar.addWidget(self.f_risk)
        filt_bar.addStretch(1)
        c4.layout().addLayout(filt_bar)
        self.table = QTableWidget()
        c4.layout().addWidget(self.table, 1)
        # 标记 & AI
        sub = QHBoxLayout()
        self.m_risk = QComboBox(); self.m_risk.addItems(["高", "中", "低", "无"])
        self.m_note = QLineEdit(); self.m_note.setPlaceholderText("备注（可选）")
        sub.addWidget(_label("标记风险")); sub.addWidget(self.m_risk); sub.addSpacing(12)
        sub.addWidget(self.m_note, 1)
        sub.addWidget(_btn("标记选中入库", self._mark, primary=True))
        sub.addWidget(_btn("AI 辅助分析", self._ai))
        c4.layout().addLayout(sub)
        self.ai_out = QPlainTextEdit(); self.ai_out.setReadOnly(True)
        self.ai_out.setMaximumHeight(140)
        c4.layout().addWidget(self.ai_out)
        lay.addWidget(c4, 1)

        self.f_cat.currentTextChanged.connect(self._filter)
        self.f_risk.currentTextChanged.connect(self._filter)

    def _scan(self, fn, *args):
        self.status.setText("扫描中...")
        self.status.setStyleSheet(_STATUS_COLOR["run"])
        self.ai_out.clear()

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "错误: %s" % r["error"], "err")
                return
            self._result = r
            self._items = (r or {}).get("items", []) or []
            s = (r or {}).get("summary") or {}
            _set_status(self.status, "%s：共%d 高%d 中%d 低%d" % (
                (r or {}).get("category", "扫描"), s.get("total", 0),
                s.get("high", 0), s.get("med", 0), s.get("low", 0)), "ok")
            cats = sorted({it.get("category", "?") for it in self._items})
            self.f_cat.blockSignals(True)
            self.f_cat.clear()
            self.f_cat.addItem("全部")
            for cat in cats:
                self.f_cat.addItem(cat)
            self.f_cat.blockSignals(False)
            self._filter()

        _run_async(self, fn, cb, *args)

    def _scan_kw(self, fn):
        """深潜扫描专用：校验软件关键词非空后发起扫描。"""
        kw = self.deep_kw.text().strip()
        if not kw:
            QMessageBox.warning(self, "提示", "请输入软件关键词（如 Qoder）")
            return
        self._scan(fn, kw)

    def _drift_report(self):
        """指纹再生监测：返回结构与常规扫描不同，走专用渲染而非 _scan。"""
        self._run_async_drift(commit=False)

    def _run_async_drift(self, commit):
        _set_status(self.status, "漂移对比中…" if not commit else "基线记录中…", "run")
        self.ai_out.clear()

        def cb(r):
            if not isinstance(r, dict) or r.get("error"):
                _set_status(self.status, "错误: %s" % (r.get("error") if isinstance(r, dict) else r),
                            "err")
                return
            s = r.get("summary") or {}
            if r.get("first_run"):
                _set_status(self.status, "首次运行：已记录基线（跟踪 %d 个文件），"
                                        "清理后再次运行即可对比" % r.get("tracked_files", 0), "ok")
            else:
                warn = " ⚠️ %s" % r["warning"] if r.get("warning") else ""
                _set_status(self.status, "跟踪 %d 项 | 变化 %d | 原样复活 %d%s" % (
                    s.get("tracked", 0), s.get("changed", 0),
                    s.get("recreated_same_value", 0), warn),
                    "err" if r.get("warning") else "ok")
            self.ai_out.setPlainText(json_dump(r))

        _run_async(self, _mod("screener", "fingerprint_drift_report"), cb, "", commit)

    def _fmt_path(self):
        p = self.filepath.text().strip()
        if not p:
            QMessageBox.warning(self, "提示", "请先在「文件」框填写指纹文件路径")
            return ""
        return p

    def _fmt_analyze(self):
        """逆向解析指纹文件编码格式（只读）。"""
        p = self._fmt_path()
        if not p:
            return
        _set_status(self.status, "格式逆向解析中…", "run")

        def cb(r):
            if not isinstance(r, dict):
                _set_status(self.status, "解析失败: %s" % r, "err")
                return
            if r.get("error"):
                _set_status(self.status, "解析失败: %s" % r["error"], "err")
                return
            text = json_dump(r)
            self.ai_out.setPlainText(text)
            _set_status(self.status, "格式: %s | 风险: %s" % (
                r.get("format", "?"), r.get("risk", "?")), "ok")

        _run_async(self, _mod("screener", "analyze_fingerprint_format"), cb, p)

    def _fmt_preview(self):
        """生成可信替换预览（只读不写盘）。"""
        p = self._fmt_path()
        if not p:
            return
        _set_status(self.status, "生成替换预览中…", "run")

        def cb(r):
            if not isinstance(r, dict):
                _set_status(self.status, "预览失败: %s" % r, "err")
                return
            if r.get("error"):
                _set_status(self.status, "预览失败: %s" % r["error"], "err")
                return
            self.ai_out.setPlainText(json_dump(r))
            _set_status(self.status, "替换预览已生成（未写盘）", "ok")

        _run_async(self, _mod("screener", "generate_trusted_fingerprint"), cb, p)

    def _fp_guidance(self):
        """AI 指纹修改指导（带强制安全自检，只读不执行）。"""
        p = self._fmt_path()
        if not p:
            return
        q = self.fp_q.text().strip() or "请告诉我这个指纹文件的作用、格式规则，以及如何安全修改它（保持软件信任）。"
        _set_status(self.status, "AI 安全自检与指导生成中…", "run")

        def cb(r):
            if not isinstance(r, dict):
                _set_status(self.status, "AI 指导失败: %s" % r, "err")
                return
            if r.get("error"):
                _set_status(self.status, "AI 指导失败: %s" % r["error"], "err")
                return
            text = json_dump(r)
            self.ai_out.setPlainText(text)
            passed = r.get("safety_check_passed")
            _set_status(self.status,
                        "AI 指导完成（%s）" % ("已通过【已检查】" if passed else "⚠️ 安全自检未通过"),
                        "ok" if passed else "warn")

        _run_async(self, _mod("screener", "fingerprint_guidance"), cb, q, p)

    def _filter(self):
        cat = self.f_cat.currentText()
        risk = self.f_risk.currentText()
        rows = self._items
        if cat != "全部":
            rows = [i for i in rows if i.get("category") == cat]
        if risk != "全部":
            rows = [i for i in rows if i.get("risk") == risk]
        self._viewed = rows
        _fill_table(self.table, rows, 1000)

    def _selected(self):
        r = self.table.currentRow()
        return self._viewed[r] if 0 <= r < len(self._viewed) else None

    def _mark(self):
        it = self._selected()
        if not it:
            QMessageBox.warning(self, "提示", "请先选中一行")
            return
        _set_status(self.status, "标记入库中…", "run")

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "标记失败: %s" % r["error"], "err")
                QMessageBox.warning(self, "标记失败", r["error"])
                return
            it["state"] = "已标记"
            self._filter()
            _set_status(self.status, "已标记入库 obs#%s" % r, "ok")
        # 走 _run_async：mark_item 内含 SQLite 写库，不得阻塞 GUI 线程
        _run_async(self, _mod("screener", "mark_item"), cb,
                   it.get("name", "?"), it.get("category", "其他"),
                   self.m_risk.currentText(), it.get("detail", ""),
                   self.m_note.text().strip())

    def _ai(self):
        if not self._result or not self._items:
            QMessageBox.warning(self, "提示", "请先执行一次筛查")
            return
        self.ai_out.setPlainText("AI 分析中（只读辅助）...")

        def cb(r):
            if isinstance(r, dict) and r.get("ok"):
                self.ai_out.setPlainText(r["text"])
            elif isinstance(r, dict) and r.get("error"):
                self.ai_out.setPlainText("错误: %s" % r["error"])
            else:
                self.ai_out.setPlainText(str(r))

        _run_async(self, _mod("screener", "analyze_with_ai"), cb, self._result)

    def _trace_scan(self):
        kw = self.trace_kw.text().strip()
        if not kw:
            QMessageBox.warning(self, "提示", "请输入软件关键词")
            return
        self._trace_items = []
        _set_status(self.status, "留样扫描中（不依赖安装目录）…", "run")

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "错误: %s" % r["error"], "err")
                return
            self._trace_items = (r or {}).get("items", []) or []
            rows = [{"type": it.get("type"), "name": it.get("name"),
                     "target": it.get("target"), "risk": it.get("risk"),
                     "detail": it.get("detail")} for it in self._trace_items]
            _fill_table(self.trace_table, rows, 2000)
            s = (r or {}).get("summary") or {}
            _set_status(self.status, "留样：共%d 高%d 中%d 低%d" % (
                s.get("total", 0), s.get("high", 0), s.get("med", 0), s.get("low", 0)), "ok")

        _run_async(self, _mod("screener", "scan_software_traces"), cb,
                   kw, self.dir1.text().strip())

    def _trace_preview(self):
        """只读预览清理清单（不执行、不建还原点）。"""
        if not self._trace_items:
            QMessageBox.warning(self, "提示", "请先执行留样扫描")
            return
        _set_status(self.status, "只读预览中…", "run")

        def cb(r):
            if isinstance(r, dict) and r.get("error"):
                _set_status(self.status, "预览失败: %s" % r["error"], "err")
                return
            if not isinstance(r, dict):
                _set_status(self.status, "预览失败: %s" % r, "err")
                return
            will_clean = (r or {}).get("will_clean", [])
            will_deny = (r or {}).get("will_deny", [])
            lines = ["将清理 %d 项 | 将拒绝 %d 项" % (len(will_clean), len(will_deny)), ""]
            lines.append("—— 将清理 ——")
            for x in will_clean[:50]:
                lines.append("  [%s] %s" % (x.get("type", "?"), x.get("target", "")))
            if len(will_clean) > 50:
                lines.append("  … 还有 %d 项" % (len(will_clean) - 50))
            lines.append("")
            lines.append("—— 将拒绝 ——")
            for x in will_deny[:30]:
                lines.append("  [%s] %s" % (x.get("reason", "?"), x.get("target", "")))
            self.trace_out.setPlainText("\n".join(lines))
            _set_status(self.status, "预览完成：将清理 %d 项，拒绝 %d 项" % (
                len(will_clean), len(will_deny)), "ok")

        _run_async(self, _mod("screener", "preview_cleanup"), cb, self._trace_items)

    def _trace_cleanup(self):
        if not self._trace_items:
            QMessageBox.warning(self, "提示", "请先执行留样扫描")
            return
        rows = self.trace_table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.warning(self, "提示", "请先勾选要清理的项（可多选）")
            return
        items = [self._trace_items[r.row()] for r in rows
                 if 0 <= r.row() < len(self._trace_items)]
        reason, ok = QInputDialog.getText(self, "清理原因",
                                          "清理原因（至少 12 字：目的、对象、必要性）")
        if not ok or len(reason.strip()) < 12:
            QMessageBox.warning(self, "原因不足", "必须填写至少 12 字的清理原因")
            return

        def preview_cb(pv):
            # 预览失败必须中止：绝不允许"预览不可用"绕过人工确认直接删除
            if not isinstance(pv, dict) or pv.get("error"):
                err = pv.get("error", "未知错误") if isinstance(pv, dict) else pv
                QMessageBox.warning(self, "预览失败",
                                    "清理预览未完成（%s），已中止。请重试或手动核查勾选项。" % err)
                _set_status(self.status, "预览失败，已中止清理", "err")
                return
            clean_lines = "\n".join("  [清理] %s  %s" % (x.get("type"), x.get("target"))
                                    for x in pv.get("will_clean", []))
            deny_lines = "\n".join("  [拒绝] %s  %s" % (x.get("reason"), x.get("target"))
                                   for x in pv.get("will_deny", []))
            msg = ("即将清理 %d 项，拒绝 %d 项：\n\n%s\n\n将拒绝（系统身份/核心范围等）：\n%s\n\n"
                   "清理前会先创建系统还原点，删除项备份到 backups/quarantine。确认继续？" % (
                       pv.get("clean_count", 0), pv.get("deny_count", 0),
                       clean_lines or "（无）", deny_lines or "（无）"))
            if QMessageBox.question(self, "清理前预览", msg) == QMessageBox.StandardButton.Yes:
                self._do_cleanup(items, reason.strip())
            else:
                _set_status(self.status, "已取消", "info")

        _run_async(self, _mod("screener", "preview_cleanup"), preview_cb, items)

    def _do_cleanup(self, items, reason):
        _set_status(self.status, "正在创建系统还原点并清理…", "run")

        def cb(r):
            if isinstance(r, dict) and r.get("ok"):
                self.trace_out.setPlainText(json_dump(r))
                denied = len((r or {}).get("denied") or [])
                _set_status(self.status, "清理完成：成功 %d/%d%s；备份目录 %s" % (
                    r.get("ok_count", 0), r.get("total", 0),
                    "，已拒绝 %d 项" % denied if denied else "",
                    r.get("quarantine", "")), "ok")
            else:
                _set_status(self.status, "清理失败: %s" % r.get("error", r), "err")

        _run_async(self, _mod("screener", "cleanup_traces"), cb, items, reason)

    def _trace_restore(self):
        qd = self.restore_dir.text().strip()
        if not qd:
            QMessageBox.warning(self, "提示", "请输入备份目录（清理结果里的 quarantine）")
            return
        if QMessageBox.question(self, "确认恢复",
                "将从 %s 恢复被清理的项。确认继续？" % qd) != QMessageBox.StandardButton.Yes:
            return
        _set_status(self.status, "正在从备份恢复…", "run")

        def cb(r):
            if isinstance(r, dict) and r.get("ok"):
                self.trace_out.setPlainText(json_dump(r))
                _set_status(self.status, "恢复完成：成功 %d/%d" % (
                    r.get("ok_count", 0), r.get("total", 0)), "ok")
            else:
                _set_status(self.status, "恢复失败: %s" % r.get("error", r), "err")

        _run_async(self, _mod("screener", "restore_traces"), cb, qd)
