function vScreener() {
  const body = viewTemplate("v_screener", "筛查工作台", "M11 · SCREENER", "shield", "recon", ({ body, output, log }) => {
    // 最近一次留样扫描的 items（用于 preview_cleanup / cleanup_traces）
    let lastTraceItems = [];
    // 最近一次通用/文件筛查的结果（用于 analyze_with_ai 传参）
    let lastScanResult = null;
    // ① 通用扫描
    const dir = input("残留/指纹扫描目录（可选）");
    const scanSusp = btn("扫描可疑 APP", async () => {
      await run("screener", async () => {
        const r = await api("screener", "scan_suspicious_apps");
        if (bizFail(r)) throw new Error("扫描失败：" + bizErr(r));
        lastScanResult = r;
        output.innerHTML = ""; output.appendChild(table((r && r.items) || [], "可疑 APP"));
        return (r && r.summary) || {};
      }, "扫描完成");
    });
    const scanLeft = btn("扫描残留", async () => {
      await run("screener", async () => {
        const r = await api("screener", "scan_leftover", { install_dir: dir.value || "" });
        if (bizFail(r)) throw new Error("扫描失败：" + bizErr(r));
        lastScanResult = r;
        output.innerHTML = ""; output.appendChild(table((r && r.items) || [], "残留"));
        return (r && r.summary) || {};
      }, "扫描完成");
    });
    const scanFp = btn("指纹扫描", async () => {
      await run("screener", async () => {
        const r = await api("screener", "scan_fingerprints", { base_dir: dir.value || "" });
        if (bizFail(r)) throw new Error("扫描失败：" + bizErr(r));
        lastScanResult = r;
        output.innerHTML = ""; output.appendChild(table((r && r.items) || [], "指纹"));
        return (r && r.summary) || {};
      }, "扫描完成");
    });
    body.appendChild(card("① 通用扫描", [
      formRow([["扫描目录", dir]]),
      toolbar([scanSusp, scanLeft, scanFp], { primary: true }),
    ]));

    // ② 单文件 / 追踪
    const filePath = input("文件路径（py/exe/dll/class）");
    const tName = input("追踪目标名");
    const tExe = input("目标 exe 路径");
    const checkFile = btn("检查文件", async () => {
      await run("screener", async () => {
        const r = await api("screener", "check_file", { path: filePath.value });
        if (bizFail(r)) throw new Error("检查失败：" + bizErr(r));
        lastScanResult = r;
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "完成");
    });
    const trackApp = btn("追踪 APP", async () => {
      await run("screener", async () => {
        const r = await api("screener", "track_app",
          { name: tName.value, exe: tExe.value || "" });
        if (bizFail(r)) throw new Error("追踪失败：" + bizErr(r));
        lastScanResult = r;
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "完成");
    });
    const analyze = btn("AI 辅助分析", async () => {
      if (!lastScanResult || !(lastScanResult.items && lastScanResult.items.length)) {
        toast("请先执行一次筛查（通用扫描 / 检查文件 / 追踪）再分析", "warn"); return;
      }
      await run("screener", async () => {
        const r = await api("screener", "analyze_with_ai", { result: lastScanResult });
        if (bizFail(r)) throw new Error("AI 分析失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "AI 完成");
    });
    body.appendChild(card("② 单文件 / 追踪", [
      formRow([["文件", filePath], ["目标名", tName], ["exe", tExe]]),
      toolbar([checkFile, trackApp, analyze]),
    ]));

    // ③ 留样扫描 + 批量清理 + 恢复
    const traceKw = input("软件关键词（如 Qoder）");
    const restoreDir = input("恢复目录（清理结果里的 quarantine）");
    const traceSelected = { v: [] };
    const scanTraces = btn("留样扫描", async () => {
      await run("screener", async () => {
        const r = await api("screener", "scan_software_traces",
          { keyword: traceKw.value, install_dir: dir.value || "" });
        if (bizFail(r)) throw new Error("扫描失败：" + bizErr(r));
        lastTraceItems = (r && r.items) || [];
        output.innerHTML = ""; output.appendChild(traceTable(lastTraceItems, "留样清单", traceSelected));
        return (r && r.summary) || {};
      }, "扫描完成");
    });
    const previewBtn = btn("预览清理（不执行）", async () => {
      if (!lastTraceItems.length) { toast("请先执行留样扫描", "warn"); return; }
      await run("screener", async () => {
        const r = await api("screener", "preview_cleanup", { items: lastTraceItems });
        if (bizFail(r)) throw new Error("预览失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const cleanupBtn = btn("批量清理（先还原点+备份）", async () => {
      const sel = traceSelected.v;
      if (!sel.length) { toast("请先执行留样扫描并勾选项目", "warn"); return; }
      const reason = window.prompt("请填写清理原因（≥12 字：目的、对象、必要性）");
      if (!reason || reason.length < 12) {
        toast("原因不足 12 字，已取消", "warn"); return;
      }
      await run("screener", async () => {
        const prev = await api("screener", "preview_cleanup", { items: sel });
        if (bizFail(prev)) throw new Error("预览失败：" + bizErr(prev));
        const willClean = (prev && prev.will_clean) || [];
        const willDeny = (prev && prev.will_deny) || [];
        if (!willClean.length) {
          throw new Error("没有可清理的项（" + willDeny.length + " 项被安全门禁拒绝）");
        }
        const summary = "将清理 " + willClean.length + " 项；" + willDeny.length +
          " 项将被拒绝（系统身份/受保护范围，即使提交也会跳过）。\n\n" +
          JSON.stringify(prev, null, 2);
        if (!confirm(summary + "\n\n确认执行清理？")) return;
        const cleanItems = willClean.map(x => ({ type: x.type, target: x.target }));
        const r = await api("screener", "cleanup_traces",
          { items: cleanItems, reason });
        if (bizFail(r)) throw new Error("清理失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "清理完成");
    });
    const restoreBtn = btn("一键恢复", async () => {
      if (!restoreDir.value.trim()) { toast("请填写恢复目录（清理结果里的 quarantine）", "warn"); return; }
      await run("screener", async () => {
        const r = await api("screener", "restore_traces", { quarantine_dir: restoreDir.value });
        if (bizFail(r)) throw new Error("恢复失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "已恢复");
    });
    body.appendChild(card("③ 留样扫描 / 勾选清理 / 恢复", [
      formRow([["关键词", traceKw], ["恢复目录", restoreDir]]),
      toolbar([scanTraces, previewBtn, cleanupBtn, restoreBtn], { primary: true }),
      hint("清理会先创建 Windows 系统还原点，删除项备份到 backups/quarantine；"
         + " 系统身份范围（MachineGuid/BIOS/网卡）确定性拒绝。"),
    ]));

    // ④ 机器指纹文件扫描
    const fpKw = input("关键词过滤（留空=全部，可填厂商/产品名如 Qoder/Cursor/Chrome）");
    const fpBtn = btn("扫描已知指纹文件", async () => {
      await run("screener", async () => {
        const r = await api("screener", "scan_machine_fingerprints", { keyword: fpKw.value || "" });
        if (bizFail(r)) throw new Error("指纹扫描失败：" + bizErr(r));
        lastScanResult = r;
        output.innerHTML = ""; output.appendChild(table((r && r.items) || [], "机器指纹文件"));
        return (r && r.summary) || {};
      }, "指纹扫描完成");
    });
    const fpGenBtn = btn("扫描未知指纹内容", async () => {
      await run("screener", async () => {
        const r = await api("screener", "scan_generic_fingerprints", { keyword: fpKw.value || "" });
        if (bizFail(r)) throw new Error("通用指纹扫描失败：" + bizErr(r));
        lastScanResult = r;
        output.innerHTML = ""; output.appendChild(table((r && r.items) || [], "未知指纹候选"));
        return (r && r.summary) || {};
      }, "通用指纹扫描完成");
    });
    body.appendChild(card("④ 机器指纹文件扫描（设备唯一标识/令牌/状态）", [
      formRow([["关键词过滤", fpKw]]),
      toolbar([fpBtn, fpGenBtn], { primary: true }),
      hint("已知指纹：Qoder/Cursor/Windsurf/Chrome/Edge/VSCode 等的 machineid、DIPS、Client ID、auth token；"
         + "未知指纹：不依赖清单，按文件名关键词 + UUID/长十六进制内容判定。"),
    ]));

    // ④½ 指纹编码格式逆向（可信改写支持）
    const fmtPath = input("指纹文件路径（machineid / Local State / DIPS 等）", "wide");
    const fmtBtn = btn("逆向解析格式", async () => {
      if (!fmtPath.value.trim()) { toast("请填写指纹文件路径", "warn"); return; }
      await run("screener", async () => {
        const r = await api("screener", "analyze_fingerprint_format", { path: fmtPath.value.trim() });
        if (bizFail(r)) throw new Error("格式解析失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "格式: " + (r && r.format);
      }, "格式解析完成");
    });
    const fmtGenBtn = btn("生成可信替换预览", async () => {
      if (!fmtPath.value.trim()) { toast("请填写指纹文件路径", "warn"); return; }
      await run("screener", async () => {
        const r = await api("screener", "generate_trusted_fingerprint", { path: fmtPath.value.trim() });
        if (bizFail(r)) throw new Error("替换预览失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已生成替换预览（未写盘）";
      }, "替换预览完成");
    });
    body.appendChild(card("④½ 指纹编码逆向（防改写后不信任重建）", [
      formRow([["文件路径", fmtPath]]),
      toolbar([fmtBtn, fmtGenBtn], { primary: true }),
      hint("逆向常见编码格式（SQLite/JSON/DPAPI/UUID/hex），输出创建规则与改写指导；"
         + "生成符合规则的替换值预览（只读不写盘），避免改坏后软件判不信任而重新制造指纹。"),
    ]));

    // ⑤ AI 指纹修改指导（带强制安全自检）
    const aiPath = input("指纹文件路径（留空则使用上面④½的路径）", "wide");
    const aiQ = textarea("想问什么？（如：如何安全修改 machineid 让 Qoder 仍信任）", "", 2);
    const aiBtn = btn("AI 指导（安全自检）", async () => {
      const p = aiPath.value.trim() || fmtPath.value.trim();
      if (!p) { toast("请填写指纹文件路径", "warn"); return; }
      await run("screener", async () => {
        const r = await api("screener", "fingerprint_guidance",
          { question: aiQ.value || "", path: p });
        if (bizFail(r)) throw new Error("AI 指导失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return (r && r.safety_check_passed) ? "【已通过安全自检】" : "⚠️ 安全自检未通过";
      }, "AI 指导完成");
    });
    body.appendChild(card("⑤ AI 指纹修改指导（强制安全自检·绝不自动执行）", [
      formRow([["文件路径", aiPath], ["问题", aiQ]]),
      toolbar([aiBtn], { primary: true }),
      hint("AI 会在回答前强制自检：①是否绕过付费墙？②是否损害系统？"
         + "通过自检的回答开头会标注【已检查】。绝不自动执行任何命令，所有步骤须人工审查后手动操作。"),
    ]));

    // ⑥ 深潜扫描（Prefetch / 使用历史 / WER）
    const deepKw = input("软件关键词（如 Qoder）");
    const pfBtn = btn("Prefetch 执行痕迹", async () => {
      if (!deepKw.value.trim()) { toast("请先填写软件关键词", "warn"); return; }
      await run("screener", async () => {
        const r = await api("screener", "scan_prefetch_traces", { keyword: deepKw.value.trim() });
        if (bizFail(r)) throw new Error("Prefetch 扫描失败：" + bizErr(r));
        lastScanResult = r;
        output.innerHTML = ""; output.appendChild(table((r && r.items) || [], "Prefetch 执行痕迹"));
        return (r && r.summary) || {};
      }, "Prefetch 扫描完成");
    });
    const usageBtn = btn("注册表使用历史", async () => {
      if (!deepKw.value.trim()) { toast("请先填写软件关键词", "warn"); return; }
      await run("screener", async () => {
        const r = await api("screener", "scan_usage_history", { keyword: deepKw.value.trim() });
        if (bizFail(r)) throw new Error("使用历史扫描失败：" + bizErr(r));
        lastScanResult = r;
        output.innerHTML = ""; output.appendChild(table((r && r.items) || [], "使用历史（MuiCache/UserAssist/AppCompat/BAM）"));
        return (r && r.summary) || {};
      }, "使用历史扫描完成");
    });
    const werBtn = btn("WER 崩溃报告", async () => {
      if (!deepKw.value.trim()) { toast("请先填写软件关键词", "warn"); return; }
      await run("screener", async () => {
        const r = await api("screener", "scan_wer_traces", { keyword: deepKw.value.trim() });
        if (bizFail(r)) throw new Error("WER 扫描失败：" + bizErr(r));
        lastScanResult = r;
        output.innerHTML = ""; output.appendChild(table((r && r.items) || [], "WER 崩溃报告残留"));
        return (r && r.summary) || {};
      }, "WER 扫描完成");
    });
    body.appendChild(card("⑥ 深潜扫描（卸载后仍残留的隐藏痕迹）", [
      formRow([["关键词", deepKw]]),
      toolbar([pfBtn, usageBtn, werBtn], { primary: true }),
      hint("Prefetch：程序每次运行生成的 .pf 执行痕迹；使用历史：MuiCache 应用名缓存 + UserAssist 运行计数（ROT13）"
         + " + AppCompat 兼容性记录 + BAM 系统级执行时间戳；WER：崩溃报告残留。全部在软件卸载后仍保留。"),
    ]));

    // ⑥½ 文件夹&注册表扫描（宽泛 → 细扫 → 关联指导）
    const frDir = input("定向细扫目录（细扫时必填）", "wide");
    const frBroadBtn = btn("宽泛扫描（文件系统+注册表）", async () => {
      await run("screener", async () => {
        const r = await api("screener", "broad_scan");
        if (bizFail(r)) throw new Error("宽泛扫描失败：" + bizErr(r));
        lastScanResult = r;
        output.innerHTML = ""; output.appendChild(table((r && r.items) || [], "宽泛扫描"));
        return (r && r.summary) || {};
      }, "宽泛扫描完成");
    });
    const frDeepBtn = btn("定向细扫", async () => {
      if (!frDir.value.trim()) { toast("请填写要细扫的目录路径", "warn"); return; }
      await run("screener", async () => {
        const r = await api("screener", "deep_dir_scan", { dir_path: frDir.value.trim() });
        if (bizFail(r)) throw new Error("细扫失败：" + bizErr(r));
        lastScanResult = r;
        output.innerHTML = ""; output.appendChild(table((r && r.items) || [], "细扫分析"));
        return (r && r.summary) || {};
      }, "细扫完成");
    });
    const frCorrBtn = btn("关联分析与指导", async () => {
      if (!lastScanResult || !(lastScanResult.items && lastScanResult.items.length)) {
        toast("请先执行一次扫描（宽泛/细扫/留样均可）再关联", "warn"); return;
      }
      await run("screener", async () => {
        const r = await api("screener", "correlate_findings", { result: lastScanResult });
        if (bizFail(r)) throw new Error("关联失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        const s = (r && r.summary) || {};
        return "聚类 " + s.clusters + " 个（高" + s.high + "）";
      }, "关联完成");
    });
    body.appendChild(card("⑥½ 文件夹&注册表扫描（宽泛 → 细扫 → 关联指导）", [
      formRow([["目录", frDir]]),
      toolbar([frBroadBtn, frDeepBtn, frCorrBtn], { primary: true }),
      hint("宽泛：用户目录/下载桌面/TEMP/回收站 + 注册表常驻点位（Run/Winlogon/IFEO/AppInit/服务/Active Setup）"
         + " + 计划任务无差别列举（宁错杀不放过，带预算上限）；细扫：对单独目录做哈希/熵指纹级深挖并联动注册表与"
         + " Prefetch 执行痕迹；关联：跨来源聚类成证据组并给出确定性处置指导与总体行动计划。全程只读。"),
    ]));

    // ⑦ 标记入库（检修 2026-08-27：改为提交真实勾选条目——旧实现把类别输入框
    // 的字符串当 name/category 写库，每次点击都插入垃圾观察记录并回流经验库）
    const mRisk = select(["高", "中", "低", "无"], "中");
    const mNote = input("备注（可选）");
    const markBtn = btn("标记选中入库", async () => {
      const sel = pickedRows.v.filter(x => x && typeof x === "object");
      if (!sel.length) {
        toast("请先执行扫描，再在「⑧ 结果筛选」里勾选要入库的条目", "warn"); return;
      }
      await run("screener", async () => {
        let done = 0;
        for (const it of sel) {
          const r = await api("screener", "mark_item",
            { name: it.name || it.target || "(未命名)",
              category: it.category || "suspicious",
              risk: it.risk || mRisk.value,
              detail: String(it.detail || ""),
              note: mNote.value });
          if (bizFail(r)) throw new Error("标记失败：" + bizErr(r));
          done++;
        }
        output.innerHTML = ""; output.appendChild(jsonBlock({ marked: done }));
        return "已入库 " + done + " 条";
      }, "已标记");
    });
    body.appendChild(card("⑦ 标记入库（先在⑧筛选结果中勾选，再入库 observations）", [
      formRow([["兜底风险", mRisk], ["备注", mNote]]),
      toolbar([markBtn]),
    ]));

    // ⑧ 结果筛选（检修 2026-08-27：原 lastItems 声明后从未赋值，applyFilter 永远
    // 渲染空表——现直接从 lastScanResult.items 取数；表格改用带勾选的 traceTable，
    // 勾选结果供⑦标记入库）
    const fCat = select(["全部", "可疑APP", "残留", "留样", "机器指纹", "执行痕迹", "使用历史", "崩溃痕迹"], "全部");
    const fRisk = select(["全部", "高", "中", "低", "无"], "全部");
    const pickedRows = { v: [] };
    const currentItems = () =>
      (lastScanResult && Array.isArray(lastScanResult.items)) ? lastScanResult.items : [];
    const applyFilter = () => {
      let rows = currentItems();
      pickedRows.v = [];
      const catMap = { "可疑APP": "可疑APP", "残留": "残留", "留样": "留样",
        "机器指纹": "机器指纹", "执行痕迹": "执行痕迹", "使用历史": "使用历史",
        "崩溃痕迹": "崩溃痕迹" };
      if (fCat.value !== "全部") rows = rows.filter(x => x.category === catMap[fCat.value]);
      if (fRisk.value !== "全部") rows = rows.filter(x => x.risk === fRisk.value);
      output.innerHTML = "";
      output.appendChild(traceTable(rows, "筛选结果（勾选后在⑦标记入库）", pickedRows));
    };
    fCat.onchange = applyFilter;
    fRisk.onchange = applyFilter;
    body.appendChild(card("⑧ 结果筛选", [
      formRow([["类别", fCat], ["风险", fRisk]]),
      hint("按类别或风险过滤最近一次扫描结果；勾选条目后可到⑦一键标记入库。"),
    ]));
  });
}

/* ============================================================
   M2 注册表搜索
   ============================================================ */
