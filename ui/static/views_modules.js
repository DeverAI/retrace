function vRegscan() {
  const body = viewTemplate("v_regscan", "注册表搜索", "M2 · REGSCAN", "list", "recon", ({ output }) => {
    const kw = input("关键词");
    const root = select(["HKLM", "HKCU", "HKU", "ALL"], "HKLM");
    const mode = select([["包含", "contains"], ["精确值", "exact"], ["路径", "path"]], "contains");
    const btn1 = btn("搜索", async () => {
      await run("regscan", async () => {
        const r = await api("regscan", "search",
          { keyword: kw.value, root: root.value, mode: mode.value, max_hits: 500 });
        if (bizFail(r)) throw new Error("搜索失败：" + bizErr(r));
        const hits = (r && r.hits) || (Array.isArray(r) ? r : []);
        output.innerHTML = ""; output.appendChild(table(hits, "注册表命中"));
        return hits.length + " 条";
      }, "搜索完成");
    }, false, true);
    onEnter(kw, btn1);
    const btn2 = btn("扫描自启动/COM/服务点位", async () => {
      await run("regscan", async () => {
        const r = await api("regscan", "autostart_points", { root: root.value });
        output.innerHTML = ""; output.appendChild(table(r || [], "常驻点位"));
        return (r || []).length + " 条";
      });
    });
    const btn3 = btn("读精确值", async () => {
      const sub = (window.prompt("HKCU\\子键") || "").trim();
      const clean = sub.replace(/^\\+/, "").replace(/^HKCU\\/i, "");
      if (!clean) { toast("子键不能为空", "warn"); return; }
      const name = window.prompt("值名（可空）");
      await run("regscan", async () => {
        const keyPath = "HKCU\\" + clean;
        const r = await api("regscan", "read_value", { key_path: keyPath, name: name || "" });
        if (bizFail(r)) throw new Error("读取失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });

    // ② 观察键管理（与 M7 watcher 联动的注册表基线）
    const watchKey = input("观察键（如 HKLM\\SOFTWARE\\...\\Run）", "wide");
    let lastWatchSnap = null;
    const addWatchBtn = btn("添加观察", async () => {
      if (!watchKey.value.trim()) { toast("请输入观察键", "warn"); return; }
      await run("regscan", async () => {
        const r = await api("regscan", "add_watch", { key_path: watchKey.value.trim() });
        if (bizFail(r)) throw new Error("添加失败：" + bizErr(r));
        return "已添加观察";
      }, "已添加");
    });
    const removeWatchBtn = btn("移除观察", async () => {
      if (!watchKey.value.trim()) { toast("请输入观察键", "warn"); return; }
      await run("regscan", async () => {
        const r = await api("regscan", "remove_watch", { key_path: watchKey.value.trim() });
        if (bizFail(r)) throw new Error("移除失败：" + bizErr(r) + "（可能本就不在观察列表）");
        return "已移除";
      }, "已移除");
    });
    const listWatchBtn = btn("查看观察列表", async () => {
      await run("regscan", async () => {
        const r = await api("regscan", "list_watches", {});
        output.innerHTML = ""; output.appendChild(table(r || [], "观察键"));
        return (r || []).length + " 个";
      }, "已加载");
    });
    const snapWatchBtn = btn("快照观察键", async () => {
      await run("regscan", async () => {
        const r = await api("regscan", "snapshot_watches", {});
        lastWatchSnap = r;
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已快照（可再点「对比快照」）";
      }, "已快照");
    });
    const diffWatchBtn = btn("对比两次快照", async () => {
      if (!lastWatchSnap) { toast("请先点「快照观察键」做一次快照", "warn"); return; }
      await run("regscan", async () => {
        const after = await api("regscan", "snapshot_watches", {});
        const r = await api("regscan", "diff_watches", { before: lastWatchSnap, after });
        lastWatchSnap = after;
        output.innerHTML = ""; output.appendChild(table(r || [], "观察键变化"));
        return (r || []).length + " 处变化";
      }, "已对比");
    });

    body.appendChild(card("① 搜索", [
      formRow([["关键词", kw], ["根键", root], ["模式", mode]]),
      toolbar([btn1, btn2, btn3], { primary: true }),
      hint("搜索：关键词/路径/值名/值数据；自启动：HKCU/HKLM Run/RunOnce + 服务 + COM InprocServer32 + IFEO 等漏洞常驻点位。"),
    ]));
    body.appendChild(card("② 观察键管理（供 M7 集中观察做基线 diff）", [
      formRow([["观察键", watchKey]]),
      toolbar([addWatchBtn, removeWatchBtn, listWatchBtn, "spacer", snapWatchBtn, diffWatchBtn], { primary: true }),
      hint("快照→（等 APP 运行一段时间）→对比快照，得到注册表值的变化清单。"),
    ]));
    body.appendChild(card("③ 结果", [output]));
  });
}

/* ============================================================
   M3 经验检索
   ============================================================ */
function vEmbed() {
  const body = viewTemplate("v_embed", "经验检索", "M3 · EMBEDDING", "search", "analysis", ({ output }) => {
    const q = input("检索关键词");
    const topK = input("Top K", "", "10");
    const btn1 = btn("检索", async () => {
      await run("embed", async () => {
        const r = await api("embedding", "search",
          { query: q.value, top_k: Number(topK.value) || 10 });
        output.innerHTML = ""; output.appendChild(table(r || [], "语义检索结果"));
        return (r || []).length + " 条";
      }, "检索完成");
    }, false, true);
    onEnter(q, btn1);

    const memo = textarea("新经验文本（点击「记住入库」按当前 provider 编码）", "", 3);
    const btn2 = btn("记住入库", async () => {
      await run("embed", async () => {
        const r = await api("embedding", "remember",
          { text: memo.value, meta: { source: "web" } });
        if (bizFail(r)) throw new Error("入库失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        memo.value = "";
        return "已入库 #" + r;
      }, "已入库");
    });
    const btn3 = btn("查看 provider / 索引状态", async () => {
      await run("embed", async () => {
        const prov = await api("embedding", "provider").catch(() => null);
        const stats = await api("embedding", "stats").catch(() => null);
        if (prov === null && stats === null) {
          throw new Error("无法获取 embedding 状态（模块可能已关闭）");
        }
        output.innerHTML = ""; output.appendChild(jsonBlock({ provider: prov, stats }));
        return "完成";
      });
    });
    const btn4 = btn("编码单条文本", async () => {
      const text = memo.value;
      await run("embed", async () => {
        const vec = await api("embedding", "embed", { text });
        const v = Array.isArray(vec) ? vec : [];
        output.innerHTML = ""; output.appendChild(jsonBlock({
          text_len: (text || "").length, vec_len: v.length, vec_head: v.slice(0, 12)
        }));
        return "已编码（" + v.length + " 维）";
      }, "已编码");
    });
    const btn5 = btn("保存索引到磁盘", async () => {
      await run("embed", async () => {
        const r = await api("embedding", "save_index", {});
        if (bizFail(r)) throw new Error("保存失败：" + bizErr(r));
        return "索引已写入 embedding_index.json";
      }, "已保存");
    });

    body.appendChild(card("① 语义检索", [
      formRow([["查询", q], ["Top K", topK]]),
      toolbar([btn1], { primary: true }),
    ]));
    body.appendChild(card("② 写入新经验", [memo, toolbar([btn2, btn4])]));
    body.appendChild(card("③ 调试 / 状态", [toolbar([btn3, btn5]), output]));
  });
}

/* ============================================================
   M6 多类别反编译
   ============================================================ */
function vDecompile() {
  const body = viewTemplate("v_decompile", "多类别反编译", "M6 · DECOMPILE", "code", "analysis", ({ output }) => {
    const path = input("文件路径（py/exe/dll/class）", "wide");
    const btnRun = btn("反编译分析", async () => {
      await run("decompile", async () => {
        const r = await api("decompile", "analyze", { path: path.value });
        if (bizFail(r)) throw new Error("分析失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "分析完成");
    }, false, true);
    onEnter(path, btnRun);
    const btnAudit = btn("AI 审计（danger≥0.5 调用）", async () => {
      await run("decompile", async () => {
        const r = await api("decompile", "ai_audit", { path: path.value });
        if (bizFail(r)) throw new Error("审计失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "AI 完成";
      }, "审计完成");
    });

    body.appendChild(card("① 目标", [
      formRow([["文件", path]]),
      toolbar([btnRun, btnAudit], { primary: true }),
      hint("支持 Python 字节码（受子进程隔离）/ PE32+ / Java .class；纯本地解析，"
         + "AI 审计由全局 ai Agent 仅以只读顾问身份对 danger≥0.5 调用做语义分级。"),
    ]));
    body.appendChild(card("② 结果", [output]));
  });
}

/* ============================================================
   M7 APP 集中观察（watcher + remove + status + snapshot）
   ============================================================ */
function vWatcher() {
  const body = viewTemplate("v_watcher", "APP 集中观察", "M7 · WATCHER", "eye", "flow", ({ output }) => {
    const name = input("目标名");
    const exe = input("exe 路径（可选）");
    const limit = input("时间线条数", "", "300");
    const addBtn = btn("添加目标", async () => {
      await run("watcher", async () => {
        const r = await api("watcher", "add_target",
          { name: name.value, exe: exe.value || null });
        if (bizFail(r)) throw new Error("添加失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已添加";
      });
    });
    const removeBtn = btn("删除目标", async () => {
      if (!name.value) { toast("请先填写目标名", "warn"); return; }
      if (!confirm("确认删除观察目标 " + name.value + "？")) return;
      await run("watcher", async () => {
        const r = await api("watcher", "remove_target", { name: name.value });
        if (bizFail(r)) throw new Error("删除失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已删除";
      }, "已删除");
    });
    const startBtn = btn("启动观察", async () => {
      await run("watcher", async () => {
        const r = await api("watcher", "start");
        if (bizFail(r)) throw new Error("启动失败：" + bizErr(r));
        return "已启动";
      });
    });
    const stopBtn = btn("停止", async () => {
      await run("watcher", async () => {
        const r = await api("watcher", "stop");
        if (bizFail(r)) throw new Error("停止失败：" + bizErr(r));
        return "已停止";
      });
    });
    const tlBtn = btn("查看时间线", async () => {
      await run("watcher", async () => {
        const r = await api("watcher", "timeline_entries",
          { limit: Number(limit.value) || 300 });
        output.innerHTML = ""; output.appendChild(table(r || [], "时间线"));
        return (r || []).length + " 条";
      }, "已加载");
    });
    const statusBtn = btn("查看状态", async () => {
      await run("watcher", async () => {
        const r = await api("watcher", "status");
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const snapBtn = btn("生成目标快照", async () => {
      if (!name.value) { toast("请先填写目标名", "warn"); return; }
      await run("watcher", async () => {
        const r = await api("watcher", "snapshot_target", { name: name.value });
        if (r === null || r === undefined) throw new Error("目标不存在（请先添加目标）");
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });

    body.appendChild(card("① 目标 + 控制", [
      formRow([["目标名", name], ["exe", exe], ["条数", limit]]),
      toolbar([addBtn, removeBtn, "spacer", startBtn, stopBtn], { primary: true }),
    ]));
    body.appendChild(card("② 时间线 / 快照", [
      toolbar([tlBtn, statusBtn, snapBtn]),
      hint("时间线包含已注册的进程/文件/注册表事件；快照用于无时间线时的瞬时比对。"),
    ]));
    body.appendChild(card("③ 结果", [output]));
  });
}

/* ============================================================
   M4 浏览器控制
   ============================================================ */
function vBrowser() {
  const body = viewTemplate("v_browser", "浏览器控制", "M4 · BROWSER", "window", "recon", ({ output }) => {
    const cmd = input("命令（list_tabs / snapshot / activate / observe_dom / ping / canvas_guard）", "wide");
    const refreshBtn = btn("刷新状态", async () => {
      await run("browser", async () => {
        const s = await api("browser", "status");
        output.innerHTML = ""; output.appendChild(jsonBlock(s));
        return s && (s.connected || s.online) ? "已连接" : "未连接";
      });
    });
    const tabsBtn = btn("查看标签页", async () => {
      await run("browser", async () => {
        const rows = await api("browser", "list_tabs");
        output.innerHTML = ""; output.appendChild(table(rows || [], "打开的标签页"));
        return (rows || []).length + " 个";
      }, "已加载");
    });
    const domBtn = btn("查看 DOM 事件", async () => {
      await run("browser", async () => {
        const rows = await api("browser", "dom_events");
        output.innerHTML = ""; output.appendChild(table(rows || [], "DOM 事件"));
        return (rows || []).length + " 条";
      });
    });
    const privBtn = btn("查看隐私告警", async () => {
      await run("browser", async () => {
        const rows = await api("browser", "privacy_events");
        output.innerHTML = ""; output.appendChild(table(rows || [], "隐私告警"));
        return (rows || []).length + " 条";
      });
    });
    const sendBtn = btn("发送命令", async () => {
      await run("browser", async () => {
        const r = await api("browser", "send_command", { cmd: cmd.value || "list_tabs" });
        if (typeof r === "number" && r <= 0) throw new Error("无扩展连接在线，命令未投递");
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已发送 " + (cmd.value || "list_tabs");
      });
    }, false, true);
    onEnter(cmd, sendBtn);

    body.appendChild(card("① 列表", [
      toolbar([refreshBtn, tabsBtn, domBtn, privBtn], { primary: true }),
    ]));
    body.appendChild(card("② 操作（向已连扩展发命令）", [
      formRow([["命令", cmd]]),
      toolbar([sendBtn]),
      hint("需先安装 extension/ 目录下的 Chrome/Edge 扩展；WebSocket 中枢通过 token 握手后才会接受。"),
    ]));
    body.appendChild(card("③ 结果", [output]));
  });
}

/* ============================================================
   M8 大模型集成（ai 高级能力全暴露）
   ============================================================ */
