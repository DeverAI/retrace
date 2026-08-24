function vOverview() {
  const body = view("v_overview", "总览", "DASHBOARD", "grid", "dash");
  const st = status("overview", "加载中…", "info");
  body.appendChild(st);

  body.appendChild(section("实时状态"));
  const grid = el("div", "stat-grid");
  body.appendChild(grid);

  const statCard = (label, value, iconName, kind, onClick) => {
    const s = el("div", "stat" + (kind ? " " + kind : ""));
    const ic = el("div", "stat-icon"); ic.appendChild(icon(iconName)); s.appendChild(ic);
    const sb = el("div", "stat-body");
    sb.appendChild(el("div", "stat-value", value));
    sb.appendChild(el("div", "stat-label", label));
    s.appendChild(sb);
    s.appendChild(el("span", "stat-arrow", "→"));
    if (onClick) s.onclick = onClick;
    return s;
  };
  const pend = (label, iconName) => statCard(label, "…", iconName, null, null);

  const c1 = pend("模块开关", "layers"); grid.appendChild(c1);
  api("config", "switches").then(s => {
    const ent = Object.entries(s.switches || {}).filter(([k]) => k !== "ui");
    const on = ent.filter(([, x]) => x).length;
    c1.replaceWith(statCard(on + " / " + ent.length, "模块开关", "layers",
      on === 0 ? "warn" : null, () => goto("v_settings")));
  }).catch(() => c1.replaceWith(statCard("不可用", "模块开关", "layers", "err", () => goto("v_settings"))));

  const c2 = pend("观察目标", "target"); grid.appendChild(c2);
  api("hunt", "list_agents").then(rows => {
    const n = (rows || []).length;
    c2.replaceWith(statCard(String(n), "观察目标 (hunt)", "target",
      n === 0 ? "warn" : null, () => goto("v_hunt")));
  }).catch(() => c2.replaceWith(statCard("不可用", "观察目标 (hunt)", "target", "err", null)));

  const c3 = pend("浏览器扩展", "window"); grid.appendChild(c3);
  api("browser", "status").then(s => {
    const online = !!(s && (s.connected || s.online || s.ok));
    c3.replaceWith(statCard(online ? "在线" : "离线", "浏览器扩展", "window",
      online ? null : "warn", () => goto("v_browser")));
  }).catch(() => c3.replaceWith(statCard("未连接", "浏览器扩展", "window", "warn", () => goto("v_browser"))));

  const c4 = pend("大模型", "spark"); grid.appendChild(c4);
  api("ai", "configured").then(c => {
    c4.replaceWith(statCard(c ? "已配置" : "未配置", "大模型 (AI)", "spark",
      c ? null : "warn", () => goto("v_ai")));
  }).catch(() => c4.replaceWith(statCard("未知", "大模型 (AI)", "spark", "warn", null)));

  const c5 = pend("守护进程", "clock"); grid.appendChild(c5);
  api("tracking", "daemon_status").then(d => {
    const live = !!(d && d.running);
    c5.replaceWith(statCard(live ? "在线" : "离线", "守护进程", "clock",
      live ? null : "err", () => goto("v_tracking")));
  }).catch(() => c5.replaceWith(statCard("未知", "守护进程", "clock", "warn", null)));

  const c6 = pend("隐私保护", "shield"); grid.appendChild(c6);
  api("privacy_guard", "capabilities").then(c => {
    const ok = !!c;
    c6.replaceWith(statCard(ok ? "就绪" : "未配置", "隐私保护", "shield",
      ok ? null : "warn", () => goto("v_privacy")));
  }).catch(() => c6.replaceWith(statCard("不可用", "隐私保护", "shield", "warn", null)));

  body.appendChild(section("模块开关"));
  const chips = el("div", "chip-grid"); body.appendChild(chips);
  api("config", "switches").then(s => {
    chips.innerHTML = "";
    Object.entries(s.switches || {}).forEach(([k, x]) => {
      if (k === "ui") return;  // "ui" 是 Web 自身的总开关，关闭即 Web 消失，不在此展示
      const c = el("span", "chip " + (x ? "on" : "off"), k);
      c.title = "点击前往设置"; c.onclick = () => goto("v_settings");
      chips.appendChild(c);
    });
  }).catch(e => chips.appendChild(el("span", "muted", "无法加载: " + e.message)));
  setStatus("overview", "就绪", "ok");
}

/* ============================================================
   M1 网络抓包
   ============================================================ */
function vPcap() {
  const body = viewTemplate("v_pcap", "网络抓包", "M1 · PCAP", "globe", "recon", ({ body, output }) => {
    const sel = input("接口名"); const lim = input("条数", "", "200");
    let running = false; let startBtn;
    const startBtnClick = async () => {
      if (running) {
        await run("pcap", () => api("pcap", "stop_capture", { name: "main" }), "已停止");
        running = false; startBtn.textContent = "开始抓包";
        return;
      }
      await run("pcap", () => api("pcap", "start_capture",
        { name: "main", interface: sel.value || null }), "抓包中");
      running = true; startBtn.textContent = "停止抓包";
    };
    startBtn = btn("开始抓包", startBtnClick, false, true);
    const refreshBtn = btn("刷新接口", async () => {
      await run("pcap", async () => {
        const rows = await api("pcap", "list_interfaces");
        sel.value = (rows && rows[0] && rows[0].name) || "";
        return "已刷新";
      });
    });
    const recentBtn = btn("查看最近包", async () => {
      await run("pcap", async () => {
        const rows = await api("pcap", "get_recent",
          { name: "main", limit: Number(lim.value) || 200 });
        output.innerHTML = ""; output.appendChild(table(rows, "最近数据包"));
        return (rows || []).length + " 条";
      }, "已加载");
    });
    onEnter(sel, recentBtn); onEnter(lim, recentBtn);

    const offlinePath = input("离线 pcap 文件路径");
    const offlineBtn = btn("离线解析", async () => {
      await run("pcap", async () => {
        const r = await api("pcap", "parse_offline", { path: offlinePath.value });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已解析";
      }, "已解析");
    });

    const statusBtn = btn("抓包状态", async () => {
      await run("pcap", async () => {
        const r = await api("pcap", "capture_status", { name: "main" });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return r;  // 返回原始快照：error 态经 bizFail(last_error) 走红字路径
      }, "状态已获取");
    });
    const statsBtn = btn("流量统计（最近包）", async () => {
      await run("pcap", async () => {
        const rows = await api("pcap", "get_recent",
          { name: "main", limit: Number(lim.value) || 500 });
        const r = await api("pcap", "stat_summary", { packets: rows || [] });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const pruneBtn = btn("清理已停抓包", async () => {
      await run("pcap", async () => {
        const n = await api("pcap", "prune", {});
        return "已清理 " + (typeof n === "number" ? n : 0) + " 个已停/空闲抓包";
      }, "已清理");
    });
    const stopAllBtn = btn("停止全部抓包", async () => {
      if (!confirm("确认停止全部抓包任务？")) return;
      await run("pcap", async () => {
        const n = await api("pcap", "stop_all", {});
        running = false; startBtn.textContent = "开始抓包";
        return "已停止全部（" + (typeof n === "number" ? n : 0) + " 个运行中）";
      }, "已停止全部");
    });

    body.appendChild(card("① 控制", [
      formRow([
        ["接口", sel], ["条数", lim],
      ]),
      toolbar([startBtn, refreshBtn, recentBtn, statusBtn], { primary: true }),
      toolbar([statsBtn, pruneBtn, stopAllBtn]),
    ]));
    body.appendChild(card("② 离线解析",
      [formRow([["pcap/pcapng 路径", offlinePath]]), toolbar([offlineBtn])]));
    body.appendChild(card("③ 结果", [output]));
  });
}

/* ============================================================
   M11 筛查工作台（含留样扫描 + 批量清理 + 恢复）
   ============================================================ */
