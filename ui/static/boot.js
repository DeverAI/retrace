function setLive(ok) {
  const dot = document.getElementById("liveDot");
  const txt = document.getElementById("liveText");
  if (!dot || !txt) return;
  dot.className = "dot " + (ok ? "ok" : "off");
  txt.textContent = ok ? "已连接 · 本地" : "离线模式";
}

/* ============================================================
   启动（开关判定逻辑与原版一致；新增视图按配置 gates）
   ============================================================ */
async function boot() {
  vOverview();
  let sw = {};
  let alive = true;
  try {
    const p = await api("config", "switches");
    sw = p.switches || {};
  } catch (e) {
    try {
      const r = await fetch("/api/ping"); const j = await r.json();
      sw = j.modules || {};
    } catch (e2) { alive = false; /* 离线时全显示 */ }
  }
  setLive(alive);
  const show = (k, fn) => { if (sw[k] !== false) fn(); };

  // 侦查 / 筛查
  show("pcap", vPcap);
  show("regscan", vRegscan);
  show("browser", vBrowser);
  show("screener", vScreener);
  // 分析
  show("embedding", vEmbed);
  show("decompile", vDecompile);
  show("ai", vAi);
  show("evolve", vEvolve);
  // 任务 / 编排
  show("tracking", vTracking);
  show("watcher", vWatcher);
  show("hunt", vHunt);
  show("agent", vAgent);
  // 系统
  show("privacy_guard", vPrivacy);
  vSettings();
  renderNav();

  let target = "v_overview";
  try {
    const saved = localStorage.getItem(LS_KEY);
    if (saved && VIEWS[saved]) target = saved;
  } catch (e) { /* ignore */ }
  // hash 深链：#v_screener 直达指定视图（可收藏/分享定位）
  try {
    const h = (location.hash || "").slice(1);
    if (h && VIEWS[h]) target = h;
  } catch (e) { /* ignore */ }
  goto(target);
  // 后续 hash 变化（含浏览器前进/后退）同步切换视图
  window.addEventListener("hashchange", () => {
    const h = (location.hash || "").slice(1);
    if (h && VIEWS[h]) goto(h);
  });
}
boot();

