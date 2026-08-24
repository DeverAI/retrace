"use strict";
/* ============================================================
   ReTrace Web 控制台 — 暗色 UI v3
   重构与补齐（2026-08-15）：
   - 新增 vScreener / vPrivacyGuard / vTracking / vEvolve（补齐遗漏视图）
   - 已有视图统一布局模板：title → status → 工具卡 → 操作卡 → 主输出区 → 日志
   - 强化业务失败判定（run/bizFail）
   - 参数区用 formRow / toolbar 排版
   - 所有视图保存上一份操作的 loading / error 状态
   ============================================================ */

const SW = { ui: true };
const NAV = [];
const VIEWS = {};
const LS_KEY = "retrace.view";

/* ============================================================
   API（与 web_main.py ALLOWED 一一对应）
   ============================================================ */
async function api(module, func, kwargs) {
  if (kwargs === undefined) kwargs = {};
  const r = await fetch("/api/" + module + "/" + func, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-ReTrace": "1" },
    body: JSON.stringify(kwargs),
  });
  const j = await r.json();
  if (!j.ok) throw new Error(j.error || (module + "." + func + " 失败"));
  return j.data;
}

/* ============================================================
   业务失败统一判定（与 py 端 _call 返回约定）
   - bool 直接是 false
   - [false, msg] 元组
   - {ok: false} 或 {error: "..."} 字典
   - null/undefined 也算失败（删除类反向）
   ============================================================ */
function bizFail(r) {
  if (r === false || r === null || r === undefined) return true;
  if (Array.isArray(r) && r.length > 0 && r[0] === false) return true;
  if (typeof r === "object" && !Array.isArray(r)) {
    if (r.ok === false) return true;
    if (r.error) return true;
    if (r.last_error) return true;  // pcap snapshot 的错误态字段（error 改名后的兼容判定）
  }
  return false;
}
function bizErr(r) {
  if (Array.isArray(r) && r.length > 1) {
    const second = r[1];
    if (second && typeof second === "object") {
      if (second.error) return String(second.error);
      if (second.last_error) return String(second.last_error);
      if (second.state) return "状态: " + String(second.state);
    }
    if (second !== undefined && second !== null) return String(second);
    return r[0] === false ? "操作未成功" : String(r[0]);
  }
  if (typeof r === "object" && r) {
    if (r.error) return String(r.error);
    if (r.last_error) return String(r.last_error);
  }
  return String(r);
}

/* ============================================================
   DOM helpers
   ============================================================ */
const ICONS = {
  grid:    '<rect x="2.5" y="2.5" width="4.5" height="4.5" rx="1"/><rect x="9" y="2.5" width="4.5" height="4.5" rx="1"/><rect x="2.5" y="9" width="4.5" height="4.5" rx="1"/><rect x="9" y="9" width="4.5" height="4.5" rx="1"/>',
  globe:   '<circle cx="8" cy="8" r="6"/><path d="M2 8h12"/><path d="M8 2c3 2.2 3 9.8 0 12-3-2.2-3-9.8 0-12z"/>',
  list:    '<path d="M5.5 4h8M5.5 8h8M5.5 12h8"/><circle cx="2.5" cy="4" r=".9"/><circle cx="2.5" cy="8" r=".9"/><circle cx="2.5" cy="12" r=".9"/>',
  window:  '<rect x="1.5" y="2.5" width="13" height="11" rx="1.5"/><path d="M1.5 6h13"/><circle cx="4" cy="4.3" r=".5"/><circle cx="6" cy="4.3" r=".5"/>',
  code:    '<path d="M5.5 4.5 2 8l3.5 3.5"/><path d="M10.5 4.5 14 8l-3.5 3.5"/>',
  search:  '<circle cx="6.8" cy="6.8" r="4.6"/><path d="m10.4 10.4 3.4 3.4"/>',
  spark:   '<path d="M8 1.8 9.4 5.6 13.2 7 9.4 8.4 8 12.2 6.6 8.4 2.8 7l3.8-1.4z"/><path d="M12.8 11.2l.5 1.3 1.3.5-1.3.5-.5 1.3-.5-1.3-1.3-.5 1.3-.5z"/>',
  eye:     '<path d="M1.5 8s2.6-4.3 6.5-4.3S14.5 8 14.5 8s-2.6 4.3-6.5 4.3S1.5 8 1.5 8z"/><circle cx="8" cy="8" r="2"/>',
  target:  '<circle cx="8" cy="8" r="6"/><circle cx="8" cy="8" r="2.6"/><circle cx="8" cy="8" r=".4"/>',
  gear:    '<path d="M2 5h7M12 5h2M2 11h3M8 11h6"/><circle cx="10.3" cy="5" r="1.7"/><circle cx="5.7" cy="11" r="1.7"/>',
  layers:  '<path d="M8 2 2 5.2 8 8.4l6-3.2z"/><path d="m2 8.8 6 3.2 6-3.2"/><path d="m2 12.2 6 3.2 6-3.2"/>',
  chip:    '<rect x="2" y="2" width="12" height="12" rx="2"/><path d="M7 5.5 5 8l2 2.5M9 5.5 11 8 9 10.5"/>',
  shield:  '<path d="M8 1.5 2.5 4v5c0 4 2.5 5 5.5 6.5 3-1.5 5.5-2.5 5.5-6.5v-5z"/>',
  clock:   '<circle cx="8" cy="8" r="6"/><path d="M8 4v4l3 2"/>',
  lock:    '<rect x="3" y="7" width="10" height="7" rx="1"/><path d="M5 7V5a3 3 0 0 1 6 0v2"/>',
  flag:    '<path d="M3 2v12M3 3h8l-2 3 2 3H3"/>',
  broom:   '<path d="M3 13l4-4M9 9l-2 5 5-1 4-6-3-3-6 4z"/>',
};
function icon(name) {
  const d = ICONS[name] || ICONS.grid;
  const wrap = document.createElement("span");
  wrap.style.display = "inline-flex";
  wrap.innerHTML =
    '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + d + "</svg>";
  return wrap.firstChild;
}

/* ---- 低阶 el / formRow / toolbar ---- */
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}
function formRow(pairs) {
  const r = el("div", "form-row");
  pairs.forEach(([label, control, hint]) => {
    if (!control) return;
    const w = el("div", "form-field");
    if (label) w.appendChild(el("label", null, label));
    w.appendChild(control);
    if (hint) w.appendChild(el("small", "hint", hint));
    r.appendChild(w);
  });
  return r;
}
function toolbar(items, opts) {
  opts = opts || {};
  const r = el("div", opts.primary ? "toolbar primary" : "toolbar");
  let count = 0;
  items.forEach(i => {
    if (i === null || i === undefined) return;
    if (i === "spacer") { r.appendChild(el("div", "spacer")); count++; return; }
    r.appendChild(i); count++;
  });
  return r;
}
function section(title, hint) {
  const w = el("div", "section-title");
  w.appendChild(el("h3", null, title));
  if (hint) w.appendChild(el("small", null, hint));
  return w;
}
function hint(text) { return el("div", "hint-block", text); }
function card(title, content, hintText) {
  const c = el("section", "card");
  if (title) c.appendChild(section(title, hintText));
  if (Array.isArray(content)) content.forEach(x => x && c.appendChild(x));
  else if (content) c.appendChild(content);
  return c;
}
function textarea(placeholder, value, rows) {
  const t = el("textarea");
  if (placeholder) t.placeholder = placeholder;
  if (value !== undefined && value !== null) t.value = value;
  if (rows) t.rows = rows;
  return t;
}
function select(options, value) {
  const s = el("select");
  options.forEach(opt => {
    let label, val;
    if (Array.isArray(opt)) { label = opt[0]; val = opt[1] !== undefined ? opt[1] : label; }
    else { label = String(opt); val = label; }
    const o = el("option", null, label);
    o.value = val;
    if (val === value) o.selected = true;
    s.appendChild(o);
  });
  return s;
}
function checkbox(label, checked) {
  const wrap = el("label", "checkbox");
  const cb = el("input"); cb.type = "checkbox";
  cb.checked = !!checked;
  wrap.appendChild(cb);
  wrap.appendChild(document.createTextNode(label));
  wrap.dataset.value = checked ? "1" : "0";
  cb.addEventListener("change", () => { wrap.dataset.value = cb.checked ? "1" : "0"; });
  wrap.input = cb;
  return wrap;
}
function field(labelText, control) {
  const f = el("div", "form-field");
  if (labelText) f.appendChild(el("label", null, labelText));
  f.appendChild(control);
  return f;
}

/* ---- 按钮（防重入 + loading + 业务失败 throw） ---- */
function btn(text, fn, dis, primary) {
  const b = el("button", primary ? "primary" : null, text);
  if (dis) b.disabled = true;
  b.onclick = async () => {
    if (b.disabled || b.classList.contains("loading")) return;
    b.classList.add("loading");
    const sp = el("span", "spin");
    b.insertBefore(sp, b.firstChild);
    b.disabled = true;
    try {
      await fn();
    } catch (e) {
      if (!e.__rtToasted) toast("[" + text + "] " + e.message, "err");
    } finally {
      b.classList.remove("loading");
      if (sp.parentNode) sp.remove();
      b.disabled = !!dis;
    }
  };
  return b;
}
function input(placeholder, cls, val) {
  const i = el("input", cls || "", null);
  i.placeholder = placeholder || "";
  if (val !== undefined && val !== null) i.value = val;
  return i;
}
function onEnter(inputEl, buttonEl) {
  inputEl.addEventListener("keydown", e => {
    if (e.key === "Enter" && buttonEl && !buttonEl.disabled) buttonEl.click();
  });
}

/* ============================================================
   Toast / Status
   ============================================================ */
function toast(msg, kind) {
  const w = document.getElementById("toasts");
  if (!w) return;
  const t = el("div", "toast " + (kind || "info"), msg);
  w.appendChild(t);
  setTimeout(() => {
    t.classList.add("out");
    setTimeout(() => t.remove(), 320);
  }, 3400);
}
function status(id, text, kind) {
  const s = el("div", "status" + (kind ? " " + kind : ""));
  s.id = "st-" + id;
  if (text !== undefined) s.textContent = text;
  return s;
}
function setStatus(id, text, kind) {
  const s = document.getElementById("st-" + id);
  if (!s) return;
  s.className = "status" + (kind ? " " + kind : "");
  if (text !== undefined) s.textContent = text;
}

/* ============================================================
   JSON 高亮 / 表格 / 复制
   ============================================================ */
function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function jsonBlock(obj) {
  const pre = el("pre", "json");
  const txt = escapeHtml(JSON.stringify(obj, null, 2));
  pre.innerHTML = txt
    .replace(/"([^"]*)"(\s*:)/g, '<span class="j-key">"$1"</span>$2')
    .replace(/:\s"([^"]*)"/g, ': <span class="j-str">"$1"</span>')
    .replace(/(^|[^\w/])(-?\d+\.?\d*)(?![\w"])/g, '$1<span class="j-num">$2</span>')
    .replace(/\b(true|false|null)\b/g, '<span class="j-bool">$1</span>');
  return pre;
}
function copyText(text) {
  try {
    navigator.clipboard.writeText(text)
      .then(() => toast("已复制", "ok"))
      .catch(() => toast("复制失败", "warn"));
  } catch (e) { toast("复制失败: " + e.message, "err"); }
}

/* ---- 通用表格 ---- */
function traceTable(rows, title, selected) {
  const wrap = el("div", "table-block");
  const list = Array.isArray(rows) ? rows : [];
  const bar = el("div", "table-bar");
  const cnt = el("span", "count");
  cnt.appendChild(document.createTextNode((title || "结果") + " · "));
  cnt.appendChild(el("b", null, String(list.length)));
  cnt.appendChild(document.createTextNode(" 条（勾选后批量清理）"));
  bar.appendChild(cnt);
  const selAll = el("button", "btn-sm", "全选");
  selAll.onclick = () => {
    const cbs = wrap.querySelectorAll(".trace-cb");
    const allSel = Array.from(cbs).every(c => c.checked);
    cbs.forEach(c => { c.checked = !allSel; });
    updateSel();
  };
  bar.appendChild(selAll);
  bar.appendChild(el("button", "btn-sm", "复制 JSON"));
  bar.lastChild.onclick = () => copyText(JSON.stringify(rows, null, 2));
  wrap.appendChild(bar);

  if (list.length === 0) {
    wrap.appendChild(el("div", "empty", "（无数据）"));
    return wrap;
  }
  const keys = ["type", "name", "target", "risk", "reason"];
  const t = el("table");
  const thead = el("thead"); const thr = el("tr");
  thr.appendChild(el("th", null, "选择"));
  keys.forEach(k => thr.appendChild(el("th", null, k)));
  thead.appendChild(thr); t.appendChild(thead);
  const tbody = el("tbody");
  list.forEach((r, i) => {
    const tr = el("tr");
    const tdCb = el("td");
    const cb = el("input"); cb.type = "checkbox"; cb.className = "trace-cb";
    cb.addEventListener("change", updateSel);
    tdCb.appendChild(cb); tr.appendChild(tdCb);
    keys.forEach(k => {
      let v = r[k];
      if (v && typeof v === "object") v = JSON.stringify(v);
      if (v === null || v === undefined) v = "";
      tr.appendChild(el("td", null, String(v)));
    });
    tbody.appendChild(tr);
  });
  t.appendChild(tbody);
  wrap.appendChild(t);

  function updateSel() {
    const cbs = wrap.querySelectorAll(".trace-cb");
    selected.v = [];
    cbs.forEach((cb, i) => { if (cb.checked) selected.v.push(rows[i]); });
    cnt.querySelector("b").textContent = String(selected.v.length) + "/" + list.length;
  }
  return wrap;
}
/* ---- 通用表格 ---- */
function table(rows, title, opts) {
  opts = opts || {};
  const wrap = el("div", "table-block");
  const list = Array.isArray(rows) ? rows : [];
  const bar = el("div", "table-bar");
  const cnt = el("span", "count");
  cnt.appendChild(document.createTextNode((title || "结果") + " · "));
  cnt.appendChild(el("b", null, String(list.length)));
  cnt.appendChild(document.createTextNode(" 条"));
  bar.appendChild(cnt);
  bar.appendChild(el("button", "btn-sm", "复制 JSON"));
  bar.lastChild.onclick = () => copyText(JSON.stringify(rows, null, 2));
  wrap.appendChild(bar);

  if (list.length === 0) {
    const empty = el("div", "empty", "（无数据）");
    if (opts.emptyHint) empty.appendChild(el("small", null, opts.emptyHint));
    wrap.appendChild(empty);
    return wrap;
  }
  if (typeof list[0] !== "object" || list[0] === null) {
    const box = el("div", "table-wrap");
    list.forEach(r => {
      const tr = el("div", "row");
      tr.appendChild(el("span", "key", JSON.stringify(r)));
      box.appendChild(tr);
    });
    wrap.appendChild(box);
    return wrap;
  }
  // 折叠嵌套 dict / list 为 JSON
  const keys = (opts.columns && opts.columns.length) ? opts.columns
    : Object.keys(list[0]).filter(k => typeof list[0][k] !== "function");
  const t = el("table");
  const thead = el("thead"); const thr = el("tr");
  keys.forEach(k => thr.appendChild(el("th", null, k)));
  thead.appendChild(thr); t.appendChild(thead);
  const tbody = el("tbody");
  list.forEach(r => {
    const tr = el("tr");
    keys.forEach(k => {
      let v = r[k];
      if (v && typeof v === "object") v = JSON.stringify(v);
      if (v === null || v === undefined) v = "";
      tr.appendChild(el("td", null, String(v)));
    });
    tbody.appendChild(tr);
  });
  t.appendChild(tbody);
  const box = el("div", "table-wrap"); box.appendChild(t);
  wrap.appendChild(box);
  return wrap;
}

/* ============================================================
   视图与导航
   ============================================================ */
const GROUPS = [
  { id: "dash",     label: "总览" },
  { id: "recon",    label: "侦查 / 筛查" },
  { id: "analysis", label: "分析" },
  { id: "flow",     label: "任务 / 编排" },
  { id: "system",   label: "系统" },
];
function view(id, title, tag, iconName, group) {
  const v = el("div", "view");
  v.id = id;
  const head = el("div", "view-head");
  head.appendChild(icon(iconName));
  const h = el("h2", null, title);
  if (tag) h.appendChild(el("span", "tag", tag));
  head.appendChild(h);
  v.appendChild(head);
  const body = el("div", "view-body");
  v.appendChild(body);
  VIEWS[id] = { root: v, body };
  document.getElementById("views").appendChild(v);
  NAV.push({ id, title, tag, icon: iconName, group });
  return body;
}
function goto(id) {
  const v = VIEWS[id];
  if (!v) return;
  document.querySelectorAll(".view").forEach(x => x.classList.remove("active"));
  document.querySelectorAll("#navlinks a").forEach(x => x.classList.remove("active"));
  v.root.classList.add("active");
  const link = document.querySelector('#navlinks a[data-view="' + id + '"]');
  if (link) link.classList.add("active");
  try { localStorage.setItem(LS_KEY, id); } catch (e) { /* ignore */ }
}
function renderNav() {
  const nav = document.getElementById("navlinks");
  nav.innerHTML = "";
  GROUPS.forEach(g => {
    const items = NAV.filter(n => n.group === g.id);
    if (items.length === 0) return;
    nav.appendChild(el("div", "nav-group-title", g.label));
    items.forEach(n => {
      const a = el("a");
      a.setAttribute("data-view", n.id);
      a.appendChild(icon(n.icon));
      a.appendChild(el("span", null, n.title));
      if (n.tag) a.appendChild(el("span", "nav-badge", n.tag.split(" ")[0]));
      a.onclick = () => goto(n.id);
      nav.appendChild(a);
    });
  });
}

/* ============================================================
   run：状态条 + 失败 toast + 业务失败 throw
   ============================================================ */
async function run(id, fn, okMsg) {
  setStatus(id, "执行中…", "run");
  try {
    const r = await fn();
    if (r === undefined) {          // 用户取消等中性退出：不报成功也不报失败
      setStatus(id, "已取消", "warn");
      return r;
    }
    if (bizFail(r)) {
      const msg = (okMsg || "操作") + "失败：" + bizErr(r);
      setStatus(id, msg, "err");
      throw new Error(msg);
    }
    // 回调返回的字符串（如"N 条""已清理 3 个"）直接作为状态文案，不再被丢弃
    setStatus(id, typeof r === "string" && r ? r : (okMsg || "完成"), "ok");
    return r;
  } catch (e) {
    setStatus(id, "错误: " + e.message, "err");
    // 标记已 toast，避免 btn() 包装层二次弹同一条（bizFail 双重 toast）
    e.__rtToasted = true;
    toast(e.message, "err");
    throw e;
  }
}

/* ============================================================
   通用 5 段布局模板：statusBar / toolsCard / paramsCard / outputCard / logCard
   ============================================================ */
function viewTemplate(id, title, tag, iconName, group, builder) {
  const body = view(id, title, tag, iconName, group);
  const st = status(id, "就绪", "info");
  body.appendChild(st);
  const output = el("div", "output-area");
  const log = el("div", "log-area");
  builder({ body, output, log });
  return body;
}

/* ============================================================
   总览（仪表盘）
   ============================================================ */
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
  const body = viewTemplate("v_pcap", "网络抓包", "M1 · PCAP", "globe", "recon", ({ output }) => {
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
function vScreener() {
  const body = viewTemplate("v_screener", "筛查工作台", "M11 · SCREENER", "shield", "recon", ({ output, log }) => {
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

    // ⑦ 标记入库
    const mCat = input("观察类别（suspicious / leftover / fingerprint）", "", "suspicious");
    const mRisk = select(["高", "中", "低", "无"], "中");
    const mNote = input("备注（可选）");
    const markBtn = btn("标记选中入库", async () => {
      await run("screener", async () => {
        const r = await api("screener", "mark_item",
          { name: mCat.value || "?", category: mCat.value || "suspicious",
            risk: mRisk.value, detail: "", note: mNote.value });
        if (bizFail(r)) throw new Error("标记失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已标记 obs#" + r;
      }, "已标记");
    });
    body.appendChild(card("⑦ 标记入库（人工/AI 分析后追加 observations）", [
      formRow([["类别/名称", mCat], ["风险", mRisk], ["备注", mNote]]),
      toolbar([markBtn]),
    ]));

    // ⑧ 结果筛选（同步 GUI 能力）
    const fCat = select(["全部", "可疑APP", "残留", "留样", "机器指纹", "执行痕迹", "使用历史", "崩溃痕迹"], "全部");
    const fRisk = select(["全部", "高", "中", "低", "无"], "全部");
    const lastItems = { v: [] };
    const applyFilter = () => {
      let rows = lastItems.v || [];
      const catMap = { "可疑APP": "可疑APP", "残留": "残留", "留样": "留样",
        "机器指纹": "机器指纹", "执行痕迹": "执行痕迹", "使用历史": "使用历史",
        "崩溃痕迹": "崩溃痕迹" };
      if (fCat.value !== "全部") rows = rows.filter(x => x.category === catMap[fCat.value]);
      if (fRisk.value !== "全部") rows = rows.filter(x => x.risk === fRisk.value);
      output.innerHTML = ""; output.appendChild(table(rows, "筛选结果"));
    };
    fCat.onchange = applyFilter;
    fRisk.onchange = applyFilter;
    body.appendChild(card("⑧ 结果筛选", [
      formRow([["类别", fCat], ["风险", fRisk]]),
      hint("按类别或风险过滤全部已扫描结果后再标记入库。"),
    ]));
  });
}

/* ============================================================
   M2 注册表搜索
   ============================================================ */
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
function vAi() {
  const body = viewTemplate("v_ai", "大模型集成", "M8 · AI", "spark", "analysis", ({ output }) => {
    // ① 状态
    const statusBtn = btn("检查 AI 是否已配置", async () => {
      await run("ai", async () => {
        const c = await api("ai", "configured");
        output.innerHTML = ""; output.appendChild(jsonBlock({ configured: c }));
        return c ? "已配置" : "未配置（请在设置或 config.json 配 base_url/api_key/model）";
      });
    });

    // ② 问答
    const q = textarea("向大模型提问（自动叠加只读顾问边界）", "", 3);
    const askBtn = btn("提问", async () => {
      await run("ai", async () => {
        const r = await api("ai", "answer",
          { question: q.value, context: "ReTrace 漏洞分析助手" });
        if (bizFail(r)) throw new Error("提问失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    }, false, true);

    // ③ 单项能力
    const inText = textarea("在此粘贴 / 输入文本，按不同按钮执行不同动作", "", 5);
    const btnAnalyze = btn("AI 风险分析", async () => {
      await run("ai", async () => {
        const r = await api("ai", "analyze", { finding: inText.value });
        if (bizFail(r)) throw new Error("分析失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const btnSummary = btn("AI 摘要", async () => {
      await run("ai", async () => {
        const r = await api("ai", "summarize", { observation: inText.value });
        if (bizFail(r)) throw new Error("摘要失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const btnRules = btn("AI 规则提炼", async () => {
      const list = inText.value.split(/\r?\n/).filter(s => s.trim());
      await run("ai", async () => {
        const r = await api("ai", "extract_rules", { observations: list });
        if (bizFail(r)) throw new Error("提炼失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const btnChat = btn("直连对话（chat）", async () => {
      const list = inText.value.split(/\n\n+/).filter(Boolean);
      const messages = list.length ? list.map((t, i) =>
        ({ role: i % 2 === 0 ? "user" : "assistant", content: t }))
        : [{ role: "user", content: inText.value }];
      await run("ai", async () => {
        const r = await api("ai", "chat", { messages: messages });
        if (bizFail(r)) throw new Error("对话失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });

    body.appendChild(card("① 状态", [toolbar([statusBtn])]));
    body.appendChild(card("② 上下文问答（ask）",
      [q, toolbar([askBtn], { primary: true })]));
    body.appendChild(card("③ 单项能力", [
      inText,
      toolbar([btnAnalyze, btnSummary, btnRules, btnChat]),
      hint("analyze=finding 文本；summarize=observation 文本；extract_rules=每行一条观察;"
         + " chat=传入完整 messages 列表（按 \\n\\n 切片自动分配 user/assistant）。"),
    ]));
    body.appendChild(card("④ 结果", [output]));
  });
}

/* ============================================================
   任务追踪（vTracking，全套跟踪任务操作）
   ============================================================ */
function vTracking() {
  const body = viewTemplate("v_tracking", "追踪任务", "DAEMON · TASKS", "clock", "flow", ({ output }) => {
    // ① 全局：刷新 + 验证审计链
    const refreshBtn = btn("刷新任务", async () => {
      await run("tracking", async () => {
        const rows = await api("tracking", "list_tasks");
        output.innerHTML = ""; output.appendChild(table(rows || [], "当前任务"));
        return (rows || []).length + " 个";
      }, "已刷新");
    });
    const verifyBtn = btn("验证审计链", async () => {
      await run("tracking", async () => {
        const r = await api("tracking", "audit_verify");
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        if (!r || r.ok !== true) throw new Error("审计链验证未通过（详见输出）");
        return "链完整（" + (r.checked || 0) + " 条）";
      }, "验证完成");
    });
    const auditBtn = btn("查看全局审计", async () => {
      await run("tracking", async () => {
        const rows = await api("tracking", "audit_entries", { limit: 100 });
        output.innerHTML = ""; output.appendChild(table(rows || [], "审计日志"));
        return (rows || []).length + " 条";
      }, "已加载");
    });
    const capsBtn = btn("查看采集能力", async () => {
      await run("tracking", async () => {
        const r = await api("tracking", "capabilities", {});
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });

    // ② 创建任务
    const tName = input("任务名（必填）"); const tExe = input("可执行文件路径");
    const tProc = input("进程名"); const tPaths = input("观察目录（分号分隔）");
    const tInterval = input("采样间隔（秒）", "", "5");
    const tAi = checkbox("启用 AI 摘要", false);
    const createBtn = btn("创建并启动", async () => {
      if (!tName.value) { toast("任务名必填", "warn"); return; }
      const paths = (tPaths.value || "").split(";").map(s => s.trim()).filter(Boolean);
      await run("tracking", async () => {
        const r = await api("tracking", "create_task", {
          name: tName.value, exe_path: tExe.value || "", process_name: tProc.value || "",
          watch_paths: paths, interval_sec: Number(tInterval.value) || 5,
          ai_enabled: tAi.input.checked, auto_start: true,
        });
        if (!r || !r.id) {
          throw new Error("创建失败：" + ((r && (r.error || r)) || "未知错误"));
        }
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已创建 #" + r.id;
      }, "已创建");
    }, false, true);

    // ③ 选中任务后的操作
    const tId = input("任务 ID");
    // NaN/负数/小数统一拦截：Number("abc")=NaN 会经 JSON 变 null，后端 int(None) 才报错，
    // 在这里先把非法输入挡在门外，返回 0 由各按钮 toast 提示。
    const readTaskId = () => {
      const n = Number(tId.value);
      if (!tId.value.trim() || !Number.isFinite(n) || n <= 0) {
        toast("请输入有效的任务 ID（正整数）", "warn"); return 0;
      }
      return Math.trunc(n);
    };
    const startBtn = btn("启动", async () => {
      const tid = readTaskId(); if (!tid) return;
      await run("tracking", async () => {
        const r = await api("tracking", "start_task", { task_id: tid });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已启动";
      });
    });
    const pauseBtn = btn("暂停", async () => {
      const tid = readTaskId(); if (!tid) return;
      await run("tracking", async () => {
        const r = await api("tracking", "pause_task", { task_id: tid });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已暂停";
      });
    });
    const editBtn = btn("编辑", async () => {
      const tid = readTaskId(); if (!tid) return;
      const newName = window.prompt("新任务名", "");
      if (!newName) return;
      await run("tracking", async () => {
        const r = await api("tracking", "update_task",
          { task_id: tid, name: newName });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已更新";
      });
    });
    const deleteBtn = btn("删除", async () => {
      const tid = readTaskId(); if (!tid) return;
      if (!confirm("确认删除任务 #" + tid + "？其事件与运行历史将一并删除。")) return;
      await run("tracking", async () => {
        const r = await api("tracking", "delete_task", { task_id: tid });
        if (bizFail(r)) throw new Error("删除失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已删除";
      });
    });

    // ④ 查看事件 / 运行 / AI 摘要
    const evLimit = input("事件条数", "", "300");
    const evBtn = btn("查看事件", async () => {
      const tid = readTaskId(); if (!tid) return;
      await run("tracking", async () => {
        const rows = await api("tracking", "task_events",
          { task_id: tid, limit: Number(evLimit.value) || 300 });
        output.innerHTML = ""; output.appendChild(table(rows || [], "事件"));
        return (rows || []).length + " 条";
      }, "已加载");
    });
    const runsBtn = btn("查看运行历史", async () => {
      const tid = readTaskId(); if (!tid) return;
      await run("tracking", async () => {
        const rows = await api("tracking", "task_runs", { task_id: tid });
        output.innerHTML = ""; output.appendChild(table(rows || [], "运行历史"));
        return (rows || []).length + " 条";
      }, "已加载");
    });
    const aiBtn = btn("AI 风险摘要", async () => {
      const tid = readTaskId(); if (!tid) return;
      await run("tracking", async () => {
        const r = await api("tracking", "analyze_task", { task_id: tid });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        if (!r || !r.text) throw new Error("AI 摘要失败：" + (r && r.error ? r.error : "无返回文本"));
        return "AI 完成";
      }, "AI 完成");
    });

    body.appendChild(card("① 全局", [
      toolbar([refreshBtn, verifyBtn, auditBtn, capsBtn], { primary: true }),
    ]));
    body.appendChild(card("② 创建任务", [
      formRow([["任务名", tName], ["可执行文件", tExe], ["进程名", tProc]]),
      formRow([["观察目录", tPaths], ["间隔(秒)", tInterval], ["AI 摘要", tAi.input]]),
      toolbar([createBtn]),
    ]));
    body.appendChild(card("③ 选中任务后操作（按 ID）", [
      formRow([["任务 ID", tId]]),
      toolbar([startBtn, pauseBtn, editBtn, deleteBtn]),
    ]));
    body.appendChild(card("④ 详情（事件/运行/AI）", [
      formRow([["事件条数", evLimit]]),
      toolbar([evBtn, runsBtn, aiBtn]),
    ]));
    body.appendChild(card("⑤ 结果", [output]));
  });
}

/* ============================================================
   隐私保护（vPrivacy，全套门禁操作）
   ============================================================ */
function vPrivacy() {
  const body = viewTemplate("v_privacy", "隐私保护", "PRIVACY GUARD", "shield", "system", ({ output }) => {
    const reasonInput = input("明确原因（≥12 字：目的、对象、必要性）", "wide");
    const taskIdInput = input("任务 ID（归属）");
    const subkey = input("HKCU 子树（Software\\厂商\\产品）");
    const valueName = input("值名（可空）");
    const newVal = input("新 REG_SZ 值（设置用）");
    const publisher = input("发布者（登记用）");
    const owner = input("所有权说明（≥12 字）", "wide");
    const exe = input("EXE 路径（隔离用）");
    const net = checkbox("允许联网", false);
    const clip = checkbox("允许剪贴板", false);
    const site = input("Canvas 站点（例 https://example.com）");

    // ① 能力
    const capsBtn = btn("查看能力", async () => {
      await run("privacy", async () => {
        const r = await api("privacy_guard", "capabilities");
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const rulesBtn = btn("查看保护规则", async () => {
      await run("privacy", async () => {
        const r = await api("privacy_guard", "protected_rules");
        output.innerHTML = ""; output.appendChild(table(r || [], "保护规则"));
        return (r || []).length + " 条";
      });
    });
    // 任务 ID 统一校验：拦截 NaN/负数/小数，避免 JSON null 传后端 int(None) TypeError
    const readPrivacyId = () => {
      const n = Number(taskIdInput.value);
      if (!taskIdInput.value.trim() || !Number.isFinite(n) || n <= 0) {
        toast("请输入有效的任务 ID（正整数）", "warn"); return 0;
      }
      return Math.trunc(n);
    };
    const taskReportBtn = btn("查看任务报告", async () => {
      const tid = readPrivacyId(); if (!tid) return;
      await run("privacy", async () => {
        const r = await api("privacy_guard", "task_report", { task_id: tid });
        if (bizFail(r)) throw new Error("报告失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const registryScopesBtn = btn("查看已登记的 HKCU 范围", async () => {
      await run("privacy", async () => {
        const r = await api("privacy_guard", "registry_scopes", {});
        output.innerHTML = ""; output.appendChild(table(r || [], "已登记范围"));
        return (r || []).length + " 项";
      });
    });

    // ② 隔离
    const previewBtn = btn("预览 WSB（只读映射）", async () => {
      await run("privacy", async () => {
        const r = await api("privacy_guard", "sandbox_preview",
          { exe_path: exe.value, network: net.input.checked, clipboard: clip.input.checked, memory_mb: 4096 });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const planLaunchBtn = btn("审查并启动 Sandbox", async () => {
      if (!exe.value) { toast("请填写 EXE 路径", "warn"); return; }
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      await run("privacy", async () => {
        const plan = await api("privacy_guard", "plan_system_action", {
          action: "launch_sandbox",
          args: { exe_path: exe.value, network: net.input.checked, clipboard: clip.input.checked, memory_mb: 4096 },
          reason
        });
        if (!plan || !plan.token) throw new Error("计划创建失败：" + bizErr(plan));
        if (!confirm("即将执行：\n" + JSON.stringify(plan, null, 2))) return;
        const cap = await api("privacy_guard", "approve_system_action", {
          token: plan.token, confirmation: "我已审查并批准", reason, approval_context: "web_dialog"
        });
        if (!cap || !cap.approval_token) throw new Error("批准失败：" + (cap && cap.error ? cap.error : "无批准能力"));
        const r = await api("privacy_guard", "execute_system_action", {
          approval_token: cap.approval_token, reason
        });
        if (bizFail(r)) throw new Error("执行失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "完成");
    });

    // ③ 注册表登记 / 撤销
    const registerBtn = btn("登记 HKCU 子树", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      if (!subkey.value) { toast("请填写子树", "warn"); return; }
      const tid = readPrivacyId(); if (!tid) return;
      await run("privacy", async () => {
        const r = await api("privacy_guard", "register_registry_scope", {
          task_id: tid, root: "HKCU", subkey: subkey.value,
          publisher: publisher.value || "", ownership_note: owner.value, reason,
          confirmation: "我已审查并批准"
        });
        if (bizFail(r)) throw new Error("登记失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "已登记");
    });
    const removeScopeBtn = btn("撤销 HKCU 子树登记", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      if (!subkey.value) { toast("请填写子树", "warn"); return; }
      const tid = readPrivacyId(); if (!tid) return;
      await run("privacy", async () => {
        const r = await api("privacy_guard", "remove_registry_scope", {
          task_id: tid, subkey: subkey.value, reason,
          confirmation: "我已审查并批准"
        });
        if (bizFail(r)) throw new Error("撤销失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "已撤销");
    });
    const setBtn = btn("审查·设置值", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      if (!subkey.value || !valueName.value) { toast("必填 子树/值名", "warn"); return; }
      const tid = readPrivacyId(); if (!tid) return;
      await run("privacy", async () => {
        const plan = await api("privacy_guard", "plan_system_action", {
          action: "registry_set_string",
          args: { task_id: tid, root: "HKCU", subkey: subkey.value,
                 value_name: valueName.value, new_value: newVal.value || "" },
          reason
        });
        if (!plan || !plan.token) throw new Error("计划失败：" + bizErr(plan));
        if (!confirm("设置 HKCU 注册表值：\n" + JSON.stringify(plan, null, 2))) return;
        const cap = await api("privacy_guard", "approve_system_action", {
          token: plan.token, confirmation: "我已审查并批准", reason, approval_context: "web_dialog"
        });
        if (!cap || !cap.approval_token) throw new Error("批准失败：" + (cap && cap.error ? cap.error : "无批准能力"));
        const r = await api("privacy_guard", "execute_system_action", {
          approval_token: cap.approval_token, reason
        });
        if (bizFail(r)) throw new Error("执行失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "已设置");
    });
    const delBtn = btn("审查·删除值", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      if (!subkey.value || !valueName.value) { toast("必填 子树/值名", "warn"); return; }
      const tid = readPrivacyId(); if (!tid) return;
      await run("privacy", async () => {
        const plan = await api("privacy_guard", "plan_system_action", {
          action: "registry_delete_value",
          args: { task_id: tid, root: "HKCU", subkey: subkey.value,
                 value_name: valueName.value },
          reason
        });
        if (!plan || !plan.token) throw new Error("计划失败：" + bizErr(plan));
        if (!confirm("删除 HKCU 注册表值：\n" + JSON.stringify(plan, null, 2))) return;
        const cap = await api("privacy_guard", "approve_system_action", {
          token: plan.token, confirmation: "我已审查并批准", reason, approval_context: "web_dialog"
        });
        if (!cap || !cap.approval_token) throw new Error("批准失败：" + (cap && cap.error ? cap.error : "无批准能力"));
        const r = await api("privacy_guard", "execute_system_action", {
          approval_token: cap.approval_token, reason
        });
        if (bizFail(r)) throw new Error("执行失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "已删除");
    });

    // ④ Canvas / WLAN
    const enableCanvasBtn = btn("启用 Canvas 扰动", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      if (!site.value) { toast("请填写站点", "warn"); return; }
      await run("privacy", async () => {
        const r = await api("privacy_guard", "set_canvas_guard",
          { site: site.value, enabled: true, reason });
        if (bizFail(r)) throw new Error("启用失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const disableCanvasBtn = btn("停用 Canvas 扰动", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      if (!site.value) { toast("请填写站点", "warn"); return; }
      await run("privacy", async () => {
        const r = await api("privacy_guard", "set_canvas_guard",
          { site: site.value, enabled: false, reason });
        if (bizFail(r)) throw new Error("停用失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const macBtn = btn("WLAN 随机硬件地址能力", async () => {
      await run("privacy", async () => {
        const r = await api("privacy_guard", "mac_randomization_status", {});
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const wifiBtn = btn("审查·打开 Windows WLAN 设置", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      await run("privacy", async () => {
        const plan = await api("privacy_guard", "plan_system_action",
          { action: "open_wifi_privacy_settings", args: {}, reason });
        if (!plan || !plan.token) throw new Error("计划失败：" + bizErr(plan));
        if (!confirm("打开 Windows WLAN 隐私设置：\n" + JSON.stringify(plan, null, 2))) return;
        const cap = await api("privacy_guard", "approve_system_action",
          { token: plan.token, confirmation: "我已审查并批准", reason, approval_context: "web_dialog" });
        if (!cap || !cap.approval_token) throw new Error("批准失败：" + (cap && cap.error ? cap.error : "无批准能力"));
        const r = await api("privacy_guard", "execute_system_action",
          { approval_token: cap.approval_token, reason });
        if (bizFail(r)) throw new Error("执行失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });

    body.appendChild(card("全局原因（必填 ≥12 字，所有系统操作都看这里）",
      [formRow([["原因", reasonInput]])]));
    body.appendChild(card("① 能力 / 报告 / 范围", [
      formRow([["任务 ID", taskIdInput]]),
      toolbar([capsBtn, rulesBtn, taskReportBtn, registryScopesBtn], { primary: true }),
    ]));
    body.appendChild(card("② Sandbox 隔离", [
      formRow([["EXE", exe]]),
      toolbar([net, clip, "spacer", previewBtn, planLaunchBtn], { primary: true }),
    ]));
    body.appendChild(card("③ HKCU 注册表（先登记再修改）", [
      formRow([["子树", subkey], ["值名", valueName], ["新值", newVal]]),
      formRow([["发布者", publisher], ["所有权说明", owner]]),
      toolbar([registerBtn, removeScopeBtn, "spacer", setBtn, delBtn]),
      hint("HKLM 与系统身份范围确定性拒绝；HKCU 子树必须先登记并绑定 task + EXE。"),
    ]));
    body.appendChild(card("④ Canvas / WLAN", [
      formRow([["站点", site]]),
      toolbar([enableCanvasBtn, disableCanvasBtn, "spacer", macBtn, wifiBtn]),
    ]));
    body.appendChild(card("⑤ 结果", [output]));
  });
}

/* ============================================================
   M9 漏洞主流程
   ============================================================ */
function vHunt() {
  const body = viewTemplate("v_hunt", "漏洞主流程", "M9 · HUNT", "target", "flow", ({ output }) => {
    const aname = input("目标名");
    const apath = input("路径");
    const agentsSel = el("select");
    const refill = async () => {
      // 用独立状态 id，避免与外层按钮的 run("hunt") 共用状态条互相覆盖
      await run("hunt_refill", async () => {
        const rows = await api("hunt", "list_agents");
        agentsSel.innerHTML = "";
        (rows || []).forEach(a => {
          const o = el("option", null, (a.name || "?") + " #" + a.id);
          o.value = a.id; agentsSel.appendChild(o);
        });
        return (rows || []).length + " 个";
      });
    };
    const regBtn = btn("登记目标", async () => {
      if (!aname.value) { toast("请填写目标名", "warn"); return; }
      await run("hunt", async () => {
        const r = await api("hunt", "create_agent",
          { name: aname.value, path: apath.value, kind: "app" });
        if (bizFail(r)) throw new Error("登记失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        refill();
        return "已登记";
      });
    }, false, true);
    onEnter(aname, regBtn); onEnter(apath, regBtn);
    const startBtn = btn("开始观察", async () => {
      if (!agentsSel.value) { toast("请先登记并选择目标", "warn"); return; }
      await run("hunt", async () => {
        const r = await api("hunt", "start_hunt",
          { agent_id: Number(agentsSel.value), title: "Web 集中观察" });
        if (bizFail(r)) throw new Error("开始观察失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已启动";
      });
    });
    const recentBtn = btn("最近观察", async () => {
      await run("hunt", async () => {
        const rows = await api("hunt", "recent_hunts", { limit: 30 });
        output.innerHTML = ""; output.appendChild(table(rows || [], "最近观察"));
        return (rows || []).length + " 条";
      }, "已加载");
    });

    // ③ 观察收尾：收集证据 / AI 分析 / 标记完成 / 详情（M9 观察-标记-沉淀闭环）
    const obsId = input("观察 ID（最近观察列表中的 id）");
    const readObsId = () => {
      const n = Number(obsId.value);
      if (!obsId.value.trim() || !Number.isFinite(n) || n <= 0) {
        toast("请输入有效的观察 ID（正整数）", "warn"); return 0;
      }
      return Math.trunc(n);
    };
    const collectBtn = btn("收集证据", async () => {
      const id = readObsId(); if (!id) return;
      await run("hunt", async () => {
        const r = await api("hunt", "collect_evidence", { obs_id: id });
        if (bizFail(r)) throw new Error("收集失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已收集 " + (r && r.evidence_blocks ? r.evidence_blocks + " 个证据块" : "");
      }, "已收集");
    });
    const aiBtn = btn("AI 分析观察", async () => {
      const id = readObsId(); if (!id) return;
      await run("hunt", async () => {
        const r = await api("hunt", "analyze_with_ai", { obs_id: id });
        if (bizFail(r)) throw new Error("AI 分析失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "AI 完成";
      }, "AI 完成");
    });
    const finishBtn = btn("标记完成", async () => {
      const id = readObsId(); if (!id) return;
      const risk = window.prompt("风险（高/中/低/无）", "低");
      if (!risk) return;
      const category = window.prompt("类别", "其他") || "其他";
      const mark = window.prompt("标记（可空）") || "";
      const conclusion = window.prompt("结论（可空）") || "";
      await run("hunt", async () => {
        const r = await api("hunt", "finish_observation",
          { obs_id: id, risk, category, mark, conclusion });
        if (bizFail(r)) throw new Error("标记失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已标记入库并回流经验";
      }, "已标记");
    });
    const detailBtn = btn("查看详情", async () => {
      const id = readObsId(); if (!id) return;
      await run("hunt", async () => {
        const r = await api("hunt", "get_hunt", { obs_id: id });
        if (r === null || r === undefined) throw new Error("观察 #" + id + " 不存在");
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });

    body.appendChild(card("① 登记目标", [
      formRow([["目标名", aname], ["路径", apath]]),
      toolbar([regBtn], { primary: true }),
    ]));
    body.appendChild(card("② 选择目标 + 开始", [
      formRow([["目标", agentsSel]]),
      toolbar([startBtn, recentBtn], { primary: true }),
    ]));
    body.appendChild(card("③ 观察收尾（收集 → AI 分析 → 标记入库）", [
      formRow([["观察 ID", obsId]]),
      toolbar([collectBtn, aiBtn, finishBtn, detailBtn]),
      hint("标记完成会写入 observations 并回流 knowledge/embedding 经验库（观察-标记-沉淀闭环）。"),
    ]));
    body.appendChild(card("④ 结果", [output]));
    refill();
  });
}

/* ============================================================
   M5 自我进化（evolve）
   ============================================================ */
function vEvolve() {
  const body = viewTemplate("v_evolve", "自我进化", "M5 · EVOLVE", "broom", "analysis", ({ output }) => {
    const mineBtn = btn("挖掘候选规则", async () => {
      await run("evolve", async () => {
        const r = await api("evolve", "mine_rules");
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "已挖掘");
    });
    const adjustBtn = btn("调整观察权重", async () => {
      await run("evolve", async () => {
        const r = await api("evolve", "adjust_weights", { auto_apply: false });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成（候选调整，未落库）";
      });
    });
    const adjustApplyBtn = btn("调整并确认应用", async () => {
      if (!confirm("确认把热点类别规则的 risk_weight 上调 0.05 并落库？")) return;
      await run("evolve", async () => {
        const r = await api("evolve", "adjust_weights", { auto_apply: true });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已按确认应用";
      }, "已应用");
    });
    const reportBtn = btn("查看最近报告", async () => {
      await run("evolve", async () => {
        const r = await api("evolve", "report");
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const applyBtn = btn("挖掘并确认写入", async () => {
      if (!confirm("确认把候选规则直接写入经验库（mine_rules auto_apply=true）？")) return;
      await run("evolve", async () => {
        const r = await api("evolve", "mine_rules", { auto_apply: true });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已按确认写入";
      }, "已写入");
    });

    body.appendChild(card("① 进化（默认 auto_apply=false；「确认」类按钮是显式人工确认入口）", [
      toolbar([mineBtn, applyBtn, "spacer", adjustBtn, adjustApplyBtn], { primary: true }),
      toolbar([reportBtn]),
      hint("挖掘候选规则/权重调整默认不落库；确认候选后点「挖掘并确认写入」「调整并确认应用」显式入库（走同一 facade，全程审计）。"),
    ]));
    body.appendChild(card("② 结果", [output]));
  });
}

/* ============================================================
   设置
   ============================================================ */
function vSettings() {
  const body = viewTemplate("v_settings", "设置", "CONFIG", "gear", "system", ({ output }) => {

    body.appendChild(card("① 模块开关（重启生效）", [
      (function () {
        const sw = el("div", "switch-grid");
        api("config", "switches").then(s => {
          sw.innerHTML = "";
          const m = new Map();
          Object.entries(s.switches || {}).forEach(([k, on]) => {
            if (k === "ui") return;  // 关闭即 Web 消失，不展示以免自锁
            const swEl = el("label", "switch" + (on ? " on" : ""));
            swEl.appendChild(el("span", "name", k));
            swEl.appendChild(el("span", "toggle"));
            sw.appendChild(swEl);
            m.set(k, swEl);
            swEl.onclick = () => {
              const now = swEl.classList.contains("on");
              swEl.classList.toggle("on", !now);
              const cfg = { switches: {} };
              m.forEach((node, key) => {
                cfg.switches[key] = node.classList.contains("on");
              });
              api("config", "set_switches", { switches: cfg.switches })
                .then(() => toast("开关已保存", "ok"))
                .catch(e => { swEl.classList.toggle("on", now); toast(e.message, "err"); });
            };
          });
        }).catch(e => toast("加载失败: " + e.message, "err"));
        return sw;
      }()),
    ]));

    body.appendChild(card("② 大模型配置（AI 辅助 / Agent 使用）", [
      (function () {
        const base = input("base_url（如 https://api.deepseek.com/v1）", "wide");
        const key = input("api_key", "wide"); key.type = "password";
        const model = input("model（如 deepseek-v4-flash）");
        api("config", "get_ai").then(c => {
          base.value = c.base_url || ""; key.value = c.api_key || ""; model.value = c.model || "";
        }).catch(e => toast("读取 AI 配置失败: " + e.message, "warn"));
        const saveBtn = el("button", "primary", "保存 AI 配置");
        saveBtn.onclick = async () => {
          await run("cfg_ai", async () => {
            const r = await api("config", "save_ai",
              { base_url: base.value.trim(), api_key: key.value.trim(), model: model.value.trim() });
            if (bizFail(r)) throw new Error("保存失败：" + bizErr(r));
            return "已保存";
          }, "已保存到 config.json");
        };
        return [formRow([["base_url", base], ["model", model]]),
                formRow([["api_key", key]]),
                toolbar([saveBtn])];
      }()),
    ]));

    body.appendChild(card("③ 系统集成", [
      (function () {
        const auto = el("label", "checkbox");
        const cb = el("input"); cb.type = "checkbox";
        auto.appendChild(cb); auto.appendChild(document.createTextNode("开机自启（最小化到托盘）"));
        api("autostart", "is_enabled").then(r => cb.checked = !!r.enabled).catch(() => {});
        cb.onchange = () => api("autostart", "set_enabled", { enabled: cb.checked })
          .then(() => toast("自启已 " + (cb.checked ? "开启" : "关闭"), "ok"))
          .catch(e => { cb.checked = !cb.checked; toast(e.message, "err"); });
        return auto;
      }()),
    ]));

    body.appendChild(card("④ 数据库（观察库 / 经验库）", [
      (function () {
        function reload(kind) {
          api("db", kind === "obs" ? "observations" : "knowledge",
            { limit: kind === "obs" ? 100 : 200 })
            .then(r => {
              output.innerHTML = "";
              output.appendChild(table(r || [], kind === "obs" ? "观察库" : "经验库"));
            })
            .catch(e => toast("加载失败: " + e.message, "err"));
        }
        const wrap = el("div");
        wrap.appendChild(el("div", "toolbar"));
        const row = wrap.firstChild;
        ["obs", "know"].forEach(k => {
          const b = el("button", null, k === "obs" ? "加载观察库" : "加载经验库");
          b.onclick = () => reload(k);
          row.appendChild(b);
        });
        const oid = el("input"); oid.placeholder = "观察条目 ID";
        const kid = el("input"); kid.placeholder = "经验条目 ID";
        const delBtn = el("button", "primary", "删除观察");
        delBtn.onclick = async () => {
          const id = Number(oid.value);
          if (!id || id <= 0) { toast("请填写有效 ID", "warn"); return; }
          await run("db", async () => {
            const r = await api("db", "delete_observation", { oid: id });
            if (bizFail(r)) throw new Error("删除失败：" + bizErr(r));
            return "已删除";
          });
        };
        const delKBtn = el("button", "primary", "删除经验");
        delKBtn.onclick = async () => {
          const id = Number(kid.value);
          if (!id || id <= 0) { toast("请填写有效 ID", "warn"); return; }
          await run("db", async () => {
            const r = await api("db", "delete_knowledge", { kid: id });
            if (bizFail(r)) throw new Error("删除失败：" + bizErr(r));
            return "已删除";
          });
        };
        const offBtn = el("button", null, "停用经验");
        offBtn.onclick = async () => {
          const id = Number(kid.value);
          if (!id || id <= 0) { toast("请填写有效 ID", "warn"); return; }
          await run("db", async () => {
            const r = await api("db", "set_knowledge_enabled", { kid: id, enabled: false });
            if (bizFail(r)) throw new Error("停用失败：" + bizErr(r));
            return "已停用";
          });
        };
        const onBtn = el("button", null, "启用经验");
        onBtn.onclick = async () => {
          const id = Number(kid.value);
          if (!id || id <= 0) { toast("请填写有效 ID", "warn"); return; }
          await run("db", async () => {
            const r = await api("db", "set_knowledge_enabled", { kid: id, enabled: true });
            if (bizFail(r)) throw new Error("启用失败：" + bizErr(r));
            return "已启用";
          });
        };
        wrap.appendChild(el("div", "toolbar"));
        const row2 = wrap.lastChild;
        row2.appendChild(oid); row2.appendChild(delBtn);
        row2.appendChild(kid); row2.appendChild(delKBtn);
        row2.appendChild(offBtn); row2.appendChild(onBtn);
        return wrap;
      }()),
    ]));

    body.appendChild(card("⑤ 结果", [output]));
  });
}

/* ============================================================
   AI 助手（M10 agent 入口，未配置 key 时仅显示提示）
   ============================================================ */
function vAgent() {
  const body = viewTemplate("v_agent", "AI 助手", "M10 · AGENT", "lock", "flow", ({ output }) => {
    const task = textarea("在此输入任务指令（如：列出可疑进程并标记高风险）", "", 3);
    const runBtn = btn("发送给 Agent", async () => {
      await run("agent", async () => {
        const r = await api("agent", "run_task", { task: task.value });
        if (bizFail(r)) throw new Error("Agent 失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return r && r.final ? "Agent 完成" : "Agent 完成（无 final 文本）";
      });
    }, false, true);
    body.appendChild(card("① 任务", [task, toolbar([runBtn], { primary: true })]));
    body.appendChild(card("② 结果", [output,
      hint("Agent 命令经独立审核模型 + 人工弹窗审批；高危工具需逐项确认。"),
    ]));
  });
}

/* ============================================================
   连接指示
   ============================================================ */
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
  goto(target);
}
boot();
