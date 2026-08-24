
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
  // 同步 hash（相同值不触发 hashchange，无循环风险）
  try {
    if (location.hash !== "#" + id) history.replaceState(null, "", "#" + id);
  } catch (e) { /* ignore */ }
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
