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
  // 深度拍平：子项本身可以是数组（如 IIFE 返回 [formRow, toolbar] 的场景）
  const flat = [];
  const push = (x) => {
    if (Array.isArray(x)) x.forEach(push);
    else if (x) flat.push(x);
  };
  push(content);
  flat.forEach(x => c.appendChild(x));
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

/* ---- Markdown 渲染（AI 结果专用；先整体 HTML 转义再转换，防注入） ---- */
function _mdInline(s) {
  return escapeHtml(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>")
    .replace(/(^|[^*\w])\*([^*\n]+)\*/g, "$1<i>$2</i>")
    .replace(/~~([^~]+)~~/g, "<s>$1</s>");
}
function mdToHtml(src) {
  const lines = String(src || "").replace(/\r\n/g, "\n").split("\n");
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    // 围栏代码块
    if (/^\s*```/.test(line)) {
      const buf = [];
      i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) { buf.push(lines[i]); i++; }
      i++;
      out.push('<pre class="md-code"><code>' + escapeHtml(buf.join("\n")) + "</code></pre>");
      continue;
    }
    // 表格：本行 | 分列 且下一行是 |---|---| 分隔行
    if (/^\s*\|.*\|\s*$/.test(line) && i + 1 < lines.length &&
        /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1])) {
      const cells = (l) => l.trim().replace(/^\|/, "").replace(/\|$/, "")
        .split("|").map(c => c.trim());
      const head = cells(line);
      i += 2;
      const rows = [];
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) {
        rows.push(cells(lines[i])); i++;
      }
      let h = '<table class="md-table"><thead><tr>';
      head.forEach(c => { h += "<th>" + _mdInline(c) + "</th>"; });
      h += "</tr></thead><tbody>";
      rows.forEach(r => {
        h += "<tr>";
        head.forEach((_c, ci) => { h += "<td>" + _mdInline(r[ci] || "") + "</td>"; });
        h += "</tr>";
      });
      h += "</tbody></table>";
      out.push(h);
      continue;
    }
    // 标题
    const hm = line.match(/^(#{1,6})\s+(.*)$/);
    if (hm) {
      const lv = hm[1].length;
      out.push("<h" + lv + ' class="md-h">' + _mdInline(hm[2]) + "</h" + lv + ">");
      i++; continue;
    }
    // 分隔线
    if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      out.push('<hr class="md-hr">'); i++; continue;
    }
    // 引用块
    if (/^\s*>\s?/.test(line)) {
      const buf = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) {
        buf.push(lines[i].replace(/^\s*>\s?/, "")); i++;
      }
      out.push('<blockquote class="md-quote">' + _mdInline(buf.join(" ")) + "</blockquote>");
      continue;
    }
    // 列表（单层）
    const isUl = /^\s*[-*]\s+/.test(line);
    const isOl = /^\s*\d+[.、)]\s+/.test(line);
    if (isUl || isOl) {
      const re = isUl ? /^\s*[-*]\s+(.*)$/ : /^\s*\d+[.、)]\s+(.*)$/;
      const tag = isUl ? "ul" : "ol";
      let h = "<" + tag + ' class="md-list">';
      while (i < lines.length) {
        const m = lines[i].match(re);
        if (!m) break;
        h += "<li>" + _mdInline(m[1]) + "</li>";
        i++;
      }
      h += "</" + tag + ">";
      out.push(h);
      continue;
    }
    // 空行
    if (!line.trim()) { out.push(""); i++; continue; }
    // 段落：连续普通行合并，段内单换行转 <br>
    const buf = [];
    while (i < lines.length && lines[i].trim() &&
           !/^\s*(#{1,6}\s|[-*]\s|\d+[.、)]\s|>|```)/.test(lines[i]) &&
           !/^\s*\|.*\|\s*$/.test(lines[i])) {
      buf.push(_mdInline(lines[i]));
      i++;
    }
    out.push('<p class="md-p">' + buf.join("<br>") + "</p>");
  }
  return out.join("\n");
}
function mdBlock(text) {
  const wrap = el("div", "md-block");
  wrap.innerHTML = mdToHtml(text);
  return wrap;
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
