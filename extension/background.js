// ReTrace 扩展后台：WebSocket 中枢桥接 + 命令路由
let ws = null;
let token = "";
let reconnectTimer = null;
const HOST = "127.0.0.1";
const PORT = 8765;
const topOriginByTab = new Map();
const privacyNoticeAt = new Map();

function normalizeSite(url) {
  try { return new URL(url).origin; } catch (_) { return ""; }
}

async function canvasSettings() {
  const got = await chrome.storage.local.get(["rt_canvas_sites", "rt_canvas_salt"]);
  let salt = got.rt_canvas_salt || "";
  if (!salt) {
    const raw = crypto.getRandomValues(new Uint8Array(16));
    salt = Array.from(raw, (x) => x.toString(16).padStart(2, "0")).join("");
    await chrome.storage.local.set({ rt_canvas_salt: salt });
  }
  return { sites: Array.isArray(got.rt_canvas_sites) ? got.rt_canvas_sites : [], salt };
}

async function seedFor(site, salt) {
  const bytes = new TextEncoder().encode(`${salt}|${site}|ReTraceCanvasGuard-v1`);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  // 确定性、按站点稳定的 seed（32 位）。注意：这不是对页面不可观测的秘密——
  // seed 会作为参数注入 MAIN world 供扰动函数使用，页面理论上可观测/反推；
  // 其目的仅是"同站点稳定、跨站点不同"，避免第三方 iframe 借用稳定指纹跨站关联。
  return ((hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3]) >>> 0;
}

async function injectCanvasGuard(tabId, frameId, topSite) {
  const cfg = await canvasSettings();
  if (!topSite || !cfg.sites.includes(topSite)) return false;
  const seed = await seedFor(topSite, cfg.salt);
  try {
    await chrome.scripting.executeScript({
      target: { tabId, frameIds: [frameId] }, files: ["canvas_guard.js"], world: "MAIN"
    });
    await chrome.scripting.executeScript({
      target: { tabId, frameIds: [frameId] }, world: "MAIN",
      func: (value, site) => window.__retraceInstallCanvasGuard &&
        window.__retraceInstallCanvasGuard(value, site), args: [seed, topSite]
    });
    return true;
  } catch (_) { return false; }
}

async function setCanvasGuardSite(site, enabled, reason) {
  site = normalizeSite(site);
  if (!site) throw new Error("需要有效的顶级站点 origin");
  const cfg = await canvasSettings();
  const next = new Set(cfg.sites);
  enabled ? next.add(site) : next.delete(site);
  await chrome.storage.local.set({ rt_canvas_sites: Array.from(next) });
  send({ type: "privacy_event", event: {
    type: "canvas_guard_setting", topSite: site, enabled: !!enabled,
    reason: String(reason || "用户在扩展中显式选择"), confidence: "exact_extension_setting"
  }});
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    if (normalizeSite(tab.url || "") !== site) continue;
    await chrome.tabs.reload(tab.id).catch(() => {});
  }
  return { ok: true, site, enabled: !!enabled, reloaded: true,
           protection: "best_effort_document_start" };
}

async function loadToken() {
  const got = await chrome.storage.local.get(["rt_token", "rt_port"]);
  token = got.rt_token || "";
  return got;
}

async function getWsUrl() {
  const got = await loadToken();
  const port = got.rt_port || PORT;
  return `ws://${HOST}:${port}/?token=${encodeURIComponent(token)}`;
}

function connect() {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return;
  }
  getWsUrl().then((url) => {
    try {
      ws = new WebSocket(url);
    } catch (e) {
      scheduleReconnect();
      return;
    }
    ws.onopen = () => {
      console.log("[ReTrace] 已连接中枢");
      sendTabs();
      sendHello();
      if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    };
    ws.onclose = () => {
      console.log("[ReTrace] 连接断开");
      scheduleReconnect();
    };
    ws.onerror = () => {};
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        handleCommand(msg);
      } catch (e) { /* 忽略非法消息 */ }
    };
  });
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, 5000);
}

function send(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

function sendHello() {
  send({ type: "hello", client: "retrace-ext" });
}

async function sendTabs() {
  const tabs = await chrome.tabs.query({});
  send({
    type: "tabs",
    tabs: tabs.map((t) => ({ id: t.id, title: t.title || "", url: t.url || "" }))
  });
}

async function sendTabInfo(tab) {
  if (!tab || !tab.id) return;
  const t = await chrome.tabs.get(tab.id).catch(() => null);
  if (!t) return;
  send({ type: "tab_info", tab: { id: t.id, title: t.title || "", url: t.url || "" } });
}

async function handleCommand(msg) {
  if (msg.type !== "command") return;
  const cmd = msg.cmd;
  try {
    switch (cmd) {
      case "list_tabs":
        sendTabs();
        break;
      case "snapshot":
        await snapshot();
        break;
      case "activate":
        // 必须带数字 tabId，否则 chrome.tabs.update(undefined) 抛 TypeError
        const tid = Number(msg.tabId);
        if (!Number.isFinite(tid) || tid <= 0) {
          console.warn("[ReTrace] activate 缺少有效 tabId", msg);
          return;
        }
        await chrome.tabs.update(tid, { active: true });
        break;
      case "observe_dom":
        await setDomObserve(!!msg.enabled);
        break;
      case "canvas_guard":
        await setCanvasGuardSite(msg.site || "", !!msg.enabled, msg.reason || "");
        break;
      case "ping":
        send({ type: "hello", client: "retrace-ext", pong: true });
        break;
      default:
        console.log("[ReTrace] 未知命令", cmd);
    }
  } catch (e) {
    console.error("[ReTrace] 命令失败", cmd, e);
  }
}

async function snapshot() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab) return;
  try {
    const res = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        const links = Array.from(document.querySelectorAll("a[href]"))
          .slice(0, 200).map((a) => a.href);
        const forms = Array.from(document.querySelectorAll("form"))
          .slice(0, 50).map((f) => ({
            action: f.action || "", method: f.method || "",
            inputs: Array.from(f.querySelectorAll("input")).map((i) => ({
              name: i.name, type: i.type, value: (i.value || "").slice(0, 200)
            }))
          }));
        return {
          title: document.title,
          url: location.href,
          cookieEnabled: navigator.cookieEnabled,
          links,
          forms,
          scripts: performance.getEntriesByType("resource")
            .filter((r) => r.initiatorType === "script")
            .slice(0, 100).map((r) => r.name)
        };
      }
    });
    send({ type: "tab_info", tab: {
      id: tab.id, title: tab.title || "", url: tab.url || "",
      snapshot: res && res[0] && res[0].result
    }});
  } catch (e) {
    send({ type: "tab_info", tab: { id: tab.id, title: tab.title || "",
                                     url: tab.url || "", snapshotError: String(e) } });
  }
}

async function setDomObserve(enabled) {
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (on) => {
          window.__rtObserve = on;
          if (on && !window.__rtObserver) {
            const push = (type, node) => {
              const detail = node && node.nodeName
                ? `${node.nodeName}:${(node.id || "")}:${(node.className || "").slice(0, 60)}`
                : "";
              window.postMessage({ __rtDom: { type, detail, href: location.href } }, "*");
            };
            window.__rtObserver = new MutationObserver((muts) => {
              if (!window.__rtObserve) return;
              for (const m of muts) {
                if (m.type === "childList") {
                  m.addedNodes.forEach((n) => push("dom_added", n));
                } else if (m.type === "attributes") {
                  push("attr_changed", m.target);
                }
              }
            });
            window.__rtObserver.observe(document, {
              childList: true, subtree: true, attributes: true
            });
          } else if (!on && window.__rtObserver) {
            window.__rtObserver.disconnect();
            window.__rtObserver = null;
          }
          return window.__rtObserver ? true : false;
        },
        args: [enabled]
      });
    } catch (e) { /* 页面不可注入时报错跳过 */ }
  }
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete") {
    sendTabInfo(tab);
    // 注意：DOM 事件转发由 content.js（run_at=document_start，常驻）负责。
    // 此处不再重复注入转发监听，否则每个页面会有两条 __rtDom 监听，
    // 每条 MutationObserver 上报都会被转发两次，DOM 事件统计翻倍。
  }
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId === 0) topOriginByTab.set(details.tabId, normalizeSite(details.url));
  let topSite = details.frameId === 0
    ? normalizeSite(details.url) : (topOriginByTab.get(details.tabId) || "");
  if (!topSite && details.frameId !== 0) {
    const tab = await chrome.tabs.get(details.tabId).catch(() => null);
    topSite = normalizeSite(tab && tab.url || "");
    if (topSite) topOriginByTab.set(details.tabId, topSite);
  }
  await injectCanvasGuard(details.tabId, details.frameId, topSite);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  topOriginByTab.delete(tabId);
  for (const key of privacyNoticeAt.keys()) {
    if (key.startsWith(`${tabId}:`)) privacyNoticeAt.delete(key);
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.__rtDomFromPage) {
    send({ type: "dom_event", event: {
      tabId: sender.tab ? sender.tab.id : 0,
      ...msg.__rtDomFromPage
    }});
  }
  if (msg && msg.__rtPrivacyFromPage) {
    const raw = msg.__rtPrivacyFromPage || {};
    const api = ["getImageData", "toDataURL", "toBlob"].includes(raw.api) ? raw.api : "unknown";
    const tabId = sender.tab ? sender.tab.id : 0;
    const frameId = Number(sender.frameId || 0);
    const rateKey = `${tabId}:${frameId}:${api}`;
    const now = Date.now();
    if (now - (privacyNoticeAt.get(rateKey) || 0) >= 1000) {
      privacyNoticeAt.set(rateKey, now);
      if (privacyNoticeAt.size > 5000) {
        privacyNoticeAt.delete(privacyNoticeAt.keys().next().value);
      }
      send({ type: "privacy_event", event: {
        type: "canvas_read", api,
        origin: normalizeSite(sender.url || ""),
        mode: "top-site-stable-low-bit-noise",
        confidence: "correlated_untrusted",
        tabId, frameId,
        topSite: topOriginByTab.get(tabId) || normalizeSite(sender.tab && sender.tab.url || "")
      }});
    }
  }
  if (msg && msg.__rtSetCanvasSite) {
    setCanvasGuardSite(msg.site, !!msg.enabled,
      msg.reason || "用户在扩展面板显式启用当前顶级站点")
      .then(sendResponse).catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
});

chrome.storage.onChanged.addListener((changes) => {
  if (changes.rt_token || changes.rt_port) {
    if (ws) { try { ws.close(); } catch (e) {} }
    ws = null;
    connect();
  }
});

connect();
// MV3 service worker 空闲约 30s 即被终止，WebSocket 随之断开且 setInterval 无法
// 在休眠期间运行。用 chrome.alarms（最小周期 0.5 分钟，旧版 Chrome 回落 1 分钟）
// 定期唤醒 SW 并重连，保证中枢→扩展命令的最长投递延迟有界。
function scheduleKeepAlive() {
  try {
    chrome.alarms.create("rt-keepalive", { periodInMinutes: 0.5 });
  } catch (e) {
    try {
      chrome.alarms.create("rt-keepalive", { periodInMinutes: 1 });
    } catch (e2) { /* alarms 不可用时仅依赖页面事件唤醒 */ }
  }
}
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm && alarm.name === "rt-keepalive") {
    connect();
  }
});
scheduleKeepAlive();

setInterval(() => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    send({ type: "hello", heartbeat: Date.now() });
  }
}, 30000);
