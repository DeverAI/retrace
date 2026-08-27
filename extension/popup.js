// ReTrace 插件弹出面板
const portEl = document.getElementById("port");
const tokenEl = document.getElementById("token");
const statusEl = document.getElementById("status");

function setStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = cls || "";
}

(async () => {
  const got = await chrome.storage.local.get(["rt_token", "rt_port"]);
  // 检修（2026-08-27）：不再把明文 Token 回显进输入框，只给首尾掩码摘要；
  // 与 Web 控制台同一语义——留空=保留已存，仅输入新值才覆盖。
  if (got.rt_token) {
    const t = String(got.rt_token);
    const mask = t.length > 8 ? t.slice(0, 4) + "…" + t.slice(-4) : "••••";
    tokenEl.placeholder = "已保存 " + mask + "（留空=保留；输入新值覆盖）";
  } else {
    tokenEl.placeholder = "未配置：粘贴 config.json → browser.token";
  }
  if (got.rt_port) portEl.value = got.rt_port;
  setStatus("已读取配置");
})();

document.getElementById("save").addEventListener("click", async () => {
  const fresh = tokenEl.value.trim();
  const patch = { rt_port: parseInt(portEl.value, 10) || 8765 };
  let tokenChanged = false;
  if (fresh) {
    patch.rt_token = fresh;
    tokenChanged = true;
  }
  await chrome.storage.local.set(patch);
  if (!tokenChanged) {
    setStatus("端口已保存；Token 未改动", "ok");
    return;
  }
  setStatus("已保存，正在重连...", "ok");
});

document.getElementById("snap").addEventListener("click", async () => {
  setStatus("快照中...");
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return setStatus("无活动标签", "err");
  try {
    const res = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        // 受限页面（chrome://、about:blank、sandboxed iframe）访问 localStorage/
        // sessionStorage 会抛 SecurityError，逐项 try/catch，失败记 null 不中断快照。
        let localKeys = null;
        let sessionKeys = null;
        try { localKeys = Object.keys(localStorage || {}).length; } catch (_) {}
        try { sessionKeys = Object.keys(sessionStorage || {}).length; } catch (_) {}
        return {
          title: document.title,
          url: location.href,
          cookieEnabled: navigator.cookieEnabled,
          localKeys,
          sessionKeys
        };
      }
    });
    const r = res[0].result;
    const fmt = (n) => (n === null ? "受限" : String(n));
    setStatus(`标题:${r.title.slice(0, 20)} | 存储:${fmt(r.localKeys)}+${fmt(r.sessionKeys)}`, "ok");
  } catch (e) {
    setStatus("快照失败: " + e, "err");
  }
});

const observeBtn = document.getElementById("observe");
const unobserveBtn = document.getElementById("unobserve");

function runObserve(on) {
  return chrome.tabs.query({}).then((tabs) =>
    Promise.allSettled(tabs.map((tab) =>
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (enable) => {
          window.__rtObserve = enable;
          if (enable && !window.__rtObserver) {
            const push = (type, node) => {
              const detail = node && node.nodeName
                ? `${node.nodeName}:${(node.id || "")}:${String(node.className || "").slice(0, 60)}`
                : "";
              window.postMessage({ __rtDom: { type, detail, href: location.href } }, "*");
            };
            window.__rtObserver = new MutationObserver((muts) => {
              if (!window.__rtObserve) return;
              for (const m of muts) {
                if (m.type === "childList") m.addedNodes.forEach((n) => push("dom_added", n));
                else if (m.type === "attributes") push("attr_changed", m.target);
              }
            });
            window.__rtObserver.observe(document, {
              childList: true, subtree: true, attributes: true
            });
          } else if (!enable && window.__rtObserver) {
            window.__rtObserver.disconnect();
            window.__rtObserver = null;
          }
        },
        args: [enable]
      }).catch(() => {})
    ))
  );
}

observeBtn.addEventListener("click", async () => {
  await runObserve(true);
  setStatus("DOM 观察已开启", "ok");
});

unobserveBtn.addEventListener("click", async () => {
  await runObserve(false);
  setStatus("DOM 观察已关闭", "ok");
});

async function currentSite() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return "";
  try { return new URL(tab.url).origin; } catch (_) { return ""; }
}

async function setCanvas(on) {
  const site = await currentSite();
  const out = document.getElementById("canvasStatus");
  if (!site || !/^https?:/.test(site)) {
    out.textContent = "当前页面不是可保护的 HTTP(S) 站点"; return;
  }
  // 与后端 privacy_guard.set_canvas_guard 同一契约：原因必须 ≥12 字，
  // 由用户在 popup 显式填写（用户手势 + 明确原因并列）。
  const reasonEl = document.getElementById("canvasReason");
  const reason = (reasonEl.value || "").trim();
  if (reason.length < 12) {
    out.textContent = "请先填写至少 12 字的启用/停用原因（目的、对象、必要性）"; return;
  }
  const result = await chrome.runtime.sendMessage({
    __rtSetCanvasSite: true, site, enabled: on, reason
  });
  out.textContent = result && result.ok
    ? `${site}：${on ? "已启用" : "已停用"}（原因已随设置上报审计）`
    : `操作失败：${result && result.error}`;
  if (result && result.ok) reasonEl.value = "";
}

document.getElementById("canvasOn").addEventListener("click", () => setCanvas(true));
document.getElementById("canvasOff").addEventListener("click", () => setCanvas(false));

document.getElementById("clearSite").addEventListener("click", async () => {
  const out = document.getElementById("clearStatus");
  const site = await currentSite();
  if (!site || !/^https?:/.test(site)) {
    out.textContent = "当前页面不是可清除的 HTTP(S) 站点"; return;
  }
  const reason = (document.getElementById("canvasReason").value || "").trim();
  if (reason.length < 12) {
    out.textContent = "请先填写至少 12 字的清除原因（目的、对象、必要性）"; return;
  }
  const result = await chrome.runtime.sendMessage({
    __rtClearSite: true, site, reason
  });
  out.textContent = result && result.ok
    ? `${site}：痕迹已清除（cookies/cache/存储/SW），原因已上报审计`
    : `清除失败：${result && result.error}`;
});
