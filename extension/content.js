// ReTrace 页面探针：把注入脚本经 postMessage 发出的 DOM/隐私事件转发给扩展后台。
// 注意：
// 1) 不读取/不上报 localStorage、sessionStorage、cookie——那既无消费方又属于多余
//    数据暴露面（sandboxed iframe 中读取还会抛 SecurityError）。
// 2) 转发监听只注册一次（__rtBooted 幂等），后台不再二次注入同名监听，
//    避免 MutationObserver 事件被重复上报。
(function () {
  if (window.__rtBooted) return;
  window.__rtBooted = true;

  window.addEventListener("message", (ev) => {
    // 检修（2026-08-27）：扩展更新/重载后旧页面的残留 content script 调用
    // sendMessage 会同步抛 "Extension context invalidated"，必须吞掉，
    // 否则每次页面消息都刷错误控制台。
    try {
      if (ev.data && ev.data.__rtDom) {
        chrome.runtime.sendMessage({ __rtDomFromPage: ev.data.__rtDom });
      }
      if (ev.data && ev.data.__rtPrivacy) {
        chrome.runtime.sendMessage({ __rtPrivacyFromPage: ev.data.__rtPrivacy });
      }
    } catch (_) {
      /* 扩展上下文已失效：静默丢弃 */
    }
  }, true);
})();
