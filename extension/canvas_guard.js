// ReTrace Canvas API mitigation. Installed only for a user-approved top-level site.
// Evidence sent with postMessage is correlated/untrusted because page code can forge it.
(function () {
  if (window.__retraceInstallCanvasGuard) return;
  window.__retraceInstallCanvasGuard = function installCanvasGuard(seed, topSite) {
    if (window.__retraceCanvasGuard) return false;
    window.__retraceCanvasGuard = { topSite: String(topSite || ""), mode: "top-site-noise" };
    let lastNotice = 0;
    const notify = (api) => {
      const now = Date.now();
      if (now - lastNotice < 1000) return;
      lastNotice = now;
      window.postMessage({ __rtPrivacy: {
        type: "canvas_read", api, origin: location.origin,
        topSite: String(topSite || ""), confidence: "correlated_untrusted",
        mode: "top-site-stable-deterministic-noise"
      } }, "*");
    };
    const C2D = window.CanvasRenderingContext2D;
    const Canvas = window.HTMLCanvasElement;
    if (!C2D || !Canvas) return false;
    const rawGet = C2D.prototype.getImageData;
    const rawPut = C2D.prototype.putImageData;
    const rawDraw = C2D.prototype.drawImage;
    const rawURL = Canvas.prototype.toDataURL;
    const rawBlob = Canvas.prototype.toBlob;
    const mix = (n) => {
      n = (n ^ (n >>> 16)) >>> 0; n = Math.imul(n, 0x45d9f3b) >>> 0;
      n = (n ^ (n >>> 16)) >>> 0; return n;
    };
    // 确定性噪声：对像素施加由 (seed, i) 派生的小幅偏移（-2..+2，保留 alpha）。
    // 同 seed 同站点输出完全一致；跨站点 seed 不同，输出不同。
    // 性能上界：单像素约 10 条运算；超过 MAX_WORK 像素的画布（如 4000×4000=1600 万）
    // 按确定性步长抽样扰动，工作总量封顶约 30 万像素，避免每次 Canvas 读取都
    // 全图重算而阻塞主线程数秒。
    const perturb = (img) => {
      const copy = new Uint8ClampedArray(img.data);
      const pixels = Math.floor(copy.length / 4);
      if (!pixels) return new ImageData(copy, img.width, img.height);
      const seed32 = Number(seed) >>> 0;
      const MAX_WORK = 300000;
      const stride = pixels > MAX_WORK ? Math.ceil(pixels / MAX_WORK) : 1;
      for (let i = 0; i < pixels; i += stride) {
        const h = mix(seed32 ^ i * 0x9e3779b9);
        const dx = (h % 5) - 2;              // -2..+2
        const dy = ((h >>> 8) % 5) - 2;
        const dz = ((h >>> 16) % 5) - 2;
        const base = i * 4;
        const r = copy[base] + dx;
        copy[base] = r < 0 ? 0 : (r > 255 ? 255 : r);
        const g = copy[base + 1] + dy;
        copy[base + 1] = g < 0 ? 0 : (g > 255 ? 255 : g);
        const b = copy[base + 2] + dz;
        copy[base + 2] = b < 0 ? 0 : (b > 255 ? 255 : b);
      }
      return new ImageData(copy, img.width, img.height);
    };
    C2D.prototype.getImageData = function (...args) {
      const out = rawGet.apply(this, args); notify("getImageData"); return perturb(out);
    };
    const protectedCopy = (canvas) => {
      const copy = document.createElement("canvas");
      copy.width = canvas.width; copy.height = canvas.height;
      const ctx = copy.getContext("2d");
      rawDraw.call(ctx, canvas, 0, 0);
      if (copy.width && copy.height) {
        const img = rawGet.call(ctx, 0, 0, copy.width, copy.height);
        rawPut.call(ctx, perturb(img), 0, 0);
      }
      return copy;
    };
    Canvas.prototype.toDataURL = function (...args) {
      notify("toDataURL"); return rawURL.apply(protectedCopy(this), args);
    };
    Canvas.prototype.toBlob = function (...args) {
      notify("toBlob"); return rawBlob.apply(protectedCopy(this), args);
    };
    try { delete window.__retraceInstallCanvasGuard; } catch (_) {}
    return true;
  };
})();
