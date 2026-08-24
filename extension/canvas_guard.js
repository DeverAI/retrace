// ReTrace 全谱指纹缓解（MAIN world 注入，仅对用户显式批准的顶级站点生效）。
// 覆盖面：2D Canvas 读取 / 文字度量 / WebGL 参数与像素 / Audio 频谱采样。
// 证据经 postMessage 上报属 correlated/untrusted（页面可伪造）。
// 噪声哲学与 v1 相同：同 (seed,站点) 输出完全确定；跨站点互不相同；
// 扰动幅度小到不破坏页面功能、大到足以瓦解跨会话哈希稳定。
(function () {
  if (window.__retraceInstallCanvasGuard) return;
  window.__retraceInstallCanvasGuard = function installCanvasGuard(seed, topSite) {
    if (window.__retraceCanvasGuard) return false;
    window.__retraceCanvasGuard = { topSite: String(topSite || ""), mode: "full-surface-noise" };
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

    // ---- 确定性噪声基元 ------------------------------------------------
    const mix = (n) => {
      n = (n ^ (n >>> 16)) >>> 0; n = Math.imul(n, 0x45d9f3b) >>> 0;
      n = (n ^ (n >>> 16)) >>> 0; return n;
    };
    const seed32 = Number(seed) >>> 0;
    // hash(seed, salt, i) -> 32bit；salt 区分 API 面，避免同一位置跨 API 相关
    const h32 = (salt, i) => mix((seed32 ^ Math.imul(salt, 0x9e3779b9) ^ i) >>> 0);
    const jitter3 = (h, amp) => [(h % (2 * amp + 1)) - amp,
                                 ((h >>> 8) % (2 * amp + 1)) - amp,
                                 ((h >>> 16) % (2 * amp + 1)) - amp];

    // ---- 1) 2D Canvas：像素级扰动 --------------------------------------
    const rawGet = C2D.prototype.getImageData;
    const rawPut = C2D.prototype.putImageData;
    const rawDraw = C2D.prototype.drawImage;
    const rawURL = Canvas.prototype.toDataURL;
    const rawBlob = Canvas.prototype.toBlob;
    const perturb = (img, saltConst) => {
      const copy = new Uint8ClampedArray(img.data);
      const pixels = Math.floor(copy.length / 4);
      if (!pixels) return new ImageData(copy, img.width, img.height);
      // 性能上界：超大画布按确定性步长抽样扰动，总量封顶 ~30 万像素
      const MAX_WORK = 300000;
      const stride = pixels > MAX_WORK ? Math.ceil(pixels / MAX_WORK) : 1;
      for (let i = 0; i < pixels; i += stride) {
        const [dx, dy, dz] = jitter3(h32(saltConst, i), 2);   // -2..+2
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
      notify("getImageData"); return perturb(rawGet.apply(this, args), 0x01);
    };
    const protectedCopy = (canvas) => {
      const copy = document.createElement("canvas");
      copy.width = canvas.width; copy.height = canvas.height;
      const ctx = copy.getContext("2d");
      rawDraw.call(ctx, canvas, 0, 0);
      if (copy.width && copy.height) {
        const img = rawGet.call(ctx, 0, 0, copy.width, copy.height);
        rawPut.call(ctx, perturb(img, 0x02), 0, 0);
      }
      return copy;
    };
    Canvas.prototype.toDataURL = function (...args) {
      notify("toDataURL"); return rawURL.apply(protectedCopy(this), args);
    };
    Canvas.prototype.toBlob = function (...args) {
      notify("toBlob"); return rawBlob.apply(protectedCopy(this), args);
    };

    // ---- 2) 文字度量：measureText 宽度加确定性微偏移 --------------------
    // 字体探测的经典手法是比对几十个字符串的 sub-pixel 宽度差；±0.02px 的
    // 确定性偏移足以打乱哈希，肉眼与排版不可感知。
    try {
      const rawMeasure = C2D.prototype.measureText;
      // TextMetrics 的度量是 IDL 原型 getter（依赖内部槽位），
      // Object.create(proto) 的裸对象读取会 Illegal invocation。
      // 因此逐字段从真实对象取值，包一层普通对象返回。
      const METRIC_FIELDS = ["width", "actualBoundingBoxLeft",
        "actualBoundingBoxRight", "actualBoundingBoxAscent",
        "actualBoundingBoxDescent", "fontBoundingBoxAscent",
        "fontBoundingBoxDescent"];
      C2D.prototype.measureText = function (...args) {
        const m = rawMeasure.apply(this, args);
        notify("measureText");
        const out = {};
        const j = (h32(0x03, Math.round((m.width || 0) * 1024)) % 41 - 20) * 0.001;
        for (const f of METRIC_FIELDS) {
          if (m[f] === undefined) continue;
          out[f] = (f === "width" || f === "actualBoundingBoxLeft" ||
                    f === "actualBoundingBoxRight") ? (m[f] + j) : m[f];
        }
        return out;
      };
    } catch (_) { /* 老引擎无 measureText 属性描述符时放弃该面 */ }

    // ---- 3) WebGL：参数伪装 + readPixels 扰动 ---------------------------
    try {
      const GL_VENDOR = 0x1F00, GL_RENDERER = 0x1F01, GL_VERSION = 0x1F02;
      const UNMASKED_VENDOR = 0x9245, UNMASKED_RENDERER = 0x9246;
      const fakeStrings = [
        ["Mozilla", "Firefox", "121.0"],
        ["Apple", "Safari", "17.0"],
        ["Google Inc.", "Chromium", "120.0.6099.109"]
      ][h32(0x04, 0) % 3];
      const hookGL = (Proto, tag) => {
        if (!Proto || !Proto.getParameter) return;
        const rawParam = Proto.getParameter;
        Proto.getParameter = function (p) {
          if (p === UNMASKED_VENDOR) { notify(tag + ".getParameter"); return fakeStrings[0]; }
          if (p === UNMASKED_RENDERER) { notify(tag + ".getParameter"); return fakeStrings[1]; }
          if (p === GL_VENDOR) { notify(tag + ".getParameter"); return fakeStrings[0]; }
          if (p === GL_RENDERER) { notify(tag + ".getParameter"); return fakeStrings[1]; }
          if (p === GL_VERSION) { notify(tag + ".getParameter"); return `WebGL ${fakeStrings[2]} noise`; }
          return rawParam.call(this, p);
        };
        const rawExts = Proto.getSupportedExtensions;
        if (rawExts) {
          Proto.getSupportedExtensions = function (...args) {
            const list = rawExts.apply(this, args) || [];
            notify(tag + ".getSupportedExtensions");
            // 确定性剔除约 1/8 的扩展名，破坏扩展名集合指纹
            return list.filter((_, i) => h32(0x05, i) % 8 !== 0);
          };
        }
        const rawRead = Proto.readPixels;
        if (rawRead) {
          // 就地在调用方传入的视图上扰动（天然尊重 byteOffset）：
          //   字节型（RGBA8，绝对主流）→ 每像素 RGB 通道 ±2 确定性抖动；
          //   非字节型（Uint16/Int32/Float32，如 5_6_5 或整型读回）→ 按元素 ±小步长；
          //   其余未知类型 → 跳过（不冒险写坏调用方缓冲）
          Proto.readPixels = function (x, y, w, h, fmt, type, pixels) {
            notify(tag + ".readPixels");
            const rv = rawRead.call(this, x, y, w, h, fmt, type, pixels);
            try {
              if (!pixels || !pixels.length) return rv;
              if (pixels instanceof Uint8Array || pixels instanceof Uint8ClampedArray) {
                for (let i = 0; i + 3 < pixels.length; i += 4) {
                  const [dx, dy, dz] = jitter3(h32(0x06, i), 2);
                  const r = pixels[i] + dx;
                  pixels[i] = r < 0 ? 0 : (r > 255 ? 255 : r);
                  const g = pixels[i + 1] + dy;
                  pixels[i + 1] = g < 0 ? 0 : (g > 255 ? 255 : g);
                  const b = pixels[i + 2] + dz;
                  pixels[i + 2] = b < 0 ? 0 : (b > 255 ? 255 : b);
                }
              } else if (pixels instanceof Float32Array) {
                for (let i = 0; i < pixels.length; i += 4) {
                  const [dx, dy, dz] = jitter3(h32(0x06, i), 2);
                  pixels[i] += dx * 1e-4;
                  pixels[i + 1] += dy * 1e-4;
                  pixels[i + 2] += dz * 1e-4;
                }
              } else if (pixels instanceof Uint16Array || pixels instanceof Int32Array ||
                         pixels instanceof Uint32Array) {
                for (let i = 0; i < pixels.length; i += 4) {
                  const [dx] = jitter3(h32(0x06, i), 2);
                  pixels[i] = (pixels[i] + dx) >>> 0;
                }
              }
            } catch (_) { /* 未知缓冲形态保持原样 */ }
            return rv;
          };
        }
      };
      hookGL(window.WebGLRenderingContext && window.WebGLRenderingContext.prototype, "webgl");
      hookGL(window.WebGL2RenderingContext && window.WebGL2RenderingContext.prototype, "webgl2");
    } catch (_) { /* WebGL 不可用环境跳过 */ }

    // ---- 4) AudioContext：频/时域采样微扰 --------------------------------
    // AnalyserNode 四个读取口 + AudioBuffer 读出端（OfflineAudioContext
    // 指纹的经典路径经 AudioBuffer.getChannelData/copyFromChannel 取数）。
    try {
      const saltAudio = 0x07;
      const hookAudio = (AC) => {
        if (!AC || !AC.prototype) return;
        const wrap = (name, isFloat) => {
          const raw = AC.prototype[name];
          if (!raw) return;
          AC.prototype[name] = function (arr) {
            notify(name);
            const rv = raw.call(this, arr);
            try {
              if (arr && arr.length) {
                const start = h32(saltAudio, arr.length);
                for (let i = 0; i < arr.length; i += 512) {   // 抽样扰动，性能封顶
                  if (isFloat) {
                    arr[i] = arr[i] + ((h32(saltAudio + 1, i) % 7 - 3) * 1e-7);
                  } else {
                    arr[i] = arr[i] + (h32(saltAudio + 2, i) % 3 - 1);
                  }
                }
              }
            } catch (_) { /* 冻结数组等异常场景保持原样 */ }
            return rv;
          };
        };
        wrap("getFloatFrequencyData", true);
        wrap("getByteFrequencyData", false);
        wrap("getFloatTimeDomainData", true);
        wrap("getByteTimeDomainData", false);
      };
      hookAudio(window.AnalyserNode);           // AnalyserNode 承载全部四个读取口

      // AudioBuffer：getChannelData 返回的是活缓冲（播放共用同一数组），
      // 不能每次调用都加噪（会累积漂移）。策略：每缓冲仅首读时一次性注入
      // 确定性微扰（WeakSet 去重）——指纹哈希自首次读取即被瓦解，且
      // 累积失真为零；copyFromChannel 只扰动调用方的目标副本，天然幂等。
      const AB = window.AudioBuffer;
      if (AB && AB.prototype) {
        const perturbed = new WeakSet();
        const rawGet = AB.prototype.getChannelData;
        if (rawGet) {
          AB.prototype.getChannelData = function (ch) {
            const arr = rawGet.call(this, ch);
            notify("getChannelData");
            try {
              if (arr && arr.length && !perturbed.has(arr)) {
                perturbed.add(arr);
                for (let i = 0; i < arr.length; i += 512) {
                  arr[i] = arr[i] + ((h32(saltAudio + 3, i) % 7 - 3) * 1e-7);
                }
              }
            } catch (_) { /* 冻结等异常保持原样 */ }
            return arr;
          };
        }
        const rawCopy = AB.prototype.copyFromChannel;
        if (rawCopy) {
          AB.prototype.copyFromChannel = function (dest, ch, start) {
            notify("copyFromChannel");
            const rv = rawCopy.call(this, dest, ch, start);
            try {
              if (dest && dest.length) {
                for (let i = 0; i < dest.length; i += 512) {
                  dest[i] = dest[i] + ((h32(saltAudio + 4, i) % 7 - 3) * 1e-7);
                }
              }
            } catch (_) { /* 保持原样 */ }
            return rv;
          };
        }
      }
    } catch (_) { /* AudioContext 缺失环境跳过 */ }

    try { delete window.__retraceInstallCanvasGuard; } catch (_) {}
    return true;
  };
})();
