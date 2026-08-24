"""M4 browser — 浏览器插件完整控制中枢。

自实现最小 WebSocket (RFC6455) 服务端，仅监听 127.0.0.1。
扩展 (extension/ 目录, Manifest V3) 连接后：
  - 上报标签页列表 / 当前页信息 / DOM 变化事件 / 隐私事件
  - 接收中枢命令：list_tabs / snapshot / activate {tabId} / observe_dom {enabled} /
    canvas_guard {site, enabled, reason} / ping

默认端口：config.json browser.ws_port (默认 8765)，token 认证（首次启动自动生成并写回 config）。

命令（中枢 -> 扩展）：
  list_tabs / snapshot / activate {tabId}
  observe_dom {enabled} / ping / canvas_guard {site, enabled, reason}

事件（扩展 -> 中枢消息实际结构）：
  hello {client}
  tabs {tabs: [{id,title,url}]}
  tab_info {tab: {id,title,url,snapshot?}}
  dom_event {event: {tabId,type,detail,href}}
  privacy_event {event: {type: canvas_read|canvas_guard_setting, ...}}
对外发布：
  browser.connected {client}
  browser.tab_info   {tab, id, title, url, snapshot...}
  browser.dom_event  {tabId, type, detail, href, ts}
  browser.privacy_event {tabId, type, api/origin/..., ts}
"""
import base64
import hashlib
import json
import secrets
import socket
import struct
import threading
import time

from core import config, db, events, logger

MAX_MSG = 1024 * 1024
_STATE_LOCK = threading.Lock()
_clients = []
_recent_dom = []
_recent_privacy = []
_privacy_rate = {}
_recent_tabs = []
_connected = 0
_server_thread = None
_sock = None
_sock_ready = threading.Event()
_token = ""


def _gen_token():
    sec = config.section("browser")
    t = (sec.get("token") or "").strip()
    if not t:
        t = secrets.token_hex(16)
        # 写回 config.json，保证跨重启扩展仍能连接（统一入口，锁内合并）
        config.update_section("browser", {"token": t})
        try:
            db.audit("browser.token_rotate", "generated")
        except Exception:
            pass
    return t


def ws_accept_key(key):
    return base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()


def _recv_exact(conn, n):
    """循环读取直到凑满 n 字节或对端断开（返回 None）。"""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _recv_frame(conn, bufsize=65536):
    header = _recv_exact(conn, 2)
    if header is None:
        return None
    fin = header[0] & 0x80
    opcode = header[0] & 0x0F
    masked = header[1] & 0x80
    length = header[1] & 0x7F
    if length == 126:
        raw = _recv_exact(conn, 2)
        if raw is None:
            return None
        length = struct.unpack(">H", raw)[0]
    elif length == 127:
        raw = _recv_exact(conn, 8)
        if raw is None:
            return None
        length = struct.unpack(">Q", raw)[0]
    if length > MAX_MSG:
        return ("error", "消息过大", 0)
    if masked:
        mask = _recv_exact(conn, 4)
        if mask is None:
            return None
    else:
        mask = None
    payload = b""
    while len(payload) < length:
        chunk = conn.recv(min(65536, length - len(payload)))
        if not chunk:
            return None
        payload += chunk
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return (opcode, payload, fin)


def _send_frame(conn, payload, opcode=0x1):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    header = bytearray([0x80 | opcode])
    ln = len(payload)
    if ln < 126:
        header.append(ln)
    elif ln < 65536:
        header.append(126)
        header += struct.pack(">H", ln)
    else:
        header.append(127)
        header += struct.pack(">Q", ln)
    try:
        conn.sendall(bytes(header) + payload)
        return True
    except OSError:
        return False


def _read_http_headers(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None, None
        buf += chunk
        if len(buf) > 65536:
            return None, None
    text = buf.decode("latin-1", errors="replace")
    headers = {}
    request_line = ""
    lines = text.split("\r\n")
    if lines:
        request_line = lines[0]
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers, request_line


def _extract_token(request_line):
    try:
        path = request_line.split(" ", 2)[1]
        query = path.split("?", 1)[1]
        for part in query.split("&"):
            if part.startswith("token="):
                return part[6:]
    except (IndexError, ValueError):
        pass
    return ""


def _handle_client(conn, addr):
    global _connected
    try:
        conn.settimeout(10)
        headers, request_line = _read_http_headers(conn)
        if not headers or headers.get("upgrade", "").lower() != "websocket":
            conn.close()
            return
        key = headers.get("sec-websocket-key", "")
        if not key:
            conn.close()
            return
        if _token and _extract_token(request_line) != _token:
            try:
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            except OSError:
                pass
            conn.close()
            return
        resp = ("HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: %s\r\n\r\n" % ws_accept_key(key))
        conn.sendall(resp.encode())
        # 空闲读超时须明显大于扩展心跳周期（30s），否则两个独立计时器在阈值处
        # 竞态：recv 先超时 → 中枢静默断链 → 扩展 5s 后重连，连接周期性抖动。
        conn.settimeout(75)
        with _STATE_LOCK:
            _clients.append(conn)
            _connected += 1
        events.bus.publish("browser.connected", {"client": addr})
        while True:
            msg = _recv_frame(conn)
            if msg is None:
                break
            opcode, payload, fin = msg
            if opcode == "error":
                break
            if opcode == 0x8:
                break
            if opcode == 0x9:
                _send_frame(conn, payload, 0xA)
                continue
            if opcode != 0x1:
                continue
            try:
                data = json.loads(payload.decode("utf-8", errors="replace"))
            except ValueError:
                data = {"type": "text", "data": payload.decode("utf-8",
                                                               errors="replace")[:500]}
            _dispatch(conn, data)
    except socket.timeout:
        # 空闲超时（75s 无心跳）属正常回收路径：关闭连接，扩展会自动重连
        pass
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
        with _STATE_LOCK:
            if conn in _clients:
                _clients.remove(conn)
                _connected = max(0, _connected - 1)


def _to_int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _dispatch(conn, data):
    if not isinstance(data, dict):
        return
    mtype = data.get("type", "")
    if mtype == "hello":
        _send_frame(conn, json.dumps({"type": "hello_ack",
                                      "server": "retrace"}))
    elif mtype == "tabs":
        tabs = data.get("tabs")
        if not isinstance(tabs, list):
            return
        with _STATE_LOCK:
            _recent_tabs[:] = [t for t in tabs[:100] if isinstance(t, dict)]
    elif mtype == "tab_info":
        tab = data.get("tab")
        if not isinstance(tab, dict) or not tab:
            return
        with _STATE_LOCK:
            _recent_tabs[:] = [tab] + \
                [t for t in _recent_tabs if t.get("id") != tab.get("id")][:99]
        events.bus.publish("browser.tab_info", tab)
    elif mtype == "dom_event":
        ev = data.get("event")
        if not isinstance(ev, dict):
            return
        ev["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
        with _STATE_LOCK:
            _recent_dom.append(ev)
            if len(_recent_dom) > 1000:
                del _recent_dom[:len(_recent_dom) - 1000]
        events.bus.publish("browser.dom_event", ev)
    elif mtype == "privacy_event":
        raw = data.get("event")
        if not isinstance(raw, dict):
            return
        kind = raw.get("type")
        if kind == "canvas_read":
            api = raw.get("api") if raw.get("api") in ("getImageData", "toDataURL", "toBlob") else "unknown"
            ev = {"type": "canvas_read", "api": api,
                  "origin": str(raw.get("origin", ""))[:500],
                  "topSite": str(raw.get("topSite", ""))[:500],
                  "mode": "top-site-stable-deterministic-noise",
                  "confidence": "correlated_untrusted",
                  "tabId": _to_int(raw.get("tabId"), 0),
                  "frameId": _to_int(raw.get("frameId"), 0)}
            rate_key = (ev["tabId"], ev["frameId"], api)
            now = time.monotonic()
            with _STATE_LOCK:
                if now - _privacy_rate.get(rate_key, 0) < 1:
                    return
                _privacy_rate[rate_key] = now
                if len(_privacy_rate) > 5000:
                    oldest = min(_privacy_rate, key=_privacy_rate.get)
                    _privacy_rate.pop(oldest, None)
        elif kind == "canvas_guard_setting":
            ev = {"type": kind, "topSite": str(raw.get("topSite", ""))[:500],
                  "enabled": bool(raw.get("enabled")),
                  "reason": str(raw.get("reason", ""))[:1000],
                  "confidence": "exact_extension_setting"}
            # 扩展 popup 路径同样进入审计链（与 Web/GUI 的 set_canvas_guard 并列）
            try:
                db.audit("browser.canvas_guard", "site=%s enabled=%s reason=%s" % (
                    ev["topSite"], ev["enabled"], ev["reason"][:120]))
            except Exception:
                pass
        else:
            return
        ev["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
        with _STATE_LOCK:
            _recent_privacy.append(ev)
            if len(_recent_privacy) > 1000:
                del _recent_privacy[:len(_recent_privacy) - 1000]
        events.bus.publish("browser.privacy_event", ev)


def _broadcast(payload):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    with _STATE_LOCK:
        clients = list(_clients)
    delivered = 0
    for conn in clients:
        try:
            if _send_frame(conn, payload):
                delivered += 1
        except Exception:
            pass
    return delivered


_server_bind_ok = threading.Event()  # bind 结果回传：set=成功；失败由 start() 感知
_server_bind_error = ""


def _server_loop(port):
    global _sock, _server_bind_error
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Windows 下 SO_REUSEADDR 允许双绑同端口（冲突检测失效），
    # 单实例工具改用排他绑定：端口被占时 bind 明确失败并上报
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    except OSError:
        pass
    try:
        s.bind(("127.0.0.1", port))
        s.listen(8)
    except OSError as e:
        logger.record_err("browser.socket", e)
        _server_bind_error = "端口 %d 绑定失败: %s" % (port, e)
        _sock_ready.set()  # 通知 stop()/start() 无需空等
        return
    _sock = s
    _server_bind_error = ""
    _server_bind_ok.set()
    _sock_ready.set()
    while True:
        try:
            conn, addr = s.accept()
        except OSError:
            break
        t = threading.Thread(target=_handle_client, args=(conn, addr),
                             daemon=True, name="ws-%s" % addr[1])
        t.start()


def start(port=None):
    global _server_thread, _token
    if _server_thread is not None and _server_thread.is_alive():
        return True
    if not port:
        try:
            port = int(config.section("browser").get("ws_port", 8765))
        except (TypeError, ValueError):
            port = 8765
    _token = _gen_token()
    _sock_ready.clear()
    _server_bind_ok.clear()
    _server_thread = threading.Thread(target=_server_loop, args=(port,),
                                      daemon=True, name="browser-ws")
    _server_thread.start()
    _sock_ready.wait(3)  # 等 bind 结果（成功/失败都会置位）
    if not _server_bind_ok.is_set():
        logger.error("browser 中枢启动失败：%s" % (_server_bind_error or "未知原因"))
        return False
    return True


def stop():
    global _sock, _server_thread
    _sock_ready.wait(2)  # 等监听 socket 就绪，避免 bind 竞态导致无法关闭
    with _STATE_LOCK:
        clients = list(_clients)
    for conn in clients:
        try:
            _send_frame(conn, json.dumps({"type": "bye"}))
            conn.close()
        except OSError:
            pass
    if _sock is not None:
        try:
            _sock.close()  # 使 accept 立即返回，服务线程可退出
        except OSError:
            pass
    _sock = None
    _server_bind_ok.clear()
    _sock_ready.clear()
    t = _server_thread
    _server_thread = None
    if t is not None and t.is_alive() and t is not threading.current_thread():
        t.join(timeout=2)  # 等待服务线程收尾，避免退出竞态


def send_command(cmd, **kwargs):
    if cmd not in {"list_tabs", "snapshot", "activate", "observe_dom", "ping", "canvas_guard"}:
        raise PermissionError("浏览器命令不在强类型白名单: %s" % cmd)
    try:
        db.audit("browser.command", "cmd=%s" % str(cmd)[:200])
    except Exception:
        pass
    payload = json.dumps({"type": "command", "cmd": cmd, **kwargs})
    return _broadcast(payload)


def list_tabs():
    with _STATE_LOCK:
        return list(_recent_tabs)


def dom_events(limit=100):
    with _STATE_LOCK:
        return list(_recent_dom[-limit:])


def privacy_events(limit=100):
    with _STATE_LOCK:
        return list(_recent_privacy[-limit:])


def status():
    try:
        port = int(config.section("browser").get("ws_port", 8765))
    except (TypeError, ValueError):
        port = 8765
    with _STATE_LOCK:
        return {"port": port, "clients": len(_clients),
                "connected": len(_clients) > 0,
                "tabs": len(_recent_tabs),
                "dom_events": len(_recent_dom),
                "privacy_events": len(_recent_privacy),
                "token_set": bool(_token),
                "bind_ok": _server_bind_ok.is_set(),
                "bind_error": _server_bind_error}


def register(bus, cfg):
    try:
        port = int(cfg.get("browser", {}).get("ws_port", 8765)) \
            if isinstance(cfg.get("browser"), dict) else 8765
    except (TypeError, ValueError):
        port = 8765
    if not start(port):
        logger.error("browser 中枢未能启动（端口 %d），扩展将无法连接" % port)
    bus.subscribe("browser.observe", lambda d: send_command("observe_dom",
                                                            enabled=bool(d.get("enabled")))
                  if d else None)


def shutdown():
    stop()
