"""Web 控制台（第二入口）：http.server + JSON API + 静态资源。

- GET  /                静态页
- GET  /api/ping        存活探测
- POST /api/<module>/<func>  调用模块函数（参数为 JSON body 字典）
- 模块开关关闭时，UI 不展示对应入口（见 index.html 的 /api/config/switches）。
"""
import json
import os
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core import config, db, logger

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# 允许通过 API 调用的白名单："模块.函数"。除 tracking.get_task 仅由 /api/v1 路由与
# 模块内部复用外，其余条目在 app.js 或 gui.py 至少有一处实际调用（契约由
# _verify_api_contract.py 逐调用点核对）。
ALLOWED = {
    # M1 pcap
    "pcap.list_interfaces", "pcap.start_capture", "pcap.stop_capture",
    "pcap.get_recent", "pcap.capture_status", "pcap.parse_offline",
    "pcap.stat_summary", "pcap.prune", "pcap.stop_all",
    # M2 regscan
    "regscan.search", "regscan.autostart_points",
    "regscan.add_watch", "regscan.remove_watch", "regscan.list_watches",
    "regscan.snapshot_watches", "regscan.diff_watches", "regscan.read_value",
    # M3 embedding
    "embedding.search", "embedding.remember", "embedding.embed",
    "embedding.provider", "embedding.stats", "embedding.save_index",
    # M6 decompile
    "decompile.analyze", "decompile.ai_audit",
    # M7 watcher（get_watcher 返回内部 Watcher 对象，无法经 JSON RPC 序列化，故不暴露）
    "watcher.add_target", "watcher.remove_target", "watcher.start", "watcher.stop",
    "watcher.timeline_entries", "watcher.snapshot_target", "watcher.status",
    # M4 browser
    "browser.status", "browser.list_tabs", "browser.send_command",
    "browser.dom_events", "browser.privacy_events",
    # M8 ai（chat_stream 是生成器，JSON RPC 无流式传输，经 HTTP 只会序列化出生成器
    # repr 的垃圾值，故不暴露；前端流式需求用 ai.chat 非流式实现）
    "ai.answer", "ai.configured", "ai.chat",
    "ai.analyze", "ai.summarize", "ai.extract_rules",
    # M9 hunt
    "hunt.create_agent", "hunt.list_agents", "hunt.start_hunt",
    "hunt.recent_hunts", "hunt.analyze_with_ai", "hunt.collect_evidence",
    "hunt.finish_observation", "hunt.get_hunt",
    # M5 evolve
    "evolve.mine_rules", "evolve.adjust_weights", "evolve.report",
    # M11 screener
    "screener.scan_suspicious_apps", "screener.scan_leftover",
    "screener.scan_fingerprints", "screener.check_file", "screener.track_app",
    "screener.mark_item", "screener.analyze_with_ai",
    "screener.scan_software_traces", "screener.cleanup_traces",
    "screener.preview_cleanup", "screener.restore_traces",
    "screener.scan_machine_fingerprints", "screener.scan_generic_fingerprints",
    "screener.scan_prefetch_traces", "screener.scan_usage_history",
    "screener.scan_wer_traces", "screener.analyze_fingerprint_format",
    "screener.generate_trusted_fingerprint", "screener.fingerprint_guidance",
    "screener.scan_ai_tool_traces", "screener.fingerprint_drift_report",
    "privacy_guard.build_sandbox_test_plan",
    # privacy_guard
    "privacy_guard.capabilities", "privacy_guard.protected_rules",
    "privacy_guard.task_report", "privacy_guard.sandbox_preview",
    "privacy_guard.mac_randomization_status", "privacy_guard.plan_system_action",
    "privacy_guard.registry_scopes", "privacy_guard.execute_system_action",
    "privacy_guard.approve_system_action", "privacy_guard.register_registry_scope",
    "privacy_guard.remove_registry_scope", "privacy_guard.set_canvas_guard",
    # 任务追踪 tracking（与 _v1 路由并存；前后端均可调用）
    "tracking.create_task", "tracking.list_tasks", "tracking.get_task",
    "tracking.start_task", "tracking.pause_task", "tracking.update_task",
    "tracking.delete_task", "tracking.task_events", "tracking.task_runs",
    "tracking.analyze_task", "tracking.daemon_status", "tracking.capabilities",
    "tracking.audit_entries", "tracking.audit_verify",
    # M10 agent（任务式 Agent；read/cmd 由独立 reviewer 判定——cmd 被 reviewer
    # allow 即执行、deny/不可用即拒绝（Web 无人工通道），high 工具无人工确认一律拒绝）
    "agent.run_task",
    # 配置 / 自启 / 数据库
    "config.switches", "config.set_switches", "config.save_ai", "config.get_ai",
    "autostart.is_enabled", "autostart.set_enabled",
    "db.observations", "db.knowledge",
    "db.delete_observation", "db.delete_knowledge", "db.set_knowledge_enabled",
}

MAX_BODY = 64 * 1024  # 请求体上限 64KB

# 追踪任务可编辑字段白名单（PUT /api/v1/tasks/{id} 与 POST .../update 共用）：
# 未知字段一律丢弃，避免 tracking.update_task(**body) 收到意外键名抛 TypeError。
TASK_UPDATE_FIELDS = frozenset({
    "name", "exe_path", "process_name", "pid", "watch_paths",
    "interval_sec", "ai_enabled",
})


def _to_bool(value):
    """严格布尔解析：拒绝字符串 "false"/"0" 被误当 True。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("1", "true", "on", "yes"):
            return True
        if s in ("0", "false", "off", "no"):
            return False
    raise ValueError("布尔值格式无效: %r" % value)


def _filter_task_update(body):
    """只透传可编辑字段，丢弃未知键，防止 update_task(**body) 因意外键抛 TypeError。"""
    if not isinstance(body, dict):
        raise ValueError("更新内容必须是 JSON 对象")
    return {k: v for k, v in body.items() if k in TASK_UPDATE_FIELDS}


def _call(module, func, kwargs):
    """执行白名单调用；autostart/config/db 为 UI 层直通。"""
    if module not in ("config", "db", "autostart") and not config.enabled(module):
        raise PermissionError("模块已关闭: %s" % module)
    if module == "autostart":
        from ui import autostart
        return {"enabled": autostart.is_enabled()} if func == "is_enabled" \
            else {"ok": autostart.set_enabled(_to_bool(kwargs.get("enabled")))}
    if module == "config":
        if func == "switches":
            return {"switches": config.get()["switches"]}
        if func == "set_switches":
            cfg = kwargs.get("switches", {})
            if not isinstance(cfg, dict):
                return {"error": "switches 必须是对象"}
            cfg = {k: _to_bool(v) for k, v in cfg.items()}
            config.set_switches(**cfg)
            db.audit("web.set_switches", "switches=%s" % json.dumps(cfg, ensure_ascii=False))
            return {"ok": True}
        if func == "save_ai":
            values = {k: kwargs[k] for k in
                      ("base_url", "api_key", "model", "timeout") if k in kwargs}
            config.update_section("ai", values)
            db.audit("web.save_ai", "base=%s model=%s" % (kwargs.get("base_url", ""), kwargs.get("model", "")))
            return {"ok": True}
        if func == "get_ai":
            sec = config.section("ai", {}) or {}
            return {"base_url": sec.get("base_url", ""), "api_key": sec.get("api_key", ""),
                    "model": sec.get("model", ""), "timeout": sec.get("timeout", 60)}
        return {"error": "unknown config func"}
    if module == "agent":
        # agent 是包目录，run_task 位于 modules.agent.agent；避免把整个 agent 机器
        # 挂到 modules/agent/__init__ 顶层（保持轻量、按需 import）。
        from modules.agent import agent as agent_mod
        fn = getattr(agent_mod, func)
        try:
            import inspect
            inspect.signature(fn).bind(**kwargs)
        except (TypeError, ValueError) as e:
            raise TypeError("调用参数不匹配 %s.%s: %s" % (module, func, e))
        return fn(**kwargs)
    if module == "db":
        def _id_field(name):
            raw = kwargs.get(name)
            try:
                val = int(raw or 0)
            except (TypeError, ValueError):
                raise ValueError("参数 %s 必须为正整数，收到: %r" % (name, raw))
            return val

        if func == "observations":
            try:
                limit = int(kwargs.get("limit", 200))
            except (TypeError, ValueError):
                raise ValueError("limit 必须为数字")
            return db.get_observations(status=kwargs.get("status"), limit=limit)
        if func == "knowledge":
            try:
                limit = int(kwargs.get("limit", 500))
            except (TypeError, ValueError):
                raise ValueError("limit 必须为数字")
            return db.list_knowledge(enabled_only=_to_bool(kwargs.get("enabled_only", False)),
                                     limit=limit)
        if func == "delete_observation":
            oid = _id_field("oid")
            if oid <= 0:
                return {"error": "无效的观察条目 id"}
            if not db.delete_observation(oid):
                return {"error": "观察条目不存在: %s" % oid}
            db.audit("web.db.delete_observation", "oid=%s" % oid)
            return {"ok": True}
        if func == "delete_knowledge":
            kid = _id_field("kid")
            if kid <= 0:
                return {"error": "无效的经验条目 id"}
            if not db.delete_knowledge(kid):
                return {"error": "经验条目不存在: %s" % kid}
            db.audit("web.db.delete_knowledge", "kid=%s" % kid)
            return {"ok": True}
        if func == "set_knowledge_enabled":
            kid = _id_field("kid")
            if kid <= 0:
                return {"error": "无效的经验条目 id"}
            if not db.set_knowledge_enabled(kid, _to_bool(kwargs.get("enabled"))):
                return {"error": "经验条目不存在: %s" % kid}
            db.audit("web.db.set_knowledge_enabled", "kid=%s enabled=%s" % (kid, kwargs.get("enabled")))
            return {"ok": True}
        return {"error": "unknown db func"}
    mod = __import__("modules.%s" % module, fromlist=["x"])
    fn = getattr(mod, func)
    # 调用前做签名绑定预检：参数名错位/缺必填参时返回清晰中文错误，
    # 而不是把 Python 原生 TypeError 透出（"有口没码"的兜底防线）。
    try:
        import inspect
        inspect.signature(fn).bind(**kwargs)
    except (TypeError, ValueError) as e:
        raise TypeError("调用参数不匹配 %s.%s: %s" % (module, func, e))
    return fn(**kwargs)


class _MethodNotAllowed(Exception):
    """v1 路由收到不支持的 HTTP 方法（映射为 405，区别于未知路由的 400）。"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ReTrace/2.0"

    def log_message(self, fmt, *args):
        pass  # 静默访问日志，避免刷屏

    # ---- helpers ----
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str))

    # ---- GET ----
    def do_GET(self):
        if not self._host_ok():
            self._json({"error": "拒绝访问（仅允许本地控制台）"}, 403)
            return
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/ping":
            self._json({"ok": True, "modules": _switches()})
            return
        if path.startswith("/api/v1/"):
            if not self._request_ok():
                self._json({"ok": False, "error": "拒绝访问（请求来源校验失败）"}, 403)
                return
            self._v1("GET", path, {})
            return
        if path == "/":
            path = "/index.html"
        if path.startswith("/api/"):
            self._json({"error": "GET 不支持 API 调用，请用 POST"}, 405)
            return
        fpath = os.path.abspath(os.path.normpath(os.path.join(STATIC_DIR, path.lstrip("/"))))
        try:
            inside = os.path.commonpath((os.path.abspath(STATIC_DIR), fpath)) == os.path.abspath(STATIC_DIR)
        except ValueError:
            inside = False
        if not inside or not os.path.isfile(fpath):
            self._send(404, "Not Found", "text/plain; charset=utf-8")
            return
        ctype = "text/html; charset=utf-8" if fpath.endswith(".html") else (
            "application/javascript; charset=utf-8" if fpath.endswith(".js") else
            "text/css; charset=utf-8" if fpath.endswith(".css") else
            "application/octet-stream")
        with open(fpath, "rb") as f:
            self._send(200, f.read(), ctype)

    def _host_ok(self):
        h = (self.headers.get("Host", "") or "").strip().lower()
        if h.startswith("["):  # IPv6 字面量如 [::1]:8080
            end = h.find("]")
            host = h[1:end] if end > 0 else h
        else:
            host = h.rsplit(":", 1)[0] if ":" in h else h
        return host in ("127.0.0.1", "localhost", "::1")

    def _request_ok(self):
        if not self._host_ok() or self.headers.get("X-ReTrace") != "1":
            return False
        origin = (self.headers.get("Origin") or "").strip().lower()
        if not origin:
            return True
        try:
            parsed = urllib.parse.urlparse(origin)
            return parsed.hostname in ("127.0.0.1", "localhost", "::1")
        except ValueError:
            return False

    def _read_body(self):
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/json" not in ctype:
            raise ValueError("Content-Type 必须为 application/json")
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length < 0 or length > MAX_BODY:
            raise OverflowError("请求体过大")
        self.connection.settimeout(10)
        raw = self.rfile.read(length) if length else b"{}"
        body = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(body, dict):
            raise ValueError("JSON 请求体必须为对象")
        return body

    def _v1(self, method, path, body):
        """Versioned task API used by both browser UI and external local clients."""
        from modules import tracking
        parts = [urllib.parse.unquote(p) for p in path.split("/") if p]
        request_id = uuid.uuid4().hex
        try:
            if not config.enabled("tracking"):
                raise PermissionError("任务追踪模块已关闭")
            if parts == ["api", "v1", "tasks"]:
                # 集合路由只允许 GET(列表)/POST(创建)；PUT/DELETE 必须落到具体 {id}，
                # 否则会误入 create_task 分支（如 DELETE /api/v1/tasks 竟试图建任务）。
                if method == "GET":
                    data = tracking.list_tasks()
                elif method == "POST":
                    data = tracking.create_task(**body)
                else:
                    raise _MethodNotAllowed("请求方法不允许: %s /api/v1/tasks" % method)
            elif parts == ["api", "v1", "daemon"]:
                if method != "GET":
                    raise _MethodNotAllowed("请求方法不允许: %s /api/v1/daemon" % method)
                data = tracking.daemon_status()
            elif parts == ["api", "v1", "capabilities"]:
                if method != "GET":
                    raise _MethodNotAllowed("请求方法不允许: %s /api/v1/capabilities" % method)
                data = tracking.capabilities()
            elif parts == ["api", "v1", "audit"]:
                if method != "GET":
                    raise _MethodNotAllowed("请求方法不允许: %s /api/v1/audit" % method)
                data = tracking.audit_entries(int(urllib.parse.parse_qs(
                    urllib.parse.urlparse(self.path).query).get("limit", [200])[0]))
            elif parts == ["api", "v1", "audit", "verify"]:
                if method != "POST":
                    raise _MethodNotAllowed("请求方法不允许: %s /api/v1/audit/verify" % method)
                data = tracking.audit_verify()
            elif len(parts) >= 4 and parts[:3] == ["api", "v1", "tasks"] and parts[3].isdigit():
                task_id = int(parts[3])
                if len(parts) == 4 and method == "GET":
                    data = tracking.get_task(task_id)
                elif len(parts) == 4 and method == "PUT":
                    data = tracking.update_task(task_id, **_filter_task_update(body))
                elif len(parts) == 4 and method == "DELETE":
                    data = tracking.delete_task(task_id)
                elif len(parts) == 5 and parts[4] == "events" and method == "GET":
                    query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                    data = tracking.task_events(task_id, int(query.get("limit", [300])[0]))
                elif len(parts) == 5 and parts[4] == "runs" and method == "GET":
                    data = tracking.task_runs(task_id)
                elif len(parts) == 5 and parts[4] == "start" and method == "POST":
                    data = tracking.start_task(task_id)
                elif len(parts) == 5 and parts[4] == "pause" and method == "POST":
                    data = tracking.pause_task(task_id)
                elif len(parts) == 5 and parts[4] == "update" and method == "POST":
                    data = tracking.update_task(task_id, **_filter_task_update(body))
                elif len(parts) == 5 and parts[4] == "delete" and method == "POST":
                    data = tracking.delete_task(task_id)
                elif len(parts) == 5 and parts[4] == "analyze" and method == "POST":
                    data = tracking.analyze_task(task_id)
                else:
                    known_subs = {"events", "runs", "start", "pause", "update",
                                  "delete", "analyze"}
                    if len(parts) == 5 and parts[4] in known_subs:
                        raise _MethodNotAllowed(
                            "请求方法不允许: %s /api/v1/tasks/%s/%s"
                            % (method, task_id, parts[4]))
                    if len(parts) == 4:
                        raise _MethodNotAllowed(
                            "请求方法不允许: %s /api/v1/tasks/%s" % (method, task_id))
                    raise KeyError("未知 API 路由")
            else:
                raise KeyError("未知 API 路由")
            self._json({"ok": True, "data": data, "request_id": request_id})
        except PermissionError as exc:
            self._json({"ok": False, "error": str(exc), "request_id": request_id}, 403)
        except _MethodNotAllowed as exc:
            self._json({"ok": False, "error": str(exc), "request_id": request_id}, 405)
        except (KeyError, ValueError, TypeError) as exc:
            self._json({"ok": False, "error": str(exc), "request_id": request_id}, 400)
        except Exception as exc:
            logger.record_err("web.api.v1", exc)
            self._json({"ok": False, "error": str(exc), "request_id": request_id}, 500)

    # ---- PUT / DELETE（Design §12：/api/v1/tasks/{id} 的更新与删除） ----
    def _v1_body_or_json(self, error_template):
        try:
            return self._read_body()
        except OverflowError as exc:
            self._json({"ok": False, "error": str(exc)}, 413)
            return None
        except Exception as exc:
            self._json({"ok": False, "error": error_template % exc}, 400)
            return None

    def do_PUT(self):
        if not self._request_ok():
            self._json({"error": "拒绝访问（仅允许本地控制台）"}, 403)
            return
        path = urllib.parse.urlparse(self.path).path
        if not path.startswith("/api/v1/"):
            self._json({"error": "PUT 仅支持 /api/v1/ 任务路由"}, 405)
            return
        body = self._v1_body_or_json("body 解析失败: %s")
        if body is None:
            return
        self._v1("PUT", path, body)

    def do_DELETE(self):
        if not self._request_ok():
            self._json({"error": "拒绝访问（仅允许本地控制台）"}, 403)
            return
        path = urllib.parse.urlparse(self.path).path
        if not path.startswith("/api/v1/"):
            self._json({"error": "DELETE 仅支持 /api/v1/ 任务路由"}, 405)
            return
        self._v1("DELETE", path, {})

    # ---- POST ----
    def do_POST(self):
        # CSRF/跨站防护：仅允许本地控制台访问。
        # 自定义头 X-ReTrace 阻断跨源 fetch（预检不被响应）；Host 白名单阻断 DNS rebinding。
        if not self._request_ok():
            self._json({"error": "拒绝访问（仅允许本地控制台）"}, 403)
            return
        path = urllib.parse.urlparse(self.path).path  # /api/<module>/<func>
        if path.startswith("/api/v1/"):
            try:
                body = self._read_body()
            except OverflowError as exc:
                self._json({"ok": False, "error": str(exc)}, 413)
                return
            except Exception as exc:
                self._json({"ok": False, "error": str(exc)}, 400)
                return
            self._v1("POST", path, body)
            return
        parts = [p for p in path.split("/") if p]
        if len(parts) != 3 or parts[0] != "api":
            self._json({"error": "path must be /api/<module>/<func>"}, 400)
            return
        module, func = parts[1], parts[2]
        if "%s.%s" % (module, func) not in ALLOWED:
            self._json({"error": "调用不在白名单: %s.%s" % (module, func)}, 403)
            return
        try:
            kwargs = self._read_body()
        except OverflowError as e:
            self._json({"error": str(e)}, 413)
            return
        except Exception as e:
            self._json({"error": "body 解析失败: %s" % e}, 400)
            return
        if module not in ("config", "db", "autostart") and not config.enabled(module):
            self._json({"error": "模块已关闭: %s" % module}, 403)
            return
        try:
            result = _call(module, func, kwargs)
            self._json({"ok": True, "data": result})
        except (TypeError, ValueError, KeyError) as e:
            # 参数绑定失败/业务校验失败：镜像 v1 的 400 语义，
            # 外部本地客户端按状态码判定才不会把失败当成功
            logger.record_err("web.api.%s.%s" % (module, func), e)
            self._json({"ok": False, "error": str(e)}, 400)
        except PermissionError as e:
            self._json({"ok": False, "error": str(e)}, 403)
        except Exception as e:
            logger.record_err("web.api.%s.%s" % (module, func), e)
            self._json({"ok": False, "error": str(e)}, 500)


def _switches():
    return {k: bool(v) for k, v in config.get()["switches"].items()}


def start_web(port=8080):
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", int(port)), Handler)
    except OSError as e:
        logger.record_err("web.start", e)
        logger.error("Web 控制台启动失败（端口 %s 被占用？）: %s" % (port, e))
        return
    logger.info("Web 控制台: http://127.0.0.1:%d/" % port)
    srv.serve_forever()
