"""M1 pcap — 基于 Wireshark/tshark 的抓包与解析。

能力：
  find_tshark()            定位 tshark（PATH → 常见安装路径）
  list_interfaces()        枚举本机接口
  start_capture()/stop_*   实时抓包（后台线程 + 事件发布）
  parse_offline()          离线解析 pcap/pcapng（流式）
  stat_summary()           流量统计
  get_recent()             最近抓包缓存（供 UI 轮询）

事件：
  packet.captured  {interface, packet:{num,time,proto,src,dst,sport,dport,usport,udport,len,http_host,http_uri,dns_qry}}
"""
import os
import re
import shutil
import subprocess
import threading
import time

from core import db, events, logger

TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    r"D:\Program Files\Wireshark\tshark.exe",
    r"D:\Program Files (x86)\Wireshark\tshark.exe",
]

FIELDS = [
    ("num", "frame.number"),
    ("time", "frame.time"),
    ("proto", "_ws.col.Protocol"),
    ("src", "ip.src"),
    ("dst", "ip.dst"),
    ("sport", "tcp.srcport"),
    ("dport", "tcp.dstport"),
    ("usport", "udp.srcport"),
    ("udport", "udp.dstport"),
    ("len", "frame.len"),
    ("http_host", "http.host"),
    ("http_uri", "http.request.uri"),
    ("dns_qry", "dns.qry.name"),
]
FIELD_ARGS = []
for _, arg in FIELDS:
    FIELD_ARGS += ["-e", arg]
FIELD_NAMES = [name for name, _ in FIELDS]

SUB_FLAGS = 0
if hasattr(subprocess, "CREATE_NO_WINDOW"):
    SUB_FLAGS = subprocess.CREATE_NO_WINDOW

_tshark_path = [None]
_tshark_checked = [0.0]
_tshark_ttl = 120.0

HEADER_LINE = re.compile(r"^frame\.number\tframe\.time\t", re.M)
STDERR_NOISE = ("Capturing on", "packets captured", "Capture started",
                "Cache file(s) (", "File: ")

_EVENT_RATE = 60.0


def find_tshark():
    now = time.time()
    if _tshark_path[0] is not None and now - _tshark_checked[0] < _tshark_ttl:
        return _tshark_path[0]
    found = shutil.which("tshark") or ""
    if not found or not os.path.exists(found):
        for p in TSHARK_CANDIDATES:
            if os.path.exists(p):
                found = p
                break
        else:
            found = ""
    _tshark_path[0] = found or None
    _tshark_checked[0] = now
    return _tshark_path[0]


def _base_args():
    tshark = find_tshark()
    if not tshark:
        raise RuntimeError("未找到 tshark，请安装 Wireshark")
    return [tshark, "-T", "fields", "-E", "header=y", "-E", "separator=\t",
            "-E", "occurrence=f", "-q"] + FIELD_ARGS


def _parse_line(line, header):
    if len(line) > 65536:
        return None
    parts = line.rstrip("\r\n").split("\t")
    if len(parts) != len(header):
        return None
    pkt = {}
    for i, name in enumerate(header):
        pkt[name] = parts[i]
    return pkt


def _to_int(val):
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


def _packet_view(pkt):
    sport = pkt.get("sport") or pkt.get("usport") or ""
    dport = pkt.get("dport") or pkt.get("udport") or ""
    return {
        "num": _to_int(pkt.get("num")),
        "time": pkt.get("time", ""),
        "proto": pkt.get("proto", ""),
        "src": pkt.get("src", ""),
        "dst": pkt.get("dst", ""),
        "sport": _to_int(sport),
        "dport": _to_int(dport),
        "len": _to_int(pkt.get("len")),
        "http_host": pkt.get("http_host", ""),
        "http_uri": pkt.get("http_uri", ""),
        "dns_qry": pkt.get("dns_qry", ""),
    }


def list_interfaces():
    tshark = find_tshark()
    if not tshark:
        return []
    try:
        out = subprocess.run([tshark, "-D"], capture_output=True, text=True,
                             encoding="utf-8", errors="replace",
                             creationflags=SUB_FLAGS, timeout=15).stdout
    except (subprocess.SubprocessError, OSError) as e:
        logger.record_err("pcap.interfaces", e)
        return []
    ifaces = []
    seen = set()
    for line in out.splitlines():
        parts = line.split(" ", 2)
        if len(parts) < 2:
            continue
        idx_r = parts[0].rstrip(".")
        try:
            idx = int(idx_r)
        except ValueError:
            continue
        name = parts[1].strip()
        disp = parts[2].strip() if len(parts) > 2 else name
        disp = disp.strip("()")
        if name in seen:
            disp = "%s[%d]" % (disp, idx)
        seen.add(name)
        ifaces.append({"idx": idx, "name": name, "desc": disp})
    return ifaces


class Capture:
    def __init__(self, name, interface, bpf="", max_cache=500):
        self.name = name
        self.interface = interface
        self.bpf = bpf
        self.max_cache = max(1, int(max_cache) if max_cache else 500)
        self.proc = None
        self.thread = None
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()
        self.recent = []
        self.count = 0
        self.error = None
        self.state = "idle"
        self._last_emit = [0.0]

    def start(self):
        with self.lock:
            if self.interface is None or str(self.interface) in ("", "None"):
                self.state = "error"
                self.error = "未指定抓包接口"
                return False
            if self.state in ("running", "starting"):
                return False
            if self.thread is not None and self.thread.is_alive():
                return False
            self.state = "starting"
            self.stop_flag.clear()
            self.error = None
            self.count = 0  # 重启时清空计数与缓存，避免统计误导
            self.recent = []
            self.thread = threading.Thread(target=self._run,
                                           name="cap-%s" % self.name, daemon=True)
            self.thread.start()
            return True

    def _run(self):
        tshark = find_tshark()
        if not tshark:
            self._set_error("未找到 tshark")
            self._set_state("error")
            return
        cmd = _base_args()
        idx = self.interface
        if isinstance(idx, int):
            idx = str(idx)
        cmd += ["-i", str(idx)]
        if self.bpf:
            cmd += ["-f", self.bpf]
        cmd += ["-l"]
        proc = None
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace",
                creationflags=SUB_FLAGS)
        except OSError as e:
            self._set_error("启动失败: %s" % e)
            logger.record_err("pcap.start", e)
            return
        finally:
            if proc is None:
                with self.lock:
                    self.state = "error"
                return
        with self.lock:
            self.proc = proc
        self._set_state("running")
        stderr_thread = threading.Thread(target=self._drain_stderr,
                                         args=(proc,), daemon=True)
        stderr_thread.start()
        self._emit_state("running")
        normal_stop = False
        try:
            for line in proc.stdout:
                if self.stop_flag.is_set():
                    normal_stop = True
                    break
                pkt = _parse_line(line, FIELD_NAMES)
                if pkt is None or pkt.get("num") == "frame.number":
                    continue
                view = _packet_view(pkt)
                with self.lock:
                    self.recent.append(view)
                    if len(self.recent) > self.max_cache:
                        del self.recent[:len(self.recent) - self.max_cache]
                    self.count += 1
                now = time.time()
                if now - self._last_emit[0] >= 1.0 / _EVENT_RATE:
                    self._last_emit[0] = now
                    events.bus.publish("packet.captured",
                                       {"interface": self.name, "packet": view})
        except (ValueError, OSError) as e:
            if self.stop_flag.is_set():
                normal_stop = True
            else:
                self._set_error("读取错误: %s" % e)
                logger.record_err("pcap.read.%s" % self.name, e)
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                try:
                    proc.kill()
                except OSError:
                    pass
            with self.lock:
                if self.proc is proc:
                    self.proc = None
            if normal_stop:
                self._set_error(None)
            self._set_state("stopped")
            self._emit_state("stopped")

    def _drain_stderr(self, proc):
        try:
            for err_line in proc.stderr:
                line = err_line.strip()
                if not line or line.startswith(STDERR_NOISE):
                    continue
                self._set_error(line[:300])
        except (ValueError, OSError):
            pass

    def _set_error(self, msg):
        with self.lock:
            self.error = msg

    def _set_state(self, state):
        with self.lock:
            self.state = state

    def _emit_state(self, state):
        events.bus.publish("pcap.state", {"name": self.name, "state": state})

    def stop(self):
        self.stop_flag.set()
        with self.lock:
            proc = self.proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
        thread = self.thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=6)

    def snapshot(self):
        with self.lock:
            return {
                "name": self.name,
                "interface": self.interface,
                "bpf": self.bpf,
                "state": self.state,
                "count": self.count,
                "last_error": self.error,
                "recent": list(self.recent[-50:]),
            }


_captures = {}
_captures_lock = threading.Lock()


def start_capture(name="main", interface=None, bpf=None):
    with _captures_lock:
        cap = _captures.get(name)
        if cap is None:
            cap = Capture(name, interface, bpf or "")
            _captures[name] = cap
    with cap.lock:
        if cap.interface is None:
            cap.interface = interface
        if bpf is not None:
            cap.bpf = bpf
    ok = cap.start()
    try:
        db.audit("pcap.start", "name=%s ok=%s" % (name, ok))
    except Exception:
        pass
    return ok, cap.snapshot()


def stop_capture(name="main"):
    with _captures_lock:
        cap = _captures.get(name)
    if cap:
        cap.stop()
        try:
            db.audit("pcap.stop", "name=%s" % name)
        except Exception:
            pass
        return cap.snapshot()
    # 无该抓包实例时返回幂等状态快照（而非 None），避免前端 bizFail(null) 误报"停止失败"
    return {"name": name, "state": "idle", "count": 0}


def capture_status(name="main"):
    with _captures_lock:
        cap = _captures.get(name)
    return cap.snapshot() if cap else {"name": name, "state": "idle", "count": 0}


def stop_all():
    with _captures_lock:
        caps = list(_captures.values())
    threads = []
    stopped = 0
    for cap in caps:
        cap.stop_flag.set()
        with cap.lock:
            proc = cap.proc
            thread = cap.thread
            was_running = cap.state in ("running", "starting")
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
        if thread is not None and thread.is_alive():
            threads.append(thread)
        if was_running:
            stopped += 1
    for t in threads:
        t.join(timeout=8)
    return stopped


def prune(name=None):
    with _captures_lock:
        keys = list(_captures.keys()) if name is None else [name]
        removed = 0
        for k in keys:
            cap = _captures.get(k)
            if cap and cap.state in ("idle", "stopped", "error"):
                del _captures[k]
                removed += 1
        return removed


def get_recent(name="main", limit=200):
    with _captures_lock:
        cap = _captures.get(name)
    if not cap:
        return []
    limit = max(0, min(int(limit), 5000))
    with cap.lock:
        return list(cap.recent[-limit:])


def parse_offline(path, limit=5000, timeout=120):
    tshark = find_tshark()
    if not tshark:
        raise RuntimeError("未找到 tshark")
    if not os.path.exists(path):
        raise RuntimeError("文件不存在: %s" % path)
    limit = max(1, int(limit))
    timeout = 120 if timeout is None else max(1, int(timeout))
    cmd = _base_args() + ["-r", path]
    packets = []
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
            creationflags=SUB_FLAGS)
    except OSError as e:
        logger.record_err("pcap.offline", e)
        raise RuntimeError("离线解析失败: %s" % e)
    err_lines = []

    def _drain_stderr():
        try:
            for err_line in proc.stderr:
                err_lines.append(err_line)
                if len(err_lines) > 50:
                    del err_lines[0]
        except (ValueError, OSError):
            pass

    threading.Thread(target=_drain_stderr, daemon=True).start()
    deadline = time.time() + timeout
    try:
        for line in proc.stdout:
            if time.time() > deadline:
                proc.terminate()
                break
            pkt = _parse_line(line, FIELD_NAMES)
            if pkt is None or pkt.get("num") == "frame.number":
                continue
            packets.append(_packet_view(pkt))
            if len(packets) >= limit:
                proc.terminate()
                break
    except (ValueError, OSError) as e:
        logger.record_err("pcap.offline", e)
    finally:
        try:
            proc.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            try:
                proc.kill()
            except OSError:
                pass
    err = "".join(err_lines).strip()[:400]
    if proc.returncode not in (0, None) and not packets:
        raise RuntimeError("tshark 错误: %s" % (err or "未知")[:300])
    return packets


def stat_summary(packets):
    total = len(packets)
    by_proto = {}
    pairs = {}
    for p in packets:
        proto = p.get("proto") or "?"
        by_proto[proto] = by_proto.get(proto, 0) + 1
        src, dst = p.get("src"), p.get("dst")
        if not src and not dst:
            continue
        key = "%s:%s -> %s:%s" % (src, p.get("sport"), dst, p.get("dport"))
        pairs[key] = pairs.get(key, 0) + 1
    top_proto = sorted(by_proto.items(), key=lambda x: -x[1])[:10]
    top_pairs = sorted(pairs.items(), key=lambda x: -x[1])[:10]
    return {"total": total, "by_proto": dict(top_proto),
            "top_pairs": [{"conn": k, "count": v} for k, v in top_pairs]}


def register(bus, cfg):
    sec = cfg.get("pcap")
    if not isinstance(sec, dict):
        sec = {}
    _tshark_path[0] = sec.get("tshark_path") or None
    _tshark_checked[0] = 0.0
    if not find_tshark():
        logger.warn("pcap 模块：未找到 tshark，仅保留离线解析能力（需安装 Wireshark）")


def shutdown():
    stop_all()