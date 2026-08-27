"""M7 watcher — 选定 APP 集中观察（行为时间线）。

能力：
  add_target(name, pid/exe)   注册观察目标
  remove_target/start/stop    生命周期
  timeline_entries()          时间线查询（UI 轮询）
  snapshot_target(name)       目标当前状态快照

采集维度（轮询循环，interval 可配置）：
  进程树 / TCP-UDP 连接 / DNS 解析出现项 / 注册表 watch diff / 目标目录文件变化

事件：
  watcher.event  {ts, target, type, detail}
"""
import csv
import io
import os
import subprocess
import threading
import time

from core import config, db, events, logger
from modules import regscan
from modules.tracking import _process_image_path

SUB_FLAGS = 0
if hasattr(subprocess, "CREATE_NO_WINDOW"):
    SUB_FLAGS = subprocess.CREATE_NO_WINDOW


class Watcher:
    def __init__(self, cfg):
        sec = cfg.get("watcher") if isinstance(cfg, dict) else None
        if not isinstance(sec, dict):
            sec = {}
        try:
            self.interval = max(0.5, float(sec.get("interval", 2.0)))
        except (TypeError, ValueError):
            self.interval = 2.0
        try:
            self.max_events = max(50, int(sec.get("max_events", 500)))
        except (TypeError, ValueError):
            self.max_events = 500
        _wd = sec.get("watch_dirs")
        self.watch_dirs = list(_wd) if isinstance(_wd, (list, tuple)) else []
        self.targets = {}
        self.timeline = []
        self.lock = threading.Lock()
        self.stop_flag = threading.Event()
        self.thread = None
        self.state = "idle"
        self._reg_base = {}
        self._exit_notified = set()  # 已发过"退出"事件的目标名（防每周期刷屏）

    def add_target(self, name, pid=None, exe=None):
        if not pid and not exe:
            return False, "需提供 pid 或 exe 路径"
        if not pid and exe:
            pid = self._find_pid_by_exe(exe)
            if not pid:
                return False, "未找到进程: %s" % exe
        info = {"name": name, "pid": int(pid), "exe": exe or "",
                "added": time.strftime("%Y-%m-%d %H:%M:%S")}
        with self.lock:
            self.targets[name] = info
            self._exit_notified.discard(name)  # 重加同名目标：复位"已退出"标记，退出事件可再次发出
        return True, info

    def remove_target(self, name):
        with self.lock:
            removed = bool(self.targets.pop(name, None))
            self._exit_notified.discard(name)
            return removed

    def _find_pid_by_exe(self, exe):
        target = os.path.basename(exe).lower()
        try:
            out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                                 capture_output=True, text=True,
                                 encoding="utf-8", errors="replace",
                                 creationflags=SUB_FLAGS, timeout=15).stdout
        except (subprocess.SubprocessError, OSError):
            return None
        for row in csv.reader(io.StringIO(out)):
            if len(row) >= 2 and row[0].lower() == target:
                try:
                    return int(row[1])
                except ValueError:
                    continue
        return None

    def start(self):
        with self.lock:
            if self.state != "idle":
                return False
            if self.thread is not None and self.thread.is_alive():
                return False  # 旧采集线程尚未退出，避免双采集
            self.stop_flag.clear()
            self.state = "running"
            self.thread = threading.Thread(target=self._loop, daemon=True,
                                           name="watcher")
            self.thread.start()
        events.bus.publish("watcher.state", {"state": "running"})
        return True

    def stop(self):
        if self.stop_flag.is_set():
            return
        self.stop_flag.set()
        thread = self.thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5)
        with self.lock:
            self.state = "idle"
        events.bus.publish("watcher.state", {"state": "stopped"})

    def _loop(self):
        last_dns = {}
        self._reg_base = regscan.snapshot_watches()
        while not self.stop_flag.is_set():
            cycle_start = time.time()
            with self.lock:
                tnames = list(self.targets.keys())
            for name in tnames:
                try:
                    self._collect(name)
                except Exception as e:
                    logger.record_err("watcher.collect.%s" % name, e)
            dns_new = self._dns_diff(last_dns)
            last_dns = dns_new["current"]
            for item in dns_new["new"]:
                self._add_event("dns", "DNS 新解析: %s -> %s" % (item[0], item[1]))
            reg_after = regscan.snapshot_watches()
            for d in regscan.diff_watches(self._reg_base, reg_after):
                self._add_event("registry",
                                "注册表变化 %s\\%s: %s -> %s"
                                % (d["key"], d["name"], d["old"], d["new"]))
            self._reg_base = reg_after
            if self.watch_dirs:
                self._scan_dirs()
            elapsed = time.time() - cycle_start
            wait = self.interval - elapsed
            if wait > 0:
                self.stop_flag.wait(wait)

    def _process_tree(self, root_pid):
        """返回目标进程与其全部子孙进程的列表；采集失败返回 None（区别于"目标已退出"）。

        优先用 wmic 的 ParentProcessId 建树；wmic 不可用/失败时降级为"仅根进程"，
        绝不把全系统进程当作目标——否则网络连接会变成全网误归因。
        tasklist/wmic 结果按 1.5s 缓存（仅 watcher 单线程消费，无锁契约见 _collect）。
        """
        now = time.monotonic()
        cache = getattr(self, "_proc_cache", None)
        if cache and now - cache[0] < 1.5:
            rows, parents = cache[1], cache[2]
        else:
            rows = self._list_processes()
            parents = self._parent_map() if rows else {}
            self._proc_cache = (now, rows, parents)
        if not rows:
            return None  # tasklist 瞬时失败：不能断定目标退出
        root_pid = int(root_pid)
        if not any(p["pid"] == root_pid for p in rows):
            return []
        wanted = {root_pid}
        if parents:
            # BFS 收集全部子孙
            frontier = [root_pid]
            while frontier:
                pid = frontier.pop()
                for child, parent in parents.items():
                    if parent == pid and child not in wanted:
                        wanted.add(child)
                        frontier.append(child)
        return [p for p in rows if p["pid"] in wanted]

    def _list_processes(self):
        try:
            out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                                 capture_output=True, text=True,
                                 encoding="utf-8", errors="replace",
                                 creationflags=SUB_FLAGS, timeout=20).stdout
        except (subprocess.SubprocessError, OSError) as e:
            logger.record_err("watcher.tasklist", e)
            return []
        procs = []
        for row in csv.reader(io.StringIO(out)):
            if len(row) < 2:
                continue
            try:
                pid = int(row[1])
                procs.append({"pid": pid, "name": row[0],
                              "mem": row[4] if len(row) > 4 else ""})
            except ValueError:
                continue
        return procs

    def _parent_map(self):
        """wmic process get ProcessId,ParentProcessId /value → {child: parent}。失败返回 {}。

        输出按字母序（ParentProcessId 在前、ProcessId 在后）逐行出现，且字段间夹空行，
        因此不做"按空行分块"，而是记住最近一行 ParentProcessId，遇到 ProcessId 即配对。
        """
        try:
            out = subprocess.run(
                ["wmic", "process", "get", "ProcessId,ParentProcessId", "/value"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", creationflags=SUB_FLAGS, timeout=15).stdout
        except (subprocess.SubprocessError, OSError) as e:
            logger.record_err("watcher.wmic", e)
            return {}
        pairs = {}
        pending_parent = None
        for raw in out.splitlines():
            line = raw.strip()
            if not line:
                continue
            low = line.lower()
            try:
                if low.startswith("parentprocessid="):
                    pending_parent = int(line.split("=", 1)[1].strip())
                elif low.startswith("processid="):
                    pid = int(line.split("=", 1)[1].strip())
                    if pending_parent is not None and pid != pending_parent:
                        pairs[pid] = pending_parent
                    pending_parent = None
            except ValueError:
                # 任一行解析失败即作废当前配对，防止陈旧 parent 与下一进程错配
                pending_parent = None
                continue
        return pairs

    def _collect(self, name):
        with self.lock:
            info = self.targets.get(name)
        if not info:
            return
        root_pid = info["pid"]
        procs = self._process_tree(root_pid)
        if procs is None:
            return  # 本轮系统采集失败（tasklist 不可用），不当作目标退出
        alive = [p for p in procs if p["pid"] == root_pid]
        if not alive:
            # 退出事件只发一次；仅首次退出时补抓一次"最后连接"快照，避免每周期刷屏。
            with self.lock:
                exited = name in getattr(self, "_exit_notified", set())
            if not exited:
                with self.lock:
                    self._exit_notified = getattr(self, "_exit_notified", set()) | {name}
                self._add_event("process", "%s 进程已退出 (PID %d)" % (name, root_pid))
                latest = self._connections_for([root_pid])
                for c in latest:
                    self._add_event("network", c)
            return
        # 检修（2026-08-27）：PID 复用/同名进程误归因防线。登记时提供过映像路径的
        # 目标，每周期对根 PID 用 QueryFullProcessImageNameW 复核映像基名；
        # 明确不一致（查得到但不是它）视同目标已退出——绝不把无关进程的
        # 网络连接/DNS 写进时间线证据。查询失败（权限等）返回空串时不判罚，
        # 保持旧行为，避免把"无法核验"错当"归因失效"。
        if info.get("exe"):
            actual = _process_image_path(root_pid)
            if actual and os.path.basename(actual).lower() != \
                    os.path.basename(info["exe"]).lower():
                with self.lock:
                    exited = name in getattr(self, "_exit_notified", set())
                if not exited:
                    with self.lock:
                        self._exit_notified = \
                            getattr(self, "_exit_notified", set()) | {name}
                    self._add_event(
                        "process",
                        "%s PID %d 映像不符 (%s)，判定原目标已退出，停止采集"
                        % (name, root_pid, os.path.basename(actual)))
                return
        with self.lock:
            self._exit_notified = getattr(self, "_exit_notified", set()) - {name}
        conns = self._connections_for([p["pid"] for p in procs])
        with self.lock:
            seen = set(getattr(self, "_conn_seen", set()))
        new_seen = set()
        for c in conns:
            new_seen.add(c)
            if c not in seen:
                self._add_event("network", c)
        with self.lock:
            # 下一周期的"已见"集合 = 本周期全集（连接消失时自然从 seen 中淘汰）
            self._conn_seen = new_seen

    def _connections_for(self, pids):
        try:
            out = subprocess.run(["netstat", "-ano"], capture_output=True,
                                 text=True, encoding="utf-8", errors="replace",
                                 creationflags=SUB_FLAGS, timeout=20).stdout
        except (subprocess.SubprocessError, OSError) as e:
            logger.record_err("watcher.netstat", e)
            return []
        pid_set = set(pids)
        found = []
        tw_count = 0
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith(("Active", "Proto", "协议")):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                pid = int(parts[-1])
            except ValueError:
                continue
            if pid not in pid_set:
                continue
            if parts[0] == "UDP":
                # UDP 无连接状态，直接收录（与模块声明"TCP-UDP 连接"一致）
                found.append("UDP %s -> %s (PID %d)" % (parts[1], parts[2], pid))
                continue
            if len(parts) < 5:
                continue
            state = parts[3]
            if state == "TIME_WAIT":
                tw_count += 1
                continue
            if state not in ("ESTABLISHED", "LISTENING"):
                continue
            found.append("TCP %s -> %s %s (PID %d)" % (parts[1], parts[2], state, pid))
        if tw_count:
            found.append("另有 %d 个 TIME_WAIT 瞬态连接" % tw_count)
        return found[:100]

    def _dns_diff(self, prev):
        try:
            out = subprocess.run(["ipconfig", "/displaydns"],
                                 capture_output=True, text=True,
                                 encoding="utf-8", errors="replace",
                                 creationflags=SUB_FLAGS, timeout=20).stdout
        except (subprocess.SubprocessError, OSError) as e:
            logger.record_err("watcher.ipconfig", e)
            return {"current": prev, "new": []}
        current = {}
        for raw in out.splitlines():
            line = raw.strip()
            if not line or ":" not in line:
                continue
            low = line.lower()
            if not (low.startswith("记录名称") or low.startswith("record name")):
                continue
            name = line.split(":", 1)[1].strip().rstrip(".")
            if name:
                current[name] = True
        new = []
        for key in current:
            if key and key not in prev:
                new.append((key, "新增 DNS 记录"))
        return {"current": current, "new": new[:20]}

    def _scan_dirs(self):
        for d in self.watch_dirs:
            if not os.path.isdir(d):
                continue
            try:
                entries = sorted(os.listdir(d))
            except OSError as e:
                logger.record_err("watcher.scandir", e)
                continue
            key = "dir_%s" % d
            with self.lock:
                prev = getattr(self, "_dir_snap", {}).get(key, None)
            mtime = 0
            hashes = []
            for e in entries:
                try:
                    p = os.path.join(d, e)
                    st = os.stat(p)
                    if os.path.isfile(p):
                        hashes.append((e, int(st.st_mtime)))
                        mtime = max(mtime, int(st.st_mtime))
                except OSError:
                    continue
            cur = {"mtime": mtime, "files": dict(hashes)}
            if prev is not None:
                for f, tm in cur["files"].items():
                    if prev["files"].get(f) != tm:
                        self._add_event("file", "%s 变化: %s" % (d, f))
                for f in prev["files"]:
                    if f not in cur["files"]:
                        self._add_event("file", "%s 删除: %s" % (d, f))
            with self.lock:
                snap = getattr(self, "_dir_snap", {})
                snap[key] = cur
                self._dir_snap = snap

    def _add_event(self, etype, detail):
        ev = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "type": etype,
              "detail": detail[:400]}
        with self.lock:
            self.timeline.append(ev)
            if len(self.timeline) > self.max_events:
                del self.timeline[:len(self.timeline) - self.max_events]
        events.bus.publish("watcher.event", ev)

    def timeline_entries(self, limit=200):
        limit = max(1, int(limit))
        with self.lock:
            return list(self.timeline[-limit:])

    def snapshot_target(self, name=None):
        with self.lock:
            if name:
                info = self.targets.get(name)
                return dict(info) if info else None
            return [dict(v) for v in self.targets.values()]

    def status(self):
        with self.lock:
            return {"state": self.state, "targets": len(self.targets),
                    "events": len(self.timeline),
                    "interval": self.interval}


_watcher = None


def get_watcher():
    global _watcher
    if _watcher is None:
        _watcher = Watcher(config.get() if config.get() else {})
    return _watcher


def add_target(name, pid=None, exe=None):
    r = get_watcher().add_target(name, pid, exe)
    try:
        ok = bool(isinstance(r, (tuple, list)) and r[0])
        db.audit("watcher.add", "name=%s ok=%s" % (name, ok))
    except Exception:
        pass
    return r


def remove_target(name):
    return get_watcher().remove_target(name)


def start():
    try:
        db.audit("watcher.start", "all")
    except Exception:
        pass
    return get_watcher().start()


def stop():
    try:
        db.audit("watcher.stop", "all")
    except Exception:
        pass
    get_watcher().stop()
    return True  # 与 start() 一致的 bool 契约，前端 bizFail 判定依赖该返回值


def timeline_entries(limit=200):
    return get_watcher().timeline_entries(limit)


def snapshot_target(name=None):
    return get_watcher().snapshot_target(name)


def status():
    return get_watcher().status()


def register(bus, cfg):
    global _watcher
    _watcher = Watcher(cfg)
    bus.subscribe("watcher.start", lambda d: _watcher.start())
    bus.subscribe("watcher.stop", lambda d: _watcher.stop())


def shutdown():
    if _watcher is not None:
        _watcher.stop()