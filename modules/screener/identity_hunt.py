"""软件指纹深度排查——动态发现任意软件在机器上留下的所有身份标识。

本模块的目标：对任意软件（不依赖模式库），自动产出类似
"Qoder目录说明.md" 级别的完整排查报告。

核心能力：
  1. deep_registry_scan     注册表深度扫描（全根键，不止 Software）
  2. extract_identity_semantics  身份标识语义提取（不止 UUID）
  3. correlate_identity_sources   跨来源关联（文件↔注册表，主从判定）
  4. monitor_identity_access      运行时访问监控（动态补漏）
  5. assess_identity_impact       影响评估 + 处理建议
"""
import glob
import json
import os
import re
import time
from collections import defaultdict

# 身份标识语义分类（按影响力排序）
IDENTITY_SEMANTICS = {
    # 设备唯一标识（影响力最高）
    "device_id": {"weight": 1.0, "desc": "设备唯一标识", "examples": ["deviceid", "device_id", "deviceId", "devDeviceId"]},
    "machine_id": {"weight": 1.0, "desc": "机器唯一标识", "examples": ["machineid", "machine_id", "machineId", "MachineId"]},
    "installation_id": {"weight": 0.9, "desc": "安装实例标识", "examples": ["installationid", "installation_id", "installationId"]},
    "client_id": {"weight": 0.8, "desc": "客户端标识", "examples": ["clientid", "client_id", "clientId"]},
    # 用户/账号标识
    "user_id": {"weight": 0.7, "desc": "用户标识", "examples": ["userid", "user_id", "userId", "uid", "username", "email"]},
    "account_id": {"weight": 0.7, "desc": "账号标识", "examples": ["accountid", "account_id", "accountId"]},
    "login_state": {"weight": 0.6, "desc": "登录状态", "examples": ["logged_in", "login_state", "token", "session", "refresh_token"]},
    # 遥测/分析
    "telemetry": {"weight": 0.5, "desc": "遥测标识", "examples": ["telemetry", "sqmId", "sqm_id", "audit_enabled"]},
    # 派生/缓存
    "encrypted_key": {"weight": 0.4, "desc": "加密密钥", "examples": ["encrypted_key", "os_crypt", "device_id_salt"]},
    "cache": {"weight": 0.2, "desc": "缓存/派生", "examples": ["cache", "cached", "backup", "tmp"]},
}

# 注册表根键映射
REG_ROOTS = {
    "HKCU": 0x80000001,  # HKEY_CURRENT_USER
    "HKLM": 0x80000002,  # HKEY_LOCAL_MACHINE
    "HKU":  0x80000003,  # HKEY_USERS
    "HKCR": 0x80000000,  # HKEY_CLASSES_ROOT
}

# 需要重点扫描的注册表路径（按优先级）
REG_CRITICAL_PATHS = [
    r"Software",
    r"SOFTWARE\WOW6432Node",
    r"Software\Microsoft\DeveloperTools",
    r"SOFTWARE\Microsoft\SQMClient",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SYSTEM\CurrentControlSet\Services",
    r"SOFTWARE\Microsoft\Cryptography",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
]

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
HEX32_RE = re.compile(r"[0-9a-f]{32}", re.I)


_REG_NODE_BUDGET = 2000


def deep_registry_scan(keyword: str, max_depth: int = 3) -> dict:
    """注册表深度扫描（2026-08-27 检修 T12）：旧实现只枚举单层键名/值，
    "深度"名不副实——"QoderWork CN" 命中后读不到其下的 InstallLocation。
    现在：名字命中的子键继续下钻（进入后收集该子树全部值），全程节点预算封顶；
    未命中的子键不下钻，成本与命中数成比例。

    检修（2026-09-19）：①节点预算改为整次调用共享一份——旧实现每个
    (root,path) 组合新建预算，上限实为 2000×路径数，整树倾倒失控；
    ②关键词至少 2 字符——空串在 `keyword in name` 判定下恒真，
    会把全部顶层值当命中（实测 12k 命中 / 1MB JSON）。"""
    import winreg

    keyword_lower = str(keyword or "").lower().strip()
    if len(keyword_lower) < 2:
        return {"error": "关键词至少 2 字符（空/单字符会把整树值当命中倾倒）"}

    results = {}
    budget = [_REG_NODE_BUDGET]  # 整次扫描共享
    truncated = [False]  # 检修（2026-09-19）：截断必须显式上报——旧实现
    # 预算耗尽/枚举出错静默 break，部分结果被当成全机结论（FreqErr §8
    # "截断快照当完整基线"同坑在扫描侧的残留）。
    for root_name, root_handle in REG_ROOTS.items():
        if budget[0] <= 0:
            truncated[0] = True
            break
        for path in REG_CRITICAL_PATHS:
            full_path = f"{root_name}\\{path}"
            try:
                k = winreg.OpenKey(root_handle, path, 0, winreg.KEY_READ)
            except OSError:
                continue
            try:
                hits = _scan_reg_key(k, keyword_lower, int(max_depth),
                                     budget, inside_match=False,
                                     truncated=truncated)
                if hits:
                    results[full_path] = hits
            finally:
                try:
                    winreg.CloseKey(k)
                except OSError:
                    pass
        if budget[0] <= 0:
            truncated[0] = True
            break

    if truncated[0]:
        results["truncated"] = True  # 预留键：消费方按非 list 值跳过
    return results


def scan_system_anchors() -> dict:
    """系统锚点扫描：不依赖关键词，扫描已知的系统级注册表路径。

    这些锚点跨重装存活，是"主犯"级别的标识来源。
    包括：DeveloperTools、SQMClient、Cryptography、Windows NT 等。
    """
    import winreg

    # 已知的系统级锚点路径（按影响力排序）
    ANCHOR_PATHS = [
        # 设备标识（影响力最高）
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\DeveloperTools", "deviceid"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\SQMClient", "MachineId"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\SQMClient", "WindowsId"),
        # 加密/标识
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", "MachineGuid"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "InstallDate"),
        # 网络/硬件
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Hostname"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001", "HwProfileGuid"),
    ]
    # 检修（2026-08-27 T11）：旧 REG_ROOTS 反查 dict 在部分 Python 构建下因
    # winreg 句柄常量符号性不一致而 miss，输出裸整数句柄；改为常量直接比较
    root_names = {winreg.HKEY_CURRENT_USER: "HKCU", winreg.HKEY_LOCAL_MACHINE: "HKLM"}

    results = {}
    for root, path, value_name in ANCHOR_PATHS:
        root_name = root_names.get(root, "HK?")
        try:
            k = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
        except OSError:
            continue
        try:
            try:
                data, dtype = winreg.QueryValueEx(k, value_name)
                data_str = _reg_value_text(data, dtype)
                full_path = f"{root_name}\\{path}\\{value_name}"
                results[full_path] = {
                    "type": "value",
                    "name": value_name,
                    "data": data_str[:200],
                    "is_uuid": bool(UUID_RE.search(data_str)),
                    "is_system_anchor": True,
                }
            except OSError:
                pass
        finally:
            # 检修（2026-09-19）：CloseKey 入 finally——异常路径不再泄漏句柄
            try:
                winreg.CloseKey(k)
            except OSError:
                pass

    return results


def _reg_value_text(data, dtype) -> str:
    """注册表值 → 可比较文本（检修 2026-09-19）：旧实现只认 REG_SZ，
    REG_EXPAND_SZ/MULTI_SZ 变成 "[2:45B]" 占位符，correlate 又整体跳过——
    自启动路径、多值标识这类最该关联的形态被系统性漏配。"""
    import winreg
    if dtype in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
        return str(data)
    if dtype == winreg.REG_MULTI_SZ:
        try:
            return "\n".join(str(x) for x in data)
        except TypeError:
            pass
    return f"[{dtype}:{len(str(data))}B]"


def _scan_reg_key(key, keyword: str, max_depth: int, budget,
                  inside_match: bool, truncated=None) -> list:
    """有界递归扫描（检修 T12）。

    inside_match=True 表示已进入名字命中的子树：该子树下所有值都视为相关
    （不再按关键词过滤）；更深层子键仅按关键词继续下钻。
    budget 为单元素列表（跨递归共享节点预算），防整棵树遍历失控。
    truncated 为单元素列表（检修 2026-09-19）：预算耗尽截断或枚举中途
    出错（非 259）时置 True——部分结果不得冒充全量。"""
    import winreg

    if truncated is None:
        truncated = [False]
    hits = []
    if budget[0] <= 0:
        truncated[0] = True
        return hits
    # 值枚举
    i = 0
    while budget[0] > 0:
        try:
            name, data, dtype = winreg.EnumValue(key, i)
        except OSError as e:
            if e.winerror != 259:
                truncated[0] = True  # 权限/IO 错误：本键值清单不完整
            break
        budget[0] -= 1
        i += 1
        data_str = _reg_value_text(data, dtype)
        if inside_match or keyword in name.lower() or keyword in data_str.lower():
            hits.append({
                "type": "value",
                "name": name,
                "data": data_str[:200],
                "is_uuid": bool(UUID_RE.search(data_str)),
            })
    else:
        truncated[0] = True  # while 因预算耗尽退出（非枚举自然结束）
    # 子键枚举：仅名字命中者下钻
    if max_depth > 0:
        i = 0
        while budget[0] > 0:
            try:
                subname = winreg.EnumKey(key, i)
            except OSError as e:
                if e.winerror != 259:
                    truncated[0] = True  # 子键清单不完整
                break
            budget[0] -= 1
            i += 1
            if keyword not in subname.lower():
                continue
            hits.append({"type": "key", "name": subname, "data": "", "is_uuid": False})
            try:
                sk = winreg.OpenKey(key, subname, 0, winreg.KEY_READ)
            except OSError:
                continue
            try:
                hits.extend(_scan_reg_key(sk, keyword, max_depth - 1, budget,
                                          inside_match=True,
                                          truncated=truncated))
            finally:
                try:
                    winreg.CloseKey(sk)
                except OSError:
                    pass
        else:
            truncated[0] = True  # 子键枚举因预算耗尽中断
    return hits


def _mask(v) -> str:
    """掩码显示（首4+…+尾4）；与 core.config.mask_secret 同源。"""
    try:
        from core.config import mask_secret
        return mask_secret(str(v))
    except Exception:
        s = str(v)
        return (s[:4] + "…" + s[-4:]) if len(s) > 8 else "••••"


def _read_file_values(p, fsize) -> list:
    """读小文件（≤64KB）内容作为身份值候选。

    二进制（头 512B 含 NUL）不做文本提取；内容为 JSON 时优先提取身份键的
    标量值（如 .qoderworkcn\\default 的 uid），否则取整段文本（如 machineid）。"""
    if fsize <= 0 or fsize > 64 * 1024:
        return []
    try:
        with open(p, "rb") as f:
            head = f.read(64 * 1024)
    except OSError:
        return []
    if b"\x00" in head[:512]:
        return []
    text = head.decode("utf-8", errors="ignore").strip()
    if not text:
        return []
    if text[:1] in ("{", "["):
        try:
            data = json.loads(text)
            vals = []

            def _dig(obj):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if isinstance(v, (str, int, float)) and str(v).strip():
                            kl = k.lower()
                            if any(ex in kl for sem in IDENTITY_SEMANTICS.values()
                                   for ex in sem["examples"]):
                                vals.append(str(v).strip())
                        elif isinstance(v, (dict, list)):
                            _dig(v)
                elif isinstance(obj, list):
                    for item in obj[:10]:
                        if isinstance(item, (dict, list)):
                            _dig(item)

            _dig(data)
            seen = []
            for v in vals:
                if v not in seen:
                    seen.append(v)
            return [{"raw": v, "masked": _mask(v)} for v in seen[:8]]
        except Exception:
            pass
    if len(text) > 512:
        return []
    return [{"raw": text, "masked": _mask(text)}]


def extract_identity_semantics(paths: list) -> list:
    """从文件列表中提取身份标识并分类语义。

    不止提取 UUID，还识别登录态、遥测、安装标识等。
    优化：减少误报（package.json、product.json 等配置文件不算 device_id）。
    检修（2026-08-27 T13）：每个 finding 附 values=[{raw,masked}]——
    旧实现只记"有没有"不记"值是什么"，导致跨来源关联无从比对。
    raw 仅用于模块内关联，返回链路上由 sanitize_findings 剥除。
    """
    findings = []

    # 排除模式（这些文件不算身份标识）
    EXCLUDE_PATTERNS = [
        "package.json", "product.json", "manifest.json", "metadata.json",
        "extensions.json", "installed_plugins.json", "settings.json",
        "argv.json", "languagepacks.json",
    ]

    for p in paths:
        if not os.path.isfile(p):
            continue
        # 检修（2026-09-19）：isfile 与 getsize 之间的竞态/云占位符/权限问题
        # 会抛 OSError 冒穿整条管线——已扫结果全部作废。逐文件容错继续。
        try:
            fsize = os.path.getsize(p)
        except OSError:
            continue

        fname = os.path.basename(p).lower()

        # 排除常见配置文件
        if fname in EXCLUDE_PATTERNS:
            continue

        # 规则 1：文件名匹配（附值提取——machineid/machine-id 等文件内容即值）
        name_hit = None
        for sem_key, sem_info in IDENTITY_SEMANTICS.items():
            for example in sem_info["examples"]:
                if example in fname:
                    name_hit = (sem_key, sem_info)
                    break
            if name_hit:
                break
        if name_hit:
            findings.append({
                "path": p,
                "semantic": name_hit[0],
                "weight": name_hit[1]["weight"],
                "desc": name_hit[1]["desc"],
                "source": "filename",
                "values": _read_file_values(p, fsize),
            })

        # 规则 2：小文件内容提取
        if fsize > 0 and fsize < 1024 * 1024:
            try:
                with open(p, "rb") as f:
                    content = f.read()

                try:
                    text = content.decode("utf-8", errors="ignore")
                except Exception:
                    text = ""

                already = any(f["path"] == p for f in findings)
                if not already:
                    uuids = UUID_RE.findall(text)
                    if uuids:
                        dedup = []
                        for u in uuids:
                            if u not in dedup:
                                dedup.append(u)
                        findings.append({
                            "path": p,
                            "semantic": "device_id",
                            "weight": 1.0,
                            "desc": f"内容含 {len(dedup)} 个 UUID",
                            "source": "content",
                            "values": [{"raw": u, "masked": _mask(u)}
                                       for u in dedup[:8]],
                        })

                # JSON 键匹配
                if p.endswith(".json") and text:
                    try:
                        data = json.loads(text)
                        _extract_json_identities(data, p, findings)
                    except Exception:
                        pass

            except OSError:
                pass

    return findings


def _extract_json_identities(data, path, findings, prefix=""):
    """递归提取 JSON 中的身份标识（检修 T13：命中键附标量值 raw/masked）"""
    if isinstance(data, dict):
        for k, v in data.items():
            full_key = f"{prefix}.{k}" if prefix else k
            # 键名匹配
            for sem_key, sem_info in IDENTITY_SEMANTICS.items():
                for example in sem_info["examples"]:
                    if example in k.lower():
                        entry = {
                            "path": path,
                            "semantic": sem_key,
                            "weight": sem_info["weight"],
                            "desc": f"JSON 键 {full_key}",
                            "source": "json_key",
                        }
                        if isinstance(v, (str, int, float)) and str(v).strip():
                            sv = str(v).strip()
                            entry["values"] = [{"raw": sv, "masked": _mask(sv)}]
                        findings.append(entry)
                        break
            # 递归
            if isinstance(v, (dict, list)):
                _extract_json_identities(v, path, findings, full_key)
    elif isinstance(data, list):
        for i, item in enumerate(data[:10]):  # 限前 10 项
            if isinstance(item, (dict, list)):
                _extract_json_identities(item, path, findings, f"{prefix}[{i}]")


def correlate_identity_sources(file_findings: list, reg_findings: dict) -> dict:
    """跨来源关联（2026-08-27 检修 T13 重做）：以「值」为关联键。

    旧实现把文件按 path 分组、注册表按 data 分组——两组键永不相交，
    cross_references 恒空，关联形同虚设。现在：文件侧取 findings.values[].raw，
    注册表侧取 hit data（含 UUID 提取、去花括号归一）；同一值同时出现在
    文件与注册表 → 记为跨来源引用。返回结构只含 masked 值，raw 不出模块。"""
    def _norm(s):
        # 检修（2026-09-19）：一并剥引号——带引号的值（"\"{guid}\""）此前不匹配。
        return str(s or "").strip().strip("{}\"' \t").lower()

    value_sources = defaultdict(lambda: {"files": [], "registry": [], "masked": ""})
    for f in file_findings or []:
        for v in f.get("values") or []:
            raw = str(v.get("raw") or "").strip()
            masked = str(v.get("masked") or "").strip()
            # 检修（2026-09-19）：工具链上 extract_identity_semantics 出口已
            # sanitize（raw 剥除只剩 masked），correlate 若只认 raw 则
            # cross_references 恒空、关联工具整链报废。masked 也作关联键；
            # 模块内部（raw 尚在）行为不变。
            fp = f.get("path") or ""
            for key in {_norm(raw), _norm(masked)}:
                if len(key) < 8:
                    continue
                entry = value_sources[key]
                entry["masked"] = entry["masked"] or masked or _mask(raw)
                if fp and fp not in entry["files"]:
                    entry["files"].append(fp)

    for reg_path, hits in (reg_findings or {}).items():
        # 检修（2026-09-19）：形状契约闭合——scan_system_anchors 返回
        # {path: hit_dict}、deep_registry_scan 返回 {path: [hit,...]}、错误封套
        # 是 {error: str}；作为 Agent 工具由模型回传时三种形态都会出现，
        # 旧实现直接迭代在 dict/str 形态上抛 AttributeError。
        if isinstance(hits, dict):
            hits = [hits]
        if not isinstance(hits, list):
            continue
        for h in hits:
            if not isinstance(h, dict):
                continue
            data = str(h.get("data") or "")
            if not data or data.startswith("["):
                continue
            cands = {data.strip()} | set(UUID_RE.findall(data))
            for c in cands:
                # masked 形态一并作候选键（_mask 归一到去花括号小写，与
                # 文件侧 masked 键同源同形）
                for key in {_norm(c), _norm(_mask(_norm(c)))}:
                    if len(key) < 8 or key not in value_sources:
                        continue
                    vname = str(h.get("name") or "")
                    # 锚点形态的 key 已含值名（...\deviceid），不再重复拼接
                    if vname and not reg_path.lower().endswith("\\" + vname.lower()):
                        label = "%s\\%s" % (reg_path, vname)
                    else:
                        label = reg_path
                    if label not in value_sources[key]["registry"]:
                        value_sources[key]["registry"].append(label)

    cross = []
    seen = set()  # raw 键与 masked 键指向同一文件集时会各产一条，按内容去重
    for entry in value_sources.values():
        if entry["files"] and entry["registry"]:
            sig = (entry["masked"], tuple(entry["files"]), tuple(entry["registry"]))
            if sig in seen:
                continue
            seen.add(sig)
            cross.append({
                "value": entry["masked"],
                "files": entry["files"],
                "registry": entry["registry"],
                "verdict": "注册表与文件同值：注册表为主来源，文件为缓存/派生",
            })
    cross.sort(key=lambda x: (-len(x["files"]), x["value"]))
    return {
        "cross_references": cross[:50],
        "note": "判定语义：值同现 → 注册表为主、文件为派生；"
                "仅文件出现 → 用 derive_probe 追溯派生链或判定随机/云端",
    }


def monitor_identity_access(process_name: str, duration: int = 30) -> dict:
    """运行时访问监控：监控进程对文件/注册表的访问，发现动态身份标识。

    使用 watcher 模块监控进程行为。
    检修（2026-09-14）：duration 钳制 0~300 秒（防调用方传大值挂死工作线程）；
    进程名查找补 ".exe" 双尝试——hunt 传入的常是软件关键词（"Qoder"），
    而 tasklist 镜像名恒带扩展名（"qoder.exe"），否则监控恒"未找到进程"。
    """
    from modules.watcher import Watcher

    duration = max(0, min(int(duration or 0), 300))
    w = Watcher({})
    name = str(process_name or "").strip()
    pid = w._find_pid_by_exe(name)
    lookup = name
    if not pid and name and "." not in os.path.basename(name):
        lookup = name + ".exe"
        pid = w._find_pid_by_exe(lookup)

    if not pid:
        return {"ok": False, "error": "未找到进程: %s" % name}

    w.add_target(lookup, pid=pid)
    try:
        w.start()
        try:
            time.sleep(duration)
        finally:
            # 检修（2026-09-19）：sleep 被打断/异常也必须收线程（FreqErr §30
            # "只开不收"同款——daemon 采集线程永不停止、双份轮询）。
            w.stop()
    except Exception as e:
        return {"ok": False, "error": "监控失败: %s" % e}
    # 分析时间线中的文件/注册表访问
    entries = w.timeline_entries()
    identity_access = []
    
    for e in entries:
        detail = e.get("detail", "")
        # 过滤含身份标识的访问
        if any(kw in detail.lower() for kw in ["machineid", "device", "identity", "uuid", "telemetry"]):
            identity_access.append(e)
    
    return {
        "ok": True,
        "process": process_name,
        "pid": pid,
        "duration": duration,
        "total_entries": len(entries),
        "identity_access": identity_access,
    }


def assess_identity_impact(findings: list, correlation: dict) -> list:
    """影响评估 + 处理建议。
    
    评分逻辑：
    - 语义权重（device_id > cache）
    - 跨来源一致性（多处引用 = 高影响）
    - 动态访问频率（运行时频繁访问 = 高影响）
    
    处理建议：
    - 可删：删后无害或重建无害
    - 可篡改：篡改后软件接受新值
    - 不可动：系统级锚点
    """
    assessed = []

    # 跨来源命中集合（检修 T13：按 path 精确匹配，不再字符串包含整个 ref dict）
    cross_files = set()
    for ref in (correlation or {}).get("cross_references") or []:
        cross_files.update(ref.get("files") or [])

    for f in findings:
        score = f.get("weight", 0.5)

        # 跨来源加分（round 防浮点漂移：0.6+0.3=0.8999…9 曾使评分卡在档位线下）
        if f.get("path") in cross_files:
            score = round(score + 0.3, 6)
        
        # 处理建议
        if score >= 0.9:
            action = "可删/可篡改"
            note = "主标识，删后重启重建新值"
        elif score >= 0.6:
            action = "可删"
            note = "派生标识，删后可能再生"
        elif score >= 0.3:
            action = "谨慎"
            note = "系统锚点或加密密钥，删后可能影响其他软件"
        else:
            action = "不动"
            note = "缓存/临时，无需处理"
        
        assessed.append({
            **f,
            "impact_score": min(score, 1.0),
            "action": action,
            "note": note,
        })
    
    # 按影响力排序
    assessed.sort(key=lambda x: x["impact_score"], reverse=True)
    return assessed


def file_identity_pipeline(keyword: str) -> dict:
    """文件侧管线（2026-08-27 检修 T10 拆分）：目录发现 → 逐文件语义提取。

    供 hunt_software_fingerprint 与 run_full_investigation 共用，
    避免同一关键词重复走两遍文件树/注册表。"""
    file_results = []
    patterns = [
        f"%APPDATA%\\*{keyword}*",
        f"%LOCALAPPDATA%\\*{keyword}*",
        f"%PROGRAMDATA%\\*{keyword}*",
        f"%USERPROFILE%\\.*{keyword}*",
        f"%USERPROFILE%\\*{keyword}*",
        f"%LOCALAPPDATA%\\Programs\\*{keyword}*",
    ]
    for pat in patterns:
        file_results.extend(glob.glob(os.path.expandvars(pat)))
    file_results = list(set(file_results))  # 去重

    all_files = [f for f in file_results if os.path.isfile(f)]
    dir_files = []
    # 检修（2026-09-19）：目录展开加总量预算——keyword 命中一个大目录
    # （如整个 AppData 产品目录）时旧实现无上限收集全部文件，
    # 规则2 再逐文件 read() ≤1MB，可达 GB 级 IO。
    _MAX_DIR_FILES = 2000
    files_truncated = False
    for d in file_results:
        if os.path.isdir(d):
            for root, dirs, files in os.walk(d):
                depth = root[len(d):].count(os.sep)
                if depth >= 3:
                    dirs[:] = []
                    continue
                for f in files:
                    if len(dir_files) >= _MAX_DIR_FILES:
                        files_truncated = True
                        break
                    dir_files.append(os.path.join(root, f))
                if files_truncated:
                    break
        if files_truncated:
            break

    findings = extract_identity_semantics(all_files + dir_files)
    return {"findings": findings, "file_hits": file_results,
            "scanned_files": len(all_files) + len(dir_files),
            "files_truncated": files_truncated}


def sanitize_findings(findings: list) -> list:
    """剥除 raw 值只留 masked（raw 仅用于模块内关联，绝不出模块边界）。"""
    out = []
    for f in findings or []:
        g = dict(f)
        vals = g.get("values")
        if isinstance(vals, list):
            g["values"] = [{"masked": v.get("masked", "")}
                           for v in vals if isinstance(v, dict)]
        out.append(g)
    return out


def hunt_software_fingerprint(keyword: str, monitor_duration: int = 0) -> dict:
    """整合入口：对任意软件，动态发现所有身份指纹。

    流程：注册表深度扫描 → 系统锚点 → 文件管线 → 跨来源关联
    → 运行时监控（可选）→ 影响评估 → 脱敏输出。

    检修：系统锚点一并并入关联输入——DeveloperTools\\deviceid 等"主犯"值
    与文件内 telemetry.devDeviceId 的同值关系只有把锚点喂进 correlate 才能现形。"""
    if not str(keyword or "").strip() or len(str(keyword).strip()) < 2:
        return {"error": "关键词至少 2 字符（防整树/整目录倾倒）"}
    reg_all = dict(deep_registry_scan(keyword))
    if reg_all.get("error"):
        return {"error": reg_all["error"]}
    # 锚点结构是 {path: hit_dict}，correlate 期望 {path: [hit,...]}，统一包列表
    reg_all.update({k: [v] for k, v in scan_system_anchors().items()})
    pipe = file_identity_pipeline(keyword)
    findings = pipe["findings"]

    correlation = correlate_identity_sources(findings, reg_all)
    reg_truncated = bool(reg_all.pop("truncated", False))

    monitor_results = None
    if monitor_duration > 0:
        monitor_results = monitor_identity_access(keyword, monitor_duration)

    assessed = sanitize_findings(assess_identity_impact(findings, correlation))

    return {
        "software": keyword,
        "registry_hits": reg_all,
        "file_hits": pipe["file_hits"],
        "identity_findings": assessed,
        "correlation": correlation,
        "monitor": monitor_results,
        "summary": {
            "total_files": pipe["scanned_files"],
            "files_truncated": pipe.get("files_truncated", False),
            "registry_truncated": reg_truncated,
            "total_identities": len(assessed),
            "high_impact": len([a for a in assessed if a["impact_score"] >= 0.9]),
            "medium_impact": len([a for a in assessed if 0.6 <= a["impact_score"] < 0.9]),
            "low_impact": len([a for a in assessed if a["impact_score"] < 0.6]),
        },
    }
