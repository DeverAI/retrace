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


def deep_registry_scan(keyword: str, max_depth: int = 3) -> dict:
    """注册表深度扫描：遍历所有根键下的关键路径，找含关键词的键值。
    
    不止扫 Software，还包括 DeveloperTools、SQMClient、Run、Services 等。
    """
    import winreg
    
    results = {}
    keyword_lower = keyword.lower()
    
    for root_name, root_handle in REG_ROOTS.items():
        for path in REG_CRITICAL_PATHS:
            full_path = f"{root_name}\\{path}"
            try:
                k = winreg.OpenKey(root_handle, path, 0, winreg.KEY_READ)
                hits = _scan_reg_key(k, keyword_lower, max_depth)
                if hits:
                    results[full_path] = hits
                winreg.CloseKey(k)
            except OSError:
                continue
    
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
    
    results = {}
    for root, path, value_name in ANCHOR_PATHS:
        root_name = {v: k for k, v in REG_ROOTS.items()}.get(root, str(root))
        try:
            k = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
            try:
                data, dtype = winreg.QueryValueEx(k, value_name)
                data_str = str(data) if dtype == winreg.REG_SZ else f"[{dtype}:{len(str(data))}B]"
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
            winreg.CloseKey(k)
        except OSError:
            continue
    
    return results


def _scan_reg_key(key, keyword: str, max_depth: int) -> list:
    """递归扫描注册表键"""
    import winreg
    
    hits = []
    try:
        # 枚举值
        i = 0
        while True:
            try:
                name, data, dtype = winreg.EnumValue(key, i)
                data_str = str(data) if dtype == winreg.REG_SZ else f"[{dtype}:{len(str(data))}B]"
                if keyword in name.lower() or keyword in data_str.lower():
                    hits.append({
                        "type": "value",
                        "name": name,
                        "data": data_str[:200],
                        "is_uuid": bool(UUID_RE.search(data_str)),
                    })
                i += 1
            except OSError:
                break
        
        # 枚举子键（限深度）
        if max_depth > 0:
            i = 0
            while True:
                try:
                    subname = winreg.EnumKey(key, i)
                    if keyword in subname.lower():
                        hits.append({
                            "type": "key",
                            "name": subname,
                            "data": "",
                            "is_uuid": False,
                        })
                    i += 1
                except OSError:
                    break
    except OSError:
        pass
    
    return hits


def extract_identity_semantics(paths: list) -> list:
    """从文件列表中提取身份标识并分类语义。
    
    不止提取 UUID，还识别登录态、遥测、安装标识等。
    优化：减少误报（package.json、product.json 等配置文件不算 device_id）。
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
        
        fname = os.path.basename(p).lower()
        fsize = os.path.getsize(p)
        
        # 排除常见配置文件
        if fname in EXCLUDE_PATTERNS:
            continue
        
        # 规则 1：文件名匹配
        for sem_key, sem_info in IDENTITY_SEMANTICS.items():
            for example in sem_info["examples"]:
                if example in fname:
                    findings.append({
                        "path": p,
                        "semantic": sem_key,
                        "weight": sem_info["weight"],
                        "desc": sem_info["desc"],
                        "source": "filename",
                    })
                    break
        
        # 规则 2：小文件内容提取
        if fsize > 0 and fsize < 1024 * 1024:
            try:
                with open(p, "rb") as f:
                    content = f.read()
                
                # 尝试 UTF-8 解码
                try:
                    text = content.decode("utf-8", errors="ignore")
                except:
                    text = ""
                
                # 提取 UUID（仅当文件未被文件名规则匹配时）
                if not any(f["path"] == p for f in findings):
                    uuids = UUID_RE.findall(text)
                    if uuids:
                        # 过滤：如果文件是 JSON 且 UUID 是某个键的值，检查键名
                        if p.endswith(".json") and text:
                            try:
                                data = json.loads(text)
                                identity_uuids = _extract_identity_uuids_from_json(data)
                                if identity_uuids:
                                    findings.append({
                                        "path": p,
                                        "semantic": "device_id",
                                        "weight": 1.0,
                                        "desc": f"内容含 {len(identity_uuids)} 个身份 UUID",
                                        "source": "content",
                                    })
                            except:
                                pass
                        else:
                            findings.append({
                                "path": p,
                                "semantic": "device_id",
                                "weight": 1.0,
                                "desc": f"内容含 {len(uuids)} 个 UUID",
                                "source": "content",
                            })
                
                # JSON 键匹配
                if p.endswith(".json") and text:
                    try:
                        data = json.loads(text)
                        _extract_json_identities(data, p, findings)
                    except:
                        pass
                
            except OSError:
                pass
    
    return findings


def _extract_identity_uuids_from_json(data) -> list:
    """从 JSON 中提取与身份标识相关的 UUID（排除版本号、构建 ID 等）"""
    identity_uuids = []
    
    def _walk(obj, key_path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{key_path}.{k}" if key_path else k
                # 检查键名是否与身份相关
                is_identity_key = any(
                    example in k.lower()
                    for sem in IDENTITY_SEMANTICS.values()
                    for example in sem["examples"]
                )
                if is_identity_key and isinstance(v, str) and UUID_RE.match(v):
                    identity_uuids.append(v)
                if isinstance(v, (dict, list)):
                    _walk(v, full_key)
        elif isinstance(obj, list):
            for i, item in enumerate(obj[:10]):
                if isinstance(item, (dict, list)):
                    _walk(item, f"{key_path}[{i}]")
    
    _walk(data)
    return identity_uuids


def _extract_json_identities(data, path, findings, prefix=""):
    """递归提取 JSON 中的身份标识"""
    if isinstance(data, dict):
        for k, v in data.items():
            full_key = f"{prefix}.{k}" if prefix else k
            # 键名匹配
            for sem_key, sem_info in IDENTITY_SEMANTICS.items():
                for example in sem_info["examples"]:
                    if example in k.lower():
                        findings.append({
                            "path": path,
                            "semantic": sem_key,
                            "weight": sem_info["weight"],
                            "desc": f"JSON 键 {full_key}",
                            "source": "json_key",
                        })
                        break
            # 递归
            if isinstance(v, (dict, list)):
                _extract_json_identities(v, path, findings, full_key)
    elif isinstance(data, list):
        for i, item in enumerate(data[:10]):  # 限前 10 项
            if isinstance(item, (dict, list)):
                _extract_json_identities(item, path, findings, f"{prefix}[{i}]")


def correlate_identity_sources(file_findings: list, reg_findings: dict) -> dict:
    """跨来源关联：文件↔注册表，判定谁是"主"谁是"从"。
    
    逻辑：
    - 注册表值 = 文件内容 → 注册表是"主"，文件是"从"（缓存）
    - 文件内容含注册表没有的值 → 文件是独立来源
    - 多处文件含相同值 → 该值是"主标识"，需追踪来源
    """
    correlation = {
        "primary_sources": [],   # 主来源（注册表/独立文件）
        "derived_sources": [],   # 派生来源（缓存/备份）
        "cross_references": [],  # 跨来源引用
    }
    
    # 收集所有值
    all_values = defaultdict(list)
    for f in file_findings:
        all_values[f.get("path", "")].append(f)
    for reg_path, hits in reg_findings.items():
        for h in hits:
            all_values[h.get("data", "")].append({**h, "reg_path": reg_path})
    
    # 判定主从（简化：注册表优先）
    for val, sources in all_values.items():
        if len(val) < 6:  # 忽略短值
            continue
        has_reg = any("reg_path" in s for s in sources)
        has_file = any("path" in s and "reg_path" not in s for s in sources)
        
        if has_reg and has_file:
            correlation["cross_references"].append({
                "value_preview": val[:20] + "...",
                "primary": [s for s in sources if "reg_path" in s],
                "derived": [s for s in sources if "reg_path" not in s],
            })
    
    return correlation


def monitor_identity_access(process_name: str, duration: int = 30) -> dict:
    """运行时访问监控：监控进程对文件/注册表的访问，发现动态身份标识。
    
    使用 watcher 模块监控进程行为。
    """
    from modules.watcher import Watcher
    
    w = Watcher({})
    pid = w._find_pid_by_exe(process_name)
    
    if not pid:
        return {"ok": False, "error": f"未找到进程: {process_name}"}
    
    w.add_target(process_name, pid=pid)
    w.start()
    time.sleep(duration)
    w.stop()
    
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
    
    for f in findings:
        score = f.get("weight", 0.5)
        
        # 跨来源加分
        if correlation.get("cross_references"):
            for ref in correlation["cross_references"]:
                if f.get("path", "") in str(ref):
                    score += 0.3
        
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


def hunt_software_fingerprint(keyword: str, monitor_duration: int = 0) -> dict:
    """整合入口：对任意软件，动态发现所有身份指纹。
    
    流程：
    1. 注册表深度扫描
    2. 文件系统痕迹发现
    3. 身份标识语义提取
    4. 跨来源关联
    5. 运行时监控（可选）
    6. 影响评估 + 处理建议
    """
    # 阶段 1：注册表
    reg_results = deep_registry_scan(keyword)
    
    # 阶段 2：文件系统
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
    
    # 阶段 3：语义提取
    all_files = [f for f in file_results if os.path.isfile(f)]
    dir_files = []
    for d in file_results:
        if os.path.isdir(d):
            for root, dirs, files in os.walk(d):
                depth = root[len(d):].count(os.sep)
                if depth >= 3:
                    dirs[:] = []
                    continue
                for f in files:
                    dir_files.append(os.path.join(root, f))
    
    findings = extract_identity_semantics(all_files + dir_files)
    
    # 阶段 4：跨来源关联
    correlation = correlate_identity_sources(findings, reg_results)
    
    # 阶段 5：运行时监控（可选）
    monitor_results = None
    if monitor_duration > 0:
        monitor_results = monitor_identity_access(keyword, monitor_duration)
    
    # 阶段 6：影响评估
    assessed = assess_identity_impact(findings, correlation)
    
    return {
        "software": keyword,
        "registry_hits": reg_results,
        "file_hits": file_results,
        "identity_findings": assessed,
        "correlation": correlation,
        "monitor": monitor_results,
        "summary": {
            "total_files": len(all_files + dir_files),
            "total_identities": len(assessed),
            "high_impact": len([a for a in assessed if a["impact_score"] >= 0.9]),
            "medium_impact": len([a for a in assessed if 0.6 <= a["impact_score"] < 0.9]),
            "low_impact": len([a for a in assessed if a["impact_score"] < 0.6]),
        },
    }
