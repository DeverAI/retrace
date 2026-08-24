"""筛查工作台——留样清理与一键恢复（备份→修改→验证→回滚协议）。

安全不变量：
  - 清理前强制系统还原点（privacy_guard._create_restore_point），失败即中止
  - 注册表/文件操作前先备份到 quarantine，manifest 先于删除落盘
  - HKCR/HKU 与共享/系统核心范围确定性拒绝；系统/项目目录拒绝搬移
  - 恢复仅允许 backups/quarantine 内的备份（realpath 防符号链接逃逸）
"""
import json
import os
import shutil
import threading
import time
import uuid

from core import config, db, logger
from modules.screener.common import (
    _CLEANABLE_ROOTS, _REG_ROOTS, _is_protected_fs_path, _winroot)

_cleanup_lock = threading.Lock()


def _parse_reg_target(target):
    """解析注册表目标，返回 (root_name, subkey, value_name) 或 None。"""
    target = (target or "").strip()
    path, _, value_name = target.partition("|")
    root_name, _, subkey = path.partition("\\")
    root_name = root_name.upper()
    if root_name not in _REG_ROOTS:
        return None
    subkey = subkey.lstrip("\\")
    return root_name, subkey, value_name


def _safe_json_value(v):
    """把任意注册表值转成可 JSON 序列化的形式。"""
    if isinstance(v, bytes):
        return {"__bytes_hex__": v.hex()}
    try:
        json.dumps(v)
        return v
    except (TypeError, ValueError):
        return str(v)


def _backup_reg_value(root_name, subkey, value_name, qdir):
    """备份注册表值。返回 (True, 文件名) / (False, None)=已不存在 / 抛异常=备份失败。"""
    import winreg
    try:
        with winreg.OpenKey(_winroot(root_name), subkey, 0, winreg.KEY_READ) as key:
            data, vtype = winreg.QueryValueEx(key, value_name)
    except FileNotFoundError:
        return (False, None)  # 值已不存在，视为已清理
    payload = {"root": root_name, "subkey": subkey, "value_name": value_name,
               "type": vtype, "data": _safe_json_value(data)}
    fname = "reg_value_%s.json" % uuid.uuid4().hex[:8]
    with open(os.path.join(qdir, fname), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, default=str)
    return (True, fname)


def _backup_reg_key(root_name, subkey, qdir):
    """递归备份注册表键。返回 (True, 文件名) / (False, None)=已不存在 / 抛异常=备份失败。"""
    import winreg

    def walk(key_path, depth=0):
        if depth > 12:
            raise RuntimeError("注册表键过深，中止备份")
        node = {}
        try:
            with winreg.OpenKey(_winroot(root_name), key_path, 0, winreg.KEY_READ) as key:
                vals, i = {}, 0
                while True:
                    try:
                        vname, vdata, vtype = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    vals[vname] = {"type": vtype, "data": _safe_json_value(vdata)}
                    i += 1
                node["values"] = vals
                subs, i = {}, 0
                while True:
                    try:
                        sname = winreg.EnumKey(key, i)
                    except OSError:
                        break
                    subs[sname] = walk(key_path + "\\" + sname, depth + 1)
                    i += 1
                node["subkeys"] = subs
        except OSError:
            return None
        return node

    tree = walk(subkey)
    if tree is None:
        return (False, None)
    payload = {"root": root_name, "subkey": subkey, "tree": tree}
    fname = "reg_key_%s.json" % uuid.uuid4().hex[:8]
    with open(os.path.join(qdir, fname), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, default=str)
    return (True, fname)


def _delete_reg_key_recursive(root_name, subkey):
    import winreg
    if not subkey:
        return False  # 拒绝删根键
    try:
        with winreg.OpenKey(_winroot(root_name), subkey, 0, winreg.KEY_ALL_ACCESS) as key:
            while True:
                try:
                    sname = winreg.EnumKey(key, 0)
                except OSError:
                    break
                _delete_reg_key_recursive(root_name, subkey + "\\" + sname)
        winreg.DeleteKey(_winroot(root_name), subkey)
        return True
    except FileNotFoundError:
        return True  # 已不存在
    except Exception as e:
        logger.record_err("screen.cleanup.delkey", e)
        return False


def _quarantine_fs(path, qroot, manifest):
    p = os.path.abspath(path)
    if _is_protected_fs_path(p):
        return False  # 系统/项目目录拒绝搬移
    base = os.path.basename(p)
    if not base:
        return False  # 盘符根/空 basename 拒绝
    if not os.path.exists(p):
        return True  # 已不存在，视为已清理
    is_dir = os.path.isdir(p)
    dest = os.path.join(qroot, base)
    if os.path.exists(dest):
        dest = dest + "_" + uuid.uuid4().hex[:6]
    shutil.move(p, dest)
    manifest.append({"type": "dir" if is_dir else "file", "target": p, "backup": dest})
    return True


def _cleanup_reg_value(target, qroot, manifest):
    import winreg
    parsed = _parse_reg_target(target)
    if not parsed:
        return False
    root_name, subkey, value_name = parsed
    if not value_name:
        return False
    try:
        backed, fname = _backup_reg_value(root_name, subkey, value_name, qroot)
    except Exception as e:
        logger.record_err("screen.cleanup.backup.regval", e)
        return False  # 备份失败，不删除
    if backed is False:
        return True  # 目标已不存在，视为已清理
    # 备份已生成，先记 manifest（即使删除失败，备份仍可恢复）
    manifest.append({"type": "registry_value", "target": target,
                     "backup": os.path.join(qroot, fname)})
    try:
        with winreg.OpenKey(_winroot(root_name), subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, value_name)
        return True
    except FileNotFoundError:
        return True  # 已不存在
    except Exception as e:
        logger.record_err("screen.cleanup.delval", e)
        return False


def _cleanup_reg_key(target, qroot, manifest):
    parsed = _parse_reg_target(target)
    if not parsed:
        return False
    root_name, subkey, value_name = parsed
    if value_name or not subkey:
        return False  # 值目标或根键，均不按键删除处理
    try:
        backed, fname = _backup_reg_key(root_name, subkey, qroot)
    except Exception as e:
        logger.record_err("screen.cleanup.backup.regkey", e)
        return False  # 备份失败，不删除
    if backed is False:
        return True  # 目标已不存在，视为已清理
    # 备份已生成，先记 manifest（即使删除部分失败，备份仍可恢复）
    manifest.append({"type": "registry_key", "target": target,
                     "backup": os.path.join(qroot, fname)})
    return _delete_reg_key_recursive(root_name, subkey)


def _classify_clean(it):
    """判定单个项可否清理。返回 (True, "") 或 (False, 拒绝原因)。预览与清理共用。"""
    from modules import privacy_guard
    if not isinstance(it, dict):
        return (False, "非法项类型")
    target = (it.get("target") or it.get("path") or "").strip()
    itype = it.get("type", "")
    if privacy_guard.match_sensitive(target):
        return (False, "系统身份/敏感项")
    if itype in ("file", "dir") and _is_protected_fs_path(target):
        return (False, "系统/项目目录")
    if itype.startswith("registry"):
        parsed = _parse_reg_target(target)
        if not parsed:
            return (False, "注册表目标解析失败")
        if parsed[0] not in _CLEANABLE_ROOTS:
            return (False, "HKCR/HKU 合并视图")
        full = privacy_guard._normalize_registry(parsed[0] + "\\" + parsed[1])
        if any(full.startswith(p) for p in privacy_guard._REGISTRY_DENY) or \
                any(seg in full for seg in privacy_guard._REGISTRY_DENY_SEGMENTS):
            return (False, "共享/系统核心范围")
        if itype == "registry_value" and not parsed[2]:
            return (False, "注册表值缺少值名")
        if itype == "registry_key" and not parsed[1]:
            return (False, "拒绝清理注册表根键")
    if itype == "uninstall_entry":
        return (False, "卸载条目（非残留，仅参考）")
    if itype not in ("file", "dir", "registry_value", "registry_key"):
        return (False, "未知类型")
    return (True, "")


def preview_cleanup(items):
    """清理前预览（纯只读）：列出将清理 / 将拒绝的项，不执行、不建还原点。"""
    items = items or []
    will_clean, will_deny = [], []
    for it in items:
        target = (it.get("target") or it.get("path") or "").strip() if isinstance(it, dict) else ""
        name = it.get("name", "") if isinstance(it, dict) else ""
        itype = it.get("type", "") if isinstance(it, dict) else ""
        can, reason = _classify_clean(it)
        if can:
            will_clean.append({"target": target, "name": name, "type": itype,
                               "risk": it.get("risk", "")})
        else:
            will_deny.append({"target": target, "name": name, "reason": reason})
    return {"will_clean": will_clean, "will_deny": will_deny,
            "clean_count": len(will_clean), "deny_count": len(will_deny)}


def cleanup_traces(items, reason=""):
    """批量清理留样项。强制先创建系统还原点，逐项备份后清理，写 manifest。"""
    items = items or []
    if not items:
        return {"ok": False, "error": "没有勾选要清理的项"}
    reason = (reason or "").strip()
    if len(reason) < 12:
        return {"ok": False, "error": "必须说明至少 12 字的清理原因（目的、对象、必要性）"}

    if not _cleanup_lock.acquire(blocking=False):
        return {"ok": False, "error": "已有清理进行中，请稍后再试"}

    try:
        from modules import privacy_guard
        # 1) 强制系统还原点（硬门禁，失败即中止，绝不裸删）
        try:
            restore = privacy_guard._create_restore_point()
        except Exception as e:
            logger.record_err("screen.cleanup.restore", e)
            return {"ok": False, "error": "系统还原点创建失败，已中止清理: %s" % e}

        # 2) 逐项清理
        qroot = os.path.join(config.ROOT, "backups", "quarantine",
                             time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6])
        os.makedirs(qroot, exist_ok=True)
        manifest, results, denied = [], [], []
        for it in items:
            if not isinstance(it, dict):
                results.append({"target": "", "ok": False, "error": "非法项类型"})
                continue
            target = (it.get("target") or it.get("path") or "").strip()
            itype = it.get("type", "")
            name = it.get("name", "")
            can, reason2 = _classify_clean(it)
            if not can:
                denied.append({"target": target, "name": name, "reason": reason2})
                results.append({"target": target, "ok": False, "error": reason2 + "，已跳过"})
                continue
            try:
                if itype in ("file", "dir"):
                    ok = _quarantine_fs(target, qroot, manifest)
                elif itype == "registry_value":
                    ok = _cleanup_reg_value(target, qroot, manifest)
                elif itype == "registry_key":
                    ok = _cleanup_reg_key(target, qroot, manifest)
                else:
                    ok = False
                if ok:
                    error = None
                elif itype in ("file", "dir"):
                    # _quarantine_fs 拒绝系统/项目目录、盘符根等，消息如实说明
                    error = "清理失败（目标受保护或无法搬移）"
                else:
                    error = "清理失败（未知类型 %s）" % itype
                results.append({"target": target, "ok": ok, "error": error})
            except Exception as e:
                logger.record_err("screen.cleanup.item", e)
                results.append({"target": target, "ok": False, "error": str(e)})

        # 3) 写 manifest（供一键恢复）
        manifest_payload = {"created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "reason": reason, "items": manifest}
        with open(os.path.join(qroot, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest_payload, f, ensure_ascii=False, default=str)

        ok_count = sum(1 for r in results if r.get("ok"))
        db.audit("screen.cleanup", "items=%d ok=%d denied=%d reason=%s" % (
            len(items), ok_count, len(denied), reason[:120]))
        return {"ok": True, "restore_point": restore, "total": len(items),
                "ok_count": ok_count, "denied": denied, "results": results,
                "quarantine": qroot, "manifest": manifest_payload}
    finally:
        _cleanup_lock.release()


# ---------------- 一键恢复 ----------------
def _from_json_value(v):
    if isinstance(v, dict) and "__bytes_hex__" in v:
        return bytes.fromhex(v["__bytes_hex__"])
    return v


def _restore_guard(root_name, subkey):
    """恢复注册表前的安全校验：仅允许 HKLM/HKCU 且非 deny 范围。"""
    from modules import privacy_guard
    root_name = str(root_name or "").upper()
    subkey = str(subkey or "").lstrip("\\")
    if root_name not in _CLEANABLE_ROOTS or not subkey:
        return False
    full = privacy_guard._normalize_registry(root_name + "\\" + subkey)
    if any(full.startswith(p) for p in privacy_guard._REGISTRY_DENY) or \
            any(seg in full for seg in privacy_guard._REGISTRY_DENY_SEGMENTS) or \
            privacy_guard.match_sensitive(full):
        return False
    return True


def _restore_fs(target, backup):
    if not os.path.exists(backup):
        return False
    if _is_protected_fs_path(target):
        return False  # 拒绝恢复到系统/项目目录
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    if os.path.exists(target):
        target = target + "_restored_" + uuid.uuid4().hex[:6]
    shutil.move(backup, target)
    return True


def _restore_reg_value(target, backup):
    import winreg
    if not os.path.isfile(backup):
        return False
    with open(backup, "r", encoding="utf-8") as f:
        payload = json.load(f)
    root_name, subkey = payload["root"], payload["subkey"]
    if not _restore_guard(root_name, subkey):
        return False  # 越界拒绝
    value_name, vtype = payload["value_name"], payload["type"]
    data = _from_json_value(payload["data"])
    with winreg.CreateKeyEx(_winroot(root_name), subkey, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, value_name, 0, vtype, data)
    return True


def _restore_reg_key(target, backup):
    import winreg
    if not os.path.isfile(backup):
        return False
    with open(backup, "r", encoding="utf-8") as f:
        payload = json.load(f)
    root_name, subkey, tree = payload["root"], payload["subkey"], payload["tree"]
    if not _restore_guard(root_name, subkey):
        return False  # 越界拒绝

    def create(key_path, node, depth=0):
        if depth > 12:
            raise RuntimeError("恢复键过深，中止")
        with winreg.CreateKeyEx(_winroot(root_name), key_path, 0, winreg.KEY_SET_VALUE):
            pass
        for vname, vinfo in (node.get("values") or {}).items():
            with winreg.OpenKey(_winroot(root_name), key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, vname, 0, vinfo["type"], _from_json_value(vinfo["data"]))
        for sname, snode in (node.get("subkeys") or {}).items():
            create(key_path + "\\" + sname, snode, depth + 1)

    create(subkey, tree)
    return True


def restore_traces(quarantine_dir):
    """从 quarantine 一键还原被清理的项（依据 manifest.json）。"""
    if not _cleanup_lock.acquire(blocking=False):
        return {"ok": False, "error": "已有清理/恢复进行中，请稍后再试"}
    try:
        qdir = os.path.normcase(os.path.realpath(os.path.abspath(quarantine_dir)))
        qbase = os.path.normcase(os.path.realpath(os.path.abspath(
            os.path.join(config.ROOT, "backups", "quarantine"))))
        if not (qdir == qbase or qdir.startswith(qbase + "\\")):
            return {"ok": False, "error": "仅允许还原 backups/quarantine 内的备份目录"}
        manifest_path = os.path.join(qdir, "manifest.json")
        if not os.path.isfile(manifest_path):
            return {"ok": False, "error": "该目录无 manifest.json，无法还原"}
        with open(manifest_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        entries = payload.get("items", [])
        results = []
        for e in entries:
            if not isinstance(e, dict):
                results.append({"target": "", "ok": False, "error": "非法项"})
                continue
            etype = e.get("type", "")
            target = e.get("target", "")
            backup = e.get("backup", "")
            # 备份文件必须位于 qdir 内（realpath 防符号链接逃逸）
            if not backup:
                results.append({"target": target, "ok": False, "error": "备份路径缺失"})
                continue
            backup_real = os.path.normcase(os.path.realpath(os.path.abspath(backup)))
            if not backup_real.startswith(qdir + "\\"):
                results.append({"target": target, "ok": False, "error": "备份路径越界，已跳过"})
                continue
            try:
                if etype in ("file", "dir"):
                    ok = _restore_fs(target, backup)
                elif etype == "registry_value":
                    ok = _restore_reg_value(target, backup)
                elif etype == "registry_key":
                    ok = _restore_reg_key(target, backup)
                else:
                    ok = False
                results.append({"target": target, "ok": ok})
            except Exception as ex:
                logger.record_err("screen.restore.item", ex)
                results.append({"target": target, "ok": False, "error": str(ex)})
        ok_count = sum(1 for r in results if r.get("ok"))
        db.audit("screen.restore", "qdir=%s ok=%d/%d" % (qdir, ok_count, len(entries)))
        return {"ok": True, "ok_count": ok_count, "total": len(entries), "results": results}
    finally:
        _cleanup_lock.release()
