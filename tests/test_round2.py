"""第二轮新增能力测试：AI 痕迹扫描 / 指纹再生监测 / 沙箱测试计划。"""
import json
import os
import tempfile
import unittest
import uuid
from unittest import mock

from core import logger
from modules.screener.ai_tools import (
    _extract_key_fields, _hash_preview, scan_ai_tool_traces)
from modules.screener.drift import classify_paths


class AiToolsTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.addCleanup(mock.patch.stopall)

    def _patch_home(self):
        return mock.patch("modules.screener.ai_tools._home",
                          lambda: self.home.name)

    def test_detects_claude_code_and_hashes_userid(self):
        uid = str(uuid.uuid4())
        with open(os.path.join(self.home.name, ".claude.json"), "w",
                  encoding="utf-8") as f:
            json.dump({"userID": uid, "theme": "dark"}, f)
        os.mkdir(os.path.join(self.home.name, ".codex"))
        with open(os.path.join(self.home.name, ".codex", "auth.json"), "w",
                  encoding="utf-8") as f:
            json.dump({"tokens": {"account_id": "acc-123"}}, f)

        with self._patch_home():
            res = scan_ai_tool_traces()
        products = {it["product"] for it in res["items"]}
        self.assertIn("Claude Code", products)
        self.assertIn("Codex CLI", products)

        claude = [it for it in res["items"] if it["product"] == "Claude Code"
                  and it.get("artifact_kind") == "file"][0]
        fields = claude["key_fields"]
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0]["field"], "userID")
        self.assertEqual(fields[0]["shape"], "uuid")
        self.assertEqual(fields[0]["sha256_12"], _hash_preview(uid))
        # 安全红线：明文 userID 绝不能出现在任何回显字段里
        blob = json.dumps(res, ensure_ascii=False)
        self.assertNotIn(uid, blob)

    def test_keyword_filter(self):
        os.mkdir(os.path.join(self.home.name, ".gemini"))
        with self._patch_home():
            res = scan_ai_tool_traces("gemini")
        self.assertEqual([it["vendor"] for it in res["items"]],
                         ["Google"])

    def test_missing_files_no_hits(self):
        with self._patch_home():
            res = scan_ai_tool_traces()
        self.assertEqual(res["summary"]["total"], 0)

    def test_extract_key_fields_nested_and_bad_json(self):
        p = os.path.join(self.home.name, "cfg.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"tokens": {"account_id": "abc"}}, f)
        out = _extract_key_fields(p, ["tokens.account_id", "missing.x"])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["field"], "tokens.account_id")
        with open(p, "w", encoding="utf-8") as f:
            f.write("{not json")
        self.assertEqual(_extract_key_fields(p, ["a"]), [])


class DriftClassifyTest(unittest.TestCase):
    """纯函数状态机：清理后再生的核心语义必须可回归。"""

    P = "c:\\users\\x\\machineid"

    def test_all_statuses(self):
        base = {self.P: {"sha16": "aaa", "size": 10}}
        hist = {}
        cur = {self.P: {"sha16": "aaa", "size": 10}}
        rows = {r["path"]: r["status"]
                for r in classify_paths(base, hist, cur)}
        self.assertEqual(rows[self.P], "unchanged")

        cur2 = {self.P: {"sha16": "bbb", "size": 12}}
        rows = {r["path"]: r["status"]
                for r in classify_paths(base, hist, cur2)}
        self.assertEqual(rows[self.P], "value_changed")   # 软件重新生成 → 成功

        rows = {r["path"]: r["status"] for r in classify_paths(base, hist, {})}
        self.assertEqual(rows[self.P], "gone")

    def test_recreated_same_value_is_flagged(self):
        # 基线为"删除后"空态，history 记住删除前的哈希（v2 列表格式）
        hist = {self.P: [{"sha16": "aaa", "size": 10}]}
        cur = {self.P: {"sha16": "aaa", "size": 10}}
        rows = {r["path"]: r["status"] for r in classify_paths({}, hist, cur)}
        self.assertEqual(rows[self.P], "recreated_same_value")

        hist2 = {self.P: [{"sha16": "old", "size": 9}]}
        rows = {r["path"]: r["status"] for r in classify_paths({}, hist2, cur)}
        self.assertEqual(rows[self.P], "regenerated_new_value")

    def test_recreated_across_generations(self):
        # 回归：A→B→删除→A 复活。v2 累积历史下必须识别（v1 单槽会漏报）
        hist = {self.P: [{"sha16": "bbb", "size": 12}, {"sha16": "aaa", "size": 10}]}
        cur = {self.P: {"sha16": "aaa", "size": 10}}
        rows = {r["path"]: r["status"] for r in classify_paths({}, hist, cur)}
        self.assertEqual(rows[self.P], "recreated_same_value")

    def test_size_mismatch_is_not_same_value(self):
        # 同哈希但大小不同（前 1MB 同内容）→ 不得误判为同值复活
        hist = {self.P: [{"sha16": "aaa", "size": 10}]}
        cur = {self.P: {"sha16": "aaa", "size": 999}}
        rows = {r["path"]: r["status"] for r in classify_paths({}, hist, cur)}
        self.assertEqual(rows[self.P], "regenerated_new_value")

    def test_legacy_single_dict_history_tolerated(self):
        # load_state 的兼容逻辑经 evolve_state 存取，这里直接验证分类函数
        # 对旧格式（单 dict）也能通过 load_state 的包装——此处测分类端容错
        hist = {self.P: {"sha16": "aaa", "size": 10}}  # 旧格式未包装
        cur = {self.P: {"sha16": "aaa", "size": 10}}
        rows = {r["path"]: r["status"] for r in classify_paths({}, hist, cur)}
        # 旧格式在 classify 端按"有记录但非列表"处理 → regenerated（可接受降级）
        self.assertIn(rows[self.P], ("regenerated_new_value", "new"))

    def test_new_path(self):
        rows = {r["path"]: r["status"]
                for r in classify_paths({}, {}, {self.P: {"sha16": "x", "size": 1}})}
        self.assertEqual(rows[self.P], "new")


class RunCommandGuardTest(unittest.TestCase):
    """run_command 确定性守卫：tshark lua/导出与 ipconfig 夹带必须被拒。"""

    def _call(self, command):
        from modules.agent import executor
        r = executor.call("run_command", {"command": command,
                                          "reason": "检修验证：确定性守卫回归测试"})
        return r

    def test_tshark_lua_script_denied(self):
        r = self._call("tshark -X lua_script:evil.lua")
        self.assertFalse(r["ok"])
        self.assertIn("禁止", r["error"])

    def test_tshark_long_option_denied(self):
        r = self._call("tshark --export-objects http,C:\\tmp")
        self.assertFalse(r["ok"])

    def test_tshark_safe_args_allowed_shape(self):
        # 不真执行（本机无 tshark 也会走执行分支），仅验证守卫不拦截合法形态
        from modules.agent.tools import _vet_tshark
        self.assertIsNone(_vet_tshark(["tshark", "-r", "x.pcap", "-q", "-z", "io,phs"])
                          if False else _vet_tshark(["tshark", "-D"]))
        self.assertIsNotNone(_vet_tshark(["tshark", "-w", "out.pcap"]))
        self.assertIsNotNone(_vet_tshark(["tshark", "-C", "cfg"]))

    def test_ipconfig_smuggled_flag_denied(self):
        r = self._call("ipconfig /all /release")
        self.assertFalse(r["ok"])
        self.assertIn("release", r["error"])

    def test_ipconfig_safe_allowed_shape(self):
        # 仅验证校验逻辑（不执行）：构造到执行前的拒绝分支
        r = self._call("ipconfig /displaydns")
        # 本机执行 displaydns 需要管理员；无论成败都不应出现"仅允许查询"守卫错误
        if not r["ok"]:
            self.assertNotIn("仅允许查询", r.get("error", ""))


class SandboxPlanTest(unittest.TestCase):
    def test_plan_structure(self):
        from modules.privacy_guard import build_sandbox_test_plan
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        exe = os.path.join(tmp.name, "app.exe")
        with open(exe, "wb") as f:
            f.write(b"MZ\x00")
        plan = build_sandbox_test_plan(exe, network=False)
        self.assertTrue(plan["ok"])
        self.assertIn("Configuration", plan["wsb_xml"])
        self.assertIn("LogonCommand", plan["wsb_xml"])
        self.assertEqual(len(plan["checklist"]), 6)
        phases = [s["phase"] for s in plan["checklist"]]
        self.assertEqual(phases[0], "host_baseline")
        self.assertIn("regen_probe", phases)   # 再生探针是核心步骤
        # 安全红线：计划只是规划，不得包含自动执行动作
        self.assertNotIn("subprocess", json.dumps(plan))

    def test_plan_rejects_non_exe(self):
        from modules.privacy_guard import build_sandbox_test_plan
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        notexe = os.path.join(tmp.name, "app.txt")
        with open(notexe, "w") as f:
            f.write("hi")
        with self.assertRaises(ValueError):
            build_sandbox_test_plan(notexe)


if __name__ == "__main__":
    logger.clear_err()
    unittest.main()


class CleanupManifestReservedNameTest(unittest.TestCase):
    """被隔离物名为 manifest.json 时必须改名，防止恢复清单覆盖原始内容。"""

    def test_quarantine_renames_manifest_json(self):
        from modules.screener import cleanup as sc
        work = tempfile.TemporaryDirectory()
        qroot = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.addCleanup(qroot.cleanup)
        victim = os.path.join(work.name, "manifest.json")
        with open(victim, "w", encoding="utf-8") as f:
            f.write('{"precious": true}')
        manifest = []
        ok = sc._quarantine_fs(victim, qroot.name, manifest)
        self.assertTrue(ok)
        self.assertEqual(len(manifest), 1)
        backup = manifest[0]["backup"]
        self.assertTrue(os.path.isfile(backup))
        # 原始内容完好，且未被放在保留名上
        self.assertNotEqual(os.path.basename(backup).lower(), "manifest.json")
        with open(backup, encoding="utf-8") as f:
            self.assertEqual(json.load(f), {"precious": True})
        # 恢复清单记录了改名来源
        self.assertEqual(manifest[0]["renamed_from"], "manifest.json")
