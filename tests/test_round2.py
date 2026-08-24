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
        # 基线有 → 用户删除 → 软件以相同内容写回（当前快照又有，但基线已无）
        # 模拟时序：baseline 为"删除后"的空态，history 记住删除前的哈希
        hist = {self.P: {"sha16": "aaa", "size": 10}}
        cur = {self.P: {"sha16": "aaa", "size": 10}}
        rows = {r["path"]: r["status"] for r in classify_paths({}, hist, cur)}
        self.assertEqual(rows[self.P], "recreated_same_value")

        hist2 = {self.P: {"sha16": "old", "size": 9}}
        rows = {r["path"]: r["status"] for r in classify_paths({}, hist2, cur)}
        self.assertEqual(rows[self.P], "regenerated_new_value")

    def test_new_path(self):
        rows = {r["path"]: r["status"]
                for r in classify_paths({}, {}, {self.P: {"sha16": "x", "size": 1}})}
        self.assertEqual(rows[self.P], "new")


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
