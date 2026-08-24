"""core 层测试：coerce / config / db 包（hunt_store、tracking_store、audit 链）。"""
import json
import os
import tempfile
import unittest
from unittest import mock

from core import audit as core_audit
from core import config, db, logger
from core.coerce import as_bool, parse_bool, strict_bool
from core.db import connection as db_conn


class CoerceTest(unittest.TestCase):
    def test_parse_bool_matrix(self):
        self.assertIs(parse_bool(True), True)
        self.assertIs(parse_bool(False), False)
        self.assertIs(parse_bool("TRUE"), True)
        self.assertIs(parse_bool(" on "), True)
        self.assertIs(parse_bool("0"), False)
        self.assertIs(parse_bool("no"), False)
        self.assertIs(parse_bool(""), False)
        self.assertIsNone(parse_bool("maybe"))
        self.assertIsNone(parse_bool(None))
        self.assertIs(parse_bool(1.0), True)

    def test_as_bool_default(self):
        self.assertFalse(as_bool("junk"))
        self.assertTrue(as_bool("junk", True))
        self.assertIs(as_bool("yes"), True)

    def test_strict_bool_raises(self):
        with self.assertRaises(ValueError):
            strict_bool("perhaps")
        self.assertIs(strict_bool("off"), False)


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "config.json")
        patcher = mock.patch.object(config, "CONFIG_PATH", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        config._cfg = None

    def tearDown(self):
        config._cfg = None

    def test_defaults_when_missing(self):
        cfg = config.load()
        for key in ("pcap", "regscan", "ui", "screener"):
            self.assertIn(key, cfg["switches"])
            self.assertTrue(cfg["switches"][key])

    def test_string_false_not_truthy(self):
        # FreqErr 蠕虫：bool("false") == True 曾把关闭误判为开启
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"switches": {"pcap": "false"}}, f)
        cfg = config.load()
        self.assertIs(cfg["switches"]["pcap"], False)

    def test_update_section_merges_and_persists(self):
        config.load()
        config.update_section("browser", {"ws_port": 9999, "token": "abc"})
        sec = config.section("browser")
        self.assertEqual(sec["ws_port"], 9999)
        self.assertEqual(sec["token"], "abc")
        # 落盘校验
        with open(self.path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        self.assertEqual(raw["browser"]["ws_port"], 9999)

    def test_update_section_switch_whitelist(self):
        config.load()
        out = config.update_section("switches", {"pcap": "false",
                                                 "bogus_key": True})
        self.assertIs(out["pcap"], False)
        self.assertNotIn("bogus_key", out)

    def test_set_switches_roundtrip(self):
        config.load()
        config.set_switches(embedding=False)
        self.assertFalse(config.enabled("embedding"))


class DbTest(unittest.TestCase):
    """DB 全套走临时库，绝不碰真实 retrace.db。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dbfile = os.path.join(self.tmp.name, "test_retrace.db")
        patcher = mock.patch.object(db_conn, "DB_PATH", self.dbfile)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        db.init()

    def test_observation_roundtrip(self):
        oid = db.add_observation(title="t", evidence=["a", "b"], risk="高")
        obs = db.get_observation(oid)
        self.assertEqual(obs["evidence"], ["a", "b"])
        db.update_observation(oid, status="marked", conclusion="ok")
        self.assertEqual(db.get_observation(oid)["status"], "marked")
        self.assertTrue(db.delete_observation(oid))
        self.assertFalse(db.delete_observation(oid))  # 幂等删除语义
        with self.assertRaises(ValueError):
            db.delete_observation(0)
        with self.assertRaises(ValueError):
            db.delete_observation(-5)

    def test_knowledge_weight_clamped(self):
        kid = db.add_knowledge("cat", "title", "pat")
        self.assertTrue(db.set_knowledge_weight(kid, 1.7))
        row = [r for r in db.list_knowledge() if r["id"] == kid][0]
        self.assertEqual(row["risk_weight"], 1.0)
        self.assertTrue(db.set_knowledge_enabled(kid, False))
        self.assertEqual([r for r in db.list_knowledge(enabled_only=True)
                          if r["id"] == kid], [])
        with self.assertRaises(ValueError):
            db.set_knowledge_weight(kid, "bad")

    def test_tracking_batch_pause_race(self):
        tid = db.create_tracking_task("t")
        run = db.start_task_run(tid)
        # 任务未启用 → 批次必须被拒
        self.assertFalse(db.commit_tracking_batch(
            tid, run, [{"type": "e", "fingerprint": "f1"}], {}, 5))
        db.update_tracking_task(tid, enabled=True, status="running")
        run2 = db.start_task_run(tid)
        self.assertTrue(db.commit_tracking_batch(
            tid, run2,
            [{"type": "e", "fingerprint": "f1", "data": {"pid": 1}},
             {"type": "e", "fingerprint": "f1", "data": {"pid": 2}}], {"c": 1}, 5))
        events = db.tracking_events(tid)
        self.assertEqual(len(events), 1)          # 指纹去重合并
        self.assertGreaterEqual(events[0]["count"], 2)
        task = db.get_tracking_task(tid)
        self.assertEqual(task["checkpoint"], {"c": 1})
        self.assertEqual(task["status"], "running")

    def test_delete_task_cascades(self):
        tid = db.create_tracking_task("t2")
        db.update_tracking_task(tid, enabled=True, status="running")
        run = db.start_task_run(tid)
        db.commit_tracking_batch(
            tid, run, [{"type": "e", "fingerprint": "x"}], {}, 5)
        self.assertTrue(db.delete_tracking_task(tid))
        self.assertEqual(db.count_tracking_events(tid), 0)
        self.assertEqual(db.task_runs(tid), [])

    def test_daemon_lease_lifecycle(self):
        self.assertTrue(db.acquire_daemon_lease("tracking", "ownerA"))
        self.assertFalse(db.acquire_daemon_lease("tracking", "ownerB"))
        self.assertTrue(db.refresh_daemon_lease("tracking", "ownerA"))
        self.assertFalse(db.refresh_daemon_lease("tracking", "ownerB"))
        db.release_daemon_lease("tracking", "ownerA")
        self.assertTrue(db.acquire_daemon_lease("tracking", "ownerB"))

    def test_audit_chain_and_redaction(self):
        rid = core_audit.record("t.op", {"api_key": "sk-secret-xyz",
                                         "note": "hello"}, actor="tester")
        rows = core_audit.list_entries(10)
        target = [r for r in rows if r["request_id"] == rid][0]
        self.assertNotIn("sk-secret-xyz", target["detail"])
        self.assertIn("REDACTED", target["detail"])
        v = core_audit.verify()
        self.assertTrue(v["ok"])
        self.assertFalse(v["legacy_unchained"])

    def test_audit_bearer_and_kv_redaction(self):
        rid = core_audit.record("t.op2", {"h": "Bearer abc.def.g",
                                          "line": "password=hunter2"})
        rows = {r["request_id"]: r for r in core_audit.list_entries(10)}
        detail = rows[rid]["detail"]
        self.assertNotIn("hunter2", detail)
        self.assertNotIn("abc.def.g", detail)


if __name__ == "__main__":
    logger.clear_err()
    unittest.main()
