"""modules 层测试：embedding / decompile / screener 基元与格式逆向 / browser WS。"""
import base64
import os
import tempfile
import unittest
import uuid
from unittest import mock

from core import logger
from modules import embedding, regscan
from modules.browser import ws_accept_key
from modules.decompile import analyze, detect_kind
from modules.screener import cleanup as scr_cleanup
from modules.screener.common import (
    _extract_exe, _is_protected_fs_path, _risk_label, json_d)
from modules.screener.fmt_reverse import _parse_leaf, _walk_json


class EmbeddingTest(unittest.TestCase):
    def tearDown(self):
        embedding._index = None

    def test_local_index_search_and_dump(self):
        idx = embedding.LocalIndex(dim=64)
        idx.add("registry autorun key suspicious", {"src": "a"})
        idx.add("network packet capture baseline", {})
        res = idx.search("autorun registry", top_k=1)
        self.assertEqual(res[0]["text"], "registry autorun key suspicious")
        idx2 = embedding.LocalIndex(dim=64)
        idx2.load(idx.dump())
        self.assertEqual(idx2.size(), 2)
        hit = idx2.search("packet capture", top_k=1)[0]["text"]
        self.assertIn("network", hit)

    def test_load_skips_non_string_docs(self):
        idx = embedding.LocalIndex()
        idx.load({"dim": 32, "docs": [{"text": 123}, {"meta": {}},
                                      {"text": "valid text here", "meta": {}}]})
        self.assertEqual(idx.size(), 1)

    def test_missing_index_file_is_silent(self):
        # 回归：首跑缺索引文件曾被记入 Err.log 造成启动误报
        embedding._index = None
        missing = os.path.join(tempfile.gettempdir(), "no_such_index_xyz.json")
        with mock.patch.object(embedding, "INDEX_FILE", missing):
            stats = embedding.stats()
            self.assertEqual(stats["docs"], 0)


class DecompileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write(self, name, data, mode="w"):
        p = os.path.join(self.tmp.name, name)
        if mode == "wb":
            with open(p, mode) as f:
                f.write(data)
        else:
            with open(p, mode, encoding="utf-8") as f:
                f.write(data)
        return p

    def test_python_danger_calls(self):
        src = ("import os\n"
               "eval('1+1')\n"
               "os.system('calc')\n"
               "url = 'https://evil.example.com/c2'\n")
        r = analyze(self._write("t.py", src))
        self.assertEqual(r["kind"], "python")
        names = [c["name"] for c in r["calls"]]
        self.assertIn("eval", names)
        self.assertIn("os.system", names)
        self.assertTrue(r["suspicious"])
        self.assertGreaterEqual(r["score"]["high"], 2)

    def test_pe_guard_and_kind_detect(self):
        fake = self._write("fake.exe", b"MZ" + b"\x00" * 64, "wb")
        r = analyze(fake)
        self.assertEqual(r["kind"], "pe")
        self.assertIn("error", r["info"])  # 无 PE 签名 → 报错而非崩溃
        junk = self._write("junk.bin", b"\x00\x01\x02", "wb")
        self.assertIsNone(detect_kind(junk))

    def test_oversize_refused(self):
        p = self._write("big.py", "x=1\n")
        with mock.patch("modules.decompile.common.MAX_FILE_SIZE", 4):
            r = analyze(p)
        self.assertIn("error", r["info"])  # 超上限拒绝（缩小阈值避免造大文件）


class ScreenerCommonTest(unittest.TestCase):
    def test_risk_labels(self):
        self.assertEqual(_risk_label(0.9), "高")
        self.assertEqual(_risk_label(0.5), "中")
        self.assertEqual(_risk_label(0.3), "低")
        self.assertEqual(_risk_label(0.1), "无")

    def test_extract_exe(self):
        quoted = '"C:' + chr(92) + 'a b' + chr(92) + 'x.exe" -flag'
        self.assertEqual(_extract_exe(quoted),
                         "C:" + chr(92) + "a b" + chr(92) + "x.exe")
        self.assertEqual(_extract_exe("no path here"), "")
        self.assertEqual(_extract_exe(None), "")

    def test_protected_paths(self):
        win = chr(92)
        self.assertTrue(
            _is_protected_fs_path("C:" + win + "Windows" + win + "System32"))
        self.assertFalse(
            _is_protected_fs_path("C:" + win + "some" + win + "user"))

    def test_json_d_never_raises(self):
        self.assertIn("x", json_d({"x": 1}))


class CleanupClassifyTest(unittest.TestCase):
    """清理分类的拒绝路径——安全关键，必须可回归。"""

    def test_uninstall_entry_denied(self):
        can, why = scr_cleanup._classify_clean(
            {"type": "uninstall_entry", "target": "HKLM" + chr(92) + "X"})
        self.assertFalse(can)
        self.assertIn("卸载条目", why)

    def test_hkcr_hku_denied(self):
        w = chr(92)
        for root in ("HKCR", "HKU"):
            target = root + w + "Software" + w + "Foo|Bar"
            parsed = scr_cleanup._parse_reg_target(target)
            self.assertIsNotNone(parsed, target + " 应可解析")
            can, why = scr_cleanup._classify_clean(
                {"type": "registry_value", "target": target})
            self.assertFalse(can, target + " 必须拒绝清理")
            self.assertIn("合并视图", why)

    def test_root_key_deletion_denied(self):
        can, why = scr_cleanup._classify_clean(
            {"type": "registry_key", "target": "HKCU" + chr(92)})
        self.assertFalse(can)
        self.assertIn("根键", why)

    def test_unknown_type_denied(self):
        can, _why = scr_cleanup._classify_clean(
            {"type": "mystery", "target": "whatever"})
        self.assertFalse(can)

    def test_preview_partition(self):
        tmpdir = tempfile.gettempdir()  # 非保护目录 → 可清理
        items = [{"type": "uninstall_entry", "target": "HKLM" + chr(92) + "A"},
                 {"type": "dir", "target": tmpdir}]
        out = scr_cleanup.preview_cleanup(items)
        self.assertEqual(out["clean_count"], 1)
        self.assertEqual(out["deny_count"], 1)


class FmtReverseTest(unittest.TestCase):
    def test_leaf_kinds(self):
        cases = {
            str(uuid.uuid4()): "uuid",
            "a" * 32: "hex32",
            "ab" * 32: "hex64",
            uuid.uuid4().hex: "hex32",
            "1234567890": "unix_timestamp",
            "hello world": "string",
            "": "string_empty",
        }
        for val, kind in cases.items():
            self.assertEqual(_parse_leaf(val)[0], kind,
                             "%r => %s" % (val, _parse_leaf(val)[0]))
        blob = base64.b64encode(
            b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf" + b"\x00" * 16).decode()
        self.assertEqual(_parse_leaf(blob)[0], "dpapi_blob")
        self.assertIsNone(_parse_leaf(blob)[2])  # 不可伪造 → 无替换值

    def test_walk_json_collects_identity_fields(self):
        obj = {"machineId": str(uuid.uuid4()),
               "createdAt": 1700000000,
               "nested": {"deviceId": "b" * 32}}
        out = []
        _walk_json(obj, out)
        fields = {e["field"]: e for e in out}
        self.assertIn("$.machineId", fields)
        self.assertIn("$.nested.deviceId", fields)
        self.assertTrue(fields["$.machineId"]["identity_hint"])
        self.assertEqual(fields["$.nested.deviceId"]["kind"], "hex32")

    def test_analyze_rejects_missing(self):
        from modules.screener.fmt_reverse import analyze_fingerprint_format
        r = analyze_fingerprint_format(r"C:\definitely\nope.bin")
        self.assertFalse(r["ok"])


class RegscanDiffTest(unittest.TestCase):
    def test_diff_watches_pure_logic(self):
        before = {"HKCU" + chr(92) + "K": {"v1": "aaa", "gone": "bbb"}}
        after = {"HKCU" + chr(92) + "K": {"v1": "changed", "new2": "ccc"},
                 "HKCU" + chr(92) + "NewKey": {"n": "d"}}
        diffs = regscan.diff_watches(before, after)
        pairs = {(d["key"], d["name"]) for d in diffs}
        self.assertIn(("HKCU" + chr(92) + "K", "v1"), pairs)      # 变更
        self.assertIn(("HKCU" + chr(92) + "K", "gone"), pairs)    # 删除
        self.assertIn(("HKCU" + chr(92) + "K", "new2"), pairs)    # 新增
        self.assertIn(("HKCU" + chr(92) + "NewKey", "(新键)"), pairs)


class BrowserWSTest(unittest.TestCase):
    def test_accept_key_rfc6455_vector(self):
        # RFC 6455 §1.3 官方测试向量
        self.assertEqual(ws_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
                         "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")


if __name__ == "__main__":
    logger.clear_err()
    unittest.main()
