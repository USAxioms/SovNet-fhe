import hashlib
import json
import os
import tempfile
import unittest

import sovereign_node as S

ZERO = "0x" + "0" * 64


def canon_hash(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


class TestSovereignNode(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        os.remove(self.path)
        self.addCleanup(lambda: os.path.exists(self.path) and os.remove(self.path))

    def test_result_type(self):
        self.assertEqual(S.Res.__name__, "Res")
        self.assertEqual(S.Res._fields, ("ok", "value", "reason"))
        d = S.SovereignNodeDaemon(1, self.path)
        self.assertTrue(repr(d.step_refinement_loop({}, 1)).startswith("Res(ok=True, value='"))

    def test_constants_and_constructor_state(self):
        self.assertEqual(S.ZERO_HASH, ZERO)
        d = S.SovereignNodeDaemon(7, self.path)
        self.assertEqual((d.node_id, d.ledger_path, d.current_state_hash), (7, self.path, ZERO))
        self.assertEqual(len(ZERO), 66)

    def test_state_hash_is_sha256_of_sorted_canonical_json(self):
        d = S.SovereignNodeDaemon(1, self.path)
        p = {"b": 2, "a": {"z": 1, "y": [3, 4]}}
        h = d.compute_wad18_state_hash(p)
        self.assertEqual(h, canon_hash(p))
        self.assertEqual(len(h), 64)
        self.assertFalse(h.startswith("0x"))
        self.assertEqual(h, d.compute_wad18_state_hash({"a": {"y": [3, 4], "z": 1}, "b": 2}))
        self.assertNotEqual(h, d.compute_wad18_state_hash({"a": {"y": [3, 5], "z": 1}, "b": 2}))
        self.assertEqual(d.current_state_hash, ZERO)
        self.assertFalse(os.path.exists(self.path))

    def test_step_commits_payload_and_chains_hashes(self):
        d = S.SovereignNodeDaemon(3, self.path)
        r1 = d.step_refinement_loop({"v": 1, "w": 2}, 1700000000)
        r2 = d.step_refinement_loop({"v": 5}, 1700000000)
        p1 = {"node_id": 3, "timestamp": 1700000000, "inputs": {"v": 1, "w": 2}, "prev_hash": ZERO}
        p2 = {"node_id": 3, "timestamp": 1700000000, "inputs": {"v": 5}, "prev_hash": r1.value}
        self.assertEqual((r1.ok, r1.reason, r1.value), (True, "", canon_hash(p1)))
        self.assertEqual((r2.ok, r2.reason, r2.value), (True, "", canon_hash(p2)))
        self.assertNotEqual(r1.value, r2.value)
        self.assertEqual(d.current_state_hash, r2.value)
        with open(self.path) as fh:
            raw = fh.read()
        self.assertTrue(raw.endswith("\n"))
        lines = raw.split("\n")[:-1]
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0]), {"hash": r1.value, "payload": p1})
        self.assertEqual(json.loads(lines[1]), {"hash": r2.value, "payload": p2})

    def test_reproducible_bit_for_bit(self):
        a, b = S.SovereignNodeDaemon(1, self.path), S.SovereignNodeDaemon(1, self.path + ".2")
        self.addCleanup(lambda: os.path.exists(self.path + ".2") and os.remove(self.path + ".2"))
        for ts, vec in ((100, {"k": 1}), (101, {"k": 2, "j": -3}), (101, {})):
            self.assertEqual(a.step_refinement_loop(vec, ts), b.step_refinement_loop(vec, ts))
        self.assertEqual(a.current_state_hash, b.current_state_hash)
        self.assertNotEqual(S.SovereignNodeDaemon(1, self.path + ".3").step_refinement_loop({"k": 1}, 100).value,
                            S.SovereignNodeDaemon(1, self.path + ".3").step_refinement_loop({"k": 1}, 101).value)
        self.addCleanup(lambda: os.path.exists(self.path + ".3") and os.remove(self.path + ".3"))

    def test_timestamp_boundaries_and_type(self):
        d = S.SovereignNodeDaemon(1, self.path)
        self.assertTrue(d.step_refinement_loop({}, 0).ok)
        for bad in (-1, "5", True, None, b"5"):
            r = d.step_refinement_loop({}, bad)
            self.assertEqual((r.ok, r.value, r.reason), (False, None, "BAD_TIMESTAMP"), bad)
        with open(self.path) as fh:
            self.assertEqual(len(fh.readlines()), 1)

    def test_input_validation(self):
        d = S.SovereignNodeDaemon(1, self.path)
        for bad in ([("a", 1)], "x", None, 5):
            r = d.step_refinement_loop(bad, 1)
            self.assertEqual((r.ok, r.value, r.reason), (False, None, "BAD_INPUTS"), bad)
        for bad in ({"a": "1"}, {"a": True}, {"a": None}, {1: 2}, {"a": [1]}, {"ok": 1, "a": {"b": 1}}):
            r = d.step_refinement_loop(bad, 1)
            self.assertEqual((r.ok, r.value, r.reason), (False, None, "NON_INTEGER_INPUT"), bad)
        self.assertEqual(d.current_state_hash, ZERO)
        self.assertFalse(os.path.exists(self.path))
        self.assertTrue(d.step_refinement_loop({"neg": -5, "big": 10 ** 30}, 1).ok)

    def test_io_failure_is_returned_and_chain_head_is_unchanged(self):
        d = S.SovereignNodeDaemon(1, self.path)
        first = d.step_refinement_loop({"a": 1}, 1)
        broken = S.SovereignNodeDaemon(1, os.path.dirname(self.path))        # a directory: open() fails
        r = broken.step_refinement_loop({"a": 1}, 1)
        self.assertEqual((r.ok, r.value, r.reason), (False, None, "LEDGER_WRITE_FAILED"))
        self.assertEqual(broken.current_state_hash, ZERO)
        self.assertEqual(d.current_state_hash, first.value)

    def test_appends_to_existing_file(self):
        with open(self.path, "w") as fh:
            fh.write("old line\n")
        S.SovereignNodeDaemon(1, self.path).step_refinement_loop({"a": 1}, 1)
        with open(self.path) as fh:
            lines = fh.read().split("\n")
        self.assertEqual(lines[0], "old line")
        self.assertEqual(len(lines), 3)

    def test_two_daemons_same_input_differ_by_node_id(self):
        a, b = S.SovereignNodeDaemon(1, self.path), S.SovereignNodeDaemon(2, self.path)
        self.assertNotEqual(a.step_refinement_loop({"k": 1}, 100).value, b.step_refinement_loop({"k": 1}, 100).value)

    def test_module_has_no_clock_or_entropy_imports(self):
        for name in ("time", "secrets", "random"):
            self.assertFalse(hasattr(S, name), name)


if __name__ == "__main__":
    unittest.main()
