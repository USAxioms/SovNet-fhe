import hashlib
import json
import os
import shutil
import tempfile
import unittest
import zipfile

import build_capsule as BC
import verify_capsule as VC


class TestCapsuleIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="capsule_test_")
        cls.a = os.path.join(cls.tmp, "a.zip")
        cls.b = os.path.join(cls.tmp, "b.zip")
        cls.sha_a, cls.digest_a = BC.build(cls.a)
        cls.sha_b, cls.digest_b = BC.build(cls.b)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def rewrite(self, name, mutate):
        out = os.path.join(self.tmp, name)
        with zipfile.ZipFile(self.a) as src, zipfile.ZipFile(out, "w") as dst:
            members = [(i, src.read(i.filename)) for i in src.infolist()]
            for info, data in mutate(members):
                dst.writestr(info, data)
        return out

    def test_two_builds_are_byte_identical_and_digests_agree(self):
        self.assertEqual(self.sha_a, self.sha_b)
        self.assertEqual(self.digest_a, self.digest_b)
        with open(self.a, "rb") as fa, open(self.b, "rb") as fb:
            self.assertEqual(fa.read(), fb.read())
        with open(self.a, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), self.sha_a)

    def test_clean_zip_passes_and_reports_consistent_identities(self):
        ok, problems, info = VC.check_zip(self.a)
        self.assertEqual((ok, problems), (True, []))
        self.assertEqual(info["zip_sha256"], self.sha_a)
        self.assertEqual(info["capsule_digest"], self.digest_a)
        self.assertEqual(info["revision"], BC.REVISION)
        self.assertEqual(info["members"], len(BC.MEMBERS))
        with zipfile.ZipFile(self.a) as z:
            self.assertEqual(hashlib.sha256(z.read("MANIFEST.json")).hexdigest(), self.digest_a)

    def test_manifest_lists_exactly_the_declared_members_with_true_hashes(self):
        with zipfile.ZipFile(self.a) as z:
            m = json.loads(z.read("MANIFEST.json"))
            self.assertEqual(sorted(m["files"]), sorted(BC.MEMBERS))
            self.assertEqual(sorted(z.namelist()), sorted(BC.MEMBERS + ["MANIFEST.json"]))
            for n, d in m["files"].items():
                with open(os.path.join(BC.HERE, n), "rb") as fh:
                    self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), d, n)
                self.assertEqual(hashlib.sha256(z.read(n)).hexdigest(), d, n)

    def test_changed_member_is_reported(self):
        def mut(ms):
            return [(i, d + b"\n#x" if i.filename == "README.md" else d) for i, d in ms]
        ok, problems, _ = VC.check_zip(self.rewrite("chg.zip", mut))
        self.assertFalse(ok)
        self.assertEqual(problems, ["HASH MISMATCH README.md"])

    def test_missing_member_is_reported(self):
        ok, problems, _ = VC.check_zip(self.rewrite("miss.zip", lambda ms: [(i, d) for i, d in ms if i.filename != "LICENSE"]))
        self.assertFalse(ok)
        self.assertEqual(problems, ["MISSING LICENSE"])

    def test_extra_unlisted_member_is_reported(self):
        def mut(ms):
            extra = zipfile.ZipInfo("evil.py", BC.FIXED_TIME)
            return ms + [(extra, b"print(1)")]
        ok, problems, _ = VC.check_zip(self.rewrite("extra.zip", mut))
        self.assertFalse(ok)
        self.assertEqual(problems, ["UNLISTED MEMBER evil.py"])

    def test_unsafe_and_duplicate_names_are_reported(self):
        def mut(ms):
            return ms + [(zipfile.ZipInfo("../x.py", BC.FIXED_TIME), b"")]
        ok, problems, _ = VC.check_zip(self.rewrite("slip.zip", mut))
        self.assertFalse(ok)
        self.assertIn("UNSAFE PATH ../x.py", problems)
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ok, problems, _ = VC.check_zip(self.rewrite("dup.zip", lambda ms: ms + [ms[0]]))
        self.assertFalse(ok)
        self.assertIn("DUPLICATE MEMBER NAMES", problems)

    def test_missing_manifest_is_reported(self):
        ok, problems, info = VC.check_zip(self.rewrite("nom.zip", lambda ms: [(i, d) for i, d in ms if i.filename != "MANIFEST.json"]))
        self.assertEqual((ok, problems), (False, ["NO MANIFEST"]))
        self.assertIn("zip_sha256", info)

    def test_manifest_tamper_changes_capsule_digest(self):
        def mut(ms):
            out = []
            for i, d in ms:
                if i.filename == "MANIFEST.json":
                    m = json.loads(d)
                    m["revision"] = 0
                    d = (json.dumps(m, sort_keys=True, indent=2) + "\n").encode()
                out.append((i, d))
            return out
        ok, problems, info = VC.check_zip(self.rewrite("man.zip", mut))
        self.assertTrue(ok)
        self.assertNotEqual(info["capsule_digest"], self.digest_a)
        self.assertEqual(info["revision"], 0)


if __name__ == "__main__":
    unittest.main()
