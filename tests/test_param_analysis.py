import os
import unittest

import bfv_wad18 as B
from audit import param_analysis as PA
from audit import standard_params_attest as AT
from audit import standard_params_smoke as SM


class TestSamplerModel(unittest.TestCase):
    def test_engine_error_sampler_is_centred_binomial_with_variance_3_over_2(self):
        counts = {}
        for byte in range(256):
            v = bin(byte & 7).count("1") - bin((byte >> 3) & 7).count("1")
            counts[v] = counts.get(v, 0) + 1
        self.assertEqual((min(counts), max(counts)), (-3, 3))
        self.assertEqual(sum(v * v * c for v, c in counts.items()) * 2, 3 * 256)    # Var = 3/2
        self.assertEqual(sum(v * c for v, c in counts.items()), 0)
        d = B.Drbg(b"var", "x")
        self.assertTrue(all(-3 <= d.small() <= 3 for _ in range(500)))

    def test_sigma_threshold_is_21(self):
        self.assertEqual([e for e in range(1, 40) if PA.sigma_ok(e)][0], 21)
        self.assertFalse(PA.sigma_ok(3))
        self.assertFalse(PA.sigma_ok(20))
        self.assertTrue(PA.sigma_ok(21))
        self.assertEqual(PA.variance_times_2(7), 7)

    def test_smoke_sampler_variance_and_range(self):
        class Fake(object):
            def __init__(self, d):
                self.d = d

            def bytes(self, n):
                return self.d.bytes(n)
        f = Fake(B.Drbg(b"cbd", "x"))
        n = 4000
        vals = [SM.cbd_small(f) for _ in range(n)]
        self.assertTrue(all(-SM.ETA <= v <= SM.ETA for v in vals))
        self.assertEqual(SM.ETA, 21)
        self.assertTrue(9 * n <= sum(v * v for v in vals) <= 12 * n)                 # true variance 10.5
        self.assertTrue(abs(sum(vals)) < 6 * n // 10)


class TestTable(unittest.TestCase):
    def test_hes_table_values(self):
        self.assertEqual(PA.HES_128_TERNARY[4096], 109)
        self.assertEqual(PA.HES_128_TERNARY[8192], 218)
        self.assertEqual(PA.HES_128_TERNARY[16384], 438)
        self.assertEqual(PA.HES_128_TERNARY[32768], 881)

    def test_required_k_goldens_and_smallest_compliant_degree(self):
        g3, g21 = PA.table(3), PA.table(21)
        self.assertEqual(B.ERR_BOUND, 3)                                            # table() restores the global
        self.assertEqual((g3[(4, 1024)], g3[(64, 4096)], g3[(96, 32768)]), (192, 384, 512))
        self.assertEqual((g21[(4, 1024)], g21[(64, 1024)], g21[(96, 32768)]), (224, 352, 512))
        for grid in (g3, g21):
            for bits in (4, 8, 16, 32, 48):
                self.assertEqual(PA.smallest_n(grid, bits), 16384)
            for bits in (64, 96):
                self.assertEqual(PA.smallest_n(grid, bits), 32768)
        self.assertTrue(all(g21[key] >= g3[key] for key in g3))                    # larger error never needs less modulus


class TestKronecker(unittest.TestCase):
    def test_matches_engine_zmul(self):
        d = B.Drbg(b"kron", "x")
        for n in (1, 2, 3, 8, 16):
            for bits in (1, 5, 40, 130):
                a = [d.uniform(bits) - (1 << (bits - 1)) for _ in range(n)]
                b = [d.uniform(bits) - (1 << (bits - 1)) for _ in range(n)]
                self.assertEqual(SM.kronecker_zmul(a, b, n), B.zmul(a, b, n), (n, bits))
        z = [0] * 4
        self.assertEqual(SM.kronecker_zmul(z, [1, 2, 3, 4], 4), [0] * 4)
        self.assertEqual(SM.kronecker_zmul([1, -1, 1, -1], [-1, 1, -1, 1], 4), B.zmul([1, -1, 1, -1], [-1, 1, -1, 1], 4))
        a, b = [5, 0, 0, 0], [0, 0, 0, 7]
        self.assertEqual(SM.kronecker_zmul(a, b, 4), [0, 0, 0, 35])
        self.assertEqual(SM.kronecker_zmul([0, 0, 0, 5], [0, 0, 0, 7], 4), [0, 0, -35, 0])   # x^3 * x^3 = x^6 = -x^2 (mod x^4 + 1)
        self.assertEqual(SM.kronecker_zmul([0, 0, 0, 5], [0, 0, 0, 7], 4), B.zmul([0, 0, 0, 5], [0, 0, 0, 7], 4))


class TestPatchHygieneAndSmallAttest(unittest.TestCase):
    def snapshot(self):
        return (B.zmul, B.ERR_BOUND, B.Drbg.small, B.WBITS, B.ct_and)

    def test_install_restores_every_patched_name(self):
        before = self.snapshot()
        restore = SM.install(64)
        self.assertIs(B.zmul, SM.kronecker_zmul)
        self.assertEqual((B.ERR_BOUND, B.WBITS), (21, 64))
        self.assertIs(B.Drbg.small, SM.cbd_small)
        restore()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual((B.ERR_BOUND, B.WBITS), (3, 32))

    def test_small_ring_attest_matches_plain_reference_and_restores(self):
        before = self.snapshot()
        for debt, ev in ((7, 15), (7, 14), (6, 14), (0, 9), (15, 15), (9, 15), (1, 1)):
            r = AT.run(debt, ev, 4, 64, 32)
            self.assertTrue(r["attest_ok"], (debt, ev))
            self.assertEqual(r["and_gates"], 120)
            self.assertEqual(r["expected"], [20 * debt > 9 * ev, 25 * debt > 12 * ev])
            self.assertEqual(r["got"], r["expected"], (debt, ev))
            self.assertTrue(r["match"] and r["bound_dominates"])
            self.assertTrue(max(r["noise_bits"]) <= max(r["bound_bits"]) <= r["limit_bits"])
            self.assertEqual(self.snapshot(), before)
        a, b = AT.run(7, 15, 4, 64, 32), AT.run(7, 15, 4, 64, 32)
        self.assertEqual((a["cap_digest"], a["brk_digest"]), (b["cap_digest"], b["brk_digest"]))
        self.assertEqual(len(a["cap_digest"]), 64)

    def test_gate_cache_resumes_and_gives_identical_result(self):
        import tempfile
        import shutil
        d = tempfile.mkdtemp(prefix="gatecache_")
        try:
            first = AT.run(7, 15, 4, 64, 32, cache_dir=d)
            files = sorted(os.listdir(d))
            self.assertTrue(100 <= len(files) <= 120)                                # duplicate gates share one entry
            second = AT.run(7, 15, 4, 64, 32, cache_dir=d)
            self.assertEqual(sorted(os.listdir(d)), files)
            for key in ("cap_digest", "brk_digest", "got", "noise_bits", "bound_bits", "and_gates"):
                self.assertEqual(first[key], second[key], key)
            plain = AT.run(7, 15, 4, 64, 32)
            self.assertEqual((plain["cap_digest"], plain["brk_digest"]), (first["cap_digest"], first["brk_digest"]))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_failure_paths_do_not_leave_patches_installed(self):
        before = self.snapshot()
        with self.assertRaises(Exception):
            AT.run(99, 15, 4, 64, 32)                                              # value out of range for 4 bits
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
