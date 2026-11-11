"""FHE-WAD18 rev 3 oracle suite: BFV t=2 ct x ct multiplication + encrypted solvency comparator.

Set FHE_FAST=1 to skip the full-width (96-bit) real-ciphertext tests (used by mutation runs).
"""
import ast
import hashlib
import json
import os
import unittest

import bfv_wad18 as B

HERE = os.path.dirname(os.path.abspath(__file__))
SRC_DIRS = [HERE] + [d for d in (os.path.join(HERE, "..", "src"),) if os.path.isdir(d)]
WAD = B.WAD
FAST = bool(os.environ.get("FHE_FAST"))
BITS5 = 5
K5 = B.choose_k(8, BITS5)
P5 = B.Params(8, K5)
_KH = {}


def keys(p, tag):
    key = (p.n, p.k, tag)
    if key not in _KH:
        kh = B.KeyHolder(p, b"bfv-test-" + tag.encode())
        _KH[key] = (kh, B.Encryptor(kh.public, b"enc-" + tag.encode()))
    return _KH[key]


def lcg(n, seed):
    x, out = seed, []
    for _ in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) % (1 << 64)
        out.append(x)
    return out


class TestNoFloat(unittest.TestCase):
    def test_no_float_division_or_numeric_imports(self):
        banned = {"math", "decimal", "fractions", "numpy", "random", "cmath"}
        files = sorted(f for d in SRC_DIRS for f in os.listdir(d) if f.endswith(".py"))
        paths = sorted(os.path.join(d, f) for d in SRC_DIRS for f in os.listdir(d) if f.endswith(".py"))
        self.assertIn("bfv_wad18.py", files)
        for path in paths:
            f = os.path.basename(path)
            with open(path) as fh:
                tree = ast.parse(fh.read())
            for n in ast.walk(tree):
                if isinstance(n, ast.Constant):
                    self.assertNotIn(type(n.value).__name__, ("float", "complex"), f)
                if isinstance(n, (ast.BinOp, ast.AugAssign)):
                    self.assertNotIsInstance(n.op, ast.Div, f)
                if isinstance(n, ast.Name):
                    self.assertNotIn(n.id, ("float", "complex"), f)
                if isinstance(n, ast.Import):
                    for a in n.names:
                        self.assertNotIn(a.name.split(".")[0], banned, f)
                if isinstance(n, ast.ImportFrom):
                    self.assertNotIn((n.module or "").split(".")[0], banned, f)


class TestParams(unittest.TestCase):
    def test_exact_values(self):
        p = B.Params(8, 128)
        self.assertEqual(p.q, 1 << 128)
        self.assertEqual(p.delta, 1 << 127)
        self.assertEqual(p.half_delta, 1 << 126)
        self.assertEqual(p.r, 6)
        self.assertEqual(p.fresh, 51)
        self.assertEqual(p.w, 1 << 32)
        self.assertEqual(p.l, 5)
        self.assertEqual(p.relin, 5 * 8 * (1 << 31) * 3)
        self.assertEqual(p.rounding, 37)
        self.assertEqual(B.Params(16, 64).r, 10)
        self.assertEqual(B.Params(8, 31).l, 1)
        self.assertEqual(B.Params(8, 32).l, 2)

    def test_mul_bound_formula(self):
        p = B.Params(8, 128)
        base = p.rounding + p.relin
        self.assertEqual(B.mul_bound(p, 0, 0), base)
        self.assertEqual(B.mul_bound(p, 10, 0), base + 10 * 97)
        self.assertEqual(B.mul_bound(p, 3, 4), base + 7 * 97 + 1)      # ceil(2*8*12/2^128) = 1
        big = 1 << 100
        self.assertEqual(B.mul_bound(p, big, big),
                         2 * big * 97 + (16 * big * big + p.q - 1) // p.q + base)
        self.assertEqual(B.mul_bound(p, 5, 9), B.mul_bound(p, 9, 5))

    def test_ratios_are_exact_45_and_48_percent(self):
        self.assertEqual(WAD * B.CAP_NUM % B.CAP_DEN, 0)
        self.assertEqual(WAD * B.BRK_NUM % B.BRK_DEN, 0)
        self.assertEqual(WAD * B.CAP_NUM // B.CAP_DEN, 45 * WAD // 100)
        self.assertEqual(WAD * B.BRK_NUM // B.BRK_DEN, 48 * WAD // 100)
        self.assertEqual(B.EV_WAD, 3000000000000000000000000000)

    def test_choose_k(self):
        self.assertEqual(B.choose_k(8, 4) % 32, 0)
        self.assertTrue(B.choose_k(8, 4) <= B.choose_k(8, 96))
        for bits in (4, 12):
            k = B.choose_k(8, bits)
            p = B.Params(8, k)
            ops = B.BoundOps(p)
            w = B.solvency_flags(ops, [ops.fresh() for _ in range(bits)],
                                 [ops.fresh() for _ in range(bits)])
            self.assertTrue(max(x.v for x in w) < p.half_delta)
            if k > 64:
                p2 = B.Params(8, k - 32)
                o2 = B.BoundOps(p2)
                w2 = B.solvency_flags(o2, [o2.fresh() for _ in range(bits)],
                                      [o2.fresh() for _ in range(bits)])
                self.assertTrue(max(x.v for x in w2) >= p2.half_delta)


class TestRing(unittest.TestCase):
    def test_zmul_negacyclic(self):
        n = 8
        a = [0] * n
        a[n - 1] = 1
        b = [0] * n
        b[1] = 1
        self.assertEqual(B.zmul(a, b, n), [-1] + [0] * (n - 1))
        c = [0] * n
        c[2] = 3
        d = [0] * n
        d[3] = -4
        r = B.zmul(c, d, n)
        self.assertEqual(r[5], -12)
        self.assertEqual(sum(1 for x in r if x), 1)
        x = [1, 2, 3, 4, 5, 6, 7, 8]
        y = [-3, 0, 1, 0, 0, 2, 0, -1]
        self.assertEqual(B.zmul(x, y, n), B.zmul(y, x, n))
        one = [1] + [0] * 7
        self.assertEqual(B.zmul(x, one, n), x)

    def test_centre(self):
        q = 1 << 10
        self.assertEqual(B.centre(512, q), 512)
        self.assertEqual(B.centre(513, q), -511)
        self.assertEqual(B.centre(-512, q), 512)
        self.assertEqual(B.centre(1024, q), 0)
        self.assertEqual(B.centre(1023, q), -1)

    def test_decompose_reconstructs_exactly(self):
        p = B.Params(8, 128)
        half = p.q >> 1
        vals = [0, 1, -1, p.w >> 1, (p.w >> 1) + 1, -(p.w >> 1), -(p.w >> 1) - 1,
                half, -half + 1, 123456789123456789123456789, -98765432123456789]
        poly = vals[:8]
        poly2 = vals[3:11]
        for c in (poly, poly2):
            ds = B.decompose(c, p)
            self.assertEqual(len(ds), p.l)
            for i in range(p.n):
                self.assertEqual(sum(ds[j][i] * (p.w ** j) for j in range(p.l)), c[i])
                for j in range(p.l):
                    self.assertTrue(-(p.w >> 1) <= ds[j][i] <= (p.w >> 1))


class TestDrbg(unittest.TestCase):
    def test_properties(self):
        self.assertEqual(B.Drbg(b"s", "l").bytes(70), B.Drbg(b"s", "l").bytes(70))
        self.assertNotEqual(B.Drbg(b"s", "l").bytes(32), B.Drbg(b"s", "m").bytes(32))
        d = B.Drbg(b"stat", "x")
        tern = [d.ternary() for _ in range(300)]
        small = [d.small() for _ in range(300)]
        uni = [d.uniform(100) for _ in range(40)]
        self.assertEqual(set(tern), {-1, 0, 1})
        self.assertTrue(set(small) <= set(range(-3, 4)))
        self.assertTrue(len(set(small)) >= 5)
        self.assertTrue(all(0 <= u < (1 << 100) for u in uni))
        self.assertTrue(max(uni).bit_length() > 95)
        x = B.Drbg(b"len", "x")
        self.assertEqual(len(x.bytes(1)), 1)
        self.assertEqual(len(x.bytes(33)), 33)


class TestScheme(unittest.TestCase):
    def setUp(self):
        self.p = P5
        self.kh, self.enc = keys(self.p, "scheme")
        self.pub = self.kh.public
        self.k = 0

    def bit(self, b):
        self.k += 1
        r = B.Encryptor(self.pub, b"scheme-enc").encrypt_bit(b, "b%d" % self.k)
        self.assertTrue(r.ok)
        return r.value

    def test_encrypt_decrypt_and_errors(self):
        for b in (0, 1, 0, 1, 1, 0):
            self.assertEqual(self.kh.decrypt_bit(self.bit(b)), b)
        e = B.Encryptor(self.pub, b"x")
        self.assertTrue(e.encrypt_bit(1, "L").ok)
        self.assertEqual(e.encrypt_bit(1, "L").reason, "LABEL_REUSE")
        self.assertEqual(e.encrypt_bit(2, "N").reason, "NOT_A_BIT")
        self.assertEqual(e.encrypt_bit(-1, "N2").reason, "NOT_A_BIT")
        self.assertEqual(e.encrypt_int(32, 5, "I").reason, "VALUE_OUT_OF_RANGE")
        self.assertEqual(e.encrypt_int(-1, 5, "I2").reason, "VALUE_OUT_OF_RANGE")
        r = e.encrypt_int(21, 5, "I3")
        self.assertEqual([self.kh.decrypt_bit(c) for c in r.value], [1, 0, 1, 0, 1])
        self.assertEqual(len(e.encrypt_int(0, 0, "I4").value), 0)

    def test_gate_truth_tables_and_noise_dominance(self):
        p, evk = self.p, self.pub.evk
        for a in (0, 1):
            for b in (0, 1):
                ca, cb = self.bit(a), self.bit(b)
                x = B.ct_xor(p, ca, cb)
                m = B.ct_and(p, evk, ca, cb)
                self.assertEqual(self.kh.decrypt_bit(x), a ^ b)
                self.assertEqual(self.kh.decrypt_bit(m), a & b)
                self.assertEqual(self.kh.decrypt_bit(B.ct_not(p, ca)), 1 - a)
                self.assertEqual((x.nb, m.nb), (2 * p.fresh, B.mul_bound(p, p.fresh, p.fresh)))
                self.assertTrue(0 < self.kh.noise(ca) <= ca.nb)
                self.assertTrue(self.kh.noise(x) <= x.nb)
                self.assertTrue(self.kh.noise(m) <= m.nb)
                self.assertEqual(B.ct_not(p, ca).nb, ca.nb)

    def test_trivial_constants(self):
        for b in (0, 1):
            t = B.ct_trivial(self.p, b)
            self.assertEqual((self.kh.decrypt_bit(t), t.nb, self.kh.noise(t)), (b, 0, 0))
            self.assertEqual(self.kh.decrypt_bit(B.ct_and(self.p, self.pub.evk, t, self.bit(1))), b)

    def test_deep_and_chain_and_random_circuit_bounds(self):
        p, evk = self.p, self.pub.evk
        acc = self.bit(1)
        for _ in range(4):
            acc = B.ct_and(p, evk, acc, self.bit(1))
            self.assertEqual(self.kh.decrypt_bit(acc), 1)
            self.assertTrue(self.kh.noise(acc) <= acc.nb)
        r = lcg(60, 7)
        pool = [(self.bit(r[i] & 1), r[i] & 1) for i in range(6)]
        for i in range(20):
            (x, xv), (y, yv) = pool[r[6 + i] % len(pool)], pool[r[30 + i] % len(pool)]
            if r[40 + i] & 1:
                z, zv = B.ct_and(p, evk, x, y), xv & yv
            else:
                z, zv = B.ct_xor(p, x, y), xv ^ yv
            if z.nb < p.half_delta:
                self.assertEqual(self.kh.decrypt_bit(z), zv)
                self.assertTrue(self.kh.noise(z) <= z.nb)
                pool.append((z, zv))

    def test_wrong_key_and_determinism(self):
        other = B.KeyHolder(self.p, b"another-key")
        cts = [self.bit(1) for _ in range(24)]
        self.assertFalse(all(other.decrypt_bit(c) == 1 for c in cts))
        kh1, kh2 = B.KeyHolder(self.p, b"s"), B.KeyHolder(self.p, b"s")
        self.assertEqual(kh1.public.b, kh2.public.b)
        self.assertEqual(kh1.public.evk, kh2.public.evk)
        self.assertNotEqual(kh1.public.b, B.KeyHolder(self.p, b"t").public.b)
        c1 = B.Encryptor(kh1.public, b"e").encrypt_bit(1, "q").value
        c2 = B.Encryptor(kh2.public, b"e").encrypt_bit(1, "q").value
        c3 = B.Encryptor(kh1.public, b"e").encrypt_bit(1, "r").value
        self.assertEqual(c1, c2)
        self.assertNotEqual(c1, c3)
        self.assertNotEqual(c1.c1, c3.c1)

    def test_serialisation_equality(self):
        c = self.bit(1)
        back = B.Ciphertext.from_dict(json.loads(json.dumps(c.to_dict())))
        self.assertEqual(back, c)
        self.assertEqual(hash(back), hash(c))
        self.assertFalse(back != c)
        self.assertNotEqual(c, "x")
        for field in ("c0", "c1"):
            d = c.to_dict()
            d[field][0] += 1
            self.assertNotEqual(B.Ciphertext.from_dict(d), c)
        d = c.to_dict()
        d["n"] += 1
        self.assertNotEqual(B.Ciphertext.from_dict(d), c)

    def test_decryptor_logs_every_open(self):
        dec = B.Decryptor(self.kh)
        self.assertEqual(dec.open(self.bit(1)), 1)
        self.assertEqual(dec.open(self.bit(0)), 0)
        self.assertEqual(dec.query_log, ["open", "open"])

    def test_benign_noise_tolerated_large_noise_flips(self):
        c = self.bit(1)
        c0 = list(c.c0)
        c0[0] = B.centre(c0[0] + 1, self.p.q)
        self.assertEqual(self.kh.decrypt_bit(B.Ciphertext(c0, c.c1, c.nb)), 1)
        c0[0] = B.centre(c.c0[0] + self.p.delta, self.p.q)
        self.assertEqual(self.kh.decrypt_bit(B.Ciphertext(c0, c.c1, c.nb)), 0)


def ref_flags(d, e):
    return int(20 * d > 9 * e), int(25 * d > 12 * e)


class TestCircuitsPlain(unittest.TestCase):
    P = B.PlainOps()

    def val(self, bits):
        return sum(b << i for i, b in enumerate(bits))

    def test_add2_exhaustive(self):
        for w in (1, 3, 5):
            for a in range(1 << w):
                for b in range(1 << w):
                    out = B.add2(self.P, B.to_bits(a, w), B.to_bits(b, w), w)
                    self.assertEqual(self.val(out), (a + b) % (1 << w))
        out = B.add2(self.P, B.to_bits(3, 2), B.to_bits(1, 2), 4)
        self.assertEqual((len(out), self.val(out)), (4, 4))

    def test_csa_and_sum_parts(self):
        for a in range(0, 16, 3):
            for b in range(0, 16, 2):
                for c in range(0, 16, 5):
                    s, cy = B.csa(self.P, B.to_bits(a, 4), B.to_bits(b, 4), B.to_bits(c, 4), 8)
                    self.assertEqual(self.val(s) + self.val(cy), a + b + c)
                    out = B.sum_parts(self.P, [B.to_bits(a, 4), B.to_bits(b, 4), B.to_bits(c, 4)], 8)
                    self.assertEqual(self.val(out), a + b + c)
        parts = [B.to_bits(v, 5) for v in (31, 17, 9, 30, 1)]
        self.assertEqual(self.val(B.sum_parts(self.P, parts, 9)), 31 + 17 + 9 + 30 + 1)
        self.assertEqual(self.val(B.sum_parts(self.P, [B.to_bits(13, 4)], 6)), 13)
        self.assertEqual(self.val(B.sum_parts(self.P, [], 6)), 0)

    def test_mul_const(self):
        for const in (0, 1, 2, 3, 9, 12, 20, 25, 31, 100):
            for v in (0, 1, 7, 31, 63):
                out = B.mul_const(self.P, B.to_bits(v, 6), const, 14)
                self.assertEqual(self.val(out), v * const)

    def test_less_than_exhaustive(self):
        for w in (1, 4, 5):
            for a in range(1 << w):
                for b in range(1 << w):
                    got = B.less_than(self.P, B.to_bits(a, w), B.to_bits(b, w), w)
                    self.assertEqual(got, int(a < b))
        self.assertEqual(B.less_than(self.P, [1], [0, 1, 0], 3), 1)
        self.assertEqual(B.less_than(self.P, [0, 0, 1], [1], 3), 0)

    def test_flags_exhaustive_6_bits(self):
        for d in range(64):
            for e in range(64):
                got = B.solvency_flags(self.P, B.to_bits(d, 6), B.to_bits(e, 6))
                self.assertEqual(got, ref_flags(d, e), (d, e))

    def test_flags_unequal_widths(self):
        for d, e in ((3, 200), (200, 3), (100, 222), (0, 0), (255, 255)):
            got = B.solvency_flags(self.P, B.to_bits(d, 3 if d < 8 else 8), B.to_bits(e, 8))
            self.assertEqual(got, ref_flags(d, e))

    def test_full_width_matches_rev2_integer_rule(self):
        cap, brk = 45 * WAD // 100, 48 * WAD // 100
        ev = 3_000_000_000 * WAD
        base_pairs = [(1_350_000_000 * WAD, ev), (1_440_000_000 * WAD, ev),
                      (1_350_000_000 * WAD, 2_812_500_000 * WAD)]
        pairs = []
        for d, e in base_pairs:
            for dd in (-1, 0, 1):
                for ee in (-1, 0, 1):
                    pairs.append((d + dd, e + ee))
        r = lcg(70, 99)
        for i in range(30):
            pairs.append(((r[i] << 30 ^ r[i + 1]) % (1 << 95), (r[30 + i] << 30 ^ r[31 + i]) % (1 << 95)))
        pairs += [(0, 0), (0, ev), (ev, 0), ((1 << 96) - 1, (1 << 96) - 1)]
        for d, e in pairs:
            got = B.solvency_flags(self.P, B.to_bits(d, 96), B.to_bits(e, 96))
            want = (int(cap * e < WAD * d), int(brk * e < WAD * d))
            self.assertEqual(got, want, (d, e))

    def test_gate_and_depth_pins(self):
        pins = {4: ([7, 8], 120, 82, 32), 8: ([8, 9], 259, 197, 48), 96: ([14, 15], 5144, 3726, 400)}
        for bits, (depth, ands, xors, nots) in pins.items():
            o = B.DepthOps()
            w = B.solvency_flags(o, [o.fresh() for _ in range(bits)], [o.fresh() for _ in range(bits)])
            self.assertEqual([x.v for x in w], depth)
            self.assertEqual((o.ands, o.xors, o.nots), (ands, xors, nots))

    def test_constant_folding_edges(self):
        o = B.DepthOps()
        w = o.fresh()
        self.assertEqual(B.g_and(o, 0, w), 0)
        self.assertEqual(B.g_and(o, w, 0), 0)
        self.assertIs(B.g_and(o, 1, w), w)
        self.assertIs(B.g_and(o, w, 1), w)
        self.assertIs(B.g_xor(o, 0, w), w)
        self.assertIs(B.g_xor(o, w, 0), w)
        self.assertEqual(o.ands + o.xors + o.nots, 0)
        B.g_xor(o, 1, w)
        B.g_xor(o, w, 1)
        self.assertEqual(o.nots, 2)
        self.assertEqual((B.g_xor(o, 1, 1), B.g_and(o, 1, 1), B.g_not(o, 0), B.g_not(o, 1)), (0, 1, 1, 0))
        B.g_not(o, w)
        self.assertEqual(o.nots, 3)
        B.g_and(o, w, w)
        B.g_xor(o, w, w)
        self.assertEqual((o.ands, o.xors), (1, 1))


class TestCircuitsReal(unittest.TestCase):
    PAIRS = [(0, 0), (9, 20), (10, 20), (12, 25), (13, 25), (31, 31), (1, 31), (6, 13), (31, 0), (0, 31)]

    def setUp(self):
        self.p = P5
        self.kh, _ = keys(self.p, "real")
        self.pub = self.kh.public
        self.n = 0

    def encrypt(self, d, e):
        self.n += 1
        enc = B.Encryptor(self.pub, b"real-enc")
        dd = enc.encrypt_int(d, BITS5, "d%d" % self.n).value
        ee = enc.encrypt_int(e, BITS5, "e%d" % self.n).value
        return dd, ee

    def test_flags_match_reference_including_exact_boundaries(self):
        self.assertEqual(ref_flags(9, 20), (0, 0))      # exactly 45 %
        self.assertEqual(ref_flags(10, 20), (1, 1))
        self.assertEqual(ref_flags(12, 25), (1, 0))     # exactly 48 %
        self.assertEqual(ref_flags(13, 25), (1, 1))
        dec = B.Decryptor(self.kh)
        for d, e in self.PAIRS:
            dc, ec = self.encrypt(d, e)
            r = B.attest(self.pub, dc, ec)
            self.assertTrue(r.ok, r.reason)
            got = (dec.open(r.value[0]), dec.open(r.value[1]))
            self.assertEqual(got, ref_flags(d, e), (d, e))
        self.assertEqual(len(dec.query_log), 2 * len(self.PAIRS))

    def test_real_bounds_equal_bound_backend_and_dominate_noise(self):
        dc, ec = self.encrypt(9, 20)
        r = B.attest(self.pub, dc, ec)
        bo = B.BoundOps(self.p)
        w = B.solvency_flags(bo, [bo.fresh() for _ in range(BITS5)], [bo.fresh() for _ in range(BITS5)])
        for ct, wire in zip(r.value, w):
            self.assertEqual(ct.nb, wire.v)
            self.assertTrue(self.kh.noise(ct) <= ct.nb)
            self.assertTrue(ct.nb < self.p.half_delta)

    def test_operator_uses_only_public_material(self):
        dc, ec = self.encrypt(10, 20)
        r = B.attest(self.pub, dc, ec)
        self.assertEqual(B.Decryptor(self.kh).open(r.value[0]), 1)
        self.assertFalse(hasattr(self.pub, "_s"))
        self.assertFalse(hasattr(B.RealOps(self.pub), "_kh"))

    def test_decryptor_sees_only_two_bits(self):
        dc, ec = self.encrypt(12, 25)
        r = B.attest(self.pub, dc, ec)
        dec = B.Decryptor(self.kh)
        dec.open(r.value[0])
        dec.open(r.value[1])
        self.assertEqual(dec.query_log, ["open", "open"])

    def test_headroom_exhaustion_is_reported_not_guessed(self):
        tiny = B.Params(8, 64)
        kh = B.KeyHolder(tiny, b"tiny")
        enc = B.Encryptor(kh.public, b"tiny-enc")
        d = enc.encrypt_int(9, 4, "d").value
        e = enc.encrypt_int(20 & 15, 4, "e").value
        r = B.attest(kh.public, d, e)
        self.assertEqual((r.ok, r.reason), (False, "HEADROOM_EXHAUSTED"))

    def test_benign_input_noise_does_not_change_outputs(self):
        dc, ec = self.encrypt(10, 20)
        c0 = list(dc[0].c0)
        c0[0] = B.centre(c0[0] + 1, self.p.q)
        dc[0] = B.Ciphertext(c0, dc[0].c1, dc[0].nb)
        r = B.attest(self.pub, dc, ec)
        dec = B.Decryptor(self.kh)
        self.assertEqual((dec.open(r.value[0]), dec.open(r.value[1])), (1, 1))

    def test_flipped_input_bit_changes_verdict(self):
        dc, ec = self.encrypt(9, 20)                    # exactly 45 %: not over
        c0 = list(dc[0].c0)
        c0[0] = B.centre(c0[0] + self.p.delta, self.p.q)   # D becomes 8 (bit0 flipped)
        dc[0] = B.Ciphertext(c0, dc[0].c1, dc[0].nb)
        r = B.attest(self.pub, dc, ec)
        dec = B.Decryptor(self.kh)
        self.assertEqual((dec.open(r.value[0]), dec.open(r.value[1])), ref_flags(8, 20))

    def test_golden_attestation_digest(self):
        dc, ec = self.encrypt(10, 20)
        r = B.attest(self.pub, dc, ec)
        blob = json.dumps([c.to_dict() for c in r.value], sort_keys=True, separators=(",", ":"))
        self.assertEqual(hashlib.sha256(blob.encode()).hexdigest(), GOLDEN)


@unittest.skipIf(FAST, "full-width real-ciphertext tests skipped under FHE_FAST")
class TestFullWidthReal(unittest.TestCase):
    def test_wad_boundaries_on_real_ciphertexts(self):
        bits = 96
        p = B.Params(8, B.choose_k(8, bits))
        kh = B.KeyHolder(p, b"full-width")
        enc = B.Encryptor(kh.public, b"full-enc")
        dec = B.Decryptor(kh)
        ev = 3_000_000_000 * WAD
        cases = [(1_350_000_000 * WAD, ev, (0, 0)),
                 (1_350_000_000 * WAD + 1, ev, (1, 0)),
                 (1_440_000_000 * WAD, ev, (1, 0)),
                 (1_440_000_000 * WAD + 1, ev, (1, 1))]
        for i, (d, e, want) in enumerate(cases):
            dc = enc.encrypt_int(d, bits, "D%d" % i).value
            ec = enc.encrypt_int(e, bits, "E%d" % i).value
            r = B.attest(kh.public, dc, ec)
            self.assertTrue(r.ok, r.reason)
            self.assertEqual((dec.open(r.value[0]), dec.open(r.value[1])), want, i)
            for ct in r.value:
                self.assertTrue(kh.noise(ct) <= ct.nb < p.half_delta)
        self.assertEqual(len(dec.query_log), 8)


class TestBfvSurvivorKillers(unittest.TestCase):
    def test_result_plumbing(self):
        self.assertEqual(B.Res._fields, ("ok", "value", "reason"))
        self.assertEqual(B.Res.__name__, "Res")
        r = B._ok(5)
        self.assertEqual((r.ok, r.value, r.reason), (True, 5, ""))
        self.assertEqual(repr(r), "Res(ok=True, value=5, reason='')")
        f = B._fail("X")
        self.assertEqual((f.ok, f.value, f.reason), (False, None, "X"))

    def test_slotted_classes(self):
        self.assertEqual(B.Ciphertext.__slots__, ("c0", "c1", "nb"))
        self.assertEqual(B._W.__slots__, ("v",))
        c = B.Ciphertext([0], [0], 0)
        with self.assertRaises(AttributeError):
            c.extra = 1
        w = B._W(1)
        with self.assertRaises(AttributeError):
            w.extra = 1

    def test_ciphertext_equality_every_field_both_directions(self):
        base = B.Ciphertext([1, 1], [2, 2], 5)
        self.assertTrue(base == B.Ciphertext([1, 1], [2, 2], 5))
        self.assertFalse(base != B.Ciphertext([1, 1], [2, 2], 5))
        for v in (B.Ciphertext([2, 1], [2, 2], 5), B.Ciphertext([0, 1], [2, 2], 5),
                  B.Ciphertext([1, 1], [3, 2], 5), B.Ciphertext([1, 1], [1, 2], 5),
                  B.Ciphertext([1, 1], [2, 2], 6), B.Ciphertext([1, 1], [2, 2], 4)):
            self.assertFalse(base == v)
            self.assertFalse(v == base)
            self.assertTrue(base != v)
        self.assertFalse(base == ([1, 1], [2, 2], 5))

    def test_trivial_ciphertext_layout_and_decryption(self):
        kh, enc = keys(P5, "sk")
        for bit in (0, 1):
            t = B.ct_trivial(P5, bit)
            self.assertEqual(list(t.c1), [0] * P5.n)
            self.assertEqual(t.nb, 0)
            self.assertEqual(t.c0[0], B.centre(bit * P5.delta, P5.q))
            self.assertEqual(list(t.c0[1:]), [0] * (P5.n - 1))
            self.assertEqual(kh.decrypt_bit(t), bit)
            self.assertEqual(kh.noise(t), 0)

    def test_public_key_a_is_centred(self):
        kh, enc = keys(P5, "sk")
        h = P5.q >> 1
        self.assertTrue(all(-h < c <= h for c in kh.public.a))
        self.assertTrue(all(-h < c <= h for c in kh.public.b))
        for bj, aj in kh.public.evk:
            self.assertTrue(all(-h < c <= h for c in aj))

    def test_encrypt_int_range_and_error_propagation(self):
        kh, enc0 = keys(P5, "sk")
        enc = B.Encryptor(kh.public, b"range-enc")
        for bad in (-1, -16, 16, 17, 1 << 20):
            r = enc.encrypt_int(bad, 4, "r%d" % bad)
            self.assertEqual((r.ok, r.value, r.reason), (False, None, "VALUE_OUT_OF_RANGE"))
        self.assertEqual(enc._used, set())
        ok = enc.encrypt_int(15, 4, "top")
        self.assertTrue(ok.ok)
        self.assertEqual([kh.decrypt_bit(c) for c in ok.value], [1, 1, 1, 1])
        self.assertEqual(enc.encrypt_int(0, 4, "zero").ok, True)
        again = enc.encrypt_int(3, 4, "top")                 # labels top:0.. already used
        self.assertEqual((again.ok, again.value, again.reason), (False, None, "LABEL_REUSE"))
        enc.encrypt_bit(1, "part:0")
        part = enc.encrypt_int(1, 3, "part")
        self.assertEqual((part.ok, part.reason), (False, "LABEL_REUSE"))
        self.assertIsNone(part.value)

    def test_drbg_uniform_matches_independent_reference(self):
        for bits in (1, 8, 9, 64, 65, 100, 320):
            d = B.Drbg(b"seed", "lab")
            n = (bits + 7) // 8 + 8
            stream, ctr = b"", 0
            while len(stream) < 2 * n:
                stream += hashlib.sha256(b"seed|lab|" + str(ctr).encode()).digest()
                ctr += 1
            self.assertEqual(d.uniform(bits), int.from_bytes(stream[:n], "big") % (1 << bits))
            self.assertEqual(d.uniform(bits), int.from_bytes(stream[n:2 * n], "big") % (1 << bits))

    def test_params_and_mul_bound_exact(self):
        p = B.Params(8, 128)
        self.assertEqual((p.rounding, p.r, p.l, p.relin), (37, 6, 5, 257698037760))
        self.assertEqual(B.mul_bound(p, 5, 7), 12 * 97 + 1 + 37 + 257698037760)
        self.assertEqual(B.mul_bound(p, 0, 0), 37 + 257698037760)
        big = p.q  # forces the ceiling term past 1
        self.assertEqual(B.mul_bound(p, big, 1),
                         (big + 1) * 97 + (16 * big + p.q - 1) // p.q + 37 + 257698037760)
        for n in (8, 16, 64):
            q = B.Params(n, 96)
            self.assertEqual(q.rounding, (n * n + n + 2) // 2)

    def test_choose_k_goldens_and_minimality(self):
        gold = {(8, 1): 64, (8, 2): 96, (8, 4): 96, (8, 6): 96, (16, 1): 96, (16, 4): 128,
                (64, 1): 96, (64, 4): 160, (64, 6): 160}
        for (n, bits), k in gold.items():
            self.assertEqual(B.choose_k(n, bits), k, (n, bits))

        def worst(n, bits, k):
            pp = B.Params(n, k)
            ops = B.BoundOps(pp)
            ws = B.solvency_flags(ops, [ops.fresh() for _ in range(bits)], [ops.fresh() for _ in range(bits)])
            return max(w.v for w in ws if not isinstance(w, int)), pp.half_delta
        for (n, bits), k in gold.items():
            w, h = worst(n, bits, k)
            self.assertLess(w, h)
            for below in range(k - 32, -1, -32):
                w2, h2 = worst(n, bits, below)
                self.assertGreater(w2, h2, (n, bits, below))      # strict: never exactly equal

    def test_solvency_flags_exact_gate_counts(self):
        gold = {1: (16, 6, 13), 2: (50, 27, 21), 3: (87, 54, 27), 4: (120, 82, 32),
                5: (152, 110, 36), 6: (187, 139, 40)}
        for bits, want in gold.items():
            ops = B.BoundOps(B.Params(8, B.choose_k(8, bits)))
            B.solvency_flags(ops, [ops.fresh() for _ in range(bits)], [ops.fresh() for _ in range(bits)])
            self.assertEqual((ops.ands, ops.xors, ops.nots), want, bits)

    def test_less_than_exhaustive_on_plain_wires(self):
        for width in range(1, 9):
            vals = range(1 << width) if width <= 4 else sorted(set(lcg(40, width)[i] % (1 << width) for i in range(40)) | {0, (1 << width) - 1})
            for a in vals:
                for b in vals:
                    r = B.less_than(None, B.to_bits(a, width), B.to_bits(b, width), width)
                    self.assertEqual(r, int(a < b), (width, a, b))

    def test_sum_parts_and_csa_widths(self):
        w = 4
        s, cy = B.csa(None, [1, 1, 1, 1], [1, 0, 1, 0], [1, 1, 0, 0], w)
        self.assertEqual((len(s), len(cy)), (w, w))
        self.assertEqual(cy[0], 0)
        for parts in ([], [[1, 0, 1]], [[1, 0, 1], [1, 1]], [[1, 1, 1], [1, 1, 1], [1, 1, 1]],
                      [[1, 1, 1, 1, 1, 1], [1]], [[1, 1, 1, 1, 1, 1], [0, 1, 1, 1, 1, 1], [1, 1], [1], [1, 0, 1]]):
            out = B.sum_parts(None, parts, w)
            want = sum(sum(b << i for i, b in enumerate(x[:w])) for x in parts) % (1 << w)
            self.assertEqual(len(out), w)
            self.assertEqual(sum(b << i for i, b in enumerate(out)), want, parts)

    def test_mul_const_and_add2_plain(self):
        for width in (1, 2, 3, 4, 5, 6, 7, 8, 9):
            for const in (0, 1, 2, 3, 9, 20, 25, 45, 100):
                for v in (0, 1, 5, 11, 31):
                    out = B.mul_const(None, B.to_bits(v, 5), const, width)
                    self.assertEqual(sum(b << i for i, b in enumerate(out)), (v * const) % (1 << width), (width, const, v))
            for a in (0, 1, 3, 7, 12, 31):
                for b in (0, 1, 5, 9, 30):
                    out = B.add2(None, B.to_bits(a, 5), B.to_bits(b, 5), width)
                    self.assertEqual(len(out), width)
                    self.assertEqual(sum(x << i for i, x in enumerate(out)), (a + b) % (1 << width))

    def test_gate_folding_truth_tables(self):
        for a in (0, 1):
            for b in (0, 1):
                self.assertEqual(B.g_xor(None, a, b), a ^ b)
                self.assertEqual(B.g_and(None, a, b), a & b)
        self.assertEqual(B.g_not(None, 0), 1)
        self.assertEqual(B.g_not(None, 1), 0)
        ops = B.BoundOps(B.Params(8, 96))
        w = ops.fresh()
        self.assertIs(B.g_xor(ops, 0, w), w)
        self.assertIs(B.g_xor(ops, w, 0), w)
        self.assertIs(B.g_and(ops, 1, w), w)
        self.assertIs(B.g_and(ops, w, 1), w)
        self.assertEqual((B.g_and(ops, 0, w), B.g_and(ops, w, 0)), (0, 0))
        self.assertEqual((ops.ands, ops.xors, ops.nots), (0, 0, 0))
        self.assertIsNotNone(B.g_xor(ops, 1, w))
        self.assertIsNotNone(B.g_xor(ops, w, 1))
        self.assertEqual(ops.nots, 2)


class TestMutationHardeningBfv(unittest.TestCase):
    def test_decompose_tie_prefers_positive_half(self):
        p = B.Params(8, 128)
        half = p.w >> 1
        ds = B.decompose([half, -half, half + 1, 0, 0, 0, 0, 0], p)
        self.assertEqual((ds[0][0], ds[1][0]), (half, 0))
        self.assertEqual((ds[0][1], ds[1][1]), (half, -1))
        self.assertEqual((ds[0][2], ds[1][2]), (-half + 1, 1))
        for j in range(p.l):
            self.assertEqual(ds[j][3], 0)

    def test_pad_and_shift(self):
        self.assertEqual(B.pad([1], 3), [1, 0, 0])
        self.assertEqual(B.pad([1, 1, 1], 3), [1, 1, 1])
        self.assertEqual(B.pad([], 2), [0, 0])
        self.assertEqual(B.shift([1, 1], 2), [0, 0, 1, 1])
        self.assertEqual(B.shift([1], 0), [1])

    def test_measured_noise_sees_negative_and_positive_error(self):
        kh, _ = keys(P5, "noise")
        zero = B.ct_trivial(P5, 0)
        for delta in (5, -5, 1, -1, 0):
            c0 = list(zero.c0)
            c0[0] = B.centre(c0[0] + delta, P5.q)
            self.assertEqual(kh.noise(B.Ciphertext(c0, zero.c1, 0)), abs(delta))
        c0 = list(zero.c0)
        c0[0], c0[3] = -9, 4
        self.assertEqual(kh.noise(B.Ciphertext(c0, zero.c1, 0)), 9)
        c0[0], c0[3] = 9, -4
        self.assertEqual(kh.noise(B.Ciphertext(c0, zero.c1, 0)), 9)

    def test_gate_counters_agree_across_backends(self):
        bits = 4
        p = B.Params(8, B.choose_k(8, bits))
        bo, do = B.BoundOps(p), B.DepthOps()
        for ops in (bo, do):
            B.solvency_flags(ops, [ops.fresh() for _ in range(bits)], [ops.fresh() for _ in range(bits)])
        self.assertEqual((bo.ands, bo.xors, bo.nots), (120, 82, 32))
        self.assertEqual((do.ands, do.xors, do.nots), (120, 82, 32))
        kh, _ = keys(p, "cnt")
        enc = B.Encryptor(kh.public, b"cnt-enc")
        d = enc.encrypt_int(5, bits, "d").value
        e = enc.encrypt_int(9, bits, "e").value
        ro = B.RealOps(kh.public)
        B.solvency_flags(ro, d, e)
        self.assertEqual(ro.ands, 120)
        self.assertFalse(ro.exhausted)

    def test_real_ops_exhaustion_boundary_is_inclusive(self):
        kh, _ = keys(P5, "edge")
        ro = B.RealOps(kh.public)
        base = B.ct_trivial(P5, 1)
        x = B.Ciphertext(base.c0, base.c1, P5.half_delta - 5)
        y = B.Ciphertext(base.c0, base.c1, 5)
        z = B.Ciphertext(base.c0, base.c1, 4)
        ro.xor(x, z)
        self.assertFalse(ro.exhausted)
        ro.xor(x, y)
        self.assertTrue(ro.exhausted)
        ro2 = B.RealOps(kh.public)
        ro2.and_(B.ct_trivial(P5, 1), B.ct_trivial(P5, 1))
        self.assertEqual(ro2.ands, 1)
        self.assertFalse(ro2.exhausted)
        self.assertEqual(B.RealOps(kh.public).ands, 0)
        self.assertEqual(ro.lift(1), B.ct_trivial(P5, 1))
        self.assertIs(ro.lift(x), x)

    def test_plain_backend_has_no_gate_methods(self):
        for name in ("xor", "and_", "not_"):
            self.assertFalse(hasattr(B.PlainOps(), name))


GOLDEN = "ab935c0ffb8b5a22eb3c6d61098fa9e4f7a4aa7cdc74745a7aa7938604e3caf4"

if __name__ == "__main__":
    unittest.main()
