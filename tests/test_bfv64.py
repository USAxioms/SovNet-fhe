"""N=64 tests for rev-3 BFV: ct x ct identity, relinearisation correctness, noise budget.
Run: python -m unittest test_bfv64 -v   (real ciphertexts, N=64, pure Python)"""
import unittest
import bfv_wad18 as B

N = 64
BITS = 4
K = B.choose_k(N, BITS)
_CTR = 0


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = B.Params(N, K)
        cls.kh = B.KeyHolder(cls.p, b"n64-test-seed")
        cls.pub = cls.kh.public
        cls.enc = B.Encryptor(cls.pub, b"n64-enc")

    def bit(self, v):
        global _CTR
        _CTR += 1
        return self.enc.encrypt_bit(v, "t%d" % _CTR).value


class TestMultiplication(Base):
    def test_and_truth_table(self):
        for x in (0, 1):
            for y in (0, 1):
                c = B.ct_and(self.p, self.pub.evk, self.bit(x), self.bit(y))
                self.assertEqual(self.kh.decrypt_bit(c), x & y)

    def test_multiplicative_identity_and_zero(self):
        one, zero = B.ct_trivial(self.p, 1), B.ct_trivial(self.p, 0)
        for v in (0, 1):
            x = self.bit(v)
            self.assertEqual(self.kh.decrypt_bit(B.ct_and(self.p, self.pub.evk, x, one)), v)
            self.assertEqual(self.kh.decrypt_bit(B.ct_and(self.p, self.pub.evk, x, zero)), 0)

    def test_commutative_and_associative_decryption(self):
        a, b, c = self.bit(1), self.bit(1), self.bit(0)
        A = lambda x, y: B.ct_and(self.p, self.pub.evk, x, y)
        d = self.kh.decrypt_bit
        self.assertEqual(d(A(a, b)), d(A(b, a)))
        self.assertEqual(d(A(A(a, b), c)), d(A(a, A(b, c))))

    def test_distributes_over_xor(self):
        for x in (0, 1):
            for y in (0, 1):
                for z in (0, 1):
                    a, b, c = self.bit(x), self.bit(y), self.bit(z)
                    lhs = B.ct_and(self.p, self.pub.evk, a, B.ct_xor(self.p, b, c))
                    rhs = B.ct_xor(self.p, B.ct_and(self.p, self.pub.evk, a, b),
                                   B.ct_and(self.p, self.pub.evk, a, c))
                    self.assertEqual(self.kh.decrypt_bit(lhs), x & (y ^ z))
                    self.assertEqual(self.kh.decrypt_bit(rhs), x & (y ^ z))


class TestRelinearisation(Base):
    def _degree2_phase0(self, x, y):
        """Decrypt the scaled degree-2 tensor (c0,c1,c2) directly with s^2 (no key switching)."""
        p = self.p
        t0 = B.zmul(x.c0, y.c0, p.n)
        a = B.zmul(x.c0, y.c1, p.n)
        b = B.zmul(x.c1, y.c0, p.n)
        t1 = [a[i] + b[i] for i in range(p.n)]
        t2 = B.zmul(x.c1, y.c1, p.n)
        sc = lambda poly: [B.centre((2 * c + p.delta) // (2 * p.delta), p.q) for c in poly]
        s0, s1, s2 = sc(t0), sc(t1), sc(t2)
        s = self.kh._s
        s_sq = B.zmul(s, s, p.n)
        ph = B.qadd(B.qadd(s0, B.qmul(s1, s, p), p), B.qmul(s2, s_sq, p), p)
        return ph

    def test_relinearised_matches_degree2_decryption(self):
        for x in (0, 1):
            for y in (0, 1):
                a, b = self.bit(x), self.bit(y)
                ph = self._degree2_phase0(a, b)
                direct = ((ph[0] + self.p.half_delta) // self.p.delta) % 2
                relin = self.kh.decrypt_bit(B.ct_and(self.p, self.pub.evk, a, b))
                self.assertEqual(direct, x & y)
                self.assertEqual(relin, direct)

    def test_relinearisation_noise_within_declared_bound(self):
        a, b = self.bit(1), self.bit(1)
        ph = self._degree2_phase0(a, b)
        d2 = max(abs(v - round_to(v, self.p.delta)) for v in ph)
        out = B.ct_and(self.p, self.pub.evk, a, b)
        added = abs(self.kh.noise(out) - d2)
        self.assertLessEqual(added, self.p.relin)

    def test_evk_is_deterministic_from_seed(self):
        k2 = B.KeyHolder(self.p, b"n64-test-seed")
        self.assertEqual(k2.public.evk, self.pub.evk)
        self.assertNotEqual(B.KeyHolder(self.p, b"other").public.evk, self.pub.evk)

    def test_evk_has_one_component_per_digit(self):
        self.assertEqual(len(self.pub.evk), self.p.l)


def round_to(v, delta):
    return ((v + (delta >> 1)) // delta) * delta


class TestNoiseBudget(Base):
    def test_tracked_bound_dominates_measured_along_depth(self):
        x = self.bit(1)
        acc = x
        prev_bound = acc.nb
        for depth in range(1, 6):
            acc = B.ct_and(self.p, self.pub.evk, acc, self.bit(1))
            self.assertEqual(self.kh.decrypt_bit(acc), 1)
            self.assertLessEqual(self.kh.noise(acc), acc.nb)
            self.assertGreater(acc.nb, prev_bound)       # budget is consumed monotonically
            prev_bound = acc.nb
        self.assertLess(prev_bound, self.p.half_delta)   # still inside headroom

    def test_budget_consumption_reported(self):
        acc = self.bit(1)
        for _ in range(3):
            acc = B.ct_and(self.p, self.pub.evk, acc, self.bit(1))
        used = acc.nb.bit_length()
        left = self.p.half_delta.bit_length() - used
        self.assertGreater(left, 0)

    def test_headroom_exhausted_is_failure_not_wrong_answer(self):
        p = B.Params(N, 64)             # deliberately too small
        kh = B.KeyHolder(p, b"tiny")
        e = B.Encryptor(kh.public, b"tiny-enc")
        d = e.encrypt_int(5, BITS, "d").value
        v = e.encrypt_int(9, BITS, "e").value
        r = B.attest(kh.public, d, v)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")

    def test_xor_adds_noise_bounds(self):
        a, b = self.bit(1), self.bit(0)
        c = B.ct_xor(self.p, a, b)
        self.assertEqual(c.nb, a.nb + b.nb)
        self.assertLessEqual(self.kh.noise(c), c.nb)


class TestComparatorN64(Base):
    def test_solvency_flags_match_integer_rule(self):
        dec = B.Decryptor(self.kh)
        cases = [(0, 1), (9, 20), (10, 20), (6, 12), (7, 12), (15, 15), (5, 15), (1, 15)]
        for i, (D, E) in enumerate(cases):
            d = self.enc.encrypt_int(D, BITS, "cd%d" % i).value
            e = self.enc.encrypt_int(E, BITS, "ce%d" % i).value if E < 16 else None
            if e is None:
                continue
            r = B.attest(self.pub, d, e)
            self.assertTrue(r.ok)
            got = tuple(dec.open(c) for c in r.value)
            want = (int(20 * D > 9 * E), int(25 * D > 12 * E))
            self.assertEqual(got, want, (D, E))
        self.assertEqual(len(dec.query_log) % 2, 0)   # two opens per attestation, nothing else


if __name__ == "__main__":
    unittest.main()
