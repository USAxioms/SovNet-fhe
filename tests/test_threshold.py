import hashlib
import json
import unittest
import bfv_wad18 as B
import threshold_bfv as T

N, BITS = 64, 4
K0 = B.choose_k(N, BITS)
K = K0 + 64      # extra modulus bits are the smudging budget (40 bits + margin)


class TestThreshold(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = B.Params(N, K)
        cls.kh = B.KeyHolder(cls.p, b"thr-seed")
        cls.pub = cls.kh.public
        cls.enc = B.Encryptor(cls.pub, b"thr-enc")
        cls.parties = T.split_key(cls.kh, 3, b"split")
        cls.i = 0

    def fresh(self, v):
        TestThreshold.i += 1
        return self.enc.encrypt_bit(v, "x%d" % TestThreshold.i).value

    def test_shares_sum_to_secret(self):
        p = self.p
        acc = [0] * p.n
        for party in self.parties:
            acc = [acc[i] + party._share[i] for i in range(p.n)]
        self.assertEqual([B.centre(c, p.q) for c in acc], self.kh._s)

    def test_combined_matches_single_key_decrypt_on_flags(self):
        for party in self.parties:
            party.allowed.clear()
        D = self.enc.encrypt_int(10, BITS, "d").value
        E = self.enc.encrypt_int(15, BITS, "e").value
        r = B.attest(self.pub, D, E)
        self.assertTrue(r.ok)
        for ct in r.value:
            for party in self.parties:
                party.authorise(T.ct_digest(ct))
        got = [T.threshold_open(self.p, ct, self.parties, "f%d" % j).value for j, ct in enumerate(r.value)]
        want = [self.kh.decrypt_bit(ct) for ct in r.value]
        self.assertEqual(got, want)
        self.assertEqual(got, [int(20 * 10 > 9 * 15), int(25 * 10 > 12 * 15)])

    def test_party_refuses_unauthorised_ciphertext(self):
        ct = self.fresh(1)                      # an INPUT ciphertext, never authorised
        r = T.threshold_open(self.p, ct, self.parties, "bad")
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "NOT_AUTHORISED")
        for party in self.parties:
            self.assertNotIn(T.ct_digest(ct), party.opened)

    def test_one_missing_party_cannot_decrypt(self):
        ok_wrong = 0
        trials = 24
        for v in [0, 1] * (trials // 2):
            ct = self.fresh(v)
            for party in self.parties:
                party.authorise(T.ct_digest(ct))
            parts = [party.partial(ct, "m%d" % self.i).value for party in self.parties[:-1]]
            r = T.combine(self.p, ct, parts)
            if r.ok and r.value == v:
                ok_wrong += 1
        self.assertLess(ok_wrong, trials)       # missing share => essentially a coin flip, not all correct

    def test_smudging_noise_is_large_and_bounded(self):
        ct = self.fresh(1)
        for party in self.parties:
            party.authorise(T.ct_digest(ct))
        parts = [party.partial(ct, "s%d" % self.i).value for party in self.parties]
        for poly, bound in parts:
            self.assertEqual(bound, ct.nb << T.SMUDGE_BITS)
        total = ct.nb + sum(b for _, b in parts)
        self.assertLess(total, self.p.half_delta)

    def test_headroom_failure_closes(self):
        p = B.Params(N, 96)
        kh = B.KeyHolder(p, b"small")
        ps = T.split_key(kh, 2, b"sp")
        ct = B.Encryptor(kh.public, b"se").encrypt_bit(1, "a").value
        big = B.Ciphertext(ct.c0, ct.c1, p.half_delta >> 10)
        for q in ps:
            q.authorise(T.ct_digest(big))
        r = T.threshold_open(p, big, ps, "h")
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")

    def test_minimal_modulus_fails_closed_for_threshold_open(self):
        p = B.Params(N, K0)                      # comparator fits, smudging does not
        kh = B.KeyHolder(p, b"min")
        enc = B.Encryptor(kh.public, b"min-e")
        r = B.attest(kh.public, enc.encrypt_int(10, BITS, "d").value, enc.encrypt_int(15, BITS, "e").value)
        self.assertTrue(r.ok)
        ps = T.split_key(kh, 3, b"mm")
        res = []
        for j, ct in enumerate(r.value):
            for q in ps:
                q.authorise(T.ct_digest(ct))
            res.append(T.threshold_open(p, ct, ps, "m%d" % j))
        self.assertIn("HEADROOM_EXHAUSTED", [x.reason for x in res if not x.ok])

    def test_smudge_is_actually_added_and_within_bound(self):
        ct = self.fresh(1)
        party = self.parties[0]
        party.authorise(T.ct_digest(ct))
        part, bound = party.partial(ct, "smudge-check").value
        clean = B.qmul(list(ct.c1), party._share, self.p)
        e = [B.centre(part[i] - clean[i], self.p.q) for i in range(self.p.n)]
        worst = max(abs(x) for x in e)
        self.assertGreater(worst, ct.nb << 20)      # far above the ciphertext's own noise
        self.assertLessEqual(worst, bound)

    def test_open_is_logged_per_party(self):
        ct = self.fresh(0)
        for party in self.parties:
            party.authorise(T.ct_digest(ct))
        before = [len(q.opened) for q in self.parties]
        T.threshold_open(self.p, ct, self.parties, "log")
        for q, b in zip(self.parties, before):
            self.assertEqual(len(q.opened), b + 1)
            self.assertEqual(q.opened[-1], T.ct_digest(ct))

    def test_combine_rejects_when_total_noise_reaches_half_delta(self):
        ct = self.fresh(1)
        ph = [0] * self.p.n
        r = T.combine(self.p, ct, [(ph, self.p.half_delta)])
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")
        ok = T.combine(self.p, ct, [(ph, 0)])
        self.assertTrue(ok.ok)

    def test_party_itself_refuses_oversized_smudge(self):
        ct = self.fresh(1)
        big = B.Ciphertext(ct.c0, ct.c1, self.p.half_delta >> 10)
        party = self.parties[0]
        party.authorise(T.ct_digest(big))
        r = party.partial(big, "big")
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")
        self.assertNotIn(T.ct_digest(big), party.opened)

    def test_deterministic(self):
        ct = self.fresh(1)
        for party in self.parties:
            party.authorise(T.ct_digest(ct))
        a = self.parties[0].partial(ct, "same").value
        b = self.parties[0].partial(ct, "same").value
        self.assertEqual(a, b)


N8 = 8
K8 = B.choose_k(N8, 4) + 64
GOLDEN_SHARES = "10db61d31ceafedbd6ba2a0f86f29d020ed318ebd631c151f60f2217c093189b"
GOLDEN_PARTIAL = "45fa484fb41bb3eee049f7d9c87ffeb3b22fb4d8e71338d9f4c9f76514c23764"


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class TestThresholdHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = B.Params(N8, K8)
        cls.kh = B.KeyHolder(cls.p, b"thr8-seed")
        cls.enc = B.Encryptor(cls.kh.public, b"thr8-enc")
        cls.n = 0

    def bit(self, v):
        TestThresholdHardening.n += 1
        return self.enc.encrypt_bit(v, "h%d" % TestThresholdHardening.n).value

    def parties(self, n, seed=b"hp"):
        return T.split_key(self.kh, n, seed)

    def test_constants(self):
        self.assertEqual(T.SMUDGE_BITS, 40)

    def test_ct_digest_exact_format(self):
        ct = B.Ciphertext([1, 2], [3, 4], 0)
        self.assertEqual(T.ct_digest(ct), hashlib.sha256(b"1,2,|3,4,|").hexdigest())
        neg = B.Ciphertext([-5, 0], [7, -8], 9)
        self.assertEqual(T.ct_digest(neg), hashlib.sha256(b"-5,0,|7,-8,|").hexdigest())
        self.assertNotEqual(T.ct_digest(ct), T.ct_digest(B.Ciphertext([3, 4], [1, 2], 0)))
        self.assertEqual(T.ct_digest(ct), T.ct_digest(B.Ciphertext([1, 2], [3, 4], 77)))   # bound excluded
        self.assertEqual(len(T.ct_digest(ct)), 64)

    def test_split_key_argument_validation(self):
        for n in (-1, 0, 1):
            with self.assertRaises(ValueError) as cm:
                T.split_key(self.kh, n, b"x")
            self.assertEqual(str(cm.exception), "need at least 2 parties")
        self.assertEqual(len(T.split_key(self.kh, 2, b"x")), 2)

    def test_split_key_party_fields_and_share_sum_for_several_sizes(self):
        for n in (2, 3, 5):
            ps = self.parties(n, b"sz%d" % n)
            self.assertEqual(len(ps), n)
            acc = [0] * self.p.n
            for i, q in enumerate(ps):
                self.assertEqual(q.index, i)
                self.assertIs(q.p, self.p)
                self.assertEqual(q._seed, b"sz%d" % n)
                self.assertEqual((q.allowed, q.opened), (set(), []))
                self.assertEqual(len(q._share), self.p.n)
                self.assertTrue(all(-(self.p.q >> 1) < c <= (self.p.q >> 1) for c in q._share))
                acc = [acc[j] + q._share[j] for j in range(self.p.n)]
            self.assertEqual([B.centre(c, self.p.q) for c in acc], self.kh._s)

    def test_split_is_deterministic_and_seed_dependent(self):
        a, b = self.parties(3, b"same"), self.parties(3, b"same")
        self.assertEqual([q._share for q in a], [q._share for q in b])
        c = self.parties(3, b"other")
        self.assertNotEqual(a[0]._share, c[0]._share)
        self.assertNotEqual(a[0]._share, a[1]._share)

    def test_golden_share_digest(self):
        ps = self.parties(3, b"golden-split")
        self.assertEqual(digest([q._share for q in ps]), GOLDEN_SHARES)

    def test_party_authorisation_and_log_semantics(self):
        q = self.parties(2)[0]
        ct = self.bit(1)
        r = q.partial(ct, "u")
        self.assertEqual((r.ok, r.value, r.reason), (False, None, "NOT_AUTHORISED"))
        self.assertEqual(q.opened, [])
        q.authorise(T.ct_digest(ct))
        q.authorise(T.ct_digest(ct))
        self.assertEqual(q.allowed, {T.ct_digest(ct)})
        r = q.partial(ct, "u")
        self.assertTrue(r.ok)
        self.assertEqual(q.opened, [T.ct_digest(ct)])
        self.assertEqual(r.value[1], ct.nb << T.SMUDGE_BITS)
        self.assertEqual(len(r.value[0]), self.p.n)

    def test_smudge_headroom_boundary_is_inclusive(self):
        q = self.parties(2)[0]
        base = self.bit(1)
        edge = self.p.half_delta >> (T.SMUDGE_BITS + 1)
        at = B.Ciphertext(base.c0, base.c1, edge)
        under = B.Ciphertext(base.c0, base.c1, edge - 1)
        for ct in (at, under):
            q.authorise(T.ct_digest(ct))
        self.assertEqual(q.partial(at, "e").reason, "HEADROOM_EXHAUSTED")
        self.assertTrue(q.partial(under, "e").ok)
        self.assertEqual(q.opened, [T.ct_digest(under)])

    def test_smudge_depends_on_party_label_and_ciphertext_bound(self):
        ps = self.parties(2)
        ct = self.bit(1)
        for q in ps:
            q.authorise(T.ct_digest(ct))

        def noise(q, label):
            part, bound = q.partial(ct, label).value
            clean = B.qmul(list(ct.c1), q._share, self.p)
            return [B.centre(part[i] - clean[i], self.p.q) for i in range(self.p.n)], bound

        e00, b = noise(ps[0], "l1")
        self.assertNotEqual(e00, noise(ps[0], "l2")[0])
        self.assertNotEqual(e00, noise(ps[1], "l1")[0])
        self.assertEqual(e00, noise(ps[0], "l1")[0])
        self.assertTrue(all(-b <= x <= b for x in e00))
        self.assertTrue(max(abs(x) for x in e00) > (b >> 8))

    def test_golden_partial_digest(self):
        ps = T.split_key(self.kh, 3, b"golden-split")
        ct = self.enc.encrypt_bit(1, "golden-ct").value
        for q in ps:
            q.authorise(T.ct_digest(ct))
        parts = [q.partial(ct, "golden-label").value for q in ps]
        self.assertEqual(digest([[list(p), b] for p, b in parts]), GOLDEN_PARTIAL)

    def test_combine_decoding_and_total_noise_boundary(self):
        p = self.p
        for bit in (0, 1):
            ct = B.ct_trivial(p, bit)
            self.assertEqual(T.combine(p, ct, []).value, bit)
            self.assertEqual(T.combine(p, ct, [([0] * p.n, 0)]).value, bit)
        zero = B.ct_trivial(p, 0)
        shift = [p.delta] + [0] * (p.n - 1)
        self.assertEqual(T.combine(p, zero, [(shift, 0)]).value, 1)
        self.assertEqual(T.combine(p, zero, [(shift, 0), (shift, 0)]).value, 0)
        ph = [0] * p.n
        edge = B.Ciphertext(zero.c0, zero.c1, 7)
        half = p.half_delta
        self.assertFalse(T.combine(p, edge, [(ph, half - 7)]).ok)
        self.assertFalse(T.combine(p, edge, [(ph, half - 17), (ph, 10)]).ok)
        self.assertTrue(T.combine(p, edge, [(ph, half - 8)]).ok)
        self.assertTrue(T.combine(p, edge, [(ph, half - 18), (ph, 10)]).ok)
        r = T.combine(p, edge, [(ph, half)])
        self.assertEqual((r.ok, r.value, r.reason), (False, None, "HEADROOM_EXHAUSTED"))

    def test_threshold_open_end_to_end_for_two_to_five_parties(self):
        for n in (2, 3, 5):
            ps = self.parties(n, b"e2e%d" % n)
            for v in (0, 1, 1, 0):
                ct = self.bit(v)
                for q in ps:
                    q.authorise(T.ct_digest(ct))
                r = T.threshold_open(self.p, ct, ps, "o%d" % self.n)
                self.assertEqual((r.ok, r.value), (True, v))
            for q in ps:
                self.assertEqual(len(q.opened), 4)

    def test_threshold_open_stops_at_first_refusal(self):
        ps = self.parties(3, b"stop")
        ct = self.bit(1)
        ps[0].authorise(T.ct_digest(ct))
        r = T.threshold_open(self.p, ct, ps, "s")
        self.assertEqual((r.ok, r.reason), (False, "NOT_AUTHORISED"))
        self.assertEqual(ps[0].opened, [T.ct_digest(ct)])
        self.assertEqual((ps[1].opened, ps[2].opened), ([], []))
        self.assertEqual(T.threshold_open(self.p, ct, [], "none").value, B.ct_trivial(self.p, 0) and
                         T.combine(self.p, ct, []).value)

    def test_wrong_party_subset_does_not_decrypt_reliably(self):
        ps = self.parties(3, b"subset")
        wrong = 0
        for v in (0, 1) * 12:
            ct = self.bit(v)
            for q in ps:
                q.authorise(T.ct_digest(ct))
            r = T.threshold_open(self.p, ct, ps[:2], "w%d" % self.n)
            wrong += (r.ok and r.value == v)
        self.assertLess(wrong, 24)


if __name__ == "__main__":
    unittest.main()
