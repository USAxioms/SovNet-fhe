"""Seeded property and differential tests against plain-integer references (no wall clock, no OS entropy).

Reference semantics (axioms): over_cap  <=>  20*D > 9*E   (debt above 45 % of enterprise value)
                              over_brk  <=>  25*D > 12*E  (debt above 48 %).
"""
import unittest

import bfv_wad18 as B
import fhe_wad18 as F1
import rlwe_wad18 as F2

WAD = 10 ** 18
MASK = (1 << 64) - 1


class Rng(object):
    def __init__(self, seed):
        self.x = seed

    def next(self):
        self.x = (self.x * 6364136223846793005 + 1442695040888963407) & MASK
        return self.x >> 11

    def below(self, n):
        return self.next() % n


def ref_flags(d, e):
    return (20 * d > 9 * e, 25 * d > 12 * e)


def ratio_cases(rng, count):
    """Mix of boundary-adjacent and random (debt, ev) pairs, all with ev > 0."""
    cases = []
    for _ in range(count):
        e = (1 + rng.below(3_000_000_000)) * WAD // (1 + rng.below(7))
        e = max(e, 100)
        kind = rng.below(5)
        if kind == 0:
            d = e * 9 // 20
        elif kind == 1:
            d = e * 12 // 25
        elif kind == 2:
            d = rng.below(2 * e)
        elif kind == 3:
            d = e * 9 // 20 + (rng.below(5) - 2)
        else:
            d = e * 12 // 25 + (rng.below(5) - 2)
        cases.append((max(d, 0), e))
    return cases


class LtvDifferential(object):
    F = None

    def test_ltv_status_matches_plain_reference(self):
        kh = self.F.KeyHolder(b"prop-" + self.F.__name__.encode())
        aud = self.F.BlindedAuditor(kh)
        rng = Rng(7)
        for i, (d, e) in enumerate(ratio_cases(rng, 60)):
            dc = kh.encrypt(d, "d%d" % i).value
            ec = kh.encrypt(e, "e%d" % i).value
            r = self.F.ltv_status(aud, dc, ec)
            self.assertTrue(r.ok, (d, e))
            self.assertEqual(r.value, ref_flags(d, e), (d, e))

    def test_exact_boundary_pairs(self):
        kh = self.F.KeyHolder(b"bnd-" + self.F.__name__.encode())
        aud = self.F.BlindedAuditor(kh)
        e = 20 * 25 * WAD
        for i, (d, want) in enumerate(((9 * e // 20, (False, False)), (9 * e // 20 + 1, (True, False)),
                                       (12 * e // 25, (True, False)), (12 * e // 25 + 1, (True, True)),
                                       (0, (False, False)), (e, (True, True)))):
            dc = kh.encrypt(d, "bd%d" % i).value
            ec = kh.encrypt(e, "be%d" % i).value
            self.assertEqual(self.F.ltv_status(aud, dc, ec).value, want, d)
            self.assertEqual(ref_flags(d, e), want)


class TestLtvRev1(LtvDifferential, unittest.TestCase):
    F = F1


class TestLtvRev2(LtvDifferential, unittest.TestCase):
    F = F2


class LedgerProperties(object):
    F = None

    def test_random_balanced_postings_conserve_and_audit(self):
        F = self.F
        kh = F.KeyHolder(b"led-" + F.__name__.encode())
        aud = F.BlindedAuditor(kh)
        led = F.Ledger(aud, kh.encrypt(F.EV_WAD, "genesis:ev").value)
        rng = Rng(11)
        plain = {}
        for i in range(12):
            amount = (1 + rng.below(50_000_000)) * WAD
            accts = ["A", "B", "C", F.DEBT_ACCOUNT]
            src, dst = accts[rng.below(4)], accts[rng.below(4)]
            if src == dst:
                continue
            d = kh.encrypt(amount, "p%dd" % i).value
            c = kh.encrypt(amount, "p%dc" % i).value
            r = led.post("p%d" % i, [(src, "D", d), (dst, "C", c)])
            if r.ok:
                plain[src] = plain.get(src, 0) + amount
                plain[dst] = plain.get(dst, 0) - amount
            self.assertEqual(sum(plain.values()), 0)
            for acct, bal in led.balances.items():
                self.assertEqual(kh.decrypt(bal), plain.get(acct, 0), (i, acct))
            self.assertEqual(set(led.balances), set(plain))
            if led.state != F.NORMAL:
                break
        self.assertTrue(led.audit().ok)

    def test_unbalanced_posting_is_rejected_and_state_unchanged(self):
        F = self.F
        kh = F.KeyHolder(b"unb-" + F.__name__.encode())
        led = F.Ledger(F.BlindedAuditor(kh), kh.encrypt(F.EV_WAD, "g").value)
        rng = Rng(13)
        for i in range(8):
            a = 1 + rng.below(10 ** 9)
            b = a + 1 + rng.below(10 ** 9)
            before = dict(led.balances)
            head = len(led.entries)
            r = led.post("u%d" % i, [("X", "D", kh.encrypt(a, "u%da" % i).value), ("Y", "C", kh.encrypt(b, "u%db" % i).value)])
            self.assertEqual((r.ok, r.reason), (False, "PARITY_VIOLATION"))
            self.assertEqual(led.balances, before)
            self.assertEqual(led.state, F.NORMAL)
            self.assertGreaterEqual(len(led.entries), head)
        self.assertTrue(led.audit().ok)


class TestLedgerRev1(LedgerProperties, unittest.TestCase):
    F = F1


class TestLedgerRev2(LedgerProperties, unittest.TestCase):
    F = F2


class TestBfvComparatorDifferential(unittest.TestCase):
    def val(self, bits):
        return sum(b << i for i, b in enumerate(bits))

    def test_plain_wire_flags_match_reference_up_to_64_bits(self):
        ops = B.PlainOps()
        rng = Rng(17)
        for width in (1, 2, 3, 5, 8, 13, 21, 34, 48, 64):
            cap = (1 << width) - 1
            for _ in range(60):
                e = rng.below(cap + 1)
                kind = rng.below(4)
                d = (e * 9 // 20 + rng.below(3) - 1 if kind == 0 else
                     e * 12 // 25 + rng.below(3) - 1 if kind == 1 else rng.below(cap + 1))
                d = min(max(d, 0), cap)
                got = B.solvency_flags(ops, B.to_bits(d, width), B.to_bits(e, width))
                self.assertEqual(tuple(bool(x) for x in got), ref_flags(d, e), (width, d, e))

    def test_exhaustive_small_widths(self):
        ops = B.PlainOps()
        for width in (1, 2, 3, 4, 5, 6):
            for d in range(1 << width):
                for e in range(1 << width):
                    got = B.solvency_flags(ops, B.to_bits(d, width), B.to_bits(e, width))
                    self.assertEqual(tuple(bool(x) for x in got), ref_flags(d, e), (width, d, e))

    def test_gate_layer_is_boolean_on_real_ciphertexts(self):
        p = B.Params(8, B.choose_k(8, 4))
        kh = B.KeyHolder(p, b"prop-bfv")
        enc = B.Encryptor(kh.public, b"prop-bfv-enc")
        ops = B.RealOps(kh.public)
        rng = Rng(19)
        for i in range(6):
            d, e = rng.below(16), rng.below(16)
            dc = enc.encrypt_int(d, 4, "pd%d" % i).value
            ec = enc.encrypt_int(e, 4, "pe%d" % i).value
            cap, brk = B.solvency_flags(ops, dc, ec)
            got = (kh.decrypt_bit(ops.lift(cap)) == 1, kh.decrypt_bit(ops.lift(brk)) == 1)
            self.assertEqual(got, ref_flags(d, e), (d, e))


if __name__ == "__main__":
    unittest.main()
