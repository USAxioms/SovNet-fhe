"""FHE-WAD18 rev 2 oracle suite: RLWE layer + ported ledger/fault-injection tests."""
import ast
import json
import os
import unittest

import rlwe_wad18 as F
from ledger_hardening import LedgerHardeningMixin

SEED = b"FHE-WAD18-RLWE-TEST-SEED-0001"
HERE = os.path.dirname(os.path.abspath(__file__))
SRC_DIRS = [HERE] + [d for d in (os.path.join(HERE, "..", "src"),) if os.path.isdir(d)]


def new_ledger(ev=F.EV_WAD, tag="t"):
    kh = F.KeyHolder(SEED + tag.encode())
    aud = F.BlindedAuditor(kh)
    led = F.Ledger(aud, kh.encrypt(ev, "genesis:ev").value)
    return kh, aud, led


def borrow(kh, led, txid, amount, acct="CASH"):
    d = kh.encrypt(amount, txid + ":D").value
    c = kh.encrypt(amount, txid + ":C").value
    return led.post(txid, [(acct, "D", d), (F.DEBT_ACCOUNT, "C", c)])


def run_scenario():
    kh, aud, led = new_ledger()
    borrow(kh, led, "tx1", 1_000_000_000 * F.WAD)
    borrow(kh, led, "tx2", 350_000_000 * F.WAD)
    return kh, aud, led


class TestNoFloat(unittest.TestCase):
    def test_no_float_division_or_numeric_imports(self):
        banned_imports = {"math", "decimal", "fractions", "numpy", "random", "cmath"}
        files = sorted(f for d in SRC_DIRS for f in os.listdir(d) if f.endswith(".py"))
        paths = sorted(os.path.join(d, f) for d in SRC_DIRS for f in os.listdir(d) if f.endswith(".py"))
        self.assertIn("rlwe_wad18.py", files)
        for path in paths:
            f = os.path.basename(path)
            with open(path) as fh:
                tree = ast.parse(fh.read())
            for n in ast.walk(tree):
                if isinstance(n, ast.Constant):
                    self.assertNotIn(type(n.value).__name__, ("float", "complex"), f)
                if isinstance(n, ast.BinOp):
                    self.assertNotIsInstance(n.op, ast.Div, f)
                if isinstance(n, ast.AugAssign):
                    self.assertNotIsInstance(n.op, ast.Div, f)
                if isinstance(n, ast.Name):
                    self.assertNotIn(n.id, ("float", "complex"), f)
                if isinstance(n, ast.Import):
                    for a in n.names:
                        self.assertNotIn(a.name.split(".")[0], banned_imports, f)
                if isinstance(n, ast.ImportFrom):
                    self.assertNotIn((n.module or "").split(".")[0], banned_imports, f)


class TestParameters(unittest.TestCase):
    def test_parameters_exact(self):
        self.assertEqual(F.N, 64)
        self.assertEqual(F.T, 1 << 192)
        self.assertEqual(F.DELTA, 1 << 128)
        self.assertEqual(F.Q, 1 << 320)
        self.assertEqual(F.HALF_T, 1 << 191)
        self.assertEqual(F.HALF_DELTA, 1 << 127)
        self.assertEqual(F.FRESH_NOISE, 3 * 129)
        self.assertEqual(F.VALUE_MAX, 1 << 100)
        self.assertEqual(F.CAP_RATIO_WAD, 450000000000000000)
        self.assertEqual(F.BREAKER_RATIO_WAD, 480000000000000000)
        self.assertEqual(F.EV_WAD, 3000000000000000000000000000)
        for v in (F.N, F.T, F.DELTA, F.Q, F.WAD, F.EV_WAD):
            self.assertIs(type(v), int)


class TestLedger(unittest.TestCase):
    def test_balanced_posting_commits_and_audit_passes(self):
        kh, aud, led = run_scenario()
        self.assertEqual(led.state, F.NORMAL)
        r = led.audit()
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(r.value, led.head())
        self.assertEqual(kh.decrypt(led.balances["CASH"]), 1_350_000_000 * F.WAD)
        self.assertEqual(kh.decrypt(led.balances[F.DEBT_ACCOUNT]), -1_350_000_000 * F.WAD)

    def test_unbalanced_posting_rejected_and_state_unchanged(self):
        kh, aud, led = new_ledger()
        d = kh.encrypt(100 * F.WAD, "u:D").value
        c = kh.encrypt(100 * F.WAD + 1, "u:C").value
        r = led.post("u", [("CASH", "D", d), (F.DEBT_ACCOUNT, "C", c)])
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "PARITY_VIOLATION")
        self.assertEqual(led.balances, {})
        self.assertEqual(led.entries[-1]["kind"], "REJECT")

    def test_malformed_postings(self):
        kh, aud, led = new_ledger()
        d = kh.encrypt(1, "m:D").value
        self.assertEqual(led.post("m1", []).reason, "EMPTY_POSTING")
        self.assertEqual(led.post("m2", [("A", "D", d)]).reason, "MALFORMED_POSTING")
        self.assertEqual(led.post("m3", [("A", "X", d), ("B", "C", d)]).reason,
                         "MALFORMED_POSTING")

    def test_cap_boundary_exactly_45_accepted_plus_one_wei_rejected(self):
        kh, aud, led = run_scenario()          # exactly 45.000000000000000000 %
        self.assertEqual(led.state, F.NORMAL)
        r = borrow(kh, led, "tx3", 1)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "DEBT_CAP_EXCEEDED")
        self.assertEqual(led.state, F.NORMAL)
        self.assertEqual(kh.decrypt(led.balances[F.DEBT_ACCOUNT]), -1_350_000_000 * F.WAD)

    def test_over_leverage_origination_46pct_rejected(self):
        kh, aud, led = new_ledger()
        r = borrow(kh, led, "ol", 1_380_000_000 * F.WAD)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "DEBT_CAP_EXCEEDED")

    def test_breaker_boundary_exactly_48_does_not_freeze(self):
        kh, aud, led = run_scenario()
        ev = 2_812_500_000 * F.WAD             # debt/EV == 0.48 exactly
        r = led.update_ev("ev1", kh.encrypt(ev, "ev1:e").value)
        self.assertTrue(r.ok)
        self.assertEqual(led.state, F.OVER_CAP)

    def test_breaker_trips_one_wei_below_48_boundary(self):
        kh, aud, led = run_scenario()
        ev = 2_812_500_000 * F.WAD - 1
        r = led.update_ev("ev1", kh.encrypt(ev, "ev1:e").value)
        self.assertTrue(r.ok)
        self.assertEqual(led.state, F.FROZEN)

    def test_ev_shock_freezes_and_frozen_is_sticky(self):
        kh, aud, led = run_scenario()
        led.update_ev("shock", kh.encrypt(2_700_000_000 * F.WAD, "shock:e").value)
        self.assertEqual(led.state, F.FROZEN)
        r = borrow(kh, led, "tx9", 1)
        self.assertEqual(r.reason, "STATE_FROZEN")
        led.update_ev("recover", kh.encrypt(F.EV_WAD, "recover:e").value)
        self.assertEqual(led.state, F.FROZEN)            # sticky
        self.assertEqual(borrow(kh, led, "tx10", 1).reason, "STATE_FROZEN")

    def test_over_cap_allows_deleveraging_but_not_borrowing(self):
        kh, aud, led = run_scenario()
        led.update_ev("mark", kh.encrypt(2_900_000_000 * F.WAD, "mark:e").value)
        self.assertEqual(led.state, F.OVER_CAP)
        up = borrow(kh, led, "up", 1)
        self.assertFalse(up.ok)
        self.assertEqual(up.reason, "DEBT_CAP_EXCEEDED")
        d = kh.encrypt(10_000_000 * F.WAD, "rep:D").value
        c = kh.encrypt(10_000_000 * F.WAD, "rep:C").value
        r = led.post("rep", [(F.DEBT_ACCOUNT, "D", d), ("CASH", "C", c)])
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(led.state, F.OVER_CAP)
        # repay enough to return within 45 %: need debt <= 0.45 * 2.9e9 = 1.305e9
        d = kh.encrypt(40_000_000 * F.WAD, "rep2:D").value
        c = kh.encrypt(40_000_000 * F.WAD, "rep2:C").value
        r = led.post("rep2", [(F.DEBT_ACCOUNT, "D", d), ("CASH", "C", c)])
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(led.state, F.NORMAL)

    def test_posting_that_would_cross_breaker_freezes(self):
        kh, aud, led = new_ledger(ev=1_000_000_000 * F.WAD)
        r = borrow(kh, led, "big", 490_000_000 * F.WAD)
        self.assertEqual(r.reason, "CIRCUIT_BREAKER")
        self.assertEqual(led.state, F.FROZEN)

    def test_global_conservation_over_ciphertexts(self):
        kh, aud, led = run_scenario()
        tot = F.he_sum([led.balances[k] for k in sorted(led.balances)]).value
        self.assertTrue(aud.is_zero(tot))


class TestFaultInjection(unittest.TestCase):
    def test_noise_on_inbound_posting_is_caught_by_parity(self):
        kh, aud, led = new_ledger()
        d = kh.encrypt(5 * F.WAD, "n:D").value
        c = F.inject_noise(kh.encrypt(5 * F.WAD, "n:C").value, 0, F.DELTA)
        r = led.post("n", [("CASH", "D", d), (F.DEBT_ACCOUNT, "C", c)])
        self.assertEqual(r.reason, "PARITY_VIOLATION")

    def test_noise_on_live_balance_halts_ledger(self):
        kh, aud, led = run_scenario()
        led.balances["CASH"] = F.inject_noise(led.balances["CASH"], 3, 1)  # benign-size noise: still detected by ciphertext equality
        r = led.audit()
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "STATE_DIVERGENCE")
        self.assertEqual(led.state, F.HALTED)
        self.assertEqual(borrow(kh, led, "after", 1).reason, "STATE_HALTED")
        self.assertEqual(led.update_ev("evx", kh.encrypt(1, "evx:e").value).reason,
                         "STATE_HALTED")

    def test_noise_on_ev_halts_ledger(self):
        kh, aud, led = run_scenario()
        led.ev = F.inject_noise(led.ev, 0, 1)
        r = led.audit()
        self.assertEqual(r.reason, "EV_DIVERGENCE")
        self.assertEqual(led.state, F.HALTED)

    def test_log_tamper_detected(self):
        kh, aud, led = run_scenario()
        led.entries[1]["payload"]["lines"][0]["c"]["c0"][0] ^= 1
        r = led.audit()
        self.assertEqual(r.reason, "ENTRY_TAMPERED")
        self.assertEqual(led.state, F.HALTED)

    def test_broken_chain_detected(self):
        kh, aud, led = run_scenario()
        del led.entries[1]
        self.assertEqual(led.audit().reason, "CHAIN_BROKEN")

    def test_consistent_rewrite_detected_by_replay_and_anchor(self):
        kh, aud, led = run_scenario()
        anchor = led.head()
        # attacker perturbs a logged line and re-hashes the whole chain consistently
        led.entries[1]["payload"]["lines"][0]["c"]["c0"][0] ^= 1
        prev = F.GENESIS_PREV
        for e in led.entries:
            e["prev"] = prev
            e["hash"] = F.entry_hash(prev, e["seq"], e["kind"], e["txid"], e["payload"])
            prev = e["hash"]
        r = led.audit(expected_head=anchor)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "HEAD_MISMATCH")
        kh2, aud2, led2 = run_scenario()
        led2.entries[1]["payload"]["lines"][0]["c"]["c0"][0] ^= 1
        prev = F.GENESIS_PREV
        for e in led2.entries:
            e["prev"] = prev
            e["hash"] = F.entry_hash(prev, e["seq"], e["kind"], e["txid"], e["payload"])
            prev = e["hash"]
        r2 = led2.audit()
        self.assertFalse(r2.ok)
        self.assertIn(r2.reason, ("REPLAY_PARITY", "STATE_DIVERGENCE"))

    def test_cap_not_enforced_detected(self):
        kh, aud, led = run_scenario()
        led.update_ev("mark", kh.encrypt(2_900_000_000 * F.WAD, "mark:e").value)
        led.state = F.NORMAL                  # attacker clears the alarm flag
        self.assertEqual(led.audit().reason, "CAP_NOT_ENFORCED")

    def test_breaker_not_tripped_detected(self):
        kh, aud, led = run_scenario()
        led.update_ev("shock", kh.encrypt(2_700_000_000 * F.WAD, "shock:e").value)
        led.state = F.OVER_CAP
        self.assertEqual(led.audit().reason, "BREAKER_NOT_TRIPPED")

    def test_clean_audit_does_not_halt(self):
        kh, aud, led = run_scenario()
        led.update_ev("mark", kh.encrypt(2_900_000_000 * F.WAD, "mark:e").value)
        self.assertTrue(led.audit().ok)
        self.assertEqual(led.state, F.OVER_CAP)


class TestRing(unittest.TestCase):
    def test_negacyclic_wrap(self):
        a = [0] * F.N
        a[F.N - 1] = 1
        b = [0] * F.N
        b[1] = 1
        r = F._pmul(a, b)
        self.assertEqual(r[0], F.Q - 1)
        self.assertEqual(r[1:], [0] * (F.N - 1))
        c = [0] * F.N
        c[3] = 1
        d = [0] * F.N
        d[4] = 5
        r2 = F._pmul(c, d)
        self.assertEqual(r2[7], 5)
        self.assertEqual(sum(r2) - 5, 0)

    def test_ring_laws(self):
        d = F.Drbg(b"laws", "x")
        a = [d.uniform_q() for _ in range(F.N)]
        b = [d.ternary() for _ in range(F.N)]
        c = [d.small() % F.Q for _ in range(F.N)]
        self.assertEqual(F._pmul(a, b), F._pmul(b, a))
        self.assertEqual(F._pmul(a, F._padd(b, c)), F._padd(F._pmul(a, b), F._pmul(a, c)))
        self.assertEqual(F._padd(a, F._pneg(a)), [0] * F.N)
        self.assertEqual(F._pscale(a, 3), F._padd(F._padd(a, a), a))
        self.assertEqual(F._pscale(a, -1), F._pneg(a))
        self.assertEqual(F._pscale(a, 0), [0] * F.N)
        for v in F._pmul(a, b) + F._pneg(a) + F._pscale(a, -5):
            self.assertTrue(0 <= v < F.Q)

    def test_center_t(self):
        self.assertEqual(F._center_t(F.HALF_T), F.HALF_T)
        self.assertEqual(F._center_t(F.HALF_T + 1), 1 - F.HALF_T)
        self.assertEqual(F._center_t(F.T - 1), -1)
        self.assertEqual(F._center_t(0), 0)
        self.assertEqual(F._center_t(F.T + 5), 5)

    def test_drbg(self):
        a, b = F.Drbg(b"s", "l"), F.Drbg(b"s", "l")
        self.assertEqual(a.bytes(100), b.bytes(100))
        self.assertNotEqual(F.Drbg(b"s", "l").bytes(32), F.Drbg(b"s", "m").bytes(32))
        self.assertNotEqual(F.Drbg(b"s", "l").bytes(32), F.Drbg(b"t", "l").bytes(32))
        d = F.Drbg(b"stat", "x")
        tern = [d.ternary() for _ in range(300)]
        small = [d.small() for _ in range(300)]
        uni = [d.uniform_q() for _ in range(50)]
        self.assertEqual(set(tern), {-1, 0, 1})
        self.assertTrue(set(small) <= set(range(-3, 4)))
        self.assertTrue(len(set(small)) >= 5)
        self.assertTrue(all(0 <= u < F.Q for u in uni))
        self.assertTrue(max(uni).bit_length() > 300)
        x = F.Drbg(b"len", "x")
        self.assertEqual(len(x.bytes(1)), 1)
        self.assertEqual(len(x.bytes(33)), 33)


class TestRlwe(unittest.TestCase):
    def setUp(self):
        self.kh = F.KeyHolder(SEED)
        self.aud = F.BlindedAuditor(self.kh)
        self.k = 0

    def enc(self, v):
        self.k += 1
        r = self.kh.encrypt(v, "e:%d" % self.k)
        self.assertTrue(r.ok, r.reason)
        return r.value

    def test_roundtrip_and_value_bound(self):
        for v in (0, 1, -1, 65536, F.WAD, -F.WAD, F.EV_WAD, -F.EV_WAD, F.VALUE_MAX, -F.VALUE_MAX):
            self.assertEqual(self.kh.decrypt(self.enc(v)), v)
        for v in (F.VALUE_MAX + 1, -F.VALUE_MAX - 1):
            r = self.kh.encrypt(v, "toobig:%d" % (v & 1))
            self.assertEqual((r.ok, r.reason), (False, "VALUE_TOO_LARGE"))

    def test_label_hygiene_and_failed_encrypt_does_not_burn_label(self):
        self.assertTrue(self.kh.encrypt(1, "L").ok)
        self.assertEqual(self.kh.encrypt(1, "L").reason, "LABEL_REUSE")
        self.assertFalse(self.kh.encrypt(F.VALUE_MAX + 1, "M").ok)
        self.assertTrue(self.kh.encrypt(1, "M").ok)

    def test_homomorphic_ops_exact(self):
        xs = [0, 5, -7, 10 ** 27, -(10 ** 25) - 3, F.VALUE_MAX]
        ys = [3, -11, 10 ** 20, 10 ** 24, -F.VALUE_MAX, 1]
        for x, y in zip(xs, ys):
            a, b = self.enc(x), self.enc(y)
            self.assertEqual(self.kh.decrypt(F.he_add(a, b).value), x + y)
            self.assertEqual(self.kh.decrypt(F.he_sub(a, b).value), x - y)
            self.assertEqual(self.kh.decrypt(F.he_neg(a).value), -x)
            self.assertEqual(self.kh.decrypt(F.he_sub(a, a).value), 0)
        for s in (0, 1, -1, 2, -7, F.WAD, -F.WAD, F.CAP_RATIO_WAD, 12345678901234567):
            a = self.enc(10 ** 26 + 7)
            self.assertEqual(self.kh.decrypt(F.he_scale(a, s).value), (10 ** 26 + 7) * s)

    def test_linear_combination_solvency_form(self):
        e, d = 3 * 10 ** 27, 1_350_000_000 * 10 ** 18
        ce, cd = self.enc(e), self.enc(d)
        r = F.he_sub(F.he_scale(ce, F.CAP_RATIO_WAD).value, F.he_scale(cd, F.WAD).value)
        self.assertTrue(r.ok)
        self.assertEqual(self.kh.decrypt(r.value), 0)

    def test_bound_accounting_exact(self):
        a, b = self.enc(1), self.enc(2)
        self.assertEqual((a.nb, a.pb), (F.FRESH_NOISE, F.VALUE_MAX))
        s = F.he_add(a, b).value
        self.assertEqual((s.nb, s.pb), (2 * F.FRESH_NOISE, 2 * F.VALUE_MAX))
        s = F.he_sub(a, b).value
        self.assertEqual((s.nb, s.pb), (2 * F.FRESH_NOISE, 2 * F.VALUE_MAX))
        s = F.he_neg(a).value
        self.assertEqual((s.nb, s.pb), (F.FRESH_NOISE, F.VALUE_MAX))
        for sc in (7, -7):
            s = F.he_scale(a, sc).value
            self.assertEqual((s.nb, s.pb), (7 * F.FRESH_NOISE, 7 * F.VALUE_MAX))
        s = F.he_scale(a, 0).value
        self.assertEqual((s.nb, s.pb), (0, 0))

    def test_tracked_noise_dominates_measured_noise(self):
        a, b = self.enc(10 ** 27), self.enc(-5 * 10 ** 26)
        cands = [a, b, F.he_add(a, b).value, F.he_sub(a, b).value, F.he_neg(a).value,
                 F.he_scale(a, F.WAD).value, F.he_scale(b, -F.CAP_RATIO_WAD).value,
                 F.he_sub(F.he_scale(a, F.BREAKER_RATIO_WAD).value, F.he_scale(b, F.WAD).value).value]
        for ct in cands:
            m = self.kh.noise(ct)
            self.assertTrue(m <= ct.nb, (m, ct.nb))
        self.assertTrue(self.kh.noise(a) > 0)
        self.assertTrue(self.kh.noise(a) <= F.FRESH_NOISE)
        self.assertEqual(self.kh.noise(F.he_scale(a, 0).value), 0)

    def test_headroom_noise_boundary(self):
        a = self.enc(1)
        at = F.Ciphertext(a.c0, a.c1, F.HALF_DELTA, a.pb)
        under = F.Ciphertext(a.c0, a.c1, F.HALF_DELTA - 1, a.pb)
        r = F.he_neg(at)
        self.assertEqual((r.ok, r.reason), (False, "HEADROOM_EXHAUSTED"))
        self.assertTrue(F.he_neg(under).ok)

    def test_headroom_plaintext_boundary(self):
        a = self.enc(1)
        edge = F.HALF_T // F.VALUE_MAX
        self.assertEqual(F.he_scale(a, edge).reason, "HEADROOM_EXHAUSTED")
        ok = F.he_scale(a, edge - 1)
        self.assertTrue(ok.ok)
        self.assertEqual(self.kh.decrypt(ok.value), edge - 1)
        near = F.Ciphertext(a.c0, a.c1, a.nb, F.HALF_T - 1)
        self.assertTrue(F.he_neg(near).ok)
        self.assertFalse(F.he_neg(F.Ciphertext(a.c0, a.c1, a.nb, F.HALF_T)).ok)

    def test_headroom_exhaustion_is_total_and_never_wrong(self):
        ct, exact, failed = self.enc(1), 1, False
        for _ in range(40):
            r = F.he_scale(ct, 1 << 40)
            if not r.ok:
                self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")
                failed = True
                break
            ct = r.value
            exact <<= 40
            self.assertEqual(self.kh.decrypt(ct), exact)
        self.assertTrue(failed)

    def test_he_sum(self):
        vals = [3, -9, 10 ** 20, 7, -(10 ** 19), 11]
        cts = [self.enc(v) for v in vals]
        r = F.he_sum(cts)
        self.assertEqual(self.kh.decrypt(r.value), sum(vals))
        self.assertEqual((r.value.nb, r.value.pb), (6 * F.FRESH_NOISE, 6 * F.VALUE_MAX))
        near = F.Ciphertext(cts[0].c0, cts[0].c1, F.HALF_DELTA - 1, cts[0].pb)
        self.assertEqual(F.he_sum([cts[1], near, cts[2]]).reason, "HEADROOM_EXHAUSTED")
        self.assertEqual(F.he_sum([cts[0]]).value, cts[0])
        self.assertEqual(F.he_sum([]).reason, "EMPTY_SUM")

    def test_semantic_hiding_properties(self):
        a, b = self.enc(77), self.enc(77)
        self.assertNotEqual(a.c0, b.c0)
        self.assertNotEqual(a.c1, b.c1)
        self.assertFalse(self.kh.decrypt(F.he_sub(a, b).value))
        trivial = [0] * F.N
        trivial[0] = F.DELTA * 77
        self.assertNotEqual(list(a.c0), trivial)
        other = F.KeyHolder(SEED + b"-other")
        self.assertNotEqual(other.decrypt(a), 77)
        self.assertNotEqual(F.KeyHolder(SEED + b"2").pk, self.kh.pk)
        self.assertTrue(max(a.c1).bit_length() > 300)

    def test_determinism_and_serialisation(self):
        a = F.KeyHolder(SEED).encrypt(42, "d:0").value
        b = F.KeyHolder(SEED).encrypt(42, "d:0").value
        c = F.KeyHolder(SEED + b"x").encrypt(42, "d:0").value
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        self.assertNotEqual(a, c)
        back = F.Ciphertext.from_dict(json.loads(json.dumps(a.to_dict())))
        self.assertEqual(back, a)
        self.assertEqual(self.kh.decrypt(back), 42)
        self.assertFalse(a != b)
        self.assertNotEqual(a, "not a ciphertext")
        for field in ("c0", "c1"):
            d = a.to_dict()
            d[field][0] ^= 1
            self.assertNotEqual(F.Ciphertext.from_dict(d), a)
        for field in ("n", "p"):
            d = a.to_dict()
            d[field] += 1
            self.assertNotEqual(F.Ciphertext.from_dict(d), a)

    def test_inject_noise_semantics(self):
        ct = self.enc(10 ** 25)
        base_noise = self.kh.noise(ct)
        benign = F.inject_noise(ct, 0, 1)
        self.assertEqual(self.kh.decrypt(benign), 10 ** 25)
        self.assertNotEqual(benign, ct)
        self.assertEqual((benign.nb, benign.pb, benign.c1), (ct.nb, ct.pb, ct.c1))
        self.assertEqual(self.kh.noise(F.inject_noise(ct, 0, 0)), base_noise)
        shifted = F.inject_noise(ct, 0, F.DELTA)
        self.assertEqual(self.kh.decrypt(shifted), 10 ** 25 + 1)
        self.assertEqual(self.kh.decrypt(F.inject_noise(ct, 0, -F.DELTA)), 10 ** 25 - 1)
        far = F.inject_noise(ct, 5, F.DELTA)             # non-constant coefficient
        self.assertEqual(self.kh.decrypt(far), 10 ** 25)
        self.assertNotEqual(far.c0, ct.c0)
        self.assertEqual([i for i in range(F.N) if far.c0[i] != ct.c0[i]], [5])
        wrapped = F.inject_noise(ct, 2, F.Q - 1)
        self.assertEqual(wrapped.c0[2], (ct.c0[2] - 1) % F.Q)
        self.assertTrue(all(0 <= c < F.Q for c in wrapped.c0))
        big = F.inject_noise(ct, 0, F.HALF_DELTA)       # noise at the decoding edge
        self.assertNotEqual(self.kh.decrypt(big), 10 ** 25)

    def test_sign_and_zero_oracle(self):
        for v, want in ((1, 1), (2, 1), (-1, -1), (-2, -1), (0, 0)):
            self.assertEqual(self.aud.sign(self.enc(v)), want)
        self.assertTrue(self.aud.is_zero(self.enc(0)))
        self.assertFalse(self.aud.is_zero(self.enc(-1)))
        self.assertEqual(self.aud.query_log, ["sign"] * 5 + ["zero"] * 2)


class TestRlweLedgerExtras(unittest.TestCase):
    def test_post_rejects_when_sums_exceed_headroom(self):
        kh, aud, led = new_ledger(tag="hs")
        c = kh.encrypt(1, "hs:C").value
        d = kh.encrypt(1, "hs:D").value
        big = F.Ciphertext(d.c0, d.c1, F.HALF_DELTA - 1, d.pb)
        r = led.post("hs", [("A", "D", big), ("A", "D", big), ("B", "C", c)])
        self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")
        r = led.post("hs2", [("A", "D", d), ("B", "C", big), ("B", "C", big)])
        self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")
        self.assertEqual(led.balances, {})

    def test_over_cap_allows_debt_neutral_posting(self):
        kh, aud, led = run_scenario()
        led.update_ev("mark", kh.encrypt(2_900_000_000 * F.WAD, "mark:e").value)
        d = kh.encrypt(5 * F.WAD, "mv:D").value
        c = kh.encrypt(5 * F.WAD, "mv:C").value
        r = led.post("mv", [("TREASURY", "D", d), ("CASH", "C", c)])
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(led.state, F.OVER_CAP)

    def test_ev_remark_state_transitions(self):
        kh, aud, led = run_scenario()
        r = led.update_ev("up", kh.encrypt(3_100_000_000 * F.WAD, "up:e").value)
        self.assertEqual((r.ok, r.value, led.state), (True, F.NORMAL, F.NORMAL))
        led.update_ev("dn", kh.encrypt(2_900_000_000 * F.WAD, "dn:e").value)
        self.assertEqual(led.state, F.OVER_CAP)
        r = led.update_ev("rec", kh.encrypt(3_100_000_000 * F.WAD, "rec:e").value)
        self.assertEqual((r.value, led.state), (F.NORMAL, F.NORMAL))

    def test_ev_update_without_debt_keeps_state(self):
        kh, aud, led = new_ledger(tag="nd")
        r = led.update_ev("e1", kh.encrypt(5, "e1:e").value)
        self.assertEqual((r.ok, r.value), (True, F.NORMAL))

    def test_chain_reason_specificity(self):
        kh, aud, led = run_scenario()
        led.entries[1]["seq"] = 7
        self.assertEqual(led.audit().reason, "CHAIN_BROKEN")
        kh, aud, led = run_scenario()
        led.entries[2]["prev"] = "0" * 64
        self.assertEqual(led.audit().reason, "CHAIN_BROKEN")

    def test_audit_without_debt_account(self):
        kh, aud, led = new_ledger(tag="ad")
        self.assertTrue(led.audit().ok)
        d = kh.encrypt(9, "ad:D").value
        c = kh.encrypt(9, "ad:C").value
        self.assertTrue(led.post("ad", [("X", "D", d), ("Y", "C", c)]).ok)
        self.assertTrue(led.audit().ok)
        self.assertEqual(led.state, F.NORMAL)

    def test_parity_only_forgery_is_named_replay_parity(self):
        kh, aud, led = run_scenario()
        e = led.entries[1]
        ln = e["payload"]["lines"][1]["c"]
        ln["c0"][0] = (ln["c0"][0] + F.DELTA) % F.Q          # credit now exceeds debit by 1
        prev = F.GENESIS_PREV
        for x in led.entries:
            x["prev"] = prev
            x["hash"] = F.entry_hash(prev, x["seq"], x["kind"], x["txid"], x["payload"])
            prev = x["hash"]
        led.balances[F.DEBT_ACCOUNT] = F.inject_noise(led.balances[F.DEBT_ACCOUNT], 0, -F.DELTA)
        r = led.audit()
        self.assertEqual(r.reason, "REPLAY_PARITY")
        self.assertEqual(led.state, F.HALTED)

    def test_benign_noise_on_logged_line_is_state_divergence_not_parity(self):
        kh, aud, led = run_scenario()
        led.entries[1]["payload"]["lines"][0]["c"]["c0"][0] ^= 1
        prev = F.GENESIS_PREV
        for x in led.entries:
            x["prev"] = prev
            x["hash"] = F.entry_hash(prev, x["seq"], x["kind"], x["txid"], x["payload"])
            prev = x["hash"]
        self.assertEqual(led.audit().reason, "STATE_DIVERGENCE")

    def test_global_parity_detects_balance_swap_forgery(self):
        kh, aud, led = run_scenario()
        led.balances["CASH"] = F.inject_noise(led.balances["CASH"], 0, F.DELTA)
        self.assertEqual(led.audit().reason, "STATE_DIVERGENCE")


class TestMutationHardeningRlwe(unittest.TestCase):
    def test_measured_noise_sees_negative_and_positive_error(self):
        kh = F.KeyHolder(SEED + b"-noise")
        zero = F.he_scale(kh.encrypt(1, "z").value, 0).value      # all-zero ciphertext
        self.assertEqual(kh.noise(zero), 0)
        for delta in (5, -5, 1, -1):
            self.assertEqual(kh.noise(F.inject_noise(zero, 0, delta)), abs(delta))
        two = F.inject_noise(F.inject_noise(zero, 0, -9), 3, 4)
        self.assertEqual(kh.noise(two), 9)
        two = F.inject_noise(F.inject_noise(zero, 0, 9), 3, -4)
        self.assertEqual(kh.noise(two), 9)

    def test_global_sum_headroom_halts_with_named_reason(self):
        kh, aud, led = new_ledger(tag="gs")
        x = F.HALF_DELTA // 4 + 1                 # one posting fits, the global sum does not
        def forged(v, label):
            c = kh.encrypt(v, label).value
            return F.Ciphertext(c.c0, c.c1, x, c.pb)
        for k in (1, 2):
            r = led.post("gs%d" % k, [("A", "D", forged(5, "gd%d" % k)),
                                      ("B", "C", forged(5, "gc%d" % k))])
            self.assertTrue(r.ok, r.reason)
        a = led.audit()
        self.assertEqual((a.ok, a.reason), (False, "GLOBAL_PARITY"))
        self.assertEqual(led.state, F.HALTED)

    def test_forged_log_with_overflowing_credit_sum_halts_not_crashes(self):
        kh, aud, led = run_scenario()
        x = F.HALF_DELTA - 1
        def forged(v, label):
            c = kh.encrypt(v, label).value
            return F.Ciphertext(c.c0, c.c1, x, c.pb).to_dict()
        led.entries[1]["payload"]["lines"] = [
            {"a": "A", "s": "D", "c": forged(5, "f1")},
            {"a": "B", "s": "C", "c": forged(3, "f2")},
            {"a": "C", "s": "C", "c": forged(2, "f3")}]
        prev = F.GENESIS_PREV
        for e in led.entries:
            e["prev"] = prev
            e["hash"] = F.entry_hash(prev, e["seq"], e["kind"], e["txid"], e["payload"])
            prev = e["hash"]
        r = led.audit()
        self.assertEqual((r.ok, r.reason), (False, "REPLAY_HEADROOM"))
        self.assertEqual(led.state, F.HALTED)


class TestLedgerHardeningRev2(LedgerHardeningMixin, unittest.TestCase):
    F = F
    LIMIT = F.HALF_DELTA
    new_ledger = staticmethod(new_ledger)
    borrow = staticmethod(borrow)
    run_scenario = staticmethod(run_scenario)

    def forge(self, ct, bound):
        return F.Ciphertext(ct.c0, ct.c1, bound, ct.pb)

    def forge_dict(self, d, bound):
        d["n"] = bound

    def scale(self, s):
        return abs(s)


class TestRlweSurvivorKillers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kh = F.KeyHolder(SEED + b"-sk")
        cls.aud = F.BlindedAuditor(cls.kh)

    def ct(self, v, label):
        return self.kh.encrypt(v, label).value

    def test_center_t_reduces_modulo_t_first(self):
        T, H = F.T, F.HALF_T
        self.assertEqual(F._center_t(0), 0)
        self.assertEqual(F._center_t(T), 0)
        self.assertEqual(F._center_t(2 * T + 1), 1)
        self.assertEqual(F._center_t(-1), -1)
        self.assertEqual(F._center_t(H), H)
        self.assertEqual(F._center_t(H + 1), H + 1 - T)

    def test_ciphertext_is_slotted(self):
        c = self.ct(1, "sl")
        self.assertEqual(F.Ciphertext.__slots__, ("c0", "c1", "nb", "pb"))
        with self.assertRaises(AttributeError):
            c.extra = 1
        self.assertFalse(hasattr(c, "__dict__"))

    def test_equality_compares_every_field_in_both_directions(self):
        base = F.Ciphertext([1] * F.N, [2] * F.N, 5, 7)
        same = F.Ciphertext([1] * F.N, [2] * F.N, 5, 7)
        self.assertTrue(base == same)
        self.assertFalse(base != same)
        self.assertEqual(hash(base), hash(same))
        variants = [
            F.Ciphertext([2] + [1] * (F.N - 1), [2] * F.N, 5, 7),
            F.Ciphertext([0] + [1] * (F.N - 1), [2] * F.N, 5, 7),
            F.Ciphertext([1] * F.N, [3] + [2] * (F.N - 1), 5, 7),
            F.Ciphertext([1] * F.N, [1] + [2] * (F.N - 1), 5, 7),
            F.Ciphertext([1] * F.N, [2] * F.N, 6, 7),
            F.Ciphertext([1] * F.N, [2] * F.N, 4, 7),
            F.Ciphertext([1] * F.N, [2] * F.N, 5, 8),
            F.Ciphertext([1] * F.N, [2] * F.N, 5, 6),
        ]
        for v in variants:
            self.assertFalse(base == v)
            self.assertFalse(v == base)
            self.assertTrue(base != v)
        self.assertFalse(base == (base.c0, base.c1, 5, 7))

    def test_check_bounds_are_strict_at_the_exact_edge(self):
        z = [0] * F.N
        for nb, pb, ok in ((F.HALF_DELTA - 1, 0, True), (F.HALF_DELTA, 0, False), (F.HALF_DELTA + 1, 0, False),
                           (0, F.HALF_T - 1, True), (0, F.HALF_T, False), (0, F.HALF_T + 1, False),
                           (F.HALF_DELTA + 1, F.HALF_T + 1, False)):
            r = F._check(z, z, nb, pb)
            self.assertEqual(r.ok, ok, (nb, pb))
            if not ok:
                self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")

    def test_he_scale_bounds_use_absolute_scalar(self):
        c = self.ct(3, "sc")
        for s in (-1, 1, -2, 2, 0, -7):
            r = F.he_scale(c, s)
            self.assertTrue(r.ok)
            self.assertEqual((r.value.nb, r.value.pb), (c.nb * abs(s), c.pb * abs(s)))
            self.assertEqual(self.kh.decrypt(r.value), 3 * s)

    def test_is_zero_and_sign_distinguish_all_signs(self):
        for v, z, sg in ((0, True, 0), (5, False, 1), (-5, False, -1), (1, False, 1)):
            c = self.ct(v, "z%d" % v)
            self.assertIs(self.aud.is_zero(c), z)
            self.assertEqual(self.aud.sign(c), sg)

    def test_noise_is_exact_measured_infinity_norm(self):
        c = self.ct(9, "nz")
        n = self.kh.noise(c)
        self.assertTrue(0 < n <= c.nb)
        manual = max(abs(x - ((x + F.HALF_DELTA) // F.DELTA) * F.DELTA) for x in self.kh._phase(c))
        self.assertEqual(n, manual)
        zero = F.Ciphertext([0] * F.N, [0] * F.N, 0, 0)
        self.assertEqual(self.kh.noise(zero), 0)
        shifted = F.Ciphertext([F.DELTA] + [0] * (F.N - 1), [0] * F.N, 0, 1)
        self.assertEqual(self.kh.noise(shifted), 0)
        off = F.Ciphertext([F.DELTA + 5] + [0] * (F.N - 1), [0] * F.N, 0, 1)
        self.assertEqual(self.kh.noise(off), 5)
        neg = F.Ciphertext([F.DELTA - 5] + [0] * (F.N - 1), [0] * F.N, 0, 1)
        self.assertEqual(self.kh.noise(neg), 5)


class TestReproducibility(unittest.TestCase):
    GOLDEN_HEAD = "ae608abb977d720b4bfa4ef6e32de91f0bdf1e439d46de21ba00ff4f333dbdfd"

    def test_two_runs_identical_head_and_entries(self):
        a, b = run_scenario()[2], run_scenario()[2]
        self.assertEqual(a.head(), b.head())
        self.assertEqual(a.entries, b.entries)

    def test_golden_head_pin(self):
        self.assertEqual(run_scenario()[2].head(), self.GOLDEN_HEAD)

    def test_no_plaintext_amount_in_log(self):
        text = repr(run_scenario()[2].entries)
        for needle in (str(F.EV_WAD), str(1_000_000_000 * F.WAD), str(350_000_000 * F.WAD)):
            self.assertNotIn(needle, text)


if __name__ == "__main__":
    unittest.main()
