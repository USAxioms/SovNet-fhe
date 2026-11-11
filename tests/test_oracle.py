"""FHE-WAD18 Cryptographic Test Oracle Suite (stdlib unittest, integer-only).

Run:  python -m unittest test_oracle -v
Includes built-in fault injection (ciphertext noise, log tampering, over-leverage).
"""
import ast
import os
import unittest

import fhe_wad18 as F
from ledger_hardening import LedgerHardeningMixin

SEED = b"FHE-WAD18-TEST-SEED-0001"
HERE = os.path.dirname(os.path.abspath(__file__))
SRC_DIRS = [HERE] + [d for d in (os.path.join(HERE, "..", "src"),) if os.path.isdir(d)]
MUL = 6364136223846793005
INC = 1442695040888963407


def lcg(n, seed=12345):
    x, out = seed, []
    for _ in range(n):
        x = (x * MUL + INC) % (1 << 64)
        out.append(x)
    return out


def signed_vals(n, seed=12345):
    r = lcg(2 * n, seed)
    out = []
    for i in range(n):
        v = (r[2 * i] << 60) ^ r[2 * i + 1]
        out.append(-v if r[2 * i] & 1 else v)
    return out


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
        self.assertIn("fhe_wad18.py", files)
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


class TestConstants(unittest.TestCase):
    def test_constants_bit_exact(self):
        self.assertEqual(F.WAD, 1000000000000000000)
        self.assertEqual(F.HE_MODULUS, 9223372036854775807)
        self.assertEqual(F.EV_WAD, 3000000000000000000000000000)
        self.assertEqual(F.CAP_RATIO_WAD, 450000000000000000)
        self.assertEqual(F.BREAKER_RATIO_WAD, 480000000000000000)
        self.assertEqual(F.HALF, 4611686018427387903)
        self.assertEqual((F.LIMB_BITS, F.N_LIMBS), (16, 16))
        for v in (F.WAD, F.HE_MODULUS, F.EV_WAD, F.CAP_RATIO_WAD, F.BREAKER_RATIO_WAD):
            self.assertIs(type(v), int)


class TestRing(unittest.TestCase):
    def setUp(self):
        self.kh = F.KeyHolder(SEED)

    def enc(self, v, label):
        r = self.kh.encrypt(v, label)
        self.assertTrue(r.ok, r.reason)
        return r.value

    def test_roundtrip(self):
        vals = [0, 1, -1, 65535, 65536, -65536, F.WAD, F.EV_WAD, -F.EV_WAD,
                (1 << 255), -(1 << 255)] + signed_vals(20)
        for i, v in enumerate(vals):
            self.assertEqual(self.kh.decrypt(self.enc(v, "rt:%d" % i)), v)

    def test_too_large_rejected(self):
        r = self.kh.encrypt(1 << 256, "big:0")
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "VALUE_TOO_LARGE")

    def test_additive_blinding_formula(self):
        v = 123456789
        ct = self.enc(v, "form:0")
        key = F.derive_key_limbs(SEED, "form:0")
        digits = F._digits(v) + [0] * (F.N_LIMBS - len(F._digits(v)))
        for i in range(F.N_LIMBS):
            self.assertEqual(ct.limbs[i], (digits[i] + key[i]) % F.HE_MODULUS)
        self.assertEqual(sum(d << (16 * i) for i, d in enumerate(digits)), v)
        self.assertNotEqual(ct.limbs[0], digits[0])

    def test_homomorphic_add_sub_neg(self):
        xs, ys = signed_vals(15, 1), signed_vals(15, 2)
        for i, (x, y) in enumerate(zip(xs, ys)):
            a, b = self.enc(x, "a:%d" % i), self.enc(y, "b:%d" % i)
            self.assertEqual(self.kh.decrypt(F.he_add(a, b).value), x + y)
            self.assertEqual(self.kh.decrypt(F.he_sub(a, b).value), x - y)
            self.assertEqual(self.kh.decrypt(F.he_neg(a).value), -x)
            self.assertEqual(self.kh.decrypt(F.he_sub(a, a).value), 0)

    def test_scalar_scaling_bit_exact(self):
        xs = signed_vals(10, 3)
        ss = [0, 1, -1, 2, -7, F.WAD, -F.WAD, F.CAP_RATIO_WAD, 12345678901234567890123]
        k = 0
        for x in xs:
            for s in ss:
                ct = self.enc(x, "sc:%d" % k)
                k += 1
                r = F.he_scale(ct, s)
                self.assertTrue(r.ok, r.reason)
                self.assertEqual(self.kh.decrypt(r.value), x * s)

    def test_scale_then_add_linear_combination(self):
        x, y = 10 ** 27 + 7, 3 * 10 ** 26 + 11
        a, b = self.enc(x, "lc:a"), self.enc(y, "lc:b")
        left = F.he_scale(a, F.CAP_RATIO_WAD).value
        right = F.he_scale(b, F.WAD).value
        self.assertEqual(self.kh.decrypt(F.he_sub(left, right).value),
                         x * F.CAP_RATIO_WAD - y * F.WAD)

    def test_headroom_exhaustion_is_total_and_never_wrong(self):
        ct = self.enc(1, "hr:0")
        exact, failed = 1, False
        for _ in range(40):
            r = F.he_scale(ct, 1 << 90)
            if not r.ok:
                self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")
                failed = True
                break
            ct = r.value
            exact <<= 90
            self.assertEqual(self.kh.decrypt(ct), exact)
        self.assertTrue(failed)

    def test_determinism_and_label_hygiene(self):
        a = F.KeyHolder(SEED).encrypt(42, "d:0").value
        b = F.KeyHolder(SEED).encrypt(42, "d:0").value
        c = F.KeyHolder(SEED + b"x").encrypt(42, "d:0").value
        self.assertEqual(a, b)
        self.assertEqual(a.to_dict(), b.to_dict())
        self.assertNotEqual(a, c)
        kh = F.KeyHolder(SEED)
        self.assertTrue(kh.encrypt(1, "u:0").ok)
        r = kh.encrypt(1, "u:0")
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "LABEL_REUSE")

    def test_equal_plaintexts_have_distinct_ciphertexts(self):
        a, b = self.enc(77, "eq:a"), self.enc(77, "eq:b")
        self.assertNotEqual(a.limbs, b.limbs)
        self.assertFalse(self.kh.decrypt(F.he_sub(a, b).value))

    def test_empty_sum_total(self):
        self.assertFalse(F.he_sum([]).ok)


class TestAuditorOracle(unittest.TestCase):
    def test_sign_and_zero_bits_only(self):
        kh = F.KeyHolder(SEED)
        aud = F.BlindedAuditor(kh)
        pos = kh.encrypt(5, "s:p").value
        neg = kh.encrypt(-5, "s:n").value
        zero = kh.encrypt(0, "s:z").value
        self.assertEqual((aud.sign(pos), aud.sign(neg), aud.sign(zero)), (1, -1, 0))
        self.assertTrue(aud.is_zero(zero))
        self.assertFalse(aud.is_zero(pos))
        self.assertEqual(aud.query_log, ["sign", "sign", "sign", "zero", "zero"])


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
        c = F.inject_noise(kh.encrypt(5 * F.WAD, "n:C").value, 0, 1)
        r = led.post("n", [("CASH", "D", d), (F.DEBT_ACCOUNT, "C", c)])
        self.assertEqual(r.reason, "PARITY_VIOLATION")

    def test_noise_on_live_balance_halts_ledger(self):
        kh, aud, led = run_scenario()
        led.balances["CASH"] = F.inject_noise(led.balances["CASH"], 3, 1)
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
        led.entries[1]["payload"]["lines"][0]["c"]["l"][0] ^= 1
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
        led.entries[1]["payload"]["lines"][0]["c"]["l"][0] ^= 1
        prev = F.GENESIS_PREV
        for e in led.entries:
            e["prev"] = prev
            e["hash"] = F.entry_hash(prev, e["seq"], e["kind"], e["txid"], e["payload"])
            prev = e["hash"]
        r = led.audit(expected_head=anchor)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "HEAD_MISMATCH")
        kh2, aud2, led2 = run_scenario()
        led2.entries[1]["payload"]["lines"][0]["c"]["l"][0] ^= 1
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


class TestMutationHardening(unittest.TestCase):
    """Targeted oracles that pin boundary / accounting behaviour."""

    def setUp(self):
        self.kh = F.KeyHolder(SEED + b"-mh")
        self.aud = F.BlindedAuditor(self.kh)

    def enc(self, v, label):
        return self.kh.encrypt(v, label).value

    def test_add_of_unequal_length_polynomials(self):
        x = 10 ** 27 + 12345
        a = self.enc(x, "ue:a")
        scaled = F.he_scale(a, F.WAD).value          # longer limbs and term poly
        self.assertNotEqual(len(a.limbs), len(scaled.limbs))
        for left, right, want in ((a, scaled, x + x * F.WAD),
                                  (scaled, a, x + x * F.WAD)):
            r = F.he_add(left, right)
            self.assertTrue(r.ok)
            self.assertEqual(self.kh.decrypt(r.value), want)
            self.assertEqual(len(r.value.limbs), len(scaled.limbs))

    def test_polynomial_length_structure(self):
        a = self.enc(5, "pl:a")
        d = F._digits(F.WAD)
        r = F.he_scale(a, F.WAD).value
        self.assertEqual(len(r.limbs), F.N_LIMBS + len(d) - 1)
        self.assertEqual(len(r.terms[0][1]), len(d))

    def test_bound_accounting_exact(self):
        a, b = self.enc(1, "ba:a"), self.enc(2, "ba:b")
        self.assertEqual(a.bound, F.LIMB_MASK)
        self.assertEqual(F.he_add(a, b).value.bound, 2 * F.LIMB_MASK)
        self.assertEqual(F.he_sub(a, b).value.bound, 2 * F.LIMB_MASK)
        self.assertEqual(F.he_neg(a).value.bound, F.LIMB_MASK)
        self.assertEqual(F.he_scale(a, 7).value.bound, 7 * F.LIMB_MASK)
        self.assertEqual(F.he_scale(a, -7).value.bound, 7 * F.LIMB_MASK)
        self.assertEqual(F.he_scale(a, 0).value.bound, 0)
        self.assertEqual(F.he_scale(a, -F.WAD).value.bound,
                         F.he_scale(a, F.WAD).value.bound)
        self.assertEqual(F._abs_sum([-3, 4, 0, -5]), 12)

    def test_headroom_boundary_is_exclusive_of_half(self):
        a = self.enc(1, "hb:a")
        at = F.Ciphertext(a.limbs, dict(a.terms), F.HALF)
        under = F.Ciphertext(a.limbs, dict(a.terms), F.HALF - 1)
        r = F.he_neg(at)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")
        self.assertTrue(F.he_neg(under).ok)

    def test_he_sum_many_and_failure_propagation(self):
        vals = [3, -9, 10 ** 20, 7, -(10 ** 19), 11]
        cts = [self.enc(v, "sm:%d" % i) for i, v in enumerate(vals)]
        r = F.he_sum(cts)
        self.assertTrue(r.ok)
        self.assertEqual(self.kh.decrypt(r.value), sum(vals))
        self.assertEqual(r.value.bound, len(vals) * F.LIMB_MASK)
        near = F.Ciphertext(cts[0].limbs, dict(cts[0].terms), F.HALF - 1)
        bad = F.he_sum([cts[1], near, cts[2]])
        self.assertFalse(bad.ok)
        self.assertEqual(bad.reason, "HEADROOM_EXHAUSTED")
        one = F.he_sum([cts[0]])
        self.assertTrue(one.ok)
        self.assertEqual(one.value, cts[0])

    def test_inject_noise_semantics(self):
        ct = self.enc(10 ** 25, "in:a")
        base = self.kh.decrypt(ct)
        for idx in (0, 1, 5):
            for delta in (1, 7, -3):
                noisy = F.inject_noise(ct, idx, delta)
                self.assertEqual(self.kh.decrypt(noisy) - base, delta << (16 * idx))
                self.assertEqual(noisy.terms, ct.terms)
                self.assertEqual(noisy.bound, ct.bound)
        wrapped = F.inject_noise(ct, 2, F.HE_MODULUS - 1)
        self.assertEqual(wrapped.limbs[2], (ct.limbs[2] - 1) % F.HE_MODULUS)
        for c in wrapped.limbs:
            self.assertTrue(0 <= c < F.HE_MODULUS)
        self.assertNotEqual(ct.limbs, F.inject_noise(ct, 0, 1).limbs)

    def test_decrypt_balanced_representative_boundary(self):
        key = F.derive_key_limbs(SEED + b"-mh", "bal:0")
        for plain, want in ((F.HALF, F.HALF), (-F.HALF, -F.HALF), (F.HALF + 1, -F.HALF)):
            limbs = [(plain + key[0]) % F.HE_MODULUS] + [k % F.HE_MODULUS for k in key[1:]]
            ct = F.Ciphertext(limbs, {"bal:0": [1]}, 1)
            self.assertEqual(self.kh.decrypt(ct), want)

    def test_sign_oracle_unit_values(self):
        for v, want in ((1, 1), (2, 1), (-1, -1), (-2, -1), (0, 0)):
            self.assertEqual(self.aud.sign(self.enc(v, "sg:%d" % v)), want)
        self.assertTrue(self.aud.is_zero(self.enc(0, "sg:z")))
        self.assertFalse(self.aud.is_zero(self.enc(-1, "sg:m")))

    def test_digits_edge_cases(self):
        self.assertEqual(F._digits(0), [0])
        self.assertEqual(F._digits(65535), [65535])
        self.assertEqual(F._digits(65536), [0, 1])
        self.assertEqual(F._digits(-65536), [0, -1])
        self.assertEqual(F._digits(-1), [-1])
        self.assertEqual(F._padd([1, 2], [10]), [11, 2])
        self.assertEqual(F._padd([10], [1, 2]), [11, 2])
        self.assertEqual(F._pmul([1, 2], [3, 4]), [3, 10, 8])

    def test_post_rejects_when_debit_sum_exceeds_headroom(self):
        kh, aud, led = new_ledger(tag="hs")
        c = kh.encrypt(1, "hs:C").value
        d = kh.encrypt(1, "hs:D").value
        big = F.Ciphertext(d.limbs, dict(d.terms), F.HALF - 1)
        r = led.post("hs", [("A", "D", big), ("A", "D", big), ("B", "C", c)])
        self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")
        r = led.post("hs2", [("A", "D", d), ("B", "C", big), ("B", "C", big)])
        self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")
        self.assertEqual(led.balances, {})

    def test_over_cap_allows_debt_neutral_posting(self):
        kh, aud, led = run_scenario()
        led.update_ev("mark", kh.encrypt(2_900_000_000 * F.WAD, "mark:e").value)
        self.assertEqual(led.state, F.OVER_CAP)
        d = kh.encrypt(5 * F.WAD, "mv:D").value
        c = kh.encrypt(5 * F.WAD, "mv:C").value
        r = led.post("mv", [("TREASURY", "D", d), ("CASH", "C", c)])
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(led.state, F.OVER_CAP)

    def test_ev_remark_state_transitions(self):
        kh, aud, led = run_scenario()                       # exactly 45 %
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

    def test_audit_without_debt_account_and_empty_ledger(self):
        kh, aud, led = new_ledger(tag="ad")
        self.assertTrue(led.audit().ok)
        d = kh.encrypt(9, "ad:D").value
        c = kh.encrypt(9, "ad:C").value
        self.assertTrue(led.post("ad", [("X", "D", d), ("Y", "C", c)]).ok)
        r = led.audit()
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(led.state, F.NORMAL)

    def test_parity_only_forgery_is_named_replay_parity(self):
        kh, aud, led = run_scenario()
        e = led.entries[1]
        e["payload"]["lines"][1]["c"]["l"][0] = (e["payload"]["lines"][1]["c"]["l"][0] + 1) % F.HE_MODULUS
        prev = F.GENESIS_PREV
        for x in led.entries:
            x["prev"] = prev
            x["hash"] = F.entry_hash(prev, x["seq"], x["kind"], x["txid"], x["payload"])
            prev = x["hash"]
        led.balances[F.DEBT_ACCOUNT] = F.inject_noise(led.balances[F.DEBT_ACCOUNT], 0, -1)
        # tx1's credit line was nudged by +1; keep live balance consistent with the replay
        r = led.audit()
        self.assertEqual(r.reason, "REPLAY_PARITY")
        self.assertEqual(led.state, F.HALTED)


class TestLedgerHardeningRev1(LedgerHardeningMixin, unittest.TestCase):
    F = F
    LIMIT = F.HALF
    new_ledger = staticmethod(new_ledger)
    borrow = staticmethod(borrow)
    run_scenario = staticmethod(run_scenario)

    def forge(self, ct, bound):
        return F.Ciphertext(ct.limbs, dict(ct.terms), bound)

    def forge_dict(self, d, bound):
        d["b"] = bound

    def scale(self, s):
        return F._abs_sum(F._digits(s))


class TestRev1CiphertextHardening(unittest.TestCase):
    def setUp(self):
        self.kh = F.KeyHolder(SEED + b"-h1")

    def enc(self, v, label):
        return self.kh.encrypt(v, label).value

    def test_ciphertext_is_slotted(self):
        ct = self.enc(1, "s")
        with self.assertRaises(AttributeError):
            ct.extra = 1
        self.assertEqual(F.Ciphertext.__slots__, ("limbs", "terms", "bound"))

    def test_equality_compares_every_field_in_both_directions(self):
        a = F.Ciphertext([1, 2], {"k": [1]}, 5)
        self.assertEqual(a, F.Ciphertext([1, 2], {"k": [1]}, 5))
        others = [F.Ciphertext([1, 3], {"k": [1]}, 5), F.Ciphertext([1, 1], {"k": [1]}, 5),
                  F.Ciphertext([1, 2], {"k": [2]}, 5), F.Ciphertext([1, 2], {"k": [0]}, 5),
                  F.Ciphertext([1, 2], {"j": [1]}, 5), F.Ciphertext([1, 2], {"l": [1]}, 5),
                  F.Ciphertext([1, 2], {"k": [1]}, 6), F.Ciphertext([1, 2], {"k": [1]}, 4)]
        for o in others:
            self.assertNotEqual(a, o)
            self.assertNotEqual(o, a)
            self.assertFalse(a == o)
            self.assertTrue(a != o)
        self.assertNotEqual(a, "x")
        self.assertNotEqual(a, None)

    def test_hash_is_an_int_consistent_with_equality(self):
        a = F.Ciphertext([1, 2], {"k": [1]}, 5)
        b = F.Ciphertext([1, 2], {"k": [1]}, 5)
        self.assertIs(type(hash(a)), int)
        self.assertEqual(hash(a), hash(b))
        self.assertEqual(len({a, b}), 1)
        self.assertEqual(len({a, F.Ciphertext([1, 2], {"k": [1]}, 6)}), 2)

    def test_zero_polynomials_are_pruned_from_terms(self):
        a = self.enc(5, "p:a")
        self.assertEqual(F.he_sub(a, a).value.terms, ())
        self.assertEqual(F.he_scale(a, 0).value.terms, ())
        self.assertEqual(F.he_add(a, F.he_neg(a).value).value.terms, ())
        b = self.enc(7, "p:b")
        self.assertEqual(len(F.he_add(a, b).value.terms), 2)

    def test_scale_by_minus_one_and_small_digits_have_positive_bounds(self):
        a = self.enc(1, "m:a")
        for s, want in ((-1, 1), (1, 1), (-2, 2), (-65535, 65535), (-65536, 1), (65537, 2), (-65537, 2)):
            r = F.he_scale(a, s)
            self.assertEqual(r.value.bound, F.LIMB_MASK * want, s)
        self.assertEqual(F._abs_sum([-1]), 1)
        self.assertEqual(F._abs_sum([1, -1, 0]), 2)

    def test_decrypt_is_total_on_forged_term_polynomials(self):
        ct = self.enc(9, "t:a")
        long_poly = [1] + [0] * 40
        forged = F.Ciphertext(ct.limbs, {"t:a": long_poly}, ct.bound)
        self.assertEqual(self.kh.decrypt(forged), self.kh.decrypt(ct))
        longer = F.Ciphertext(ct.limbs, {"t:a": [1] + [0] * (F.N_LIMBS + 5)}, ct.bound)
        self.assertEqual(self.kh.decrypt(longer), 9)
        exact = F.Ciphertext(ct.limbs, {"t:a": [1] + [0] * (F.N_LIMBS - 1)}, ct.bound)
        self.assertEqual(self.kh.decrypt(exact), 9)

    def test_digits_exact_values(self):
        self.assertEqual(F._digits(0), [0])
        self.assertEqual(F._digits(1), [1])
        self.assertEqual(F._digits(-1), [-1])
        self.assertEqual(F._digits(65535), [65535])
        self.assertEqual(F._digits(65536), [0, 1])
        self.assertEqual(F._digits(-65537), [-1, -1])
        self.assertEqual(F._digits(2 ** 32 + 5), [5, 0, 1])


class TestReproducibility(unittest.TestCase):
    GOLDEN_HEAD = "d78758739934d75427dc3259038754b1b5a9d4ce3a6ed2d077e254292a225375"

    def test_two_runs_identical_head(self):
        a = run_scenario()[2]
        b = run_scenario()[2]
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
