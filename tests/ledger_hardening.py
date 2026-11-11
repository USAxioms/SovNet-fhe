"""Mutation-hardening tests shared by the rev 1 (fhe_wad18) and rev 2 (rlwe_wad18) ledgers.

Their ledger code is identical; only the ciphertext type differs. A concrete TestCase mixes
LedgerHardeningMixin in and supplies the adapter attributes listed below.

  F                  the engine module
  LIMIT              smallest noise/bound value that counts as exhausted
  forge(ct, bound)   same ciphertext body, forged public bound
  forge_dict(d, b)   same, on a serialised ciphertext dict
  scale(s)           factor by which he_scale multiplies the bound for scalar s
  new_ledger(ev=None, tag=...), borrow(kh, led, txid, amount), run_scenario()
"""
HEX0, HEXF = "0" * 64, "f" * 64


class LedgerHardeningMixin(object):
    def rehash(self, led):
        prev = self.F.GENESIS_PREV
        for e in led.entries:
            e["prev"] = prev
            e["hash"] = self.F.entry_hash(prev, e["seq"], e["kind"], e["txid"], e["payload"])
            prev = e["hash"]

    def enc(self, kh, v, label):
        r = kh.encrypt(v, label)
        self.assertTrue(r.ok)
        return r.value

    # ---------------------------------------------------------------- plumbing
    def test_state_names_constants_and_result_plumbing(self):
        F = self.F
        self.assertEqual((F.NORMAL, F.OVER_CAP, F.FROZEN, F.HALTED),
                         ("NORMAL", "OVER_CAP", "FROZEN", "HALTED"))
        self.assertEqual(F.DEBT_ACCOUNT, "SENIOR_DEBT")
        self.assertEqual(F.GENESIS_PREV, "0" * 64)
        self.assertEqual(F.Res.__name__, "Res")
        self.assertEqual(F.Res._fields, ("ok", "value", "reason"))
        good = F._ok(5)
        self.assertIs(good.ok, True)
        self.assertEqual((good.value, good.reason), (5, ""))
        bad = F._fail("why")
        self.assertIs(bad.ok, False)
        self.assertIsNone(bad.value)
        self.assertEqual(bad.reason, "why")
        e = F.he_sum([])
        self.assertEqual((e.ok, e.value, e.reason), (False, None, "EMPTY_SUM"))

    def test_reject_entries_record_txid_and_reason(self):
        kh, aud, led = self.new_ledger()
        self.assertEqual(led.halt_reason, "")
        r = led.post("tx-empty", [])
        self.assertEqual((r.ok, r.reason), (False, "EMPTY_POSTING"))
        e = led.entries[-1]
        self.assertEqual((e["kind"], e["txid"], e["payload"]), ("REJECT", "tx-empty", {"reason": "EMPTY_POSTING"}))
        self.assertEqual(e["seq"], len(led.entries) - 1)
        self.assertEqual(led.entries[0]["kind"], "GENESIS")
        self.assertEqual(led.entries[0]["txid"], "genesis")
        self.assertEqual(led.entries[0]["prev"], self.F.GENESIS_PREV)

    def test_state_gates_use_exact_reasons(self):
        kh, aud, led = self.run_scenario()
        led.state = self.F.FROZEN
        self.assertEqual(self.borrow(kh, led, "f1", 1).reason, "STATE_FROZEN")
        self.assertEqual(led.entries[-1]["payload"], {"reason": "STATE_FROZEN"})
        led.state = self.F.HALTED
        self.assertEqual(self.borrow(kh, led, "f2", 1).reason, "STATE_HALTED")
        self.assertEqual(led.entries[-1]["payload"], {"reason": "STATE_HALTED"})
        led.state = self.F.OVER_CAP
        self.assertEqual(self.borrow(kh, led, "f3", 1).reason, "DEBT_CAP_EXCEEDED")

    # ----------------------------------------------------------- malformed posts
    def test_unknown_side_with_both_real_sides_is_malformed(self):
        kh, aud, led = self.new_ledger()
        d, c, x = (self.enc(kh, 5, "m:%s" % k) for k in "dcx")
        for bad in ("X", "A", "B", "d", "c", ""):
            r = led.post("m%s" % bad, [("A", "D", d), ("B", "C", c), ("C", bad, x)])
            self.assertEqual((r.ok, r.reason), (False, "MALFORMED_POSTING"), bad)
            self.assertEqual(led.entries[-1]["payload"], {"reason": "MALFORMED_POSTING"})
        self.assertEqual(led.balances, {})
        kh2, aud2, led2 = self.new_ledger(tag="m2")
        d, c = self.enc(kh2, 5, "q:d"), self.enc(kh2, 5, "q:c")
        self.assertEqual(led2.post("only-d", [("A", "D", d), ("B", "D", c)]).reason, "MALFORMED_POSTING")
        d, c = self.enc(kh2, 5, "r:d"), self.enc(kh2, 5, "r:c")
        self.assertEqual(led2.post("only-c", [("A", "C", d), ("B", "C", c)]).reason, "MALFORMED_POSTING")

    # ------------------------------------------------------ headroom in post()
    def test_post_negation_failure_is_reported_with_txid(self):
        kh, aud, led = self.new_ledger()
        d, c = self.enc(kh, 1, "n:d"), self.enc(kh, 1, "n:c")
        r = led.post("neg-fail", [("A", "D", d), ("B", "C", self.forge(c, self.LIMIT))])
        self.assertIs(r.ok, False)
        self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")
        self.assertEqual(led.entries[-1]["txid"], "neg-fail")
        self.assertEqual(led.entries[-1]["payload"], {"reason": "HEADROOM_EXHAUSTED"})
        self.assertEqual(led.balances, {})

    def test_post_sum_overflow_is_reported(self):
        kh, aud, led = self.new_ledger()
        c = self.enc(kh, 2, "s:c")
        d1, d2 = self.enc(kh, 1, "s:d1"), self.enc(kh, 1, "s:d2")
        half = self.LIMIT // 2
        r = led.post("sum-fail", [("B", "C", c), ("A", "D", self.forge(d1, half)), ("C", "D", self.forge(d2, half))])
        self.assertEqual((r.ok, r.reason), (False, "HEADROOM_EXHAUSTED"))
        self.assertEqual(led.entries[-1]["txid"], "sum-fail")
        just = self.LIMIT // 2 - 1
        c2, d3, d4 = self.enc(kh, 2, "s:c2"), self.enc(kh, 1, "s:d3"), self.enc(kh, 1, "s:d4")
        r = led.post("sum-ok", [("B", "C", self.forge(c2, 1)), ("A", "D", self.forge(d3, just)), ("C", "D", self.forge(d4, just))])
        self.assertTrue(r.ok, r.reason)

    def test_post_balance_add_overflow_is_reported(self):
        kh, aud, led = self.new_ledger()
        a, b = self.enc(kh, 5, "b:a"), self.enc(kh, 5, "b:b")
        self.assertTrue(led.post("p1", [("A", "D", a), ("B", "C", b)]).ok)
        led.balances["A"] = self.forge(led.balances["A"], self.LIMIT - 1)
        d, c = self.enc(kh, 1, "b:d"), self.enc(kh, 1, "b:c")
        r = led.post("p2", [("A", "D", d), ("B", "C", c)])
        self.assertEqual((r.ok, r.reason), (False, "HEADROOM_EXHAUSTED"))
        self.assertEqual(led.entries[-1]["txid"], "p2")
        self.assertEqual(led.entries[-1]["payload"], {"reason": "HEADROOM_EXHAUSTED"})

    def test_post_with_corrupt_live_debt_balance_fails_closed(self):
        kh, aud, led = self.run_scenario()
        led.balances[self.F.DEBT_ACCOUNT] = self.forge(led.balances[self.F.DEBT_ACCOUNT], self.LIMIT)
        d, c = self.enc(kh, 1, "k:d"), self.enc(kh, 1, "k:c")
        r = led.post("corrupt", [("X", "D", d), ("Y", "C", c)])
        self.assertEqual((r.ok, r.reason), (False, "HEADROOM_EXHAUSTED"))
        self.assertEqual(led.entries[-1]["txid"], "corrupt")
        self.assertNotIn("X", led.balances)

    def test_post_with_exhausted_ev_reports_ltv_failure_reason(self):
        kh, aud, led = self.run_scenario()
        led.ev = self.forge(led.ev, self.LIMIT - 1)
        r = self.borrow(kh, led, "ev-bad", 1)
        self.assertEqual((r.ok, r.reason), (False, "HEADROOM_EXHAUSTED"))
        self.assertEqual(led.entries[-1]["txid"], "ev-bad")
        self.assertEqual(led.entries[-1]["payload"], {"reason": "HEADROOM_EXHAUSTED"})

    def test_breaker_and_cap_rejections_record_exact_reasons(self):
        kh, aud, led = self.new_ledger()
        self.assertEqual(self.borrow(kh, led, "big", 1_380_000_000 * self.F.WAD).reason, "DEBT_CAP_EXCEEDED")
        self.assertEqual(led.entries[-1]["payload"], {"reason": "DEBT_CAP_EXCEEDED"})
        self.assertEqual(led.state, self.F.NORMAL)
        kh2, aud2, led2 = self.new_ledger(ev=1_000_000_000 * self.F.WAD, tag="brk")
        self.assertEqual(self.borrow(kh2, led2, "huge", 490_000_000 * self.F.WAD).reason, "CIRCUIT_BREAKER")
        self.assertEqual(led2.entries[-1]["payload"], {"reason": "CIRCUIT_BREAKER"})
        self.assertEqual(led2.state, self.F.FROZEN)

    def test_over_cap_posting_that_increases_debt_is_rejected_and_neutral_one_allowed(self):
        kh, aud, led = self.run_scenario()
        led.update_ev("mark", self.enc(kh, 2_900_000_000 * self.F.WAD, "oc:e"))
        self.assertEqual(led.state, self.F.OVER_CAP)
        up = self.borrow(kh, led, "up", 1)
        self.assertEqual((up.ok, up.reason), (False, "DEBT_CAP_EXCEEDED"))
        self.assertEqual(led.state, self.F.OVER_CAP)
        d, c = self.enc(kh, 5, "oc:d"), self.enc(kh, 5, "oc:c")
        ok = led.post("neutral", [("T", "D", d), ("CASH", "C", c)])
        self.assertTrue(ok.ok)
        self.assertEqual(led.state, self.F.OVER_CAP)
        d, c = self.enc(kh, 50_000_000 * self.F.WAD, "oc:rd"), self.enc(kh, 50_000_000 * self.F.WAD, "oc:rc")
        self.assertTrue(led.post("repay", [(self.F.DEBT_ACCOUNT, "D", d), ("CASH", "C", c)]).ok)
        self.assertEqual(led.state, self.F.NORMAL)

    def test_over_cap_with_no_prior_debt_account_is_rejected(self):
        kh, aud, led = self.new_ledger(ev=1_000_000_000 * self.F.WAD, tag="nodebt")
        r = self.borrow(kh, led, "first", 460_000_000 * self.F.WAD)       # 46 %, no earlier debt
        self.assertEqual((r.ok, r.reason), (False, "DEBT_CAP_EXCEEDED"))

    # --------------------------------------------------------- ltv_status direct
    def test_ltv_status_value_types_and_failures(self):
        F = self.F
        kh, aud, led = self.run_scenario()
        debt = F.he_neg(led.balances[F.DEBT_ACCOUNT]).value
        r = F.ltv_status(aud, debt, led.ev)
        self.assertIs(r.ok, True)
        self.assertEqual(r.value, (False, False))
        self.assertIs(type(r.value[0]), bool)
        self.assertIs(type(r.value[1]), bool)
        bad = F.ltv_status(aud, debt, self.forge(led.ev, self.LIMIT - 1))
        self.assertEqual((bad.ok, bad.value, bad.reason), (False, None, "HEADROOM_EXHAUSTED"))
        bad = F.ltv_status(aud, self.forge(debt, self.LIMIT - 1), led.ev)
        self.assertEqual((bad.ok, bad.reason), (False, "HEADROOM_EXHAUSTED"))
        s = max(self.scale(F.CAP_RATIO_WAD), self.scale(F.BREAKER_RATIO_WAD))
        ev_b = (self.LIMIT - 1) // s
        debt_b = (self.LIMIT - 1) // self.scale(F.WAD)
        sub_fail = F.ltv_status(aud, self.forge(debt, debt_b), self.forge(led.ev, ev_b))
        self.assertEqual((sub_fail.ok, sub_fail.value, sub_fail.reason), (False, None, "HEADROOM_EXHAUSTED"))

    # ------------------------------------------------------------- update_ev paths
    def test_update_ev_failure_paths_and_return_values(self):
        F = self.F
        kh, aud, led = self.run_scenario()
        ok = led.update_ev("e1", self.enc(kh, 3_100_000_000 * F.WAD, "e1:e"))
        self.assertEqual((ok.ok, ok.value, ok.reason), (True, F.NORMAL, ""))
        bad = led.update_ev("e2", self.forge(self.enc(kh, 3_000_000_000 * F.WAD, "e2:e"), self.LIMIT - 1))
        self.assertEqual((bad.ok, bad.value, bad.reason), (False, None, "HEADROOM_EXHAUSTED"))
        self.assertEqual(led.entries[-1]["kind"], "EV_UPDATE")
        kh2, aud2, led2 = self.run_scenario()
        led2.balances[F.DEBT_ACCOUNT] = self.forge(led2.balances[F.DEBT_ACCOUNT], self.LIMIT)
        bad = led2.update_ev("e3", self.enc(kh2, 3_000_000_000 * F.WAD, "e3:e"))
        self.assertEqual((bad.ok, bad.value, bad.reason), (False, None, "HEADROOM_EXHAUSTED"))

    def test_update_ev_when_halted_is_rejected_with_reason(self):
        kh, aud, led = self.run_scenario()
        led.state = self.F.HALTED
        r = led.update_ev("h", self.enc(kh, self.F.EV_WAD, "h:e"))
        self.assertEqual((r.ok, r.reason), (False, "STATE_HALTED"))
        self.assertEqual(led.entries[-1]["payload"], {"reason": "STATE_HALTED"})
        self.assertEqual(led.entries[-1]["kind"], "REJECT")

    def test_frozen_state_is_sticky_through_every_ev_remark(self):
        F = self.F
        kh, aud, led = self.run_scenario()
        led.update_ev("shock", self.enc(kh, 2_700_000_000 * F.WAD, "sh:e"))
        self.assertEqual(led.state, F.FROZEN)
        for i, ev in enumerate((2_900_000_000, 3_000_000_000, 3_500_000_000, 2_600_000_000)):
            r = led.update_ev("re%d" % i, self.enc(kh, ev * F.WAD, "re%d:e" % i))
            self.assertEqual((r.ok, r.value), (True, F.FROZEN), ev)
            self.assertEqual(led.state, F.FROZEN)
        self.assertTrue(led.audit().ok)
        self.assertEqual(led.state, F.FROZEN)

    def test_ev_remark_states_without_frozen(self):
        F = self.F
        kh, aud, led = self.run_scenario()
        r = led.update_ev("a", self.enc(kh, 2_900_000_000 * F.WAD, "a:e"))
        self.assertEqual((r.value, led.state), (F.OVER_CAP, F.OVER_CAP))
        r = led.update_ev("b", self.enc(kh, 3_100_000_000 * F.WAD, "b:e"))
        self.assertEqual((r.value, led.state), (F.NORMAL, F.NORMAL))
        r = led.update_ev("c", self.enc(kh, 2_900_000_000 * F.WAD, "c:e"))
        self.assertEqual((r.value, led.state), (F.OVER_CAP, F.OVER_CAP))
        r = led.update_ev("d", self.enc(kh, 2_700_000_000 * F.WAD, "d:e"))
        self.assertEqual((r.value, led.state), (F.FROZEN, F.FROZEN))

    # ------------------------------------------------------------------- audit
    def test_audit_chain_checks_in_both_directions(self):
        for field, vals, reason in (("seq", (0, 5), "CHAIN_BROKEN"),
                                    ("prev", (HEX0, HEXF), "CHAIN_BROKEN"),
                                    ("hash", (HEX0, HEXF), "ENTRY_TAMPERED")):
            for v in vals:
                kh, aud, led = self.run_scenario()
                led.entries[1][field] = v
                r = led.audit()
                self.assertEqual((r.ok, r.reason), (False, reason), (field, v))
                self.assertEqual(led.state, self.F.HALTED)
                self.assertEqual(led.halt_reason, reason)

    def test_audit_expected_head_anchor(self):
        kh, aud, led = self.run_scenario()
        r = led.audit(expected_head=led.head())
        self.assertEqual((r.ok, r.value), (True, led.head()))
        self.assertEqual(led.state, self.F.NORMAL)
        self.assertEqual(led.halt_reason, "")
        for bad in (HEX0, HEXF):
            kh, aud, led = self.run_scenario()
            r = led.audit(expected_head=bad)
            self.assertEqual((r.ok, r.reason), (False, "HEAD_MISMATCH"), bad)
            self.assertEqual(led.halt_reason, "HEAD_MISMATCH")

    def test_audit_with_rejects_and_unknown_entry_kinds(self):
        kh, aud, led = self.run_scenario()
        d, c = self.enc(kh, 5, "ar:d"), self.enc(kh, 6, "ar:c")
        self.assertEqual(led.post("unbal", [("A", "D", d), ("B", "C", c)]).reason, "PARITY_VIOLATION")
        led._append("NOTE", "memo", {"text": "hello"})
        led._append("AAA", "memo2", {})
        led._append("ZZZ", "memo3", {})
        r = led.audit()
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(r.value, led.head())

    def test_audit_without_genesis_reports_ev_divergence(self):
        kh, aud, led = self.new_ledger()
        led.entries = []
        led.balances = {}
        r = led.audit()
        self.assertEqual((r.ok, r.reason), (False, "EV_DIVERGENCE"))

    def test_audit_state_flags_and_exact_reasons(self):
        F = self.F
        kh, aud, led = self.run_scenario()
        led.update_ev("mark", self.enc(kh, 2_900_000_000 * F.WAD, "af:e"))
        led.state = F.NORMAL
        self.assertEqual(led.audit().reason, "CAP_NOT_ENFORCED")
        kh, aud, led = self.run_scenario()
        led.update_ev("shock", self.enc(kh, 2_700_000_000 * F.WAD, "ab:e"))
        for st in (F.NORMAL, F.OVER_CAP):
            kh, aud, led = self.run_scenario()
            led.update_ev("shock", self.enc(kh, 2_700_000_000 * F.WAD, "ac:e"))
            led.state = st
            self.assertEqual(led.audit().reason, "BREAKER_NOT_TRIPPED", st)
        kh, aud, led = self.run_scenario()
        led.update_ev("shock", self.enc(kh, 2_700_000_000 * F.WAD, "ad:e"))
        led.state = F.HALTED
        self.assertEqual(led.audit().reason, "BREAKER_NOT_TRIPPED")

    def test_audit_replay_headroom_paths(self):
        F = self.F
        big = self.LIMIT - 1
        # (a) negation of an exhausted credit line
        kh, aud, led = self.run_scenario()
        for ln in led.entries[1]["payload"]["lines"]:
            if ln["s"] == "C":
                self.forge_dict(ln["c"], self.LIMIT)
        self.rehash(led)
        self.assertEqual(led.audit().reason, "REPLAY_HEADROOM")
        # (b) balance accumulation overflow on one account
        kh, aud, led = self.run_scenario()
        for e in led.entries[1:]:
            for ln in e["payload"]["lines"]:
                self.forge_dict(ln["c"], big)
        self.rehash(led)
        self.assertEqual(led.audit().reason, "REPLAY_HEADROOM")
        # (c) per-posting sum overflow with distinct accounts
        kh, aud, led = self.run_scenario()
        ln = led.entries[1]["payload"]["lines"]
        extra = [{"a": "X", "s": "D", "c": dict(ln[0]["c"])}, {"a": "Y", "s": "C", "c": dict(ln[1]["c"])}]
        led.entries[1]["payload"]["lines"] = [ln[0], ln[1]] + extra
        for l2 in led.entries[1]["payload"]["lines"]:
            self.forge_dict(l2["c"], self.LIMIT // 2 - 1)
        self.rehash(led)
        self.assertEqual(led.audit().reason, "REPLAY_HEADROOM")

    def test_he_sub_reports_negation_failure_of_exhausted_subtrahend(self):
        F = self.F
        kh = F.KeyHolder(b"hsub-seed") if hasattr(F, "KeyHolder") else None
        x = self.enc(kh, 5, "hs-x")
        y = self.enc(kh, 3, "hs-y")
        r = F.he_sub(x, self.forge(y, self.LIMIT))
        self.assertEqual((r.ok, r.value, r.reason), (False, None, "HEADROOM_EXHAUSTED"))
        self.assertTrue(F.he_sub(x, y).ok)

    def test_audit_replay_balance_accumulation_overflow_is_named_and_halts(self):
        import copy
        kh, aud, led = self.new_ledger(tag="acc")
        d, c = self.enc(kh, 5, "ac1d"), self.enc(kh, 5, "ac1c")
        self.assertTrue(led.post("ac1", [("A", "D", d), ("B", "C", c)]).ok)
        b1 = self.LIMIT // 3 + 1                     # 2*b1 < LIMIT <= 3*b1
        first = led.entries[1]
        for k in (2, 3):
            e = copy.deepcopy(first)
            e["seq"], e["txid"] = k, "ac%d" % k
            led.entries.append(e)
        for e in led.entries[1:]:
            for ln in e["payload"]["lines"]:
                self.forge_dict(ln["c"], b1)
        self.rehash(led)
        r = led.audit()
        self.assertEqual((r.ok, r.value, r.reason), (False, None, "REPLAY_HEADROOM"))
        self.assertEqual((led.state, led.halt_reason), (self.F.HALTED, "REPLAY_HEADROOM"))

    def test_audit_replay_ltv_failure_is_named(self):
        kh, aud, led = self.run_scenario()
        self.forge_dict(led.entries[0]["payload"]["ev"], self.LIMIT - 1)
        self.rehash(led)
        led.ev = self.F.Ciphertext.from_dict(led.entries[0]["payload"]["ev"])
        r = led.audit()
        self.assertEqual((r.ok, r.reason), (False, "HEADROOM_EXHAUSTED"))
        self.assertEqual(led.halt_reason, "HEADROOM_EXHAUSTED")

    def test_audit_global_sum_checks(self):
        F = self.F
        kh, aud, led = self.new_ledger(tag="gl")
        x = self.LIMIT // 4 + 1
        for k in (1, 2):
            d, c = self.enc(kh, 5, "g%dd" % k), self.enc(kh, 5, "g%dc" % k)
            self.assertTrue(led.post("g%d" % k, [("A", "D", self.forge(d, x)), ("B", "C", self.forge(c, x))]).ok)
        r = led.audit()
        self.assertEqual((r.ok, r.reason), (False, "GLOBAL_PARITY"))
        self.assertEqual(led.halt_reason, "GLOBAL_PARITY")
        kh, aud, led = self.run_scenario()
        self.assertTrue(led.audit().ok)

    def test_audit_balances_divergence_for_missing_and_extra_accounts(self):
        kh, aud, led = self.run_scenario()
        led.balances["GHOST"] = led.balances["CASH"]
        self.assertEqual(led.audit().reason, "STATE_DIVERGENCE")
        kh, aud, led = self.run_scenario()
        del led.balances["CASH"]
        self.assertEqual(led.audit().reason, "STATE_DIVERGENCE")
