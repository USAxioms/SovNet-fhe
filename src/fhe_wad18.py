"""FHE-WAD18 reference engine (zero dependencies, integer-only).

Scope (read the memorandum before relying on this): an additively homomorphic
BLINDING scheme over Z_M with M = 2**63 - 1, a limb encoding that lets 10**18-scaled
WAD values (up to 256 bits) live in that ring, a ciphertext-only ledger engine,
and a key-holding BlindedAuditor that discloses only sign / zero bits.

This is NOT lattice-based FHE: ciphertext x ciphertext multiplication and
comparison are not possible. Comparisons are delegated to the auditor's
one-bit oracle.  No floats, no '/' operator, no math/decimal/fractions imports.
"""
import hashlib
import json
from collections import namedtuple

WAD = 10 ** 18
HE_MODULUS = 2 ** 63 - 1
HALF = HE_MODULUS // 2
LIMB_BITS = 16
LIMB_BASE = 1 << LIMB_BITS
LIMB_MASK = LIMB_BASE - 1
N_LIMBS = 16

EV_WAD = 3_000_000_000 * WAD
CAP_RATIO_WAD = 45 * WAD // 100        # 45.000000000000000000 %
BREAKER_RATIO_WAD = 48 * WAD // 100    # 48.000000000000000000 %
DEBT_ACCOUNT = "SENIOR_DEBT"

NORMAL = "NORMAL"
OVER_CAP = "OVER_CAP"
FROZEN = "FROZEN"
HALTED = "HALTED"

Res = namedtuple("Res", "ok value reason")


def _ok(value):
    return Res(True, value, "")


def _fail(reason):
    return Res(False, None, reason)


# ---------------------------------------------------------------- polynomials
def _digits(v):
    """Signed base-2**16 digits of integer v (all digits share the sign of v)."""
    sign = -1 if v < 0 else 1
    a = -v if v < 0 else v
    out = []
    while a:
        out.append(sign * (a & LIMB_MASK))
        a >>= LIMB_BITS
    return out if out else [0]


def _padd(a, b):
    n = max(len(a), len(b))
    return [(a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)
            for i in range(n)]


def _pmul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] += x * y
    return out


def _abs_sum(p):
    return sum(-x if x < 0 else x for x in p)


def derive_key_limbs(seed, label):
    """Deterministic blinding key: one limb per index, uniform-ish in [0, M)."""
    out = []
    for i in range(N_LIMBS):
        h = hashlib.sha256(seed + b"|" + label.encode() + b"|" + str(i).encode()).digest()
        out.append(int.from_bytes(h, "big") % HE_MODULUS)
    return out


# ----------------------------------------------------------------- ciphertext
class Ciphertext(object):
    """limbs: ring elements c_i = (a_i + k_i) mod M.
    terms: public linear program {label: poly} describing which keys (and with
    what plaintext-scalar polynomial) are folded into this ciphertext.
    bound: public upper bound on |a_i| (headroom accounting)."""
    __slots__ = ("limbs", "terms", "bound")

    def __init__(self, limbs, terms, bound):
        self.limbs = tuple(limbs)
        self.terms = tuple(sorted((k, tuple(v)) for k, v in dict(terms).items()))
        self.bound = bound

    def to_dict(self):
        return {"b": self.bound, "l": list(self.limbs),
                "t": [[k, list(v)] for k, v in self.terms]}

    @staticmethod
    def from_dict(d):
        return Ciphertext(d["l"], dict((k, v) for k, v in d["t"]), d["b"])

    def __eq__(self, other):
        return (isinstance(other, Ciphertext) and self.limbs == other.limbs
                and self.terms == other.terms and self.bound == other.bound)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.limbs, self.terms, self.bound))


def _check_bound(limbs, terms, bound):
    if bound >= HALF:
        return _fail("HEADROOM_EXHAUSTED")
    return _ok(Ciphertext(limbs, terms, bound))


def he_add(x, y):
    n = max(len(x.limbs), len(y.limbs))
    xl = list(x.limbs) + [0] * (n - len(x.limbs))
    yl = list(y.limbs) + [0] * (n - len(y.limbs))
    limbs = [(xl[i] + yl[i]) % HE_MODULUS for i in range(n)]
    terms = dict(x.terms)
    for k, p in y.terms:
        terms[k] = _padd(list(terms[k]), list(p)) if k in terms else list(p)
    terms = dict((k, p) for k, p in terms.items() if any(p))
    return _check_bound(limbs, terms, x.bound + y.bound)


def he_neg(x):
    limbs = [(-c) % HE_MODULUS for c in x.limbs]
    terms = dict((k, [-c for c in p]) for k, p in x.terms)
    return _check_bound(limbs, terms, x.bound)


def he_sub(x, y):
    n = he_neg(y)
    if not n.ok:
        return n
    return he_add(x, n.value)


def he_scale(x, s):
    """Homomorphic multiplication by the PLAINTEXT integer scalar s (signed)."""
    d = _digits(s)
    limbs = [c % HE_MODULUS for c in _pmul(list(x.limbs), d)]
    terms = dict((k, _pmul(list(p), d)) for k, p in x.terms)
    terms = dict((k, p) for k, p in terms.items() if any(p))
    return _check_bound(limbs, terms, x.bound * _abs_sum(d))


def he_sum(cts):
    acc = None
    for c in cts:
        if acc is None:
            acc = c
        else:
            r = he_add(acc, c)
            if not r.ok:
                return r
            acc = r.value
    if acc is None:
        return _fail("EMPTY_SUM")
    return _ok(acc)


def inject_noise(ct, index, delta):
    """Fault injection: perturb one ciphertext limb by delta (mod M)."""
    limbs = list(ct.limbs)
    limbs[index] = (limbs[index] + delta) % HE_MODULUS
    return Ciphertext(limbs, dict(ct.terms), ct.bound)


# ------------------------------------------------------------------- key side
class KeyHolder(object):
    def __init__(self, seed):
        self._seed = seed
        self._used = set()

    def encrypt(self, value, label):
        if label in self._used:
            return _fail("LABEL_REUSE")
        d = _digits(value)
        if len(d) > N_LIMBS:
            return _fail("VALUE_TOO_LARGE")
        d = d + [0] * (N_LIMBS - len(d))
        key = derive_key_limbs(self._seed, label)
        self._used.add(label)
        limbs = [(d[i] + key[i]) % HE_MODULUS for i in range(N_LIMBS)]
        return _ok(Ciphertext(limbs, {label: [1]}, LIMB_MASK))

    def decrypt(self, ct):
        n = len(ct.limbs)
        key = [0] * n
        for label, poly in ct.terms:
            prod = _pmul(derive_key_limbs(self._seed, label), list(poly))
            for i, x in enumerate(prod):
                if i < n:
                    key[i] += x
        total = 0
        for i in range(n):
            p = (ct.limbs[i] - key[i]) % HE_MODULUS
            if p > HALF:
                p -= HE_MODULUS
            total += p << (LIMB_BITS * i)
        return total


class BlindedAuditor(object):
    """Holds the key; discloses ONLY sign(-1/0/1) or a zero flag per query."""

    def __init__(self, keyholder):
        self._kh = keyholder
        self.query_log = []

    def sign(self, ct):
        v = self._kh.decrypt(ct)
        self.query_log.append("sign")
        return (v > 0) - (v < 0)

    def is_zero(self, ct):
        v = self._kh.decrypt(ct)
        self.query_log.append("zero")
        return v == 0


# -------------------------------------------------------------------- ledger
def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def entry_hash(prev, seq, kind, txid, payload):
    body = _canon({"seq": seq, "kind": kind, "txid": txid, "payload": payload})
    return hashlib.sha256((prev + "|" + body).encode()).hexdigest()


GENESIS_PREV = "0" * 64


def ltv_status(auditor, debt_ct, ev_ct):
    """Returns Res(ok, (over_cap, over_breaker)); evaluated entirely over
    ciphertexts; only the two sign bits are disclosed by the auditor."""
    ev_cap = he_scale(ev_ct, CAP_RATIO_WAD)
    ev_brk = he_scale(ev_ct, BREAKER_RATIO_WAD)
    dw = he_scale(debt_ct, WAD)
    for r in (ev_cap, ev_brk, dw):
        if not r.ok:
            return r
    s_cap = he_sub(ev_cap.value, dw.value)
    s_brk = he_sub(ev_brk.value, dw.value)
    for r in (s_cap, s_brk):
        if not r.ok:
            return r
    return _ok((auditor.sign(s_cap.value) < 0, auditor.sign(s_brk.value) < 0))


class Ledger(object):
    def __init__(self, auditor, genesis_ev):
        self.auditor = auditor
        self.entries = []
        self.balances = {}
        self.ev = genesis_ev
        self.state = NORMAL
        self.halt_reason = ""
        self._append("GENESIS", "genesis", {"ev": genesis_ev.to_dict()})

    # -- log
    def _append(self, kind, txid, payload):
        prev = self.entries[-1]["hash"] if self.entries else GENESIS_PREV
        seq = len(self.entries)
        h = entry_hash(prev, seq, kind, txid, payload)
        self.entries.append({"seq": seq, "kind": kind, "txid": txid,
                             "payload": payload, "prev": prev, "hash": h})

    def head(self):
        return self.entries[-1]["hash"]

    def _reject(self, txid, reason):
        self._append("REJECT", txid, {"reason": reason})
        return _fail(reason)

    # -- helpers
    def _debt(self, balances):
        if DEBT_ACCOUNT not in balances:
            return _ok(None)
        return he_neg(balances[DEBT_ACCOUNT])

    # -- postings
    def post(self, txid, lines):
        """lines: list of (account, 'D'|'C', Ciphertext). Atomic."""
        if self.state in (FROZEN, HALTED):
            return self._reject(txid, "STATE_" + self.state)
        if not lines:
            return self._reject(txid, "EMPTY_POSTING")
        sides = [s for (_, s, _) in lines]
        if "D" not in sides or "C" not in sides or any(s not in ("D", "C") for s in sides):
            return self._reject(txid, "MALFORMED_POSTING")
        deltas = []
        for acct, side, ct in lines:
            if side == "D":
                deltas.append(ct)
            else:
                n = he_neg(ct)
                if not n.ok:
                    return self._reject(txid, "HEADROOM_EXHAUSTED")
                deltas.append(n.value)
        total = he_sum(deltas)
        if not total.ok:
            return self._reject(txid, "HEADROOM_EXHAUSTED")
        if not self.auditor.is_zero(total.value):
            return self._reject(txid, "PARITY_VIOLATION")
        new = dict(self.balances)
        for (acct, _, _), delta in zip(lines, deltas):
            if acct in new:
                r = he_add(new[acct], delta)
                if not r.ok:
                    return self._reject(txid, "HEADROOM_EXHAUSTED")
                new[acct] = r.value
            else:
                new[acct] = delta
        new_debt = self._debt(new)
        if not new_debt.ok:
            return self._reject(txid, "HEADROOM_EXHAUSTED")
        new_state = NORMAL
        if new_debt.value is not None:
            st = ltv_status(self.auditor, new_debt.value, self.ev)
            if not st.ok:
                return self._reject(txid, st.reason)
            over_cap, over_brk = st.value
            if over_brk:
                self.state = FROZEN
                return self._reject(txid, "CIRCUIT_BREAKER")
            if over_cap:
                if DEBT_ACCOUNT not in self.balances:
                    return self._reject(txid, "DEBT_CAP_EXCEEDED")
                rel = he_sub(new[DEBT_ACCOUNT], self.balances[DEBT_ACCOUNT])
                if not rel.ok:
                    return self._reject(txid, rel.reason)
                if self.auditor.sign(rel.value) < 0:
                    return self._reject(txid, "DEBT_CAP_EXCEEDED")
                new_state = OVER_CAP
        self.balances = new
        self.state = new_state
        self._append("POST", txid, {"lines": [
            {"a": a, "s": s, "c": c.to_dict()} for (a, s, c) in lines]})
        return _ok(self.head())

    def update_ev(self, txid, new_ev):
        """Re-mark enterprise value (ciphertext). Breaker is sticky once tripped."""
        if self.state in (HALTED,):
            return self._reject(txid, "STATE_HALTED")
        self.ev = new_ev
        self._append("EV_UPDATE", txid, {"ev": new_ev.to_dict()})
        debt = self._debt(self.balances)
        if not debt.ok:
            return _fail(debt.reason)
        if debt.value is None:
            return _ok(self.state)
        st = ltv_status(self.auditor, debt.value, new_ev)
        if not st.ok:
            return st
        over_cap, over_brk = st.value
        if over_brk:
            self.state = FROZEN
        elif over_cap and self.state not in (FROZEN,):
            self.state = OVER_CAP
        elif self.state not in (FROZEN,):
            self.state = NORMAL
        return _ok(self.state)

    # -- recompute-and-compare oracle
    def audit(self, expected_head=None):
        """Replays the log from genesis over ciphertexts and compares with live
        state. Any deviation HALTs the ledger. Returns Res."""
        def halt(reason):
            self.state = HALTED
            self.halt_reason = reason
            return _fail(reason)

        prev = GENESIS_PREV
        for i, e in enumerate(self.entries):
            if e["seq"] != i or e["prev"] != prev:
                return halt("CHAIN_BROKEN")
            if entry_hash(prev, i, e["kind"], e["txid"], e["payload"]) != e["hash"]:
                return halt("ENTRY_TAMPERED")
            prev = e["hash"]
        if expected_head is not None and expected_head != prev:
            return halt("HEAD_MISMATCH")
        balances = {}
        ev = None
        for e in self.entries:
            if e["kind"] in ("GENESIS", "EV_UPDATE"):
                ev = Ciphertext.from_dict(e["payload"]["ev"])
            elif e["kind"] == "POST":
                deltas = []
                for ln in e["payload"]["lines"]:
                    ct = Ciphertext.from_dict(ln["c"])
                    d = ct
                    if ln["s"] == "C":
                        r = he_neg(ct)
                        if not r.ok:
                            return halt("REPLAY_HEADROOM")
                        d = r.value
                    deltas.append(d)
                    if ln["a"] in balances:
                        r = he_add(balances[ln["a"]], d)
                        if not r.ok:
                            return halt("REPLAY_HEADROOM")
                        balances[ln["a"]] = r.value
                    else:
                        balances[ln["a"]] = d
                z = he_sum(deltas)
                if not z.ok:
                    return halt("REPLAY_HEADROOM")
                if not self.auditor.is_zero(z.value):
                    return halt("REPLAY_PARITY")
        if balances != self.balances:
            return halt("STATE_DIVERGENCE")
        if ev != self.ev:
            return halt("EV_DIVERGENCE")
        if balances:
            tot = he_sum(list(balances[k] for k in sorted(balances)))
            if not tot.ok or not self.auditor.is_zero(tot.value):
                return halt("GLOBAL_PARITY")
        debt = self._debt(balances)
        if debt.value is not None:
            st = ltv_status(self.auditor, debt.value, ev)
            if not st.ok:
                return halt(st.reason)
            over_cap, over_brk = st.value
            if over_brk and self.state not in (FROZEN,):
                return halt("BREAKER_NOT_TRIPPED")
            if over_cap and self.state in (NORMAL,):
                return halt("CAP_NOT_ENFORCED")
        return _ok(prev)
