"""FHE-WAD18 rev 2: BFV-style RLWE ciphertext layer (zero dependencies, integer-only).

Ring R_q = Z_q[x]/(x^N + 1), plaintext space Z_t (values stored in the constant
coefficient, balanced representative), q = t * DELTA. Public-key encryption
(b, a) with ternary secret; all randomness from a SHA-256 counter DRBG so every
run is bit-for-bit reproducible. Supported homomorphic ops: add, sub, neg,
multiplication by a PLAINTEXT integer. Both noise and plaintext magnitude are
tracked as public bounds; exhausting either returns HEADROOM_EXHAUSTED.

PARAMETERS ARE TOY-SIZED (N=64 with a ~320-bit modulus is far outside any
standard security table). No security claim is made. NOT supported:
ciphertext x ciphertext multiplication, relinearisation, bootstrapping, and
therefore homomorphic comparison; the key-holding auditor is still required.
No floats, no '/' operator, no math/decimal/fractions imports.
"""
import hashlib
import json
from collections import namedtuple

WAD = 10 ** 18
N = 64
T = 1 << 192
DELTA = 1 << 128
Q = T * DELTA
HALF_T = T // 2
HALF_DELTA = DELTA // 2
ERR_BOUND = 3
VALUE_MAX = 1 << 100
FRESH_NOISE = ERR_BOUND * (2 * N + 1)

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


# ------------------------------------------------------------------ randomness
class Drbg(object):
    def __init__(self, seed, label):
        self._seed = seed + b"|" + label.encode()
        self._ctr = 0
        self._buf = b""

    def bytes(self, n):
        while len(self._buf) < n:
            self._buf += hashlib.sha256(self._seed + b"|" + str(self._ctr).encode()).digest()
            self._ctr += 1
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def uniform_q(self):
        return int.from_bytes(self.bytes(48), "big") % Q

    def ternary(self):
        return int.from_bytes(self.bytes(2), "big") % 3 - 1

    def small(self):
        b = self.bytes(1)[0]
        return (bin(b & 7).count("1")) - (bin((b >> 3) & 7).count("1"))


# ------------------------------------------------------------------ ring ops
def _pmul(a, b):
    out = [0] * N
    for i in range(N):
        x = a[i]
        if x == 0:
            continue
        for j in range(N):
            y = b[j]
            if y == 0:
                continue
            k = i + j
            if k < N:
                out[k] += x * y
            else:
                out[k - N] -= x * y
    return [c % Q for c in out]


def _padd(a, b):
    return [(a[i] + b[i]) % Q for i in range(N)]


def _pneg(a):
    return [(-c) % Q for c in a]


def _pscale(a, s):
    return [(c * s) % Q for c in a]


def _center_t(p):
    p = p % T
    return p - T if p > HALF_T else p


# ----------------------------------------------------------------- ciphertext
class Ciphertext(object):
    """c0, c1: tuples of N coefficients mod Q. nb: public noise bound.
    pb: public plaintext-magnitude bound (a declared cap, never the value)."""
    __slots__ = ("c0", "c1", "nb", "pb")

    def __init__(self, c0, c1, nb, pb):
        self.c0 = tuple(c0)
        self.c1 = tuple(c1)
        self.nb = nb
        self.pb = pb

    def to_dict(self):
        return {"c0": list(self.c0), "c1": list(self.c1), "n": self.nb, "p": self.pb}

    @staticmethod
    def from_dict(d):
        return Ciphertext(d["c0"], d["c1"], d["n"], d["p"])

    def __eq__(self, other):
        return (isinstance(other, Ciphertext) and self.c0 == other.c0
                and self.c1 == other.c1 and self.nb == other.nb and self.pb == other.pb)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.c0, self.c1, self.nb, self.pb))


def _check(c0, c1, nb, pb):
    if nb >= HALF_DELTA or pb >= HALF_T:
        return _fail("HEADROOM_EXHAUSTED")
    return _ok(Ciphertext(c0, c1, nb, pb))


def he_add(x, y):
    return _check(_padd(x.c0, y.c0), _padd(x.c1, y.c1), x.nb + y.nb, x.pb + y.pb)


def he_neg(x):
    return _check(_pneg(x.c0), _pneg(x.c1), x.nb, x.pb)


def he_sub(x, y):
    n = he_neg(y)
    if not n.ok:
        return n
    return he_add(x, n.value)


def he_scale(x, s):
    """Multiply by the PLAINTEXT integer s (signed)."""
    a = -s if s < 0 else s
    return _check(_pscale(x.c0, s), _pscale(x.c1, s), x.nb * a, x.pb * a)


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
    """Fault injection: add delta to coefficient `index` of c0 (mod Q).
    delta=1 is benign RLWE noise; delta=DELTA shifts the plaintext by 1."""
    c0 = list(ct.c0)
    c0[index] = (c0[index] + delta) % Q
    return Ciphertext(c0, ct.c1, ct.nb, ct.pb)


# ------------------------------------------------------------------- key side
class KeyHolder(object):
    def __init__(self, seed):
        self._seed = seed
        self._used = set()
        d = Drbg(seed, "keygen")
        self._s = [d.ternary() for _ in range(N)]
        a = [d.uniform_q() for _ in range(N)]
        e = [d.small() for _ in range(N)]
        b = _padd(_pneg(_pmul(a, self._s)), [c % Q for c in e])
        self.pk = (tuple(b), tuple(a))

    def encrypt(self, value, label):
        if label in self._used:
            return _fail("LABEL_REUSE")
        if value > VALUE_MAX or value < -VALUE_MAX:
            return _fail("VALUE_TOO_LARGE")
        self._used.add(label)
        d = Drbg(self._seed, "enc|" + label)
        u = [d.ternary() for _ in range(N)]
        e1 = [d.small() % Q for _ in range(N)]
        e2 = [d.small() % Q for _ in range(N)]
        b, a = self.pk
        c0 = _padd(_pmul(list(b), u), e1)
        c0[0] = (c0[0] + DELTA * value) % Q
        c1 = _padd(_pmul(list(a), u), e2)
        return _ok(Ciphertext(c0, c1, FRESH_NOISE, VALUE_MAX))

    def _phase(self, ct):
        sc1 = _pmul(list(ct.c1), self._s)
        return [(ct.c0[i] + sc1[i]) % Q for i in range(N)]

    def decrypt(self, ct):
        x = self._phase(ct)[0]
        return _center_t((x + HALF_DELTA) // DELTA)

    def noise(self, ct):
        """Measured infinity-norm noise (key-holder diagnostic)."""
        worst = 0
        for x in self._phase(ct):
            r = (x + HALF_DELTA) // DELTA
            e = x - r * DELTA
            e = -e if e < 0 else e
            if e > worst:
                worst = e
        return worst


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
