"""n-of-n threshold decryption for bfv_wad18 (rev 5 draft).

Secret s is additively shared: s = s_1 + ... + s_n over R_Q. Each party i publishes a partial
decryption  d_i = c1*s_i + e_i  (e_i = 'smudging' noise, bound = nb * 2^SMUDGE_BITS), and the
combiner outputs round((c0 + sum d_i)/delta) mod 2.  No single share decrypts anything.

LIMITS (stated plainly):
  * Trusted dealer: shares come from the existing KeyHolder (it knows s once, then must discard it).
    The evaluation key needs s^2, so dealer-less keygen would need an interactive protocol: not done.
  * n-of-n: all parties are needed (no t-of-n), and ALL n colluding can decrypt everything.
  * Release control is a per-party gate (only digests of registered output ciphertexts are signed
    off). It is policy in each party's process, not a cryptographic proof of what is being opened.
  * Smudging gives ~SMUDGE_BITS bits of statistical hiding of the other shares; toy parameters.
"""
import hashlib
import bfv_wad18 as B

SMUDGE_BITS = 40


def ct_digest(ct):
    h = hashlib.sha256()
    for poly in (ct.c0, ct.c1):
        for c in poly:
            h.update(str(c).encode() + b",")
        h.update(b"|")
    return h.hexdigest()


def split_key(keyholder, n_parties, seed):
    """Additively share the secret. Returns a list of Party objects. Caller must discard keyholder."""
    if n_parties < 2:
        raise ValueError("need at least 2 parties")
    p = keyholder.p
    d = B.Drbg(seed, "share-split")
    shares = []
    acc = [0] * p.n
    for _ in range(n_parties - 1):
        sh = [B.centre(d.uniform(p.k), p.q) for _ in range(p.n)]
        shares.append(sh)
        acc = [acc[i] + sh[i] for i in range(p.n)]
    shares.append([B.centre(keyholder._s[i] - acc[i], p.q) for i in range(p.n)])
    return [Party(p, i, sh, seed) for i, sh in enumerate(shares)]


class Party(object):
    def __init__(self, p, index, share, seed):
        self.p, self.index, self._share, self._seed = p, index, share, seed
        self.allowed = set()      # digests of ciphertexts this party agreed to open
        self.opened = []          # audit log of digests it has contributed to

    def authorise(self, digest):
        self.allowed.add(digest)

    def partial(self, ct, label):
        dg = ct_digest(ct)
        if dg not in self.allowed:
            return B._fail("NOT_AUTHORISED")
        bound = ct.nb << SMUDGE_BITS
        if bound * 2 >= self.p.half_delta:          # leave room for >= 2 smudges
            return B._fail("HEADROOM_EXHAUSTED")
        d = B.Drbg(self._seed + b"|party%d" % self.index, "smudge|" + label)
        span = 2 * bound + 1
        e = [(int.from_bytes(d.bytes(self.p.k // 8 + 8), "big") % span) - bound for _ in range(self.p.n)]
        part = B.qadd(B.qmul(list(ct.c1), self._share, self.p), e, self.p)
        self.opened.append(dg)
        return B._ok((part, bound))


def combine(p, ct, parts):
    """parts: list of (partial_poly, smudge_bound). Fails closed if total noise could flip the bit."""
    total = ct.nb + sum(b for _, b in parts)
    if total >= p.half_delta:
        return B._fail("HEADROOM_EXHAUSTED")
    ph = list(ct.c0)
    for poly, _ in parts:
        ph = B.qadd(ph, poly, p)
    return B._ok(((ph[0] + p.half_delta) // p.delta) % 2)


def threshold_open(p, ct, parties, label):
    parts = []
    for party in parties:
        r = party.partial(ct, label)
        if not r.ok:
            return r
        parts.append(r.value)
    return combine(p, ct, parts)
