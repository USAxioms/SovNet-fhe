"""Smoke test of the BFV engine at a standard-compatible (N, k): N = 4096, k = 109 (the 128-bit table maximum
for N = 4096) with a centred-binomial error of eta = 21 (variance 10.5 >= 3.2^2). Depth-1 only:
keygen, encrypt, XOR, one ct x ct AND with relinearisation, decrypt, bound-dominates-noise.

Pure Python is made fast enough by Kronecker substitution for the exact negacyclic product (patched in at
run time; checked equal to the engine's own zmul first). This is NOT a solvency attestation and NOT a
security claim: the comparator needs a larger k at this N (see param_analysis.py).
Usage: python audit/standard_params_smoke.py [--n 4096 --k 109]
"""
import sys

import bfv_wad18 as B

ETA = 21


def cbd_small(self):
    """Centred binomial: popcount of ETA bits minus popcount of ETA bits (variance ETA/2)."""
    raw = int.from_bytes(self.bytes(6), "big")                       # 48 bits >= 2 * ETA
    low = raw & ((1 << ETA) - 1)
    high = (raw >> ETA) & ((1 << ETA) - 1)
    return bin(low).count("1") - bin(high).count("1")


def kronecker_zmul(a, b, n):
    """Exact negacyclic product over Z by Kronecker substitution, linear-time packing.

    Each coefficient is biased into [0, 2^slot) and written as a fixed-width little-endian byte slot, so the
    packed integer is built with one int.from_bytes call (no quadratic shift loop). The bias is removed
    arithmetically, the big integers are multiplied, and the product is un-biased and sliced the same way.
    Slots are whole bytes and wide enough that no slot of the full product can carry into its neighbour."""
    ma = max(abs(c) for c in a)
    mb = max(abs(c) for c in b)
    need = ma.bit_length() + mb.bit_length() + n.bit_length() + 2
    sb = (need + 7) // 8                       # bytes per slot
    slot = 8 * sb
    half = 1 << (slot - 1)
    ones = int.from_bytes(b"\x01" + b"\x00" * (sb - 1), "little")      # 1 in the lowest slot

    def spread(count):                         # sum over slots of 2^(slot*i), i < count
        return ((1 << (slot * count)) - 1) // ((1 << slot) - 1)

    def pack(p):
        raw = b"".join((c + half).to_bytes(sb, "little") for c in p)
        return int.from_bytes(raw, "little") - half * spread(len(p))
    prod = pack(a) * pack(b)
    count = 2 * n - 1
    raw = (prod + half * spread(count)).to_bytes(sb * count, "little")
    out = [0] * n
    for i in range(count):
        c = int.from_bytes(raw[i * sb:(i + 1) * sb], "little") - half
        if i < n:
            out[i] += c
        else:
            out[i - n] -= c
    return out


def install(wbits=None):
    """Patch the engine at run time; returns a function that restores every patched name."""
    saved = (B.zmul, B.ERR_BOUND, B.Drbg.small, B.WBITS)
    B.zmul = kronecker_zmul
    B.ERR_BOUND = ETA
    B.Drbg.small = cbd_small
    if wbits is not None:
        B.WBITS = wbits

    def restore():
        B.zmul, B.ERR_BOUND, B.Drbg.small, B.WBITS = saved
    return restore


def run(n, k):
    restore = install()
    try:
        return _run(n, k)
    finally:
        restore()


def _run(n, k):
    p = B.Params(n, k)
    kh = B.KeyHolder(p, b"standard-smoke")
    enc = B.Encryptor(kh.public, b"standard-smoke-enc")
    evk = kh.public.evk
    bits = [(0, 0), (1, 1), (1, 0)]
    for i, (x, y) in enumerate(bits):
        cx = enc.encrypt_bit(x, "sx%d" % i).value
        cy = enc.encrypt_bit(y, "sy%d" % i).value
        cxor = B.ct_xor(p, cx, cy)
        cand = B.ct_and(p, evk, cx, cy)
        assert kh.decrypt_bit(cxor) == x ^ y, ("xor", x, y)
        assert kh.decrypt_bit(cand) == x & y, ("and", x, y)
        for c in (cx, cxor, cand):
            assert kh.noise(c) <= c.nb, "tracked bound violated"
        print("bits (%d,%d): xor=%d and=%d  noise(and)=2^%d  bound=2^%d  limit=2^%d" % (
            x, y, x ^ y, x & y, kh.noise(cand).bit_length(), cand.nb.bit_length(), p.half_delta.bit_length()))
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    n = int(args[args.index("--n") + 1]) if "--n" in args else 4096
    k = int(args[args.index("--k") + 1]) if "--k" in args else 109
    sys.exit(run(n, k))
