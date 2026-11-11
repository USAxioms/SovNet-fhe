"""Full encrypted solvency attestation (bfv_wad18.attest) at an HES-128-compatible ring size.

Defaults: N = 16384, relinearisation digit 64 bits, centred-binomial error eta = 21 (variance 10.5 >= 3.2^2),
k = the engine's own choose_k(N, bits) for the comparator width (a 4-bit width gives k = 288 <= 438).
The unmodified engine is driven with run-time patches only: Kronecker multiplication (equal to zmul, tested),
ERR_BOUND/eta, and WBITS. Deterministic seeds: re-running reproduces the output ciphertext digests.
Usage: python audit/standard_params_attest.py --debt D --ev E [--bits 4] [--n 16384] [--wbits 64] [--out f.json]
       [--cache DIR]   resumable: each finished AND gate is stored under DIR keyed by its input hash
Takes about an hour for 4 bits on one core. NOT a security claim (see MEMORANDUM section 19).
"""
import hashlib
import json
import sys
import time

import os
import pickle

import bfv_wad18 as B

try:
    from audit import standard_params_smoke as SM
except ImportError:
    import standard_params_smoke as SM


def digest(ct):
    h = hashlib.sha256()
    for poly in (ct.c0, ct.c1):
        h.update(b",".join(str(c).encode() for c in poly) + b"|")
    return h.hexdigest()


def arg(name, default):
    a = sys.argv[1:]
    return int(a[a.index(name) + 1]) if name in a else default


def gate_key(x, y):
    h = hashlib.sha256()
    for ct in (x, y):
        h.update(digest(ct).encode())
    return h.hexdigest()


def run(debt, ev, bits, n, wbits, log=None, cache_dir=None):
    """Runs one attestation under the run-time patches and always restores the engine. Returns a result dict."""
    restore = SM.install(wbits)
    real_and = B.ct_and
    try:
        return _run(debt, ev, bits, n, wbits, log or (lambda *a: None), cache_dir)
    finally:
        B.ct_and = real_and
        restore()


def _run(debt, ev, bits, n, wbits, log, cache_dir):
    k = B.choose_k(n, bits)
    t0 = time.monotonic_ns()

    def now():
        return (time.monotonic_ns() - t0) // 10 ** 9
    real_and = B.ct_and
    count = [0]

    def counted_and(p, evk, x, y):
        count[0] += 1
        path = None
        if cache_dir:
            path = os.path.join(cache_dir, gate_key(x, y) + ".pkl")
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    c0, c1, nb = pickle.load(fh)
                return B.Ciphertext(c0, c1, nb)
        out = real_and(p, evk, x, y)
        if path:
            with open(path + ".tmp", "wb") as fh:
                pickle.dump((list(out.c0), list(out.c1), out.nb), fh)
            os.replace(path + ".tmp", path)
        if count[0] % 5 == 0:
            log("  %d ANDs at %ds" % (count[0], now()))
        return out
    B.ct_and = counted_and
    p = B.Params(n, k)
    log("N=%d k=%d wbits=%d eta=%d l=%d  debt=%d ev=%d bits=%d" % (n, k, wbits, SM.ETA, p.l, debt, ev, bits))
    kh = B.KeyHolder(p, b"standard-attest")
    log("keygen done at %ds" % now())
    enc = B.Encryptor(kh.public, b"standard-attest-enc")
    dc = enc.encrypt_int(debt, bits, "debt").value
    ec = enc.encrypt_int(ev, bits, "ev").value
    log("encrypted at %ds" % now())
    r = B.attest(kh.public, dc, ec)
    log("attest finished at %ds ok=%s ands=%d" % (now(), r.ok, count[0]))
    result = {"n": n, "k": k, "wbits": wbits, "eta": SM.ETA, "bits": bits, "debt": debt, "ev": ev,
              "attest_ok": r.ok, "and_gates": count[0], "elapsed_s": now(),
              "expected": [20 * debt > 9 * ev, 25 * debt > 12 * ev]}
    if r.ok:
        cap, brk = r.value
        got = [kh.decrypt_bit(cap) == 1, kh.decrypt_bit(brk) == 1]
        result.update({"got": got, "match": got == result["expected"],
                       "noise_bits": [kh.noise(cap).bit_length(), kh.noise(brk).bit_length()],
                       "bound_bits": [cap.nb.bit_length(), brk.nb.bit_length()],
                       "limit_bits": p.half_delta.bit_length(),
                       "bound_dominates": kh.noise(cap) <= cap.nb and kh.noise(brk) <= brk.nb,
                       "cap_digest": digest(cap), "brk_digest": digest(brk)})
    return result


def main():
    debt, ev = arg("--debt", 7), arg("--ev", 15)
    bits, n, wbits = arg("--bits", 4), arg("--n", 16384), arg("--wbits", 64)
    out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else None
    cache = sys.argv[sys.argv.index("--cache") + 1] if "--cache" in sys.argv else None
    if cache:
        os.makedirs(cache, exist_ok=True)
    result = run(debt, ev, bits, n, wbits, log=lambda m: print(m, flush=True), cache_dir=cache)
    print(json.dumps(result, sort_keys=True), flush=True)
    if out:
        with open(out, "w") as fh:
            json.dump(result, fh, sort_keys=True, indent=1)
    return 0 if result["attest_ok"] and result.get("match") and result.get("bound_dominates") else 1


if __name__ == "__main__":
    sys.exit(main())
