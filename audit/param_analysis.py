"""Parameter gap analysis (integer-only, deterministic, no wall clock).

For each comparator width (bits) and ring degree N it prints the modulus size k = log2 q that the engine's
own worst-case noise analysis (bfv_wad18.choose_k) requires, and marks cells where k is within the
Homomorphic Encryption Security Standard 128-bit classical maximum for that N (ternary secret, sigma 3.2).

Error distribution: Drbg.small() is a CENTRED BINOMIAL with eta = ERR_BOUND (difference of two eta-bit
popcounts; eta = 3 uses 3+3 bits of one byte). Its variance is eta/2 (exactly 1.5 for eta = 3, sigma ~ 1.22),
far below the table's sigma = 3.2 (variance 10.24), which needs eta >= 21. The table is for a discrete
Gaussian; a centred binomial of equal variance is the usual substitute, not an identical distribution.
This tool makes NO security claim: a table lookup is necessary, not sufficient (see MEMORANDUM section 19).
"""
import sys

import bfv_wad18 as B

HES_128_TERNARY = {1024: 27, 2048: 54, 4096: 109, 8192: 218, 16384: 438, 32768: 881, 65536: 1761}
DEGREES = (1024, 2048, 4096, 8192, 16384, 32768)
WIDTHS = (4, 8, 16, 32, 48, 64, 96)


def variance_times_2(eta):
    return eta                                     # 2 * Var(centred binomial eta) = eta


def sigma_ok(eta):
    return variance_times_2(eta) * 100 >= 2 * 1024           # Var >= 3.2^2 = 10.24, compared as integers


def table(err_bound):
    saved = B.ERR_BOUND
    B.ERR_BOUND = err_bound
    try:
        return dict(((bits, n), B.choose_k(n, bits)) for bits in WIDTHS for n in DEGREES)
    finally:
        B.ERR_BOUND = saved


def smallest_n(grid, bits):
    for n in DEGREES:
        if n in HES_128_TERNARY and grid[(bits, n)] <= HES_128_TERNARY[n]:
            return n
    return None


def main():
    for eb in (3, 21):
        grid = table(eb)
        print("eta=ERR_BOUND=%d  2*Var=%d  sigma>=3.2: %s" % (eb, variance_times_2(eb), sigma_ok(eb)))
        print("  bits  " + "".join("N=%-8d" % n for n in DEGREES) + "smallest compliant N")
        for bits in WIDTHS:
            cells = "".join("%-4d%-5s" % (grid[(bits, n)], "ok" if grid[(bits, n)] <= HES_128_TERNARY[n] else "")
                            for n in DEGREES)
            print("  %-5d %s%s" % (bits, cells, smallest_n(grid, bits)))
        print("  HES max log q: " + "  ".join("%d:%d" % (n, HES_128_TERNARY[n]) for n in DEGREES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
