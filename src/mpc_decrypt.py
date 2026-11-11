"""
Shamir share recombination over GF(P) (see dkg_wad18) (rev 9).

This module reconstructs a shared field element from threshold-many shares by Lagrange
interpolation at 0. It is NOT connected to the BFV secret key (threshold_bfv.py has its own
n-of-n additive split) and offers no noise smudging: smudging a Shamir share is not meaningful
because Lagrange recombination multiplies the noise (removed in rev 9; see MEMORANDUM section 15).
Failures are returned as Res values, not raised.
"""

from typing import List, Tuple

from dkg_wad18 import P, fail, is_int, ok

def combine_partial_decryptions(shares: List[Tuple[int, int]], threshold: int):
    """Reconstructs f(0) from the first `threshold` shares. Returns Res(value)."""
    if not is_int(threshold) or threshold < 1:
        return fail("BAD_THRESHOLD")
    if len(shares) < threshold:
        return fail("INSUFFICIENT_SHARES")
    used = shares[:threshold]
    for x_i, y_i in used:
        if not (is_int(x_i) and is_int(y_i)):
            return fail("NON_INTEGER_SHARE")
        if y_i < 0 or y_i >= P:
            return fail("SHARE_OUT_OF_FIELD")
    xs = [x % P for x, _ in used]
    if 0 in xs or any(v in xs[:k] for k, v in enumerate(xs)):
        return fail("BAD_NODE_ID")

    reconstructed = 0
    for i, (x_i, y_i) in enumerate(used):
        num = 1
        den = 1
        for j, (x_j, _) in enumerate(used):
            if i != j:
                num = (num * (-x_j)) % P
                den = (den * (x_i - x_j)) % P
        reconstructed = (reconstructed + y_i * num * pow(den, -1, P)) % P
    return ok(reconstructed)
