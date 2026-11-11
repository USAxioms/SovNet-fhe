"""
Distributed Key Generation (DKG) over GF(P): standalone Shamir dealer-sum sharing (rev 9).
Not bound to the BFV secret key used by threshold_bfv.py (see MEMORANDUM section 15).

Shamir sharing is evaluated over the prime field GF(P), P = 2^61 - 1 (a Mersenne prime), so every
difference of distinct node ids in 1..P-1 is invertible and any threshold t >= 1 reconstructs.
(Rev 6 used the composite modulus 10^18, which is not a field: see MEMORANDUM section 12.)

Deterministic: coefficients are derived from an explicit seed with SHA-256, never from OS entropy.
Integer-only; failures are returned as Res values, not raised.
"""

import hashlib
from collections import namedtuple
from typing import List, Tuple

WAD = 10**18
P = 2**61 - 1

Res = namedtuple("Res", "ok value reason")


def ok(value):
    return Res(True, value, "")


def fail(reason):
    return Res(False, None, reason)


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def derive_coefficient(seed: bytes, node_id: int, index: int) -> int:
    """Uniform-enough element of GF(P): SHA-256 of a labelled seed, reduced mod P."""
    label = seed + b"|dkg|" + str(node_id).encode() + b"|" + str(index).encode()
    return int.from_bytes(hashlib.sha256(label).digest(), "big") % P


def new_node(node_id, threshold, total_nodes, seed):
    """Validated constructor. Returns Res(DKGNode) or a named failure."""
    if not (is_int(node_id) and is_int(threshold) and is_int(total_nodes)):
        return fail("NON_INTEGER_PARAMETER")
    if not isinstance(seed, bytes) or not seed:
        return fail("BAD_SEED")
    if total_nodes < 1 or total_nodes >= P:
        return fail("BAD_TOTAL_NODES")
    if threshold < 1 or threshold > total_nodes:
        return fail("BAD_THRESHOLD")
    if node_id < 1 or node_id > total_nodes:
        return fail("BAD_NODE_ID")
    return ok(DKGNode(node_id, threshold, total_nodes, seed))


class DKGNode:
    """Precondition: arguments already validated (use new_node)."""

    def __init__(self, node_id: int, threshold: int, total_nodes: int, seed: bytes):
        self.node_id = node_id
        self.threshold = threshold
        self.total_nodes = total_nodes
        self.coefficients = [derive_coefficient(seed, node_id, k) for k in range(threshold)]
        self.received_shares: List[Tuple[int, int]] = []

    def evaluate_polynomial(self, x: int) -> int:
        """Evaluates local secret polynomial at point x over GF(P) (Horner)."""
        result = 0
        for coeff in reversed(self.coefficients):
            result = (result * x + coeff) % P
        return result

    def generate_shares(self) -> List[Tuple[int, int]]:
        """Share tuple (node_id, evaluation) for every participant 1..total_nodes."""
        return [(i, self.evaluate_polynomial(i)) for i in range(1, self.total_nodes + 1)]

    def receive_share(self, sender_id: int, share_value: int):
        """Records one dealer share. Returns Res; duplicates and out-of-field values are refused."""
        if not (is_int(sender_id) and is_int(share_value)):
            return fail("NON_INTEGER_SHARE")
        if sender_id < 1 or sender_id > self.total_nodes:
            return fail("BAD_SENDER")
        if share_value < 0 or share_value >= P:
            return fail("SHARE_OUT_OF_FIELD")
        if any(s == sender_id for s, _ in self.received_shares):
            return fail("DUPLICATE_SENDER")
        self.received_shares.append((sender_id, share_value))
        return ok(len(self.received_shares))

    def compute_final_secret_share(self) -> int:
        """Sums received shares over GF(P)."""
        return sum(val for _, val in self.received_shares) % P
