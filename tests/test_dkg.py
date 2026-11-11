import hashlib
import itertools
import unittest

import dkg_wad18 as D
from dkg_wad18 import DKGNode, new_node

SEED = b"dkg-test-seed"


def is_prime(n):
    """Deterministic Miller-Rabin: these 12 bases are exact for n < 3.3 * 10^24."""
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n < 2:
        return False
    for p in small:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def ref_coeff(seed, node_id, k):
    h = hashlib.sha256(seed + b"|dkg|" + str(node_id).encode() + b"|" + str(k).encode()).digest()
    return int.from_bytes(h, "big") % (2 ** 61 - 1)


def make_node(coeffs, node_id=1, total=5):
    """DKGNode whose polynomial is exactly `coeffs` (set after validated construction)."""
    node = new_node(node_id, len(coeffs), total, SEED).value
    node.coefficients = list(coeffs)
    return node


class TestField(unittest.TestCase):
    def test_modulus_is_the_mersenne_prime_2_61_minus_1(self):
        self.assertEqual(D.P, 2305843009213693951)
        self.assertTrue(is_prime(D.P))
        self.assertTrue(D.P > D.WAD)
        self.assertEqual(D.WAD, 10 ** 18)
        self.assertFalse(is_prime(D.WAD))

    def test_primality_helper_is_sound(self):
        for n in (2, 3, 5, 97, 7919, 2 ** 31 - 1):
            self.assertTrue(is_prime(n), n)
        for n in (0, 1, 4, 9, 91, 561, 1105, 10 ** 18, 2 ** 61 + 1):
            self.assertFalse(is_prime(n), n)

    def test_every_small_gap_is_invertible(self):
        for g in list(range(1, 200)) + [D.P - 1, D.P - 2]:
            self.assertEqual(g * pow(g, -1, D.P) % D.P, 1)

    def test_result_helpers_and_int_check(self):
        self.assertEqual(D.ok(3), (True, 3, ""))
        self.assertEqual(D.fail("X"), (False, None, "X"))
        self.assertEqual(D.Res.__name__, "Res")
        self.assertEqual(D.Res._fields, ("ok", "value", "reason"))
        self.assertEqual(repr(D.ok(1)), "Res(ok=True, value=1, reason='')")
        self.assertTrue(D.is_int(0) and D.is_int(-4))
        for bad in (True, False, "1", None, b"1", [1], (1,)):
            self.assertFalse(D.is_int(bad), bad)


class TestConstructorValidation(unittest.TestCase):
    def reason(self, *a):
        r = new_node(*a)
        self.assertFalse(r.ok)
        self.assertIsNone(r.value)
        return r.reason

    def test_every_failure_has_its_own_reason(self):
        self.assertEqual(self.reason("1", 1, 3, SEED), "NON_INTEGER_PARAMETER")
        self.assertEqual(self.reason(1, "1", 3, SEED), "NON_INTEGER_PARAMETER")
        self.assertEqual(self.reason(1, 1, "3", SEED), "NON_INTEGER_PARAMETER")
        self.assertEqual(self.reason(True, 1, 3, SEED), "NON_INTEGER_PARAMETER")
        self.assertEqual(self.reason(1, 1, 3, "seed"), "BAD_SEED")
        self.assertEqual(self.reason(1, 1, 3, b""), "BAD_SEED")
        self.assertEqual(self.reason(1, 1, 0, SEED), "BAD_TOTAL_NODES")
        self.assertEqual(self.reason(1, 1, D.P, SEED), "BAD_TOTAL_NODES")
        self.assertEqual(self.reason(1, 1, D.P + 1, SEED), "BAD_TOTAL_NODES")
        self.assertEqual(self.reason(1, 1, 2 * D.P, SEED), "BAD_TOTAL_NODES")
        self.assertEqual(self.reason(1, 0, 3, SEED), "BAD_THRESHOLD")
        self.assertEqual(self.reason(1, 4, 3, SEED), "BAD_THRESHOLD")
        self.assertEqual(self.reason(0, 1, 3, SEED), "BAD_NODE_ID")
        self.assertEqual(self.reason(4, 1, 3, SEED), "BAD_NODE_ID")

    def test_boundaries_accepted(self):
        for args in ((1, 1, 1, SEED), (3, 3, 3, SEED), (1, 3, 3, SEED), (3, 1, 3, SEED)):
            r = new_node(*args)
            self.assertTrue(r.ok, args)
            self.assertEqual(r.reason, "")
            self.assertIsInstance(r.value, DKGNode)

    def test_constructor_state_and_coefficients_match_independent_derivation(self):
        node = new_node(4, 3, 9, SEED).value
        self.assertEqual((node.node_id, node.threshold, node.total_nodes), (4, 3, 9))
        self.assertEqual(node.coefficients, [ref_coeff(SEED, 4, k) for k in range(3)])
        self.assertEqual(node.received_shares, [])
        self.assertTrue(all(0 <= c < D.P for c in node.coefficients))

    def test_derivation_depends_on_seed_node_and_index(self):
        c = D.derive_coefficient
        base = c(SEED, 1, 0)
        self.assertNotEqual(base, c(SEED + b"x", 1, 0))
        self.assertNotEqual(base, c(SEED, 2, 0))
        self.assertNotEqual(base, c(SEED, 1, 1))
        self.assertNotEqual(c(SEED, 1, 11), c(SEED, 11, 1))
        self.assertEqual(base, c(SEED, 1, 0))
        self.assertEqual(c(b"a", 12, 3), ref_coeff(b"a", 12, 3))

    def test_received_shares_not_shared_between_nodes(self):
        a, b = make_node([1, 2]), make_node([3, 4])
        a.receive_share(1, 9)
        self.assertEqual(b.received_shares, [])


class TestPolynomial(unittest.TestCase):
    def test_horner_order_and_values(self):
        node = make_node([5, 7, 11])
        self.assertEqual(node.evaluate_polynomial(0), 5)
        self.assertEqual(node.evaluate_polynomial(1), 23)
        self.assertEqual(node.evaluate_polynomial(2), 5 + 14 + 44)
        self.assertEqual(node.evaluate_polynomial(10), 5 + 70 + 1100)
        self.assertEqual(node.evaluate_polynomial(D.P + 3), node.evaluate_polynomial(3))

    def test_wraps_mod_p_at_every_step(self):
        node = make_node([D.P - 1, D.P - 1, D.P - 1])
        self.assertEqual(node.evaluate_polynomial(2), D.P - 7)
        self.assertEqual(node.evaluate_polynomial(1), D.P - 3)
        sq = make_node([0, 0, 1])
        self.assertEqual(sq.evaluate_polynomial(2 ** 40), 2 ** 80 % D.P)
        self.assertEqual(sq.evaluate_polynomial(D.P - 1), 1)

    def test_single_coefficient_is_constant(self):
        node = make_node([77])
        for x in (0, 1, 5, D.P - 1):
            self.assertEqual(node.evaluate_polynomial(x), 77)

    def test_generate_shares_ids_values_and_count(self):
        node = make_node([5, 7, 11], total=4)
        self.assertEqual(node.generate_shares(), [(1, 23), (2, 63), (3, 5 + 21 + 99), (4, 5 + 28 + 176)])
        self.assertEqual(len(make_node([5], total=1).generate_shares()), 1)

    def test_shares_are_in_field_for_real_seeds(self):
        node = new_node(2, 4, 6, SEED).value
        self.assertTrue(all(0 <= v < D.P for _, v in node.generate_shares()))


class TestReceive(unittest.TestCase):
    def test_appends_in_order_and_returns_count(self):
        node = make_node([1])
        r = node.receive_share(3, 30)
        self.assertEqual((r.ok, r.value, r.reason), (True, 1, ""))
        self.assertEqual(node.receive_share(1, 10).value, 2)
        self.assertEqual(node.received_shares, [(3, 30), (1, 10)])

    def test_refusals_leave_state_unchanged(self):
        node = make_node([1], total=5)
        node.receive_share(2, 5)
        cases = (((2, 6), "DUPLICATE_SENDER"), ((0, 1), "BAD_SENDER"), ((6, 1), "BAD_SENDER"),
                 ((3, -1), "SHARE_OUT_OF_FIELD"), ((3, D.P), "SHARE_OUT_OF_FIELD"),
                 ((3, D.P + 1), "SHARE_OUT_OF_FIELD"), ((3, 2 * D.P), "SHARE_OUT_OF_FIELD"),
                 (("3", 1), "NON_INTEGER_SHARE"), ((3, "1"), "NON_INTEGER_SHARE"),
                 ((True, 1), "NON_INTEGER_SHARE"), ((3, True), "NON_INTEGER_SHARE"))
        for args, reason in cases:
            r = node.receive_share(*args)
            self.assertEqual((r.ok, r.value, r.reason), (False, None, reason), args)
        self.assertEqual(node.received_shares, [(2, 5)])
        self.assertTrue(node.receive_share(5, D.P - 1).ok)
        self.assertTrue(node.receive_share(1, 0).ok)

    def test_final_share_sums_mod_p(self):
        node = make_node([1])
        self.assertEqual(node.compute_final_secret_share(), 0)
        node.receive_share(1, D.P - 1)
        node.receive_share(2, 5)
        self.assertEqual(node.compute_final_secret_share(), 4)


class TestEndToEnd(unittest.TestCase):
    def run_dkg(self, t, n, tag):
        nodes = [new_node(i, t, n, SEED + tag).value for i in range(1, n + 1)]
        for sender in nodes:
            for rid, val in sender.generate_shares():
                self.assertTrue(nodes[rid - 1].receive_share(sender.node_id, val).ok)
        return nodes

    def test_final_shares_lie_on_the_summed_polynomial(self):
        nodes = self.run_dkg(3, 5, b"a")
        summed = [sum(nd.coefficients[k] for nd in nodes) % D.P for k in range(3)]
        for nd in nodes:
            x = nd.node_id
            self.assertEqual(nd.compute_final_secret_share(), (summed[0] + summed[1] * x + summed[2] * x * x) % D.P)

    def test_any_threshold_subset_reconstructs_the_joint_secret(self):
        """The old composite-modulus code failed here for every t >= 3 (and for even id gaps)."""
        import mpc_decrypt as M
        for t, n in ((1, 3), (2, 4), (3, 5), (4, 6), (5, 7)):
            nodes = self.run_dkg(t, n, b"t%d" % t)
            secret = sum(nd.coefficients[0] for nd in nodes) % D.P
            shares = [(nd.node_id, nd.compute_final_secret_share()) for nd in nodes]
            for subset in itertools.combinations(shares, t):
                r = M.combine_partial_decryptions(list(subset), t)
                self.assertEqual((r.ok, r.value), (True, secret), (t, n, subset))

    def test_fewer_than_threshold_does_not_reconstruct(self):
        import mpc_decrypt as M
        nodes = self.run_dkg(3, 5, b"few")
        secret = sum(nd.coefficients[0] for nd in nodes) % D.P
        shares = [(nd.node_id, nd.compute_final_secret_share()) for nd in nodes]
        r = M.combine_partial_decryptions(shares[:2], 2)       # wrong threshold: a different interpolation
        self.assertTrue(r.ok)
        self.assertNotEqual(r.value, secret)


if __name__ == "__main__":
    unittest.main()
