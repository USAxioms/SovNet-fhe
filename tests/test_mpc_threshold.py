import unittest

import mpc_decrypt as M
from dkg_wad18 import P


def shamir(coeffs, xs):
    return [(x, sum(c * pow(x, k, P) for k, c in enumerate(coeffs)) % P) for x in xs]


class TestModuleSurface(unittest.TestCase):
    def test_field_and_no_smudging_api(self):
        self.assertEqual(M.P, 2 ** 61 - 1)
        for name in ("inject_smudging_noise", "SMUDGING_BOUND", "hashlib"):
            self.assertFalse(hasattr(M, name), name)


class TestCombine(unittest.TestCase):
    def test_refusals_and_reasons(self):
        for args, reason in ((([(1, 1)], 2), "INSUFFICIENT_SHARES"), (([], 1), "INSUFFICIENT_SHARES"),
                             (([(1, 1)], 0), "BAD_THRESHOLD"), (([(1, 1)], -1), "BAD_THRESHOLD"),
                             (([(1, 1)], "1"), "BAD_THRESHOLD"), (([(1, 1)], True), "BAD_THRESHOLD"),
                             (([(1, "1")], 1), "NON_INTEGER_SHARE"), (([("1", 1)], 1), "NON_INTEGER_SHARE"),
                             (([(1, True)], 1), "NON_INTEGER_SHARE"), (([(True, 1)], 1), "NON_INTEGER_SHARE"),
                             (([(1, -1)], 1), "SHARE_OUT_OF_FIELD"), (([(1, P)], 1), "SHARE_OUT_OF_FIELD"),
                             (([(1, P + 1)], 1), "SHARE_OUT_OF_FIELD"), (([(1, 2 * P)], 1), "SHARE_OUT_OF_FIELD"),
                             (([(0, 1)], 1), "BAD_NODE_ID"), (([(P, 1)], 1), "BAD_NODE_ID"),
                             (([(2, 1), (2, 5)], 2), "BAD_NODE_ID"), (([(2, 1), (2 + P, 5)], 2), "BAD_NODE_ID")):
            r = M.combine_partial_decryptions(*args)
            self.assertEqual((r.ok, r.value, r.reason), (False, None, reason), args)

    def test_boundary_accepts(self):
        self.assertEqual(M.combine_partial_decryptions([(1, 9)], 1), (True, 9, ""))
        self.assertEqual(M.combine_partial_decryptions([(1, P - 1)], 1).value, P - 1)
        self.assertEqual(M.combine_partial_decryptions([(1, 0)], 1).value, 0)

    def test_every_threshold_and_subset_recovers_constant_term(self):
        import itertools
        for t in range(1, 7):
            coeffs = [(1234567891011 * (k + 3) + 17 * k * k) % P for k in range(t)]
            coeffs[0] = (coeffs[0] + P - 1) % P
            pts = shamir(coeffs, [1, 2, 3, 4, 6, 9, 10, 17])
            for subset in itertools.combinations(pts, t):
                self.assertEqual(M.combine_partial_decryptions(list(subset), t).value, coeffs[0], (t, subset))
                self.assertEqual(M.combine_partial_decryptions(list(reversed(subset)), t).value, coeffs[0])

    def test_even_gaps_and_gaps_sharing_factors_with_ten_work(self):
        coeffs = [42, 7, 9]
        for ids in ([1, 2, 3], [1, 3, 5], [1, 4, 7], [2, 4, 6], [5, 10, 15], [10, 20, 30]):
            self.assertEqual(M.combine_partial_decryptions(shamir(coeffs, ids), 3).value, 42, ids)
        self.assertEqual(M.combine_partial_decryptions(shamir([42, 7], [1, 3]), 2).value, 42)

    def test_lagrange_weights_for_ids_1_2(self):
        self.assertEqual(M.combine_partial_decryptions([(1, 10), (2, 4)], 2).value, 16)
        self.assertEqual(M.combine_partial_decryptions([(1, 0), (2, 5)], 2).value, P - 5)
        self.assertEqual(M.combine_partial_decryptions([(1, 5), (2, 0)], 2).value, 10)

    def test_only_first_threshold_shares_are_inspected(self):
        good = shamir([42, 7], [1, 2])
        self.assertEqual(M.combine_partial_decryptions(good + [(3, 999)], 2).value, 42)
        self.assertEqual(M.combine_partial_decryptions(good + [("bad", 1), (2, 5)], 2).value, 42)

    def test_x_ids_are_taken_mod_p(self):
        pts = shamir([42, 7], [1, 2])
        shifted = [(pts[0][0] + P, pts[0][1]), pts[1]]
        self.assertEqual(M.combine_partial_decryptions(shifted, 2).value, 42)

    def test_result_is_in_field(self):
        for pts in ([(1, P - 1), (2, P - 1)], [(3, 5), (7, P - 2)]):
            self.assertTrue(0 <= M.combine_partial_decryptions(pts, 2).value < P)

    def test_wrong_threshold_gives_wrong_answer(self):
        pts = shamir([42, 7, 9], [1, 2, 3])
        self.assertNotEqual(M.combine_partial_decryptions(pts[:2], 2).value, 42)


if __name__ == "__main__":
    unittest.main()
