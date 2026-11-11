"""Write audit/equivalents/<engine>.json from a mutation survivors JSON.
Each survivor must match a rule below (by source-line text and mutation kind) or the script
refuses: nothing is pinned without a written justification. Pins bind to the engine sha256."""
import json, os, sys

R = []   # (line substring, id-kind substring or None, class, why)
def rule(line, kind, cls, why):
    R.append((line, kind, cls, why))

ZERO = "v == 0 is the only value whose branch changes; there sign*0 == 0 and -0 == 0, so output is identical."
rule("sign = -1 if v < 0 else 1", None, "proved", ZERO + " (<=0 and the constant 0->1 both only alter the v==0 case)")
rule("a = -v if v < 0 else v", None, "proved", ZERO)
rule("return sum(-x if x < 0 else x for x in p)", None, "proved", "abs(0) == -0 == 0, so a term with x == 0 contributes 0 either way.")
rule("max(len(a), len(b))", "swap01", "proved", "max is symmetric.")
rule("max(len(x.limbs), len(y.limbs))", "swap01", "proved", "max is symmetric.")
rule("xl = list(x.limbs) + [0] *", None, "proved", "Only indices < n are read (range(n)); a longer zero pad is never indexed.")
rule("yl = list(y.limbs) + [0] *", None, "proved", "Only indices < n are read (range(n)); a longer zero pad is never indexed.")
rule("d = d + [0] * (N_LIMBS - len(d))", None, "argued", "Extra trailing zero limbs are inert: _pmul output is only consumed through low indices and limbs are reduced; no length-sensitive consumer, checked by reading the code.")
rule("terms[k] = _padd(list(terms[k]), list(p))", "swap01", "proved", "_padd is symmetric integer vector addition.")
rule("_pmul(list(x.limbs), d)", "swap01", "proved", "polynomial product is commutative over the integers.")
rule("_pmul(list(p), d)", "swap01", "proved", "polynomial product is commutative over the integers.")
rule("_pmul(derive_key_limbs(self._seed, label), list(poly))", "swap01", "proved", "polynomial product is commutative over the integers.")
for ln in ("return he_add(x, n.value)", "r = he_add(acc, c)", "r = he_add(new[acct], delta)", 'r = he_add(balances[ln["a"]], d)'):
    rule(ln, "swap01", "argued", "he_add is commutative on limbs (mod add), terms (symmetric merge, dict equality ignores order) and bound (sum); the failure path depends only on the bound sum.")
rule('if side == "D":', "Eq>GtE", "proved", "post() first rejects any side outside {D,C}; on that domain 'D'>='D' true and 'C'>='D' false, identical to ==.")
rule('if ln["s"] == "C":', "Eq>LtE", "proved", "replay lines already passed post(); sides are in {D,C}; 'D'<='C' false and 'C'<='C' true, identical to ==.")
rule("if not rel.ok:", "cond:false", "argued", "Dead: over_cap implies ltv_status admitted 20*bound(new debt) < HALF, so bound(new)+bound(old) < HALF/10 and he_sub cannot fail here.")
rule("return self._reject(txid, rel.reason)", None, "argued", "Dead branch (see 'if not rel.ok' pin).")
rule("if not tot.ok or not self.auditor.is_zero(tot.value):", "bool:left", "argued", "Reached only after replay parity and balance equality: total = sum of posting deltas, each decrypting to 0 mod the modulus, so is_zero(tot) holds whenever tot.ok.")
rule("B.qadd(B.qmul(list(ct.c1), self._share, self.p), e, self.p)", "swap01", "proved", "qadd and qmul are commutative modulo q.")
rule("ph = B.qadd(ph, poly, p)", "swap01", "proved", "qadd is commutative modulo q.")

rule("if x == 0:", None, "proved", "Zero-skip is a pure optimisation: a zero coefficient adds 0*y to every output slot.")
rule("if y == 0:", None, "proved", "Zero-skip is a pure optimisation: a zero coefficient adds x*0 to the output slot.")
rule("continue", None, "proved", "Removing a zero-skip 'continue' only adds terms equal to 0.")
rule("while len(self._buf) < n:", "Lt>LtE", "proved", "The DRBG output is the fixed concatenation of sha256 blocks; refilling one block early does not change the byte stream.")
rule("b = self.bytes(1)[0]", "const", "proved", "bytes(1) has length 1, so index -1 and index 0 coincide.")
rule("a = -s if s < 0 else s", "Lt>LtE", "proved", ZERO)
rule("a = -s if s < 0 else s", "const:+1", "proved", "s < 1 is s <= 0; only s == 0 differs and there -0 == 0.")
rule("worst = 0", "const:-1", "proved", "The first measured |e| >= 0 replaces -1 (e > -1), so the loop result is identical for N >= 1.")
rule("e = x - r * DELTA", "bswap", "proved", "Operands swapped negates e; e is immediately replaced by |e|.")
rule("e = -e if e < 0 else e", None, "proved", ZERO)
rule("if e > worst:", "Gt>GtE", "proved", "Equal values assign the same value.")
rule("b = _padd(_pneg(_pmul(a, self._s))", "swap01", "proved", "Polynomial product and addition mod q are commutative.")
rule("c0 = _padd(_pmul(list(b), u), e1)", "swap01", "proved", "Polynomial product and addition mod q are commutative.")
rule("c1 = _padd(_pmul(list(a), u), e2)", "swap01", "proved", "Polynomial product and addition mod q are commutative.")
rule("sc1 = _pmul(list(ct.c1), self._s)", "swap01", "proved", "Polynomial product is commutative.")
rule("return _check(_padd(x.c0, y.c0), _padd(x.c1, y.c1), x.nb + y.nb, x.pb + y.pb)", "swap01", "proved", "Addition mod q and integer sums are commutative.")

rule("if isinstance(a, int) and isinstance(b, int):", "cond:false", "proved", "Fallthrough branches return b/a/0 for constant 0/1 operands, which equals a^b / a&b on {0,1}.")
rule("return ops.xor(a, b)", "swap01", "argued", "XOR over wires is commutative: ct_xor adds limbs mod q and sums nb; _W/BoundOps use symmetric max/sum.")
rule("return ops.and_(a, b)", "swap01", "argued", "ct_and is symmetric up to the symmetric products t1 = x0*y1 + x1*y0; mul_bound is symmetric in (v1, v2).")
rule("t0 = zmul(x.c0, y.c0, p.n)", "swap01", "proved", "negacyclic integer product is commutative.")
rule("a = zmul(x.c0, y.c1, p.n)", "swap01", "proved", "t1 = a + b is symmetric; the product is commutative.")
rule("b = zmul(x.c1, y.c0, p.n)", "swap01", "proved", "t1 = a + b is symmetric; the product is commutative.")
rule("t2 = zmul(x.c1, y.c1, p.n)", "swap01", "proved", "negacyclic integer product is commutative.")
rule("return [centre(c, p.q) for c in zmul(a, b, p.n)]", "swap01", "proved", "negacyclic integer product is commutative.")
rule("Ciphertext(qadd(x.c0, y.c0, p), qadd(x.c1, y.c1, p), x.nb + y.nb)", "swap01", "proved", "Addition mod q and integer sums are commutative.")
rule("out0 = qadd(out0, qmul(d, bj, p), p)", "swap01", "proved", "Addition and ring product mod q are commutative.")
rule("out1 = qadd(out1, qmul(d, aj, p), p)", "swap01", "proved", "Addition and ring product mod q are commutative.")
rule("c0 = qadd(qmul(list(self.pub.b), u, p), e1, p)", "swap01", "proved", "Addition and ring product mod q are commutative.")
rule("c1 = qadd(qmul(list(self.pub.a), u, p), e2, p)", "swap01", "proved", "Addition and ring product mod q are commutative.")
rule("b = qadd([centre(-c, p.q) for c in qmul(a, self._s, p)], e, p)", "swap01", "proved", "Addition and ring product mod q are commutative.")
rule("bj = qmul(aj, self._s, p)", "swap01", "proved", "Ring product mod q is commutative.")
rule("bj = qadd(bj, ej, p)", "swap01", "proved", "Addition mod q is commutative.")
rule("bj = qadd(bj, shifted, p)", "swap01", "proved", "Addition mod q is commutative.")
rule("sc1 = qmul(list(ct.c1), self._s, self.p)", "swap01", "proved", "Ring product mod q is commutative.")
rule("return qadd(list(ct.c0), sc1, self.p)", "swap01", "proved", "Addition mod q is commutative.")
rule("c0[0] = centre(c0[0] + p.delta, p.q)", "bin:Sub", "proved", "t = 2 so q = 2*delta and -delta == delta (mod q); centre() canonicalises.")
rule("c0[0] = centre(c0[0] + bit * p.delta, p.q)", "bin:Sub", "proved", "bit is 0 or 1 and -delta == delta (mod q) because q = 2*delta; centre() canonicalises.")
rule("if value < 0 or value >> bits:", None, "proved", "For negative value, value >> bits is -1 or less, hence truthy: the 'value < 0' test is redundant (and -1 vs 0 in its constant is the same predicate on integers).")
rule("while d < width:", "Lt>LtE", "proved", "When d == width the inner range(d, width) is empty, so the extra pass changes nothing.")
rule("if len(parts) == 2:", "Eq>GtE", "proved", "After the while loop len(parts) <= 2.")
rule("if len(parts) == 1:", "Eq>GtE", "proved", "len(parts) <= 1 here; >= 1 and == 1 agree (the 0 case is excluded by both).")
rule("while (const >> i) != 0:", "NotEq>Gt", "proved", "const is a non-negative literal; != 0 and > 0 coincide.")
rule("while len(nodes) > 1:", "Gt>NotEq", "argued", "nodes is never empty (width >= 1), so != 1 and > 1 coincide; width 0 is never constructed (width = max(len)+6).")
rule("width = max(len(debt), len(ev)) + 6", None, "argued", "Bits above the value range are constants and fold to zero gates; +5 already suffices because 25*(2^b-1) < 2^(b+5), so width only has to be large enough and cost is unchanged (checked by exact gate-count goldens for 1..6 bits).")
rule("k = 64", "const:0", "argued", "Search start only; the result is the least multiple of 32 that fits and every golden/grid case needs k >= 64, so starting at 0 visits 0 and 32 first and rejects them.")
rule("if worst < p.half_delta:", "Lt>LtE", "argued", "Would differ only if the worst-case bound equals half_delta exactly; the golden grid asserts strict inequality at every probed k.")
rule("while len(self._buf) < n:", "Lt>LtE", "proved", "The DRBG output is the fixed concatenation of sha256 blocks; refilling one block early does not change the byte stream.")
rule("b = self.bytes(1)[0]", "const", "proved", "bytes(1) has length 1, so index -1 and index 0 coincide.")
rule("worst = 0", "const:-1", "proved", "The first measured |e| >= 0 replaces -1, so the loop result is identical.")
rule("e = x - r * self.p.delta", "bswap", "proved", "Operands swapped negates e; e is immediately replaced by |e|.")
rule("e = -e if e < 0 else e", None, "proved", ZERO)
rule("if e > worst:", "Gt>GtE", "proved", "Equal values assign the same value.")
rule("if len(nodes) % 2:", "bswap", "argued", "2 % len is truthy for even len > 2 and appends a duplicate of the last node; the reduction lt = hi.lt ^ (hi.eq & lo.lt) is idempotent on a repeated top node (checked by hand and by exhaustive plain-wire tests for widths 1..8).")
rule("return W(max", None, "proved", "max is symmetric.")
rule("return _W(max(a.v, b.v))", "swap01", "proved", "max is symmetric.")
rule("return _W(max(a.v, b.v) + 1)", "swap01", "proved", "max is symmetric.")
rule("return b if a == 0 else ops.not_(b)", "Eq>LtE", "proved", "Operand is a constant bit in {0,1}; <= 0 and == 0 coincide.")
rule("return a if b == 0 else ops.not_(a)", "Eq>LtE", "proved", "Operand is a constant bit in {0,1}; <= 0 and == 0 coincide.")
rule("return 0 if a == 0 else b", "Eq>LtE", "proved", "Operand is a constant bit in {0,1}; <= 0 and == 0 coincide.")
rule("return 0 if b == 0 else a", "Eq>LtE", "proved", "Operand is a constant bit in {0,1}; <= 0 and == 0 coincide.")
rule("carry = 0 if i == 0 else gg[i - 1]", "Eq>LtE", "proved", "i is a non-negative loop index; <= 0 and == 0 coincide.")
rule("return parts[0]", "const", "proved", "len(parts) == 1 here, so index -1 equals index 0.")
rule("return nodes[0][0]", "const", "proved", "len(nodes) == 1 here, so index -1 equals index 0.")
rule("self.rounding = (n * n + n + 2) // 2", "const:+1", "proved", "n*n + n is always even, so adding 3 instead of 2 gives the same floor.")
rule("digits = [[0] * p.n for _ in range(p.l)]", None, "proved", "Every entry is overwritten by the loop below.")
rule("(2 * p.n * v1 * v2 + p.q - 1) // p.q", "const:+1", "proved", "The numerator term is even and q is even, so x % q == 1 never occurs; the ceiling cannot change.")
rule("if x == 0:", "cond:false", "proved", "Zero-skip is a pure optimisation.")
rule("if y == 0:", "cond:false", "proved", "Zero-skip is a pure optimisation.")
rule("continue", None, "proved", "Removing a zero-skip 'continue' only adds terms equal to 0.")

def main(survivors_json):
    d = json.load(open(survivors_json))
    pins, bad = {}, []
    for s in d["survivors"]:
        hit = None
        for line, kind, cls, why in R:
            if line in s["line"] and (kind is None or kind in s["id"]):
                hit = (cls, why); break
        if hit is None: bad.append(s)
        else: pins[s["id"]] = {"class": hit[0], "why": hit[1]}
    if bad:
        for s in bad: print("UNJUSTIFIED", s["id"], s["line"])
        return 1
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "equivalents", os.path.basename(d["engine"]) + ".json")
    json.dump({"engine_sha256": d["sha256"], "pins": pins}, open(out, "w"), indent=1, sort_keys=True)
    print("wrote", out, len(pins), "pins"); return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
