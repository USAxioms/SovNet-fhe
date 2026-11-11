# FHE-WAD18 — Institutional Security & Compliance Memorandum (White Paper v1.0.0)

Companion to capsule revision 1. Read §1 first: it states what this system is and is not.

## 1. Scope and honest limits

**What it is.** A zero-dependency, integer-only reference implementation of (a) an additively homomorphic *blinding* scheme over Z_M, M = 2^63 − 1, (b) a ciphertext-only double-entry ledger with a hash-chained log, and (c) a key-holding *Blinded Auditor* that discloses only sign and zero bits.

**What it is not.**

- It is **not lattice-based FHE**. There is no ciphertext×ciphertext multiplication, no bootstrapping, and no noise-growth model. The "noise" in the fault-injection suite is deliberate adversarial perturbation, not RLWE noise.
- Comparisons (LTV ≥ cap, LTV ≥ breaker) are **not computed by the ledger operator over ciphertexts alone**. The operator forms ciphertexts of `cap·EV − debt·WAD` and `brk·EV − debt·WAD` homomorphically; the auditor, who holds the key, reveals one sign bit for each. "Zero plaintext exposure" therefore holds for the *operator*, not the *auditor*, who sees two bits per evaluation and the zero-flag of each posting.
- Keys are derived from a seed with SHA-256, and the same keyholder encrypts and decrypts. Confidentiality reduces to the secrecy of the seed and the one-time use of labels (enforced: `LABEL_REUSE`). This is a one-time-pad-style construction in Z_M; it is information-theoretically hiding only per label and only while labels are never reused. It is not a production KMS design.
- Ciphertext equality (the "parity check") is evaluated as *decryption-to-zero by the auditor*, not as raw ciphertext equality, because independent blindings make equal plaintexts encrypt to different ciphertexts (tested: `test_equal_plaintexts_have_distinct_ciphertexts`).
- Nothing here has had external cryptographic review. Do not clear real assets with it.

## 2. Arithmetic ring (WAD18)

- WAD = 10^18; all quantities are Python `int`. Ratios: cap = 45·WAD//100 = 4.5×10^17, breaker = 48·WAD//100 = 4.8×10^17, both exact. EV = 3×10^9·WAD.
- A repository-wide AST test forbids float/complex constants, `/`, `float`, and the imports `math, decimal, fractions, numpy, random, cmath`.
- Values (up to 256 bits signed) are written as 16 signed base-2^16 limbs; each limb is blinded: `c_i = (a_i + k_i) mod M` with `k_i = SHA256(seed|label|i) mod M`.
- Operators are total: they return `Res(ok, value, reason)` and never raise on valid input. Scalar scaling by a plaintext integer s multiplies the limb vector by the digit polynomial of s. The key schedule is tracked as a public polynomial per label (`terms`), so decryption subtracts `key·poly` exactly.

**Theorem 1 (exactness).** If every limb of the true plaintext vector has |a_i| < HALF = ⌊M/2⌋ at every step, decryption returns the exact integer result of the operation sequence.
*Proof sketch.* Limb arithmetic commutes with reduction mod M; subtracting the tracked key polynomial recovers each plaintext limb mod M; the balanced representative in (−HALF, HALF] equals the true limb by the bound; recomposition Σ p_i·2^{16i} is exact integer arithmetic. ∎

**Headroom accounting.** `Ciphertext.bound` is a public upper bound on |a_i|, updated as `+` for add/sub, `×Σ|digits(s)|` for scale. Any operation reaching `bound ≥ HALF` returns `HEADROOM_EXHAUSTED` instead of a wrong answer (tested with a 90-bit-per-step scaling loop). Theorem 1 is thereby enforced rather than assumed. The bound is conservative and leaks only operation structure.

## 3. Solvency and circuit breaker

For ciphertexts D (debt) and E (EV) the operator computes S_cap = cap·E − WAD·D and S_brk = brk·E − WAD·D homomorphically (exact integer identity: D/E ≤ r ⇔ r·E·… ≥ WAD·D with r in WAD units). The auditor returns sign(S).

| Condition | Outcome |
|---|---|
| S_brk < 0 (LTV > 48 %) | state → FROZEN (sticky), posting rejected `CIRCUIT_BREAKER` |
| S_cap < 0 (45 % < LTV ≤ 48 %) | new borrowing rejected `DEBT_CAP_EXCEEDED`; postings that do not increase debt are allowed; state OVER_CAP |
| otherwise | NORMAL |

Boundaries are strict and tested at the wei level: exactly 45 % is accepted and +1 wei rejected; exactly 48 % does not freeze and 1 wei past it does. FROZEN is sticky by design: an EV recovery does not unfreeze automatically; release is an out-of-band governance action not implemented here.

## 4. Conservation law and audit oracle

Each posting must satisfy ΣD − ΣC = 0 (auditor zero-flag) before it is applied atomically; rejected postings are logged as `REJECT` and leave balances untouched. The log is a SHA-256 hash chain over canonical JSON. `Ledger.audit()` (the recompute-and-compare oracle) replays the log from genesis over ciphertexts and compares to live state; on any deviation it sets HALTED, after which every posting and EV update is rejected.

Detected classes (each has a test): entry tamper, deleted entry, broken `prev`/`seq`, consistent re-hash forgery (caught by replay parity/state divergence, and by `expected_head` anchoring), noise on a live balance, noise on EV, cleared cap flag, un-tripped breaker, global non-zero sum.

**Residual risk.** A fully consistent rewrite that also forges balanced ciphertexts requires the key; without an externally anchored head hash the log alone cannot prove history. Operators must publish the head hash (golden head for the test scenario: `d78758739934d75427dc3259038754b1b5a9d4ce3a6ed2d077e254292a225375`).

## 5. Threat model summary

| Threat | Mitigation | Residual |
|---|---|---|
| Operator reads amounts | Blinded limbs; no plaintext in log (tested) | Seed compromise; structure leakage via `bound`/`terms`/account names |
| Silent overflow | Headroom bound → explicit failure | Bound is conservative, may reject valid deep chains |
| Unbalanced posting | Auditor zero-flag, atomic apply | Auditor availability / honesty |
| State or log tampering | Hash chain + replay oracle + HALT | No external anchor unless head is published |
| Over-leverage | Strict cap & breaker over ciphertexts | Auditor learns two sign bits per evaluation |
| Label reuse | `LABEL_REUSE` rejection | Reuse across processes with the same seed is not detected |

## 6. Verification evidence (this capsule)

- 52 unit/oracle tests, including fault injection; all pass; two independent scenario runs give identical heads (golden pin).
- AST mutation harness: 175 mutants, 161 killed, 14 pinned as equivalent, 0 unaccounted (adjusted score 100 %, raw 92 %). The equivalence list is bound to the engine's SHA-256 and is void if the engine changes. **Equivalence of #91, #137, #160 and #166 is argued from invariants, not machine-proved**; treat it as reviewer-checkable, not as a proof.
- Reproducibility: `build_capsule.py` emits a byte-identical ZIP (sorted entries, fixed timestamps, fixed permissions); `verify_capsule.py` rebuilds and checks the manifest hashes.

## 7. Compliance posture

This memorandum makes no claim of regulatory approval (SOC 2, ISO 27001, FIPS, Basel, or otherwise). It documents design intent and test evidence for review. Production use would need: a real HE or MPC/ZK scheme for comparison without a key-holding auditor, an HSM-backed key custodian with separation of duties, an external log anchor, formal review, and an independent audit.

---

## 8. Revision 2 addendum — RLWE ciphertext layer (`rlwe_wad18.py`)

Rev 1 is retained unchanged. Rev 2 replaces the blinding layer with a BFV-style ring-LWE scheme behind the same ledger code.

**Construction.** Ring R_q = Z_q[x]/(x^64 + 1); plaintext modulus t = 2^192, Δ = 2^128, q = tΔ = 2^320. Secret key ternary; public key (b, a) with b = −a·s + e; encryption (c0, c1) = (b·u + e1 + Δ·m, a·u + e2) with ternary u and errors in [−3, 3]. A value m (|m| ≤ 2^100) lives in the constant coefficient. All randomness is a SHA-256 counter DRBG keyed by seed and label, so every ciphertext is reproducible bit for bit.

**Operations.** add, sub, neg, and multiplication by a plaintext integer. Each ciphertext carries two public bounds: `nb` (noise) and `pb` (a declared plaintext-magnitude cap, never the actual value). Fresh noise is bounded by B(2N+1) = 387; the bound adds under addition and multiplies by |s| under scaling. An operation whose result would reach nb ≥ Δ/2 or pb ≥ t/2 returns `HEADROOM_EXHAUSTED`.

**Theorem 2 (decryption correctness).** If nb < Δ/2 and pb < t/2, decryption of the constant coefficient returns the exact integer result.
*Proof sketch.* c0 + c1·s = Δ·m + v with |v| ≤ nb < Δ/2 (v = e·u + e1 + e2·s for fresh ciphertexts, with |v| ≤ B(2N+1)); rounding (c0 + c1·s)/Δ recovers m mod t exactly, and |m| < t/2 makes the balanced representative equal to m. Linear operations preserve the form with the stated bound updates. ∎ (Tested: measured noise never exceeds the tracked bound across all tested operation chains.)

**What changed against rev 1.**

- Noise is real. A perturbation of size < Δ/2 does not change decryption (RLWE tolerance), so it is invisible to the parity check. It is still caught by the audit oracle, because live state is compared to the replayed state by exact ciphertext equality (`STATE_DIVERGENCE`). A perturbation of Δ shifts the plaintext by one unit and is caught by parity (`PARITY_VIOLATION` / `REPLAY_PARITY`). Both are tested.
- The accounting bounds no longer leak operation structure through a key-polynomial list; they leak only the number and scale of operations.
- Public-key encryption: anyone holding the public key can encrypt, the secret key is needed only to decrypt.

**What did NOT change, stated plainly.**

- Still no ciphertext × ciphertext multiplication, relinearisation, or bootstrapping, and therefore **no homomorphic comparison**. The cap and breaker tests are still decided by a key-holding auditor revealing one sign bit.
- **Parameters are toy-sized.** N = 64 with a 320-bit modulus is far below the ring dimensions that standard lattice-security tables require for moduli of this size. No security claim is made for this capsule. Do not use it to protect real data.
- The key holder and the auditor are the same trust domain. Removing that trust requires threshold decryption or a zero-knowledge range proof; not implemented.
- Value range is narrower than rev 1: |m| ≤ 2^100 (about 1.27 × 10^30), enough for the 3 × 10^27 enterprise value used here.

**Verification evidence, rev 2.** 55 tests (ring laws, negacyclic wrap, DRBG, exactness, bound dominance, headroom boundaries, determinism, ledger and fault-injection ports) all pass. Mutation harness `mutation_oracle2.py`: 201 mutants, 193 killed, 8 pinned equivalent, 0 unaccounted (raw 96 %, adjusted 100 %). Equivalence of mutant #163 is argued from invariants, not machine-proved. Golden ledger head for the rev 2 scenario: `ae608abb977d720b4bfa4ef6e32de91f0bdf1e439d46de21ba00ff4f333dbdfd`.

**Next steps toward the stated objective.** (1) ct×ct multiplication with relinearisation and a bit-decomposition comparison circuit to remove the sign oracle; (2) real security parameters (N ≥ several thousand, which needs an NTT in pure integer Python); (3) threshold key custody; (4) external review.

---

## 9. Revision 3 addendum — encrypted solvency comparator (`bfv_wad18.py`)

Rev 1 and rev 2 are retained unchanged. Rev 3 removes the interactive sign-oracle from the **comparison** step. It does not remove the key holder, and it does not make the ledger oblivious (see "What did NOT change").

**Construction.** Leveled BFV with plaintext modulus t = 2 over R_Q = Z_Q[x]/(x^8 + 1), Q = 2^K. A bit is one ciphertext. XOR is ciphertext addition; NOT adds Δ to the constant coefficient; AND is ciphertext × ciphertext multiplication with relinearisation (tensor product over Z, scaling by 2/Q, balanced base-2^32 gadget decomposition of the quadratic term). Integers are little-endian bit vectors.

**Worst-case noise bound (public, tracked per ciphertext).** With R = N/2 + 2 (ciphertext coefficients are kept centred), L = ⌊K/32⌋ + 1 digits, B = 3:

  v_mul ≤ (1 + 2NR)(v1 + v2) + ⌈2N·v1·v2 / Q⌉ + ⌈(N² + N + 1)/2⌉ + L·N·2^31·B.

Terms: m·v′ + m′·v; 2r·v′ + 2r′·v (wrap-around polynomials r, bounded by centring); 2v·v′/Q; rounding of the three scaled tensor components against 1, s, s²; relinearisation noise. Decryption of a bit is correct whenever the bound is below Δ/2 = 2^(K−2). Tests check that measured noise never exceeds the tracked bound (gate level, random circuits, and full circuits). The bound is loose: at 96 bits the tracked output bounds are below 2^135 and 2^142 while measured noise is below 2^79 (limit 2^159).

**Circuits (all constant-folded).** Kogge–Stone adder, 3:2 compressor, constant multiplier by shift-and-add, tree comparator. The two ratios are exact rationals: 45 % = 9/20 and 48 % = 12/25, so

  over_cap ⇔ 20·D > 9·E,  over_breaker ⇔ 25·D > 12·E

with D and E the WAD-scaled debt and enterprise value. This is exactly the rev 1/2 rule `ratio_WAD·E − WAD·D < 0`, checked at the wei level (D ± 1, E ± 1 around both thresholds) at full 96-bit width, and at 6 bits exhaustively.

| Input width | AND gates | Mult. depth (cap, breaker) | Modulus bits K | Tracked output bound |
|---|---|---|---|---|
| 4 | 120 | 7, 8 | 96 | below 2^78, 2^88 |
| 8 | 259 | 8, 9 | 128 | below 2^85, 2^96 |
| 96 | 5 144 | 14, 15 | 160 | below 2^135, 2^142 |

Measured on this capsule: one full 96-bit attestation (both flags) takes about 1.2 s in pure Python; encrypting two 96-bit inputs takes about 0.01 s.

**Operator / decryptor split.**

- `attest(public, D_bits, E_bits)` uses only public material: ciphertexts, the encryption key and the relinearisation key. It returns two ciphertexts, or `HEADROOM_EXHAUSTED` if any intermediate bound reaches Δ/2 (tested with a deliberately too-small modulus). It never returns a possibly-wrong result.
- `Decryptor.open` is called exactly twice per attestation (once per flag), and its log is tested.
- Compare with rev 2: there the auditor decrypted the full integer S = cap·E − WAD·D and returned its sign by policy; the key holder saw |S|. Here no intermediate integer is ever decrypted. Benign noise on inputs does not change the verdict; flipping an input bit does (both tested).

**What did NOT change, stated plainly.**

1. **The key holder still exists and is trusted.** The decryptor holds the single secret key. It can decrypt any ciphertext, including the inputs, so "opens only two bits" is a **protocol policy, not a cryptographic restriction**. Enforcing it needs threshold key custody or MPC with an output-only release rule. Not implemented.
2. **It is a one-shot attestation, not an oblivious ledger.** Inputs are fresh bit-encryptions of D and E supplied by the clients. There is no bootstrapping, so noise accumulates: chaining postings homomorphically (adders for balances, an oblivious accept/reject mux, an encrypted freeze flag) would exceed any modest modulus after a few postings without periodic re-encryption, which needs the key.
3. **No link to the rev 2 additive balances.** Nothing proves that the bit-encrypted D and E equal the balances held in the additive ledger. Converting an additive integer ciphertext to bits is homomorphic digit extraction; not implemented. A zero-knowledge proof of consistency would be needed to close this gap.
4. **Toy parameters.** N = 8 with moduli of 96–160 bits is far below any security table. No security claim.
5. **Range:** D and E are unsigned and must fit the stated bit width; the full-width tests use 96 bits (about 7.9 × 10^28), enough for the 3 × 10^27 enterprise value.

**Verification evidence, rev 3.** 41 tests (ring, decomposition tie rule, DRBG, gate truth tables, noise dominance, exact 6-bit exhaustive circuit checks, full-width wei-boundary checks against the integer rule, backend agreement, golden attestation digest, full-width real-ciphertext run at 96 bits). Mutation harness `mutation_oracle3.py`: 279 mutants, 267 killed, 12 pinned as equivalent, 0 unaccounted (raw 95 %, adjusted 100 %). The equivalence of mutants #88 and #277 is argued, not machine-proved. The mutation runs skip the full-width real-ciphertext test (`FHE_FAST=1`); the plain-backend full-width test, which exercises the same circuit code, stays in.

**Next steps toward the stated objective.** (1) Threshold key generation and output-only decryption; (2) a verifiable link between additive ledger ciphertexts and the bit-encrypted inputs (ZK range/consistency proof); (3) real parameters (N in the thousands) with an NTT, and bootstrapping or periodic re-encryption for multi-posting chains; (4) external review.

---

## 10. Revision 4 addendum — N = 64 evidence, relinearisation checks, draft ledger contract

`bfv_wad18.py` is **unchanged** from rev 3 (the engine already had ct×ct multiplication, relinearisation with an evaluation key from the SHA-256 DRBG, tracked noise bounds and the encrypted comparator). Rev 4 adds evidence at the requested ring size and does not remove the key holder.

**N = 64 runs (real ciphertexts, 96-bit inputs, `choose_k` → K = 224).** Exact 45 % → flags (0,0); 45 % + 1 wei → (1,0); 48 % + 1 wei → (1,1). Measured noise 2^124–2^128 against a limit of 2^223; about 45 s per attestation in pure Python (N = 8: about 1 s). The tracked bound is conservative, as at N = 8.

**`test_bfv64.py` (13 tests).** AND truth table; multiplicative identity and zero; commutativity/associativity/distributivity over XOR by decryption; relinearised result equals direct degree-2 decryption with s²; noise added by key switching ≤ the declared relinearisation term; evaluation key deterministic from the seed and one component per digit; tracked bound dominates measured noise and grows monotonically with depth; `HEADROOM_EXHAUSTED` (never a wrong answer) at a too-small modulus; comparator agrees with 20D > 9E / 25D > 12E on sampled 4-bit pairs with exactly two opens per attestation.

**Fault injection (manual, six mutants against `test_bfv64` only).** Five killed (removed key-switch term; evk missing W^j; dropped cross term t1; bound missing the relinearisation term; bound missing the cross term). One survived: removing the `+ delta` rounding in the tensor scaling. It changes each scaled coefficient by at most 1, which the tracked bound's rounding term already covers, so no decryption-level test can distinguish it; treated as equivalent by argument, **not machine-proved**. The rev 3 mutation harness was not re-run because the engine file is unchanged (hash in MANIFEST).

**What did NOT change.** The trusted key holder; policy-only "two bits opened"; one-shot leveled attestation; no link to the rev 2 additive balances; toy parameters (N = 64 with K = 224 is still far below standard security tables); no external review.

**`CognitiveStateLedger.sol`.** Draft only: it was not compiled or tested here. It anchors and sequences (entry, approval by a second custodian, verification in a strictly later block, FIFO); it cannot verify BFV maths, so flags are custodian attestations.

---

## 11. Revision 5 addendum — n-of-n threshold decryption (`threshold_bfv.py`)

`bfv_wad18.py` is still unchanged. Rev 5 splits the secret key additively, s = s_1 + … + s_n, and replaces the single `Decryptor` with parties that each publish d_i = c1·s_i + e_i, where e_i is smudging noise bounded by nb·2^40. The combiner outputs round((c0 + Σ d_i)/Δ) mod 2 and fails closed (`HEADROOM_EXHAUSTED`) if ct noise plus all smudge bounds could reach Δ/2. Each party signs off only ciphertexts whose digest it has authorised (`NOT_AUTHORISED` otherwise) and logs every contribution.

**What this removes.** No single key holder exists after setup: one share, or all but one, does not decrypt (tested: a missing share gives a coin flip), and a party never contributes to an unauthorised ciphertext (e.g. an input bit).

**What it does NOT remove.**
1. **Trusted dealer.** Shares come from the existing KeyHolder, which knows s once and must discard it. The evaluation key needs s², so dealer-less keygen needs an interactive protocol; not done.
2. **n-of-n.** All parties are required (no t-of-n availability), and all n colluding can decrypt everything.
3. **The release gate is policy in each party's process.** It is not a cryptographic proof that only the two solvency flags are opened; correct authorisation of digests is still a governance duty.
4. Smudging gives about 40 bits of statistical hiding, and needs about 64 extra modulus bits over the comparator-only minimum (tested: at the minimal K the second flag's open fails closed).
5. Toy parameters (N = 64), no external review.

**Evidence.** 12 tests (shares sum to the secret; combined output equals single-key decryption on the real solvency flags; refusal of unauthorised ciphertexts; missing-share failure; smudge present, large and bounded; per-party audit log; combiner and party headroom guards; minimal-K failure; determinism). Manual fault injection: 8 mutants, 8 killed, after a first pass that survived 4 and led to 4 added tests. The three rev 1–3 mutation harnesses were not re-run (their engine files are unchanged).


---

## 12. Revision 6 addendum — mutation program on the repository layout

**Scope.** `audit/mutation_oracle4.py` mutates every engine in `src/` (AST families: const, str, bin, bswap, aug, unary, cmp, bool, cond, ret, del, args, slice), runs the matching suite per mutant in an isolated copy with `unittest -f`, and exits 0 only when no unpinned survivor remains. An equivalent-mutant pin is honoured only if it carries a class (`proved` or `argued`) and a written reason, and only while the engine sha256 matches (`audit/equivalents/<engine>.json`, produced by `audit/make_pins.py`, which refuses any survivor that has no rule).

**Result (final run, unmodified harness).**

| engine | mutants | killed | pinned proved / argued | unpinned |
|---|---|---|---|---|
| fhe_wad18 | 994 | 969 | 20 / 5 | 0 |
| rlwe_wad18 | 1086 | 1054 | 24 / 8 | 0 |
| bfv_wad18 | 1252 | 1187 | 55 / 10 | 0 |
| threshold_bfv | 163 | 160 | 3 / 0 | 0 |
| dkg_wad18 | 39 | 39 | none | 0 |
| mpc_decrypt | 86 | 86 | none | 0 |
| sovereign_node | 31 | 31 | none | 0 |

Raw (unpinned-credit) scores: 97 %, 97 %, 94 %, 98 %, 100 %, 100 %, 100 %. The "adjusted 100 %" figure is only as good as the pins: 102 are algebraic or domain arguments that can be re-checked by reading the one line concerned; 23 are marked `argued` (they rely on a property of the calling code, e.g. that `nodes` is never empty, or that wider constant-folded width costs no gates) and a stricter run (`--strict`) counts them as survivors.

**What changed in the code.** Behaviour-preserving refactors in `fhe_wad18.py` and `rlwe_wad18.py` (the ledger `post` and `audit` paths; removed redundant branches, same text in both). No cryptographic or numeric behaviour changed. Shared tests are in `tests/ledger_hardening.py`; new suites cover threshold goldens, bound edges, circuit helpers, gate counts, DRBG reference vectors and `choose_k` minimality.

**Limits of this evidence.** Mutation score measures how well the tests pin the current behaviour, not that the behaviour is secure or correct against the specification. Pinned mutants are my judgement, not a machine proof. The harness mutates single AST nodes only. Parameters are still toy-sized.

**Defects found in the modules that arrived with the repository (not fixed here, disclosed).**
1. `dkg_wad18.py` does Shamir/Lagrange over the composite modulus 10^18. This is mathematically unsound for threshold >= 3 and for evaluation-point gaps sharing a factor with 10 (a non-invertible difference); tests only use thresholds and ids where it happens to work.
2. `dkg_wad18.py`, `mpc_decrypt.py` and `sovereign_node.py` call non-deterministic sources (`secrets`, `time`, salted `hash`) and use `raise`, which departs from this project's determinism and no-exception axioms; the tests patch them.
3. The DKG shares are not connected to the BFV key used by `threshold_bfv.py`; they are separate mechanisms.
4. These three modules were not in the rev 5 manifest; they are now.
5. The Solidity contracts and Foundry test are still uncompiled and unrun here.
6. The rev 5 `build_capsule.py` / `verify_capsule.py` assumed a flat layout; they are rewritten for `src/ tests/ audit/`.


---

## 13. Revision 7 addendum — DKG over a prime field; determinism and no-exception rules restored

**Changes (`src/dkg_wad18.py`, `src/mpc_decrypt.py`, `src/sovereign_node.py`; the BFV engines are untouched).**
1. Shamir sharing and Lagrange interpolation now run over GF(P), P = 2^61 - 1 (a Mersenne prime; primality is re-checked in the tests by deterministic Miller-Rabin). Every difference of distinct node ids is invertible, so any threshold t >= 1 reconstructs from any t shares. The tests check every t-subset for t = 1..6 over ids with even gaps and gaps sharing a factor with 10: the case rev 6 documented as failing.
2. Randomness is gone. DKG coefficients are SHA-256(seed | node | index) mod P, and smudging noise is SHA-256(seed | value), both with an explicit caller-supplied seed. The salted builtin `hash()`, `secrets` and `time` are no longer used.
3. No module raises on bad input. `new_node`, `receive_share`, `combine_partial_decryptions` and `step_refinement_loop` return `Res(ok, value, reason)` with a named reason; refusals leave state unchanged. The daemon takes its timestamp from the caller and treats a ledger write error as `LEDGER_WRITE_FAILED` without advancing the chain head.
4. API change: `DKGNode(..., seed)`, `inject_smudging_noise(value, seed)`, `step_refinement_loop(inputs, timestamp)`, and the combiner and daemon return `Res`. Callers of rev 6 must be updated.

**Evidence.** 234 / 156 / 91 mutants: all killed, with no pins, in `--strict` mode (`dkg_wad18`, `mpc_decrypt`, `sovereign_node`). This replaces the rev 6 rows for those three modules. All 316 tests in the eight suites pass.

**Still open.**
- The DKG shares are still not connected to the BFV key used by `threshold_bfv`; they are a separate mechanism. A prime field also does not make "smudging a share" meaningful: noise added to a share is multiplied by Lagrange coefficients on reconstruction, so `inject_smudging_noise` is not a working security feature of this DKG as written.
- Unverified: `contracts/*.sol` and `tests/foundry/CSL.t.sol` were NOT compiled or run. This container has no `solc` or `forge`, and package installs are refused. No compile or test receipt exists, so their status is unchanged: unknown.


---

## 14. Revision 8 addendum — independent evidence for the pins

`tests/test_properties.py` adds seeded (LCG, no entropy) differential tests against plain-integer references: `ltv_status` on both ledgers for random and boundary-adjacent (debt, ev) pairs and at the exact 20D = 9E and 25D = 12E edges; ledger conservation against a plain model with decrypted balances; rejection of unbalanced postings; the bfv comparator on plain wires for widths up to 64 bits and exhaustively up to 6 bits; and real ciphertexts at 4 bits.

**Pin cross-check.** All 122 pinned mutants of `fhe_wad18`, `rlwe_wad18` and `bfv_wad18` were re-run with these tests added to the original suite: 0 killed. That is consistent with the pins but does not prove them; the 3 `threshold_bfv` pins are not covered by these tests. Pins remain author judgement and still need independent human review.


---

## 15. Revision 9 addendum — misleading smudging removed; DKG scope stated

**Decision.** Of the two options for the DKG/BFV disconnect (bind the DKG shares to the BFV key, or remove the misleading parts), the cheaper one was taken. Nothing was bound to the BFV key.
- `inject_smudging_noise` and `SMUDGING_BOUND` are removed from `mpc_decrypt.py`. Noise added to a Shamir share is multiplied by Lagrange coefficients on reconstruction, so it protected nothing and corrupted the result; keeping it implied a security property that did not exist.
- `dkg_wad18.py` and `mpc_decrypt.py` remain as a standalone, correct Shamir dealer-sum sharing and recombination over GF(2^61 - 1). Their docstrings now say they are not connected to the BFV key. Threshold decryption of BFV ciphertexts is provided only by `threshold_bfv.py` (n-of-n additive split with its own smudging, whose noise bound is tracked).

**Evidence.** `mpc_decrypt`: 121 of 121 mutants killed in `--strict` mode, no pins; `test_dkg` and `test_mpc_threshold` pass. API change: `inject_smudging_noise` no longer exists.

**Still open.** DKG shares and the BFV key are separate mechanisms; no t-of-n BFV decryption; toy parameters; Solidity uncompiled (no compiler in this container).


---

## 16. Revision 10 addendum — capsule identity and verification hardening

**Problem reported.** Hashes from the capsule, the manifest and the verifier appeared not to agree. Audit of the delivered rev 6 and rev 9 zips: each zip matched its own manifest and each quoted zip sha256 matched the file, so the delivered artefacts were self-consistent. The checker itself had real weaknesses that can produce or hide mismatches:
1. `verify_capsule.py` checked only manifest-to-zip: a member the manifest did not list (added, stale or injected) passed silently, and nothing reported the zip's own hash.
2. In full mode the verifier looked for a `raw score` line that the oracle-4 harness never prints, so the mutation step would have crashed.
3. There was one revision number hard-coded in the build and none checked, and no single string identifying a capsule: people compared a zip hash, a manifest and file hashes by hand. The manifest cannot contain its own or the zip's hash.
4. Rebuilding from a tree whose line endings had been rewritten (Windows checkout with autocrlf) changes member bytes, hence every hash.

**Changes.** `verify_capsule.py` now checks both directions (missing, mismatched and UNLISTED members, duplicate names, unsafe paths), prints three identities and can enforce them: `zip_sha256` (the file), `capsule_digest` (sha256 of `MANIFEST.json`, which covers every member hash and the revision) and `revision`; `--expect-zip-sha` and `--expect-digest` fail on any difference. `build_capsule.py` prints the same two values, takes the revision from one constant (`REVISION`), and writes a `<zip>.sha256` sidecar. `.gitattributes` (`* -text`) is a member so a git checkout keeps bytes. `tests/test_capsule.py` (9 tests) proves: two builds are byte-identical, the manifest lists exactly the declared members with true hashes, and each kind of tampering is reported with the exact problem.

**How to compare.** The zip hash is per file; the capsule digest is per content and does not change if only the zip container is rebuilt. Quote both. Anyone verifying: `python verify_capsule.py X.zip --quick --expect-digest <digest>`.

**Not solved by hashes.** A hash shows the bytes are the ones published, not that they are correct, and a person who can change both the zip and the digest you compare against can defeat it; the digest has to be obtained from a channel the zip did not travel on.


---

## 17. Revision 11 addendum — Solidity status (user-reported compile, not independently verified)

**What changed.** `contracts/CognitiveStateLedger.sol` is replaced by the version supplied by the user (sha256 `cf48988c...e1992` before CR removal; the file was LF-only). It differs from the version in the rev 5 upload in two lines: `pragma solidity ^0.8.24;` became `^0.8.20;`, and the doc comment `/// @param ctDigests: ...` became `/// @dev ctDigests: ...`. The original comment was a real defect: NatSpec `@param` must name an actual parameter, and `ctDigests` is not one, so solc rejects it (DocstringParsingError). Nothing else in the file changed.

**Status.** The user reports compiling in Remix with Solidity 0.8.20; no compiler output was provided, so this has NOT been checked by me and the claim is the user's. `contracts/libraries/WAD18.sol` (pragma ^0.8.20) was not reported compiled. The Foundry test and the deploy script (they import `forge-std`) have not been run by anyone.

**Known issues, not fixed.**
1. `WAD18.sol` `wadMul` can silently wrap: its guard `x > max / y` covers `x * y` but `+ HALF_WAD` runs inside `unchecked`. With x = (2^256-1)/3 and y = 3 it returns 0 instead of reverting `WadOverflow` (checked by integer arithmetic only, not compiled).
2. `WAD18` is defined twice with different APIs: a standalone library in `libraries/WAD18.sol` and an embedded one in `CognitiveStateLedger.sol`. They are independent now; importing both into one compilation would raise a duplicate-declaration error. The ledger uses its embedded one only.
3. The ledger anchors and sequences; it does not verify the lattice maths (stated in its own header).


---

## 18. Revision 12 addendum — `WAD18.wadMul` overflow guard

**Change.** `contracts/libraries/WAD18.sol`: the guard in `wadMul` is now `x > (type(uint256).max - HALF_WAD) / y` (was `x > type(uint256).max / y`), so it covers `x * y + HALF_WAD`. The old guard let products within `HALF_WAD` of 2^256 pass and then wrap in the `unchecked` addition. A comment explains why. No other line changed (the diff against the user's file is exactly these lines).

**Evidence (arithmetic model only; the Solidity was NOT compiled or run by me).** In Python with a small word size M and rounding constant H, for every (x, y) in a 400 x 400 grid at four (M, H) settings, the new guard passes exactly when x*y + H <= M (0 mismatches), while the old guard disagrees in 36, 250, 460 and 22 cases. At 256 bits, x = (2^256-1)/3, y = 3 passes the old guard and fails the new one, as it should.

**Status.** Needs a compile by the user (Remix, 0.8.20 or newer) and ideally a test of the boundary values. The rest of the library is unchanged and `wadDiv` was already guarded correctly.


---

## 19. Revision 13 addendum — the "toy parameters" gap, measured

**What "toy" means here.** The engine's default parameters are N = 64 with k = 96..224 bits and an error sampler of very small variance. They carry no security claim. This addendum measures the distance to the Homomorphic Encryption Security Standard (128-bit classical, ternary secret, sigma = 3.2; maximum log q = 109 at N = 4096, 218 at 8192, 438 at 16384, 881 at 32768; values read from the HEonGPU source listing of the table).

**Correction of an earlier statement.** The error sampler `Drbg.small()` is a centred binomial with eta = 3, variance exactly 3/2 (sigma about 1.22), NOT a uniform distribution on [-3, 3]; earlier text in this project that implied the latter was wrong. The table's sigma = 3.2 (variance 10.24) needs eta >= 21. Our secret is ternary, as the table assumes.

**Measured gap (`audit/param_analysis.py`, from the engine's own worst-case bound `choose_k`).** For comparator widths of 4 to 48 bits the smallest degree whose table maximum covers the required modulus is N = 16384; for 64 and 96 bits it is N = 32768. At eta = 21 the required k grows by up to 32 bits (e.g. 64 bits at N = 1024: 320 to 352) and the same N values still qualify. Real WAD values are about 91 bits (3 x 10^9 x 10^18), so a faithful 128-bit-class instantiation of the solvency comparator needs N = 32768, k about 512, a centred binomial with eta >= 21, and a power-of-two q as the engine requires.

**What was achieved.** `audit/standard_params_smoke.py` runs the unmodified BFV engine at N = 4096, k = 109 (the table maximum for that N) with eta = 21: keygen, encryption, XOR and one ct x ct AND with relinearisation decrypt correctly for three input pairs; measured noise 2^41 under a tracked bound 2^50 and a limit 2^108 (about 45 s). Pure-Python speed comes from Kronecker substitution for the exact negacyclic product, patched in at run time and tested equal to the engine's `zmul` (6 tests in `tests/test_param_analysis.py`).

**What was NOT achieved, and why.**
1. No full comparator at a compliant size. At N = 16384 a single polynomial product costs about a minute in pure Python (extrapolated from N = 4096 at 0.8 to 1.7 s), and the comparator needs hundreds of ct x ct products. A native NTT backend is required; the project's stdlib-only axioms (and the ban on `decimal`/`numpy`) rule out the usual routes. This is a real constraint, not a tuning problem.
2. The engine defaults were not changed. Moving the defaults would alter every golden digest and bound and require a full re-run of the mutation program.
3. No security claim. Table membership is necessary, not sufficient: the table is for discrete Gaussian error, our error is a centred binomial of equal variance; the table covers the LWE encryption key and not the leakage from decryption oracles or from the key holder's trust; and the depth-1 smoke is not the comparator. Independent cryptographic review remains required.

**Recommended path.** (a) Decide whether a native backend may be added outside the stdlib-only core (a separate module with the same interface, verified by differential tests against `zmul`). (b) Parameterise the error sampler by eta and make the default eta = 21. (c) Run the comparator at N = 32768 offline and record the result.


---

## 20. Revision 14 addendum — a full encrypted solvency attestation at a standard-compatible ring size

**Result.** `audit/standard_params_attest.py` ran the unmodified `bfv_wad18.attest` (120 AND gates, 4-bit debt and enterprise value) at N = 16384, k = 288, relinearisation digit 64 bits (l = 5), centred-binomial error eta = 21 (variance 10.5, above the table's 3.2^2 = 10.24). k = 288 is below the 128-bit table maximum of 438 for N = 16384. Two runs, about 65 minutes each on one core, in `audit/results/`:

| debt, ev | expected (over cap, over breaker) | decrypted | max measured noise | tracked bound | limit (half delta) |
|---|---|---|---|---|---|
| 7, 15 | (True, False) | (True, False) | 2^172 | 2^284 | 2^287 |
| 7, 14 | (True, True) | (True, True) | 2^172 | 2^284 | 2^287 |

The reference is 20D > 9E and 25D > 12E. In both runs the tracked worst-case bound dominated the measured noise and stayed below the limit, as the engine's `choose_k` guarantees (the bound is within a few bits of the limit by construction). The output ciphertext digests are recorded in the result files; seeds are fixed, so a rerun reproduces them. The inputs (7, 15) sit one unit under the 48% breaker and (7, 14) one unit over it, so both flags change between the runs.

**What made it feasible, without changing the engine.** Three run-time patches in `audit/standard_params_smoke.py`: (1) Kronecker substitution with linear-time byte packing for the exact negacyclic product (equal to `zmul`; an earlier quadratic pack loop made keygen 129 s, now 9 s); (2) the centred binomial with eta = 21; (3) relinearisation digit 64 bits, which lowers the products per AND from 22 to 14 at the cost of 32 bits of modulus. They are installed and always restored (tested). A gate-level disk cache keyed by input hash makes long runs resumable, because background processes do not survive between sessions; the cache stores 115 distinct results for 120 gates because 5 gates share inputs. `tests/test_param_analysis.py` runs the same driver at N = 64 against the plain reference for seven input pairs.

**What this is not.**
1. Not a security claim. The table covers the LWE problem for discrete-Gaussian error; this uses a centred binomial of similar variance, ternary secret and a power-of-two modulus, outside the settings in which the table was derived. Independent cryptanalytic review is still required.
2. Not the engine default. The shipped defaults remain N = 64.
3. Only 4-bit values. Real WAD amounts are about 91 bits, which per `param_analysis.py` need N = 32768 and k about 512, with about 2.4 times the modulus and many more AND gates: roughly 20 to 40 hours per attestation in this pure-Python form (an extrapolation, not a measurement).
4. The measurement was made on two input pairs, not a sweep.
