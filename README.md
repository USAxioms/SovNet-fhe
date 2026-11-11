# FHE-WAD18 reproducibility capsule (rev 5)

Python 3.9+, standard library only.

    python -m unittest test_oracle -v      # 52 tests incl. fault injection
    python mutation_oracle.py              # AST mutation analysis (exit 0 = pass)
    python build_capsule.py out.zip        # byte-reproducible ZIP
    python verify_capsule.py out.zip       # manifest + clean-extract test run

Read MEMORANDUM.md §1 first: this is an additive blinding scheme with a key-holding
sign/zero auditor, not lattice FHE, and has had no external review.

Revision 2 adds an RLWE (BFV-style) layer:

    python -m unittest test_rlwe -v        # 55 tests
    python mutation_oracle2.py             # 201 mutants

Rev 2 still has no ct x ct multiplication / homomorphic comparison (auditor remains) and
uses toy parameters: no security claim. See MEMORANDUM.md section 8.

Revision 3 adds leveled BFV (t=2) with ct x ct multiplication and an encrypted solvency
comparator (no sign oracle in the comparison step):

    python -m unittest test_bfv -v         # 41 tests (FHE_FAST=1 skips the 96-bit real run)
    python mutation_oracle3.py             # 279 mutants (~11 min)
    python verify_capsule.py out.zip --quick

Still true: the key holder is trusted (policy, not cryptographic restriction), parameters
are toy-sized (no security claim), and rev 3 is a one-shot attestation, not an oblivious
ledger. See MEMORANDUM.md section 9.

Revision 4 (engine `bfv_wad18.py` unchanged from rev 3) adds N=64 evidence and a draft contract:

    python -m unittest test_bfv64 -v       # 13 tests, real N=64 ciphertexts (~6 s)

`CognitiveStateLedger.sol` is an UNCOMPILED, UNTESTED draft (no solc was available). The key holder
is still trusted; see MEMORANDUM.md section 10.

Revision 5 adds n-of-n threshold decryption (`threshold_bfv.py`, 12 tests): no single party can decrypt.

    python -m unittest test_threshold -v

Trusted dealer for key setup, n-of-n only, release gate is per-party policy. See MEMORANDUM.md section 11.

Revision 6 (repository layout; engines unchanged in behaviour) adds the oracle-4 mutation program:

    PYTHONPATH=src:.:tests python -m unittest test_oracle test_rlwe test_bfv test_threshold test_dkg \
        test_mpc_threshold test_sovereign_node
    python audit/mutation_oracle4.py --engine src/rlwe_wad18.py --tests test_rlwe   # exit 0 = no unpinned survivor
    python build_capsule.py out.zip && python verify_capsule.py out.zip [--quick]

3,651 mutants over seven engines, 3,526 killed, 125 pinned equivalents (102 proved, 23 argued, each with a written
reason in audit/equivalents/). See MEMORANDUM.md section 12, including defects found in dkg/mpc/sovereign_node.

Revision 7: dkg_wad18 / mpc_decrypt / sovereign_node moved to GF(2^61-1), seeded determinism, Res-returning
(no raises). 100% of 481 mutants killed in --strict mode with no pins. Solidity still uncompiled. MEMORANDUM section 13.

Revision 8: tests/test_properties.py (seeded differential tests); 122 pinned mutants re-run against it, 0 killed. MEMORANDUM section 14.

Revision 9: removed the non-functional Shamir-share smudging from mpc_decrypt; DKG/MPC documented as standalone and not bound to the BFV key. MEMORANDUM section 15.

Revision 10: capsule identity. build_capsule.py prints zip_sha256 and capsule_digest and writes OUT.zip.sha256;
python verify_capsule.py X.zip --quick --expect-digest HEX  checks both directions and fails on any unlisted,
missing or changed member. See MEMORANDUM section 16.
Revision 11: CognitiveStateLedger.sol replaced by the user's ^0.8.20 version (NatSpec fix); Solidity compile is user-reported only. MEMORANDUM section 17.

Revision 12: WAD18.wadMul overflow guard fixed (model-checked only; needs your Solidity compile). MEMORANDUM section 18.

Revision 13: toy-parameter gap measured (audit/param_analysis.py), standard-compatible smoke at N=4096,k=109 (audit/standard_params_smoke.py). No security claim. MEMORANDUM section 19.

Revision 14: full 4-bit encrypted attestation at N=16384, k=288, eta=21 (two runs, audit/results/). Not a security claim; defaults unchanged. MEMORANDUM section 20.
