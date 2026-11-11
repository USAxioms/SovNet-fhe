"""Deterministic capsule builder (stdlib only).

Writes MANIFEST.json (sha256 of every member) and a byte-reproducible ZIP:
sorted names, fixed timestamp, fixed permissions, fixed compression level.
Also writes OUT.zip.sha256 (sidecar) and prints the zip sha256 and the capsule digest.
Usage: python build_capsule.py OUT.zip
"""
import hashlib
import json
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
MEMBERS = sorted(
    ["src/" + n for n in ("fhe_wad18.py", "rlwe_wad18.py", "bfv_wad18.py", "threshold_bfv.py",
                          "dkg_wad18.py", "mpc_decrypt.py", "sovereign_node.py")]
    + ["tests/" + n for n in ("ledger_hardening.py", "test_oracle.py", "test_rlwe.py", "test_bfv.py",
                              "test_bfv64.py", "test_threshold.py", "test_dkg.py",
                              "test_mpc_threshold.py", "test_sovereign_node.py", "test_properties.py", "test_capsule.py", "test_param_analysis.py",
                              "foundry/CSL.t.sol")]
    + ["audit/" + n for n in ("mutation_oracle.py", "mutation_oracle2.py", "mutation_oracle3.py",
                              "mutation_oracle4.py", "make_pins.py", "param_analysis.py",
                              "standard_params_smoke.py", "standard_params_attest.py")]
    + ["audit/results/attest_N16384_k288_debt7_ev14.json", "audit/results/attest_N16384_k288_debt7_ev15.json"]
    + ["audit/equivalents/" + n + ".json" for n in ("fhe_wad18.py", "rlwe_wad18.py", "bfv_wad18.py",
                                                    "threshold_bfv.py")]
    + ["contracts/CognitiveStateLedger.sol", "contracts/libraries/WAD18.sol",
       "contracts/script/DeployCSL.s.sol", "config/wad18_node_spec.yaml", "LICENSE", ".gitattributes",
       "state/COGNITIVE_LEDGER.jsonl", "MEMORANDUM.md", "README.md",
       "build_capsule.py", "verify_capsule.py"])
REVISION = 14
FIXED_TIME = (2026, 11, 7, 0, 0, 0)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build(out_path):
    blobs = {}
    for name in MEMBERS:
        with open(os.path.join(HERE, name), "rb") as fh:
            blobs[name] = fh.read()
    manifest = {"capsule": "FHE-WAD18", "revision": REVISION,
                "files": dict((n, sha(b)) for n, b in sorted(blobs.items()))}
    blobs["MANIFEST.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    with zipfile.ZipFile(out_path, "w") as z:
        for name in sorted(blobs):
            zi = zipfile.ZipInfo(name, FIXED_TIME)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o100644 << 16
            zi.create_system = 3
            z.writestr(zi, blobs[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    with open(out_path, "rb") as fh:
        zip_sha = sha(fh.read())
    return zip_sha, sha(blobs["MANIFEST.json"])


if __name__ == "__main__":
    zip_sha, capsule_digest = build(sys.argv[1])
    with open(sys.argv[1] + ".sha256", "w") as fh:
        fh.write("%s  %s\n" % (zip_sha, os.path.basename(sys.argv[1])))
    print("zip_sha256     ", zip_sha)
    print("capsule_digest ", capsule_digest, "(sha256 of MANIFEST.json; covers every member)")
