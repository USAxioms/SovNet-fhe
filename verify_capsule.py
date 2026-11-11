"""Verify a capsule ZIP: manifest hashes match members, and tests pass from a clean extract.
Usage: python verify_capsule.py CAPSULE.zip [--quick] [--expect-zip-sha HEX] [--expect-digest HEX]   (--quick skips the mutation runs, ~30 min)
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile


def check_zip(path):
    """Hash-only check. Returns (ok, problems, info). Checks BOTH directions: every manifest entry
    matches its member, and no member exists that the manifest does not list."""
    problems = []
    with open(path, "rb") as fh:
        zip_sha = hashlib.sha256(fh.read()).hexdigest()
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if len(names) != len(set(names)):
            problems.append("DUPLICATE MEMBER NAMES")
        for n in names:
            if n.startswith("/") or ".." in n.split("/") or "\\" in n:
                problems.append("UNSAFE PATH " + n)
        if "MANIFEST.json" not in names:
            return False, problems + ["NO MANIFEST"], {"zip_sha256": zip_sha}
        raw = z.read("MANIFEST.json")
        manifest = json.loads(raw)
        listed = manifest["files"]
        for name, digest in sorted(listed.items()):
            if name not in names:
                problems.append("MISSING " + name)
            elif hashlib.sha256(z.read(name)).hexdigest() != digest:
                problems.append("HASH MISMATCH " + name)
        for name in sorted(set(names) - set(listed) - {"MANIFEST.json"}):
            problems.append("UNLISTED MEMBER " + name)
    info = {"zip_sha256": zip_sha, "capsule_digest": hashlib.sha256(raw).hexdigest(),
            "revision": manifest.get("revision"), "members": len(listed)}
    return not problems, problems, info


def main(path):
    ok, problems, info = check_zip(path)
    print("zip_sha256     ", info["zip_sha256"])
    print("capsule_digest ", info.get("capsule_digest"))
    print("revision       ", info.get("revision"), " members:", info.get("members"))
    for opt, key in (("--expect-zip-sha", "zip_sha256"), ("--expect-digest", "capsule_digest")):
        if opt in sys.argv:
            want = sys.argv[sys.argv.index(opt) + 1].lower()
            if info.get(key) != want:
                problems.append("%s EXPECTED %s GOT %s" % (key, want, info.get(key)))
    if problems:
        for p in problems:
            print("PROBLEM", p)
        return 1
    print("manifest: all", info["members"], "members match, none unlisted")
    with zipfile.ZipFile(path) as z:
        tmp = tempfile.mkdtemp(prefix="capsule_")
        z.extractall(tmp)
    env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0", "PYTHONPATH": "src:.:tests",
           "PATH": os.environ.get("PATH", "")}
    ok = True
    suites = ["test_oracle", "test_rlwe", "test_bfv", "test_bfv64", "test_threshold", "test_dkg",
              "test_mpc_threshold", "test_sovereign_node", "test_properties", "test_capsule", "test_param_analysis"]
    cmds = [["-m", "unittest", t] for t in suites]
    if "--quick" not in sys.argv:
        for eng, tst, extra in (("fhe_wad18", "test_oracle", []), ("rlwe_wad18", "test_rlwe", []),
                                ("bfv_wad18", "test_bfv", ["--env", "FHE_FAST=1"]),
                                ("threshold_bfv", "test_threshold", []), ("dkg_wad18", "test_dkg", []),
                                ("mpc_decrypt", "test_mpc_threshold", []),
                                ("sovereign_node", "test_sovereign_node", [])):
            cmds.append(["audit/mutation_oracle4.py", "--engine", "src/%s.py" % eng, "--tests", tst] + extra)
    for cmd in cmds:
        r = subprocess.run([sys.executable, "-s"] + cmd, cwd=tmp, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = r.stdout.decode().strip().splitlines()
        label = cmd[-1] if cmd[0] == "-m" else cmd[2]
        shown = lines[-1] if cmd[0] == "-m" else [l for l in lines if l.startswith("engine=")][-1]
        print(label, "->", shown)
        ok = ok and r.returncode == 0
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
