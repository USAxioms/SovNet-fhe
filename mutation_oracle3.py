"""Deterministic AST mutation harness for bfv_wad18.py (stdlib only).

Usage: python mutation_oracle3.py [--max N]
Every mutant of the engine must be killed (test suite fails) or be listed as an
equivalent/survivor. Exit code 0 only if the mutation score meets the threshold.
"""
import ast
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
THRESHOLD_PERCENT = 95

# Mutants proven behaviourally equivalent (filled after analysis).
# Honoured ONLY while bfv_wad18.py hashes to ENGINE_SHA256; any edit voids the list.
ENGINE_SHA256 = "81ef0040aa0aaf2d7dd98b42f4a7e2adcd417106f56a90678d1a8bbbbe849379"
EQUIVALENT = {
    13: "Drbg.bytes: len<n vs len<=n; same byte stream, an extra block is only buffered earlier",
    69: "Params.rounding: n*n+n is always even, so (n*n+n+2)//2 == (n*n+n+3)//2",
    88: "mul_bound ceil: 2*n*v1*v2 is even and Q is even, so the numerator is never congruent to 1 mod Q; q-1 vs q-2 give equal quotients",
    107: "decompose: the initial 0 is overwritten for every (j, i) before it is read",
    128: "ct_not: c + DELTA == c - DELTA (mod Q) because 2*DELTA == Q, then centred",
    141: "encrypt_bit: bit*DELTA added vs subtracted, same residue mod Q for bit in {0,1}",
    167: "noise(): e<=0 vs e<0 differs only at e=0",
    168: "noise(): e<1 vs e<0 differs only at e=0",
    170: "noise(): e>=worst vs e>worst yields the same maximum",
    214: "add2: while d<=width adds one level with an empty index range, no gates",
    271: "solvency_flags: width k+7 vs k+6 only adds high zero bits, which constant-fold away (gate counts and results identical; values stay below 2^(k+5))",
    277: "choose_k: worst<half vs <=; ARGUED unreachable (the bound would have to equal 2^(K-2) exactly), not machine-proved",
}

SWAPS = {
    ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.FloorDiv,
    ast.FloorDiv: ast.Mult, ast.Mod: ast.Mult, ast.BitAnd: ast.BitOr,
    ast.LShift: ast.RShift, ast.RShift: ast.LShift, ast.BitXor: ast.BitOr,
    ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt,
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.And: ast.Or, ast.Or: ast.And,
}


class Collector(ast.NodeVisitor):
    def __init__(self):
        self.sites = []

    def visit_Constant(self, node):
        if type(node.value) is int:
            self.sites.append(("const", node))

    def visit_BinOp(self, node):
        if type(node.op) in SWAPS:
            self.sites.append(("op", node))
        self.generic_visit(node)

    def visit_Compare(self, node):
        if type(node.ops[0]) in SWAPS:
            self.sites.append(("cmp", node))
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        self.sites.append(("bool", node))
        self.generic_visit(node)

    def visit_UnaryOp(self, node):
        if isinstance(node.op, (ast.USub, ast.Not)):
            self.sites.append(("unary", node))
        self.generic_visit(node)


def mutate(source, index):
    tree = ast.parse(source)
    c = Collector()
    c.visit(tree)
    if index >= len(c.sites):
        return None, None
    kind, node = c.sites[index]
    if kind == "const":
        desc = "const %d -> %d (line %d)" % (node.value, node.value + 1, node.lineno)
        node.value = node.value + 1
    elif kind == "op":
        new = SWAPS[type(node.op)]
        desc = "binop %s -> %s (line %d)" % (type(node.op).__name__, new.__name__, node.lineno)
        node.op = new()
    elif kind == "cmp":
        new = SWAPS[type(node.ops[0])]
        desc = "cmp %s -> %s (line %d)" % (type(node.ops[0]).__name__, new.__name__, node.lineno)
        node.ops[0] = new()
    elif kind == "bool":
        new = ast.Or if isinstance(node.op, ast.And) else ast.And
        desc = "boolop %s -> %s (line %d)" % (type(node.op).__name__, new.__name__, node.lineno)
        node.op = new()
    else:
        desc = "unary %s dropped (line %d)" % (type(node.op).__name__, node.lineno)
        # replace by operand via marker: turn into identity using UAdd / no-op for Not
        node.op = ast.UAdd() if isinstance(node.op, ast.USub) else ast.USub()
    ast.fix_missing_locations(tree)
    return ast.unparse(tree), desc


def count_sites(source):
    c = Collector()
    c.visit(ast.parse(source))
    return len(c.sites)


def run_suite(workdir):
    try:
        env = {"PYTHONDONTWRITEBYTECODE": "1", "FHE_FAST": "1", "PATH": os.environ.get("PATH", "")}
        r = subprocess.run([sys.executable, "-s", "-m", "unittest", "test_bfv"],
                           cwd=workdir, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=60)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False        # a hang is a detected deviation


def main(argv):
    limit = None
    if "--max" in argv:
        limit = int(argv[argv.index("--max") + 1])
    with open(os.path.join(HERE, "bfv_wad18.py")) as fh:
        source = fh.read()
    n = count_sites(source)
    if limit is not None:
        n = min(n, limit)
    # baseline must be green on the unmodified copy
    tmp = tempfile.mkdtemp(prefix="mut_")
    try:
        for f in ("test_bfv.py", "bfv_wad18.py"):
            shutil.copy(os.path.join(HERE, f), os.path.join(tmp, f))
        if not run_suite(tmp):
            print("BASELINE FAILS; mutation run aborted")
            return 2
        killed, survivors, total = 0, [], 0
        for i in range(n):
            msrc, desc = mutate(source, i)
            if msrc is None:
                break
            total += 1
            with open(os.path.join(tmp, "bfv_wad18.py"), "w") as fh:
                fh.write(msrc)
            if run_suite(tmp):
                survivors.append("#%d %s" % (i, desc))
            else:
                killed += 1
        pinned = hashlib.sha256(source.encode()).hexdigest() == ENGINE_SHA256
        real, equiv = [], []
        for sv in survivors:
            idx = int(sv.split()[0][1:])
            (equiv if pinned and idx in EQUIVALENT else real).append(sv)
        denom = total - len(equiv)
        score = (killed * 100) // denom if denom else 0
        print("mutants=%d killed=%d equivalent=%d unkilled=%d adjusted_score=%d%% (raw %d%%)"
              % (total, killed, len(equiv), len(real), score, (killed * 100) // total if total else 0))
        for sv in equiv:
            print("EQUIVALENT", sv, "::", EQUIVALENT[int(sv.split()[0][1:])])
        for sv in real:
            print("SURVIVOR", sv)
        return 0 if score >= THRESHOLD_PERCENT and not real else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
