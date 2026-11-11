#!/usr/bin/env python3
"""Fierce AST mutation harness v4 (stdlib only, deterministic).

Usage (from anywhere):
  python audit/mutation_oracle4.py --engine src/bfv_wad18.py --tests test_bfv [--env FHE_FAST=1]
         [--workers 2] [--json out.json] [--only-ids prev.json] [--list] [--strict]

Operator families (each yields many mutants per site):
  const   int +1 / -1 / 0, bool flip          str    string/bytes suffix
  bin     arithmetic/bit operator replacement bswap  operand swap (non-commutative)
  aug     augmented-assignment operator       unary  drop -, not, ~
  cmp     every other comparison operator, is/is not, in/not in
  bool    and<->or, keep-left, keep-right     cond   if/while/ifexp/comprehension: not, True, False
  ret     return value -> None                del    statement deletion (-> pass)
  args    swap first two call arguments       slice  drop slice bound
A mutant is KILLED when the test run fails, errors or times out; it SURVIVES when the
whole run passes. Equivalent mutants may be pinned in audit/equivalents/<engine>.json,
honoured only while the engine's sha256 matches, each with class "proved" or "argued".
Exit code 0 only if no unpinned survivor remains (--strict: argued pins also count).
"""
import argparse
import ast
import concurrent.futures
import hashlib
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CMP = [ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq]
CMP_PAIR = {ast.Is: ast.IsNot, ast.IsNot: ast.Is, ast.In: ast.NotIn, ast.NotIn: ast.In}
BIN_REPL = {
    ast.Add: [ast.Sub, ast.Mult], ast.Sub: [ast.Add], ast.Mult: [ast.Add, ast.FloorDiv],
    ast.FloorDiv: [ast.Mult], ast.Mod: [ast.Mult], ast.Pow: [ast.Mult],
    ast.BitAnd: [ast.BitOr], ast.BitOr: [ast.BitAnd], ast.BitXor: [ast.BitOr, ast.BitAnd],
    ast.LShift: [ast.RShift], ast.RShift: [ast.LShift],
}
BIN_SWAP = (ast.Sub, ast.FloorDiv, ast.Mod, ast.LShift, ast.RShift, ast.Pow)
DEL_TYPES = (ast.Expr, ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Raise, ast.Delete,
             ast.Assert, ast.Break, ast.Continue)


def become(dst, src):
    dst.__class__ = src.__class__
    dst.__dict__ = dict(src.__dict__)


def is_docstring(node, parents):
    p = parents.get(node)
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
            and isinstance(node.value.value, str) and isinstance(p, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
        return p.body[0] is node
    return False


def variants(tree):
    """Deterministic list of (mutant_id, mutator). Each mutator mutates its node in place."""
    parents = {}
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            parents[c] = p
    in_fstring = set()
    docstr_consts = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.JoinedStr):
            for c in ast.walk(n):
                in_fstring.add(c)
        if isinstance(n, ast.Expr) and is_docstring(n, parents):
            docstr_consts.add(n.value)
    out = []

    def add(node, kind, name, fn):
        out.append(("%d:%d:%s:%s" % (node.lineno, node.col_offset, kind, name), fn))

    def setter(node, attr, val):
        return lambda: setattr(node, attr, val)

    for node in ast.walk(tree):
        if not hasattr(node, "lineno"):
            continue
        if isinstance(node, ast.Constant) and node not in in_fstring and node not in docstr_consts:
            v = node.value
            if isinstance(v, bool):
                add(node, "const", "flip", setter(node, "value", not v))
            elif isinstance(v, int):
                for nm, nv in (("+1", v + 1), ("-1", v - 1), ("0", 0)):
                    if nv != v:
                        add(node, "const", nm, setter(node, "value", nv))
            elif isinstance(v, str):
                add(node, "str", "suffix", setter(node, "value", v + "X"))
            elif isinstance(v, bytes):
                add(node, "str", "suffix", setter(node, "value", v + b"X"))
        elif isinstance(node, ast.BinOp):
            for new in BIN_REPL.get(type(node.op), []):
                add(node, "bin", new.__name__, setter(node, "op", new()))
            if type(node.op) in BIN_SWAP:
                add(node, "bswap", "swap", (lambda n=node: _swap_binop(n)))
        elif isinstance(node, ast.AugAssign):
            for new in BIN_REPL.get(type(node.op), []):
                add(node, "aug", new.__name__, setter(node, "op", new()))
        elif isinstance(node, ast.UnaryOp):
            add(node, "unary", "drop", (lambda n=node: become(n, n.operand)))
        elif isinstance(node, ast.Compare):
            op = type(node.ops[0])
            if op in CMP:
                for new in CMP:
                    if new is not op:
                        add(node, "cmp", "%s>%s" % (op.__name__, new.__name__), (lambda n=node, c=new: n.ops.__setitem__(0, c())))
            elif op in CMP_PAIR:
                add(node, "cmp", "%s>%s" % (op.__name__, CMP_PAIR[op].__name__), (lambda n=node, c=CMP_PAIR[op]: n.ops.__setitem__(0, c())))
        elif isinstance(node, ast.BoolOp):
            new = ast.Or if isinstance(node.op, ast.And) else ast.And
            add(node, "bool", "swap", setter(node, "op", new()))
            add(node, "bool", "left", (lambda n=node: become(n, n.values[0])))
            add(node, "bool", "right", (lambda n=node: become(n, n.values[-1])))
        elif isinstance(node, (ast.If, ast.While, ast.IfExp)):
            add(node, "cond", "not", (lambda n=node: setattr(n, "test", ast.UnaryOp(op=ast.Not(), operand=n.test))))
            if not isinstance(node, ast.While):
                add(node, "cond", "true", setter(node, "test", ast.Constant(value=True)))
            add(node, "cond", "false", setter(node, "test", ast.Constant(value=False)))
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            for gi, gen in enumerate(node.generators):
                for ci in range(len(gen.ifs)):
                    add(node, "cond", "comp%d.%d" % (gi, ci),
                        (lambda g=gen, k=ci: g.ifs.__setitem__(k, ast.UnaryOp(op=ast.Not(), operand=g.ifs[k]))))
        elif isinstance(node, ast.Return):
            if node.value is not None and not (isinstance(node.value, ast.Constant) and node.value.value is None):
                add(node, "ret", "None", setter(node, "value", ast.Constant(value=None)))
        elif isinstance(node, ast.Call):
            if len(node.args) >= 2 and not any(isinstance(a, ast.Starred) for a in node.args) \
                    and ast.dump(node.args[0]) != ast.dump(node.args[1]):
                add(node, "args", "swap01", (lambda n=node: _swap_args(n)))
        elif isinstance(node, ast.Slice):
            for attr in ("lower", "upper", "step"):
                if getattr(node, attr) is not None:
                    add(node, "slice", "drop-" + attr, setter(node, attr, None))
        if isinstance(node, DEL_TYPES) and not is_docstring(node, parents):
            add(node, "del", type(node).__name__, (lambda n=node: become(n, ast.Pass())))
    # disambiguate duplicate ids deterministically
    seen = {}
    final = []
    for key, fn in out:
        seen[key] = seen.get(key, 0) + 1
        final.append((key if seen[key] == 1 else "%s#%d" % (key, seen[key]), fn))
    return final


def _swap_binop(n):
    n.left, n.right = n.right, n.left


def _swap_args(n):
    n.args[0], n.args[1] = n.args[1], n.args[0]


def mutate_source(source, index):
    tree = ast.parse(source)
    vs = variants(tree)
    mid, fn = vs[index]
    fn()
    ast.fix_missing_locations(tree)
    return mid, ast.unparse(tree)


def enumerate_ids(source):
    return [mid for mid, _ in variants(ast.parse(source))]


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class Runner(object):
    def __init__(self, engine_rel, tests, env_extra, timeout, workers):
        self.engine_rel = engine_rel
        self.tests = tests
        self.timeout = timeout
        self.env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0",
                    "PATH": os.environ.get("PATH", "")}
        self.env.update(env_extra)
        self.dirs = queue.Queue()
        self.tmp_all = []
        for _ in range(workers):
            d = tempfile.mkdtemp(prefix="mut4_")
            for sub in ("src", "tests"):
                shutil.copytree(os.path.join(ROOT, sub), os.path.join(d, sub))
            self.tmp_all.append(d)
            self.dirs.put(d)

    def cleanup(self):
        for d in self.tmp_all:
            shutil.rmtree(d, ignore_errors=True)

    def run_in(self, d, source):
        with open(os.path.join(d, self.engine_rel), "w") as fh:
            fh.write(source)
        env = dict(self.env)
        env["PYTHONPATH"] = os.pathsep.join([os.path.join(d, "src"), d, os.path.join(d, "tests")])
        try:
            r = subprocess.run([sys.executable, "-s", "-m", "unittest", "-f"] + self.tests,
                               cwd=d, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=self.timeout)
            return r.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def one(self, source):
        d = self.dirs.get()
        try:
            return self.run_in(d, source)
        finally:
            self.dirs.put(d)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", required=True)
    ap.add_argument("--tests", nargs="+", required=True)
    ap.add_argument("--env", nargs="*", default=[])
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--json")
    ap.add_argument("--only-ids")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--strict", action="store_true")
    a = ap.parse_args(argv)
    engine_path = os.path.join(ROOT, a.engine)
    with open(engine_path) as fh:
        source = fh.read()
    ids = enumerate_ids(source)
    lines = source.split("\n")
    if a.list:
        print(len(ids))
        return 0
    env_extra = dict(kv.split("=", 1) for kv in a.env)
    pins_path = os.path.join(ROOT, "audit", "equivalents", os.path.basename(a.engine) + ".json")
    pins, pin_sha = {}, None
    if os.path.exists(pins_path):
        with open(pins_path) as fh:
            doc = json.load(fh)
        pin_sha, pins = doc["engine_sha256"], doc["pins"]
    pinned_ok = pin_sha == sha256(engine_path)
    todo = list(range(len(ids)))
    if a.only_ids:
        with open(a.only_ids) as fh:
            want = set(x["id"] for x in json.load(fh)["survivors"])
        todo = [i for i in todo if ids[i] in want]
    # baseline
    t0 = time.time()
    probe = Runner(a.engine, a.tests, env_extra, 600, 1)
    ok = probe.one(source)
    base = time.time() - t0
    probe.cleanup()
    if not ok:
        print("BASELINE FAILS; aborting")
        return 2
    timeout = max(20, int(base * 8) + 5)
    runner = Runner(a.engine, a.tests, env_extra, timeout, a.workers)
    results = {}
    seen_sources = {}

    def work(i):
        mid, msrc = mutate_source(source, i)
        if msrc == ast.unparse(ast.parse(source)):
            return i, mid, "noop"
        return i, mid, "survived" if runner.one(msrc) else "killed"

    start = time.time()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as ex:
            for n, (i, mid, res) in enumerate(ex.map(work, todo)):
                results[i] = (mid, res)
                if (n + 1) % 100 == 0:
                    print("  .. %d/%d  (%.0fs)" % (n + 1, len(todo), time.time() - start), file=sys.stderr)
    finally:
        runner.cleanup()
    killed = sum(1 for m, r in results.values() if r == "killed")
    noop = sum(1 for m, r in results.values() if r == "noop")
    surv = [(i, m) for i, (m, r) in sorted(results.items()) if r == "survived"]
    proved, argued, live = [], [], []
    for i, m in surv:
        pin = pins.get(m) if pinned_ok else None
        if pin and (pin["class"] == "proved" or not a.strict):
            (proved if pin["class"] == "proved" else argued).append((i, m, pin))
        else:
            live.append((i, m))
    total = len(results) - noop
    denom = total - len(proved) - len(argued)
    fam = {}
    for i, (m, r) in results.items():
        if r == "noop":
            continue
        k = m.split(":")[2]
        f = fam.setdefault(k, [0, 0])
        f[0] += 1
        f[1] += (r == "killed")
    print("engine=%s sha=%s  mutants=%d killed=%d survived=%d (proved-equiv=%d argued-equiv=%d unpinned=%d) noop=%d"
          % (a.engine, sha256(engine_path)[:12], total, killed, len(surv), len(proved), len(argued), len(live), noop))
    print("raw score %d%%   adjusted score %d%%   wall %.0fs   pins %s"
          % ((killed * 100) // total if total else 0, (killed * 100) // denom if denom else 100,
             time.time() - start, "ACTIVE" if pinned_ok and pins else ("STALE" if pins else "none")))
    print("by family: " + "  ".join("%s %d/%d" % (k, v[1], v[0]) for k, v in sorted(fam.items())))
    for i, m, pin in proved + argued:
        print("PINNED[%s] %s :: %s" % (pin["class"], m, pin["why"]))
    for i, m in live:
        ln = int(m.split(":")[0])
        print("SURVIVOR %s :: %s" % (m, lines[ln - 1].strip()[:110]))
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"engine": a.engine, "sha256": sha256(engine_path), "total": total, "killed": killed,
                       "survivors": [{"id": m, "line": lines[int(m.split(":")[0]) - 1].strip()} for i, m in live]},
                      fh, indent=1)
    return 0 if not live else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
