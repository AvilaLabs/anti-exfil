#!/usr/bin/env python3
"""Gate: every normative sentence of the two documents is covered by a row or an exclusion.

Checks, against spec/bip-anti-exfil.md and spec/bip-anti-exfil-psbt.md (hashes named in the JSON):
  1. both documents hash to the values recorded in the requirements file;
  2. every quote is an exact substring of the line it names;
  3. every sentence containing a normative word (tier 1: MUST, MUST NOT, SHOULD, SHOULD NOT, MAY,
     "fail if", "fails"; tier 2, stricter than the protocol: fail, failed, must, shall, never,
     refus*) is intersected by at least one quote or exclusion;
  4. every exclusion text is on its line and carries a reason, and no sentence is both quoted and excluded;
  5. every row has a valid class; math/psbt/operational rows carry a coverage list of real test names
     (checked against psbt/tests) or "none", a target, and a targeted mutant or a mutant_exempt
     reason; not_machine_testable rows carry a reason; ids are unique;
  6. every mutant names only existing requirement ids.

check(doc) is pure so the controls in check.py can feed it altered copies.
Usage: extract_check.py [--json PATH] [--controls]
"""
import ast
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import sentences  # noqa: E402

CLASSES = ("math", "psbt", "operational", "not_machine_testable")
TARGETS = ("math", "host", "signer", "spend", "codec")
TESTS_DIR = ROOT / "psbt/tests"


def real_tests():
    names = set()
    for p in sorted(TESTS_DIR.glob("test_*.py")):
        tree = ast.parse(p.read_text())
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                for f in node.body:
                    if isinstance(f, ast.FunctionDef) and f.name.startswith("test_"):
                        names.add("%s.%s.%s" % (p.stem, node.name, f.name))
    return names


def mutant_table():
    try:
        import targeted_mutants
    except ImportError:
        return None
    out = {}
    for m in targeted_mutants.all_mutants():
        for rid in m["reqs"]:
            out.setdefault(rid, []).append(m["id"])
    return out


def check(doc, mutants="load", tests=None):
    """Return (problems, info). Problems are strings; info has counts."""
    problems = []
    lines = {}
    for d, meta in doc["documents"].items():
        raw = (ROOT / meta["path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != meta["sha256"]:
            problems.append("document %s differs from the hash recorded in the requirements file" % d)
        lines[d] = raw.decode("utf-8").split("\n")
    tests = real_tests() if tests is None else tests
    mut = mutant_table() if mutants == "load" else mutants
    spans = {d: [] for d in lines}          # (line, start, end, kind, id)
    ids, counts, none_cov = set(), {c: 0 for c in CLASSES}, []
    for r in doc["requirements"]:
        rid = r.get("id")
        if rid in ids:
            problems.append("duplicate id %s" % rid)
        ids.add(rid)
        cls = r.get("class")
        if cls not in CLASSES:
            problems.append("%s: bad class %r" % (rid, cls))
            continue
        counts[cls] += 1
        if r.get("document") not in lines:
            problems.append("%s: bad document" % rid)
            continue
        if not r.get("quotes"):
            problems.append("%s: no quotes" % rid)
        for q in r.get("quotes", []):
            n, text = q.get("line"), q.get("text")
            ls = lines[r["document"]]
            if not isinstance(n, int) or not 1 <= n <= len(ls) or not text or text not in ls[n - 1]:
                problems.append("%s: quote not found on line %s: %r" % (rid, n, (text or "")[:70]))
            else:
                a = ls[n - 1].index(text)
                spans[r["document"]].append((n, a, a + len(text), "row", rid))
        if cls == "not_machine_testable":
            if not r.get("reason"):
                problems.append("%s: not_machine_testable without reason" % rid)
            continue
        cov = r.get("coverage")
        if cov != "none":
            if not (isinstance(cov, list) and cov and all(isinstance(c, str) and c for c in cov)):
                problems.append("%s: coverage must be 'none' or a non-empty list" % rid)
            elif cls != "math":
                for c in cov:
                    if c not in tests:
                        problems.append("%s: coverage names no such test: %s" % (rid, c))
        else:
            none_cov.append(rid)
        if r.get("target") not in TARGETS:
            problems.append("%s: bad target" % rid)
        if mut is not None and not mut.get(rid) and not r.get("mutant_exempt"):
            problems.append("%s: no targeted mutant and no mutant_exempt reason" % rid)
    excl = []
    for e in doc.get("exclusions", []):
        d, n, text = e.get("document"), e.get("line"), e.get("text")
        ls = lines.get(d)
        if ls is None or not isinstance(n, int) or not 1 <= n <= len(ls) or not text or text not in ls[n - 1]:
            problems.append("exclusion on line %s does not quote the line" % n)
        elif not e.get("reason"):
            problems.append("exclusion on line %s has no reason" % n)
        else:
            a = ls[n - 1].index(text)
            spans[d].append((n, a, a + len(text), "excl", None))
            excl.append(e)
    tier_counts = {1: 0, 2: 0}
    for d, ls in lines.items():
        for n, line in enumerate(ls, 1):
            for a, b, text in sentences.sentences(line):
                t = sentences.tier(text)
                if not t:
                    continue
                tier_counts[t] += 1
                hit = [s for s in spans[d] if s[0] == n and s[1] < b and a < s[2]]
                if not hit:
                    problems.append("tier %d sentence not covered: %s line %d: %s" % (t, d, n, text.strip()[:90]))
                elif any(s[3] == "excl" for s in hit) and any(s[3] == "row" for s in hit):
                    problems.append("sentence both quoted and excluded: %s line %d: %s" % (d, n, text.strip()[:70]))
    if mut is not None:
        for rid in mut:
            if rid not in ids:
                problems.append("a mutant names unknown requirement %s" % rid)
    info = {"counts": counts, "exclusions": len(excl), "tier1_sentences": tier_counts[1], "tier2_sentences": tier_counts[2],
            "coverage_none": none_cov, "rows": len(doc["requirements"])}
    return problems, info


def load(path=None):
    return json.loads(pathlib.Path(path or HERE / "requirements.json").read_text(encoding="utf-8"))


def main(argv):
    path = argv[argv.index("--json") + 1] if "--json" in argv else None
    problems, info = check(load(path))
    print("rows %d, by class %s, exclusions %d, normative sentences tier1 %d tier2 %d" % (
        info["rows"], info["counts"], info["exclusions"], info["tier1_sentences"], info["tier2_sentences"]))
    print("testable rows with coverage 'none': %d %s" % (len(info["coverage_none"]), info["coverage_none"]))
    for p in problems:
        print("PROBLEM:", p)
    print("extract_check: %s" % ("FAIL (%d problems)" % len(problems) if problems else "PASS"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
