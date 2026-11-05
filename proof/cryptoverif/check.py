#!/usr/bin/env python3
"""Run every CryptoVerif 2.13 model, parse the real output format, compare with the
expected results, write result.json. CRYPTOVERIF names the cryptoverif 2.13 binary. One prover at a time, each run capped."""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from fractions import Fraction

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CV = pathlib.Path(os.environ.get("CRYPTOVERIF", "cryptoverif"))   # CryptoVerif 2.13
SCRATCH = ROOT / ".work/cryptoverif"
OUT = HERE / (sys.argv[1] if len(sys.argv) > 1 else "result.json")
TIMEOUT = 900

# query id -> substring that identifies it in a RESULT line (CryptoVerif's printed form)
KEYS = {
    "extract": "KeyExtracted",
    "complete": "ExtractedAt",
    "cross": "ContextLookup(m, c, x, y)) && event(AdversaryHashQuery(x, y2))",
    "repeat_hidden": "ContextLookup(m, c, x, y)) && event(ContextLookup(m, c, x2, y2))",
    "repeat_adv": "AdversaryHashQuery(x, y)) && event(AdversaryHashQuery(x, y2))",
    "table": "==> event(NonceROUsed",
    "adv_table": "event(AdversaryHashQuery(x, y)) ==> event(NonceROUsed",
    "ctx_table": "event(ContextLookup(m, c, x, y)) ==> event(NonceROUsed",
    "Bad2": "event(Bad2) ==> false",
    "Bad3": "event(Bad3) ==> false",
    "Bad4": "event(Bad4) ==> false",
    "O2Unres": "event(O2Unres) ==> false",
}
INDIST = "indistinguishability"
EX, PR, NO = "proved_exact", "proved_prob", "not_proved"
M = ROOT / "proof/cryptoverif/models"

# (name, path, goal, is_control, {query id: expected status})
MODELS = [
    ("ga_bip340", M / "ga_bip340.ocv", "G-A", False,
     {k: EX for k in ("extract", "complete", "cross", "repeat_hidden", "repeat_adv", "table")}),
    ("ga_ecdsa", M / "ga_ecdsa.ocv", "G-A", False,
     {k: EX for k in ("extract", "complete", "cross", "repeat_hidden", "repeat_adv", "table")}),
    ("gb_bip340", M / "gb_bip340.ocv", "G-B", False, {INDIST: EX}),
    ("gb_ecdsa", M / "gb_ecdsa.ocv", "G-B", False, {INDIST: EX}),
    ("gc_bad2", M / "gc_bad2.ocv", "G-C", False, {"Bad2": PR}),
    ("gc_bad3", M / "gc_bad3.ocv", "G-C", False, {"Bad3": PR}),
    ("gc_bad4", M / "gc_bad4.ocv", "G-C", False, {"Bad4": PR}),
    ("gc_o2unres", M / "gc_o2unres.ocv", "G-C", False, {"O2Unres": PR}),
    ("gd_coupling", M / "gd_coupling.ocv", "G-D", False, {INDIST: NO}),
    ("gd_xor_toy", M / "gd_xor_toy.ocv", "G-D", False, {INDIST: NO}),
    ("m1_ga_nomask", M / "m1_ga_nomask.ocv", "M1", True, {"extract": EX, "complete": NO}),
    ("m1_gb_nomask", M / "m1_gb_nomask.ocv", "M1", True, {INDIST: NO}),
    ("m2_gc_o2unres", M / "m2_gc_o2unres.ocv", "M2", True, {"O2Unres": NO}),
]
# controls: these query ids must not be proved (the extract goal of m1_ga is not the control goal)
CONTROL_MUST_FAIL = {"m1_ga_nomask": ["complete"], "m1_gb_nomask": [INDIST], "m2_gc_o2unres": ["O2Unres"]}


def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def parse(text):
    """Return {query id: (status, probability text or None)} from real CryptoVerif output."""
    res = {}
    for line in text.splitlines():
        if not line.startswith("RESULT "):
            continue
        body = line[len("RESULT "):]
        if body.startswith("Proved indistinguishability"):
            m = re.search(r" up to probability (.*)$", body)
            res[INDIST] = (PR if m else EX, m.group(1) if m else None)
        elif body.startswith("Could not prove indistinguishability"):
            res[INDIST] = (NO, None)
        elif body.startswith("Proved "):
            m = re.search(r" up to probability (.*)$", body)
            for qid, key in KEYS.items():
                if key in body:
                    res[qid] = (PR if m else EX, m.group(1) if m else None)
        elif body.startswith("Could not prove "):
            for qid, key in KEYS.items():
                if key in body:
                    res[qid] = (NO, None)
    return res


def run_model(path):
    SCRATCH.mkdir(parents=True, exist_ok=True)
    cmd = ["nice", "-n", "15", "systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=2G",
           "-p", "MemorySwapMax=0", "/usr/bin/time", "-f", "MAXRSS_KB=%M", "timeout", str(TIMEOUT),
           str(CV), str(path)]
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=str(path.parent), stdin=subprocess.DEVNULL)
    el = time.time() - t0
    rss = re.search(r"MAXRSS_KB=(\d+)", p.stderr)
    return p.returncode, p.stdout, p.stderr, el, int(rss.group(1)) if rss else None


def numeric_checks():
    """Exact arithmetic for the G1 to G2 term: not a CryptoVerif result."""
    out = {}
    # toy modulus: B = 2^8, n = 251 (prime), g = B - n = 5, and a second toy B = 2^10, n = 1021
    for B, n in ((256, 251), (1024, 1021)):
        g = B - n
        cnt = {}
        zero = 0
        for x in range(B):
            k = x % n
            if k == 0:
                zero += 1
            else:
                cnt[k] = cnt.get(k, 0) + 1
        tot = sum(cnt.values())
        tv = sum(max(Fraction(c, tot) - Fraction(1, n - 1), 0) for c in cnt.values())
        tv += sum(max(Fraction(1, n - 1) - Fraction(cnt.get(k, 0), tot), 0) for k in range(1, n) if k not in cnt)
        beta = Fraction((g - 1) * (n - g), (B - 2) * (n - 1))
        out["toy_B%d_n%d" % (B, n)] = {
            "zero_count": zero, "fail_prob_equals_2_over_B": Fraction(zero, B) == Fraction(2, B),
            "tv_exact": str(tv), "beta_formula": str(beta), "tv_equals_beta": tv == beta}
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    B = 2 ** 256
    g = B - n
    beta = Fraction((g - 1) * (n - g), (B - 2) * (n - 1))
    out["secp256k1"] = {"g_bits": g.bit_length(), "beta_float": float(beta), "beta_log2": float(beta.numerator.bit_length() - beta.denominator.bit_length()),
                        "two_n_gt_B": 2 * n > B}
    ok = all(v.get("tv_equals_beta", True) and v.get("fail_prob_equals_2_over_B", True) for v in out.values() if "zero_count" in v)
    return out, ok


def main():
    if not CV.exists():
        print("cryptoverif binary missing")
        sys.exit(2)
    runs = []
    for name, path, goal, ctrl, expect in MODELS:
        rc, so, se, el, rss = run_model(path)
        (SCRATCH / (name + ".out")).write_text(so + se)
        got = parse(so)
        entry = {"model": name, "goal": goal, "control": ctrl, "path": str(path.relative_to(ROOT)),
                 "sha256": sha(path), "exit": rc, "seconds": round(el, 2), "maxrss_kb": rss,
                 "all_queries_proved": "All queries proved." in so,
                 "timeout": rc == 124, "queries": {}}
        for qid, want in expect.items():
            st, prob = got.get(qid, ("missing", None))
            entry["queries"][qid] = {"expected": want, "got": st, "probability": prob, "match": st == want}
        entry["unexpected_extra_results"] = sorted(set(got) - set(expect))
        entry["output_tail"] = "\n".join([l for l in so.splitlines() if l.startswith("RESULT") or l.startswith("All queries")])
        runs.append(entry)
    num, num_ok = numeric_checks()
    invalid = []
    mismatch = []
    for e in runs:
        if e["exit"] != 0:
            invalid.append("%s: exit %s%s" % (e["model"], e["exit"], " (timeout)" if e["timeout"] else ""))
            continue
        for qid, q in e["queries"].items():
            if e["control"] and qid in CONTROL_MUST_FAIL[e["model"]]:
                if q["got"] != NO:
                    invalid.append("%s: control proved %s (%s)" % (e["model"], qid, q["got"]))
            elif not q["match"]:
                mismatch.append("%s/%s: expected %s got %s" % (e["model"], qid, q["expected"], q["got"]))
    if not num_ok:
        mismatch.append("numeric check of beta or 2/B failed")
    verdict = "INVALID" if invalid else ("MISMATCH" if mismatch else "OK")
    result = {"verdict": verdict, "invalid": invalid, "mismatch": mismatch,
              "binary_sha256": sha(CV), "total_seconds": round(sum(r["seconds"] for r in runs), 2),
              "numeric_checks": num, "numeric_ok": num_ok, "runs": runs}
    OUT.write_text(json.dumps(result, indent=1) + "\n")
    print(verdict, "total %.1fs" % result["total_seconds"])
    for x in invalid + mismatch:
        print(" -", x)
    sys.exit(0 if verdict == "OK" else 1)


if __name__ == "__main__":
    main()
