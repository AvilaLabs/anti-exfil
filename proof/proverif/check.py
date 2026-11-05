#!/usr/bin/env python3
"""Run every symbolic model and compare each query with its expected answer. PROVERIF names the proverif 2.05 binary."""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TOOL = pathlib.Path(os.environ.get("PROVERIF", "proverif"))   # ProVerif 2.05
LIB = "defs"
T, F = "true", "false"

# (model, [(query id, expected, role)]) in the order the queries appear in the file.
MODELS = [
    ("setupB.pv", [("Q1", T, "real"), ("Q2", T, "real"), ("Q4a", T, "real"), ("Q4b", T, "real")]),
    ("setupA.pv", [("Q3", T, "real"), ("Q4a", T, "real"), ("Q4b", T, "real"), ("Q4c", T, "real"),
                   ("Q6a", T, "real"), ("Q6b", T, "real"), ("Q7", T, "real"), ("K1", F, "control")]),
    ("setupA_private.pv", [("Q5a", T, "real")]),
    ("setupA_preopen.pv", [("Q5c", T, "real")]),
    ("mut_M1_early_rho.pv", [("Q1", F, "control M1")]),
    ("mut_M2_no_compare.pv", [("Q2", F, "control M2")]),
    ("mut_M3_reuse_rho.pv", [("Q4a", F, "control M3"), ("Q4b", F, "control M3")]),
    ("mut_M4_no_approval.pv", [("Q7", F, "control M4")]),
    ("mut_M5_r0_from_response.pv", [("Q2", F, "control M5")]),
    ("mut_M6_fresh_nonce.pv", [("Q6a", T, "side"), ("Q6b", F, "control M6")]),
]
RESULT = re.compile(r"^RESULT .* is (true|false|cannot be proved)\.$", re.M)


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(model):
    cmd = ["nice", "-n", "15", "systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=2G",
           "-p", "MemorySwapMax=0", "timeout", "600", str(TOOL), "-lib", LIB, model]
    p = subprocess.run(cmd, cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def main():
    if len(sys.argv) > 2:
        raise SystemExit("usage: check.py [RESULT.json]")
    result = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "result.json"
    out = ROOT / ".work" / "proverif"        # the raw output of each model
    out.mkdir(parents=True, exist_ok=True)
    records, bad_run = [], False
    for model, queries in MODELS:
        code, text = run(model)
        (out / (model + ".txt")).write_text(text)
        got = RESULT.findall(text)
        ok_run = code == 0 and len(got) == len(queries)
        bad_run |= not ok_run
        qs = []
        for i, (qid, exp, role) in enumerate(queries):
            res = got[i] if i < len(got) else "missing"
            qs.append({"query": qid, "role": role, "expected": exp, "result": res,
                       "as_expected": ok_run and res == exp})
        records.append({"model": model, "sha256": sha(HERE / model), "returncode": code,
                        "trace_present": "a trace has been found" in text.lower(),
                        "queries": qs})
        print(model, [(q["query"], q["result"]) for q in qs], flush=True)
    allq = [q for r in records for q in r["queries"]]
    controls_fire = all(q["as_expected"] for q in allq if q["role"].startswith("control"))
    real_ok = all(q["as_expected"] for q in allq if q["role"] == "real")
    side_ok = all(q["as_expected"] for q in allq if q["role"] == "side")
    if bad_run or not controls_fire:
        verdict = "INVALID"
    elif real_ok and side_ok:
        verdict = "PASS"
    else:
        verdict = "FINDING"
    doc = {"tool_sha256": sha(TOOL), "lib_sha256": sha(HERE / (LIB + ".pvl")),
           "records": records,
           "controls_fire": controls_fire, "real_queries_as_expected": real_ok,
           "verdict": verdict, "scope": "symbolic, free constructors; no curve, hash or bias"}
    result.write_text(json.dumps(doc, indent=2) + "\n")
    print("VERDICT:", verdict)
    raise SystemExit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
