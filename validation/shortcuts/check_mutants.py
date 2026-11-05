#!/usr/bin/env python3
"""Section 3: the requirement mutants of validation/requirements, run through the vectors alone.

    check_mutants.py [--base RESULT.json] [--out FILE] [--workers n]

The reused mutants are the disabled-check cases of check.py, so only the new ones run here. N00, the no-op, must
pass. Uses the controls of the result file RESULT.json written by check.py (default .work/shortcuts/result.json),
and refuses if any tested source has changed since that run.
Survivors are classed by hand in not_caught_requirements.json, in the same classes and with the same rules as section 1.
"""
import concurrent.futures as cf
import importlib.util
import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check as B  # noqa: E402


def load():
    spec = importlib.util.spec_from_file_location("targeted_mutants", B.ROOT / "validation" / "requirements" / "targeted_mutants.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = []
    for m in mod.NEW:
        patches = [("psbt/" + m["file"], p[0], p[1], p[2] if len(p) > 2 else 1) for p in m["patches"]]
        out.append((m["id"], patches, m["desc"]))
    return out


def main():
    argv = sys.argv[1:]
    if "-h" in argv or "--help" in argv:
        print(__doc__)
        return
    base_path = pathlib.Path(argv[argv.index("--base") + 1]) if "--base" in argv else B.WORK / "result.json"
    workers = int(sys.argv[sys.argv.index("--workers") + 1]) if "--workers" in sys.argv else 3
    workers = min(workers, 3)
    base = json.loads(base_path.read_text())
    out = pathlib.Path(argv[argv.index("--out") + 1]) if "--out" in argv else base_path.with_name("result_section3.json")
    if base["source_sha256"] != B.source_hashes() or base["vectors_sha256"] != B.sha(B.H.VECTORS) or not base["controls"]["valid"]:
        sys.exit("sources or vectors changed since %s was written, or its controls were not valid" % base_path)
    t0 = time.time()
    cases = load()
    digests = base["controls"]["unpatched"]["digests"]
    recs = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(B.do_case, *c, digests) for c in cases]
        for f in cf.as_completed(futs):
            r = f.result()
            recs.append(r)
            print("%-44s %-7s %s" % (r["id"], r["status"], json.dumps(r.get("first_failure", r.get("error", "")))[:110]), flush=True)
    order = {c[0]: i for i, c in enumerate(cases)}
    recs.sort(key=lambda r: order[r["id"]])
    cpath = HERE / "not_caught_requirements.json"
    classified = {c["id"]: c for c in json.loads(cpath.read_text())} if cpath.exists() else {}
    passing = [r for r in recs if r["status"] == "passes" and r["id"] != "N00-noop"]
    noop = next((r for r in recs if r["id"] == "N00-noop"), None)
    unclassed = [r["id"] for r in passing if r["id"] not in classified]
    gaps = [i for i, c in classified.items() if c.get("class") == "vector_gap"]
    errors = [r["id"] for r in recs if r["status"] == "ERROR"]
    ok = noop and noop["status"] == "passes" and not unclassed and not gaps and not errors
    res = {"section": 3, "verdict": "PASS" if ok else "INCOMPLETE",
           "vectors_sha256": base["vectors_sha256"], "source_sha256": base["source_sha256"],
           "targeted_mutants_sha256": B.sha(B.ROOT / "validation" / "requirements" / "targeted_mutants.py"),
           "classified_sha256": B.sha(cpath) if cpath.exists() else None,
           "total_cases": len(recs), "caught": sum(1 for r in recs if r["status"] == "caught"), "passes_vectors": len(passing),
           "errors": errors, "unclassed": unclassed, "vector_gaps": gaps, "classified": classified, "cases": recs,
           "wall_seconds": round(time.time() - t0, 1)}
    out.write_text(json.dumps(res, indent=1, sort_keys=True) + "\n")
    print("VERDICT", res["verdict"], "cases", len(recs), "caught", res["caught"], "passes", len(passing), "errors", errors, "wall", res["wall_seconds"])


if __name__ == "__main__":
    main()
