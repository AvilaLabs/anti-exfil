#!/usr/bin/env python3
"""Runner: requirement gate, controls, targeted mutants, mechanical estimate/sweep.

  check.py --run [--workers 3] [--estimate-sample 24] [--mechanical] [--budget-min 60] [--out FILE]
  check.py --run [--only ID,ID] [--no-controls] [--no-mechanical-sample]   a partial run, for trying it out
  check.py --validate                       apply every patch, enumerate sites, run the gate
  check.py --review RUN.json CLASSES.json   recompute the result with survivor classes (read-only)

A mutant is killed when a test goes red on a copy of psbt/ under .work/requirements/. Targeted mutants
first run the tests the rows claim (phase A, failfast), then, if those stay green, the whole no-regtest
suite module by module (phase B, fastest-likely module first, stop at the first red module). A survivor
therefore has had the whole suite run on it. A module that exceeds its time limit is a timeout, never a
kill; a mutant with a timeout and no red test is `timeout`.
Result (computed here): FAIL_CONTROL, FAIL_REQUIREMENT_GATE, INCOMPLETE (a targeted mutant timed out,
errored or was not run), FAIL_UNEXPLAINED_SURVIVORS, PASS. The mechanical score has no threshold.
Mechanical: a fixed-seed sample is run in full and the wall time of the whole sweep is estimated; if it
exceeds --budget-min the sweep is not started and the estimate is recorded.
Run under: nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 python3 -B -I check.py ...
"""
import argparse
import concurrent.futures as cf
import copy
import hashlib
import json
import os
import pathlib
import random
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SRC = ROOT / "psbt"
WORK = ROOT / ".work/requirements"
sys.path.insert(0, str(HERE))
import extract_check  # noqa: E402
import mechanical_mutants  # noqa: E402
import targeted_mutants  # noqa: E402

FILES = ("host.py", "signer.py", "spend.py", "psbt_codec.py")
MODULE_TIMEOUT = {"test_bip_psbt_cases": 60, "test_outside_sighash": 60, "test_regressions": 90, "test_known_answers": 60, "test_math_codec": 90, "test_lifecycle": 200, "test_signer": 260,
                  "test_host_response": 320, "test_positive": 500}
ORDER = {
    "host.py": ("test_regressions", "test_known_answers", "test_lifecycle", "test_host_response", "test_signer", "test_math_codec", "test_positive", "test_bip_psbt_cases", "test_outside_sighash"),
    "signer.py": ("test_regressions", "test_known_answers", "test_signer", "test_host_response", "test_lifecycle", "test_math_codec", "test_positive", "test_bip_psbt_cases", "test_outside_sighash"),
    "spend.py": ("test_regressions", "test_known_answers", "test_signer", "test_host_response", "test_math_codec", "test_lifecycle", "test_positive", "test_bip_psbt_cases", "test_outside_sighash"),
    "psbt_codec.py": ("test_math_codec", "test_known_answers", "test_regressions", "test_signer", "test_host_response", "test_lifecycle", "test_positive", "test_bip_psbt_cases", "test_outside_sighash"),
}
PHASE_A_TIMEOUT = 200
HASHED = ("check.py", "extract_check.py", "sentences.py", "targeted_mutants.py", "mechanical_mutants.py", "requirements.json")
EXTRA_HASHED = ("psbt/tests/mutation_check.py", "psbt/tests/test_known_answers.py", "psbt/tests/run_tests.py",
                "psbt/tests/test_signer.py", "psbt/tests/test_host_response.py", "psbt/tests/test_math_codec.py")
REGTEST_MUTANTS = ["N80-legacy-seq", "N81-bip143-value", "N82-bip143-hs", "N83-tap-annex", "N84-tap-leafver", "N85-tap-outputs",
                   "N86-tap-tweak-order", "N87-empty-root", "N88-sigkey-script"]


def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


RUNNER = (
    "import sys, json, unittest; sys.path.insert(0, %r)\n"
    "s = unittest.defaultTestLoader.loadTestsFromNames(%r)\n"
    "r = unittest.TextTestRunner(verbosity=0, failfast=True, stream=open('/dev/null', 'w')).run(s)\n"
    "bad = (r.failures + r.errors)\n"
    "print(json.dumps({'red': not r.wasSuccessful(), 'failed': bad[0][0].id() if bad else None, 'ran': r.testsRun}))\n")


def run_tests(srcdir, names, timeout):
    """Run test names (modules or dotted ids) against the copy in srcdir. Returns a dict."""
    code = RUNNER % (str(SRC / "tests"), list(names))
    t0 = time.time()
    try:
        p = subprocess.run([sys.executable, "-B", "-I", "-c", code], capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, AE_HOST_SRC=str(srcdir), LANG="C"), cwd=str(WORK))
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "seconds": round(time.time() - t0, 1)}
    secs = round(time.time() - t0, 1)
    try:
        d = json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        return {"status": "error", "seconds": secs, "detail": (p.stderr or p.stdout)[-300:]}
    return {"status": "red" if d["red"] else "green", "seconds": secs, "failed": d["failed"], "ran": d["ran"]}


def full_suite(srcdir, order):
    """The whole no-regtest suite, module by module. Returns (status, info)."""
    mods, timeouts, secs, ran = [], 0, 0.0, 0
    for mod in order:
        r = run_tests(srcdir, [mod], MODULE_TIMEOUT[mod])
        secs += r["seconds"]
        mods.append({"module": mod, **{k: v for k, v in r.items() if k != "seconds"}, "seconds": r["seconds"]})
        if r["status"] == "red":
            return "killed", {"killed_by": r["failed"], "modules": mods, "suite_seconds": round(secs, 1)}
        if r["status"] == "timeout":
            timeouts += 1
        elif r["status"] == "error":
            return "error", {"modules": mods, "suite_seconds": round(secs, 1), "detail": r.get("detail")}
        else:
            ran += r["ran"]
    st = "timeout" if timeouts else "survived"
    return st, {"modules": mods, "suite_seconds": round(secs, 1), "tests_run": ran}


def make_copy(run_dir, name, file, text):
    d = run_dir / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    for f in SRC.glob("*.py"):
        shutil.copy(f, d / f.name)
    if file:
        (d / file).write_text(text, encoding="utf-8")
    return d


def claimed_tests(m, rows):
    if m.get("tests"):
        return list(m["tests"])
    out = []
    for rid in m["reqs"]:
        r = rows.get(rid)
        if r and isinstance(r.get("coverage"), list) and r["class"] != "math":
            out += [c for c in r["coverage"] if c not in out]
    return out


def run_targeted(m, rows, run_dir, base):
    rec = {"id": m["id"], "kind": "targeted", "source": m["source"], "file": m["file"], "reqs": m["reqs"], "desc": m["desc"]}
    t0 = time.time()
    try:
        text = targeted_mutants.apply(m, base[m["file"]])
        d = make_copy(run_dir, m["id"], m["file"], text)
    except Exception as exc:  # noqa: BLE001
        rec.update(status="error", detail="%s: %s" % (type(exc).__name__, str(exc)[:200]))
        return rec
    try:
        claimed = claimed_tests(m, rows)
        rec["claimed_tests"] = claimed
        if claimed:
            a = run_tests(d, claimed, PHASE_A_TIMEOUT)
            rec["phase_a"] = a
            if a["status"] == "red":
                rec.update(status="killed", killed_by=a["failed"], killed_in="claimed_tests")
                return rec
        st, info = full_suite(d, ORDER[m["file"]])
        rec.update(status=st, **info)
        if st == "killed":
            rec["killed_in"] = "full_suite"
    finally:
        rec["seconds"] = round(time.time() - t0, 1)
        shutil.rmtree(d, ignore_errors=True)
    if rec["status"] == "survived":
        rec["classification"] = ""
        rec["classification_reason"] = ""
    return rec


def run_mechanical(file, idx, text, run_dir, kind_desc):
    rec = {"id": "MM-%s-%04d" % (file[:-3], idx), "kind": "mechanical", "file": file, "desc": kind_desc}
    t0 = time.time()
    d = make_copy(run_dir, rec["id"], file, text)
    try:
        st, info = full_suite(d, ORDER[file])
        rec.update(status=st, **info)
    finally:
        rec["seconds"] = round(time.time() - t0, 1)
        shutil.rmtree(d, ignore_errors=True)
    if rec["status"] == "survived":
        rec["classification"] = ""
        rec["classification_reason"] = ""
    return rec


def verdict_from(records, controls_ok, gate_ok, mech_status):
    tgt = [r for r in records if r["kind"] == "targeted" and r["id"] != "N00-noop"]
    cnt = lambda rs, s: sum(1 for r in rs if r["status"] == s)
    out = {"targeted": {s: cnt(tgt, s) for s in ("killed", "survived", "timeout", "error", "not_run")}}
    out["targeted"]["total"] = len(tgt)
    out["targeted"]["killed_by_claimed_tests"] = sum(1 for r in tgt if r.get("killed_in") == "claimed_tests")
    out["targeted"]["killed_only_by_other_tests"] = [r["id"] for r in tgt if r.get("killed_in") == "full_suite"]
    unexplained = [r["id"] for r in tgt if r["status"] == "survived" and not r.get("classification")]
    out["targeted_unexplained_survivors"] = unexplained
    classes = {}
    for r in tgt:
        if r["status"] == "survived" and r.get("classification"):
            classes[r["classification"]] = classes.get(r["classification"], 0) + 1
    out["targeted_survivor_classes"] = classes
    mech = [r for r in records if r["kind"] == "mechanical"]
    m = {s: cnt(mech, s) for s in ("killed", "survived", "timeout", "error")}
    m["total"] = len(mech)
    m["status"] = mech_status
    den = m["killed"] + m["survived"]
    m["score_killed_over_killed_plus_survived"] = round(m["killed"] / den, 4) if den else None
    den2 = den + m["timeout"]
    m["score_timeouts_counted_as_killed"] = round((m["killed"] + m["timeout"]) / den2, 4) if den2 else None
    out["mechanical_sample" if mech_status != "complete" else "mechanical"] = m
    if not controls_ok:
        v = "FAIL_CONTROL"
    elif not gate_ok:
        v = "FAIL_REQUIREMENT_GATE"
    elif out["targeted"]["not_run"] or out["targeted"]["error"] or out["targeted"]["timeout"] or out["targeted"]["total"] == 0:
        v = "INCOMPLETE"
    elif unexplained:
        v = "FAIL_UNEXPLAINED_SURVIVORS"
    else:
        v = "PASS"
    out["verdict"] = v
    return out


def gate_controls(doc):
    """Quote control and coverage control on altered copies of the requirements file."""
    res = {}
    d = copy.deepcopy(doc)
    d["requirements"][0]["quotes"][0]["text"] = "this sentence is not in the document"
    probs, _ = extract_check.check(d, mutants=None)
    res["broken_quote_detected"] = any("quote not found" in p for p in probs)
    d = copy.deepcopy(doc)
    victim = next(r for r in d["requirements"] if r["id"] == "B-025")      # "Scripts containing an `OP_SUCCESSx` opcode fail."
    d["requirements"] = [r for r in d["requirements"] if r is not victim]
    probs, _ = extract_check.check(d, mutants=None)
    res["removed_sentence_detected"] = any("not covered" in p and "OP_SUCCESSx" in p for p in probs)
    res["ok"] = res["broken_quote_detected"] and res["removed_sentence_detected"]
    return res


def validate_only(req_path=None):
    problems = []
    for m in targeted_mutants.all_mutants():
        try:
            targeted_mutants.apply(m, (SRC / m["file"]).read_text())
        except ValueError as e:
            problems.append(str(e))
    ms = targeted_mutants.all_mutants()
    print("targeted mutants: %d (%d reused, %d new)" % (len(ms), len(ms) - len(targeted_mutants.NEW), len(targeted_mutants.NEW)))
    total = 0
    for f in FILES:
        n = len(mechanical_mutants.enumerate_sites((SRC / f).read_text()))
        total += n
        print("mechanical sites %-14s %d" % (f, n))
    print("mechanical total", total)
    gp, info = extract_check.check(extract_check.load(req_path))
    problems += gp
    print(info)
    for p in problems:
        print("PROBLEM:", p)
    print("validate:", "FAIL" if problems else "OK")
    return 1 if problems else 0


def review(run_path, class_path, write):
    doc = json.loads(pathlib.Path(run_path).read_text())
    cls = json.loads(pathlib.Path(class_path).read_text())
    for r in doc["records"]:
        if r["status"] == "survived" and r["id"] in cls:
            r["classification"] = cls[r["id"]]["classification"]
            r["classification_reason"] = cls[r["id"]]["reason"]
    out = verdict_from(doc["records"], doc["controls_ok"], doc["requirement_gate_ok"], doc["mechanical_status"])
    print(json.dumps({k: out[k] for k in ("verdict", "targeted", "targeted_unexplained_survivors", "targeted_survivor_classes")}, indent=1))
    if write:
        p = pathlib.Path(run_path).with_name(pathlib.Path(run_path).stem + "_verdict.json")
        with open(p, "x") as f:
            json.dump({"classifications": cls, **out}, f, indent=1, sort_keys=True)
        print("wrote", p)
    return 0


def flush(path, doc):
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--only")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--estimate-sample", type=int, default=24)
    ap.add_argument("--sample-seed", type=int, default=70, help="seed of the mechanical sample; the default is 70")
    ap.add_argument("--no-mechanical-sample", action="store_true")
    ap.add_argument("--mechanical", action="store_true", help="run the full sweep if the estimate allows")
    ap.add_argument("--budget-min", type=float, default=60.0)
    ap.add_argument("--no-controls", action="store_true")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--requirements", help="requirements file (default requirements.json)")
    ap.add_argument("--out", help="result file (default .work/requirements/result.json)")
    ap.add_argument("--regtest-section", action="store_true", help="after the targeted mutants, run N80-N88 once against test_regtest (reported apart from the verdict)")
    ap.add_argument("--review", nargs=2)
    ap.add_argument("--write-review", action="store_true")
    args = ap.parse_args(argv)
    if args.validate:
        return validate_only(args.requirements)
    if args.review:
        return review(*args.review, args.write_review)
    if args.workers > 3:
        ap.error("at most 3 workers")
    if not args.run:
        ap.error("--run is required")
    found = {x.stem for x in (ROOT / "psbt" / "tests").glob("test_*.py")} - {"test_regtest"}
    for f, mods in ORDER.items():
        if set(mods) != found:
            ap.error("the module list for %s differs from the suite: %s" % (f, sorted(set(mods) ^ found)))
    hashes = {n: sha(HERE / n) for n in HASHED}
    hashes.update({n: sha(ROOT / n) for n in EXTRA_HASHED})
    WORK.mkdir(parents=True, exist_ok=True)
    tag = "result"
    out_path = pathlib.Path(args.out) if args.out else WORK / "result.json"
    run_dir = WORK / tag
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    started = time.time()
    docs = extract_check.load(args.requirements)
    doc_req_name = pathlib.Path(args.requirements).name if args.requirements else "requirements.json"
    src_hashes = {f.name: sha(f) for f in sorted(SRC.glob("*.py"))}
    src_hashes.update({"tests/" + f.name: sha(f) for f in sorted((SRC / "tests").glob("*.py"))})
    gate_problems, gate_info = extract_check.check(docs)
    doc = {"requirements_file": doc_req_name, "status": "RUNNING", "documents": docs["documents"], "psbt_sha256": src_hashes, "scripts": hashes,
           "requirement_gate_ok": not gate_problems, "requirement_gate_problems": gate_problems,
           "requirement_counts": gate_info["counts"], "requirement_rows": gate_info["rows"],
           "requirements_with_coverage_none": gate_info["coverage_none"], "records": [], "mechanical_status": "not_run"}
    flush(out_path, doc)
    # ---- controls
    controls = {"gate": gate_controls(docs)}
    base = {f: (SRC / f).read_text() for f in FILES}
    jobs = {"baseline_unmutated": None}
    for f in FILES:
        jobs["roundtrip_" + f] = f
    if args.no_controls:
        controls["suite"] = "skipped (--no-controls)"
        suite_ok = True
    else:
        def ctl(name):
            f = jobs[name]
            d = make_copy(run_dir, "ctl_" + name, f, mechanical_mutants.roundtrip(base[f]) if f else None)
            try:
                st, info = full_suite(d, ORDER[f or "host.py"])
            finally:
                shutil.rmtree(d, ignore_errors=True)
            return name, {"status": st, **info}
        with cf.ThreadPoolExecutor(args.workers) as ex:
            for name, r in ex.map(ctl, list(jobs)):
                controls[name] = r
        suite_ok = all(controls[n]["status"] == "survived" for n in jobs)
    controls["ok_suite_green_on_unmutated_and_roundtrip"] = suite_ok
    controls_ok = suite_ok and controls["gate"]["ok"]
    doc["controls"] = controls
    doc["controls_ok"] = controls_ok
    flush(out_path, doc)
    if not controls_ok:
        doc.update(verdict_from([], False, not gate_problems, "not_run"))
        doc["status"] = "DONE"
        flush(out_path, doc)
        print("CONTROL FAILURE", json.dumps(controls)[:600])
        return 1
    # ---- targeted
    rows = {r["id"]: r for r in docs["requirements"]}
    muts = targeted_mutants.all_mutants()
    if args.only:
        want = set(args.only.split(","))
        muts = [m for m in muts if m["id"] in want]
    t0 = time.time()
    with cf.ThreadPoolExecutor(args.workers) as ex:
        futs = [ex.submit(run_targeted, m, rows, run_dir, base) for m in muts]
        for n, fu in enumerate(futs):
            rec = fu.result()
            doc["records"].append(rec)
            print("%-34s %-9s %s" % (rec["id"], rec["status"], rec["desc"][:70]), flush=True)
            if n % 5 == 0:
                flush(out_path, doc)
    noop = next((r for r in doc["records"] if r["id"] == "N00-noop"), None)
    if noop is not None:
        controls["noop_mutant_survives"] = noop["status"] == "survived"
        if noop["status"] != "survived":
            controls_ok = False
            doc["controls_ok"] = False
    doc["targeted_seconds"] = round(time.time() - t0, 1)
    # ---- regtest section (not part of the verdict)
    if args.regtest_section:
        by_id = {m["id"]: m for m in targeted_mutants.all_mutants()}

        def reg(mid):
            m = by_id[mid]
            d = make_copy(run_dir, "reg_" + mid, m["file"], targeted_mutants.apply(m, base[m["file"]]))
            try:
                r = run_tests(d, ["test_regtest"], 900)
            finally:
                shutil.rmtree(d, ignore_errors=True)
            st = {"red": "killed", "green": "survived"}.get(r["status"], r["status"])
            return {"id": mid, "desc": m["desc"], "status": st, "killed_by": r.get("failed"), "seconds": r["seconds"]}
        with cf.ThreadPoolExecutor(min(args.workers, 2)) as ex:
            doc["regtest_section"] = list(ex.map(reg, REGTEST_MUTANTS))
        for r in doc["regtest_section"]:
            print("regtest %-26s %s" % (r["id"], r["status"]), flush=True)
    # ---- mechanical
    sites = {f: mechanical_mutants.enumerate_sites(base[f]) for f in FILES}
    total = sum(len(s) for s in sites.values())
    mech_info = {"sites": {f: len(s) for f, s in sites.items()}, "total_mutants": total}
    mech_status = "not_run"
    if not args.no_mechanical_sample:
        rng = random.Random(args.sample_seed)
        allm = [(f, s["index"], s) for f in FILES for s in sites[f]]
        pick = rng.sample(allm, min(args.estimate_sample, len(allm)))

        def one(item):
            f, idx, s = item
            return run_mechanical(f, idx, mechanical_mutants.mutate(base[f], idx), run_dir, "%s line %d: %s" % (s["kind"], s["line"], s["desc"]))
        with cf.ThreadPoolExecutor(args.workers) as ex:
            sample = list(ex.map(one, pick))
        doc["records"] += sample
        mean = sum(r["seconds"] for r in sample) / len(sample)
        est_wall = mean * total / args.workers
        mech_info.update(sample_seed=args.sample_seed, sample_size=len(sample), sample_mean_seconds=round(mean, 1),
                         sample_survived=sum(1 for r in sample if r["status"] == "survived"),
                         estimate_wall_minutes=round(est_wall / 60, 1), workers=args.workers, budget_minutes=args.budget_min,
                         estimate_note="mean seconds per mutant (sum of module times, so the mean already includes contention at this worker count) x total / workers")
        if est_wall / 60 > args.budget_min:
            mech_status = "not_started_over_budget"
        elif args.mechanical:
            done = {r["id"] for r in sample}
            rest = [x for x in allm if "MM-%s-%04d" % (x[0][:-3], x[1]) not in done]
            with cf.ThreadPoolExecutor(args.workers) as ex:
                for r in ex.map(one, rest):
                    doc["records"].append(r)
            mech_status = "complete"
        else:
            mech_status = "not_started_flag_off"
    doc["mechanical_info"] = mech_info
    doc["mechanical_status"] = mech_status
    doc.update(verdict_from(doc["records"], controls_ok, not gate_problems, mech_status))
    doc["status"] = "DONE"
    doc["elapsed_seconds"] = round(time.time() - started, 1)
    flush(out_path, doc)
    print("requirements: %s  elapsed %.0fs" % (doc["verdict"], doc["elapsed_seconds"]))
    print(json.dumps({k: doc[k] for k in doc if k in ("targeted", "targeted_unexplained_survivors", "mechanical_info", "mechanical_status")}, indent=1))
    print("output:", out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
