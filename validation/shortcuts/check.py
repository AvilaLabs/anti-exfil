#!/usr/bin/env python3
"""Can a lazy implementation pass the vectors while breaking a MUST?

    check.py --run          run every case and write the result
    check.py --timing       time a few cases and print the estimate for the whole run
Options: --out FILE (the result; default .work/shortcuts/result.json), --only id,id  (restrict the cases;
controls always run), --workers n (at most 3)

Every case is a patched copy of psbt and reference under .work/shortcuts/<id>/, driven through the
harness's helpers on vectors/bip-anti-exfil-psbt.json. A case stops at its first failed vector (that is a catch);
a case that passes ran every vector. Passing cases are classed by hand in not_caught.json.
"""
import concurrent.futures as cf
import hashlib
import importlib.util
import json
import os
import pathlib
import py_compile
import shutil
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "validation" / "second_implementations"))
import check_independent as H           # noqa: E402  (the harness; used, never edited)
import harness as HV         # noqa: E402  (the base helpers plus further classes)
import shortcuts as SC          # noqa: E402

WORK = ROOT / ".work" / "shortcuts"
CLI_REL = pathlib.Path("a") / "b" / "reference_cli.py"      # parents[2] of the copy is the case folder


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def load_mutants():
    spec = importlib.util.spec_from_file_location("mutation_check", ROOT / "psbt" / "tests" / "mutation_check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return [("M-" + mid, [("psbt/" + f, old, new, cnt) for old, new, cnt in pairs], desc)
            for mid, f, pairs, tests, desc in mod.M]


def all_cases():
    return load_mutants() + SC.all_shortcuts()


# ----------------------------------------------------------------- building
def build(cid, patches):
    """Returns (folder, error). error is None if every patch applied and the code still compiles."""
    d = WORK / cid
    if d.exists():
        shutil.rmtree(d)
    (d / "a" / "b").mkdir(parents=True)
    for pkg in ("psbt", "reference"):
        (d / pkg).mkdir()
        for f in (ROOT / pkg).glob("*.py"):
            shutil.copy(f, d / pkg / f.name)
    shutil.copy(HERE / "reference_cli.py", d / CLI_REL)
    (d / "RUN").write_text("python3 -B %s\n" % CLI_REL)
    touched = {}
    for f, old, new, cnt in patches:
        rel = CLI_REL if f == "reference_cli.py" else pathlib.Path(f)
        text = touched.get(rel)
        if text is None:
            text = (d / rel).read_text()
        if text.count(old) != cnt:
            return d, "BAD-ANCHOR: found %d of %d for %r in %s" % (text.count(old), cnt, old[:70], f)
        touched[rel] = text.replace(old, new)
    for rel, text in touched.items():
        orig = (ROOT / rel).read_text() if rel != CLI_REL else (HERE / "reference_cli.py").read_text()
        if text == orig:
            return d, "NO-CHANGE: patch left %s as it was" % rel
        (d / rel).write_text(text)
        try:
            py_compile.compile(str(d / rel), cfile=str(d / "compiled.pyc"), doraise=True)
        except py_compile.PyCompileError as e:
            return d, "SYNTAX: %s" % str(e)[:200]
    return d, None


# ------------------------------------------------------------------ running
def smoke(folder):
    """Both programs must import in the patched copy: a signer result is reused from the control when only host code changed."""
    p = subprocess.run([sys.executable, "-B", "-c", "import sys; sys.path[:0] = ['psbt', 'reference']; "
                        "import host, signer, spend, psbt_codec, transport, anti_exfil"], cwd=str(folder), capture_output=True, text=True)
    return None if p.returncode == 0 else "IMPORT: " + p.stderr.strip().splitlines()[-1][:200]


def crashed(first):
    """A python traceback exits 1 or 2; the contract's codes are 0, 3, 4, 5, 6 and 7."""
    s = json.dumps(first["why"]) if first else ""
    return "exit 1 " in s or "exit 2 " in s or "exit 1\"" in s or "exit 2\"" in s


def do_case(cid, patches, desc, base=None):
    """base: digests of the control's code by kind; a kind whose code equals the control's passes there, so it is not run."""
    t0 = time.time()
    folder, err = build(cid, patches)
    rec = {"id": cid, "desc": desc, "source_sha256": source_hashes()}
    err = err or smoke(folder)
    if err:
        rec.update(status="ERROR", error=err)
        return rec
    skip = tuple(k for k in ("signer", "host") if base and HV.digest(folder, k) == base[k])
    res, first = HV.run_all(folder, skip_kinds=skip)
    rec["seconds"] = round(time.time() - t0, 1)
    rec["reused_from_control"] = list(skip)
    if first:
        rec.update(status="caught", first_failure={"class": first["class"], "vector": first["vector"], "why": first["why"]},
                   exit_1_or_2=crashed(first))
    else:
        rec.update(status="passes", classes_run=[c for c in HV.CLASSES if c in res and res[c]],
                   vectors_run=sum(len(d) for d in res.values()))
    shutil.rmtree(folder, ignore_errors=True)
    return rec


def source_hashes():
    return {f: sha(ROOT / f) for f in ("psbt/host.py", "psbt/signer.py", "psbt/spend.py", "psbt/psbt_codec.py",
                                       "psbt/transport.py", "reference/anti_exfil.py")}


def controls(workers):
    """The unpatched copy passes everything, agrees with check_independent.run_impl on its classes and sets the code digests that
    let a case reuse the control's result for a kind it did not change; the byte flip is caught; a broken reference fails
    lifecycle_scenarios, and so does a copy that forgets the open attempt at restart."""
    flip = [("reference/anti_exfil.py", "        raise ValueError(\"internal BIP340 verification failed\")\n    return sig\n",
             "        raise ValueError(\"internal BIP340 verification failed\")\n    return sig[:-1] + bytes([sig[-1] ^ 1])\n", 1)]
    l04 = [("psbt/host.py", "                if not v[\"counted\"]:\n                    r[\"failures\"] += 1\n", "                pass\n", 1)]    # M-L04, written for the current host.py
    out = {}
    t0 = time.time()

    def unpatched():
        folder, err = build("control-unpatched", [])
        res, first = HV.run_all(folder, stop_early=False)
        ref_res = H.run_impl(folder)
        base = {k: HV.digest(folder, k) for k in ("signer", "host")}
        shutil.rmtree(folder, ignore_errors=True)
        base_res = {c: res[c] for c in HV.BASE_CLASSES}
        return {"all_pass": first is None and H.tally(res)["all_pass"], "first_failure": first,
                "agrees_with_base_run_impl": base_res == ref_res, "digests": base,
                "tally": {c: "%d/%d" % (t["pass"], t["total"]) for c, t in H.tally(res).items() if c != "all_pass"}}

    def flipped():
        return do_case("control-flip-byte", flip, "one signature byte flipped in the signer's BIP340 output")

    def broken():
        folder, err = build("control-broken-reference", [])
        env = dict(os.environ, CLI_MUTANT="host_no_count")
        res, first = HV.run_all(folder, env=env, stop_early=False, skip_kinds=("signer",), classes=("lifecycle_scenarios",))
        shutil.rmtree(folder, ignore_errors=True)
        failed = sorted(k for k, w in res["lifecycle_scenarios"].items() if w)
        r04 = do_case("control-restart-forgets-open-attempt", l04, "M-L04 patch: an open attempt at startup is not counted")
        return {"host_no_count_scenarios_failed": failed, "host_no_count_total": len(res["lifecycle_scenarios"]),
                "restart_forgets": {"status": r04["status"], "first_failure": r04.get("first_failure")}}
    with cf.ThreadPoolExecutor(max_workers=min(3, workers)) as ex:
        a_, b_, c_ = ex.submit(unpatched), ex.submit(flipped), ex.submit(broken)
        out["unpatched"], out["flip_byte"], out["broken_references"] = a_.result(), b_.result(), c_.result()
    br = out["broken_references"]
    out["valid"] = bool(out["unpatched"]["all_pass"] and out["unpatched"]["agrees_with_base_run_impl"]
                        and out["flip_byte"]["status"] == "caught" and br["host_no_count_scenarios_failed"]
                        and br["restart_forgets"]["status"] == "caught"
                        and br["restart_forgets"]["first_failure"]["class"] == "lifecycle_scenarios")
    out["seconds"] = round(time.time() - t0, 1)
    return out


CLASSES_OK = ("vector_gap", "beyond_vectors", "equivalent", "not_required")


def verdict(controls_rec, cases, classified):
    if not controls_rec["valid"]:
        return "INVALID", {}
    if any(c["source_sha256"] != source_hashes() for c in cases):
        return "ERROR", {"source_changed_during_run": True}
    if any(c["status"] == "ERROR" for c in cases):
        return "ERROR", {}
    cls = {c["id"]: c for c in classified}
    unclassed = [c["id"] for c in cases if c["status"] == "passes" and c["id"] not in cls]
    for c in cases:
        if c["status"] == "passes" and c["id"] in cls:
            e = cls[c["id"]]
            c["class"], c["reason"] = e["class"], e["reason"]
            if e["class"] not in CLASSES_OK or (e["class"] == "not_required" and not e.get("sentence")):
                unclassed.append(c["id"])
            if e["class"] == "not_required":
                c["sentence"] = e["sentence"]
    stale = [i for i in cls if i not in {c["id"] for c in cases if c["status"] == "passes"}]
    extra = {"unclassed": unclassed, "classified_but_not_passing": stale}
    if unclassed:
        return "INCOMPLETE", extra
    gaps = [c["id"] for c in cases if c.get("class") == "vector_gap"]
    extra["open_vector_gaps"] = gaps
    return ("FAIL" if gaps else "PASS"), extra


def main():
    args = sys.argv[1:]
    only = None
    workers = 3
    if "--only" in args:
        i = args.index("--only")
        only = set(args[i + 1].split(","))
        del args[i:i + 2]
    if "--workers" in args:
        i = args.index("--workers")
        workers = min(3, int(args[i + 1]))
        del args[i:i + 2]
    out = WORK / "result.json"
    if "--out" in args:
        i = args.index("--out")
        out = pathlib.Path(args[i + 1]).resolve()
        del args[i:i + 2]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return
    mode = args[0]
    WORK.mkdir(parents=True, exist_ok=True)
    cases = all_cases()
    ids = [c[0] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    if mode == "--timing":
        pick = ["M-H01-core-tx", "W-signer-returns-rho", "W-host-retries-forever", "M-S06-nonce-only", "W-host-response-as-result"]
        t0 = time.time()
        times = []
        for cid, patches, desc in cases:
            if cid in pick:
                r = do_case(cid, patches, desc, None)
                times.append(r.get("seconds"))
                print(cid, r["status"], r.get("seconds"), flush=True)
        tc = time.time()
        c = controls(1)
        print("controls", c["valid"], c["seconds"], c["unpatched"]["tally"], flush=True)
        print("total cases", len(cases), "mean timed (s)", sum(times) / len(times))
        return
    if mode != "--run":
        sys.exit("usage: check.py --run | --timing  [--out FILE] [--only id,id] [--workers n]")
    out.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    crec = controls(workers)
    print("controls valid=%s %s" % (crec["valid"], json.dumps(crec["unpatched"]["tally"])), flush=True)
    recs = []
    if crec["valid"]:
        todo = [c for c in cases if only is None or c[0] in only]
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(do_case, *c, crec["unpatched"]["digests"]): c[0] for c in todo}
            for f in cf.as_completed(futs):
                r = f.result()
                recs.append(r)
                print("%-46s %-7s %s" % (r["id"], r["status"], json.dumps(r.get("first_failure", r.get("error", "")))[:110]), flush=True)
    order = {cid: i for i, cid in enumerate(ids)}
    recs.sort(key=lambda r: order[r["id"]])
    cpath = HERE / "not_caught.json"
    classified = json.loads(cpath.read_text()) if cpath.exists() else []
    verd, extra = verdict(crec, recs, classified) if only is None else ("PARTIAL", {})
    caught = [r["id"] for r in recs if r["status"] == "caught"]
    passing = [r for r in recs if r["status"] == "passes"]
    result = {
        "vectors_sha256": sha(H.VECTORS), "shortcuts_sha256": sha(HERE / "shortcuts.py"), "check_sha256": sha(HERE / "check.py"),
        "source_sha256": source_hashes(), "classified_sha256": sha(cpath) if cpath.exists() else None,
        "sections": {"1_disabled_checks": "run", "2_written_shortcuts": "run", "3_requirement_mutants": "not run here; see check_mutants.py"},
        "verdict": verd, "controls": crec,
        "total_cases": len(recs), "caught": len(caught), "passes_vectors": len(passing),
        "passes_by_class": {k: sum(1 for r in passing if r.get("class") == k) for k in CLASSES_OK},
        "vector_counts": {k: len(v) for k, v in json.loads(H.VECTORS.read_text()).items() if isinstance(v, list)},
        "errors": [r["id"] for r in recs if r["status"] == "ERROR"],
        **extra, "cases": recs, "wall_seconds": round(time.time() - t0, 1),
    }
    out.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    print("VERDICT", verd, "cases", len(recs), "caught", len(caught), "passes", len(passing), "wall", result["wall_seconds"])


if __name__ == "__main__":
    main()
