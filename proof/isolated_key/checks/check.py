"""Driver of the isolated-key checks. Usage: check.py [--smoke] [--out PATH]

Prints one line per item A1..A5, B1..B4 and OVERALL, writes a JSON file.
The full run is `check.py` without --smoke. Both write to .work/isolated_key/ unless --out is given; smoke uses the smoke plan.
"""
import argparse
import json
import os
import sys
import time
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import toy_law  # noqa: E402
import toy_sim  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

PLANS = {
    "full": {
        "A": dict(curves=toy_law.CURVES_FULL, nkeys=6, nz=6, netab=2, ncontrol=2, seed="isolated-A-v1"),
        "B": dict(p=79, N_fine=60000, N_coarse=40000, N_control=60000, seed="isolated-B-v1"),
    },
    "smoke": {
        "A": dict(curves=toy_law.CURVES_SMOKE, nkeys=3, nz=4, netab=1, ncontrol=1, seed="isolated-A-smoke"),
        "B": dict(p=79, N_fine=20000, N_coarse=12000, N_control=20000, seed="isolated-B-smoke"),
    },
}


def jdefault(o):
    if isinstance(o, Fraction):
        return str(o)
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    return str(o)


def verdicts(a, b):
    v = {}
    A1, A2, A3, A4, A5 = (a[k] for k in ("A1", "A2", "A3", "A4", "A5"))
    v["A1"] = (not A1["fail"] and A1["cases"] > 0,
               f"cases={A1['cases']} TV(G3,G4)=0 exactly in all; fail={len(A1['fail'])}")
    n_beta = sum(1 for r in A2["curves"] if r["beta"] != "0")
    v["A2"] = (not A2["fail"] and not a["assumptions"],
               f"curves={len(A2['curves'])} (beta>0 on {n_beta}); conditional TV == beta exactly on all; "
               f"toy B assumptions broken on {len(a['assumptions'])} curves; fail={len(A2['fail'])}")
    v["A3"] = (not A3["fail"] and A3["cases"] > 0 and A3["max_bad"] <= 8,
               f"cases={A3['cases']} max_bad={A3['max_bad']} bad_hist={A3['bad_hist']} "
               f"full-law TV<=bad/n in all={A3['full_tv_le_bad_over_n_all']}; conditional TV bad/(n-1) exceeds "
               f"bad/n in {A3['cond_tv_exceeds_bad_over_n']}/{A3['cond_tv_cases_with_bad']} cases with bad>0")
    v["A4"] = (not A4["fail"] and A4["cases"] > 0,
               f"cases={A4['cases']} TV(G4',G5)=0 exactly; Sign_Rand sigs={A4['sign_rand_sigs']} "
               f"K_good not neg-closed={A4['kgood_not_neg_closed']} V!=+-W={A4['V_not_pm_W']} "
               f"cached!=device={A4['cached_sig_differs']}; fail={len(A4['fail'])}")
    names = sorted(A5["controls"])
    v["A5"] = (not A5["fail"] and len(names) >= 3,
               f"{len(names)} wrong samplers, all TV>0 ({'; '.join(f'{k} min {A5['controls'][k]['min_tv']:.4g}' for k in names)})")
    b1 = b["B1"]
    v["B1"] = (b1["ok"], f"Reduction.__init__{b1['signature']}; forbidden identifiers: {b1['forbidden_identifiers_in_class_body']}; "
                         f"PublicCurve exposes no dlog={b1['dlog_not_exposed']}")
    sc = b["B"]["scripts"]
    inv = sum(g["inv_fail"] for g in b["B"]["groups"])
    exc = sum(g["counts_exceed"] for g in b["B"]["groups"])
    ali = sum(g["alias_invalid"] for g in b["B"]["groups"])
    runs = sum(g["inv_runs"] for g in b["B"]["groups"])
    ec = [s for t, s in sc.items() if t.startswith("ecdsa")]
    xs, xg, xa = (sum(s[k] for s in ec) for k in ("sigs", "x_ge_n", "alt_lift"))
    v["B2"] = (inv == 0 and exc == 0 and ali == 0 and runs > 0 and len(sc) > 0,
               f"{len(sc)} script/scheme cells, {runs} invariant-checked runs; invariant failures={inv} "
               f"(valid sigs, step-5 host check, repeats equal, programmed H_point); declared N/D/T or "
               f"q_s+1 Sign_Rand exceeded={exc}; invalid alias forgeries={ali}; ECDSA signatures in real groups: {xs}, with x(W)>=n: {xg}, "
               f"other lift on curve: {xa}")
    ch = b["B"]["chi2"]
    bad_p = [c for c in ch if c["p"] <= 1e-5]
    badb = []
    for t, s in sc.items():
        for f, r in s["real_bad"].items():
            if f != "bad1" and not r["ok"]:
                badb.append((t, "real", f))
    for g in b["B"]["groups"]:
        for f, r in g.get("bad_vs_bound", {}).items():
            if f != "bad1" and not r["ok"]:
                badb.append((g["tag"], g["kind"], f))
    wav = sum(s["win_abort_viol"] for s in sc.values())
    bv = sum(g["bwin_viol"] for g in b["B"]["groups"])
    minp = min((c["p"] for c in ch), default=1.0)
    v["B3"] = (not bad_p and not badb and wav == 0 and bv == 0 and len(ch) > 0,
               f"{len(ch)} chi-square comparisons, min p={minp:.3g}, below 1e-5: {len(bad_p)}; bad2/3/4 above bound: "
               f"{len(badb)}; F wins with abort at correct guess={wav}; B forgery not fresh={bv}")
    ct = b["B"]["controls"]
    miss = [c for c in ct if not c["detected"]]
    v["B4"] = (not miss and len(ct) >= 3,
               f"{len(ct)} broken simulators, detected {len(ct) - len(miss)}; undetected: "
               f"{[(c['scheme'], c['variant'], round(c['p'], 4)) for c in miss]}")
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()
    plan = PLANS["smoke" if args.smoke else "full"]
    if args.out:
        out = args.out
    else:
        out = os.path.join(ROOT, ".work", "isolated_key", "smoke_result.json" if args.smoke else "result.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    t0 = time.time()
    print(f"isolated-key check {'SMOKE' if args.smoke else 'FULL'} plan: {json.dumps(plan, default=str)}")
    a = toy_law.run_part_a(plan["A"], log=lambda m: print(m, flush=True))
    ta = time.time() - t0
    b1 = toy_sim.b1_check()
    bres = toy_sim.run_part_b(plan["B"], log=lambda m: print(m, flush=True))
    v = verdicts(a, {"B1": b1, "B": bres})
    order = ["A1", "A2", "A3", "A4", "A5", "B1", "B2", "B3", "B4"]
    for k in order:
        print(f"{k} {'PASS' if v[k][0] else 'FAIL'} {v[k][1]}")
    overall = all(v[k][0] for k in order)
    wrong = [k for k in ("A1", "A2", "A4", "B3") if not v[k][0]]
    line = "PASS" if overall else "FAIL" + (f" (written proof wrong as stated: {', '.join(wrong)})" if wrong else " (checker items only)")
    print(f"OVERALL {line}")
    rec = {"smoke": args.smoke, "plan": plan, "verdicts": {k: {"pass": v[k][0], "text": v[k][1]} for k in order},
           "overall": line, "seconds": {"part_a": ta, "total": time.time() - t0}, "A": a, "B1": b1, "B": bres}
    with open(out, "w") as fh:
        json.dump(rec, fh, indent=1, default=jdefault, sort_keys=True)
    print(f"wrote {out} in {time.time() - t0:.0f}s")
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
