#!/usr/bin/env python3
"""Exact check of the refusal bound on small finite sets (spec/security-argument.md, Part 2). Writes result.json."""
import itertools
import json
import math
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parent
TOL = 1e-9
LN2 = math.log(2)


def analyse(D, n, accept):
    """accept(history, w) -> probability in [0, 1]. Return exact quantities.

    Law of the published value at step t given history: proportional to
    accept(history, w). Expected failures at that step: 1 / mean(accept) - 1.
    """
    law = {}
    kl = 0.0
    mid = 0.0
    ef = 0.0
    def walk(hist, p):
        nonlocal kl, mid, ef
        if len(hist) == n:
            law[hist] = p
            if p > 0:
                kl += p * (math.log2(p) + n * math.log2(D))
            return
        ps = [accept(hist, w) for w in range(D)]
        mean = sum(ps) / D
        if mean <= 0:
            raise ValueError("stall")
        f = 1.0 / mean - 1.0
        ef += p * f
        mid += p * math.log2(1.0 + f)
        for w in range(D):
            q = ps[w] / (D * mean)
            if q > 0:
                walk(hist + (w,), p * q)
    walk((), 1.0)
    return {"law": law, "kl": kl, "mid": mid, "ef": ef}


def mutual_information(a, b):
    """I(S; published) for a uniform secret with two values, from two laws."""
    total = 0.0
    for key in set(a) | set(b):
        pa, pb = a.get(key, 0.0), b.get(key, 0.0)
        m = (pa + pb) / 2
        for p in (pa, pb):
            if p > 0:
                total += 0.5 * p * math.log2(p / m)
    return total


def random_strategy(rng, D, secret):
    table = {}
    def accept(hist, w):
        key = (secret, hist, w)
        if key not in table:
            table[key] = rng.choice([0.0, 0.25, 0.5, 0.9, 1.0, rng.random()])
        return table[key]
    def safe(hist, w):
        # Guarantee at least one acceptable value at every history.
        if w == 0 and all(accept(hist, x) == 0.0 for x in range(D)):
            return 1.0
        return accept(hist, w)
    return safe


def threshold(D):
    return lambda hist, w: 0.0 if w == D - 1 else 1.0


def parity(bit):
    return lambda hist, w: 1.0 if (w & 1) == bit else 0.0


def one_value(v):
    return lambda hist, w: 1.0 if w == v else 0.0


def capped_mi(D, L, rule):
    """One signature, at most L failures, then the last candidate is taken.

    rule(secret, w) says whether the device accepts. Enumerates all candidate
    tuples of length L + 1 for both secrets of a uniform two-value secret.
    """
    laws = []
    for secret in (0, 1):
        law = {}
        for tup in itertools.product(range(D), repeat=L + 1):
            pick = tup[-1]
            for w in tup:
                if rule(secret, w):
                    pick = w
                    break
            law[pick] = law.get(pick, 0.0) + D ** -(L + 1)
        laws.append(law)
    return mutual_information(*laws)


def main():
    rng = random.Random(62)
    result = {"cases": 0, "violations": [], "controls": {}}

    def check(label, a):
        result["cases"] += 1
        if a["kl"] > a["mid"] + TOL or a["mid"] > a["ef"] / LN2 + TOL:
            result["violations"].append({"case": label, "kl": a["kl"], "mid": a["mid"], "ef": a["ef"]})

    max_ratio = 0.0
    wrong_bound_hits = 0
    for D in (2, 4, 8, 16):
        for n in (1, 2, 3):
            if D ** n > 5000:
                continue
            for i in range(200):
                s0 = analyse(D, n, random_strategy(rng, D, 0))
                s1 = analyse(D, n, random_strategy(rng, D, 1))
                check(f"random D={D} n={n} i={i} s0", s0)
                check(f"random D={D} n={n} i={i} s1", s1)
                mi = mutual_information(s0["law"], s1["law"])
                avg_ef = (s0["ef"] + s1["ef"]) / 2
                avg_kl = (s0["kl"] + s1["kl"]) / 2
                result["cases"] += 1
                if mi > avg_kl + TOL or mi > avg_ef / LN2 + TOL:
                    result["violations"].append({"case": f"mi D={D} n={n} i={i}", "mi": mi, "avg_ef": avg_ef})
                for a in (s0, s1):
                    if a["ef"] > 0:
                        max_ratio = max(max_ratio, a["kl"] / a["ef"])
                        if a["kl"] > 0.5 * a["ef"] / LN2 + TOL:
                            wrong_bound_hits += 1
            for name, st in (("threshold", threshold(D)), ("parity0", parity(0)), ("parity1", parity(1)), ("one", one_value(0))):
                check(f"{name} D={D} n={n}", analyse(D, n, st))

    # C1: naive I <= E[F] fails. A threshold strategy gives more bits than failures.
    big = analyse(1 << 10, 1, threshold(1 << 10))
    c1 = big["kl"] > big["ef"] + TOL
    result["controls"]["C1_naive_bound_violated"] = {"pass": c1, "kl": big["kl"], "ef": big["ef"], "ratio": big["kl"] / big["ef"]}
    # C2: a deliberately wrong bound is seen as violated.
    result["controls"]["C2_wrong_bound_detected"] = {"pass": wrong_bound_hits > 0, "hits": wrong_bound_hits}
    # C3: always accept.
    a = analyse(8, 2, lambda h, w: 1.0)
    result["controls"]["C3_always_accept"] = {"pass": abs(a["kl"]) < TOL and abs(a["ef"]) < TOL}
    # C4: parity, one bit per expected failure, and the secret is fully conveyed.
    p0, p1 = analyse(2, 1, parity(0)), analyse(2, 1, parity(1))
    mi = mutual_information(p0["law"], p1["law"])
    result["controls"]["C4_parity"] = {"pass": abs(mi - 1) < TOL and abs(p0["ef"] - 1) < TOL, "mi": mi, "ef": p0["ef"]}

    # Capped claim: at most L failures for one signature.
    capped = []
    for D in (2, 4, 8):
        for L in (0, 1, 2, 3):
            for trial in range(50):
                table = {(s, w): rng.random() < 0.5 for s in (0, 1) for w in range(D)}
                mi = capped_mi(D, L, lambda s, w: table[(s, w)])
                result["cases"] += 1
                capped.append(mi)
                if mi > math.log2(L + 1) + TOL:
                    result["violations"].append({"case": f"capped D={D} L={L} t={trial}", "mi": mi})
            mi = capped_mi(D, L, lambda s, w: (w & 1) == s)
            capped.append(mi)
            result["cases"] += 1
            if mi > math.log2(L + 1) + TOL:
                result["violations"].append({"case": f"capped parity D={D} L={L}", "mi": mi})

    result["max_observed_kl_per_expected_failure"] = max_ratio
    result["limit_1_over_ln2"] = 1 / LN2
    result["max_capped_mi"] = max(capped)
    ok = not result["violations"] and all(c["pass"] for c in result["controls"].values())
    result["verdict"] = "PASS" if ok else "FAIL"
    out = ROOT / "result.json"
    out.write_text(json.dumps(result, indent=1) + "\n")
    print(result["verdict"], "cases", result["cases"], "violations", len(result["violations"]))
    print("controls", {k: v["pass"] for k, v in result["controls"].items()})
    print("C1", result["controls"]["C1_naive_bound_violated"])
    print("max ratio", max_ratio, "limit", 1 / LN2, "max capped mi", result["max_capped_mi"])


if __name__ == "__main__":
    main()
