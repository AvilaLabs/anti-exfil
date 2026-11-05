#!/usr/bin/env python3
"""Cases the grid of check.py could not see. Writes result_b.json."""
import itertools
import json
import math
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parent
TOL = 1e-9
LN2 = math.log(2)


def mi(laws):
    """I(S; X) for uniform S over a list of laws."""
    total = 0.0
    n = len(laws)
    for x in set().union(*laws):
        m = sum(l.get(x, 0.0) for l in laws) / n
        for l in laws:
            p = l.get(x, 0.0)
            if p > 0:
                total += p * math.log2(p / m) / n
    return total


def kl_uniform(law, size):
    return sum(p * (math.log2(p) + math.log2(size)) for p in law.values() if p > 0)


def capped_law(D, L, accept):
    """One signature. The host stops after L failures and publishes nothing.

    accept(rejected_tuple, w) may use earlier rejected values, which the
    observer never sees. Returns the law over {w} and the symbol None.
    """
    law = {}
    def walk(rejected, p):
        for w in range(D):
            q = p / D
            a = accept(rejected, w)
            if a > 0:
                law[w] = law.get(w, 0.0) + q * a
            if a < 1:
                if len(rejected) == L:
                    law[None] = law.get(None, 0.0) + q * (1 - a)
                else:
                    walk(rejected + (w,), q * (1 - a))
    walk((), 1.0)
    return law


def hidden_state_law(D, J, accept):
    """Accepted value law with at most J attempts, the last one forced."""
    law = {}
    ej = 0.0
    def walk(rejected, p):
        nonlocal ej
        ej += p  # reaching this attempt counts one attempt
        for w in range(D):
            q = p / D
            a = 1.0 if len(rejected) == J - 1 else accept(rejected, w)
            if a > 0:
                law[w] = law.get(w, 0.0) + q * a
            if a < 1:
                walk(rejected + (w,), q * (1 - a))
    walk((), 1.0)
    return law, ej


def main():
    rng = random.Random(622)
    res = {"violations": []}

    # H1: capped with visible no-signature outcome. Bound log2(L + 2).
    worst = 0.0
    cases = 0
    for D in (2, 4):
        for L in (0, 1, 2, 3):
            if D == 4 and L == 3:
                continue
            for trial in range(100):
                tables = [{} for _ in range(2)]
                def rule(t):
                    def accept(rej, w):
                        k = (rej, w)
                        if k not in t:
                            t[k] = rng.choice([0.0, 1.0, 0.5, rng.random()])
                        return t[k]
                    return accept
                laws = [capped_law(D, L, rule(t)) for t in tables]
                v = mi(laws)
                worst = max(worst, v / math.log2(L + 2))
                cases += 1
                if v > math.log2(L + 2) + TOL:
                    res["violations"].append({"case": "H1", "D": D, "L": L, "mi": v})
    # H1 control: L = 0, device refuses or not by its secret: one full bit, above log2(L + 1) = 0.
    l0 = [capped_law(2, 0, lambda r, w: 1.0), capped_law(2, 0, lambda r, w: 0.0)]
    res["H1_cases"] = cases
    res["H1_worst_fraction_of_bound"] = worst
    res["C_H1_L0_one_bit"] = {"pass": abs(mi(l0) - 1) < TOL, "mi": mi(l0)}

    # H2: hidden state. Acceptance depends on rejected values. KL <= log2 E[attempts].
    hs = 0
    worst = 0.0
    for D, J in ((2, 4), (4, 3), (8, 2), (3, 4)):
        for trial in range(300):
            t = {}
            def accept(rej, w):
                k = (rej, w)
                if k not in t:
                    t[k] = rng.choice([0.0, 1.0, 0.25, 0.75, rng.random()])
                return t[k]
            law, ej = hidden_state_law(D, J, accept)
            kl = kl_uniform(law, D)
            hs += 1
            if ej > 1:
                worst = max(worst, kl / math.log2(ej))
            if kl > math.log2(ej) + TOL or kl > (ej - 1) / LN2 + TOL:
                res["violations"].append({"case": "H2", "D": D, "J": J, "kl": kl, "ej": ej})
    res["H2_cases"] = hs
    res["H2_worst_fraction_of_log2_EJ"] = worst

    # H3: tightness for mutual information. M secrets, each rejects its own small cell.
    res["H3_mi_per_expected_failure"] = {}
    for M in (2, 4, 16, 64, 256):
        D = M
        laws = []
        for s in range(M):
            law = {w: 1.0 / (D - 1) for w in range(D) if w != s}
            laws.append(law)
        ef = 1.0 / ((D - 1) / D) - 1.0
        res["H3_mi_per_expected_failure"][str(M)] = mi(laws) / ef
    top = res["H3_mi_per_expected_failure"]["256"]
    res["C_H3_near_limit"] = {"pass": 1.43 < top <= 1 / LN2 + TOL, "value": top, "limit": 1 / LN2}

    # H4: two signatures in one request. Accept when W1 xor W2 has parity S.
    # Published tuple law. Per-signature chain with f_1 and f_2 counted separately gives
    # f_2 = 0 yet W2 given W1 carries the bit; the request-level bound holds.
    laws = []
    for s in (0, 1):
        pairs = [(a, b) for a in (0, 1) for b in (0, 1) if (a ^ b) == s]
        laws.append({p: 1.0 / len(pairs) for p in pairs})
    joint = mi(laws)
    marg1 = mi([{a: sum(p for k, p in l.items() if k[0] == a) for a in (0, 1)} for l in laws])
    marg2 = mi([{b: sum(p for k, p in l.items() if k[1] == b) for b in (0, 1)} for l in laws])
    ef_request = 1.0
    res["H4"] = {"joint_mi": joint, "marginal_1": marg1, "marginal_2": marg2, "expected_failed_requests": ef_request}
    res["C_H4_needs_request_level"] = {"pass": abs(joint - 1) < TOL and marg1 < TOL and marg2 < TOL and joint <= ef_request / LN2 + TOL}

    # H5: the bound does NOT cover failure-dependent messages. A device with N transactions
    # fails once at an index chosen by its secret, and the wallet bumps the fee from then on.
    # The observer reads the index from the fees. Reported to show the condition is needed.
    N = 1 << 20
    bits = math.log2(N)
    res["H5"] = {"transactions": N, "bits_through_fee_bump": bits, "failures": 1, "bound_if_it_applied": 1 / LN2}
    res["C_H5_condition_needed"] = {"pass": bits > 1 / LN2}

    ok = not res["violations"] and all(v["pass"] for k, v in res.items() if k.startswith("C_"))
    res["verdict"] = "PASS" if ok else "FAIL"
    (ROOT / "result_b.json").write_text(json.dumps(res, indent=1) + "\n")
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
