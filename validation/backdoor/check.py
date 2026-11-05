#!/usr/bin/env python3
"""Measured leakage from simulated backdoored signers.

Run:
    systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 \
        python3 -B -I validation/backdoor/check.py
Small sample sizes, for trying it out (writes .work/backdoor/smoke_result.json):
    ... check.py --smoke

Verdicts are computed here from the numeric predictions coded below. A missed
prediction is reported as FINDING. Standard library only. Simulated signers and labelled test keys only.
"""

import argparse
import hashlib
import json
import math
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import signers as SG  # noqa: E402  (loads and hash-checks reference)

ROOT = SG.ROOT
REF = SG.REF
fmul, N = SG.fmul, SG.N

# Sample sizes. Protocol-fixed numbers (S, trials, L, b, inputs) are not here.
FULL = {
    "c1": 100,        # signatures per scheme
    "c2_trials": 20,  # trials of 32 signatures (256 bits) per scheme
    "a1": 1280,       # signatures per scheme (also the A4 sample)
    "a2": 1280,       # signatures per scheme (also the A4 sample)
    "a3": 100,        # signatures per variant per scheme
    "a5": 500,        # accepted signatures per b per scheme
    "a6": 100,        # exchanges per scheme
    "a7_hv_trials": 200,  # of the 200 trials per L, how many send every accepted signature through host_verify
    "a8": 400,        # accepted messages per scheme
    "a9": 300,        # accepted 4-input requests per scheme
    "a10": 100,
    "a11": 100,
    "a12": 100,
    "a13": 100,
}
SMOKE = {
    "c1": 6, "c2_trials": 2, "a1": 40, "a2": 40, "a3": 6, "a5": 12, "a6": 5,
    "a7_hv_trials": 2, "a8": 12, "a9": 6, "a10": 5, "a11": 5, "a12": 4, "a13": 4,
}
# Protocol-fixed.
A7_S, A7_TRIALS, A7_LS = 64, 200, (0, 1, 3, 8)
A5_BS = (1, 2, 4)
A9_INPUTS = 4
ALPHA_CHI2 = 1e-4
SMOKE_A7_TRIALS = 6  # smoke only: A7 trial count is protocol-fixed in a real run


def sha256_file(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# statistics
# ---------------------------------------------------------------------------

def mean_se(values):
    n = len(values)
    mean = sum(values) / n
    if n < 2:
        return mean, float("inf")
    var = sum((v - mean) ** 2 for v in values) / (n - 1)
    return mean, math.sqrt(var / n)


def bit_accuracy(correct, total):
    acc = correct / total
    se = math.sqrt(0.25 / total)
    return acc, se, abs(acc - 0.5) <= 4 * se


def gamma_q(a, x):
    """Regularized upper incomplete gamma function Q(a, x)."""
    if x <= 0:
        return 1.0
    lg = math.lgamma(a)
    if x < a + 1:
        term = total = 1.0 / a
        ap = a
        for _ in range(10000):
            ap += 1
            term *= x / ap
            total += term
            if abs(term) < abs(total) * 1e-16:
                break
        return max(0.0, 1.0 - total * math.exp(-x + a * math.log(x) - lg))
    tiny = 1e-300
    b = x + 1 - a
    c = 1 / tiny
    d = 1 / b
    h = d
    for i in range(1, 10000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = tiny if abs(d) < tiny else d
        c = b + an / c
        c = tiny if abs(c) < tiny else c
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-16:
            break
    return math.exp(-x + a * math.log(x) - lg) * h


def chi2_uniform_byte(values):
    counts = [0] * 256
    for v in values:
        counts[v] += 1
    expected = len(values) / 256
    stat = sum((c - expected) ** 2 / expected for c in counts)
    return stat, gamma_q(255 / 2, stat / 2)


def popcount(x):
    return bin(x).count("1")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class Ctx:
    def __init__(self, run, smoke, sizes):
        self.run, self.smoke, self.n = run, smoke, sizes
        self.root = SG.Drbg(("bd/smoke/run%d" if smoke else "bd/run%d") % run)
        self.lowbytes = {}

    def drbg(self, case, scheme):
        return self.root.sub("%s/%s" % (case, scheme.name))

    def key(self, case, scheme):
        return scheme.keypair("%s/%s" % (case, scheme.name))

    def shared_k(self, case, scheme):
        return SG.sha(b"bd/shared-K/" + ("%s/%s" % (case, scheme.name)).encode())


def plain_verify(scheme, pk, m, sig):
    """Ordinary signature verification, no anti-exfil check."""
    if scheme.name == "bip340":
        return bool(REF._schnorr_verify(pk, m, sig))
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (0 < r < N and 0 < s < N):
        return False
    P = REF._parse33(pk)
    z = int.from_bytes(m, "big") % N
    si = pow(s, -1, N)
    V = REF._add(fmul(z * si % N), REF._mul(r * si % N, P))
    return V is not None and V[0] % N == r


def exchange(dev, sc, key, m, rho, idx):
    """One full exchange. Returns (R0b, sig, host_accepts) or None on refusal."""
    hc = sc.host_commit(rho)
    R0b = dev.commit(m, hc, idx)
    if R0b is None:
        return None
    sig = dev.sign(m, rho, idx)
    if sig is None:
        return None
    return R0b, sig, bool(sc.host_verify(key.pk, m, rho, R0b, sig))


def result(case, scheme, ok, summary, detail, secs):
    verdict = "PASS" if ok else "FINDING"
    name = scheme if isinstance(scheme, str) else scheme.name
    line = "%-3s %-6s %-7s %s [%.1fs]" % (case, name, verdict, summary, secs)
    return {"case": case, "scheme": name, "verdict": verdict, "line": line, "detail": detail}


# ---------------------------------------------------------------------------
# controls
# ---------------------------------------------------------------------------

def case_c1(ctx, sc):
    t0 = time.time()
    n = ctx.n["c1"]
    dr, key, K = ctx.drbg("C1", sc), ctx.key("C1", sc), ctx.shared_k("C1", sc)
    dev = SG.PlainDevice(sc, key, K)
    rec = valid = 0
    for _ in range(n):
        m = dr.read(32)
        sig = dev.known_nonce_sign(m)
        valid += plain_verify(sc, key.pk, m, sig)
        rec += SG.observer_plain_known_nonce(sc, key.pk, m, sig, K) is not None
    ok = rec == n and valid == n
    return result("C1", sc, ok, "key recovered from 1 signature %d/%d (valid sigs %d/%d), predicted 100%%"
                  % (rec, n, valid, n), {"N": n, "recovered": rec, "valid": valid}, time.time() - t0)


def case_c2(ctx, sc):
    t0 = time.time()
    trials = ctx.n["c2_trials"]
    dr, key, K = ctx.drbg("C2", sc), ctx.key("C2", sc), ctx.shared_k("C2", sc)
    bits_ok = bits = valid = sigs = 0
    for t in range(trials):
        # a fresh stream per trial: 32 signatures carry 32 bytes = 256 bits
        stream = SG.Stream(SG.sha(key.sk + t.to_bytes(8, "big")))
        dev = SG.PlainDevice(sc, key, K, stream)
        for j in range(32):
            m = dr.read(32)
            sig = dev.grinding_sign(m, j)
            sigs += 1
            valid += plain_verify(sc, key.pk, m, sig)
            got = sc.r_int(sig) & 255
            bits_ok += 8 - popcount(got ^ stream.byte(j))
            bits += 8
    ok = bits_ok == bits and valid == sigs
    return result("C2", sc, ok, "decoded bits %d/%d in %d trials of 32 signatures (valid sigs %d/%d), predicted 100%%"
                  % (bits_ok, bits, trials, valid, sigs),
                  {"trials": trials, "bits": bits, "bits_correct": bits_ok, "valid": valid}, time.time() - t0)


# ---------------------------------------------------------------------------
# anti-exfil, conforming host
# ---------------------------------------------------------------------------

def case_a1(ctx, sc):
    t0 = time.time()
    n = ctx.n["a1"]
    dr, key, K = ctx.drbg("A1", sc), ctx.key("A1", sc), ctx.shared_k("A1", sc)
    dev = SG.KnownK0Device(sc, key, K=K)
    acc = rec_blind = rec_hc = 0
    low = []
    for i in range(n):
        m, rho = dr.read(32), dr.read(32)
        out = exchange(dev, sc, key, m, rho, i)
        R0b, sig, ok = out
        acc += ok
        low.append(sc.r_int(sig) & 255)
        # published observer: does not know hc, so assumes a zero hc (naive) ...
        rec_blind += SG.observer_known_k0(sc, key.pk, m, sig, K, bytes(32)) is not None
        # ... and an oracle-strengthened observer that is given the true hc
        rec_hc += SG.observer_known_k0(sc, key.pk, m, sig, K, sc.host_commit(rho)) is not None
    ctx.lowbytes[("A1", sc.name)] = low
    ok = acc == n and rec_blind == 0 and rec_hc == 0
    return result("A1", sc, ok, "host accepts %d/%d (predicted 100%%); keys recovered %d/%d, with true hc given %d/%d (predicted 0)"
                  % (acc, n, rec_blind, n, rec_hc, n),
                  {"N": n, "accepted": acc, "recovered_unknown_hc": rec_blind, "recovered_hc_given": rec_hc},
                  time.time() - t0)


def case_a2(ctx, sc):
    t0 = time.time()
    n = ctx.n["a2"]
    dr, key = ctx.drbg("A2", sc), ctx.key("A2", sc)
    dev = SG.GroundR0Device(sc, key)
    acc = pub_ok = ex_ok = 0
    low = []
    for i in range(n):
        m, rho = dr.read(32), dr.read(32)
        R0b, sig, ok = exchange(dev, sc, key, m, rho, i)
        acc += ok
        want = dev.stream.byte(i)
        got = sc.r_int(sig) & 255
        low.append(got)
        pub_ok += 8 - popcount(got ^ want)
        ex_ok += R0b[-1] == want
    ctx.lowbytes[("A2", sc.name)] = low
    acc_rate, se, inside = bit_accuracy(pub_ok, 8 * n)
    ok = acc == n and inside and ex_ok == n
    return result("A2", sc, ok, "host accepts %d/%d; published bit accuracy %.4f (window 0.5+/-%.4f); exchange decode %d/%d"
                  % (acc, n, acc_rate, 4 * se, ex_ok, n),
                  {"N": n, "accepted": acc, "published_bits": 8 * n, "published_correct": pub_ok,
                   "published_accuracy": acc_rate, "published_se": se, "exchange_decoded": ex_ok},
                  time.time() - t0)


def case_a3(ctx, sc):
    t0 = time.time()
    n = ctx.n["a3"]
    dr, key = ctx.drbg("A3", sc), ctx.key("A3", sc)
    variants = [v for v in SG.UnboundDevice.VARIANTS if v != "high_s" or sc.name == "ecdsa"]
    det = {}
    ctrl = SG.Device(sc, key)
    # control: the same loop with the honest derivation must be accepted
    c_acc = 0
    for i in range(n):
        m, rho = dr.read(32), dr.read(32)
        c_acc += exchange(ctrl, sc, key, m, rho, i)[2]
    det["honest_control_accepted"] = c_acc
    bad = []
    for v in variants:
        dev = SG.UnboundDevice(sc, key, v)
        acc = plain = 0
        for i in range(n):
            m, rho = dr.read(32), dr.read(32)
            R0b, sig, ok = exchange(dev, sc, key, m, rho, i)
            acc += ok
            plain += plain_verify(sc, key.pk, m, sig)
        det[v] = {"host_accepted": acc, "ordinary_valid": plain}
        if acc != 0 or plain != n:
            bad.append(v)
    ok = c_acc == n and not bad
    parts = ", ".join("%s %d/%d" % (v, det[v]["host_accepted"], n) for v in variants)
    return result("A3", sc, ok, "host accepts: %s (predicted 0); honest control %d/%d; ordinary-valid sigs checked"
                  % (parts, c_acc, n), {"N_per_variant": n, "detail": det}, time.time() - t0)


def case_a4(ctx, sc):
    t0 = time.time()
    det, ok, parts = {}, True, []
    for case in ("A1", "A2"):
        low = ctx.lowbytes[(case, sc.name)]
        stat, p = chi2_uniform_byte(low)
        det[case] = {"n": len(low), "chi2": stat, "p": p}
        ok = ok and p > ALPHA_CHI2
        parts.append("%s n=%d chi2=%.1f p=%.3g" % (case, len(low), stat, p))
    note = " (smoke sample: chi-square not meaningful)" if ctx.smoke else ""
    return result("A4", sc, ok, "; ".join(parts) + ", predicted p > 1e-4" + note, det, time.time() - t0)


# ---------------------------------------------------------------------------
# selective refusal
# ---------------------------------------------------------------------------

def case_a5(ctx, sc):
    t0 = time.time()
    n = ctx.n["a5"]
    dr, key = ctx.drbg("A5", sc), ctx.key("A5", sc)
    ok_all, parts, det = True, [], {}
    for b in A5_BS:
        dev = SG.RefuseOnRDevice(sc, key, bits_per_sig=b)
        cap = 200 * (1 << b)
        refusals, decoded, hv_ok, capped = [], 0, 0, 0
        for i in range(n):
            m = dr.read(32)
            k = 0
            while True:
                rho = dr.read(32)
                hc = sc.host_commit(rho)
                R0b = dev.commit(m, hc, i)
                sig = dev.sign(m, rho, i)
                if sig is not None:
                    break
                k += 1
                if k > cap:
                    capped += 1
                    break
            refusals.append(k)
            if sig is None:
                continue
            hv_ok += bool(sc.host_verify(key.pk, m, rho, R0b, sig))
            decoded += (sc.r_int(sig) & ((1 << b) - 1)) == dev.stream.bits(i * b, b)
        mean, se = mean_se(refusals)
        pred = (1 << b) - 1
        inside = abs(mean - pred) <= 4 * se
        sub = decoded == n and hv_ok == n and capped == 0 and inside
        ok_all = ok_all and sub
        parts.append("b=%d decoded %d/%d accepted %d/%d refusals/accepted %.2f+/-%.2f (window %d+/-%.2f)"
                     % (b, decoded, n, hv_ok, n, mean, se, pred, 4 * se))
        det[str(b)] = {"N": n, "decoded": decoded, "host_accepted": hv_ok, "capped": capped,
                       "mean_refusals": mean, "se": se, "predicted": pred, "in_window": inside}
    return result("A5", sc, ok_all, "; ".join(parts), det, time.time() - t0)


def case_a6(ctx, sc):
    t0 = time.time()
    n = ctx.n["a6"]
    dr, key = ctx.drbg("A6", sc), ctx.key("A6", sc)
    same_r0 = same_sig = acc = 0
    rule_rejects = hv_orig_rejects = hv_new_accepts = 0
    for _ in range(n):
        m, rho = dr.read(32), dr.read(32)
        hc = sc.host_commit(rho)
        dev = SG.Device(sc, key)
        R0 = dev.commit(m, hc)
        sig1 = dev.sign(m, rho)
        # retry of step 2 and of steps 3 and 4 with the same inputs
        same_r0 += dev.commit(m, hc) == R0
        sig2 = dev.sign(m, rho)
        same_sig += sig1 == sig2
        acc += bool(sc.host_verify(key.pk, m, rho, R0, sig2))
        # a resampling device, retried with the same rho
        rs = SG.ResamplingDevice(sc, key)
        R0_stored = rs.commit(m, hc)
        rs.sign(m, rho)
        rs.retry()
        R0_new = rs.commit(m, hc)
        sig_new = rs.sign(m, rho)
        rule_rejects += R0_new != R0_stored        # the retained-R0 rule in the spec's Failure handling
        hv_orig_rejects += not sc.host_verify(key.pk, m, rho, R0_stored, sig_new)
        hv_new_accepts += bool(sc.host_verify(key.pk, m, rho, R0_new, sig_new))
    ok = (same_r0 == n and same_sig == n and acc == n and rule_rejects == n and hv_orig_rejects == n)
    return result("A6", sc, ok,
                  "same-rho retry gives same R0 %d/%d and same sig %d/%d (host accepts %d/%d); changed R0 rejected by stored-R0 rule %d/%d, "
                  "by host_verify against stored R0 %d/%d (host_verify alone would accept the new pair %d/%d)"
                  % (same_r0, n, same_sig, n, acc, n, rule_rejects, n, hv_orig_rejects, n, hv_new_accepts, n),
                  {"N": n, "same_r0": same_r0, "same_sig": same_sig, "accepted": acc, "rule_rejects": rule_rejects,
                   "host_verify_stored_r0_rejects": hv_orig_rejects, "host_verify_new_r0_accepts": hv_new_accepts},
                  time.time() - t0)


def case_a7(ctx, sc):
    t0 = time.time()
    trials = SMOKE_A7_TRIALS if ctx.smoke else A7_TRIALS
    hv_trials = min(ctx.n["a7_hv_trials"], trials)
    dr, key = ctx.drbg("A7", sc), ctx.key("A7", sc)
    stream = SG.Stream(key.sk)
    ok_all, parts, det = True, [], {}
    for L in A7_LS:
        excess, spent, hv_n, hv_bad, over_budget = [], [], 0, 0, 0
        for t in range(trials):
            dev = SG.RefuseOnRDevice(sc, key, bits_per_sig=1, budget=L, stream=stream)
            correct = 0
            for i in range(A7_S):
                idx = t * A7_S + i
                m = dr.read(32)
                while True:
                    rho = dr.read(32)          # fresh rho for every attempt
                    hc = sc.host_commit(rho)
                    R0b = dev.commit(m, hc, idx)
                    sig = dev.sign(m, rho, idx)
                    if sig is not None:
                        break
                if t < hv_trials:
                    hv_n += 1
                    hv_bad += not sc.host_verify(key.pk, m, rho, R0b, sig)
                correct += (sc.r_int(sig) & 1) == stream.bit(idx)
            excess.append(correct - A7_S / 2)
            spent.append(dev.refusals)
            over_budget += dev.refusals > L
        mean, se = mean_se(excess)
        if L == 0:
            sub = abs(mean) <= 4 * se
            window = "|excess| <= %.3f" % (4 * se)
        else:
            lo = L / 2 - 4 * se
            sub = lo <= mean <= L + 4 * se
            window = "[%.3f, %.3f]" % (lo, L + 4 * se)
        sub = sub and hv_bad == 0 and over_budget == 0
        ok_all = ok_all and sub
        parts.append("L=%d excess %.3f+/-%.3f need %s%s" % (L, mean, se, window, "" if sub else " MISS"))
        det[str(L)] = {"trials": trials, "mean_excess": mean, "se": se, "mean_refusals": sum(spent) / len(spent),
                       "pass": sub, "host_checked": hv_n, "host_rejected": hv_bad,
                       "in_window_around_L_over_2": abs(mean - L / 2) <= 4 * se,
                       "mean_excess_le_L_plus_4se": mean <= L + 4 * se, "over_budget_trials": over_budget}
    return result("A7", sc, ok_all, "S=64 trials=%d host-checked trials/L=%d: %s" % (trials, hv_trials, "; ".join(parts)),
                  det, time.time() - t0)


def case_a8(ctx, sc):
    t0 = time.time()
    n = ctx.n["a8"]
    dr, key, K = ctx.drbg("A8", sc), ctx.key("A8", sc), ctx.shared_k("A8", sc)
    dev = SG.MessageSelectDevice(sc, key, K=K)
    decoded = hv_ok = refusals = 0
    for i in range(n):
        while True:
            m = dr.read(32)                    # the host moves to a new message after each refusal
            rho = dr.read(32)
            out = exchange(dev, sc, key, m, rho, i)
            if out is not None:
                break
            refusals += 1
        hv_ok += out[2]
        decoded += (SG.sha(b"bd/msg-select" + K + m)[0] & 1) == dev.stream.bit(i)   # observer knowing K
    ok = decoded == n and hv_ok == n
    return result("A8", sc, ok, "accepted messages decoded %d/%d (predicted 100%%), host accepts %d/%d, mean refusals %.2f"
                  % (decoded, n, hv_ok, n, refusals / n),
                  {"N": n, "decoded": decoded, "accepted": hv_ok, "mean_refusals": refusals / n}, time.time() - t0)


def case_a9(ctx, sc):
    t0 = time.time()
    n = ctx.n["a9"]
    dr, key = ctx.drbg("A9", sc), ctx.key("A9", sc)
    dev = SG.RefuseOnRDevice(sc, key, bits_per_sig=1)
    refusals, decoded, hv_ok, capped = [], 0, 0, 0
    for i in range(n):
        ms = [dr.read(32) for _ in range(A9_INPUTS)]
        k = 0
        while True:
            rhos = [dr.read(32) for _ in range(A9_INPUTS)]   # fresh rho per input per attempt
            ds = [dev.derive(ms[j], rhos[j], i * A9_INPUTS + j) for j in range(A9_INPUTS)]
            if all(dev.wants(ds[j], i * A9_INPUTS + j) for j in range(A9_INPUTS)):
                break
            k += 1                                           # whole request refused, all inputs fail
            if k > 20000:
                capped += 1
                break
        refusals.append(k)
        if k > 20000:
            continue
        for j in range(A9_INPUTS):
            idx = i * A9_INPUTS + j
            hc = sc.host_commit(rhos[j])
            R0b = dev.commit(ms[j], hc, idx)
            hv_ok += bool(sc.host_verify(key.pk, ms[j], rhos[j], R0b, ds[j].sig)) and R0b == ds[j].R0b
            decoded += (sc.r_int(ds[j].sig) & 1) == dev.stream.bit(idx)
    mean, se = mean_se(refusals)
    inside = abs(mean - 15) <= 4 * se
    total = n * A9_INPUTS
    ok = decoded == total and hv_ok == total and capped == 0 and inside
    return result("A9", sc, ok, "4 inputs: decoded %d/%d, host accepts %d/%d, refusals/accepted request %.2f+/-%.2f (window 15+/-%.2f)"
                  % (decoded, total, hv_ok, total, mean, se, 4 * se),
                  {"N_requests": n, "decoded": decoded, "accepted": hv_ok, "capped": capped,
                   "mean_refusals": mean, "se": se, "in_window": inside}, time.time() - t0)


# ---------------------------------------------------------------------------
# documented limits
# ---------------------------------------------------------------------------

def case_a10(ctx, sc):
    t0 = time.time()
    n = ctx.n["a10"]
    dr, key, K = ctx.drbg("A10", sc), ctx.key("A10", sc), ctx.shared_k("A10", sc)
    dev = SG.KnownK0Device(sc, key, K=K)
    rec = acc = 0
    for i in range(n):
        m, rho = dr.read(32), dr.read(32)
        R0b, sig, ok = exchange(dev, sc, key, m, rho, i)
        acc += ok
        rec += SG.observer_with_rho(sc, key.pk, m, sig, K, rho) is not None
    ok = rec == n and acc == n
    return result("A10", sc, ok, "observer who learns rho recovers key from 1 signature %d/%d (predicted 100%%), host accepts %d/%d"
                  % (rec, n, acc, n), {"N": n, "recovered": rec, "accepted": acc}, time.time() - t0)


def case_a11(ctx, sc):
    t0 = time.time()
    n = ctx.n["a11"]
    dr, key, K = ctx.drbg("A11", sc), ctx.key("A11", sc), ctx.shared_k("A11", sc)
    dev = SG.KnownK0NoHcDevice(sc, key, K=K)
    rec = acc = 0
    for i in range(n):
        m, rho = dr.read(32), dr.read(32)
        R0b, sig, ok = exchange(dev, sc, key, m, rho, i)
        acc += ok
        t = sc.tweak(R0b, rho)                  # all the observer learns of rho
        rec += SG.observer_with_t(sc, key.pk, m, sig, K, t) is not None
    ok = rec == n and acc == n
    return result("A11", sc, ok, "observer who learns only t recovers key from 1 signature %d/%d (predicted 100%%), host accepts %d/%d"
                  % (rec, n, acc, n), {"N": n, "recovered": rec, "accepted": acc}, time.time() - t0)


def _known_rho_case(ctx, sc, case, known, rho_for, n):
    t0 = time.time()
    dr, key = ctx.drbg(case, sc), ctx.key(case, sc)
    dev = SG.KnownRhoDevice(sc, key, known)
    decoded = acc = 0
    for i in range(n):
        m, rho = dr.read(32), rho_for(dr)
        R0b, sig, ok = exchange(dev, sc, key, m, rho, i)
        acc += ok
        decoded += (sc.r_int(sig) & 255) == dev.stream.byte(i)
    return decoded, acc, time.time() - t0


def case_a12(ctx, sc):
    t0 = time.time()
    n = ctx.n["a12"]
    known = {}
    for v in range(1 << 16):                     # the device's brute force over all 16-bit rho
        rho = bytes(30) + v.to_bytes(2, "big")
        known[sc.host_commit(rho)] = rho
    t_bf = time.time() - t0
    decoded, acc, _ = _known_rho_case(ctx, sc, "A12", known, lambda dr: bytes(30) + dr.read(2), n)
    ok = decoded == n and acc == n
    return result("A12", sc, ok, "16-bit rho: low byte of r decoded %d/%d (predicted 100%%), host accepts %d/%d, table build %.1fs"
                  % (decoded, n, acc, n, t_bf), {"N": n, "decoded": decoded, "accepted": acc, "table_seconds": t_bf},
                  time.time() - t0)


def case_a13(ctx, sc):
    t0 = time.time()
    n = ctx.n["a13"]
    seen_dr = ctx.drbg("A13-seen", sc)
    seen = [seen_dr.read(32) for _ in range(8)]
    known = {sc.host_commit(r): r for r in seen}
    decoded, acc, _ = _known_rho_case(ctx, sc, "A13", known, lambda dr: seen[dr.below(len(seen))], n)
    ok = decoded == n and acc == n
    return result("A13", sc, ok, "reused rho (8 seen): low byte of r decoded %d/%d (predicted 100%%), host accepts %d/%d"
                  % (decoded, n, acc, n), {"N": n, "decoded": decoded, "accepted": acc}, time.time() - t0)


CASES = [
    ("C1", case_c1), ("C2", case_c2), ("A1", case_a1), ("A2", case_a2), ("A3", case_a3), ("A4", case_a4),
    ("A5", case_a5), ("A6", case_a6), ("A7", case_a7), ("A8", case_a8), ("A9", case_a9),
    ("A10", case_a10), ("A11", case_a11), ("A12", case_a12), ("A13", case_a13),
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", dest="run", type=int, default=1, help="part of the seed label (default 1)")
    ap.add_argument("--smoke", action="store_true", help="small sample sizes; output .work/backdoor/smoke_result.json")
    ap.add_argument("--only", default="", help="comma list of case ids (smoke debugging only)")
    args = ap.parse_args(argv)

    if args.only and not args.smoke:
        ap.error("--only is for --smoke")
    if args.smoke:
        outdir = ROOT / ".work" / "backdoor"
        outpath = outdir / "smoke_result.json"
    else:
        outdir = ROOT / ".work" / "backdoor"
        outpath = outdir / "result.json"
    outdir.mkdir(parents=True, exist_ok=True)

    sizes = SMOKE if args.smoke else FULL
    ctx = Ctx(args.run, args.smoke, sizes)
    started = time.time()
    SG.selftest()
    print("backdoor harness%s. reference sha256 %s" % (" (SMOKE, small samples)" if args.smoke else "", SG.REF_SHA256))
    print("SELF honest simulated device matches reference commit/sign, fixed-base table matches reference multiplication")
    wanted = set(x for x in args.only.split(",") if x)
    results = []
    for cid, fn in CASES:
        if wanted and cid not in wanted:
            continue
        for sc in SG.SCHEMES:
            try:
                res = fn(ctx, sc)
            except Exception as exc:  # a harness error is not a prediction miss; stop loudly
                print("ERROR %s %s: %s: %s" % (cid, sc.name, type(exc).__name__, exc))
                raise
            print(res["line"], flush=True)
            results.append(res)
    missed = [r for r in results if r["verdict"] != "PASS"]
    if missed:
        overall = "OVERALL: FINDINGS %d of %d lines missed a prediction: %s" % (
            len(missed), len(results), ", ".join("%s/%s" % (r["case"], r["scheme"]) for r in missed))
    else:
        overall = "OVERALL: PASS %d of %d lines met their predictions" % (len(results), len(results))
    if args.smoke:
        overall += " (SMOKE: sample sizes too small to count)"
    elapsed = time.time() - started
    print(overall)
    print("elapsed %.1fs" % elapsed)
    doc = {
        "protocol": "backdoor harness", "run": args.run, "smoke": args.smoke,
        "seed_label": ("bd/smoke/run%d" if args.smoke else "bd/run%d") % args.run,
        "reference_sha256": SG.REF_SHA256, "signers_sha256": sha256_file(HERE / "signers.py"),
        "checker_sha256": sha256_file(__file__),
        "python": sys.version.split()[0], "sample_sizes": sizes,
        "fixed": {"A7_S": A7_S, "A7_trials": A7_TRIALS if not args.smoke else SMOKE_A7_TRIALS, "A7_L": A7_LS,
                  "A5_b": A5_BS, "A9_inputs": A9_INPUTS, "chi2_alpha": ALPHA_CHI2},
        "cases": results, "overall": overall, "elapsed_seconds": elapsed,
    }
    with open(outpath, "x", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote %s" % outpath)
    return 0 if not missed else 1


if __name__ == "__main__":
    raise SystemExit(main())
