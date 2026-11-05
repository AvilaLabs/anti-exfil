"""Part 1 driver of the related-key checks. Usage: check.py [--smoke]

Part 1 (E1 to E6 and the five controls) is checked against
proof/related_key/related_key_theorem.md, by exact enumeration on small prime-order groups
y^2 = x^3 + 7 over F_p (the toy curves of the isolated-key check, imported from proof/isolated_key/checks/toy_law.py).

Writes .work/related_key/result.json (smoke runs: result_smoke.json), prints one line per item.
Standard library only. Exact arithmetic is integer or Fraction throughout.
"""
import argparse
import json
import os
import random
import sys
import time
from collections import Counter
from fractions import Fraction
from itertools import product

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "isolated_key", "checks")))
import toy_law as TL  # noqa: E402

INF = None
SCHEMES = ("bip340", "ecdsa")

PLANS = {
    "full": dict(
        e1=dict(curves=[13, 43, 79, 97], nd=2, brute_curves=[13]),
        e2=dict(curves=[13, 43, 79, 97], nkeys=3, nz=3, netab=1, joint_curves={13: 6, 43: 1}),
        e3=dict(curves=[13, 43, 79, 97, 67, 61, 127], pairs_curves=[13, 43]),
        e4=dict(curves=[13, 43, 79, 97], nfam=3),
        e5=dict(full=[13, 43], sampled=[97], nsamp=6),
        e6=dict(curves=[13, 43, 79], nd=2, brute_curves=[13]),
        e7=dict(curves=[13, 43, 79, 97], nd_sig=3, nd_transfer=4),
        e8=dict(curves=[13, 43, 79, 97]),
    ),
    "smoke": dict(
        e1=dict(curves=[13, 43], nd=1, brute_curves=[13]),
        e2=dict(curves=[13, 43], nkeys=2, nz=2, netab=1, joint_curves={13: 2}),
        e3=dict(curves=[13, 43, 61], pairs_curves=[13]),
        e4=dict(curves=[13, 43], nfam=1),
        e5=dict(full=[13], sampled=[43], nsamp=4),
        e6=dict(curves=[13, 43], nd=1, brute_curves=[13]),
        e7=dict(curves=[13, 43], nd_sig=2, nd_transfer=2),
        e8=dict(curves=[13, 43]),
    ),
}


def jdefault(o):
    if isinstance(o, Fraction):
        return str(o)
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    return str(o)


# ------------------------------------------------------------------ derivations

def dphi(n, d, phi, ign=False):
    """d_phi = sigma d + tau mod n. ign=True is the 'sigma ignored' broken model."""
    s, t = phi
    if ign:
        s = 1
    return (s * d + t) % n


def pub_phi(c, P, phi, ign=False):
    """P_phi = sigma P + tau G from the public key only."""
    s, t = phi
    if ign:
        s = 1
    return c.add(P if s == 1 else c.neg(P), c.table[t])


def key_id(scheme, Q):
    if Q is INF:
        return None
    return Q[0] if scheme == "bip340" else Q


def honest_ds(c, scheme):
    """Honest secrets: BIP340 normalized (even y), ECDSA any."""
    return [d for d in range(1, c.n) if scheme == "ecdsa" or c.table[d][1] % 2 == 0]


def make_family(c, scheme, d, rng, K):
    """Phi chosen after seeing P: repeats tau across both signs, includes sigma = -1, pairwise distinct keys
    (x-only for BIP340), d_phi != 0."""
    n = c.n
    for _ in range(5000):
        t1, t2, t3 = (rng.randrange(1, n) for _ in range(3))
        fam = [(1, t1), (-1, t1), (-1, t2), (1, t3)][:K]
        if len(set(fam)) < K:
            continue
        ds = [dphi(n, d, p) for p in fam]
        if 0 in ds:
            continue
        ids = [key_id(scheme, c.table[x]) for x in ds]
        if len(set(ids)) == K:
            return fam
    raise RuntimeError(f"no family p={c.p} scheme={scheme} d={d} K={K}")


def fam_size(c, scheme):
    """Distinct nonzero d_phi give at most (n-1)/2 distinct x-only keys; K >= 3 needs n >= 7."""
    return 4 if scheme == "ecdsa" or (c.n - 1) // 2 >= 4 else 3


def mk_ctx(c, scheme, d, phi, z=None, etab=None):
    raw = dphi(c.n, d, phi)
    assert raw != 0
    return TL.Ctx(c, scheme, raw, z=z, etab=etab)


# ------------------------------------------------------------------ E1: base law, independence across keys

def kfun(scheme, n):
    """k0 as a function of the nonce hash output X."""
    if scheme == "bip340":
        return lambda X: (X % n) or None
    return lambda X: X if 0 < X < n else None


def payload(variant, ctx_info, mask):
    """Hidden nonce-hash input for a context. ctx_info = (d_phi_normalized, keyid, d_root_normalized, m, hc)."""
    dn, kid, droot, m, hc = ctx_info
    if variant == "honest":
        return (dn ^ mask[hc], kid, m, hc)
    if variant == "pk_omitted":
        return (dn ^ mask[hc], m, hc)
    if variant == "shared_nonce":
        return (droot ^ mask[hc], m, hc)
    if variant == "no_phi":
        return (m, hc)
    raise ValueError(variant)


def e1_enumerate(c, scheme, slot_of, K, want_brute):
    """slot_of[i] = hash-table cell of context i (equal cells = same payload). All contexts share one rho.
    Returns exact quantities from enumerating every assignment of the nonce-table cells."""
    n, B = c.n, c.B
    f = kfun(scheme, n)
    cnt = Counter(f(X) for X in range(B))                    # multiplicities of k0 (None = failure)
    vals = list(cnt.items())
    ell = {k: Fraction(m, B) for k, m in cnt.items()}
    S = len(set(slot_of))
    slots = sorted(set(slot_of))
    LJ = Counter()                                            # exact law of the k-vector under the model
    for combo in product(vals, repeat=S):
        w = 1
        asg = {}
        for sl, (k, m) in zip(slots, combo):
            w *= m
            asg[sl] = k
        LJ[tuple(asg[s] for s in slot_of)] += w
    tot = B ** S

    def classes(kv):
        valid = [k for k in kv if k is not None]
        return len(set(valid)), len(valid)

    # exact TV between the joint (k-vector law LJ, u uniform and shared inside each equal-R0 class) and the
    # product of the per-context marginals (k from ell, u uniform): derived per k-vector, see README text
    tv2 = Fraction(0)
    tv_pred = Fraction(0)
    p_coinc = Fraction(0)
    allk = set(LJ)
    # product-law k-vectors can lie outside LJ's support (broken model), so add them
    for kv in product(list(cnt), repeat=K):
        allk.add(kv)
    for kv in allk:
        cl, v = classes(kv)
        pj = Fraction(LJ.get(kv, 0), tot)
        pp = Fraction(1)
        for k in kv:
            pp *= ell[k]
        x = Fraction(1, B ** (v - cl))
        tv2 += abs(pj - pp * x) + pp * (1 - x)
        tv_pred += pp * (1 - x)
        if cl < v:
            p_coinc += pj
    out = dict(tv_actual=tv2 / 2, tv_independent_prediction=tv_pred, p_coincidence=p_coinc,
               payloads_distinct=(S == K))
    if want_brute:
        out["brute"] = e1_brute(c, scheme, slot_of, K, ell)
    return out


def e1_brute(c, scheme, slot_of, K, ell):
    """Full enumeration of nonce-table cells and H_point cells (one per equal-R0 class), integer weights."""
    n, B = c.n, c.B
    f = kfun(scheme, n)
    slots = sorted(set(slot_of))
    S = len(slots)
    T = B ** (S + K)                       # every assignment weighs B^(K - classes) out of T
    J = Counter()
    for xs in product(range(B), repeat=S):
        asg = dict(zip(slots, xs))
        kv = tuple(f(asg[s]) for s in slot_of)
        valid = sorted({k for k in kv if k is not None})
        cl = len(valid)
        for us in product(range(B), repeat=cl):
            um = dict(zip(valid, us))
            uv = tuple(None if k is None else um[k] for k in kv)
            J[(kv, uv)] += B ** (K - cl)
    # marginals
    M = [Counter() for _ in range(K)]
    for (kv, uv), w in J.items():
        for i in range(K):
            M[i][(kv[i], uv[i])] += w
    marg_ok = True
    for i in range(K):
        for (k, u), w in M[i].items():
            want = ell[k] * (Fraction(1, B) if k is not None else 1)
            if Fraction(w, T) != want:
                marg_ok = False
    # TV against the product of marginals; and equality on the no-coincidence event
    sup = [list(M[i]) for i in range(K)]
    tv2 = Fraction(0)
    mismatch_on_E = 0
    cases_on_E = 0
    for pt in product(*sup):
        kv = tuple(p[0] for p in pt)
        uv = tuple(p[1] for p in pt)
        pp = 1
        for i in range(K):
            pp *= M[i][pt[i]]
        pj = J.get((kv, uv), 0) * T ** (K - 1)
        tv2 += abs(Fraction(pj - pp, T ** K))
        valid = [k for k in kv if k is not None]
        if len(set(valid)) == len(valid):
            cases_on_E += 1
            if pj != pp:
                mismatch_on_E += 1
    for key in J:                           # joint points outside the product support
        kv, uv = key
        if not all((kv[i], uv[i]) in M[i] for i in range(K)):
            tv2 += Fraction(J[key], T)
    return dict(marginals_exact=marg_ok, tv=tv2 / 2, points_no_coincidence=cases_on_E,
                mismatch_on_no_coincidence=mismatch_on_E, joint_points=len(J))


def run_e1(plan, seed, log):
    rec = dict(groups=[], cases=0, fail=[], variants={}, distinct_checks=[])
    rng = random.Random(seed + "-e1")
    for p in plan["curves"]:
        c = TL.Curve(p)
        n, B = c.n, c.B
        for scheme in SCHEMES:
            ds = honest_ds(c, scheme)
            picks = [ds[0], ds[len(ds) // 2], ds[-1]][:plan["nd"]]
            for d in picks:
                K = fam_size(c, scheme)
                fam = make_family(c, scheme, d, rng, K)
                ctxs = [mk_ctx(c, scheme, d, phi) for phi in fam]
                mask = {hc: rng.randrange(B) for hc in range(4)}
                # (a) exhaustive payload distinctness over every derivation, 3 messages, 4 hc, per variant
                alld = [(s, t) for s in (1, -1) for t in range(n)]
                ids_seen, dist = {}, {}
                for variant in ("honest", "pk_omitted", "shared_nonce", "no_phi"):
                    seen = {}
                    colls = 0
                    for phi in alld:
                        dr = dphi(n, d, phi)
                        if dr == 0:
                            continue
                        cx = TL.Ctx(c, scheme, dr)
                        kid = key_id(scheme, cx.P)
                        if kid in ids_seen and ids_seen[kid] != phi and variant == "honest":
                            pass  # coincident keys are E3's business; here they are labelled as one key
                        ids_seen.setdefault(kid, phi)
                        if ids_seen[kid] != phi:
                            continue          # one label per key, as in the theorem after the coincidence step
                        for m in (1, 2, 3):
                            for hc in range(4):
                                pl = payload(variant, (cx.d, kid, d, m, hc), mask)
                                if pl in seen:
                                    colls += 1
                                seen[pl] = (phi, m, hc)
                    dist[variant] = dict(contexts=len(seen) + colls, collisions=colls)
                rec["distinct_checks"].append(dict(p=p, scheme=scheme, d=d, **{v: dist[v] for v in dist}))
                # (b) joint law of (k0, u_full) on context sets
                sets = {
                    "A_all_keys_one_message": [(i, 1) for i in range(min(K, 3))],
                    "B_repeated_phi_two_messages": [(0, 1), (0, 2), (1, 1)],
                }
                if n <= 7 or K == 4 and n <= 31:
                    sets["C_four_contexts_repeats"] = [(0, 1), (1, 1), (0, 2), (1, 2)]
                for sname, cl in sets.items():
                    for variant in ("honest", "pk_omitted", "shared_nonce", "no_phi"):
                        pls = []
                        for (i, m) in cl:
                            cx = ctxs[i]
                            pls.append(payload(variant, (cx.d, key_id(scheme, cx.P), d, m, 0), mask))
                        slot_ids = {}
                        slot_of = [slot_ids.setdefault(pl, len(slot_ids)) for pl in pls]
                        brute = p in plan["brute_curves"] and len(cl) == 3
                        if len(cl) == 4 and n > 7:
                            continue
                        r = e1_enumerate(c, scheme, slot_of, len(cl), brute)
                        N = len(cl)
                        bound = Fraction(N * N, n - 1)
                        okc = (r["payloads_distinct"] and r["tv_actual"] == r["tv_independent_prediction"]
                               and r["p_coincidence"] <= bound)
                        if brute:
                            b = r["brute"]
                            okc = okc and b["marginals_exact"] and b["tv"] == r["tv_actual"] \
                                and b["mismatch_on_no_coincidence"] == 0
                        row = dict(p=p, n=n, B=B, scheme=scheme, d=d, family=fam, set=sname, variant=variant,
                                   contexts=N, cells=len(set(slot_of)), ok=okc,
                                   tv_actual=r["tv_actual"], tv_independent_prediction=r["tv_independent_prediction"],
                                   p_coincidence=r["p_coincidence"], bound_N2_over_n_minus_1=bound,
                                   payloads_distinct=r["payloads_distinct"])
                        if brute:
                            row["brute"] = r["brute"]
                        rec["groups"].append(row)
                        if variant == "honest":
                            rec["cases"] += 1
                            if not okc:
                                rec["fail"].append(row)
                        v = rec["variants"].setdefault(variant, dict(rows=0, flagged=0))
                        v["rows"] += 1
                        v["flagged"] += (not okc)
        log(f"  E1 p={p} n={n} B={B} done")
    return rec


# ------------------------------------------------------------------ E2: simulator views

def nonce_point(ctx, P, sig):
    """Simulator's V from a signature and a public key P (no secret)."""
    c, n = ctx.c, ctx.n
    r, s = sig
    if ctx.scheme == "bip340":
        e = ctx.etab[r]
        return c.add(c.smul(s, c.G), c.neg(c.smul(e, P)))
    si = pow(s, -1, n)
    return c.add(c.smul(si * ctx.z % n, c.G), c.smul(si * r % n, P))


def g5_parts(ctx, base, simP=None, sigs=None):
    """Exact (weight, outcome) lists of the G5 simulator for a resolved context, split into the part decided by
    coins the simulator holds and the part answered from Sign_Rand (k' != 0, branch 3).
    simP: public key the simulator uses (default the context's own P_phi).
    sigs: list of (k, sig) from the Sign_Rand oracle (uniform), default the context's own oracle."""
    c = ctx.c
    n, B, g = ctx.n, c.B, c.g
    f = base.get(None, Fraction(0))
    non = 1 - f
    others = [(f, ctx.outcome(None, None))]
    w2 = non * Fraction(g, B) / ((n - 1) * g)
    for k0 in range(1, n):
        for u in range(n, B):
            others.append((w2, ctx.outcome(k0, u)))
    w0 = non * Fraction(n, B) * Fraction(1, n) / (n - 1)
    for u in range(1, n):
        others.append((w0, ctx.outcome((-u) % n, u)))
    pnz = non * Fraction(n - 1, B)
    sr = sigs if sigs is not None else TL.sign_rand_list(ctx)
    P = simP if simP is not None else ctx.P
    sigitems = []
    for ks, sig in sr:
        V = nonce_point(ctx, P, sig)
        if V is INF:
            sigitems.append((pnz / len(sr), ("sim_fail", None, None, sig[0], sig[1])))
            continue
        for b in (0, 1):
            W = V if b == 0 else c.neg(V)
            us = [u for u in range(n) if c.table[u] != W]
            w = pnz / len(sr) / 2 / len(us)
            for u in us:
                R0 = c.add(W, c.neg(c.table[u]))
                if R0 is INF:
                    sigitems.append((w, ("kp_zero", None, u, None, None)))
                else:
                    sigitems.append((w, ("ok", R0, u, sig[0], sig[1])))
    return others, sigitems


def g5_items(ctx, base, simP=None, sigs=None):
    o, s = g5_parts(ctx, base, simP, sigs)
    return o + s


def law_of(items):
    acc = TL.LawAcc()
    for w, o in items:
        acc.add(o, w)
    return acc.law()


def tv_joint(J, L1, L2):
    """TV between a joint law J (dict pair->prob) and the product L1 x L2, without building the product."""
    sup_prod = Fraction(0)
    s = Fraction(0)
    for (a, b), pj in J.items():
        pp = L1.get(a, 0) * L2.get(b, 0)
        sup_prod += pp
        s += abs(pj - pp)
    return (s + (1 - sup_prod)) / 2


def joint_items(items1, items2):
    acc = TL.LawAcc()
    for w1, o1 in items1:
        for w2, o2 in items2:
            acc.add((o1, o2), w1 * w2)
    return acc.law()


def reuse_nonce_joint(ctx1, ctx2, base1, base2):
    """Broken: one nonce point W shared by the two keys' contexts, with one coin deciding the branch for both.
    For BIP340 each marginal stays exact; only the joint is wrong."""
    c = ctx1.c
    n, B = ctx1.n, c.B
    J = {}
    non = 1 - base1.get(None, Fraction(0))
    pnz = non * Fraction(n - 1, B)
    oth1, _ = g5_parts(ctx1, base1)
    oth2, _ = g5_parts(ctx2, base2)
    sr = TL.sign_rand_list(ctx1)
    for ks, sig in sr:
        V = nonce_point(ctx1, ctx1.P, sig)
        for b in (0, 1):
            W = V if b == 0 else c.neg(V)
            sig2 = ctx2.sig_of_scalar(c.dlog[W])
            us = [u for u in range(n) if c.table[u] != W]
            w = pnz / len(sr) / 2 / len(us) / len(us)
            for u in us:
                R01 = c.add(W, c.neg(c.table[u]))
                o1 = ("kp_zero", None, u, None, None) if R01 is INF else ("ok", R01, u, sig[0], sig[1])
                for u2 in us:
                    R02 = c.add(W, c.neg(c.table[u2]))
                    if R02 is INF:
                        o2 = ("kp_zero", None, u2, None, None)
                    elif sig2 is None:
                        o2 = ("rs_fail", R02, u2, None, None)
                    else:
                        o2 = ("ok", R02, u2, sig2[0], sig2[1])
                    J[(o1, o2)] = J.get((o1, o2), 0) + w
    for w1, o1 in oth1:
        for w2, o2 in oth2:
            J[(o1, o2)] = J.get((o1, o2), 0) + w1 * w2 / (1 - pnz)
    return J


def run_e2(plan, seed, log):
    rec = dict(cases=0, joint_cases=0, fail=[], bad_hist={}, max_bad=0, max_tv_g3_g5_ecdsa=Fraction(0),
               controls={}, sigma_minus_cases=0, sigma_plus_cases=0, groups=[])
    rng = random.Random(seed + "-e2")

    def ctl(name):
        return rec["controls"].setdefault(name, dict(cases=0, detected=0, min_tv=None, max_tv=Fraction(0),
                                                    exempt_zero_expected=0, unexpected_zero=0))

    def ctl_add(name, tv, expect_nonzero=True):
        r = ctl(name)
        if not expect_nonzero:
            if tv != 0:
                r["unexpected_zero"] += 1       # (counts sanity violations on sigma=+1 cases for sigma_ignored)
            r["exempt_zero_expected"] += 1
            return
        r["cases"] += 1
        r["detected"] += (tv > 0)
        r["min_tv"] = tv if r["min_tv"] is None else min(r["min_tv"], tv)
        r["max_tv"] = max(r["max_tv"], tv)

    for p in plan["curves"]:
        c = TL.Curve(p)
        n, B = c.n, c.B
        for scheme in SCHEMES:
            hd = honest_ds(c, scheme)
            keys = [d for d in TL.key_list(c, rng, 12) if d in hd][:plan["nkeys"]]
            while len(keys) < min(plan["nkeys"], len(hd)):
                x = rng.choice(hd)
                if x not in keys:
                    keys.append(x)
            ncontrol_done = 0
            for d in keys:
                K = fam_size(c, scheme)
                fam = make_family(c, scheme, d, rng, K)
                P = c.table[d]
                # per-derivation cases
                per_phi_ctx = []
                for i, phi in enumerate(fam):
                    dr = dphi(n, d, phi)
                    if scheme == "ecdsa":
                        zs = TL.z_list(c, dr, rng, plan["nz"])
                    else:
                        zs = [None] * plan["netab"]
                    row_ctx = []
                    for z in zs:
                        etab = {x: rng.randrange(n) for x in range(p)} if scheme == "bip340" else None
                        row_ctx.append(TL.Ctx(c, scheme, dr, z=z, etab=etab))
                    per_phi_ctx.append(row_ctx)
                for i, phi in enumerate(fam):
                    sgn = phi[0]
                    for j, ctx in enumerate(per_phi_ctx[i]):
                        base = TL.base_law(ctx, "g2" if scheme == "bip340" else "real")
                        l3 = TL.g3_law(ctx, base)
                        good = ctx.good_scalars() if scheme == "ecdsa" else None
                        ref = TL.g4_law(ctx, base, good=good) if scheme == "ecdsa" else l3
                        items = g5_items(ctx, base)
                        l5 = law_of(items)
                        t_main = TL.tv(ref, l5)
                        t_old = TL.tv(l5, TL.g5_law(ctx, base))       # same as the isolated-key simulator, sanity
                        rec["cases"] += 1
                        rec["sigma_minus_cases" if sgn == -1 else "sigma_plus_cases"] += 1
                        row = dict(p=p, scheme=scheme, d=d, phi=phi, case=j, tv_sim_vs_real=t_main,
                                   tv_vs_isolated_g5=t_old)
                        if scheme == "ecdsa":
                            bad = n - 1 - len(good)
                            t3 = TL.tv(l3, l5)
                            rec["max_bad"] = max(rec["max_bad"], bad)
                            rec["bad_hist"][str(bad)] = rec["bad_hist"].get(str(bad), 0) + 1
                            rec["max_tv_g3_g5_ecdsa"] = max(rec["max_tv_g3_g5_ecdsa"], t3)
                            row.update(bad=bad, tv_g3_vs_sim=t3)
                            if bad > 8 or t3 > Fraction(bad, n):
                                rec["fail"].append(dict(row, why="bad>8 or TV(G3,sim) > bad/n"))
                            if set(good) != {(n - k) % n for k in good}:
                                rec["fail"].append(dict(row, why="K_good not closed under negation"))
                        if t_main != 0 or t_old != 0 or TL.total(l5) != 1:
                            rec["fail"].append(dict(row, why="simulator view differs from device view"))
                        if len(rec["groups"]) < 40:
                            rec["groups"].append(row)
                        # ---- controls (single-context)
                        if ncontrol_done < 6:
                            sib = (i + 1) % K
                            sctx = per_phi_ctx[sib][min(j, len(per_phi_ctx[sib]) - 1)]
                            # message must be the same one: rebuild sibling context with this message
                            sdr = dphi(n, d, fam[sib])
                            sctx = TL.Ctx(c, scheme, sdr, z=ctx.z,
                                          etab=({x: rng.randrange(n) for x in range(p)} if scheme == "bip340" else None))
                            wrongP = sctx.P
                            law = law_of(g5_items(ctx, base, simP=wrongP))
                            ctl_add("wrong_key_P_phi", TL.tv(ref, law))
                            sigs_other = TL.sign_rand_list(sctx)
                            law = law_of(g5_items(ctx, base, sigs=sigs_other))
                            ctl_add("reuse_signature_across_keys", TL.tv(ref, law))
                            # context cache keyed by (m, hc) only: this key gets the sibling key's cached outcome
                            sbase = TL.base_law(sctx, "g2" if scheme == "bip340" else "real")
                            law = law_of(g5_items(sctx, sbase))
                            ctl_add("context_keyed_without_phi", TL.tv(ref, law))
                            s_ign = c.add(P, c.table[phi[1]])       # P + tau G, sigma dropped
                            if scheme == "bip340" and s_ign is not INF and s_ign[1] % 2:
                                s_ign = c.neg(s_ign)             # same even-y lift as the honest simulator
                            law = law_of(g5_items(ctx, base, simP=s_ign))
                            tvc = TL.tv(ref, law)
                            if sgn == -1:
                                ctl_add("sigma_ignored", tvc)
                            else:
                                ctl_add("sigma_ignored", tvc, expect_nonzero=False)
                            ncontrol_done += 1
            log(f"  E2 p={p} {scheme} done")
        # ---- joint checks on pairs of keys sharing a message
        npairs = plan["joint_curves"].get(p, 0)
        if npairs:
            for scheme in SCHEMES:
                d = honest_ds(c, scheme)[0]
                K = fam_size(c, scheme)
                fam = make_family(c, scheme, d, rng, K)
                pairs = [(a, b) for a in range(K) for b in range(K) if a < b][:npairs]
                for (a, b) in pairs:
                    za = TL.z_list(c, dphi(n, d, fam[a]), rng, 2)[-1] if scheme == "ecdsa" else None
                    etabA = {x: rng.randrange(n) for x in range(p)} if scheme == "bip340" else None
                    etabB = {x: rng.randrange(n) for x in range(p)} if scheme == "bip340" else None
                    cA = TL.Ctx(c, scheme, dphi(n, d, fam[a]), z=za, etab=etabA)
                    cB = TL.Ctx(c, scheme, dphi(n, d, fam[b]), z=za, etab=etabB)
                    bA = TL.base_law(cA, "g2" if scheme == "bip340" else "real")
                    bB = TL.base_law(cB, "g2" if scheme == "bip340" else "real")
                    refA = TL.g4_law(cA, bA, good=cA.good_scalars()) if scheme == "ecdsa" else TL.g3_law(cA, bA)
                    refB = TL.g4_law(cB, bB, good=cB.good_scalars()) if scheme == "ecdsa" else TL.g3_law(cB, bB)
                    iA, iB = g5_items(cA, bA), g5_items(cB, bB)
                    J = joint_items(iA, iB)
                    t_h = tv_joint(J, refA, refB)
                    rec["joint_cases"] += 1
                    if t_h != 0 or TL.total(J) != 1:
                        rec["fail"].append(dict(p=p, scheme=scheme, d=d, pair=(fam[a], fam[b]), tv_joint=t_h,
                                                why="joint simulator view differs from independent device views"))
                    if scheme == "ecdsa" and not (cA.good_scalars() and cB.good_scalars()):
                        continue
                    Jb = reuse_nonce_joint(cA, cB, bA, bB)
                    t_b = tv_joint(Jb, refA, refB)
                    ctl_add("reuse_nonce_across_keys_joint", t_b)
            log(f"  E2 joint p={p} done")
    return rec


# ------------------------------------------------------------------ E3: coincidences

def same_class(scheme, n, phi, psi):
    """Same map, or for BIP340 the pair (sigma, tau), (-sigma, -tau): one signing key for every d."""
    return phi == psi or (scheme == "bip340" and psi == (-phi[0], (-phi[1]) % n))


def solve_coincidence(c, scheme, P, phi, psi, ign=False):
    """d from a coincidence of phi and psi on the public key P: candidates from the two linear equations,
    kept if d G = P. Returns the set of verified candidates."""
    n = c.n
    s1, t1 = phi
    s2, t2 = psi
    if ign:
        s1 = s2 = 1
    cands = set()
    if (s1 - s2) % n:
        cands.add((t2 - t1) * pow(s1 - s2, -1, n) % n)
    if scheme == "bip340" and (s1 + s2) % n:
        cands.add(-(t1 + t2) * pow(s1 + s2, -1, n) % n)
    return {x for x in cands if x and c.table[x] == P}


def detect_all(c, scheme, P, derivs, ign, all_pairs):
    """B_adv's test: derivations are named one at a time and each is looked up in a table of keys so far
    (all_pairs: every pair is tested instead). Pairs in one class are not coincidences. Returns index pairs."""
    n = c.n
    ids = [key_id(scheme, pub_phi(c, P, phi, ign)) for phi in derivs]
    out = set()
    if all_pairs:
        for i in range(len(derivs)):
            for j in range(i + 1, len(derivs)):
                if ids[i] == ids[j] and not same_class(scheme, n, derivs[i], derivs[j]):
                    out.add((i, j))
    else:
        table = {}
        for j, kid in enumerate(ids):
            for i in table.get(kid, []):
                if not same_class(scheme, n, derivs[i], derivs[j]):
                    out.add((i, j))
            table.setdefault(kid, []).append(j)
    return out


def run_e3(plan, seed, log):
    rec = dict(curves=[], cases=0, fail=[], findings=[], controls={}, classes=Counter(), class_pairs_excluded=0,
               coefficient_hist=Counter())
    ign_stats = dict(pairs_checked=0, missed_true_coincidences=0, false_coincidences=0, wrong_d=0)
    for p in plan["curves"]:
        c = TL.Curve(p)
        n = c.n
        allp = p in plan["pairs_curves"]
        derivs = [(s, t) for s in (1, -1) for t in range(n)]
        crow = Counter()
        for scheme in SCHEMES:
            for d in honest_ds(c, scheme):
                P = c.table[d]
                live = [phi for phi in derivs if dphi(n, d, phi) != 0]
                # truth by integer arithmetic, independent of the group code
                def tid(phi):
                    x = dphi(n, d, phi)
                    return min(x, n - x) if scheme == "bip340" else x
                truth = set()
                byid = {}
                for i, phi in enumerate(live):
                    byid.setdefault(tid(phi), []).append(i)
                for lst in byid.values():
                    for a in range(len(lst)):
                        for b in range(a + 1, len(lst)):
                            if same_class(scheme, n, live[lst[a]], live[lst[b]]):
                                crow["class_pairs_excluded"] += 1
                            else:
                                truth.add((lst[a], lst[b]))
                got = detect_all(c, scheme, P, live, False, allp)
                if got != truth:
                    rec["fail"].append(dict(p=p, scheme=scheme, d=d, why="detection set differs from truth",
                                            missed=sorted(truth - got)[:5], extra=sorted(got - truth)[:5]))
                for (i, j) in truth:
                    phi, psi = live[i], live[j]
                    rec["cases"] += 1
                    ds = solve_coincidence(c, scheme, P, phi, psi)
                    crow["coincident_pairs"] += 1
                    # the d coefficient of the equation that holds must be +-2 (a zero coefficient would mean
                    # the same map or class, already excluded)
                    s1, t1 = phi
                    s2, t2 = psi
                    holds = []
                    if (s1 * d + t1 - s2 * d - t2) % n == 0:
                        holds.append(("plus", (s1 - s2)))
                    if scheme == "bip340" and (s1 * d + t1 + s2 * d + t2) % n == 0:
                        holds.append(("minus", (s1 + s2)))
                    for kind, coef in holds:
                        rec["coefficient_hist"][f"{kind}:{coef}"] += 1
                        if coef not in (2, -2):
                            rec["fail"].append(dict(p=p, scheme=scheme, d=d, phi=phi, psi=psi, coef=coef,
                                                    why="coincidence equation without d coefficient +-2"))
                    if ds != {d}:
                        crow["solvable_but_d_not_recovered"] += 1
                        rec["fail"].append(dict(p=p, scheme=scheme, d=d, phi=phi, psi=psi, recovered=sorted(ds),
                                                why="coincidence, d not recovered"))
                # control: sigma ignored
                if p in plan["pairs_curves"] or p == plan["curves"][0]:
                    gi = detect_all(c, scheme, P, live, True, allp)
                    ign_stats["pairs_checked"] += 1
                    ign_stats["missed_true_coincidences"] += len(truth - gi)
                    ign_stats["false_coincidences"] += len(gi - truth)
                    for (i, j) in truth & gi:
                        if solve_coincidence(c, scheme, P, live[i], live[j], ign=True) != {d}:
                            ign_stats["wrong_d"] += 1
                crow["d_values"] += 1
                crow["derivations_per_d_total"] += len(live)
        rec["curves"].append(dict(p=p, n=n, all_pairs_test=allp, **crow))
        rec["classes"].update(crow)
        log(f"  E3 p={p} n={n} done")
    rec["controls"]["sigma_ignored"] = dict(ign_stats, detected=(ign_stats["missed_true_coincidences"]
                                                                 + ign_stats["false_coincidences"]
                                                                 + ign_stats["wrong_d"]) > 0)
    return rec


# ------------------------------------------------------------------ E4: extraction

def bad1_hit(c, scheme, idmap, pl, mask):
    t, kid, m, hc = pl
    K = t ^ mask[hc]
    if not 0 < K < c.n or kid not in idmap:
        return None
    Q = c.table[K]
    if key_id(scheme, Q) != kid:
        return None
    return K, idmap[kid]


def recover_d(c, scheme, P, phi, K, ign=False):
    s, t = phi
    if ign:
        s = 1
    n = c.n
    cands = {s * (K - t) % n}
    if scheme == "bip340":
        cands.add(s * (-K - t) % n)
    ok = [x for x in cands if x and c.table[x] == P]
    return ok


def run_e4(plan, seed, log):
    rng = random.Random(seed + "-e4")
    rec = dict(single=0, scan_cases=0, scan_hits=0, scan_expected_hits=0, cross_key_payloads=0,
               cross_key_hits=0, other_root_hits=0, other_root_cases=0, fail=[], controls={})
    ign = dict(cases=0, recovery_wrong=0)
    for p in plan["curves"]:
        c = TL.Curve(p)
        n, B = c.n, c.B
        for scheme in SCHEMES:
            mask = {hc: rng.randrange(B) for hc in range(3)}
            for d in honest_ds(c, scheme):
                P = c.table[d]
                # every single derivation: hidden-input payload is a hit and d is recovered
                for s in (1, -1):
                    for t in range(n):
                        phi = (s, t)
                        dr = dphi(n, d, phi)
                        if dr == 0:
                            continue
                        cx = TL.Ctx(c, scheme, dr)
                        kid = key_id(scheme, cx.P)
                        idmap = {kid: phi}
                        hc = rng.randrange(3)
                        pl = (cx.d ^ mask[hc], kid, 1, hc)
                        h = bad1_hit(c, scheme, idmap, pl, mask)
                        rec["single"] += 1
                        if h is None:
                            rec["fail"].append(dict(p=p, scheme=scheme, d=d, phi=phi, why="hidden input not a hit"))
                            continue
                        got = recover_d(c, scheme, P, phi, h[0])
                        if got != [d]:
                            rec["fail"].append(dict(p=p, scheme=scheme, d=d, phi=phi, recovered=got,
                                                    why="d not recovered"))
                        if scheme == "bip340":
                            rec["other_root_cases"] += 1
                            pl2 = ((n - cx.d) ^ mask[hc], kid, 1, hc)
                            h2 = bad1_hit(c, scheme, idmap, pl2, mask)
                            if h2 is None or recover_d(c, scheme, P, phi, h2[0]) != [d]:
                                rec["fail"].append(dict(p=p, scheme=scheme, d=d, phi=phi,
                                                        why="other-root payload not a hit or d not recovered"))
                            else:
                                rec["other_root_hits"] += 1
                        if phi[0] == -1:
                            ign["cases"] += 1
                            gi = recover_d(c, scheme, P, phi, h[0], ign=True)
                            ign["recovery_wrong"] += (gi != [d])
            # families: scan every payload shape of a small space, hits must be exactly the hidden inputs
            ds = honest_ds(c, scheme)
            for d in rng.sample(ds, min(plan["nfam"], len(ds))):
                P = c.table[d]
                K = fam_size(c, scheme)
                fam = make_family(c, scheme, d, rng, K)
                cxs = [mk_ctx(c, scheme, d, phi) for phi in fam]
                kids = [key_id(scheme, cx.P) for cx in cxs]
                idmap = dict(zip(kids, fam))
                for hc in range(3):
                    for m in (1, 2):
                        hits = []
                        for t in range(B):
                            for kid in kids:
                                h = bad1_hit(c, scheme, idmap, (t, kid, m, hc), mask)
                                if h:
                                    hits.append((t, kid))
                        exp = set()
                        for cx, kid in zip(cxs, kids):
                            exp.add((cx.d ^ mask[hc], kid))
                            if scheme == "bip340":
                                exp.add(((n - cx.d) ^ mask[hc], kid))
                        rec["scan_cases"] += 1
                        rec["scan_hits"] += len(hits)
                        rec["scan_expected_hits"] += len(exp)
                        if set(hits) != exp or len(hits) != len(exp):
                            rec["fail"].append(dict(p=p, scheme=scheme, d=d, hc=hc, m=m, why="hit set differs"))
                        # cross-key payloads: a masked secret with another key's public key is not a hit
                        for i, cx in enumerate(cxs):
                            for j, kid in enumerate(kids):
                                if i != j:
                                    rec["cross_key_payloads"] += 1
                                    if bad1_hit(c, scheme, idmap, (cx.d ^ mask[hc], kid, m, hc), mask):
                                        rec["cross_key_hits"] += 1
                                        rec["fail"].append(dict(p=p, scheme=scheme, d=d, i=i, j=j,
                                                                why="cross-key payload is a hit"))
        log(f"  E4 p={p} done")
    rec["controls"]["sigma_ignored"] = dict(ign, detected=ign["recovery_wrong"] > 0)
    return rec


# ------------------------------------------------------------------ E5: cross-key ECDSA relation

def ecdsa_verify(c, P, z, sig):
    n = c.n
    r, s = sig
    if not (0 < r < n and 0 < s < n):
        return False
    si = pow(s, -1, n)
    V = c.add(c.smul(z * si % n, c.G), c.smul(r * si % n, P))
    return V is not INF and V[0] % n == r


def run_e5(plan, seed, log):
    rng = random.Random(seed + "-e5")
    rec = dict(cases=0, relation_holds=0, wrong_sign_valid=0, flipped_cases=0, flipped_holds=0, fail=[],
               low_s_cases=0, curves=[])
    for p in plan["full"] + plan["sampled"]:
        c = TL.Curve(p)
        n = c.n
        full = p in plan["full"]
        ds = list(range(1, n)) if full else rng.sample(range(1, n), plan["nsamp"])
        as_ = list(range(1, n)) if full else rng.sample(range(1, n), plan["nsamp"])
        zs = list(range(n)) if full else rng.sample(range(n), plan["nsamp"])
        row = dict(p=p, n=n, full=full, cases=0)
        for dd in ds:
            P = c.table[dd]
            for a in as_:
                if (dd + a) % n == 0:
                    continue
                Pa = c.table[(dd + a) % n]
                Pf = c.add(c.neg(P), c.table[a])      # the flipped derivation -P + aG
                for z in zs:
                    for k in range(1, n):
                        W = c.table[k]
                        r = W[0] % n
                        if r == 0:
                            continue
                        s = pow(k, -1, n) * (z + r * dd) % n
                        if s == 0:
                            continue
                        if s > (n - 1) // 2:
                            s = n - s
                            rec["low_s_cases"] += 1
                        sig = (r, s)
                        rec["cases"] += 1
                        row["cases"] += 1
                        assert ecdsa_verify(c, P, z, sig)
                        z2 = (z - r * a) % n
                        if ecdsa_verify(c, Pa, z2, sig):
                            rec["relation_holds"] += 1
                        else:
                            rec["fail"].append(dict(p=p, d=dd, a=a, z=z, k=k, why="z - r a relation failed"))
                        if ecdsa_verify(c, Pa, (z + r * a) % n, sig):
                            rec["wrong_sign_valid"] += 1
                        if Pf is not INF:
                            rec["flipped_cases"] += 1
                            if ecdsa_verify(c, Pf, (-z - r * a) % n, sig):
                                rec["flipped_holds"] += 1
        rec["curves"].append(row)
        log(f"  E5 p={p} n={n} cases={row['cases']}")
    # the check must be able to see the relation: wrong-sign version must fail somewhere, and not everywhere
    rec["discriminates"] = rec["wrong_sign_valid"] < rec["cases"]
    return rec


# ------------------------------------------------------------------ E6: tweak binding

def host_accept(ctxH, W, sig):
    """Step 5 on public data with the host's key pk = ctxH.P: W = R0 + tG from step 2, signature sig."""
    c, n = ctxH.c, ctxH.n
    r, s = sig
    P = ctxH.P
    if ctxH.scheme == "bip340":
        if W[0] != r:
            return False, False
        e = ctxH.etab[r]
        R = c.add(c.smul(s, c.G), c.neg(c.smul(e, P)))
        return True, (R is not INF and R[1] % 2 == 0 and R[0] == r)
    if not 0 < s <= (n - 1) // 2 or W[0] % n != r:
        return False, False
    si = pow(s, -1, n)
    V = c.add(c.smul(ctxH.z * si % n, c.G), c.smul(si * r % n, P))
    nr = V is not INF and V[0] % n == r and V in (W, c.neg(W))
    return nr, nr


def e6_tables(ctx1, ctx2):
    """For the host's W = w G from step 2 (context phi, key P_phi) and the device's step-4 nonce scalar w2 under
    phi': (device signed?, nonce relation, full step 5 with the host key P_phi', full step 5 with the old key P_phi).
    Returns dicts keyed (w, w2)."""
    c, n = ctx1.c, ctx1.n
    sigs = {w2: ctx2.sig_of_scalar(w2) for w2 in range(1, n)}
    tabs = dict(signed=0, nonce=Counter(), acc_new=Counter(), acc_old=Counter(), point=Counter())
    nonce, acc_new, acc_old, pointc = {}, {}, {}, {}
    for w in range(1, n):
        W = c.table[w]
        for w2, sig in sigs.items():
            if sig is None:
                continue
            nr, ok_new = host_accept(ctx2, W, sig)
            _, ok_old = host_accept(ctx1, W, sig)
            nonce[(w, w2)] = nr
            acc_new[(w, w2)] = ok_new
            acc_old[(w, w2)] = ok_old
            pointc[(w, w2)] = (w == w2 or w == (n - w2) % n)
    return sigs, nonce, acc_new, acc_old, pointc


def e6_counts(c, scheme, ctx1, ctx2, shared_cell, brute):
    """Exact weights, on the scale of B^4 assignments of (X, X', t, t'), where X, X' are the nonce-table cells of
    the step-2 context phi and the step-4 context phi', and t, t' the H_point cells at (R0, rho) and (R0', rho).
    The two H_point cells are one cell exactly when R0 = R0' (same rho). shared_cell: X = X' (one payload)."""
    n, B = c.n, c.B
    f = kfun(scheme, n)
    cnt = Counter(f(X) for X in range(B))
    cnt.pop(None, None)
    sigs, nonce, acc_new, acc_old, pointc = e6_tables(ctx1, ctx2)
    full = dict(signed=sum(1 for w in range(1, n) for w2 in range(1, n) if sigs[w2] is not None),
                nonce=sum(nonce.values()), new=sum(acc_new.values()), old=sum(acc_old.values()),
                pt=sum(pointc.values()))
    diag = dict(signed=sum(1 for w in range(1, n) if sigs[w] is not None),
                nonce=sum(v for (w, w2), v in nonce.items() if w == w2),
                new=sum(v for (w, w2), v in acc_new.items() if w == w2),
                old=sum(v for (w, w2), v in acc_old.items() if w == w2),
                pt=sum(v for (w, w2), v in pointc.items() if w == w2))
    tot = dict(signed=0, nonce=0, new=0, old=0, pt=0, same_R0=0)
    for k0, m0 in cnt.items():
        if shared_cell:
            tot["same_R0"] += m0 * B ** 3
            for key in diag:
                tot[key] += m0 * B ** 2 * diag[key]
            continue
        for k1, m1 in cnt.items():
            if k0 == k1:
                tot["same_R0"] += m0 * m1 * B * B
                for key in diag:
                    tot[key] += m0 * m1 * B * diag[key]
            else:
                for key in full:
                    tot[key] += m0 * m1 * full[key]
    out = dict(total=B ** 4, **tot)
    if brute:
        out["brute"] = e6_brute(c, scheme, shared_cell, sigs, nonce, acc_new, acc_old, pointc, f)
    return out


def e6_brute(c, scheme, shared_cell, sigs, nonce, acc_new, acc_old, pointc, f):
    """Nested loops over X, X', t, t' with the H_point cell shared exactly when R0 coincide."""
    n, B = c.n, c.B
    tot = dict(signed=0, nonce=0, new=0, old=0, pt=0, same_R0=0)
    for X in range(B):
        for X2 in ([X] if shared_cell else range(B)):
            k0, k1 = f(X), f(X2)
            if k0 is None or k1 is None:
                continue
            same = k0 == k1
            wt = B * B if shared_cell else (B if same else 1)
            for t in range(B):
                for t2 in ([t] if (shared_cell or same) else range(B)):
                    if same:
                        tot["same_R0"] += wt
                    if t >= n or t2 >= n:
                        continue
                    w, w2 = (k0 + t) % n, (k1 + t2) % n
                    if w == 0 or w2 == 0 or sigs[w2] is None:
                        continue
                    tot["signed"] += wt
                    tot["nonce"] += wt * nonce[(w, w2)]
                    tot["new"] += wt * acc_new[(w, w2)]
                    tot["old"] += wt * acc_old[(w, w2)]
                    tot["pt"] += wt * pointc[(w, w2)]
    return tot


def run_e6(plan, seed, log):
    rng = random.Random(seed + "-e6")
    rec = dict(cases=0, rows=[], fail=[], controls={}, honest_same_phi_ok=True, same_phi_rows=0)
    ctl_rows = Counter()
    for p in plan["curves"]:
        c = TL.Curve(p)
        n, B = c.n, c.B
        for scheme in SCHEMES:
            hd = honest_ds(c, scheme)
            for d in rng.sample(hd, min(plan["nd"], len(hd))):
                K = fam_size(c, scheme)
                fam = make_family(c, scheme, d, rng, K)
                if scheme == "ecdsa":
                    z = TL.z_list(c, dphi(n, d, fam[0]), rng, 3)[-1]
                else:
                    z = None
                # challenge hash includes the key: an independent table per key
                ctxs = [TL.Ctx(c, scheme, dphi(n, d, phi), z=z,
                               etab=({x: rng.randrange(n) for x in range(p)} if scheme == "bip340" else None))
                        for phi in fam]
                brute = p in plan["brute_curves"]
                for i in range(K):
                    for j in range(K):
                        # honest model: distinct payloads, independent nonce cells; i == j is the same-phi positive control
                        r = e6_counts(c, scheme, ctxs[i], ctxs[j], shared_cell=(i == j), brute=brute and i < 2 and j < 2)
                        rec["cases"] += r["total"]
                        row = dict(p=p, n=n, B=B, scheme=scheme, d=d, phi=fam[i], phi2=fam[j],
                                   **{k: v for k, v in r.items() if k != "brute"})
                        ok = True
                        if i == j:
                            # same phi: no switch; every produced signature must pass step 5 with the host key
                            ok = row["new"] == row["signed"] and row["old"] == row["signed"] and row["signed"] > 0
                            rec["same_phi_rows"] += 1
                        else:
                            # accepted only on a point coincidence W' = +-W, and every point coincidence passes the
                            # nonce relation with the right key (new) when the signature is valid under it
                            ok = (row["new"] <= row["pt"] and row["nonce"] >= row["new"]
                                  and row["same_R0"] == expected_same_R0(c, scheme))
                            # reading (a): host still holds the original key; for BIP340 it needs W' = +-W too
                            if scheme == "bip340":
                                ok = ok and row["old"] <= row["pt"]
                        if "brute" in r:
                            bt = r["brute"]
                            for k in ("signed", "nonce", "new", "old", "pt", "same_R0"):
                                if bt[k] != r[k]:
                                    ok = False
                                    rec["fail"].append(dict(row, why=f"brute force differs from table sums on {k}",
                                                            brute=bt))
                                    break
                        row["ok"] = ok
                        rec["rows"].append(row)
                        if not ok:
                            rec["fail"].append(dict(row, why="E6 criteria"))
                        # ---- controls on the first off-diagonal pair per (curve, scheme)
                        if i == 0 and j == 1:
                            ctl_rows[(p, scheme)] += 1
                            # pk omitted, literal: the masked secret d_phi is still in the hash input
                            # payload distinct for every pair, so same model as honest
                            lit = e6_counts(c, scheme, ctxs[i], ctxs[j], shared_cell=False, brute=False)
                            ctl = rec["controls"].setdefault("pk_omitted_literal", dict(rows=0, detected=0))
                            ctl["rows"] += 1
                            ctl["detected"] += (lit["same_R0"] != expected_same_R0(c, scheme)
                                                or lit["new"] > lit["pt"])
                            # info: pk omitted AND the nonce secret is the parent d for every tweak
                            rs = e6_counts(c, scheme, ctxs[i], ctxs[j], shared_cell=True, brute=False)
                            ctl = rec["controls"].setdefault("shared_nonce_info", dict(rows=0, detected=0,
                                                                                               accept_fraction=[]))
                            ctl["rows"] += 1
                            ctl["detected"] += (rs["same_R0"] != expected_same_R0(c, scheme) or rs["new"] > rs["pt"])
                            ctl["accept_fraction"].append(str(Fraction(rs["new"], max(1, rs["signed"]))))
        log(f"  E6 p={p} done")
    return rec


def expected_same_R0(c, scheme):
    """Independent-cells reference: weight of (X, X', t, t') on the B^4 scale with k0 = k0' and both valid,
    counted as the proof counts it: sum_k m(k)^2 * B^2 (the shared H_point cell leaves one free)."""
    n, B = c.n, c.B
    f = kfun(scheme, n)
    cnt = Counter(f(X) for X in range(B))
    cnt.pop(None, None)
    return sum(m * m for m in cnt.values()) * B * B


# ------------------------------------------------------------------ E7: BIP340 key classes (and related controls)

def bip_verify(c, Pxy, etab, sig):
    """BIP340 verify against the x-only key of Pxy (lifted to even y)."""
    r, s = sig
    P = Pxy if Pxy[1] % 2 == 0 else c.neg(Pxy)
    R = c.add(c.smul(s, c.G), c.neg(c.smul(etab[r], P)))
    return R is not INF and R[1] % 2 == 0 and R[0] == r


def leak_d(c, scheme, P, phi1, phi2, sig1, sig2, e1=None, e2=None, z=None):
    """B_adv's use of two signatures made with ONE nonce under two keys with public offsets: solve for d.
    Returns the verified candidates. Uses only P, the offsets, the signatures and the public hash values."""
    n = c.n
    out = set()
    (s1, t1), (s2, t2) = phi1, phi2
    if scheme == "bip340":
        eps = []
        for (sg, tg) in (phi1, phi2):
            Q = pub_phi(c, P, (sg, tg))
            if Q is INF:
                return out
            eps.append(1 if Q[1] % 2 == 0 else -1)
        # s_i = k + e_i eps_i (sigma_i d + tau_i), same k
        A = (e2 * eps[1] * s2 - e1 * eps[0] * s1) % n
        rhs = (sig2[1] - sig1[1] + e1 * eps[0] * t1 - e2 * eps[1] * t2) % n
        if A:
            out.add(rhs * pow(A, -1, n) % n)
    else:
        r = sig1[0]
        if sig2[0] != r:
            return out
        for d1 in (1, -1):
            for d2 in (1, -1):
                a, b = d1 * sig1[1] % n, d2 * sig2[1] % n
                coef = r * (s1 * pow(a, -1, n) - s2 * pow(b, -1, n)) % n
                rhs = ((z + r * t2) * pow(b, -1, n) - (z + r * t1) * pow(a, -1, n)) % n
                if coef:
                    out.add(rhs * pow(coef, -1, n) % n)
    return {x for x in out if x and c.table[x] == P}


def run_e7(plan, seed, log):
    rng = random.Random(seed + "-e7")
    rec = dict(class_cases=0, class_same=0, class_sig_cases=0, class_sig_equal=0, ecdsa_cases=0, ecdsa_differ=0,
               fail=[], controls={})
    nc = dict(cases=0, fresh_wins=0, honest_fresh_wins=0)
    tr = dict(eligible=0, keyfree_valid=0, keyed_valid=0)
    lk = dict(cases=0, recovered=0, unsolvable=0, honest_cases=0, honest_recovered=0)
    for p in plan["curves"]:
        c = TL.Curve(p)
        n, B = c.n, c.B
        mask = {hc: rng.randrange(B) for hc in range(2)}
        for scheme in SCHEMES:
            hd = honest_ds(c, scheme)
            sig_ds = set(rng.sample(hd, min(plan["nd_sig"], len(hd))))
            for d in hd:
                P = c.table[d]
                for s in (1, -1):
                    for t in range(n):
                        phi, psi = (s, t), (-s, (-t) % n)
                        dr, dr2 = dphi(n, d, phi), dphi(n, d, psi)
                        if dr == 0:
                            if dr2 != 0:
                                rec["fail"].append(dict(p=p, d=d, phi=phi, why="class partner nonzero at a zero key"))
                            continue
                        Q1, Q2 = pub_phi(c, P, phi), pub_phi(c, P, psi)
                        if scheme == "bip340":
                            etab = {x: rng.randrange(n) for x in range(p)} if d in sig_ds else None
                            cx = TL.Ctx(c, scheme, dr, etab=etab)
                            cy = TL.Ctx(c, scheme, dr2, etab=etab)
                            same = (cx.d == cy.d and cx.P == cy.P and key_id(scheme, Q1) == key_id(scheme, Q2)
                                    and payload("honest", (cx.d, key_id(scheme, cx.P), d, 1, 0), mask)
                                    == payload("honest", (cy.d, key_id(scheme, cy.P), d, 1, 0), mask))
                            rec["class_cases"] += 1
                            rec["class_same"] += same
                            if not same:
                                rec["fail"].append(dict(p=p, d=d, phi=phi, why="class pair differs in key or payload"))
                            if d in sig_ds:
                                for kp in range(1, n):
                                    rec["class_sig_cases"] += 1
                                    ok = cx.sign_kp(None, None, kp) == cy.sign_kp(None, None, kp)
                                    rec["class_sig_equal"] += ok
                                    if not ok:
                                        rec["fail"].append(dict(p=p, d=d, phi=phi, kp=kp,
                                                                why="class pair signs differently"))
                                # control: no key classes. A signature under label phi verifies under label psi,
                                # so it would count as a fresh win for (psi, M)
                                for kp in range(1, n, max(1, n // 6)):
                                    sg = cx.sign_kp(None, None, kp)
                                    nc["cases"] += 1
                                    nc["fresh_wins"] += bip_verify(c, Q2, etab, (sg[3], sg[4]))
                                    # honest: freshness is indexed by class (the x-only key), so the pair is not fresh
                                    nc["honest_fresh_wins"] += (key_id(scheme, Q1) != key_id(scheme, Q2)
                                                                and bip_verify(c, Q2, etab, (sg[3], sg[4])))
                        else:
                            cx = TL.Ctx(c, scheme, dr, z=1)
                            cy = TL.Ctx(c, scheme, dr2, z=1)
                            rec["ecdsa_cases"] += 1
                            if key_id(scheme, Q1) != key_id(scheme, Q2) and cx.P != cy.P and \
                                    payload("honest", (cx.d, key_id(scheme, cx.P), d, 1, 0), mask) != \
                                    payload("honest", (cy.d, key_id(scheme, cy.P), d, 1, 0), mask):
                                rec["ecdsa_differ"] += 1
                            else:
                                rec["fail"].append(dict(p=p, d=d, phi=phi, why="ECDSA class pair gives one key"))
        # challenge hash without the key: (r, s) -> (r, s + a e) under the shifted key
        hd = honest_ds(c, "bip340")
        for d1 in rng.sample(hd, min(plan["nd_transfer"], len(hd))):
            for a in range(1, n):
                Q = c.add(c.table[d1], c.table[a])
                if Q is INF or Q[1] % 2 != 0:
                    continue               # the shifted key is the one with even y
                d2 = (d1 + a) % n
                for variant in ("key_free", "keyed"):
                    E1 = {x: rng.randrange(n) for x in range(p)}
                    E2 = E1 if variant == "key_free" else {x: rng.randrange(n) for x in range(p)}
                    c1 = TL.Ctx(c, "bip340", d1, etab=E1)
                    for kp in range(1, n):
                        sg = c1.sign_kp(None, None, kp)
                        r, sv = sg[3], sg[4]
                        tsig = (r, (sv + a * E1[r]) % n)
                        ok = bip_verify(c, Q, E2, tsig)
                        if variant == "key_free":
                            tr["eligible"] += 1
                            tr["keyfree_valid"] += ok
                        else:
                            tr["keyed_valid"] += ok
        # one nonce reused across two keys: the leak, and the same pairs under independent nonces
        for scheme in SCHEMES:
            hd = honest_ds(c, scheme)
            for d in rng.sample(hd, min(2, len(hd))):
                P = c.table[d]
                K = fam_size(c, scheme)
                fam = make_family(c, scheme, d, rng, K)
                z = rng.randrange(1, n)
                for i in range(K):
                    for j in range(K):
                        if i == j:
                            continue
                        E1 = {x: rng.randrange(n) for x in range(p)}
                        E2 = {x: rng.randrange(n) for x in range(p)}
                        ca = TL.Ctx(c, scheme, dphi(n, d, fam[i]), z=z, etab=E1 if scheme == "bip340" else None)
                        cb = TL.Ctx(c, scheme, dphi(n, d, fam[j]), z=z, etab=E2 if scheme == "bip340" else None)
                        for kp in range(1, n):
                            sa, sb = ca.sig_of_scalar(kp), cb.sig_of_scalar(kp)
                            if sa is None or sb is None:
                                continue
                            ea = E1[sa[0]] if scheme == "bip340" else None
                            eb = E2[sb[0]] if scheme == "bip340" else None
                            got = leak_d(c, scheme, P, fam[i], fam[j], sa, sb, ea, eb, z)
                            lk["cases"] += 1
                            if got == {d}:
                                lk["recovered"] += 1
                            else:
                                lk["unsolvable"] += 1
                            # honest: independent nonces
                            kq = rng.randrange(1, n)
                            sb2 = cb.sig_of_scalar(kq)
                            if sb2 is not None and kq != kp:
                                eb2 = E2[sb2[0]] if scheme == "bip340" else None
                                got2 = leak_d(c, scheme, P, fam[i], fam[j], sa, sb2, ea, eb2, z)
                                lk["honest_cases"] += 1
                                lk["honest_recovered"] += (got2 == {d})
        log(f"  E7 p={p} done")
    rec["controls"]["bip340_no_key_classes"] = dict(nc, detected=nc["fresh_wins"] > 0 and nc["honest_fresh_wins"] == 0)
    rec["controls"]["challenge_hash_without_key"] = dict(
        tr, detected=tr["eligible"] > 0 and tr["keyfree_valid"] == tr["eligible"] and tr["keyed_valid"] < tr["eligible"])
    rec["controls"]["nonce_reused_across_keys_leak"] = dict(
        lk, detected=lk["recovered"] > 0 and lk["recovered"] >= lk["cases"] - lk["unsolvable"]
        and lk["honest_recovered"] < lk["honest_cases"])
    return rec


# ------------------------------------------------------------------ E8: zero keys, adaptive naming

def run_e8(plan, seed, log):
    rng = random.Random(seed + "-e8")
    rec = dict(derivations=0, zero_keys=0, zero_detected=0, zero_d_recovered=0, nonzero_flagged=0, fail=[],
               stored_hits=0, found_at_naming=0, d_recovered=0, naive_found=0, decoys=0, decoy_hits=0)
    for p in plan["curves"]:
        c = TL.Curve(p)
        n, B = c.n, c.B
        for scheme in SCHEMES:
            mask = {hc: rng.randrange(B) for hc in range(3)}
            for d in honest_ds(c, scheme):
                P = c.table[d]
                alld = [(s, t) for s in (1, -1) for t in range(n)]
                for phi in alld:
                    rec["derivations"] += 1
                    Q = pub_phi(c, P, phi)
                    zero = dphi(n, d, phi) == 0
                    if zero:
                        rec["zero_keys"] += 1
                        rec["zero_detected"] += Q is INF
                        dd = (-phi[0] * phi[1]) % n
                        if Q is INF and dd == d and c.table[dd] == P:
                            rec["zero_d_recovered"] += 1
                        else:
                            rec["fail"].append(dict(p=p, scheme=scheme, d=d, phi=phi, why="zero key not caught"))
                    elif Q is INF:
                        rec["nonzero_flagged"] += 1
                        rec["fail"].append(dict(p=p, scheme=scheme, d=d, phi=phi, why="INF at nonzero d_phi"))
                # adaptive naming: F queries H_nonce on hidden-input payloads before naming the derivations
                live = [phi for phi in alld if dphi(n, d, phi) != 0]
                stored, decoys = {}, {}
                for phi in live:
                    cx = TL.Ctx(c, scheme, dphi(n, d, phi))
                    kid = key_id(scheme, cx.P)
                    for hc in range(3):
                        roots = [cx.d] + ([n - cx.d] if scheme == "bip340" else [])
                        for rt in roots:
                            stored.setdefault(kid, set()).add((rt ^ mask[hc], kid, 1, hc))
                # decoys: key fields never named, and cross-key masked secrets
                for _ in range(20):
                    t = rng.randrange(B)
                    kid = key_id(scheme, c.table[rng.randrange(1, n)])
                    decoys.setdefault(kid, set()).add((t, kid, 1, rng.randrange(3)))
                    rec["decoys"] += 1
                rec["stored_hits"] += sum(len(v) for v in stored.values())
                # naive B_adv: tests a query only against keys named before the query, none here
                rec["naive_found"] += 0
                order = live[:]
                rng.shuffle(order)
                named = {}
                for phi in order:
                    Q = pub_phi(c, P, phi)
                    kid = key_id(scheme, Q)
                    if kid in named:
                        continue                        # class partner or repeat: key already named
                    named[kid] = phi
                    idmap = {kid: phi}
                    for pl in stored.get(kid, ()):
                        h = bad1_hit(c, scheme, idmap, pl, mask)
                        if h is not None:
                            rec["found_at_naming"] += 1
                            if recover_d(c, scheme, P, phi, h[0]) == [d]:
                                rec["d_recovered"] += 1
                            else:
                                rec["fail"].append(dict(p=p, scheme=scheme, d=d, phi=phi, why="d not recovered"))
                # decoys: a payload is a hit only if its masked secret really is a root of the named key
                for kid, v in decoys.items():
                    if kid in named:
                        for pl in v:
                            if bad1_hit(c, scheme, {kid: named[kid]}, pl, mask) and pl[0] ^ mask[pl[3]] not in (
                                    [dphi(n, d, named[kid])] + ([n - dphi(n, d, named[kid])] if scheme == "bip340" else [])):
                                rec["decoy_hits"] += 1
        log(f"  E8 p={p} done")
    if rec["found_at_naming"] != rec["stored_hits"]:
        rec["fail"].append(dict(why="stored hits not all found at naming", stored=rec["stored_hits"],
                                found=rec["found_at_naming"]))
    return rec


# ------------------------------------------------------------------ driver

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    plan = PLANS["smoke" if args.smoke else "full"]
    out = os.path.join(HERE, "..", "..", ".work", "related_key", f"result{'_smoke' if args.smoke else ''}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    seed = "related-1-v1"
    t0 = time.time()
    log = lambda m: print(m, flush=True)       # noqa: E731
    print(f"related-key check {'SMOKE' if args.smoke else 'FULL'} plan: {json.dumps(plan, default=str)}")
    res = {}
    secs = {}
    for name, fn in (("E1", run_e1), ("E2", run_e2), ("E3", run_e3), ("E4", run_e4), ("E5", run_e5), ("E6", run_e6),
                     ("E7", run_e7), ("E8", run_e8)):
        t1 = time.time()
        res[name] = fn(plan[name.lower()], seed, log)
        secs[name] = time.time() - t1
    v = verdicts(res)
    order = ["E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8"]
    for k in order:
        print(f"{k} {'PASS' if v[k][0] else 'FAIL'} {v[k][1]}")
    ct = controls_summary(res)
    for name, r in ct.items():
        print(f"CONTROL {name}: {'DETECTED' if r['detected'] else 'NOT DETECTED'} by {r['by']}")
    overall_pass = all(v[k][0] for k in order) and all(r["detected"] for r in ct.values() if r["required"])
    for line in findings_of(res):
        print("FINDING", line)
    print(f"OVERALL {'PASS' if overall_pass else 'FAIL'}")
    rec = dict(smoke=args.smoke, plan=plan, seed=seed,
               verdicts={k: dict(passed=v[k][0], text=v[k][1]) for k in order}, controls=ct,
               overall="PASS" if overall_pass else "FAIL", findings=findings_of(res), seconds=dict(secs, total=time.time() - t0), results=res,
               notes=NOTES)
    with open(out, "w") as fh:
        json.dump(rec, fh, indent=1, default=jdefault, sort_keys=True)
    print(f"wrote {out} in {time.time() - t0:.0f}s")
    return 0 if overall_pass else 1


NOTES = [
    "E6 reading (b), host holds the tweaked key pk_phi' chosen at step 4, is the one that can detect a nonce shared "
    "between tweaks; reading (a), host keeps pk_phi, fails in every model because the signature is made under d_phi'.",
    "E6 sums over the H_point cells use the identity sum_{t,t'} F(k0+t, k1+t') = sum_{w,w'} F(w, w') for k0 != k1 and "
    "the diagonal sum when R0 coincide; checked against nested loops on the brute_curves.",
    "E1 TV is computed per k-vector in closed form; on brute_curves it is cross-checked against full enumeration of "
    "the nonce-table cells and the H_point cells.",
]


def verdicts(res):
    v = {}
    e1 = res["E1"]
    honest = [g for g in e1["groups"] if g["variant"] == "honest"]
    v["E1"] = (not e1["fail"] and e1["cases"] > 0,
               f"{len(honest)} honest context sets over {len({(g['p'], g['scheme'], g['d']) for g in honest})} (curve, scheme, key) cells; "
               f"joint TV equals independence prediction exactly in all; max coincidence prob "
               f"{float(max(g['p_coincidence'] for g in honest)):.4f} <= bound; fail={len(e1['fail'])}")
    e2 = res["E2"]
    v["E2"] = (not e2["fail"] and e2["cases"] > 0,
               f"{e2['cases']} single-context cases ({e2['sigma_minus_cases']} with sigma=-1), {e2['joint_cases']} "
               f"two-key joint cases; TV(sim, device)=0 exactly; ECDSA max_bad={e2['max_bad']} (<=8), "
               f"max TV(G3, sim)={float(e2['max_tv_g3_g5_ecdsa']):.4g}; fail={len(e2['fail'])}")
    e3 = res["E3"]
    cl = e3["classes"]
    v["E3"] = (not e3["fail"] and e3["cases"] > 0,
               f"{e3['cases']} coincident non-class pairs, d recovered in all; {cl.get('class_pairs_excluded', 0)} "
               f"same-class pairs excluded; d coefficient of the holding equation: {dict(e3['coefficient_hist'])}; "
               f"fail={len(e3['fail'])}")
    e4 = res["E4"]
    v["E4"] = (not e4["fail"] and e4["single"] > 0,
               f"{e4['single']} single-derivation extractions, d recovered; {e4['scan_cases']} scans, "
               f"{e4['scan_hits']} hits == {e4['scan_expected_hits']} expected; other-root hits "
               f"{e4['other_root_hits']}/{e4['other_root_cases']}; cross-key hits {e4['cross_key_hits']}/"
               f"{e4['cross_key_payloads']}; fail={len(e4['fail'])}")
    e5 = res["E5"]
    v["E5"] = (not e5["fail"] and e5["cases"] > 0 and e5["relation_holds"] == e5["cases"] and e5["discriminates"],
               f"{e5['cases']} (d, a, z, k) cases, relation holds in {e5['relation_holds']}; wrong-sign relation valid "
               f"in {e5['wrong_sign_valid']}; flipped-sigma relation {e5['flipped_holds']}/{e5['flipped_cases']}")
    e6 = res["E6"]
    off = [r for r in e6["rows"] if r["phi"] != r["phi2"]]
    acc = sum(r["new"] for r in off)
    pt = sum(r["pt"] for r in off)
    sg = sum(r["signed"] for r in off)
    v["E6"] = (not e6["fail"] and len(off) > 0,
               f"{len(e6['rows'])} (phi, phi') rows, {len(off)} switched; of {sg} signed weight, step 5 with the new key "
               f"accepted {acc} (all point coincidences W'=+-W; coincidences {pt}); fail={len(e6['fail'])}")
    e7 = res["E7"]
    v["E7"] = (not e7["fail"] and e7["class_cases"] > 0 and e7["class_same"] == e7["class_cases"]
               and e7["class_sig_equal"] == e7["class_sig_cases"] and e7["ecdsa_differ"] == e7["ecdsa_cases"],
               f"BIP340 class pairs {e7['class_same']}/{e7['class_cases']} give one key, normalized secret and nonce payload; "
               f"identical signatures {e7['class_sig_equal']}/{e7['class_sig_cases']}; ECDSA pairs giving different keys "
               f"and payloads {e7['ecdsa_differ']}/{e7['ecdsa_cases']}; fail={len(e7['fail'])}")
    e8 = res["E8"]
    v["E8"] = (not e8["fail"] and e8["zero_keys"] > 0 and e8["zero_detected"] == e8["zero_keys"]
               and e8["stored_hits"] > 0 and e8["decoy_hits"] == 0,
               f"{e8['zero_keys']} zero keys of {e8['derivations']} derivations, all at infinity and d = -sigma tau recovered "
               f"({e8['zero_d_recovered']}); {e8['found_at_naming']}/{e8['stored_hits']} bad1 hits stored before naming found "
               f"at naming, d recovered {e8['d_recovered']}; decoy hits {e8['decoy_hits']}; fail={len(e8['fail'])}")
    return v


def findings_of(res):
    out = []
    e1v = res["E1"]["variants"].get("pk_omitted", {})
    lit = res["E6"]["controls"].get("pk_omitted_literal", {})
    out.append(f"pk omitted from the nonce hash (removed control, literal model keeping the masked secret): E1 flagged "
               f"{e1v.get('flagged')} of {e1v.get('rows')} rows, E6 flagged {lit.get('detected')} of {lit.get('rows')} rows; "
               f"nothing changes, as expected")
    return out


def controls_summary(res):
    out = {}
    e2c = res["E2"]["controls"]
    e3c = res["E3"]["controls"]
    e4c = res["E4"]["controls"]
    e1v = res["E1"]["variants"]
    e6c = res["E6"]["controls"]

    def e2(name):
        r = e2c.get(name)
        return bool(r and r["cases"] and r["detected"] > 0), r

    d, r = e2("wrong_key_P_phi")
    out["simulator_uses_wrong_key_P_phi"] = dict(required=True, detected=d, by=["E2"] if d else [], detail=r)
    d1, r1 = e2("reuse_signature_across_keys")
    d2, r2 = e2("reuse_nonce_across_keys_joint")
    out["simulator_reuses_one_signature_across_keys"] = dict(
        required=True, detected=d1 and d2, by=[x for x, ok in (("E2 marginal", d1), ("E2 joint", d2)) if ok],
        detail=dict(signature_reuse=r1, nonce_reuse_joint=r2))
    root = e6c.get("shared_nonce_info", dict(rows=0, detected=0))
    sn = e1v.get("shared_nonce", dict(flagged=0))
    lk = res["E7"]["controls"]["nonce_reused_across_keys_leak"]
    out["one_nonce_reused_across_two_keys"] = dict(
        # E1 and the leak solver must both detect it. E6 is reported only.
        required=True, detected=bool(sn["flagged"] and lk["detected"]),
        by=[x for x, ok in (("E1", sn["flagged"]), ("E7 leak", lk["detected"])) if ok],
        detail=dict(E1=sn, E6_reported_only=root, E7_leak=lk))
    ch = res["E7"]["controls"]["challenge_hash_without_key"]
    out["challenge_hash_without_key"] = dict(required=True, detected=ch["detected"], by=["E7"] if ch["detected"] else [],
                                             detail=ch)
    nk = res["E7"]["controls"]["bip340_no_key_classes"]
    out["bip340_no_key_classes"] = dict(required=True, detected=nk["detected"], by=["E7"] if nk["detected"] else [],
                                        detail=nk)
    s2, rs2 = e2("sigma_ignored")
    s3 = e3c["sigma_ignored"]["detected"]
    s4 = e4c["sigma_ignored"]["detected"]
    out["sigma_ignored"] = dict(required=True, detected=s2 or s3 or s4,
                                by=[x for x, ok in (("E2", s2), ("E3", s3), ("E4", s4)) if ok],
                                detail=dict(E2=rs2, E3=e3c["sigma_ignored"], E4=e4c["sigma_ignored"]))
    n1 = e1v.get("no_phi", dict(flagged=0))
    n2, rn2 = e2("context_keyed_without_phi")
    out["context_keyed_without_phi"] = dict(required=True, detected=bool(n1["flagged"] or n2),
                                            by=[x for x, ok in (("E1", n1["flagged"]), ("E2", n2)) if ok],
                                            detail=dict(E1=n1, E2=rn2))
    return out


if __name__ == "__main__":
    sys.exit(main())
