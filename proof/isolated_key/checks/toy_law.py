"""Part A: exact laws on toy curves. Standard library only, Fractions throughout.

Each game hop of proof/isolated_key/isolated_theorem.md, is written as a function that
returns the exact law of one context's outcome `(status, R0, u_full, r, s)` as a dict of Fractions.
"""
import random
from collections import Counter
from fractions import Fraction

INF = None


def is_prime(v):
    if v < 2:
        return False
    i = 2
    while i * i <= v:
        if v % i == 0:
            return False
        i += 1
    return True


class Curve:
    """y^2 = x^3 + 7 over F_p. n counts the point at infinity. B is the smallest power of 2 above n."""

    def __init__(self, p):
        self.p = p
        self.points = [(x, y) for x in range(p) for y in range(p) if (y * y - x * x * x - 7) % p == 0]
        self.n = len(self.points) + 1
        self.G = self.points[0]
        self.B = 1
        while self.B <= self.n:
            self.B *= 2
        self.g = self.B - self.n
        self.table = [INF]
        for _ in range(1, self.n):
            self.table.append(self.add(self.table[-1], self.G))
        self.dlog = {pt: k for k, pt in enumerate(self.table)}
        self.x_ge_n_points = sum(1 for pt in self.points if pt[0] >= self.n)
        self.xs = {pt[0] for pt in self.points}

    def add(self, a, b):
        p = self.p
        if a is INF:
            return b
        if b is INF:
            return a
        if a[0] == b[0] and (a[1] + b[1]) % p == 0:
            return INF
        if a == b:
            m = 3 * a[0] * a[0] * pow(2 * a[1], -1, p) % p
        else:
            m = (b[1] - a[1]) * pow(b[0] - a[0], -1, p) % p
        x = (m * m - a[0] - b[0]) % p
        return (x, (m * (a[0] - x) - a[1]) % p)

    def neg(self, a):
        return INF if a is INF else (a[0], (-a[1]) % self.p)

    def smul(self, k, pt):
        """Double and add. Used where the caller must not use the discrete-log table."""
        k %= self.n
        acc = INF
        while k:
            if k & 1:
                acc = self.add(acc, pt)
            pt = self.add(pt, pt)
            k >>= 1
        return acc


# The toy curves of the full run: p, n=#E. All have prime n.
CURVES_FULL = [13, 43, 79, 97, 67, 61, 127]
CURVES_SMOKE = [13, 43, 97]


def find_toy_curves():
    out = []
    for p in range(5, 400):
        if is_prime(p) and p % 3 == 1:
            pts = sum(1 for x in range(p) for y in range(p) if (y * y - x * x * x - 7) % p == 0)
            if is_prime(pts + 1):
                out.append((p, pts + 1))
    return out


# ---------------------------------------------------------------- laws

class LawAcc:
    """Accumulate exact weights. Weights are grouped by value so Fractions are added once per outcome."""

    def __init__(self):
        self.parts = {}

    def add(self, outcome, w, cnt=1):
        if w == 0:
            return
        self.parts.setdefault(w, Counter())[outcome] += cnt

    def law(self):
        tot = {}
        for w, c in self.parts.items():
            for o, k in c.items():
                tot[o] = tot.get(o, 0) + w * k
        return tot


def tv(l1, l2):
    keys = set(l1) | set(l2)
    s = sum(abs(l1.get(k, 0) - l2.get(k, 0)) for k in keys)
    return Fraction(s) / 2


def total(law):
    return sum(law.values(), Fraction(0))


class Ctx:
    """One context: a scheme, a key, and for ECDSA a message scalar z or for BIP340 the H_chal row."""

    def __init__(self, c, scheme, d_raw, z=None, etab=None):
        self.c, self.scheme, self.n = c, scheme, c.n
        self.z, self.etab = z, etab
        if scheme == "bip340":
            P_raw = c.table[d_raw]
            if P_raw[1] % 2 == 0:
                self.d, self.P = d_raw, P_raw
            else:
                self.d, self.P = c.n - d_raw, c.neg(P_raw)
        else:
            self.d, self.P = d_raw, c.table[d_raw]

    def outcome(self, k0, u):
        """O2 for given base value k0 (None = base failure) and u_full. k0 = 0 is allowed for controls."""
        c, n = self.c, self.n
        if k0 is None:
            return ("base_fail", None, None, None, None)
        R0 = c.table[k0]
        if u >= n:
            return ("u_fail", R0, u, None, None)
        kp = (k0 + u) % n
        if kp == 0:
            return ("kp_zero", R0, u, None, None)
        return self.sign_kp(R0, u, kp)

    def sign_kp(self, R0, u, kp):
        c, n = self.c, self.n
        W = c.table[kp]
        if self.scheme == "bip340":
            k = kp if W[1] % 2 == 0 else n - kp
            r = W[0]
            return ("ok", R0, u, r, (k + self.etab[r] * self.d) % n)
        r = W[0] % n
        if r == 0:
            return ("rs_fail", R0, u, None, None)
        s = pow(kp, -1, n) * (self.z + r * self.d) % n
        if s == 0:
            return ("rs_fail", R0, u, None, None)
        if s > (n - 1) // 2:
            s = n - s
        return ("ok", R0, u, r, s)

    def sig_of_scalar(self, kp):
        """(r, s) the device or Sign_Rand produces for nonce scalar kp, or None."""
        o = self.sign_kp(None, None, kp)
        return (o[3], o[4]) if o[0] == "ok" else None

    def good_scalars(self):
        """ECDSA K_good(M, d). BIP340: every nonzero scalar."""
        if self.scheme == "bip340":
            return list(range(1, self.n))
        return [k for k in range(1, self.n) if self.sig_of_scalar(k) is not None]


def base_law(ctx, kind):
    """Law of the base outcome as dict k0 -> Fraction, None = failure.
    kind 'real': X uniform on [0,B), BIP340 k0 = X mod n (fail if 0), ECDSA k0 = X (fail if 0 or >= n).
    kind 'g2': BIP340 only. Fail with exact probability 2/B, else uniform on Z_n*."""
    c = ctx.c
    n, B = c.n, c.B
    law = {}
    if kind == "real":
        for X in range(B):
            if ctx.scheme == "bip340":
                k0 = X % n or None
            else:
                k0 = X if 0 < X < n else None
            law[k0] = law.get(k0, 0) + Fraction(1, B)
    else:
        assert ctx.scheme == "bip340"
        law[None] = Fraction(2, B)
        for k0 in range(1, n):
            law[k0] = Fraction(B - 2, B * (n - 1))
    return law


def cond_base(base):
    f = base.get(None, Fraction(0))
    return {k: w / (1 - f) for k, w in base.items() if k is not None}


def g3_law(ctx, base):
    """G3, resolved context: base outcome and u_full from fresh independent randomness."""
    B = ctx.c.B
    acc = LawAcc()
    for k0, w in base.items():
        if k0 is None:
            acc.add(ctx.outcome(None, None), w)
        else:
            for u in range(B):
                acc.add(ctx.outcome(k0, u), w / B)
    return acc.law()


def g4_law(ctx, base, good=None, pb2=None, u_excl=True):
    """G4 (good=None), G4' (good = list for K_good). Steps 1 to 3 of the proof. pb2 and u_excl are
    only for the deliberately wrong samplers of A5."""
    c = ctx.c
    n, B, g = c.n, c.B, c.g
    f = base.get(None, Fraction(0))
    non = 1 - f
    p2 = Fraction(g, B) if pb2 is None else pb2
    p3 = 1 - p2
    acc = LawAcc()
    acc.add(ctx.outcome(None, None), f)
    if p2 and g:
        w = non * p2 / ((n - 1) * g)
        for k0 in range(1, n):
            for u in range(n, B):
                acc.add(ctx.outcome(k0, u), w)
    # step 3: k' uniform on Z_n (G4), or 0 with prob 1/n and uniform on K_good otherwise (G4')
    if good is None:
        kps = [(kp, Fraction(1, n)) for kp in range(n)]
    else:
        kps = [(0, Fraction(1, n))] + [(kp, Fraction(n - 1, n) / len(good)) for kp in good]
    for kp, wk in kps:
        us = [u for u in range(n) if u != kp] if u_excl else list(range(n))
        w = non * p3 * wk / len(us)
        for u in us:
            acc.add(ctx.outcome((kp - u) % n, u), w)
    return acc.law()


def sign_rand_list(ctx):
    """Sign_Rand: law is uniform over this list of nonces. Returns [(k_s, (r,s))]."""
    out = []
    for k in ctx.good_scalars():
        out.append((k, ctx.sig_of_scalar(k)))
    return out


def sim_nonce_point(ctx, sig):
    """The simulator's step: from a signature to the point V, without d. BIP340: V = sG - eP, with the
    even-y public point. ECDSA: V = s^-1 (zG + rP)."""
    c, n = ctx.c, ctx.n
    r, s = sig
    if ctx.scheme == "bip340":
        e = ctx.etab[r]
        return c.add(c.smul(s, c.G), c.neg(c.smul(e, ctx.P)))
    si = pow(s, -1, n)
    return c.add(c.smul(si * ctx.z % n, c.G), c.smul(si * r % n, ctx.P))


def g5_law(ctx, base, fair=True, redraw=True, stats=None):
    """G5: resolved context, branch 3 with k' != 0 answered from Sign_Rand. Everything else is a coin the
    simulator holds, with the same weights as G4'. `fair` and `redraw` are switched off for controls."""
    c = ctx.c
    n, B, g = c.n, c.B, c.g
    f = base.get(None, Fraction(0))
    non = 1 - f
    acc = LawAcc()
    acc.add(ctx.outcome(None, None), f)
    w2 = non * Fraction(g, B) / ((n - 1) * g)
    for k0 in range(1, n):
        for u in range(n, B):
            acc.add(ctx.outcome(k0, u), w2)
    # k' = 0 coin
    w0 = non * Fraction(n, B) * Fraction(1, n) / (n - 1)
    for u in range(1, n):
        acc.add(ctx.outcome((-u) % n, u), w0)
    # k' != 0 from Sign_Rand
    sr = sign_rand_list(ctx)
    pnz = non * Fraction(n - 1, B)
    bs = (0, 1) if fair else (0,)
    for ks, sig in sr:
        V = sim_nonce_point(ctx, sig)
        if stats is not None:
            stats["sig_n"] += 1
            if V is INF or (ctx.scheme == "bip340" and (V[1] % 2 != 0 or V[0] != sig[0])):
                stats["V_bad"] += 1
            if ctx.scheme == "ecdsa" and V not in (c.table[ks], c.neg(c.table[ks])):
                stats["V_not_pm_W"] += 1
        for b in bs:
            W = V if b == 0 else c.neg(V)
            us = [u for u in range(n) if c.table[u] != W] if redraw else list(range(n))
            w = pnz / len(sr) / len(bs) / len(us)
            for u in us:
                R0 = c.add(W, c.neg(c.table[u]))
                if R0 is INF:
                    acc.add(("kp_zero", None, u, None, None), w)
                    continue
                acc.add(("ok", R0, u, sig[0], sig[1]), w)
                if stats is not None and ctx.scheme == "ecdsa":
                    k0 = c.dlog[R0]
                    kp = (k0 + u) % n
                    if ctx.sig_of_scalar(kp) != sig:
                        stats["cached_sig_differs"] += 1
    return acc.law()


# ---------------------------------------------------------------- the five items

def beta_formula(n, B):
    g = B - n
    return Fraction((g - 1) * (n - g), (B - 2) * (n - 1))


def xlift_stats(ctx, law):
    """Mass of ok outcomes with x(W) >= n, and of those where the other lift (x +- n) is also on the curve."""
    c, n = ctx.c, ctx.n
    mass = Fraction(0)
    alt = Fraction(0)
    for (st, R0, u, r, s), w in law.items():
        if st != "ok":
            continue
        W = c.add(R0, c.table[u])
        x = W[0]
        if x >= n:
            mass += w
        other = [x + n, x - n]
        if any(xo in c.xs for xo in other):
            alt += w
    return mass, alt


def key_list(c, rng, nkeys):
    n = c.n
    ks = []
    for k in (1, n // 2, n - 1, 2):
        if 0 < k < n and k not in ks:
            ks.append(k)
    ks = ks[:nkeys]
    while len(ks) < min(nkeys, n - 1):
        k = rng.randrange(1, n)
        if k not in ks:
            ks.append(k)
    return ks


def z_list(c, d, rng, nz):
    """Message scalars: 0, 1, n-1, the two that maximise the bad-scalar count (z = -r d), and random ones."""
    n = c.n
    zs = [0, 1, n - 1]
    cands = []
    for r in range(n):
        z = (-r * d) % n
        ctx = Ctx(c, "ecdsa", d, z=z)
        cands.append((-(n - 1 - len(ctx.good_scalars())), r, z))
    cands.sort()
    zs += [cands[0][2], cands[1][2]]
    while len(set(zs)) < nz:
        zs.append(rng.randrange(n))
    out = []
    for z in zs:
        if z not in out:
            out.append(z)
    return out[:nz] if len(out) >= nz else out


def run_part_a(plan, log=print):
    """plan: dict(curves, nkeys, nz, netab, ncontrol, seed). Returns dict of per item results."""
    rng = random.Random(plan["seed"])
    res = {
        "A1": {"cases": 0, "fail": [], "max_tv": "0"},
        "A2": {"curves": [], "fail": []},
        "A3": {"cases": 0, "fail": [], "max_bad": 0, "cond_tv_exceeds_bad_over_n": 0, "cond_tv_cases_with_bad": 0,
               "full_tv_le_bad_over_n_all": True, "bad_hist": {}},
        "A4": {"cases": 0, "fail": [], "kgood_not_neg_closed": 0, "V_bad": 0, "V_not_pm_W": 0,
               "cached_sig_differs": 0, "sign_rand_sigs": 0},
        "A5": {"controls": {}, "fail": []},
        "curves": [],
        "assumptions": [],
    }
    controls_done = Counter()
    for p in plan["curves"]:
        c = Curve(p)
        n, B, g = c.n, c.B, c.g
        assert is_prime(n)
        # assumption audit for the beta derivation and for zero's preimages
        pre = Counter(X % n for X in range(B))
        nz_ok = all(pre[v] in (1, 2) for v in range(1, n))
        zero_ok = pre[0] == 2
        half_ok = 2 * n > B
        cinfo = {"p": p, "n": n, "B": B, "g": g, "n_gt_B_half": half_ok, "nonzero_preimages_1_or_2": nz_ok,
                 "zero_has_two_preimages": zero_ok, "p_gt_n": p > n, "points_with_x_ge_n": c.x_ge_n_points,
                 "points_total": len(c.points), "frac_points_x_ge_n": c.x_ge_n_points / len(c.points),
                 "beta": str(beta_formula(n, B))}
        res["curves"].append(cinfo)
        if not (nz_ok and zero_ok and half_ok):
            res["assumptions"].append(cinfo)
        keys = key_list(c, rng, plan["nkeys"])
        log(f"  curve p={p} n={n} B={B} g={g} keys={keys}")
        # A2, curve level, base law BIP340 and ECDSA
        ctx0 = Ctx(c, "bip340", keys[0], etab={x: rng.randrange(n) for x in range(p)})
        real = base_law(ctx0, "real")
        g2 = base_law(ctx0, "g2")
        tv_base = tv(real, g2)
        l_real, l_g2 = g3_law(ctx0, real), g3_law(ctx0, g2)
        tv_full = tv(l_real, l_g2)
        bf = beta_formula(n, B)

        def cond(law):
            fail = law.get(("base_fail", None, None, None, None), Fraction(0))
            return {o: w / (1 - fail) for o, w in law.items() if o[0] != "base_fail"}

        # "Given nonzero" is the proof's wording: the conditional TV is what beta is.
        tv_base_cond = tv(cond_base(real), cond_base(g2))
        tv_full_cond = tv(cond(l_real), cond(l_g2))
        ok = (tv_base_cond == bf and tv_full_cond == bf and tv_base <= bf and tv_full <= bf
              and total(real) == 1 and total(g2) == 1)
        ctxe = Ctx(c, "ecdsa", keys[0], z=1)
        er = base_law(ctxe, "real")
        e_ok = er.get(None) == Fraction(g + 1, B) and all(er[k] == Fraction(1, B) for k in range(1, n))
        rec = {"p": p, "n": n, "B": B, "g": g, "tv_base_given_nonzero": str(tv_base_cond),
               "tv_context_law_given_nonzero": str(tv_full_cond), "tv_base_unconditional": str(tv_base),
               "tv_context_law_unconditional": str(tv_full),
               "unconditional_over_beta": (str(tv_base / bf) if bf else "n/a (beta=0)"),
               "beta": str(bf), "equal": ok, "ecdsa_valid_range_uniform_and_fail_exact": e_ok,
               "assumptions_hold": nz_ok and zero_ok and half_ok}
        res["A2"]["curves"].append(rec)
        if not ok or not e_ok:
            res["A2"]["fail"].append(rec)
        for d_raw in keys:
            # ---------------- BIP340
            for _ in range(plan["netab"]):
                etab = {x: rng.randrange(n) for x in range(p)}
                ctx = Ctx(c, "bip340", d_raw, etab=etab)
                base = base_law(ctx, "g2")
                l3, l4 = g3_law(ctx, base), g4_law(ctx, base)
                st = {"sig_n": 0, "V_bad": 0, "V_not_pm_W": 0, "cached_sig_differs": 0}
                l5 = g5_law(ctx, base, stats=st)
                t1, t4 = tv(l3, l4), tv(l4, l5)
                res["A1"]["cases"] += 1
                res["A4"]["cases"] += 1
                if t1 != 0 or total(l3) != 1 or total(l4) != 1:
                    res["A1"]["fail"].append({"scheme": "bip340", "p": p, "d": d_raw, "tv": str(t1)})
                if t4 != 0 or total(l5) != 1:
                    res["A4"]["fail"].append({"scheme": "bip340", "p": p, "d": d_raw, "tv": str(t4)})
                res["A4"]["V_bad"] += st["V_bad"]
                res["A4"]["sign_rand_sigs"] += st["sig_n"]
                if controls_done[("bip340", p)] < plan["ncontrol"]:
                    controls_done[("bip340", p)] += 1
                    run_controls(res["A5"], ctx, base, l3, "bip340", p, None)
            # ---------------- ECDSA
            for z in z_list(c, d_raw, rng, plan["nz"]):
                ctx = Ctx(c, "ecdsa", d_raw, z=z)
                good = ctx.good_scalars()
                bad = n - 1 - len(good)
                base = base_law(ctx, "real")
                l3, l4 = g3_law(ctx, base), g4_law(ctx, base)
                l4p = g4_law(ctx, base, good=good)
                st = {"sig_n": 0, "V_bad": 0, "V_not_pm_W": 0, "cached_sig_differs": 0}
                l5 = g5_law(ctx, base, stats=st)
                t1, t3, t4 = tv(l3, l4), tv(l4, l4p), tv(l4p, l5)
                neg_closed = set(good) == {(n - k) % n for k in good}
                res["A1"]["cases"] += 1
                res["A3"]["cases"] += 1
                res["A4"]["cases"] += 1
                if t1 != 0 or total(l3) != 1 or total(l4) != 1:
                    res["A1"]["fail"].append({"scheme": "ecdsa", "p": p, "d": d_raw, "z": z, "tv": str(t1)})
                # A3: the whole-context law, and the law conditional on (branch 3, k' != 0)
                cond_tv = Fraction(bad, n - 1)
                res["A3"]["bad_hist"][str(bad)] = res["A3"]["bad_hist"].get(str(bad), 0) + 1
                res["A3"]["max_bad"] = max(res["A3"]["max_bad"], bad)
                if bad:
                    res["A3"]["cond_tv_cases_with_bad"] += 1
                    if cond_tv > Fraction(bad, n):
                        res["A3"]["cond_tv_exceeds_bad_over_n"] += 1
                if not (t3 <= Fraction(bad, n)):
                    res["A3"]["full_tv_le_bad_over_n_all"] = False
                    res["A3"]["fail"].append({"p": p, "d": d_raw, "z": z, "tv": str(t3), "bad": bad, "why": "full TV > bad/n"})
                if bad > 8:
                    res["A3"]["fail"].append({"p": p, "d": d_raw, "z": z, "bad": bad, "why": "bad > 8"})
                # the conditional TV measured exactly: law given the branch, from the two laws
                if total(l4p) != 1 or total(l5) != 1:
                    res["A4"]["fail"].append({"scheme": "ecdsa", "p": p, "d": d_raw, "z": z, "why": "not normalised"})
                if t4 != 0:
                    res["A4"]["fail"].append({"scheme": "ecdsa", "p": p, "d": d_raw, "z": z, "tv": str(t4)})
                if not neg_closed:
                    res["A4"]["kgood_not_neg_closed"] += 1
                    res["A4"]["fail"].append({"scheme": "ecdsa", "p": p, "d": d_raw, "z": z, "why": "K_good not closed under negation"})
                for k in ("V_bad", "V_not_pm_W", "cached_sig_differs"):
                    res["A4"][k] += st[k]
                res["A4"]["sign_rand_sigs"] += st["sig_n"]
                if st["V_not_pm_W"] or st["cached_sig_differs"]:
                    res["A4"]["fail"].append({"scheme": "ecdsa", "p": p, "d": d_raw, "z": z, "why": "V != +-W or cached sig differs", **st})
                if "xlift" not in cinfo:
                    cinfo["xlift"] = {"cases": 0, "mass_x_ge_n": Fraction(0), "mass_alt_lift": Fraction(0)}
                m_, a_ = xlift_stats(ctx, l4p)
                cinfo["xlift"]["cases"] += 1
                cinfo["xlift"]["mass_x_ge_n"] += m_
                cinfo["xlift"]["mass_alt_lift"] += a_
                if controls_done[("ecdsa", p)] < plan["ncontrol"]:
                    controls_done[("ecdsa", p)] += 1
                    run_controls(res["A5"], ctx, base, l4p, "ecdsa", p, good)
            res["A1"]["max_tv"] = "0"
        if "xlift" in cinfo:
            x = cinfo["xlift"]
            x["mean_mass_x_ge_n"] = float(x["mass_x_ge_n"] / x["cases"])
            x["mean_mass_alt_lift"] = float(x["mass_alt_lift"] / x["cases"])
            x["mass_x_ge_n"] = str(x["mass_x_ge_n"])
            x["mass_alt_lift"] = str(x["mass_alt_lift"])
    return res


def run_controls(a5, ctx, base, ref, scheme, p, good):
    """Deliberately wrong samplers. Each must differ from the reference law, TV > 0."""
    n = ctx.n
    wrong = {}
    wrong["u_not_excluding_k'"] = (
        g4_law(ctx, base, good=good, u_excl=False) if scheme == "ecdsa" else g4_law(ctx, base, u_excl=False))
    wrong["no_fair_sign"] = g5_law(ctx, base, fair=False)
    wrong["old_invalid_branch_handling"] = g5_law(ctx, base, redraw=False)
    wrong["u_ge_n_branch_dropped"] = (
        g4_law(ctx, base, good=good, pb2=Fraction(0)) if scheme == "ecdsa" else g4_law(ctx, base, pb2=Fraction(0)))
    for name, law in wrong.items():
        t = tv(ref, law)
        rec = a5["controls"].setdefault(f"{scheme}:{name}", {"cases": 0, "min_tv": None, "all_positive": True})
        rec["cases"] += 1
        tvf = float(t)
        rec["min_tv"] = tvf if rec["min_tv"] is None else min(rec["min_tv"], tvf)
        if t <= 0:
            rec["all_positive"] = False
            a5["fail"].append({"control": f"{scheme}:{name}", "p": p, "n": n, "tv": str(t)})
