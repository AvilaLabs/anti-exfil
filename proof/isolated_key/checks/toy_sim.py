"""Part B: a real table-oracle game, and the reduction's simulator, which is never given d.

The real game (`RealGame`) answers every oracle of isolated_theorem.md Section 1 from lazily sampled tables.
The simulator (`Reduction`) is the reduction B_adv of isolated_theorem.md: G5 sampling for resolved non-reserved contexts,
concrete G4/G4' sampling for reserved and unresolved contexts, the rank guess, abort, ECDSA alias rule.
Standard library only.
"""
import ast
import hashlib
import inspect
import math
import os
import random
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from toy_law import INF, Ctx, Curve  # noqa: E402

HB = 2  # classes for hash outputs in transcript cells
QC = 3  # classes per point or signature in coarse cells
MSGS = (1, 2, 3, 4)


def seed_of(label):
    return int.from_bytes(hashlib.sha256(label.encode()).digest()[:8], "big")


# ---------------------------------------------------------------- statistics

def _gser(a, x):
    ap, s = a, 1.0 / a
    d = s
    for _ in range(100000):
        ap += 1
        d *= x / ap
        s += d
        if abs(d) < abs(s) * 1e-16:
            break
    return s * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gcf(a, x):
    tiny = 1e-300
    b = x + 1 - a
    c = 1 / tiny
    d = 1 / b
    h = d
    for i in range(1, 100000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = tiny if abs(d) < tiny else d
        c = b + an / c
        c = tiny if abs(c) < tiny else c
        d = 1 / d
        de = d * c
        h *= de
        if abs(de - 1) < 1e-16:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def chi2_sf(x, k):
    if k <= 0:
        return 1.0
    if x <= 0:
        return 1.0
    a, xx = k / 2.0, x / 2.0
    if xx < a + 1:
        return max(0.0, 1.0 - _gser(a, xx))
    return _gcf(a, xx)


def binom_tail(n, p, c):
    """P[Bin(n,p) >= c]."""
    if c <= 0 or p >= 1:
        return 1.0
    if p <= 0:
        return 0.0
    lp, lq = math.log(p), math.log1p(-p)
    lg = math.lgamma
    tot = 0.0
    for k in range(c, n + 1):
        t = math.exp(lg(n + 1) - lg(k + 1) - lg(n - k + 1) + k * lp + (n - k) * lq)
        tot += t
        if t < tot * 1e-17 and k > n * p:
            break
    return min(1.0, tot)


def two_sample_chi2(a, b, pool=10):
    """a, b: Counters over cells, equal numbers of runs. Cells with a+b < pool are merged into one.
    Statistic sum (a-b)^2/(a+b), df = number of cells (the excluded bad-run mass absorbs the constraint)."""
    stat, df, rare_a, rare_b = 0.0, 0, 0, 0
    for k in set(a) | set(b):
        x, y = a.get(k, 0), b.get(k, 0)
        if x + y < pool:
            rare_a += x
            rare_b += y
        else:
            stat += (x - y) ** 2 / (x + y)
            df += 1
    if rare_a + rare_b > 0:
        df += 1
        if rare_a + rare_b > 0:
            stat += (rare_a - rare_b) ** 2 / (rare_a + rare_b)
    return {"stat": stat, "df": df, "p": chi2_sf(stat, df), "cells": len(set(a) | set(b)),
            "na": sum(a.values()), "nb": sum(b.values())}


# ---------------------------------------------------------------- setting, shared tables, signer

class PublicCurve:
    """What the reduction may use of the group: arithmetic and multiples of G. No discrete-log table."""

    def __init__(self, c):
        self.p, self.n, self.B, self.g, self.G = c.p, c.n, c.B, c.g, c.G
        self.table = tuple(c.table)
        self.add, self.neg, self.smul = c.add, c.neg, c.smul


class Shared:
    """The shared H_chal (BIP340) or H_msg (ECDSA) table, public to both games."""

    def __init__(self, scheme, n, etab, msgtab):
        self.scheme, self.n, self.etab, self.msgtab = scheme, n, etab, msgtab

    def digest(self, M):
        return M if self.scheme == "bip340" else self.msgtab[M]

    def z(self, M):
        return self.msgtab[M] % self.n

    def chal(self, r, m):
        return self.etab[(r, m)]


class Setting:
    """One honest key, the shared tables, and the curve. Holds d: only the real game, Sign_Rand and the
    helper receive it."""

    def __init__(self, c, scheme, kind, seed):
        self.c, self.scheme, self.kind = c, scheme, kind
        rng = random.Random(seed_of(f"setting|{c.p}|{scheme}|{kind}|{seed}"))
        n = c.n
        if scheme == "bip340":
            while True:
                d_raw = rng.randrange(1, n)
                P_raw = c.table[d_raw]
                if P_raw[1] % 2 == 0:
                    self.d, self.P = d_raw, P_raw
                else:
                    self.d, self.P = n - d_raw, c.neg(P_raw)
                break
            etab = {(r, m): rng.randrange(n) for r in range(c.p) for m in MSGS}
            self.sh = Shared(scheme, n, etab, None)
            self.pkf = self.P[0]
            self.hdr = {"d_parity_flipped": P_raw[1] % 2 != 0}
        else:
            while True:
                d = rng.randrange(1, n)
                if kind == "alias":
                    # same digest for messages 1 and 3, same z (digest + n) for 2: every alias path is live
                    a = rng.randrange(1, c.B - n)
                    tab = {1: a, 2: a + n, 3: a, 4: rng.randrange(c.B)}
                else:
                    tab = {M: rng.randrange(c.B) for M in MSGS}
                # clean: K_good is every nonzero scalar for every message, so G4' = G4 exactly
                if all(len(Ctx(c, "ecdsa", d, z=tab[M] % n).good_scalars()) == n - 1 for M in MSGS):
                    break
            self.d, self.P = d, c.table[d]
            self.sh = Shared(scheme, n, None, tab)
            self.pkf = self.P
            self.hdr = {"msgtab": tab}
        self.pub = PublicCurve(c)
        self._good = {}

    def device_sig(self, M, kp):
        """The device's signature for nonce scalar k' in 1..n-1, or None."""
        c, n = self.c, self.c.n
        W = c.table[kp]
        if self.scheme == "bip340":
            k = kp if W[1] % 2 == 0 else n - kp
            r = W[0]
            return (r, (k + self.sh.chal(r, M) * self.d) % n)
        z = self.sh.z(M)
        r = W[0] % n
        if r == 0:
            return None
        s = pow(kp, -1, n) * (z + r * self.d) % n
        if s == 0:
            return None
        if s > (n - 1) // 2:
            s = n - s
        return (r, s)

    def good(self, M):
        if M not in self._good:
            self._good[M] = [k for k in range(1, self.c.n) if self.device_sig(M, k) is not None]
        return self._good[M]


def verify(st_pub, sh, scheme, P, M, sig):
    """Public verification (plain: no low-s rule for ECDSA)."""
    c = st_pub
    n = c.n
    r, s = sig
    if scheme == "bip340":
        if not (0 <= r < c.p and 0 <= s < n):
            return False
        R = c.add(c.smul(s, c.G), c.neg(c.smul(sh.chal(r, M), P)))
        return R is not INF and R[1] % 2 == 0 and R[0] == r
    if not (0 < r < n and 0 < s < n):
        return False
    si = pow(s, -1, n)
    V = c.add(c.smul(sh.z(M) * si % n, c.G), c.smul(r * si % n, P))
    return V is not INF and V[0] % n == r


class SignRand:
    """Comparison game's signer: fresh nonce on every call, repeats included."""

    def __init__(self, st, rng):
        self.st, self.rng = st, rng
        self.calls = 0
        self.msgs = []

    def sign(self, M):
        self.calls += 1
        self.msgs.append(M)
        n = self.st.c.n
        if self.st.scheme == "bip340":
            k = self.rng.randrange(1, n)
        else:
            k = self.rng.choice(self.st.good(M))
        return self.st.device_sig(M, k)


def nonce_point(c, sh, scheme, P, M, sig):
    """BIP340: V = sG - eP with the even-y public point. ECDSA: V = s^-1 (zG + rP). Public data only."""
    n = c.n
    r, s = sig
    if scheme == "bip340":
        e = sh.chal(r, sh.digest(M))
        return c.add(c.smul(s, c.G), c.neg(c.smul(e, P)))
    si = pow(s, -1, n)
    return c.add(c.smul(sh.z(M) * si % n, c.G), c.smul(r * si % n, P))


class Terminal(Exception):
    def __init__(self, kind, keep_flags=False):
        self.kind, self.keep_flags = kind, keep_flags


# ---------------------------------------------------------------- the real game

class RealGame:
    """Section 1 with table oracles. base_mode: 'g0' the literal hash (BIP340 k0 = X mod n), 'g2' BIP340 with
    the reduced hash replaced by uniform on Z_n* given nonzero (the proof's G2)."""

    def __init__(self, st, rng, base_mode="g0"):
        self.st, self.rng, self.mode = st, rng, base_mode
        self.c, self.n, self.B = st.c, st.c.n, st.c.B
        self.Hdata, self.img = {}, {}
        self.Hpoint, self.A = {}, set()
        self.Hmask, self.Hnonce, self.g2base = {}, {}, {}
        self.ctx, self.unres = {}, set()
        self.flags, self.callno = {}, 0
        self.signed = set()
        self.D = self.N = self.T = 0
        self.sigs = self.xge = self.alt = 0

    def flag(self, name):
        self.flags.setdefault(name, self.callno)

    # hash oracles
    def H_data(self, rho):
        if rho in self.Hdata:
            return self.Hdata[rho]
        v = self.rng.randrange(self.B)
        self.D += 1
        if v in self.img:
            self.flag("bad2")
        else:
            self.img[v] = rho
        if v in self.unres:
            self.flag("bad3")
        self.Hdata[rho] = v
        return v

    def H_mask(self, hc):
        v = self.Hmask.get(hc)
        if v is None:
            v = self.Hmask[hc] = self.rng.randrange(self.B)
        return v

    def _hn(self, payload):
        v = self.Hnonce.get(payload)
        if v is None:
            v = self.Hnonce[payload] = self.rng.randrange(self.B)
        return v

    def H_nonce(self, payload):
        t, pkf, m, hc = payload
        cand = t ^ self.H_mask(hc)
        if 0 < cand < self.n:
            Q = self.c.table[cand]
            if (Q[0] == self.st.P[0]) if self.st.scheme == "bip340" else (Q == self.st.P):
                self.flag("bad1")
        return self._hn(payload)

    def _hp(self, addr):
        v = self.Hpoint.get(addr)
        if v is None:
            v = self.Hpoint[addr] = self.rng.randrange(self.B)
        return v

    def H_point(self, addr):
        self.T += 1
        v = self._hp(addr)
        self.A.add(addr)
        return v

    def H_msg(self, M):
        return self.st.sh.digest(M)

    def H_chal(self, r, m):
        return self.st.sh.chal(r, m)

    # context
    def _base(self, m, hc):
        t0 = self.st.d ^ self.H_mask(hc)
        payload = (t0, self.st.pkf, m, hc)
        X = self._hn(payload)
        n = self.n
        if self.st.scheme == "bip340":
            if X % n == 0:
                return None
            if self.mode == "g0":
                return X % n
            v = self.g2base.get(payload)
            if v is None:
                v = self.g2base[payload] = self.rng.randrange(1, n)
            return v
        return X if 0 < X < n else None

    def _touch(self, m, hc):
        key = (m, hc)
        st = self.ctx.get(key)
        if st is not None:
            return st
        self.N += 1
        k0 = self._base(m, hc)
        rho = self.img.get(hc)
        if rho is None:
            self.unres.add(hc)
        R0 = None if k0 is None else self.c.table[k0]
        if rho is not None and R0 is not None:
            addr = (R0, rho)
            if addr in self.A:
                self.flag("bad4")
            self.A.add(addr)
        st = self.ctx[key] = (k0, R0)
        return st

    def O1(self, M, hc):
        return self._touch(self.st.sh.digest(M), hc)[1]

    def O2(self, M, rho):
        hc = self.H_data(rho)
        k0, R0 = self._touch(self.st.sh.digest(M), hc)
        if k0 is None:
            return None
        u = self._hp((R0, rho))
        if u >= self.n:
            return None
        kp = (k0 + u) % self.n
        if kp == 0:
            return None
        sig = self.st.device_sig(M, kp)
        if sig is not None:
            self.signed.add(M)
            x = self.c.table[kp][0]  # how often x(W) >= n, and the other lift x +- n is also a curve x
            self.sigs += 1
            self.xge += x >= self.n
            self.alt += (x + self.n in self.c.xs) or (x - self.n in self.c.xs)
        return sig


# ---------------------------------------------------------------- the reduction

class Reduction:
    """B_adv as written in isolated_theorem.md. It receives only public data: the curve arithmetic, pk, the shared table,
    the Sign_Rand oracle, its own randomness, the rank guess and q_s. `helper` is None in abort mode; in
    helper mode (the proof's thought experiment for guess independence) it signs for reserved contexts."""

    def __init__(self, curve, scheme, pk, shared, sign_rand, rng, guess, q_s, mode="abort", helper=None,
                 variant=None):
        self.c, self.scheme, self.P, self.sh = curve, scheme, pk, shared
        self.sr, self.rng, self.guess, self.q_s = sign_rand, rng, guess, q_s
        self.mode, self.helper, self.variant = mode, helper, variant
        self.n, self.B, self.g = curve.n, curve.B, curve.g
        self.Hdata, self.img = {}, {}
        self.Hpoint, self.Hmask, self.Hnonce = {}, {}, {}
        self.ctx, self.unres = {}, set()
        self.flags, self.callno = {}, 0
        self.msgs, self.seen, self.reserved = [], set(), None
        self.signed, self.sr_msgs = set(), set()
        self.alias_sig = None
        self.D = self.N = self.T = 0

    def flag(self, name):
        self.flags.setdefault(name, self.callno)

    def _terminal(self, kind, keep=False):
        if not keep:
            for k in [k for k, v in self.flags.items() if v == self.callno]:
                del self.flags[k]
        raise Terminal(kind, keep)

    # rank guess and alias rule
    def _note(self, M, protocol):
        newly = False
        if protocol and M not in self.msgs:
            self.msgs.append(M)
            if len(self.msgs) == self.guess and self.guess <= self.q_s:
                self.reserved, newly = M, True
        self.seen.add(M)
        if self.mode == "abort" and self.scheme == "ecdsa" and self.reserved is not None:
            cands = (self.seen - {self.reserved}) if newly else ({M} if M != self.reserved else set())
            zr = self.sh.z(self.reserved)
            for M2 in sorted(cands):
                if self.sh.z(M2) == zr:
                    self.alias_sig = self.sr.sign(M2)
                    self.sr_msgs.add(M2)
                    self._terminal("alias")

    # hash oracles
    def H_data(self, rho):
        if rho in self.Hdata:
            return self.Hdata[rho]
        v = self.rng.randrange(self.B)
        self.D += 1
        if v in self.img:
            self.flag("bad2")
        else:
            self.img[v] = rho
        if v in self.unres:
            self.flag("bad3")
        self.Hdata[rho] = v
        return v

    def H_mask(self, hc):
        v = self.Hmask.get(hc)
        if v is None:
            v = self.Hmask[hc] = self.rng.randrange(self.B)
        return v

    def H_nonce(self, payload):
        t, pkf, m, hc = payload
        cand = t ^ self.H_mask(hc)
        if 0 < cand < self.n:
            Q = self.c.smul(cand, self.c.G)
            if (Q[0] == self.P[0]) if self.scheme == "bip340" else (Q == self.P):
                self.flag("bad1")  # B_adv now holds d and wins by signing a fresh message
        v = self.Hnonce.get(payload)
        if v is None:
            v = self.Hnonce[payload] = self.rng.randrange(self.B)
        return v

    def _hp(self, addr):
        v = self.Hpoint.get(addr)
        if v is None:
            v = self.Hpoint[addr] = self.rng.randrange(self.B)
        return v

    def H_point(self, addr):
        self.T += 1
        return self._hp(addr)

    def H_msg(self, M):
        self._note(M, False)
        return self.sh.digest(M)

    def H_chal(self, r, m):
        return self.sh.chal(r, m)

    # sampling
    def _kgood(self, M):
        c, n = self.c, self.n
        z = self.sh.z(M) if self.scheme == "ecdsa" else None
        while True:
            k = self.rng.randrange(1, n)
            if self.scheme == "bip340":
                return k
            r = c.table[k][0] % n
            if r == 0:
                continue
            if c.add(c.table[z], c.smul(r, self.P)) is INF:
                continue
            return k

    def _V(self, M, sig):
        """From a signature to the nonce point, public data only."""
        return nonce_point(self.c, self.sh, self.scheme, self.P, M, sig)

    def _touch(self, M, m, hc):
        key = (m, hc)
        st = self.ctx.get(key)
        if st is not None:
            return st
        self.N += 1
        c, n, B, g, rng = self.c, self.n, self.B, self.g, self.rng
        rho = self.img.get(hc)
        resolved = rho is not None
        if not resolved:
            self.unres.add(hc)
        st = {"resolved": resolved, "rho": rho, "fail": None, "R0": None, "sig": None, "concrete": False,
              "kp": None, "u": None, "nz": False}
        bf = (rng.randrange(B) < 2) if self.scheme == "bip340" else (rng.randrange(B) < g + 1)
        if bf:
            st["fail"] = "base"
            self.ctx[key] = st
            return st
        if not resolved:
            k0 = rng.randrange(1, n)
            st["concrete"], st["k0"], st["R0"] = True, k0, c.table[k0]
            self.ctx[key] = st
            return st
        concrete = M == self.reserved
        st["concrete"] = concrete
        uf = rng.randrange(B)
        skip_b2 = self.variant == "no_branch2" or (concrete and self.variant == "reserved_no_branch2")
        if uf >= n and not skip_b2:
            k0 = rng.randrange(1, n)
            st.update(fail="u", k0=k0, R0=c.table[k0], u=uf)
        elif concrete:
            if self.scheme == "bip340":
                kp = rng.randrange(n)
            else:
                kp = 0 if rng.randrange(n) == 0 else self._kgood(M)
            u = rng.randrange(n - 1)
            if u >= kp:
                u += 1
            k0 = (kp - u) % n
            st.update(kp=kp, u=u, k0=k0, R0=c.table[k0])
            if kp == 0:
                st["fail"] = "kp0"
        else:
            if rng.randrange(n) == 0:  # the k' = 0 coin
                u = rng.randrange(1, n)
                st.update(fail="kp0", u=u, R0=c.neg(c.table[u]))
            else:
                sig = self.sr.sign(M)
                self.sr_msgs.add(M)
                V = self._V(M, sig)
                b = 0 if self.variant == "no_fair_sign" else rng.randrange(2)
                W = V if b == 0 else c.neg(V)
                if self.variant == "u_not_excluding":
                    u = rng.randrange(n)
                else:
                    while True:  # redraw while uG = W
                        u = rng.randrange(n)
                        if c.table[u] != W:
                            break
                R0 = c.add(W, c.neg(c.table[u]))
                if R0 is INF:  # only reachable in the u_not_excluding control: an invalid R0 reaches F
                    R0 = "INF"
                st.update(u=u, R0=R0, sig=sig, nz=True)
        if st["R0"] is not None and st["R0"] != "INF" and st["u"] is not None:
            addr = (st["R0"], rho)
            if addr in self.Hpoint:
                self.flag("bad4")
            else:
                self.Hpoint[addr] = st["u"]
        self.ctx[key] = st
        return st

    def O1(self, M, hc):
        self._note(M, True)
        return self._touch(M, self.sh.digest(M), hc)["R0"]

    def O2(self, M, rho):
        self._note(M, True)
        hc = self.H_data(rho)
        st = self._touch(M, self.sh.digest(M), hc)
        if st["fail"] is not None:
            return None
        sig = st["sig"]
        if sig is None:
            if not st["resolved"]:
                if self.mode == "abort":
                    self._terminal("unresolved", keep=True)
                u = self._hp((st["R0"], rho))
                if u >= self.n or (st["k0"] + u) % self.n == 0:
                    return None
                sig = self.helper(M, (st["k0"] + u) % self.n)
            elif self.mode == "abort":
                self._terminal("abort")  # a reserved O2 that would return a signature
            else:
                sig = self.helper(M, st["kp"])
            st["sig"] = sig
        elif self.variant == "no_cache" and st["nz"]:
            sig = self.sr.sign(M)
            self.sr_msgs.add(M)
        if sig is not None:
            self.signed.add(M)
        return sig


# ---------------------------------------------------------------- recorder and F's scripts

class Rec:
    """Records everything F sees. F is unbounded in the toy and may brute-force d from pk (`forge`)."""

    def __init__(self, game, st):
        self.g, self.st, self.ev = game, st, []
        self.q_s = 0
        self.pub = st.pub
        self.n, self.B = st.c.n, st.c.B
        self.pkf = st.pkf
        self.rng = game.rng

    def _call(self, name, *args):
        self.g.callno = len(self.ev)
        res = getattr(self.g, name)(*args)
        self.ev.append((name, args, res))
        return res

    def H_data(self, x):
        return self._call("H_data", x)

    def H_mask(self, x):
        return self._call("H_mask", x)

    def H_nonce(self, x):
        return self._call("H_nonce", x)

    def H_point(self, x):
        return self._call("H_point", x)

    def H_msg(self, x):
        return self._call("H_msg", x)

    def O1(self, M, hc):
        self.q_s += 1
        return self._call("O1", M, hc)

    def O2(self, M, rho):
        self.q_s += 1
        return self._call("O2", M, rho)

    def valid(self, M, sig):
        return sig is not None and verify(self.pub, self.st.sh, self.st.scheme, self.st.P, M, sig)

    def forge(self, M):
        st = self.st
        while True:
            k = self.rng.randrange(1, st.c.n)
            sig = st.device_sig(M, k)
            if sig is not None:
                return sig

    def host_check(self, M, R0, rho, sig):
        """Step 5 of the BIP, run by F's host half on public data, plus verification."""
        c, st = self.pub, self.st
        n = c.n
        t = self.H_point((R0, rho))
        if t >= n:
            return False
        W = c.add(R0, c.table[t])
        if W is INF:
            return False
        r, s = sig
        if st.scheme == "bip340":
            return r == W[0] and self.valid(M, sig)
        if not (0 < s <= (n - 1) // 2) or W[0] % n != r or not self.valid(M, sig):
            return False
        si = pow(s, -1, n)
        V = c.add(c.smul(st.sh.z(M) * si % n, c.G), c.smul(r * si % n, st.P))
        return V in (W, c.neg(W))


def _tail(O, M, R0, rho, sig, info):
    if R0 is None:
        return
    if R0 == "INF":
        info["inv_fail"] += 1
        return
    if sig is None:
        O.H_point((R0, rho))
    elif not O.host_check(M, R0, rho, sig):
        info["inv_fail"] += 1


def s_o1_o2(O):
    info = {"inv_fail": 0}
    hc = O.H_data(5)
    R0 = O.O1(1, hc)
    sig = O.O2(1, 5)
    _tail(O, 1, R0, 5, sig, info)
    return info


def s_o2_o1(O):
    info = {"inv_fail": 0}
    sig = O.O2(1, 5)
    hc = O.H_data(5)
    R0 = O.O1(1, hc)
    _tail(O, 1, R0, 5, sig, info)
    return info


def s_repeat(O):
    info = {"inv_fail": 0}
    hc = O.H_data(5)
    a = O.O1(1, hc)
    b = O.O1(1, hc)
    s1 = O.O2(1, 5)
    s2 = O.O2(1, 5)
    if a != b or s1 != s2:
        info["inv_fail"] += 1
    _tail(O, 1, a, 5, s1, info)
    return info


def s_same_rho(O):
    info = {"inv_fail": 0}
    hc = O.H_data(5)
    R = {M: O.O1(M, hc) for M in (1, 2)}
    sg = {M: O.O2(M, 5) for M in (1, 2, 3)}
    for M in (1, 2):
        _tail(O, M, R[M], 5, sg[M], info)
    return info


def s_point_between(O):
    info = {"inv_fail": 0}
    hc = O.H_data(5)
    O.H_point((O.pub.G, 5))  # a guessed address before the context exists
    R0 = O.O1(1, hc)
    u = O.H_point((R0, 5)) if R0 is not None else None
    sig = O.O2(1, 5)
    if R0 is not None and sig is not None and u < O.n:
        W = O.pub.add(R0, O.pub.table[u])
        rr = None if W is INF else (W[0] if O.st.scheme == "bip340" else W[0] % O.n)
        if sig[0] != rr:
            info["inv_fail"] += 1
    return info


def s_inconsistent(O):
    info = {"inv_fail": 0}
    hc = O.H_data(5)
    O.O1(1, (hc + 17) % O.B)
    O.H_data(6)
    R0 = O.O1(1, hc)
    sig = O.O2(1, 5)
    _tail(O, 1, R0, 5, sig, info)
    return info


def s_hdata_after(O):
    info = {"inv_fail": 0}
    O.O1(1, 40)
    for rho in (6, 7, 8):
        O.H_data(rho)
    hc6 = O.H_data(6)
    R0 = O.O1(1, hc6)
    sig = O.O2(1, 6)
    _tail(O, 1, R0, 6, sig, info)
    return info


def s_reserved(O):
    info = {"inv_fail": 0}
    hc = O.H_data(5)
    O.O1(1, hc)
    O.O2(2, 5)
    O.O2(3, 5)
    O.O2(1, 5)
    return info


def s_nonce_queries(O):
    info = {"inv_fail": 0}
    hc = O.H_data(5)
    R0 = O.O1(1, hc)
    for t in range(8):
        O.H_nonce((t, O.pkf, 1, hc))
    sig = O.O2(1, 5)
    _tail(O, 1, R0, 5, sig, info)
    return info


def s_hmsg_alias(O):
    info = {"inv_fail": 0}
    hc = O.H_data(5)
    O.H_msg(4)
    O.O1(1, hc)
    O.H_msg(3)
    O.O2(2, 5)
    O.O2(3, 5)
    O.H_msg(2)
    return info


# name: (fn, q_s, N, D, T, cell mode, M*, schemes, settings kinds per scheme)
SCRIPTS = {
    "S1_o1_o2": dict(fn=s_o1_o2, q=2, N=1, D=1, T=1, mode="fine", mstar=1, schemes=("bip340", "ecdsa")),
    "S2_o2_o1": dict(fn=s_o2_o1, q=2, N=1, D=1, T=1, mode="fine", mstar=1, schemes=("bip340", "ecdsa")),
    "S3_repeat": dict(fn=s_repeat, q=4, N=1, D=1, T=1, mode="fine", mstar=1, schemes=("bip340", "ecdsa")),
    "S4_same_rho_many_msgs": dict(fn=s_same_rho, q=5, N=3, D=1, T=2, mode="coarse", mstar=3, schemes=("bip340", "ecdsa")),
    "S5_h_point_between": dict(fn=s_point_between, q=2, N=1, D=1, T=2, mode="fine", mstar=1, schemes=("bip340", "ecdsa")),
    "S6_inconsistent_hc": dict(fn=s_inconsistent, q=3, N=2, D=2, T=1, mode="coarse", mstar=1, schemes=("bip340", "ecdsa")),
    "S7_h_data_after_o1": dict(fn=s_hdata_after, q=3, N=2, D=3, T=1, mode="coarse", mstar=1, schemes=("bip340", "ecdsa")),
    "S8_reserved_contexts": dict(fn=s_reserved, q=4, N=3, D=1, T=0, mode="coarse", mstar=4, schemes=("bip340", "ecdsa")),
    "S9_nonce_queries": dict(fn=s_nonce_queries, q=2, N=1, D=1, T=1, mode="coarse", mstar=1, schemes=("bip340", "ecdsa")),
    "S10_h_msg_alias": dict(fn=s_hmsg_alias, q=3, N=3, D=1, T=0, mode="coarse", mstar=1, schemes=("ecdsa",)),
}


def setting_kind(script, scheme):
    return "alias" if (scheme == "ecdsa" and script == "S10_h_msg_alias") else "plain"


# ---------------------------------------------------------------- transcript cells and truncation

def canon(ev, term, st, mode):
    """Everything compared by chi-square, as {test name: cell}. A cell is a function of the (truncated)
    transcript only.
      Hd_i, Hn_i, Hp_i  exact marginal of the i-th H_data / H_nonce / H_point answer (8 classes for the first two)
      O1_i, O2_j        exact marginal of the i-th O1 answer (index of R0) and j-th O2 answer ((r,s) or None)
      J                 joint, binned: every O1/O2 answer as none / QC classes of the index of R0 or of s,
                        the sign bit b of each signature, equality flags of repeated calls, terminal marker
      X                 (fine scripts only) joint of the exact O1/O2 answers and the terminal marker
    b = 0 if W = R0 + u G equals the nonce point V recomputed from the signature, 1 if W = -V, 2 otherwise;
    it is computed from the transcript with public data, and is how the fair sign shows up."""
    c, sh = st.c, st.sh
    n, B = c.n, c.B
    pub = st.pub
    tests = {}
    cnt = Counter()
    dm, r0map, hp = {}, {}, {}
    for name, args, res in ev:
        if name == "H_data":
            dm[args[0]] = res
        elif name == "O1" and res is not None:
            r0map[(args[0], args[1])] = res
        elif name == "H_point":
            hp[args[0]] = res
    first, joint, exact = {}, [], []
    for name, args, res in ev:
        i = cnt[name]
        cnt[name] += 1
        if name in ("H_data", "H_nonce"):
            tests[f"{'Hd' if name == 'H_data' else 'Hn'}_{i}"] = res * 8 // B
        elif name == "H_point":
            tests[f"Hp_{i}"] = res
        elif name in ("O1", "O2"):
            if name == "O1":
                key = -1 if res is None else -2 if res == "INF" else c.dlog[res]
                cls = key if key < 0 else key * QC // n
            else:
                key = res
                cls = -1 if res is None else res[1] * QC // n
            tests[f"{name}_{i}"] = key
            exact.append(key)
            joint.append(cls)
            if (name, args) in first:
                joint.append(("eq", first[(name, args)] == res))
            else:
                first[(name, args)] = res
            if name == "O2" and res is not None:
                M, rho = args
                hc = dm.get(rho)
                R0 = r0map.get((M, hc))
                u = hp.get((R0, rho)) if R0 is not None else None
                b = -1
                if isinstance(R0, tuple) and u is not None and u < n:
                    W = pub.add(R0, pub.table[u])
                    V = nonce_point(pub, sh, st.scheme, st.P, M, res)
                    b = 0 if W == V else 1 if W == pub.neg(V) else 2
                joint.append(("b", b))
    joint.append(term)
    exact.append(term)
    tests["J"] = tuple(joint)
    if mode == "fine":
        tests["X"] = tuple(exact)
    return tests


def truncate_real(ev, guess, q_s, sh, scheme):
    """Apply the rank guess, the ECDSA alias rule and the abort rule to a complete real transcript, after the
    fact. Independent of the Reduction class. Returns (prefix, terminal kind or None, cut index or len)."""
    msgs, seen, reserved = [], set(), None
    for i, (name, args, res) in enumerate(ev):
        if name in ("O1", "O2"):
            M, protocol = args[0], True
        elif name == "H_msg" and scheme == "ecdsa":
            M, protocol = args[0], False
        else:
            continue
        newly = False
        if protocol and M not in msgs:
            msgs.append(M)
            if len(msgs) == guess and guess <= q_s:
                reserved, newly = M, True
        seen.add(M)
        if scheme == "ecdsa" and reserved is not None:
            cands = (seen - {reserved}) if newly else ({M} if M != reserved else set())
            if any(sh.z(M2) == sh.z(reserved) for M2 in cands):
                return ev[:i], "alias", i
        if name == "O2" and M == reserved and res is not None:
            return ev[:i], "abort", i
    return ev, None, len(ev)


def correct_guess(script_name, q_s):
    """Rank of M* among the distinct byte messages of the protocol calls, or q_s+1 when M* is in none.
    The first-call order of each script's distinct messages is written out below by hand."""
    sp = SCRIPTS[script_name]
    order = {"S1_o1_o2": [1], "S2_o2_o1": [1], "S3_repeat": [1], "S4_same_rho_many_msgs": [1, 2, 3],
             "S5_h_point_between": [1], "S6_inconsistent_hc": [1], "S7_h_data_after_o1": [1],
             "S8_reserved_contexts": [1, 2, 3], "S9_nonce_queries": [1], "S10_h_msg_alias": [1, 2, 3]}[script_name]
    return order.index(sp["mstar"]) + 1 if sp["mstar"] in order else q_s + 1


# ---------------------------------------------------------------- group runners

BADS = ("bad1", "bad2", "bad3", "bad4")


def add_cells(store, tests):
    for k, v in tests.items():
        store[k][v] += 1


def chi_all(a, b):
    """Two-sample chi-square on every test present. Returns (min p, worst test, per-test dict)."""
    per = {}
    for t in set(a) | set(b):
        r = two_sample_chi2(a.get(t, Counter()), b.get(t, Counter()))
        per[t] = r
    worst = min(per, key=lambda t: per[t]["p"]) if per else None
    return {"min_p": per[worst]["p"] if worst else 1.0, "worst": worst, "tests": len(per),
            "na": max((r["na"] for r in per.values()), default=0),
            "per_test_p": {t: per[t]["p"] for t in sorted(per)},
            "worst_stat": per[worst]["stat"] if worst else 0, "worst_df": per[worst]["df"] if worst else 0}


def new_acc(guesses):
    return {"cells": defaultdict(Counter), "n": 0, "bad": 0, "flags": Counter(), "inv_fail": 0, "inv_runs": 0,
            "term": Counter(), "fwin": 0, "bwin": 0, "bwin_viol": 0, "alias_invalid": 0, "sr_max": 0,
            "sigs": 0, "xge": 0, "alt": 0, "counts_exceed": 0, "per_g": {g: {"cells": defaultdict(Counter), "bad": 0, "term": Counter(),
                                                       "win_abort_viol": 0} for g in guesses}}


def run_real_group(st, name, N, label, base_mode, guesses):
    sp = SCRIPTS[name]
    c = st.c
    rng = random.Random(seed_of(label))
    acc = new_acc(guesses)
    cg = correct_guess(name, sp["q"])
    for _ in range(N):
        g = RealGame(st, rng, base_mode)
        O = Rec(g, st)
        info = sp["fn"](O)
        sig = O.forge(sp["mstar"])
        fwin = O.valid(sp["mstar"], sig) and sp["mstar"] not in g.signed
        acc["n"] += 1
        acc["sigs"] += g.sigs
        acc["xge"] += g.xge
        acc["alt"] += g.alt
        acc["fwin"] += fwin
        acc["counts_exceed"] += (g.N > sp["N"]) + (g.D > sp["D"]) + (g.T > sp["T"])
        for f in g.flags:
            acc["flags"][f] += 1
        bad = bool(g.flags)
        if bad:
            acc["bad"] += 1
        else:
            add_cells(acc["cells"], canon(O.ev, None, st, sp["mode"]))
            acc["inv_runs"] += 1
            acc["inv_fail"] += info["inv_fail"]
        for gs in guesses:
            pre, term, cut = truncate_real(O.ev, gs, sp["q"], st.sh, st.scheme)
            bad_g = any(v < cut for v in g.flags.values()) if term else bool(g.flags)
            pg = acc["per_g"][gs]
            pg["term"][term] += 1
            if bad_g:
                pg["bad"] += 1
            else:
                add_cells(pg["cells"], canon(pre, term, st, sp["mode"]))
            if gs == cg and fwin and term == "abort":
                pg["win_abort_viol"] += 1
    return acc


def run_sim_group(st, name, N, label, guess, mode, variant=None):
    sp = SCRIPTS[name]
    cg = correct_guess(name, sp["q"])
    c = st.c
    rng = random.Random(seed_of(label))
    acc = new_acc([])
    pub = st.pub
    for _ in range(N):
        sr = SignRand(st, rng)
        helper = (lambda M, kp: st.device_sig(M, kp)) if mode == "helper" else None
        g = Reduction(pub, st.scheme, st.P, st.sh, sr, rng, guess, sp["q"], mode, helper, variant)
        O = Rec(g, st)
        term = None
        info = {"inv_fail": 0}
        try:
            info = sp["fn"](O)
        except Terminal as t:
            term = t.kind
        acc["n"] += 1
        acc["term"][term] += 1
        for f in g.flags:
            acc["flags"][f] += 1
        acc["counts_exceed"] += (g.N > sp["N"]) + (g.D > sp["D"]) + (g.T > sp["T"])
        acc["sr_max"] = max(acc["sr_max"], sr.calls)
        if sr.calls > sp["q"] + 1:
            acc["counts_exceed"] += 1
        if term == "alias":
            ok = O.valid(g.reserved, g.alias_sig) and g.reserved not in g.sr_msgs
            if not ok:
                acc["alias_invalid"] += 1
            acc["bwin"] += ok
        elif term is None:
            sig = O.forge(sp["mstar"])
            fview = O.valid(sp["mstar"], sig) and sp["mstar"] not in g.signed
            fresh = sp["mstar"] not in g.sr_msgs
            acc["fwin"] += fview
            if mode == "abort":
                acc["bwin"] += O.valid(sp["mstar"], sig) and fresh
                if guess == cg and fview and not fresh:
                    acc["bwin_viol"] += 1
        bad = bool(g.flags)
        if bad:
            acc["bad"] += 1
        else:
            add_cells(acc["cells"], canon(O.ev, term, st, sp["mode"]))
            acc["inv_runs"] += 1
            acc["inv_fail"] += info["inv_fail"]
    return acc


def bounds(sp, c):
    n, B = c.n, c.B
    D, N, T = sp["D"], sp["N"], sp["T"]
    return {"bad2": D * (D - 1) / (2 * B), "bad3": N * D / B, "bad4": N * (T + N) / (n - 1)}


def summarize_acc(a, keep_cells=False):
    out = {k: a[k] for k in ("n", "bad", "inv_fail", "inv_runs", "fwin", "bwin", "bwin_viol", "alias_invalid",
                             "sr_max", "counts_exceed", "sigs", "xge", "alt")}
    out["flags"] = dict(a["flags"])
    out["term"] = {str(k): v for k, v in a["term"].items()}
    out["nonbad_cells_used"] = len(a["cells"])
    return out


# ---------------------------------------------------------------- B1

FORBIDDEN_NAMES = {"d", "sk", "d_raw", "secret", "dlog", "device_sig", "RealGame", "Setting", "good", "x_ge"}


def b1_check():
    sig = inspect.signature(Reduction.__init__)
    params = [p for p in sig.parameters if p != "self"]
    bad_params = [p for p in params if p in FORBIDDEN_NAMES or "secret" in p or p.startswith("sk")]
    src = inspect.getsource(Reduction)
    tree = ast.parse(src)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    hits = sorted((names | attrs) & FORBIDDEN_NAMES)
    pub_attrs = sorted(a for a in PublicCurve(Curve(13)).__dict__)
    return {"signature": str(sig), "parameters": params, "forbidden_parameters": bad_params,
            "forbidden_identifiers_in_class_body": hits, "public_curve_fields": pub_attrs,
            "dlog_not_exposed": "dlog" not in pub_attrs,
            "ok": not bad_params and not hits and "dlog" not in pub_attrs}


# ---------------------------------------------------------------- Part B driver

def run_part_b(plan, log=print):
    c = Curve(plan["p"])
    out = {"curve": {"p": c.p, "n": c.n, "B": c.B, "g": c.g, "points_x_ge_n": c.x_ge_n_points},
           "groups": [], "chi2": [], "controls": [], "scripts": {}, "settings": {}}
    N_f, N_c, N_ctl = plan["N_fine"], plan["N_coarse"], plan["N_control"]
    real_keep = {}
    t0 = time.time()
    for scheme in ("bip340", "ecdsa"):
        for name, sp in SCRIPTS.items():
            if scheme not in sp["schemes"] or (plan.get("scripts") and name not in plan["scripts"]):
                continue
            kind = setting_kind(name, scheme)
            st = Setting(c, scheme, kind, plan["seed"])
            out["settings"][f"{scheme}:{kind}"] = {"d": st.d, **{k: (v if k != "msgtab" else v) for k, v in st.hdr.items()}}
            N = N_f if sp["mode"] == "fine" else N_c
            q = sp["q"]
            cg = correct_guess(name, q)
            hg = sorted({1, q + 1})
            ag = sorted({1, 2, cg, q + 1}) if sp["mode"] == "coarse" else sorted({1, q + 1})
            tag = f"{scheme}|{name}"
            rb = "g2" if scheme == "bip340" else "g0"
            real = run_real_group(st, name, N, f"real|{tag}|{plan['seed']}", rb, ag)
            real_keep[(scheme, name)] = (st, real)
            out["groups"].append({"tag": tag, "kind": "real", "base_mode": rb, **summarize_acc(real)})
            bd = bounds(sp, c)
            bad_report = {}
            for f in ("bad2", "bad3", "bad4"):
                cnt = real["flags"].get(f, 0)
                pt = binom_tail(real["n"], min(1.0, bd[f]), cnt)
                bad_report[f] = {"observed": cnt, "runs": real["n"], "bound": bd[f], "tail_p": pt, "ok": pt > 1e-5}
            bad_report["bad1"] = {"observed": real["flags"].get("bad1", 0), "runs": real["n"]}
            out["scripts"][tag] = {"sigs": real["sigs"], "x_ge_n": real["xge"], "alt_lift": real["alt"],
                                   "mode": sp["mode"], "q_s": q, "N": N, "declared_N_D_T": [sp["N"], sp["D"], sp["T"]],
                                   "correct_guess": cg, "helper_guesses": hg, "abort_guesses": ag,
                                   "real_bad": bad_report, "inv_fail": real["inv_fail"], "inv_runs": real["inv_runs"],
                                   "counts_exceed_real": real["counts_exceed"],
                                   "win_abort_viol": sum(real["per_g"][g]["win_abort_viol"] for g in ag),
                                   "fwin_rate_real": real["fwin"] / real["n"]}
            helpers = {}
            for g in hg:
                h = run_sim_group(st, name, N, f"helper|{tag}|{g}|{plan['seed']}", g, "helper")
                helpers[g] = h
                r = chi_all(real["cells"], h["cells"])
                out["chi2"].append({"tag": tag, "cmp": f"real_vs_sim_helper_g{g}", "p": r["min_p"], **r})
                sb = {}
                for f in ("bad2", "bad3", "bad4"):
                    cnt = h["flags"].get(f, 0)
                    pt = binom_tail(h["n"], min(1.0, bd[f]), cnt)
                    sb[f] = {"observed": cnt, "bound": bd[f], "tail_p": pt, "ok": pt > 1e-5}
                sb["bad1"] = {"observed": h["flags"].get("bad1", 0)}
                out["groups"].append({"tag": tag, "kind": f"sim_helper_g{g}", **summarize_acc(h), "bad_vs_bound": sb})
            if len(hg) == 2:
                r = chi_all(helpers[hg[0]]["cells"], helpers[hg[1]]["cells"])
                out["chi2"].append({"tag": tag, "cmp": f"sim_helper_g{hg[0]}_vs_g{hg[1]}", "p": r["min_p"], **r})
            for g in ag:
                a = run_sim_group(st, name, N, f"abort|{tag}|{g}|{plan['seed']}", g, "abort")
                r = chi_all(real["per_g"][g]["cells"], a["cells"])
                out["chi2"].append({"tag": tag, "cmp": f"real_truncated_vs_sim_abort_g{g}", "p": r["min_p"], **r})
                out["groups"].append({"tag": tag, "kind": f"sim_abort_g{g}", **summarize_acc(a),
                                      "real_term": {str(k): v for k, v in real["per_g"][g]["term"].items()}})
            log(f"  B {tag} done, {time.time() - t0:.0f}s")
    # informational: BIP340 literal hash (base G0) against the simulator, which has the proof's G2 base
    if not plan.get("scripts") or "S1_o1_o2" in plan["scripts"]:
        st = Setting(c, "bip340", "plain", plan["seed"])
        g0 = run_real_group(st, "S1_o1_o2", N_f, f"real|bip340|S1_o1_o2|g0info|{plan['seed']}", "g0", [])
        st_, real = real_keep[("bip340", "S1_o1_o2")]
        h = run_sim_group(st, "S1_o1_o2", N_f, f"helper|bip340|S1_o1_o2|g0info|{plan['seed']}", 2, "helper")
        r = chi_all(g0["cells"], h["cells"])
        out["info_g0_vs_sim"] = {**r, "p": r["min_p"], "note": "literal hash base (G0) vs simulator; the proof charges N*beta for this",
                                 "beta": (c.g - 1) * (c.n - c.g) / ((c.B - 2) * (c.n - 1))}
    # B4 controls: broken variants, compared with the real game on the same script
    ctl = [("u_not_excluding", "S1_o1_o2", "abort", "q+1"), ("no_fair_sign", "S1_o1_o2", "abort", "q+1"),
           ("no_branch2", "S1_o1_o2", "abort", "q+1"), ("no_cache", "S3_repeat", "abort", "q+1"),
           ("reserved_no_branch2", "S1_o1_o2", "helper", 1)]
    for scheme in ("bip340", "ecdsa"):
        for var, name, mode, gsel in ctl:
            if (scheme, name) not in real_keep:
                continue
            st, real = real_keep[(scheme, name)]
            sp = SCRIPTS[name]
            g = sp["q"] + 1 if gsel == "q+1" else gsel
            a = run_sim_group(st, name, N_f, f"ctl|{scheme}|{name}|{var}|{plan['seed']}", g, mode, var)
            ref = real["cells"] if mode == "helper" else real["per_g"][g]["cells"] if g in real["per_g"] else real["cells"]
            r = chi_all(ref, a["cells"])
            out["controls"].append({"scheme": scheme, "variant": var, "script": name, "mode": mode, "guess": g,
                                    "p": r["min_p"], **r, "detected": r["min_p"] < 1e-5})
    out["runtime_s"] = time.time() - t0
    return out
