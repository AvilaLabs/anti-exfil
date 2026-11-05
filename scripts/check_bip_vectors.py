#!/usr/bin/env python3
"""Independent check of vectors/bip-anti-exfil.json.

Written from spec/bip-anti-exfil.md alone. It does not import or
copy reference or the generator; the curve arithmetic below is its own.
It recomputes every valid vector, runs every rejection through the step 5
host checks, and replays every forced-hash case through a local hash seam.
Prints a summary and exits 0 only if everything matches.

Usage: check_bip_vectors.py [--json PATH]
"""
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (55066263022277343669578718895168534326250603453777594175500187360389116729240,
     32670510020758816978083085130507043184471273380659243275938904335757337482424)
HALF = (N - 1) // 2


# ------------------------------------------------------------ curve (affine)
def padd(a, b):
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def pneg(a):
    return None if a is None else (a[0], (P - a[1]) % P)


def pmul(k, pt=G):
    k %= N
    acc = None
    while k:
        if k & 1:
            acc = padd(acc, pt)
        pt = padd(pt, pt)
        k >>= 1
    return acc


def on_curve(pt):
    return pt is not None and (pt[1] * pt[1] - pt[0] ** 3 - 7) % P == 0


def lift(x, odd):
    """Point with x coordinate x and y parity odd, or None."""
    if x >= P:
        return None
    c = (x ** 3 + 7) % P
    y = pow(c, (P + 1) // 4, P)
    if y * y % P != c:
        return None
    if (y & 1) != odd:
        y = P - y
    return (x, y)


# ------------------------------------------------------------ encoding
def sha(b):
    return hashlib.sha256(b).digest()


def real_tagged(tag, x):
    th = sha(tag.encode("ascii"))
    return sha(th + th + x)


class Hash:
    """tagged_hash with an optional forced output for one tag."""
    force_tag = None
    force_val = None
    extra = {}   # further forced tags (isolated cases force up to two)

    @classmethod
    def th(cls, tag, x):
        if tag in cls.extra:
            return cls.extra[tag].to_bytes(32, "big")
        if tag == cls.force_tag:
            return cls.force_val.to_bytes(32, "big")
        return real_tagged(tag, x)


def i2b(i):
    return i.to_bytes(32, "big")


def b2i(b):
    return int.from_bytes(b, "big")


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def ser33(pt):
    return bytes([2 + (pt[1] & 1)]) + i2b(pt[0])


def parse33(b):
    if len(b) != 33 or b[0] not in (2, 3):
        return None
    return lift(b2i(b[1:]), b[0] == 3)


class Fail(Exception):
    pass


# ------------------------------------------------------------ BIP340
def s_pubkey(sk):
    d0 = b2i(sk)
    if not 0 < d0 < N:
        raise Fail("sk")
    Pt = pmul(d0)
    d = d0 if Pt[1] % 2 == 0 else N - d0
    return i2b(Pt[0]), d


def s_hc(rho):
    return Hash.th("s2c/schnorr/data", rho)


def s_k0(sk, m, hc):
    pk, d = s_pubkey(sk)
    t0 = xor(i2b(d), Hash.th("BIP0340/aux", hc))
    k0 = b2i(Hash.th("s2c/schnorr/nonce", t0 + pk + m + hc)) % N
    if k0 == 0:
        raise Fail("k0")
    return k0


def s_commit(sk, m, hc):
    return ser33(pmul(s_k0(sk, m, hc)))


def s_sign(sk, m, rho):
    pk, d = s_pubkey(sk)
    hc = s_hc(rho)
    k0 = s_k0(sk, m, hc)
    R0b = ser33(pmul(k0))
    t = b2i(Hash.th("s2c/schnorr/point", R0b + rho))
    if t >= N:
        raise Fail("t")
    kp = (k0 + t) % N
    if kp == 0:
        raise Fail("kprime")
    W = pmul(kp)
    k = kp if W[1] % 2 == 0 else N - kp
    r = i2b(W[0])
    e = b2i(Hash.th("BIP0340/challenge", r + pk + m)) % N
    return r + i2b((k + e * d) % N)


def bip340_verify(pk, m, sig):
    if len(pk) != 32 or len(sig) != 64:
        return False
    Q = lift(b2i(pk), False)
    r, s = b2i(sig[:32]), b2i(sig[32:])
    if Q is None or r >= P or s >= N:
        return False
    e = b2i(real_tagged("BIP0340/challenge", sig[:32] + pk + m)) % N
    R = padd(pmul(s), pneg(pmul(e, Q)))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def s_host(pk, m, rho, R0b, sig):
    """Return (accepted, failing step)."""
    if len(pk) != 32 or len(rho) != 32 or len(R0b) != 33 or len(sig) != 64:
        return False, "length"
    R0 = parse33(R0b)
    if R0 is None:
        return False, 1
    t = b2i(Hash.th("s2c/schnorr/point", R0b + rho))
    if t >= N:
        return False, 2
    W = padd(R0, pmul(t))
    if W is None:
        return False, 3
    if i2b(W[0]) != sig[:32]:
        return False, 4
    if not bip340_verify(pk, m, sig):
        return False, 5
    return True, None


# ------------------------------------------------------------ ECDSA
def e_hc(rho):
    return Hash.th("s2c/ecdsa/data", rho)


def e_k0(sk, m, hc):
    d = b2i(sk)
    if not 0 < d < N:
        raise Fail("sk")
    pk = ser33(pmul(d))
    d_mask = xor(i2b(d), Hash.th("s2c/ecdsa/aux", hc))
    k0 = b2i(Hash.th("s2c/ecdsa/nonce", d_mask + pk + m + hc))
    if k0 == 0 or k0 >= N:
        raise Fail("k0")
    return k0


def e_pub(sk):
    d = b2i(sk)
    if not 0 < d < N:
        raise Fail("sk")
    return ser33(pmul(d))


def e_commit(sk, m, hc):
    return ser33(pmul(e_k0(sk, m, hc)))


def e_sign(sk, m, rho):
    d = b2i(sk)
    hc = e_hc(rho)
    k0 = e_k0(sk, m, hc)
    R0b = ser33(pmul(k0))
    t = b2i(Hash.th("s2c/ecdsa/point", R0b + rho))
    if t >= N:
        raise Fail("t")
    kp = (k0 + t) % N
    if kp == 0:
        raise Fail("kprime")
    W = pmul(kp)
    r = W[0] % N
    s = pow(kp, -1, N) * (b2i(m) % N + r * d) % N
    if r == 0 or s == 0:
        raise Fail("rs")
    negated = s > HALF
    if negated:
        s = N - s
    return i2b(r) + i2b(s), negated


def ecdsa_plain_verify(pk, m, sig):
    """Ordinary low-s ECDSA verification, used to qualify rejected signatures."""
    Q = parse33(pk)
    r, s = b2i(sig[:32]), b2i(sig[32:])
    if Q is None or not (0 < r < N and 0 < s <= HALF):
        return False
    z = b2i(m) % N
    si = pow(s, -1, N)
    V = padd(pmul(z * si % N), pmul(r * si % N, Q))
    return V is not None and V[0] % N == r


def e_host(pk, m, rho, R0b, sig):
    if len(pk) != 33 or len(m) != 32 or len(rho) != 32 or len(R0b) != 33 or len(sig) != 64:
        return False, "length"
    Q = parse33(pk)
    R0 = parse33(R0b)
    if R0 is None or Q is None:
        return False, 1
    t = b2i(Hash.th("s2c/ecdsa/point", R0b + rho))
    if t >= N:
        return False, 2
    W = padd(R0, pmul(t))
    if W is None:
        return False, 3
    r, s = b2i(sig[:32]), b2i(sig[32:])
    if not (0 < r < N and 0 < s <= HALF and W[0] % N == r):
        return False, 4
    z = b2i(m) % N
    si = pow(s, -1, N)
    V = padd(pmul(z * si % N), pmul(r * si % N, Q))
    if V is None or V[0] % N != r or V not in (W, pneg(W)):
        return False, 5
    return True, None


# ------------------------------------------------------------ checking
FAILS = []
CHECKS = 0


def check(cond, msg):
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(msg)


def hb(s):
    return bytes.fromhex(s)


def derive(seed, mlen):
    sk, rho = sha((seed + "/sk").encode()), sha((seed + "/rho").encode())
    if mlen == 0:
        m = b""
    elif mlen == 1024:
        m = b"".join(sha(("%s/m/%d" % (seed, j)).encode()) for j in range(32))
    else:
        m = sha((seed + "/m").encode())
    return sk, rho, m


def par(bit):
    return "odd" if bit else "even"


def tuple_of(c):
    return tuple(hb(c[k]) for k in ("pk", "m", "rho", "R0_bytes", "sig"))


def run(path):
    doc = json.loads(path.read_text())
    stats = {}
    check(doc.get("keys_are_artificial") is True, "keys_are_artificial flag")
    for scheme in ("bip340", "ecdsa"):
        sec = doc[scheme]
        if scheme == "bip340":
            commit, sign, host, hcf, pubf = s_commit, s_sign, s_host, s_hc, lambda sk: s_pubkey(sk)[0]
            kp_tag, nonce_tag = "s2c/schnorr/point", "s2c/schnorr/nonce"
        else:
            commit, host, hcf, pubf = e_commit, e_host, e_hc, e_pub
            sign = lambda sk, m, rho: e_sign(sk, m, rho)[0]
            kp_tag, nonce_tag = "s2c/ecdsa/point", "s2c/ecdsa/nonce"
        ids = [c["id"] for c in sec["valid"] + sec["reject"] + sec["forced_hash"]]
        check(len(ids) == len(set(ids)), scheme + ": duplicate ids")
        combos, msgs, negs = set(), set(), set()
        # ---- valid
        for c in sec["valid"]:
            sk, m, rho, pk, hc, r0, sig = (hb(c[k]) for k in ("sk", "m", "rho", "pk", "hc", "R0_bytes", "sig"))
            seed = c["seed"]
            dsk, drho, dm = derive(seed, len(m) if len(m) in (0, 1024) else 32)
            check((dsk, drho, dm) == (sk, rho, m), c["id"] + ": inputs do not follow the seed derivation")
            check(c["m_length"] == len(m), c["id"] + ": m_length")
            check(pubf(sk) == pk, c["id"] + ": pk")
            check(hcf(rho) == hc, c["id"] + ": hc")
            check(commit(sk, m, hc) == r0, c["id"] + ": R0_bytes")
            if scheme == "bip340":
                check(sign(sk, m, rho) == sig, c["id"] + ": sig")
                check(len(sig) == 64 and bip340_verify(pk, m, sig), c["id"] + ": plain BIP340 verify")
            else:
                s2, negated = e_sign(sk, m, rho)
                check(s2 == sig, c["id"] + ": sig")
                check(c["s_negated"] == negated, c["id"] + ": s_negated label")
                check(ecdsa_plain_verify(pk, m, sig), c["id"] + ": plain ECDSA verify")
                negs.add(negated)
            check(host(pk, m, rho, r0, sig) == (True, None), c["id"] + ": host accepts")
            # parity labels recomputed
            R0 = parse33(r0)
            t = b2i(real_tagged(kp_tag, r0 + rho))
            W = padd(R0, pmul(t))
            if scheme == "bip340":
                Ppt = pmul(b2i(sk))
                Ppar = Ppt[1] & 1
            else:
                Ppar = pk[0] & 1
            check(c["R0_parity"] == par(r0[0] & 1), c["id"] + ": R0_parity")
            check(c["P_parity"] == par(Ppar), c["id"] + ": P_parity")
            check(c["W_parity"] == par(W[1] & 1), c["id"] + ": W_parity")
            combos.add((c["R0_parity"], c["P_parity"], c["W_parity"]))
            msgs.add(len(m))
        check(len(combos) == 8, scheme + ": parity combinations covered %d of 8" % len(combos))
        if scheme == "bip340":
            check({0, 32, 1024} <= msgs, scheme + ": message lengths covered")
        else:
            check(negs == {True, False}, scheme + ": both low-s outcomes covered")
        # ---- reject
        valid_by_id = {c["id"]: c for c in sec["valid"]}
        defects = {}
        for c in sec["reject"]:
            tp = tuple_of(c)
            ok, step = host(*tp)
            check(ok is False, c["id"] + ": host accepted a rejection case")
            check(c["expected"] == "reject", c["id"] + ": expected field")
            if "isolated" in c["id"]:
                # self-contained: it must fail at exactly the named step, and where it claims to be an
                # ordinary signature it must verify as one
                check(step == c["fails_at_step"], c["id"] + ": fails at step %r, want %r" % (step, c["fails_at_step"]))
                if c.get("plain_signature_valid"):
                    pk, m, _, _, sig = tp
                    good = bip340_verify(pk, m, sig) if scheme == "bip340" else ecdsa_plain_verify(pk, m, sig)
                    check(good, c["id"] + ": claimed ordinary signature does not verify")
                defects.setdefault(c["defect"], []).append(step)
                continue
            base = valid_by_id[c["derived_from"]]
            bt = tuple_of(base)
            diff = [i for i in range(5) if tp[i] != bt[i]]
            check(len(diff) == 1, c["id"] + ": %d fields differ from its base (want exactly 1)" % len(diff))
            check(host(*bt) == (True, None), c["id"] + ": base tuple does not verify")
            defects.setdefault(c["defect"], []).append(step)
            if c["defect"] == "nonce_not_W":
                pk, m, _, _, sig = tp
                good = bip340_verify(pk, m, sig) if scheme == "bip340" else ecdsa_plain_verify(pk, m, sig)
                check(good, c["id"] + ": nonce_not_W signature is not valid on its own")
                check(step == 4, c["id"] + ": nonce_not_W should fail at step 4, got %r" % (step,))
            if c["defect"] == "high_s":
                s = b2i(tp[4][32:])
                check(s > HALF, c["id"] + ": high_s case has low s")
            if c["defect"] == "length":
                check(step == "length", c["id"] + ": length defect did not fail on length")
            if c["defect"] in ("R0_prefix", "R0_x_range", "R0_off_curve"):
                check(step == 1, c["id"] + ": R0 defect should fail at step 1, got %r" % (step,))
        stats[scheme] = {"valid": len(sec["valid"]), "reject": len(sec["reject"]),
                         "forced_hash": len(sec["forced_hash"]),
                         "defect_classes": {k: len(v) for k, v in sorted(defects.items())}}
        # high-s cases: the same tuple with s -> n - s must verify through the low-s-free path
        if scheme == "ecdsa":
            for c in sec["reject"]:
                if c["id"].startswith("ecdsa-reject-high-s-"):
                    pk, m, _, _, sig = tuple_of(c)
                    lowsig = sig[:32] + i2b(N - b2i(sig[32:]))
                    check(ecdsa_plain_verify(pk, m, lowsig), c["id"] + ": its low-s twin does not verify")
        # ---- forced hash
        for c in sec["forced_hash"]:
            if "isolated" in c["id"]:
                check_isolated_forced(c, scheme, commit, sign, host, hcf)
                continue
            check(c["requires_hash_override"] is True, c["id"] + ": requires_hash_override")
            fh = c["forced_hash"]
            val = b2i(hb(fh["output"]))
            check(len(hb(fh["output"])) == 32, c["id"] + ": forced output length")
            name = c["id"]
            if "kprime-zero" in name or "W-infinity" in name:
                base = next(v for v in sec["valid"] if v["sk"] == c.get("sk", v["sk"]) and v["rho"] == c["rho"])
                k0 = (commit_k0(scheme, hb(base["sk"]), hb(base["m"]), hb(base["hc"])))
                check(val == (N - k0) % N, name + ": forced t is not n - k0")
            check(fh["tag"] == (kp_tag if ("-t-" in name or "kprime" in name or "W-inf" in name) else nonce_tag),
                  name + ": tag")
            Hash.force_tag, Hash.force_val = fh["tag"], val
            try:
                if c["expected"] == "device_fails":
                    for op in c["operations"]:
                        sk, m, rho, hc = (hb(c[k]) for k in ("sk", "m", "rho", "hc"))
                        try:
                            (commit(sk, m, hc) if op == "device_commit" else sign(sk, m, rho))
                            check(False, name + ": " + op + " succeeded under the override")
                        except Fail as e:
                            want = ("k0" if "k0" in name else "t" if "-t-" in name else "kprime")
                            check(str(e) == want, name + ": " + op + " failed for %r, want %r" % (str(e), want))
                else:
                    ok, step = host(*tuple_of(c))
                    check(ok is False, name + ": host accepted under the override")
                    want = 3 if "W-infinity" in name else 2
                    check(step == want, name + ": host failed at step %r, want %d" % (step, want))
            finally:
                Hash.force_tag = Hash.force_val = None
            # without the override the same inputs work
            if c["expected"] == "device_fails":
                sk, m, rho, hc = (hb(c[k]) for k in ("sk", "m", "rho", "hc"))
                commit(sk, m, hc)
                sign(sk, m, rho)
            else:
                check(host(*tuple_of(c)) == (True, None), name + ": tuple should verify without the override")
    return doc, stats


def check_isolated_forced(c, scheme, commit, sign, host, hcf):
    name = c["id"]
    check(c["requires_hash_override"] is True, name + ": requires_hash_override")
    forced = [c["forced_hash"]] + c.get("additional_forced_hashes", [])
    for f in forced:
        check(len(hb(f["output"])) == 32, name + ": forced output length")
    prim = forced[0]
    Hash.force_tag, Hash.force_val = prim["tag"], b2i(hb(prim["output"]))
    Hash.extra = {f["tag"]: b2i(hb(f["output"])) for f in forced[1:]}
    try:
        if c["expected"] == "device_produces":
            sk, m, rho, hc = (hb(c[k]) for k in ("sk", "m", "rho", "hc"))
            check(hcf(rho) == hc, name + ": hc")
            check(commit(sk, m, hc) == hb(c["R0_bytes"]), name + ": device_commit output")
            check(sign(sk, m, rho) == hb(c["sig"]), name + ": device_sign output")
        else:
            ok, step = host(*tuple_of(c))
            check(ok is (c["expected"] == "accept"), name + ": host result under the override")
            if c["expected"] == "reject":
                check(step == c["fails_at_step"], name + ": host failed at step %r, want %r" % (step, c["fails_at_step"]))
    finally:
        Hash.force_tag = Hash.force_val = None
        Hash.extra = {}
    if c["expected"] == "reject":
        # without the override the reference tuple is still refused; for accept cases the override matters
        ok, _ = host(*tuple_of(c))
        check(ok is False, name + ": should also be refused without the override")


def commit_k0(scheme, sk, m, hc):
    return s_k0(sk, m, hc) if scheme == "bip340" else e_k0(sk, m, hc)


def main():
    path = ROOT / "vectors/bip-anti-exfil.json"
    if len(sys.argv) == 3 and sys.argv[1] == "--json":
        path = pathlib.Path(sys.argv[2])
    doc, stats = run(path)
    print(json.dumps(stats, indent=2))
    print("checks run: %d, failures: %d" % (CHECKS, len(FAILS)))
    for f in FAILS:
        print("FAIL", f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
