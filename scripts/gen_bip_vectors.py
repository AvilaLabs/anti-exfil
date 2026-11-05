#!/usr/bin/env python3
"""Generate vectors/bip-anti-exfil.json, the public test vectors for the BIP.

Every input is derived from a fixed string with SHA256, so the output is
byte-for-byte reproducible. No randomness. All keys are artificial and have
no value. Values are computed with reference/anti_exfil.py. The independent
recomputation is scripts/check_bip_vectors.py and the C comparison is
c/check_vectors.py.

Usage: gen_bip_vectors.py [--check]    (--check compares with the file on disk)
"""
import hashlib
import importlib.util
import itertools
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "vectors/bip-anti-exfil.json"
REFERENCE = ROOT / "reference/anti_exfil.py"


def load_ref():
    spec = importlib.util.spec_from_file_location("ref_for_vectors", REFERENCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ref = load_ref()
P, N = ref._P, ref._N
HALF = (N - 1) // 2
MAXV = (1 << 256) - 1


def H(text):
    return hashlib.sha256(text.encode("ascii")).digest()


def b32(i):
    return i.to_bytes(32, "big")


def hx(b):
    return b.hex()


class Seam:
    """Force the output of one tagged hash; all other hashes are unchanged."""

    def __init__(self, tag, value):
        self.tag, self.value = tag, value

    def __enter__(self):
        self.orig = ref._tagged_hash

        def injected(tag, data):
            if tag == self.tag:
                return b32(self.value)
            return self.orig(tag, data)
        ref._tagged_hash = injected

    def __exit__(self, *exc):
        ref._tagged_hash = self.orig
        return False


# --------------------------------------------------------------- derivation
SCHEMES = {
    "bip340": dict(
        point_tag="s2c/schnorr/point", nonce_tag="s2c/schnorr/nonce",
        commit=ref.device_commit, sign=ref.device_sign, verify=ref.host_verify,
        pubkey=ref.public_key, hostcommit=ref.host_commit),
    "ecdsa": dict(
        point_tag="s2c/ecdsa/point", nonce_tag="s2c/ecdsa/nonce",
        commit=ref.ecdsa_device_commit, sign=ref.ecdsa_device_sign,
        verify=ref.ecdsa_host_verify, pubkey=ref.ecdsa_public_key,
        hostcommit=ref.ecdsa_host_commit),
}


def derive(seed, mkind):
    sk, rho = H(seed + "/sk"), H(seed + "/rho")
    if mkind == "empty":
        m = b""
    elif mkind == "long":
        m = b"".join(H("%s/m/%d" % (seed, j)) for j in range(32))   # 1024 bytes
    else:
        m = H(seed + "/m")
    return sk, rho, m


def props_bip340(sk, rho, m):
    """Return the internal values for a seed, or None if a step would fail."""
    d0 = int.from_bytes(sk, "big")
    if not 0 < d0 < N:
        return None
    try:
        pk, d = ref._schnorr_pub(d0)
        hc = ref.host_commit(rho)
        k0 = ref._schnorr_k0(d, pk, m, hc)
        R0 = ref._mul(k0)
        R0b = ref._ser33(R0)
        t = ref._schnorr_t(R0b, rho)
    except ValueError:
        return None
    kp = (k0 + t) % N
    if kp == 0:
        return None
    W = ref._mul(kp)
    return dict(d0=d0, d=d, pk=pk, hc=hc, k0=k0, R0b=R0b, t=t, kp=kp, W=W,
                P_odd=ref._mul(d0)[1] & 1, R0_odd=R0[1] & 1, W_odd=W[1] & 1)


def props_ecdsa(sk, rho, m):
    d = int.from_bytes(sk, "big")
    if not 0 < d < N:
        return None
    try:
        pk = ref.ecdsa_public_key(sk)
        hc = ref.ecdsa_host_commit(rho)
        k0 = ref._ecdsa_k0(d, pk, m, hc)
        R0 = ref._mul(k0)
        R0b = ref._ser33(R0)
        t = ref._ecdsa_t(R0b, rho)
    except ValueError:
        return None
    kp = (k0 + t) % N
    if kp == 0:
        return None
    W = ref._mul(kp)
    r = W[0] % N
    z = int.from_bytes(m, "big") % N
    s_raw = pow(kp, N - 2, N) * (z + r * d) % N
    if r == 0 or s_raw == 0:
        return None
    return dict(d=d, pk=pk, hc=hc, k0=k0, R0b=R0b, t=t, kp=kp, W=W, r=r, s_raw=s_raw,
                P_odd=pk[0] & 1, R0_odd=R0[1] & 1, W_odd=W[1] & 1,
                s_negated=int(s_raw > HALF))


PROPS = {"bip340": props_bip340, "ecdsa": props_ecdsa}


def find(scheme, name, mkind, pred):
    """First counter i for which the seed's derived values satisfy pred."""
    for i in range(10000):
        seed = "anti-exfil vector/%s/%s/%d" % (scheme, name, i)
        sk, rho, m = derive(seed, mkind)
        pr = PROPS[scheme](sk, rho, m)
        if pr is not None and pred(pr):
            return seed, sk, rho, m, pr
    raise RuntimeError("no seed found for " + name)


def parity_name(bit):
    return "odd" if bit else "even"


def valid_case(scheme, name, mkind, pred, comment, flags):
    sc = SCHEMES[scheme]
    seed, sk, rho, m, pr = find(scheme, name, mkind, pred)
    pk = sc["pubkey"](sk)
    hc = sc["hostcommit"](rho)
    r0 = sc["commit"](sk, m, hc)
    sig = sc["sign"](sk, m, rho)
    assert pk == (pr["pk"] if scheme == "bip340" else pr["pk"])
    assert hc == pr["hc"] and r0 == pr["R0b"]
    assert sc["verify"](pk, m, rho, r0, sig) is True
    case = {"id": "%s-valid-%s" % (scheme, name), "comment": comment, "seed": seed,
            "sk": hx(sk), "m": hx(m), "rho": hx(rho), "pk": hx(pk), "hc": hx(hc),
            "R0_bytes": hx(r0), "sig": hx(sig),
            "R0_parity": parity_name(pr["R0_odd"]),
            "P_parity": parity_name(pr["P_odd"]),
            "W_parity": parity_name(pr["W_odd"])}
    if scheme == "ecdsa":
        case["s_negated"] = bool(pr["s_negated"])
    case["m_length"] = len(m)
    return case, pr


def make_valid(scheme):
    cases, prs = [], {}
    for r0, p, w in itertools.product((0, 1), repeat=3):
        name = "r0-%s-p-%s-w-%s" % (parity_name(r0), parity_name(p), parity_name(w))
        comment = ("R0 has %s y, the public key point P has %s y and W = R0 + t*G has %s y."
                   % (parity_name(r0), parity_name(p), parity_name(w)))
        if scheme == "bip340":
            comment += " The device negates its secret key when P is odd and negates k' when W is odd."
        c, pr = valid_case(scheme, name, "32",
                           lambda q, r0=r0, p=p, w=w: (q["R0_odd"], q["P_odd"], q["W_odd"]) == (r0, p, w),
                           comment, None)
        cases.append(c)
        prs[c["id"]] = pr
    if scheme == "bip340":
        for name, mkind, text in (
                ("msg-empty", "empty", "Empty message (zero bytes). m is the empty string in the JSON."),
                ("msg-32", "32", "32-byte message."),
                ("msg-long", "long", "Long message of 1024 bytes.")):
            c, pr = valid_case(scheme, name, mkind, lambda q: True, text, None)
            cases.append(c)
            prs[c["id"]] = pr
    else:
        for name, neg, text in (
                ("low-s-negated", 1,
                 "The raw s computed in step 4 is above (n-1)/2, so the device replaces it with n - s."),
                ("low-s-not-negated", 0,
                 "The raw s computed in step 4 is already at most (n-1)/2, so s is used as computed.")):
            c, pr = valid_case(scheme, name, "32", lambda q, neg=neg: q["s_negated"] == neg, text, None)
            cases.append(c)
            prs[c["id"]] = pr
    return cases, prs


# --------------------------------------------------------------- rejections
def lift_exists(x):
    return ref._lift_x(x) is not ref._INF


def off_curve_x(label):
    for i in range(1000):
        x = int.from_bytes(H("anti-exfil vector/off-curve/%s/%d" % (label, i)), "big")
        if x < P and not lift_exists(x):
            return x
    raise RuntimeError("no off-curve x")


def ecdsa_plain_valid(pk33, m, sig):
    """Plain ECDSA verify with low-s, used only to show a rejected signature is otherwise valid."""
    Q = ref._parse33(pk33)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (0 < r < N and 0 < s <= HALF):
        return False
    z = int.from_bytes(m, "big") % N
    si = pow(s, N - 2, N)
    V = ref._add(ref._mul(z * si % N), ref._mul(r * si % N, Q))
    return V is not ref._INF and V[0] % N == r


def flip(b, i=0):
    return b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]


def make_rejects(scheme, valid, prs):
    sc = SCHEMES[scheme]
    ids = [c["id"] for c in valid]
    A = valid[0]            # all even for bip340/ecdsa combos (r0-even-p-even-w-even)
    B = valid[7]            # all odd
    assert A["id"].endswith("r0-even-p-even-w-even") and B["id"].endswith("r0-odd-p-odd-w-odd")
    other = valid[1]
    out = []

    def tup(c):
        return {k: bytes.fromhex(c[k]) for k in ("pk", "m", "rho", "R0_bytes", "sig")}

    def add(name, defect, base, comment, **changes):
        t = tup(base)
        t.update(changes)
        assert sc["verify"](t["pk"], t["m"], t["rho"], t["R0_bytes"], t["sig"]) is False, name
        out.append({"id": "%s-reject-%s" % (scheme, name), "defect": defect,
                    "derived_from": base["id"], "comment": comment,
                    "pk": hx(t["pk"]), "m": hx(t["m"]), "rho": hx(t["rho"]),
                    "R0_bytes": hx(t["R0_bytes"]), "sig": hx(t["sig"]), "expected": "reject"})

    pkl = 32 if scheme == "bip340" else 33
    # single-value defects on two bases
    for tag, base in (("a", A), ("b", B)):
        t = tup(base)
        wrong_rho = H("anti-exfil vector/%s/wrong-rho/%s" % (scheme, tag))
        add("wrong-rho-" + tag, "wrong_rho", base,
            "rho differs from the one the device was given. t changes, so W no longer matches r.",
            rho=wrong_rho)
        add("wrong-R0-" + tag, "wrong_R0", base,
            "R0_bytes is a valid point from another vector, not the device's commitment for this signature.",
            R0_bytes=bytes.fromhex(other["R0_bytes"]))
        wm = flip(t["m"], 0) if len(t["m"]) else b"\x00"
        add("wrong-m-" + tag, "wrong_m", base,
            "The message differs from the one that was signed (first bit flipped).", m=wm)
        add("wrong-pk-" + tag, "wrong_pk", base,
            "pk is a valid public key of a different key.", pk=bytes.fromhex(other["pk"]))
        r_other = bytes.fromhex(other["sig"])[:32]
        add("r-changed-" + tag, "r_changed", base,
            "The first half of sig (r) is replaced by the r of another signature; s is unchanged.",
            sig=r_other + t["sig"][32:])
        s_int = int.from_bytes(t["sig"][32:], "big")
        if scheme == "bip340":
            s_new = (s_int + 1) % N
        else:
            s_new = s_int + 1 if s_int + 1 <= HALF else s_int - 1
        add("s-changed-" + tag, "s_changed", base,
            "The second half of sig (s) is changed by one, staying in range%s." %
            (" and low" if scheme == "ecdsa" else ""), sig=t["sig"][:32] + b32(s_new))
    # encodings, on A
    t = tup(A)
    r0 = t["R0_bytes"]
    for pre in (b"\x06", b"\x07", b"\x00", b"\x04"):
        add("R0-prefix-%02x" % pre[0], "R0_prefix", A,
            "R0_bytes begins with 0x%02x. Only 0x02 and 0x03 are accepted by parse33%s."
            % (pre[0], " (0x06 and 0x07 are hybrid prefixes in SEC1)" if pre[0] in (6, 7) else ""),
            R0_bytes=pre + r0[1:])
    for label, xv in (("p", P), ("max", MAXV)):
        xb = b32(xv)
        add("R0-x-%s" % label, "R0_x_range", A,
            "R0_bytes is 0x02 followed by %s, an x coordinate that is not below p." %
            ("p" if label == "p" else "2^256-1"), R0_bytes=b"\x02" + xb)
        if scheme == "bip340":
            add("pk-x-%s" % label, "pk_x_range", A,
                "pk is %s, an x coordinate that is not below p." % ("p" if label == "p" else "2^256-1"),
                pk=xb)
        else:
            add("pk-x-%s" % label, "pk_x_range", A,
                "pk is 0x02 followed by %s, an x coordinate that is not below p." %
                ("p" if label == "p" else "2^256-1"), pk=b"\x02" + xb)
    if scheme == "bip340":
        add("sig-r-p", "sig_r_range", A, "The r half of sig is p, which is not below p.",
            sig=b32(P) + t["sig"][32:])
        add("sig-s-n", "sig_s_range", A, "The s half of sig is n, which is not below n.",
            sig=t["sig"][:32] + b32(N))
    else:
        add("sig-r-zero", "sig_r_range", A, "The r half of sig is 0.", sig=b32(0) + t["sig"][32:])
        add("sig-r-n", "sig_r_range", A, "The r half of sig is n, which is not below n.",
            sig=b32(N) + t["sig"][32:])
        add("sig-s-zero", "sig_s_range", A, "The s half of sig is 0.", sig=t["sig"][:32] + b32(0))
        add("sig-s-n", "sig_s_range", A, "The s half of sig is n.", sig=t["sig"][:32] + b32(N))
    xoff = off_curve_x("R0")
    add("R0-off-curve", "R0_off_curve", A,
        "R0_bytes is 0x02 followed by an x for which x^3 + 7 has no square root, so there is no point.",
        R0_bytes=b"\x02" + b32(xoff))
    xoff = off_curve_x("pk")
    add("pk-off-curve", "pk_off_curve", A,
        "pk is %san x for which x^3 + 7 has no square root, so there is no point." %
        ("" if scheme == "bip340" else "0x02 followed by "),
        pk=(b32(xoff) if scheme == "bip340" else b"\x02" + b32(xoff)))
    if scheme == "ecdsa":
        for prefix in (b"\x06", b"\x07", b"\x04", b"\x00"):
            add("pk-prefix-%02x" % prefix[0], "pk_prefix", A,
                "pk begins with 0x%02x. Only 0x02 and 0x03 are accepted by parse33." % prefix[0],
                pk=prefix + t["pk"][1:])
        # high-s: correct r, s replaced by n - s
        for tag, base in (("a", A), ("b", B)):
            bt = tup(base)
            s_int = int.from_bytes(bt["sig"][32:], "big")
            add("high-s-" + tag, "high_s", base,
                "sig is (r, n - s) with the correct r. It is valid ECDSA but s is above (n-1)/2.",
                sig=bt["sig"][:32] + b32(N - s_int))
        s_int = int.from_bytes(t["sig"][32:], "big")
        add("s-half-plus-one", "high_s", A,
            "s is (n-1)/2 + 1, the smallest value above the low-s limit.",
            sig=t["sig"][:32] + b32(HALF + 1))
    # wrong lengths
    def short(b):
        return b[:-1]

    def long_(b):
        return b + b"\x00"
    for label, key in (("pk", "pk"), ("rho", "rho"), ("R0_bytes", "R0_bytes"), ("sig", "sig")):
        add("%s-length-short" % label, "length", A, "%s is one byte too short." % label,
            **{key: short(t[key])})
        add("%s-length-long" % label, "length", A, "%s is one byte too long (a zero byte appended)." % label,
            **{key: long_(t[key])})
    if scheme == "ecdsa":
        add("m-length-short", "length", A, "m is 31 bytes. ECDSA m must be exactly 32.", m=short(t["m"]))
        add("m-length-long", "length", A, "m is 33 bytes. ECDSA m must be exactly 32.", m=long_(t["m"]))
    # valid signatures from the right key with a nonce other than W
    d0 = int.from_bytes(bytes.fromhex(A["sk"]), "big")
    pr = prs[A["id"]]
    msg, pk = bytes.fromhex(A["m"]), bytes.fromhex(A["pk"])
    for label, k, text in (
            ("other-nonce", int.from_bytes(H("anti-exfil vector/%s/other-nonce" % scheme), "big") % N,
             "A valid signature from the right key made with a nonce k of the signer's choice instead of W's k'."),
            ("base-nonce", pr["k0"],
             "A valid signature from the right key made with the base nonce k0 alone, as a device that ignores rho would.")):
        assert 0 < k < N and k != pr["kp"]
        if scheme == "bip340":
            Rk = ref._mul(k)
            kk = k if Rk[1] % 2 == 0 else N - k
            rb = b32(Rk[0])
            e = int.from_bytes(ref._tagged_hash("BIP0340/challenge", rb + pk + msg), "big") % N
            sg = rb + b32((kk + e * pr["d"]) % N)
            assert ref._schnorr_verify(pk, msg, sg)
        else:
            Rk = ref._mul(k)
            r = Rk[0] % N
            z = int.from_bytes(msg, "big") % N
            s = pow(k, N - 2, N) * (z + r * pr["d"]) % N
            if s > HALF:
                s = N - s
            sg = b32(r) + b32(s)
            assert ecdsa_plain_valid(pk, msg, sg)
        add(label, "nonce_not_W", A, text + " It verifies as a plain signature but its r is not x(W).", sig=sg)
    return out


# ------------------------------------------------------------ forced hashes
def make_forced(scheme, base, prs):
    sc = SCHEMES[scheme]
    pr = prs[base["id"]]
    sk, m, rho = (bytes.fromhex(base[k]) for k in ("sk", "m", "rho"))
    hc = bytes.fromhex(base["hc"])
    nonce_tag, point_tag = sc["nonce_tag"], sc["point_tag"]
    out = []

    def fails(call):
        try:
            call()
        except ValueError:
            return True
        return False

    def device(name, tag, value, ops, comment, why):
        with Seam(tag, value):
            for op in ops:
                fn = (lambda: sc["commit"](sk, m, hc)) if op == "device_commit" else (lambda: sc["sign"](sk, m, rho))
                assert fails(fn), (name, op)
        out.append({"id": "%s-forced-%s" % (scheme, name), "requires_hash_override": True,
                    "comment": comment, "operations": ops,
                    "forced_hash": {"tag": tag, "output": hx(b32(value)), "why": why},
                    "sk": base["sk"], "m": base["m"], "rho": base["rho"], "hc": base["hc"],
                    "expected": "device_fails"})

    def host(name, tag, value, comment, why):
        t = [bytes.fromhex(base[k]) for k in ("pk", "m", "rho", "R0_bytes", "sig")]
        with Seam(tag, value):
            assert sc["verify"](*t) is False, name
        out.append({"id": "%s-forced-host-%s" % (scheme, name), "requires_hash_override": True,
                    "comment": comment, "operations": ["host_verify"],
                    "forced_hash": {"tag": tag, "output": hx(b32(value)), "why": why},
                    "pk": base["pk"], "m": base["m"], "rho": base["rho"],
                    "R0_bytes": base["R0_bytes"], "sig": base["sig"], "expected": "reject"})

    both = ["device_commit", "device_sign"]
    if scheme == "bip340":
        device("k0-zero", nonce_tag, 0, both,
               "The nonce hash returns 0, so k0 = 0 and the device must fail.",
               "k0 = int(output) mod n = 0")
        device("k0-n", nonce_tag, N, both,
               "The nonce hash returns n, which reduces to 0 mod n, so the device must fail.",
               "k0 = n mod n = 0")
    else:
        device("k0-zero", nonce_tag, 0, both,
               "The nonce hash returns 0, so the device must fail.", "k0 = 0 is not in 1..n-1")
        device("k0-n", nonce_tag, N, both,
               "The nonce hash returns n. ECDSA does not reduce, so the device must fail.",
               "k0 = n is not below n")
        device("k0-max", nonce_tag, MAXV, both,
               "The nonce hash returns 2^256-1. ECDSA does not reduce or retry, so the device must fail.",
               "k0 = 2^256-1 is not below n")
    device("t-n", point_tag, N, ["device_sign"],
           "The point-tweak hash returns n, so t >= n and the device must fail in step 4.", "t = n")
    device("t-max", point_tag, MAXV, ["device_sign"],
           "The point-tweak hash returns 2^256-1, so t >= n and the device must fail in step 4.",
           "t = 2^256-1")
    kneg = (N - pr["k0"]) % N
    assert (pr["k0"] + kneg) % N == 0
    device("kprime-zero", point_tag, kneg, ["device_sign"],
           "The point-tweak hash returns n - k0, where k0 is this vector's base nonce, so k' = 0 and the device must fail in step 4.",
           "t = n - k0, so k' = (k0 + t) mod n = 0")
    host("t-n", point_tag, N,
         "The host's point-tweak hash returns n, so t >= n and the host must reject the otherwise valid tuple.", "t = n")
    host("t-max", point_tag, MAXV,
         "The host's point-tweak hash returns 2^256-1, so t >= n and the host must reject.", "t = 2^256-1")
    host("W-infinity", point_tag, kneg,
         "The host's point-tweak hash returns n - k0, so W = R0 + t*G is the point at infinity and the host must reject.",
         "t = n - k0, so W = infinity")
    return out


# ------------------------------------------------- isolated rejection cases
# Each case below fails only on the check it names. Every other check passes, so an
# implementation that skips the named check accepts the tuple (confirmed against
# mutants in validation/mutants/isolated_vector_confirm.json).
class MultiSeam:
    """Force the outputs of several tagged hashes at once; others are unchanged."""

    def __init__(self, forced):
        self.forced = forced

    def __enter__(self):
        self.orig = ref._tagged_hash
        forced, orig = self.forced, self.orig

        def injected(tag, data):
            if tag in forced:
                return b32(forced[tag])
            return orig(tag, data)
        ref._tagged_hash = injected

    def __exit__(self, *exc):
        ref._tagged_hash = self.orig
        return False


def iso_keys(scheme, name):
    seed = "anti-exfil vector/%s/isolated/%s" % (scheme, name)
    return seed, H(seed + "/sk"), H(seed + "/rho"), H(seed + "/m")


def sig_with_nonce(scheme, sk, m, k):
    """A valid ordinary signature from sk made with nonce k (BIP340, or low-s ECDSA)."""
    d0 = int.from_bytes(sk, "big")
    Rk = ref._mul(k)
    if scheme == "bip340":
        pk, d = ref._schnorr_pub(d0)
        kk = k if Rk[1] % 2 == 0 else N - k
        rb = b32(Rk[0])
        e = int.from_bytes(ref._tagged_hash("BIP0340/challenge", rb + pk + m), "big") % N
        sig = rb + b32((kk + e * d) % N)
        assert ref._schnorr_verify(pk, m, sig)
        return sig
    r = Rk[0] % N
    z = int.from_bytes(m, "big") % N
    s = pow(k, N - 2, N) * (z + r * d0) % N
    if s > HALF:
        s = N - s
    sig = b32(r) + b32(s)
    assert ecdsa_plain_valid(ref.ecdsa_public_key(sk), m, sig)
    return sig


def iso_reject(scheme, name, defect, isolates, comment, step, seed, tup, plain_valid):
    sc = SCHEMES[scheme]
    pk, m, rho, r0, sig = tup
    assert sc["verify"](pk, m, rho, r0, sig) is False, name
    case = {"id": "%s-reject-isolated-%s" % (scheme, name), "defect": defect, "isolates": isolates,
            "comment": comment, "fails_at_step": step}
    if seed:
        case["seed"] = seed
    case.update({"pk": hx(pk), "m": hx(m), "rho": hx(rho), "R0_bytes": hx(r0), "sig": hx(sig)})
    if plain_valid:
        case["plain_signature_valid"] = True
    case["expected"] = "reject"
    return case


def make_isolated_rejects(scheme):
    sc = SCHEMES[scheme]
    out = []
    # pk is not a curve point; the signature satisfies the verification equation when the pk
    # term is dropped, so only the failed lift of pk refuses it
    seed, sk, rho, m = iso_keys(scheme, "pk-off-curve")
    xoff = off_curve_x("isolated-pk")
    pkbad = b32(xoff) if scheme == "bip340" else b"\x02" + b32(xoff)
    for a in range(1, 100):
        R0b = ref._ser33(ref._mul(a))
        t = int.from_bytes(ref._tagged_hash(sc["point_tag"], R0b + rho), "big")
        if t >= N:
            continue
        kp = (a + t) % N
        W = ref._mul(kp)
        break
    if scheme == "bip340":
        s = kp if W[1] % 2 == 0 else N - kp
        sig = b32(W[0]) + b32(s)
        text = ("pk is an x with no curve point. R0 is valid and the signature is (x(W), s) with s*G = W, "
                "which satisfies the verification equation when the pk term is dropped, so only the failed "
                "lift of pk refuses it.")
        step, iso = 5, "BIP340 Verify: pk must be the x coordinate of a curve point"
    else:
        z = int.from_bytes(m, "big") % N
        s = pow(kp, N - 2, N) * z % N
        s = min(s, N - s)
        sig = b32(W[0] % N) + b32(s)
        text = ("pk is 0x02 followed by an x with no curve point. R0 is valid and the signature satisfies "
                "V = W when the pk term is dropped, so only parse33 failing on pk refuses it.")
        step, iso = 1, "parse33(pk) must succeed"
    out.append(iso_reject(scheme, "pk-off-curve", "isolated_pk_off_curve", iso, text, step, None,
                          (pkbad, m, rho, R0b, sig), False))
    # R0_bytes does not parse; the signature uses nonce t, so it holds when R0 is dropped
    x_ok = b32(ref._G[0])
    for name, r0, text in (
            ("R0-prefix-04", b"\x04" + x_ok, "R0_bytes begins with 0x04 (an uncompressed prefix)"),
            ("R0-x-off-curve", b"\x02" + b32(off_curve_x("isolated-R0")), "R0_bytes is 0x02 followed by an x with no curve point"),
            ("R0-x-not-below-p", b"\x02" + b32(P), "R0_bytes is 0x02 followed by p, an x not below p")):
        seed, sk, rho, m = iso_keys(scheme, name)
        t = int.from_bytes(ref._tagged_hash(sc["point_tag"], r0 + rho), "big")
        assert 0 < t < N
        sig = sig_with_nonce(scheme, sk, m, t)
        out.append(iso_reject(
            scheme, name, "isolated_R0_unparsable", "parse33(R0_bytes) must succeed",
            text + ". The signature is an ordinary valid signature from the key whose nonce is t = H(R0_bytes || rho), "
            "so x(W) = x(t*G) would match if R0 were dropped. Only the failed parse of R0_bytes refuses it.",
            1, seed, (sc["pubkey"](sk), m, rho, r0, sig), True))
    return out


def make_isolated_forced(scheme):
    sc = SCHEMES[scheme]
    ptag, ntag = sc["point_tag"], sc["nonce_tag"]
    out = []

    def forced(tag, value, why):
        return {"tag": tag, "output": hx(b32(value)), "why": why}

    def host_case(name, expected, forced_list, tup, comment, isolates, step=None, seed=None):
        pk, m, rho, r0, sig = tup
        with MultiSeam({f["tag"]: int(f["output"], 16) for f in forced_list}):
            got = sc["verify"](pk, m, rho, r0, sig)
        assert got is (expected == "accept"), name
        case = {"id": "%s-forced-isolated-%s" % (scheme, name), "requires_hash_override": True,
                "isolates": isolates, "comment": comment, "operations": ["host_verify"],
                "forced_hash": forced_list[0]}
        if len(forced_list) > 1:
            case["additional_forced_hashes"] = forced_list[1:]
        if seed:
            case["seed"] = seed
        case.update({"pk": hx(pk), "m": hx(m), "rho": hx(rho), "R0_bytes": hx(r0), "sig": hx(sig)})
        if step:
            case["fails_at_step"] = step
        case["expected"] = expected
        out.append(case)

    # W = R0 + t*G with t forced to 5: R0 = 5G is the doubling case, R0 = -5G gives infinity
    seed, sk, rho, m = iso_keys(scheme, "W")
    pk = sc["pubkey"](sk)
    tG = ref._mul(5)
    sig_pos = sig_with_nonce(scheme, sk, m, 10)
    sig_neg = sig_with_nonce(scheme, sk, m, N - 10)
    why5 = "t = 5"
    host_case("W-doubling", "accept", [forced(ptag, 5, why5)], (pk, m, rho, ref._ser33(tG), sig_pos),
              "The point-tweak hash returns 5 and R0 = 5*G, so W = R0 + t*G = 10*G is the doubling case of the "
              "point addition. The signature is valid with nonce 10, so the host must accept. A host that fails "
              "on R0 = t*G refuses it.", "W = R0 + t*G with R0 = t*G must be computed as a doubling", seed=seed)
    host_case("W-infinity-from-negated-R0", "reject", [forced(ptag, 5, why5)],
              (pk, m, rho, ref._ser33(ref._neg(tG)), sig_neg),
              "The point-tweak hash returns 5 and R0 = -5*G, so W = R0 + t*G is the point at infinity. The "
              "signature is valid with nonce n - 10 and would pass every later check if W were computed as the "
              "double of R0, so only the infinity check refuses it.",
              "W = R0 + t*G must not be the point at infinity", step=3, seed=seed)
    if scheme == "bip340":
        # s = n reduces to 0: with e and t forced, R = -e*P and sig = (x(R), n) satisfies R = s*G - e*P
        seed, sk, rho, m = iso_keys(scheme, "s-equals-n")
        pk = ref.public_key(sk)
        Q = ref._lift_x(int.from_bytes(pk, "big"))
        for e in range(2, 100):
            R = ref._mul(e, ref._neg(Q))
            if R[1] % 2 == 0:
                break
        sig = b32(R[0]) + b32(N)
        host_case("s-equals-n", "reject",
                  [forced(ptag, 0, "t = 0, so W = R0"), forced("BIP0340/challenge", e, "e = %d" % e)],
                  (pk, m, rho, ref._ser33(R), sig),
                  "The point-tweak hash returns 0 and the BIP340 challenge hash returns %d. R0 = -%d*P, "
                  "sig = (x(R0), n). Reduced mod n the s half is 0, which would satisfy R = s*G - e*P, so only "
                  "the range check s < n refuses it." % (e, e),
                  "BIP340 Verify: s must be below n", step=5, seed=seed)
    else:
        v, tv = 11, 13
        for name, target in (("s-one", 1), ("s-low-limit", HALF)):
            seed, sk, rho, _ = iso_keys(scheme, name)
            d = int.from_bytes(sk, "big")
            kp = v + tv
            r = ref._mul(kp)[0] % N
            m = b32((target * kp - r * d) % N)
            fh = [forced(ptag, tv, "t = %d" % tv), forced(ntag, v, "k0 = %d" % v)]
            with MultiSeam({ptag: tv, ntag: v}):
                hc = ref.ecdsa_host_commit(rho)
                r0 = ref.ecdsa_device_commit(sk, m, hc)
                sig = ref.ecdsa_device_sign(sk, m, rho)
                pk = ref.ecdsa_public_key(sk)
            assert int.from_bytes(sig[32:], "big") == target, name
            lead = ("The nonce hash returns %d and the point-tweak hash returns %d, so k' = %d and m is chosen "
                    "so that the raw s is %s. " % (v, tv, kp, "1" if target == 1 else "(n-1)/2, the largest low-s value"))
            out.append({"id": "%s-forced-isolated-%s-device" % (scheme, name), "requires_hash_override": True,
                        "isolates": "step 4: s = 1 is a valid s and is not refused" if target == 1 else
                        "step 4: s = (n-1)/2 is kept as is, not negated",
                        "comment": lead + "The device must return exactly R0_bytes and sig.",
                        "operations": ["device_commit", "device_sign"], "forced_hash": fh[0],
                        "additional_forced_hashes": fh[1:], "seed": seed, "sk": hx(sk), "m": hx(m),
                        "rho": hx(rho), "hc": hx(hc), "R0_bytes": hx(r0), "sig": hx(sig),
                        "expected": "device_produces"})
            host_case(name + "-host", "accept", fh[:1], (pk, m, rho, r0, sig),
                      lead + "The signature is valid and the host must accept it. A host whose s check is off by "
                      "one at the %s refuses it." % ("bottom (s = 1)" if target == 1 else "low-s limit (s <= (n-1)/2)"),
                      "host step 4: 0 < s <= (n-1)/2 includes both ends", seed=seed)
    return out


def build():
    doc = {
        "title": "Anti-exfil signing for BIP340 and ECDSA: test vectors",
        "specification_revision": "0.16",
        "license": "MIT",
        "keys_are_artificial": True,
        "encoding": "All byte strings are lowercase hex. An empty message is the empty string.",
        "derivation": ("sk = SHA256(seed || \"/sk\"), rho = SHA256(seed || \"/rho\"), a 32-byte m = "
                       "SHA256(seed || \"/m\"), and the long message is SHA256(seed || \"/m/j\") for "
                       "j = 0..31 concatenated. seed is the ASCII string in each valid case."),
        "classes": {
            "valid": "sk, m, rho -> pk, hc, R0_bytes, sig. A device must produce these bytes; a host must accept the tuple.",
            "reject": "A host must reject the (pk, m, rho, R0_bytes, sig) tuple. No secret key is given.",
            "forced_hash": "Needs a hash override. forced_hash.tag output is replaced by the stated 32 bytes; every other hash is computed normally.",
        },
    }
    counts = {}
    for scheme in ("bip340", "ecdsa"):
        valid, prs = make_valid(scheme)
        rejects = make_rejects(scheme, valid, prs)
        forced = make_forced(scheme, valid[0], prs)
        rejects += make_isolated_rejects(scheme)
        forced += make_isolated_forced(scheme)
        doc[scheme] = {"valid": valid, "reject": rejects, "forced_hash": forced}
        counts[scheme] = (len(valid), len(rejects), len(forced))
    return doc, counts


def main():
    doc, counts = build()
    text = json.dumps(doc, indent=2) + "\n"
    if "--check" in sys.argv:
        same = OUT.exists() and OUT.read_text() == text
        print("matches file on disk" if same else "DIFFERS from file on disk")
        return 0 if same else 1
    OUT.write_text(text)
    for scheme, (v, r, f) in counts.items():
        print("%s: valid %d, reject %d, forced_hash %d" % (scheme, v, r, f))
    print("wrote", OUT.relative_to(ROOT), hashlib.sha256(text.encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
