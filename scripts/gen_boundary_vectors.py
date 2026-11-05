#!/usr/bin/env python3
"""Generate vectors/bip-anti-exfil-boundary.json, boundary vectors for the BIP.

A companion to vectors/bip-anti-exfil.json, which is not changed. Every input
is derived from a fixed string with SHA256 as in that file, except the values
a case fixes on purpose (named under "fixed" in the case): the ECDSA message
and the secret key. No randomness. All keys are artificial. Values are computed
with reference/anti_exfil.py.

Usage: gen_boundary_vectors.py [--check]       compare with the file on disk
       gen_boundary_vectors.py --crosscheck    recompute the ECDSA message cases with the
                                               arithmetic of validation/second_implementations/python/secp.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "vectors/bip-anti-exfil-boundary.json"
REFERENCE = ROOT / "reference/anti_exfil.py"
OTHER = ROOT / "validation/second_implementations/python/secp.py"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ref = load(REFERENCE, "ref_for_boundary_vectors")
P, N = ref._P, ref._N
HALF = (N - 1) // 2
MAXV = (1 << 256) - 1


def H(text):
    return hashlib.sha256(text.encode("ascii")).digest()


def b32(i):
    return i.to_bytes(32, "big")


def hx(b):
    return b.hex()


SCHEMES = {
    "bip340": dict(commit=ref.device_commit, sign=ref.device_sign, verify=ref.host_verify,
                   pubkey=ref.public_key, hostcommit=ref.host_commit),
    "ecdsa": dict(commit=ref.ecdsa_device_commit, sign=ref.ecdsa_device_sign, verify=ref.ecdsa_host_verify,
                  pubkey=ref.ecdsa_public_key, hostcommit=ref.ecdsa_host_commit),
}


def odd(bit):
    return "odd" if bit else "even"


def tuple_values(scheme, sk, rho, m):
    """Internal values of one honest run, or None if a step of it would fail."""
    d0 = int.from_bytes(sk, "big")
    try:
        if scheme == "bip340":
            pk, d = ref._schnorr_pub(d0)
            hc = ref.host_commit(rho)
            k0 = ref._schnorr_k0(d, pk, m, hc)
            R0b = ref._ser33(ref._mul(k0))
            t = ref._schnorr_t(R0b, rho)
        else:
            d = d0
            pk = ref.ecdsa_public_key(sk)
            hc = ref.ecdsa_host_commit(rho)
            k0 = ref._ecdsa_k0(d, pk, m, hc)
            R0b = ref._ser33(ref._mul(k0))
            t = ref._ecdsa_t(R0b, rho)
    except ValueError:
        return None
    kp = (k0 + t) % N
    if kp == 0:
        return None
    W = ref._mul(kp)
    if scheme == "ecdsa":
        r = W[0] % N
        s = pow(kp, N - 2, N) * ((int.from_bytes(m, "big") % N) + r * d) % N
        if r == 0 or s == 0:
            return None
    return dict(d=d, pk=pk, hc=hc, k0=k0, R0b=R0b, t=t, kp=kp, W=W,
                P_odd=ref._mul(d0)[1] & 1, R0_odd=ref._mul(k0)[1] & 1, W_odd=W[1] & 1,
                s_negated=int(scheme == "ecdsa" and s > HALF))


def valid_case(scheme, name, comment, sk=None, m=None):
    """sk and m are fixed when given; otherwise they come from the seed."""
    for i in range(10000):
        seed = "anti-exfil boundary/%s/%s/%d" % (scheme, name, i)
        k = sk if sk is not None else H(seed + "/sk")
        mm = m if m is not None else H(seed + "/m")
        rho = H(seed + "/rho")
        pr = tuple_values(scheme, k, rho, mm)
        if pr is not None:
            break
    else:
        raise RuntimeError("no seed for " + name)
    sc = SCHEMES[scheme]
    pk, hc = sc["pubkey"](k), sc["hostcommit"](rho)
    r0, sig = sc["commit"](k, mm, hc), sc["sign"](k, mm, rho)
    assert pk == pr["pk"] and hc == pr["hc"] and r0 == pr["R0b"]
    assert sc["verify"](pk, mm, rho, r0, sig) is True
    case = {"id": "%s-boundary-%s" % (scheme, name), "comment": comment, "seed": seed,
            "fixed": [x for x, v in (("sk", sk), ("m", m)) if v is not None],
            "sk": hx(k), "m": hx(mm), "rho": hx(rho), "pk": hx(pk), "hc": hx(hc),
            "R0_bytes": hx(r0), "sig": hx(sig),
            "R0_parity": odd(pr["R0_odd"]), "P_parity": odd(pr["P_odd"]), "W_parity": odd(pr["W_odd"])}
    if scheme == "ecdsa":
        case["s_negated"] = bool(pr["s_negated"])
        case["z"] = hx(b32(int.from_bytes(mm, "big") % N))
        reduced = b32(int.from_bytes(mm, "big") % N)
        if reduced != mm:
            # k0 hashes m as given. With the reduced message the nonce would differ, so the case pins this.
            assert ref._ecdsa_k0(pr["d"], pk, reduced, hc) != pr["k0"]
    case["m_length"] = len(mm)
    return case


def device_fail(scheme, name, sk_int, comment):
    seed = "anti-exfil boundary/%s/%s" % (scheme, name)
    sk, rho, m = b32(sk_int), H(seed + "/rho"), H(seed + "/m")
    sc = SCHEMES[scheme]
    hc = sc["hostcommit"](rho)
    for call in (lambda: sc["commit"](sk, m, hc), lambda: sc["sign"](sk, m, rho)):
        try:
            call()
        except ValueError:
            continue
        raise AssertionError("device accepted key " + name)
    return {"id": "%s-boundary-%s" % (scheme, name), "comment": comment, "seed": seed, "fixed": ["sk"],
            "sk": hx(sk), "m": hx(m), "rho": hx(rho), "hc": hx(hc),
            "operations": ["device_commit", "device_sign"], "expected": "device_fails"}


def tup(c):
    return {k: bytes.fromhex(c[k]) for k in ("pk", "m", "rho", "R0_bytes", "sig")}


def host_steps(scheme, t):
    """Which of steps 1 to 4 of the host check pass for a tuple (1: parse R0, 2: t < n, 3: W not infinity, 4: r)."""
    R0 = ref._parse33(t["R0_bytes"])
    out = {1: R0 is not ref._INF}
    tag = "s2c/schnorr/point" if scheme == "bip340" else "s2c/ecdsa/point"
    tt = int.from_bytes(ref._tagged_hash(tag, t["R0_bytes"] + t["rho"]), "big")
    out[2] = tt < N
    W = ref._add(R0, ref._mul(tt)) if out[1] and out[2] else ref._INF
    out[3] = W is not ref._INF
    if out[3]:
        sig = t["sig"]
        if scheme == "bip340":
            out[4] = b32(W[0]) == sig[:32]
        else:
            r = int.from_bytes(sig[:32], "big")
            out[4] = 0 < r < N and W[0] % N == r
    return out


def reject_case(scheme, base, name, defect, names, comment, also, **changes):
    sc = SCHEMES[scheme]
    t = tup(base)
    t.update(changes)
    assert sc["verify"](t["pk"], t["m"], t["rho"], t["R0_bytes"], t["sig"]) is False, name
    return {"id": "%s-boundary-reject-%s" % (scheme, name), "defect": defect, "derived_from": base["id"],
            "names": names, "isolated": not also, "also_fails": also, "comment": comment,
            "pk": hx(t["pk"]), "m": hx(t["m"]), "rho": hx(t["rho"]), "R0_bytes": hx(t["R0_bytes"]),
            "sig": hx(t["sig"]), "expected": "reject"}


def make_bip340():
    valid = [
        valid_case("bip340", "sk-one", "sk = 1, the smallest key. P = G has even y, so the device keeps d = 1.", sk=b32(1)),
        valid_case("bip340", "sk-n-minus-one", "sk = n - 1, the largest key. P = -G has odd y, so the device uses d = n - (n - 1) = 1.", sk=b32(N - 1)),
    ]
    fail = [
        device_fail("bip340", "sk-zero", 0, "sk = 0. The device must fail in both device_commit and device_sign."),
        device_fail("bip340", "sk-n", N, "sk = n, not below n. The device must fail; it must not reduce the key to 0."),
        device_fail("bip340", "sk-max", MAXV, "sk = 2^256 - 1, not below n. The device must fail; it must not reduce the key to 2^256 - 1 - n."),
    ]
    base = valid[0]
    t = tup(base)
    r, s = t["sig"][:32], t["sig"][32:]
    for x in (host_steps("bip340", t),):
        assert all(x.values())
    rej = []
    for nm, val, text in (("s-n-plus-1", N + 1, "n + 1"), ("s-max", MAXV, "2^256 - 1")):
        rej.append(reject_case(
            "bip340", base, nm, "sig_s_range",
            "step 5: BIP340 Verify requires s < n (the second half of sig is read as an integer, not reduced)",
            "The second half of sig (s) is %s, not below n. Steps 1 to 4 pass: r is unchanged and equals x(W)." % text,
            ["the verification equation, if s were reduced mod n (the reduced value is not the signature's s)"],
            sig=r + b32(val)))
    for nm, val, text in (("r-p-plus-1", P + 1, "p + 1"), ("r-max", MAXV, "2^256 - 1")):
        rej.append(reject_case(
            "bip340", base, nm, "sig_r_range",
            "step 4: bytes32(x(W)) must equal the first 32 bytes of sig; r is not below p, so it cannot be x(W)",
            "The first half of sig (r) is %s, not below p. Steps 1 to 3 pass." % text,
            ["step 5, BIP340 Verify requires r < p"],
            sig=b32(val) + s))
    return valid, fail, rej


def make_ecdsa():
    big = MAXV
    valid = [
        valid_case("ecdsa", "m-equals-n", "m = n, so z = int(m) mod n = 0. k0 hashes m as given (not reduced).", m=b32(N)),
        valid_case("ecdsa", "m-n-plus-1", "m = n + 1, so z = 1. k0 hashes m as given.", m=b32(N + 1)),
        valid_case("ecdsa", "m-max", "m = 2^256 - 1, so z = 2^256 - 1 - n. k0 hashes m as given.", m=b32(big)),
        valid_case("ecdsa", "sk-one", "sk = 1, the smallest key. pk = ser33(G).", sk=b32(1)),
        valid_case("ecdsa", "sk-n-minus-one", "sk = n - 1, the largest key. pk = ser33(-G).", sk=b32(N - 1)),
    ]
    fail = [
        device_fail("ecdsa", "sk-zero", 0, "sk = 0. The device must fail in both device_commit and device_sign."),
        device_fail("ecdsa", "sk-n", N, "sk = n, not below n. The device must fail; it must not reduce the key to 0."),
        device_fail("ecdsa", "sk-max", MAXV, "sk = 2^256 - 1, not below n. The device must fail; it must not reduce the key."),
    ]
    base = valid[3]
    t = tup(base)
    assert all(host_steps("ecdsa", t).values())
    r, s = t["sig"][:32], t["sig"][32:]
    rej = [
        reject_case("ecdsa", base, "r-n-plus-1", "sig_r_range",
                    "step 4: 0 < r < n",
                    "r is n + 1, not below n. Steps 1 to 3 pass.",
                    ["step 4, x(W) mod n equals r (it is r reduced, not r)", "step 5, the verification equation"],
                    sig=b32(N + 1) + s),
        reject_case("ecdsa", base, "s-n-plus-1", "sig_s_range",
                    "step 4: 0 < s <= (n - 1) / 2",
                    "s is n + 1, above the low-s limit and not below n. Steps 1 to 3 pass and r is x(W) mod n.",
                    ["step 5, the verification equation, because s reduced mod n is 1 and not the signature's s"],
                    sig=r + b32(N + 1)),
    ]
    # Isolated form of the s case. The host does not check how R0 was derived, so a tuple can be built with
    # a chosen R0 and a message that makes s equal to 1 for the honest nonce. The same tuple with s = 1 is
    # accepted, and with s = n + 1 (the same value mod n) only the range check refuses it.
    for i in range(10000):
        seed = "anti-exfil boundary/ecdsa/host-s-one/%d" % i
        d, k0 = int.from_bytes(H(seed + "/sk"), "big") % N, int.from_bytes(H(seed + "/k0"), "big") % N
        rho = H(seed + "/rho")
        if d == 0 or k0 == 0:
            continue
        pk = ref._ser33(ref._mul(d))
        R0b = ref._ser33(ref._mul(k0))
        kp = (k0 + ref._ecdsa_t(R0b, rho)) % N
        if kp == 0:
            continue
        r_int = ref._mul(kp)[0] % N
        if r_int == 0:
            continue
        m = b32((kp - r_int * d) % N)    # s = kp^-1 * (z + r*d) = 1
        break
    ok = dict(pk=pk, m=m, rho=rho, R0_bytes=R0b, sig=b32(r_int) + b32(1))
    assert ref.ecdsa_host_verify(ok["pk"], ok["m"], ok["rho"], ok["R0_bytes"], ok["sig"]) is True
    host_ok = [{"id": "ecdsa-boundary-host-s-one", "comment": "Not a device run: R0 is not derived from a hash, so no device produces these bytes. "
                "A host must accept the tuple. s = 1, the smallest valid s. It is the base of ecdsa-boundary-reject-isolated-s-n-plus-1.",
                "seed": seed, "fixed": ["m"], "pk": hx(pk), "m": hx(m), "rho": hx(rho), "R0_bytes": hx(R0b),
                "sig": hx(ok["sig"]), "expected": "accept"}]
    base_ok = dict(host_ok[0])
    iso = reject_case("ecdsa", base_ok | {"id": "ecdsa-boundary-host-s-one"}, "isolated-s-n-plus-1", "sig_s_range",
                      "step 4: 0 < s <= (n - 1) / 2",
                      "The tuple of ecdsa-boundary-host-s-one with s replaced by n + 1, which is 1 mod n. Every check passes except the s range, "
                      "so a host that reduces s mod n accepts it.", [],
                      sig=b32(r_int) + b32(N + 1))
    iso["derived_from"] = "ecdsa-boundary-host-s-one"
    rej.append(iso)
    return valid, fail, rej, host_ok


def build():
    doc = {
        "title": "Anti-exfil signing for BIP340 and ECDSA: boundary test vectors",
        "specification_revision": "0.16",
        "license": "MIT",
        "keys_are_artificial": True,
        "encoding": "All byte strings are lowercase hex. An empty message is the empty string.",
        "derivation": ("rho = SHA256(seed || \"/rho\"). sk = SHA256(seed || \"/sk\") and a 32-byte m = SHA256(seed || \"/m\") "
                       "unless the case lists \"sk\" or \"m\" under \"fixed\", where the stated value is used instead. "
                       "seed is the ASCII string in each case."),
        "companion_of": "bip-anti-exfil.json, same classes and encoding. The case ecdsa-reject-s-half-plus-one there already covers s = (n - 1) / 2 + 1.",
        "classes": {
            "valid": "sk, m, rho -> pk, hc, R0_bytes, sig, as in bip-anti-exfil.json. For ECDSA, z = int(m) mod n is given; k0 hashes m as given.",
            "device_fail": "The device must fail in every listed operation and produce no output.",
            "reject": ("A host must reject the tuple. 'names' is the check that refuses it, in the numbering of the specification's host steps. "
                       "'isolated' is true when every other check passes, so a host that skips only the named check accepts the tuple. "
                       "Otherwise 'also_fails' lists the other checks the tuple fails, and the case shows only that the host refuses it."),
            "host_accept": "A host must accept the tuple. It is not a device run.",
        },
        "not_isolated": ("For BIP340 s >= n and for r >= p (and ECDSA r >= n), a tuple whose reduced value would pass the other checks "
                         "needs a signature with s or r below 2^256 - n or 2^256 - p, or a point of known discrete log with a tiny x. "
                         "Neither can be built without overriding a hash, so those cases are not isolated. The ECDSA s case is, "
                         "because the host does not check how R0 was chosen and the message can be picked to make s = 1."),
    }
    v, f, r = make_bip340()
    doc["bip340"] = {"valid": v, "device_fail": f, "reject": r}
    v, f, r, a = make_ecdsa()
    doc["ecdsa"] = {"valid": v, "device_fail": f, "reject": r, "host_accept": a}
    return doc


def crosscheck(doc):
    """Recompute the ECDSA message cases with the arithmetic of the other implementation: it must accept
    each tuple as a plain ECDSA signature for z = int(m) mod n, and the nonce hash is recomputed with its
    tagged_hash and point multiplication. Only its plain functions are used; the file is not changed."""
    o = load(OTHER, "secp_for_crosscheck")
    bad = 0
    for c in doc["ecdsa"]["valid"]:
        m, sk, rho = bytes.fromhex(c["m"]), bytes.fromhex(c["sk"]), bytes.fromhex(c["rho"])
        d = int.from_bytes(sk, "big")
        pk = o.ser33(o.pt_mul(d, o.G))
        hc = o.tagged_hash("s2c/ecdsa/data", rho)
        mask = o.tagged_hash("s2c/ecdsa/aux", hc)
        k0 = o.int_from(o.tagged_hash("s2c/ecdsa/nonce", bytes(a ^ b for a, b in zip(o.bytes32(d), mask)) + pk + m + hc))
        r0 = o.ser33(o.pt_mul(k0, o.G))
        t = o.int_from(o.tagged_hash("s2c/ecdsa/point", r0 + rho))
        W = o.pt_add(o.pt_mul(k0, o.G), o.pt_mul(t, o.G))
        sig = bytes.fromhex(c["sig"])
        r, s = o.int_from(sig[:32]), o.int_from(sig[32:])
        good = (pk.hex() == c["pk"] and hc.hex() == c["hc"] and r0.hex() == c["R0_bytes"] and W[0] % o.N == r
                and o.ecdsa_verify(o.pt_mul(d, o.G), m, r, s) and s <= (o.N - 1) // 2)
        print("%s %s" % ("PASS" if good else "FAIL", c["id"]))
        bad += not good
    return bad


def main():
    doc = build()
    text = json.dumps(doc, indent=2) + "\n"
    if "--check" in sys.argv:
        same = OUT.exists() and OUT.read_text() == text
        print("matches file on disk" if same else "DIFFERS from file on disk")
        return 0 if same else 1
    if "--crosscheck" in sys.argv:
        bad = crosscheck(doc)
        print("cross-check failures: %d" % bad)
        return 1 if bad else 0
    OUT.write_text(text)
    for scheme in ("bip340", "ecdsa"):
        print("%s: %s" % (scheme, ", ".join("%s %d" % (k, len(v)) for k, v in doc[scheme].items())))
    print("wrote", OUT.relative_to(ROOT), hashlib.sha256(text.encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
