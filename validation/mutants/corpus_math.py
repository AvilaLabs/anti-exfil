#!/usr/bin/env python3
"""Offline math corpus for anti_exfil.py.

Replays only tests that already exist in the repository, with no C and no
network:

  vec:*    the 24 stored vectors in the file named by AE_CANDIDATE_VECTORS (not part of this tree)
           (hc, pk, R0, sig recomputed from sk, m, rho; host verifier must say True)
  tuple:*  the 132 stored host-verifier tuples in the same file (exact bool)
  api:*    the public API error-contract matrix
  boundary:*    the fixed hash-seam boundary cases
  r2:*     run-2 additions for gaps found in run 1 (TM-003, 004, 023, 024, 031, 040):
           direct _lift_x calls, faults injected through the internal verifiers, an
           ECDSA verify with an unparsable key, and r = 0 on a toy curve

Not replayed: the C driver booleans and the C opening-prefix check of the API matrix (they
test the C driver output, not the Python module), and the mutation controls of the boundary cases
(they mutate the pinned reference text, not the candidate).

Usage: corpus_math.py CANDIDATE [--stop-on-fail] [--list]
Prints one JSON object. Exit status 0 only if every test passed.
"""
import hashlib
import importlib.util
import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTORS = pathlib.Path(__import__("os").environ.get("AE_CANDIDATE_VECTORS", "candidate_vectors.json"))

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
SK1 = (1).to_bytes(32, "big")
M_S = b"\x01"
M_E = (1).to_bytes(32, "big")
HC = bytes([0x42]) * 32
RHO = bytes([0x24]) * 32


# ---- independent group arithmetic ----------------------------------------------
def ser32(i):
    return i.to_bytes(32, "big")


def ser33(point):
    if point is None:
        raise ValueError("point at infinity")
    return bytes((2 | (point[1] & 1),)) + ser32(point[0])


def point_neg(point):
    return None if point is None else (point[0], (-point[1]) % P)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        slope = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % P, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def mul(k, point=G):
    k %= N
    result, addend = None, point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def lift_x(x):
    if not 0 <= x < P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    return (x, P - y if y & 1 else y)


def alternate_lift_tuple():
    for r in range(1, 10000):
        if r + N >= P:
            continue
        V, W = lift_x(r), lift_x(r + N)
        if V is None or W is None:
            continue
        R0 = point_add(W, point_neg(G))
        if R0 is None:
            continue
        Ppub = mul(pow(r, -1, N), point_add(V, point_neg(G)))
        if Ppub is None:
            continue
        return r, V, W, R0, Ppub
    raise RuntimeError("no alternate-lift control found in fixed range")


# ---- toy curve (run 2): y^2 = x^3 + 7 over F_1303, prime order 1249 < p ---------------
# Chosen offline by exhaustive point counting: p = 3 mod 4 (so the module's square-root
# lift works), p = 1 mod 3 (so the order is not p + 1), n prime and below p. x = n lifts,
# so a point with x(W) mod n = 0 exists. Discrete logs are found by brute force.
TOY_P, TOY_N = 1303, 1249


def toy_lift(x):
    c = (pow(x, 3, TOY_P) + 7) % TOY_P
    y = pow(c, (TOY_P + 1) // 4, TOY_P)
    if y * y % TOY_P != c:
        return None
    return (x, TOY_P - y if y & 1 else y)


def toy_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % TOY_P == 0:
        return None
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], -1, TOY_P) % TOY_P
    else:
        slope = (b[1] - a[1]) * pow((b[0] - a[0]) % TOY_P, -1, TOY_P) % TOY_P
    x3 = (slope * slope - a[0] - b[0]) % TOY_P
    return x3, (slope * (a[0] - x3) - a[1]) % TOY_P


def toy_mul(k, point):
    result = None
    for _ in range(k % TOY_N):
        result = toy_add(result, point)
    return result


def toy_dl(point):
    acc = None
    for k in range(1, TOY_N):
        acc = toy_add(acc, TOY_G)
        if acc == point:
            return k
    raise AssertionError("toy discrete log not found")


TOY_G = next(toy_lift(x) for x in range(1, 100) if toy_lift(x) is not None)


def toy_sanity():
    if any(TOY_N % d == 0 for d in range(2, 40)) or toy_mul(TOY_N, TOY_G) is not None:
        raise AssertionError("toy curve parameters are wrong")
    if toy_lift(TOY_N) is None:
        raise AssertionError("toy fixture: x = n must lift")


def load_toy(mod):
    """A second copy of the module under test with the curve constants replaced.

    The pinned file is not edited. _mul binds its default point at definition time, so
    that default is replaced as well.
    """
    spec = importlib.util.spec_from_file_location("toy_anti_exfil", str(mod.__file__))
    toy = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = toy
    spec.loader.exec_module(toy)
    toy._P, toy._N, toy._GX, toy._GY, toy._G = TOY_P, TOY_N, TOY_G[0], TOY_G[1], TOY_G
    toy._mul.__defaults__ = (TOY_G,)
    return toy


def ser33_toy(point):
    return bytes((2 | (point[1] & 1),)) + point[0].to_bytes(32, "big")


def tagged_bytes(tag, data):
    h = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(h + h + data).digest()


# ---- hash seam -------------------------------------------------------------------
class HashSeam:
    def __init__(self, module, overrides, capture=None):
        self.module = module
        self.overrides = overrides
        self.capture = capture if capture is not None else {}
        self.original = module._tagged_hash

    def __enter__(self):
        def injected(tag, data):
            if tag in self.overrides:
                self.capture.setdefault(tag, []).append(bytes(data))
                value = self.overrides[tag]
                return value.to_bytes(32, "big") if isinstance(value, int) else value
            return self.original(tag, data)
        self.module._tagged_hash = injected
        return self

    def __exit__(self, *exc):
        self.module._tagged_hash = self.original
        return False


def outcome(fn):
    try:
        return ("return", fn())
    except Exception as exc:  # noqa: BLE001 - outcome capture
        return ("exception", type(exc).__name__)


def seam_twice(mod, overrides, fn, capture=None):
    with HashSeam(mod, overrides, capture):
        a = outcome(fn)
        b = outcome(fn)
    if a != b:
        raise AssertionError("not deterministic across repeated calls")
    return a


def expect_return(mod, overrides, fn, value):
    kind, got = seam_twice(mod, overrides, fn)
    if kind != "return" or got != value:
        raise AssertionError("expected return %r, got %s %r" % (value, kind, got))


def expect_exc(mod, overrides, fn, name):
    kind, got = seam_twice(mod, overrides, fn)
    if kind != "exception" or got != name:
        raise AssertionError("expected %s, got %s %r" % (name, kind, got))


def load_candidate(path):
    spec = importlib.util.spec_from_file_location("candidate_anti_exfil", str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---- API contract ----------------------------------------------------------------
def expect_value_error(fn, args):
    try:
        result = fn(*args)
    except Exception as exc:  # noqa: BLE001
        if type(exc) is ValueError:
            return
        raise AssertionError("raised %s, expected exactly ValueError" % type(exc).__name__)
    raise AssertionError("did not raise ValueError (returned %r)" % (result,))


def expect_false(fn, args):
    try:
        result = fn(*args)
    except Exception as exc:  # noqa: BLE001
        raise AssertionError("raised %s, expected exact False" % type(exc).__name__)
    if type(result) is not bool or result is not False:
        raise AssertionError("did not return exactly False")


def api_rows(mod, prefix):
    pkfn = getattr(mod, prefix + "public_key")
    hcf = getattr(mod, prefix + "host_commit")
    cfn = getattr(mod, prefix + "device_commit")
    sfn = getattr(mod, prefix + "device_sign")
    vfn = getattr(mod, prefix + "host_verify")
    sk = (1).to_bytes(32, "big")
    m = b"invalid-API baseline" if not prefix else bytes(range(32))
    rho, hc = bytes(range(32)), bytes(range(32, 64))
    pk, r0 = pkfn(sk), cfn(sk, m, hc)
    sig = sfn(sk, m, rho)
    rows = [
        ("public_key type", "E", pkfn, ("\x00",)),
        ("public_key length", "E", pkfn, (b"\x01",)),
        ("public_key zero scalar", "E", pkfn, (bytes(32),)),
        ("public_key n scalar", "E", pkfn, (N.to_bytes(32, "big"),)),
        ("host_commit type", "E", hcf, (None,)),
        ("host_commit length", "E", hcf, (rho[:-1],)),
        ("device_commit sk", "E", cfn, (bytes(32), m, hc)),
        ("device_commit message type", "E", cfn, (sk, None, hc)),
        ("device_commit commitment type", "E", cfn, (sk, m, None)),
        ("device_commit commitment length", "E", cfn, (sk, m, hc[:-1])),
        ("device_sign sk", "E", sfn, (N.to_bytes(32, "big"), m, rho)),
        ("device_sign message type", "E", sfn, (sk, None, rho)),
        ("device_sign rho type", "E", sfn, (sk, m, None)),
        ("device_sign rho length", "E", sfn, (sk, m, rho[:-1])),
    ]
    if prefix == "ecdsa_":
        rows += [("device_commit message length", "E", cfn, (sk, m[:-1], hc)),
                 ("device_sign message length", "E", sfn, (sk, m[:-1], rho))]
    bad_tuples = [
        (None, m, rho, r0, sig), (pk, None, rho, r0, sig),
        (pk, m, None, r0, sig), (pk, m, rho, None, sig),
        (pk, m, rho, r0, None), (pk[:-1], m, rho, r0, sig),
        (pk, m, rho[:-1], r0, sig), (pk, m, rho, r0[:-1], sig),
        (pk, m, rho, r0, sig[:-1]), (pk, m, rho, b"\x04" + r0[1:], sig),
        (pk, m, rho, b"\x02" + P.to_bytes(32, "big"), sig),
    ]
    if prefix == "ecdsa_":
        bad_tuples += [(pk[:-1], m, rho, r0, sig), (pk, m[:-1], rho, r0, sig)]
    else:
        bad_tuples += [(b"\xff" * 32, m, rho, r0, sig), (pk, m, rho, r0, b"\xff" * 64)]
    for i, args in enumerate(bad_tuples):
        rows.append(("invalid verifier tuple %d" % i, "F", vfn, args))
    return rows


# ---- test registry ---------------------------------------------------------------
def build_tests():
    """Return ordered list of (name, fn(mod)). Cheap discriminating tests first."""
    tests = []
    vec = json.loads(VECTORS.read_text(encoding="utf-8"))

    # API contract.
    for prefix in ("", "ecdsa_"):
        def make(prefix=prefix):
            cache = {}

            def rows(mod):
                if "rows" not in cache:
                    cache["rows"] = api_rows(mod, prefix)
                return cache["rows"]
            return rows
        get_rows = make()
        labels = None
        # Row labels are static; build them without a module by mirroring api_rows order.
        static = ["public_key type", "public_key length", "public_key zero scalar",
                  "public_key n scalar", "host_commit type", "host_commit length",
                  "device_commit sk", "device_commit message type",
                  "device_commit commitment type", "device_commit commitment length",
                  "device_sign sk", "device_sign message type", "device_sign rho type",
                  "device_sign rho length"]
        if prefix == "ecdsa_":
            static += ["device_commit message length", "device_sign message length"]
        static += ["invalid verifier tuple %d" % i for i in range(13)]
        for idx, label in enumerate(static):
            def run(mod, idx=idx, label=label, get_rows=get_rows):
                row = get_rows(mod)[idx]
                assert row[0] == label, "row order drift"
                if row[1] == "E":
                    expect_value_error(row[2], row[3])
                else:
                    expect_false(row[2], row[3])
            tests.append(("api:%s:%s" % (prefix or "schnorr_", label), run))

    # Boundary cases.
    sn, en = "s2c/schnorr/nonce", "s2c/ecdsa/nonce"
    sp, ep = "s2c/schnorr/point", "s2c/ecdsa/point"
    ch = "BIP0340/challenge"
    eg = ser33(G)
    neg_g = ser33(point_neg(G))

    for value in (0, N):
        tests.append(("boundary:schnorr-k0-zero-residue-%d" % value,
                      lambda mod, v=value: expect_exc(mod, {sn: v}, lambda: mod.device_commit(SK1, M_S, HC), "ValueError")))
    tests.append(("boundary:schnorr-k0-n-plus-1-reduces-to-one",
                  lambda mod: expect_return(mod, {sn: N + 1}, lambda: mod.device_commit(SK1, M_S, HC), eg)))
    for value in (0, N, (1 << 256) - 1):
        tests.append(("boundary:ecdsa-k0-out-of-range-%d" % value,
                      lambda mod, v=value: expect_exc(mod, {en: v}, lambda: mod.ecdsa_device_commit(SK1, M_E, HC), "ValueError")))
    tests.append(("boundary:ecdsa-k0-n-minus-1-valid",
                  lambda mod: expect_return(mod, {en: N - 1}, lambda: mod.ecdsa_device_commit(SK1, M_E, HC), neg_g)))

    for scheme in ("schnorr", "ecdsa"):
        def parts(mod, scheme=scheme):
            if scheme == "schnorr":
                return (sn, sp, mod.device_commit, mod.device_sign, mod.host_verify, M_S, mod.public_key(SK1))
            return (en, ep, mod.ecdsa_device_commit, mod.ecdsa_device_sign, mod.ecdsa_host_verify, M_E,
                    mod.ecdsa_public_key(SK1))

        def t0_commit(mod, parts=parts):
            nt, pt, cf, sf, vf, msg, pk = parts(mod)
            expect_return(mod, {nt: 1}, lambda: cf(SK1, msg, HC), eg)

        def t0_sign_sig(mod, parts=parts):
            nt, pt, cf, sf, vf, msg, pk = parts(mod)
            kind, val = seam_twice(mod, {nt: 1, pt: 0}, lambda: sf(SK1, msg, RHO))
            if kind != "return" or not isinstance(val, bytes) or len(val) != 64:
                raise AssertionError("k0=1,t=0 did not give a 64-byte signature")
            return val

        def t0_verify(mod, parts=parts, t0_sign_sig=t0_sign_sig):
            nt, pt, cf, sf, vf, msg, pk = parts(mod)
            sig = t0_sign_sig(mod)
            expect_return(mod, {pt: 0}, lambda: vf(pk, msg, RHO, eg, sig), True)

        def t0_verify_padded(mod, parts=parts, t0_sign_sig=t0_sign_sig):
            # same point as G, but 34 bytes (leading zero after the prefix): the length
            # check must fail it even though a lenient parser would lift the same x
            nt, pt, cf, sf, vf, msg, pk = parts(mod)
            sig = t0_sign_sig(mod)
            padded = eg[:1] + b"\x00" + eg[1:]
            expect_return(mod, {pt: 0}, lambda: vf(pk, msg, RHO, padded, sig), False)

        def sign_stateless(mod, parts=parts):
            # device_sign takes everything from (sk, m, rho): an earlier commit made
            # with some other hc must not change the signature
            nt, pt, cf, sf, vf, msg, pk = parts(mod)
            before = sf(SK1, msg, RHO)
            cf(SK1, msg, bytes(range(100, 132)))
            if sf(SK1, msg, RHO) != before:
                raise AssertionError("signature depends on an earlier device_commit")

        def host_reject(mod, tvalue, parts=parts, t0_sign_sig=t0_sign_sig):
            nt, pt, cf, sf, vf, msg, pk = parts(mod)
            sig = t0_sign_sig(mod)
            expect_return(mod, {pt: tvalue}, lambda: vf(pk, msg, RHO, eg, sig), False)

        def sign_reject(mod, tvalue, parts=parts):
            nt, pt, cf, sf, vf, msg, pk = parts(mod)
            expect_exc(mod, {nt: 1, pt: tvalue}, lambda: sf(SK1, msg, RHO), "ValueError")

        def infinity(mod, parts=parts):
            nt, pt, cf, sf, vf, msg, pk = parts(mod)
            expect_exc(mod, {nt: 1, pt: N - 1}, lambda: sf(SK1, msg, RHO), "ValueError")

        tests.append(("boundary:%s-t0-base-commit" % scheme, t0_commit))
        tests.append(("boundary:%s-t0-sign" % scheme, lambda mod, f=t0_sign_sig: f(mod) and None))
        tests.append(("boundary:%s-t0-host-verification" % scheme, t0_verify))
        tests.append(("boundary:%s-t0-host-rejects-34-byte-R0" % scheme, t0_verify_padded))
        tests.append(("stateless:%s-sign-ignores-earlier-commit" % scheme, sign_stateless))
        for tvalue in (N, (1 << 256) - 1, N - 1):
            tests.append(("boundary:%s-host-reject-t-%d" % (scheme, tvalue),
                          lambda mod, tv=tvalue, f=host_reject: f(mod, tv)))
            if tvalue >= N:
                tests.append(("boundary:%s-sign-reject-t-%d" % (scheme, tvalue),
                              lambda mod, tv=tvalue, f=sign_reject: f(mod, tv)))
        tests.append(("boundary:%s-sign-reject-infinity-k0-plus-t" % scheme, infinity))

    tests.append(("boundary:schnorr-odd-R0-actual-parity-no-opening-flag",
                  lambda mod: expect_return(mod, {sn: N - 1}, lambda: mod.device_commit(SK1, M_S, HC), neg_g)))
    tests.append(("boundary:ecdsa-odd-R0-actual-parity-no-opening-flag",
                  lambda mod: expect_return(mod, {en: N - 1}, lambda: mod.ecdsa_device_commit(SK1, M_E, HC), neg_g)))

    def schnorr_zero_sig(mod):
        kind, val = seam_twice(mod, {sn: 1, sp: 0, ch: N - 1}, lambda: mod.device_sign(SK1, M_S, RHO))
        if kind != "return" or not isinstance(val, bytes) or len(val) != 64 or not val.endswith(b"\x00" * 32):
            raise AssertionError("signature with s=0 must return")
        return val

    tests.append(("boundary:schnorr-s-zero-permitted", lambda mod: schnorr_zero_sig(mod) and None))

    def schnorr_zero_verify(mod):
        sig = schnorr_zero_sig(mod)
        expect_return(mod, {sp: 0, ch: N - 1},
                      lambda: mod.host_verify(mod.public_key(SK1), M_S, RHO, eg, sig), True)
    tests.append(("boundary:schnorr-s-zero-host-verify", schnorr_zero_verify))
    r_g = G[0] % N
    m_zero_s = ser32((-r_g) % N)
    tests.append(("boundary:ecdsa-s-zero-signing-fails",
                  lambda mod: expect_exc(mod, {en: 1, ep: 0}, lambda: mod.ecdsa_device_sign(SK1, m_zero_s, RHO), "ValueError")))
    tests.append(("boundary:ecdsa-s-zero-host-rejects",
                  lambda mod: expect_return(mod, {ep: 0},
                                            lambda: mod.ecdsa_host_verify(mod.ecdsa_public_key(SK1), m_zero_s, RHO, eg,
                                                                          ser32(r_g) + b"\x00" * 32), False)))

    # Verifier negatives from one forced signature (nonce 1, tweak 0, challenge 0:
    # R = G, s = 1). Each variant keeps the same integers but breaks one rule, so a
    # verifier missing that rule accepts it.
    def forced_schnorr(mod):
        kind, val = seam_twice(mod, {sn: 1, sp: 0, ch: 0}, lambda: mod.device_sign(SK1, M_S, RHO))
        if kind != "return" or val != ser32(G[0]) + ser32(1):
            raise AssertionError("forced Schnorr signature is not x(G) || 1")
        return val

    def schnorr_variant(mod, name, pk=None, rho=None, sig=None, want=False):
        good = forced_schnorr(mod)
        expect_return(mod, {sp: 0, ch: 0},
                      lambda: mod.host_verify(pk or mod.public_key(SK1), M_S, rho or RHO, eg, sig or good), want)

    tests.append(("verify:schnorr-forced-valid", lambda mod: schnorr_variant(mod, "valid", want=True)))
    tests.append(("verify:schnorr-s-plus-n-rejected",
                  lambda mod: schnorr_variant(mod, "s+n", sig=ser32(G[0]) + ser32(1 + N))))
    tests.append(("verify:schnorr-odd-R-rejected",
                  lambda mod: schnorr_variant(mod, "odd R", sig=ser32(G[0]) + ser32(N - 1))))
    tests.append(("verify:schnorr-65-byte-sig-rejected",
                  lambda mod: schnorr_variant(mod, "65", sig=ser32(G[0]) + b"\x00" + ser32(1))))
    tests.append(("verify:schnorr-63-byte-sig-rejected",
                  lambda mod: schnorr_variant(mod, "63", sig=ser32(G[0]) + ser32(1)[1:])))
    tests.append(("verify:schnorr-33-byte-rho-rejected",
                  lambda mod: schnorr_variant(mod, "rho", rho=RHO + b"\x00")))
    tests.append(("verify:schnorr-33-byte-pk-rejected",
                  lambda mod: schnorr_variant(mod, "pk", pk=b"\x00" + mod.public_key(SK1))))

    for bad_prefix in (b"\x06", b"\x00", b"\x05"):
        def bad_r0(mod, bp=bad_prefix):
            sig = forced_schnorr(mod)
            expect_return(mod, {sp: 0, ch: 0},
                          lambda: mod.host_verify(mod.public_key(SK1), M_S, RHO, bp + eg[1:], sig), False)
        tests.append(("verify:schnorr-R0-prefix-%02x-rejected" % bad_prefix[0], bad_r0))

    def forced_ecdsa(mod):
        kind, val = seam_twice(mod, {en: 1, ep: 0}, lambda: mod.ecdsa_device_sign(SK1, M_E, RHO))
        if kind != "return" or len(val) != 64:
            raise AssertionError("forced ECDSA signature failed")
        return val

    def ecdsa_variant(mod, m=None, rho=None, pk=None, want=False):
        sig = forced_ecdsa(mod)
        expect_return(mod, {ep: 0},
                      lambda: mod.ecdsa_host_verify(pk or mod.ecdsa_public_key(SK1), m or M_E, rho or RHO, eg, sig), want)

    tests.append(("verify:ecdsa-forced-valid", lambda mod: ecdsa_variant(mod, want=True)))
    for bad_prefix in (b"\x06", b"\x00", b"\x05"):
        def ebad_r0(mod, bp=bad_prefix):
            sig = forced_ecdsa(mod)
            expect_return(mod, {ep: 0},
                          lambda: mod.ecdsa_host_verify(mod.ecdsa_public_key(SK1), M_E, RHO, bp + eg[1:], sig), False)
        tests.append(("verify:ecdsa-R0-prefix-%02x-rejected" % bad_prefix[0], ebad_r0))
    tests.append(("verify:ecdsa-33-byte-m-rejected", lambda mod: ecdsa_variant(mod, m=b"\x00" + M_E)))
    tests.append(("verify:ecdsa-33-byte-rho-rejected", lambda mod: ecdsa_variant(mod, rho=RHO + b"\x00")))
    tests.append(("verify:ecdsa-34-byte-pk-rejected",
                  lambda mod: ecdsa_variant(mod, pk=mod.ecdsa_public_key(SK1)[:1] + b"\x00" + mod.ecdsa_public_key(SK1)[1:])))

    def alias(mod):
        sigs = []
        for message in (ser32(1), ser32(N + 1)):
            cap = {}
            kind, val = seam_twice(mod, {en: 1, ep: 0}, lambda m=message: mod.ecdsa_device_sign(SK1, m, RHO), cap)
            inputs = cap.get(en, [])
            if kind != "return" or len(inputs) != 2 or not all(len(i) == 129 and i[65:97] == message for i in inputs):
                raise AssertionError("raw message not carried at the 32-byte m slot")
            sigs.append(val)
        if sigs[0] != sigs[1] or not isinstance(sigs[0], bytes) or len(sigs[0]) != 64:
            raise AssertionError("aliased messages must give equal signatures under a forced nonce")
    tests.append(("boundary:ecdsa-raw-message-z-alias", alias))

    def fullpoint(mod):
        r_alt, V, W, R0, Ppub = alternate_lift_tuple()
        expect_return(mod, {ep: 1},
                      lambda: mod.ecdsa_host_verify(ser33(Ppub), ser32(1), RHO, ser33(R0), ser32(r_alt) + ser32(1)),
                      False)
    tests.append(("boundary:ecdsa-alternate-x-lift-fullpoint-rejects", fullpoint))

    z_high = N // 2
    s_high = (z_high + r_g) % N
    tests.append(("boundary:ecdsa-high-s-host-rejects",
                  lambda mod: expect_return(mod, {ep: 0},
                                            lambda: mod.ecdsa_host_verify(mod.ecdsa_public_key(SK1), ser32(z_high), RHO, eg,
                                                                          ser32(r_g) + ser32(s_high)), False)))

    # ---- run 2: tests for gaps found in run 1 ---------------------------------------
    def lift_x_range(mod):
        # TM-003: x = p + 1 reduces to x = 1, which is on the curve, so a lift that
        # only bounds x by 2^256 returns a point; x >= p must be refused
        if lift_x(1) is None or mod._lift_x(1) != lift_x(1):
            raise AssertionError("x = 1 must lift")
        for x in (P + 1, P + 4):
            if mod._lift_x(x) is not None:
                raise AssertionError("_lift_x accepted x >= p")
    tests.append(("r2:lift_x-rejects-x-at-or-above-p", lift_x_range))

    def lift_x_curve(mod):
        # TM-004: x = 5 has no y on the curve; the square-root candidate must be checked
        for x in (5, 7, 9):
            if lift_x(x) is not None:
                raise AssertionError("fixture: x must be off the curve")
            for odd in (False, True):
                if mod._lift_x(x, odd) is not None:
                    raise AssertionError("_lift_x returned a point for an off-curve x")
        if mod._lift_x(2) != lift_x(2) or mod._lift_x(2, True) != (2, P - lift_x(2)[1]):
            raise AssertionError("lift of x = 2 is wrong")
    tests.append(("r2:lift_x-rejects-off-curve-x", lift_x_curve))

    def fault(mod, name, call):
        # the internal verifier reports failure; the signer must refuse to return bytes
        original = getattr(mod, name)
        setattr(mod, name, lambda *a, **k: False)
        try:
            expect_value_error(*call)
        finally:
            setattr(mod, name, original)
    tests.append(("r2:schnorr-sign-refuses-when-internal-verify-fails",
                  lambda mod: fault(mod, "_schnorr_verify", (mod.device_sign, (SK1, M_S, RHO)))))
    tests.append(("r2:ecdsa-sign-refuses-when-internal-verify-fails",
                  lambda mod: fault(mod, "_ecdsa_verify", (mod.ecdsa_device_sign, (SK1, M_E, RHO)))))

    def ecdsa_unparsable_pk(mod):
        # TM-031: a signature that is valid for no key at all but satisfies V = W when the
        # public-key term is dropped. R0 = aG, t = H(R0 || rho), s = z / (a + t), r = x(W).
        z = int.from_bytes(M_E, "big") % N
        for a in range(1, 200):
            r0 = ser33(mul(a))
            t = int.from_bytes(tagged_bytes("s2c/ecdsa/point", r0 + RHO), "big")
            W = mul(a + t)
            if W is None or t >= N:
                continue
            r = W[0] % N
            s = z * pow(a + t, -1, N) % N
            if r and 0 < s <= (N - 1) // 2:
                break
        else:
            raise AssertionError("no fixture found")
        sig = ser32(r) + ser32(s)
        for label, pk in (("x off the curve", b"\x02" + ser32(5)), ("prefix 05", b"\x05" + ser32(G[0])),
                          ("x >= p", b"\x02" + ser32(P))):
            got = mod.ecdsa_host_verify(pk, M_E, RHO, r0, sig)
            if got is not False:
                raise AssertionError("ecdsa_host_verify accepted an unparsable public key (%s)" % label)
    tests.append(("r2:ecdsa-verify-rejects-unparsable-pk", ecdsa_unparsable_pk))

    def toy_ecdsa_world(mod):
        toy_sanity()
        T = load_toy(mod)
        # control: a signature made by the module on the toy curve verifies there
        sk = ser32(5)
        pk = T.ecdsa_public_key(sk)
        m = ser32(1)
        with HashSeam(T, {"s2c/ecdsa/nonce": 7, "s2c/ecdsa/point": 3}):
            sig = T.ecdsa_device_sign(sk, m, RHO)
            r0 = T.ecdsa_device_commit(sk, m, HC)
            ok = T.ecdsa_host_verify(pk, m, RHO, r0, sig)
        if ok is not True:
            raise AssertionError("toy-curve control signature did not verify")
        return T, pk, m

    def toy_r_zero(mod):
        # TM-040: W with x(W) = n has r = x(W) mod n = 0. With r = 0 the public-key term of
        # V vanishes, so V = (z/s)G equals +-W for s = z / dlog(W): only the r > 0 rule refuses it.
        T, pk, m = toy_ecdsa_world(mod)
        W = toy_lift(TOY_N)
        w = toy_dl(W)
        s = pow(w, -1, TOY_N)
        s = min(s, TOY_N - s)
        sig = ser32(0) + ser32(s)
        with HashSeam(T, {"s2c/ecdsa/point": 0}):
            got = T.ecdsa_host_verify(pk, m, RHO, ser33_toy(W), sig)
        if got is not False:
            raise AssertionError("ecdsa_host_verify accepted r = 0")
    tests.append(("r2:ecdsa-verify-rejects-r-zero-on-toy-curve", toy_r_zero))

    # Stored vectors and tuples.
    for kind, key in (("S", "schnorr"), ("E", "ecdsa")):
        pre = "" if kind == "S" else "ecdsa_"
        for item in vec[key]:
            case, out = item["input"], item["output"]

            def run(mod, case=case, out=out, pre=pre):
                sk, msg, rho = (bytes.fromhex(case[x]) for x in ("sk", "m", "rho"))
                pk = getattr(mod, pre + "public_key")(sk)
                hc = getattr(mod, pre + "host_commit")(rho)
                r0 = getattr(mod, pre + "device_commit")(sk, msg, hc)
                sig = getattr(mod, pre + "device_sign")(sk, msg, rho)
                for name, got in (("hc", hc), ("pk", pk), ("R0", r0), ("sig", sig)):
                    if got.hex() != out[name]:
                        raise AssertionError("%s differs from stored vector" % name)
                ok = getattr(mod, pre + "host_verify")(pk, msg, rho, r0, sig)
                if type(ok) is not bool or ok is not True:
                    raise AssertionError("valid vector must verify with exact True")
            tests.append(("vec:" + case["id"], run))

    for tc in vec["host_verify_cases"]:
        def run(mod, tc=tc):
            fn = mod.ecdsa_host_verify if tc["id"].startswith("E") else mod.host_verify
            got = fn(*(bytes.fromhex(tc[k]) for k in ("pk", "m", "rho", "R0", "sig")))
            if type(got) is not bool or got is not tc["expected"]:
                raise AssertionError("expected %r got %r" % (tc["expected"], got))
        tests.append(("tuple:" + tc["id"], run))
    return tests


def run(candidate, stop_on_fail=False):
    t0 = time.time()
    results = {}
    try:
        mod = load_candidate(candidate)
    except BaseException as exc:  # noqa: BLE001 - load failure fails everything
        return {"target": "math", "candidate": str(candidate), "loaded": False,
                "load_error": "%s: %s" % (type(exc).__name__, str(exc)[:200]),
                "total": 0, "passed": 0, "failed": ["<load>"], "results": {}, "seconds": time.time() - t0}
    tests = build_tests()
    failed = []
    for name, fn in tests:
        try:
            fn(mod)
            results[name] = {"ok": True}
        except BaseException as exc:  # noqa: BLE001 - any failure kills
            if isinstance(exc, KeyboardInterrupt):
                raise
            results[name] = {"ok": False, "detail": "%s: %s" % (type(exc).__name__, str(exc)[:160])}
            failed.append(name)
            if stop_on_fail:
                break
    return {"target": "math", "candidate": str(candidate), "loaded": True, "total": len(tests),
            "ran": len(results), "passed": sum(1 for r in results.values() if r["ok"]),
            "failed": failed, "results": results, "seconds": round(time.time() - t0, 3)}


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = {a for a in argv[1:] if a.startswith("--")}
    if "--list" in flags:
        print(json.dumps([name for name, _ in build_tests()]))
        return 0
    if len(args) != 1:
        print("usage: corpus_math.py CANDIDATE [--stop-on-fail] [--list]", file=sys.stderr)
        return 2
    summary = run(pathlib.Path(args[0]), stop_on_fail="--stop-on-fail" in flags)
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["loaded"] and not summary["failed"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
