#!/usr/bin/env python3
"""Math survivors: new tests for the survivors triaged as killable or redundant.

Standalone. It imports corpus_math.py read-only (for the independent affine arithmetic,
the toy curve and the hash seam) and does not edit it.

  reference_math_mutant_tests.py                       run every test on reference/anti_exfil.py
  reference_math_mutant_tests.py --candidate PATH      run every test on another file
  reference_math_mutant_tests.py --confirm [--only ID] rebuild each mutant from the pinned source with
                                               mechanical_mutants.mutate, require each test to pass on
                                               the original and to fail on every mutant it lists

Each test carries a `section`:
  api     public entry points only, optionally with the hash seam or the toy curve (the
          mechanisms corpus_math.py already uses). A failure is a refusal that the original
          makes through a public call.
  helper  a direct call of an internal function. The public entry points never pass these
          inputs (an earlier check or the callers' invariants prevent it). These are the
          "redundant" or "dead path" survivors; the test shows the mutant is separable.

Refusals are asserted by exception type and message text. A mutant that fails the same way
with another message is killed on purpose: the original's message names the reason.
Every test runs under a 3 second alarm so a mutant that loops forever fails, not hangs.

Run as: nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 \
        python3 -B -I validation/mutants/reference_math_mutant_tests.py --confirm
"""
import json
import pathlib
import signal
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import corpus_math as CM  # noqa: E402
import mechanical_mutants as MM  # noqa: E402

P, N, G = CM.P, CM.N, CM.G
H = (N - 1) // 2
SK1 = CM.SK1
RHO = CM.RHO
PINNED = ROOT / "reference/anti_exfil.py"
WORK = ROOT / ".work/mutants/confirm"
TIMEOUT_S = 3


# ---- independent helpers -----------------------------------------------------------
def ser32(i):
    return i.to_bytes(32, "big")


def neg(pt):
    return CM.point_neg(pt)


def tagged(tag, data):
    return CM.tagged_bytes(tag, data)


def cube_root_minus_six():
    """x with x^3 = -6 (mod p): the curve has points (x, 1) and (x, p - 1). p - 1 = 3 mod 9 * ..., so 3 is
    invertible modulo (p - 1) / 3 and a^(3^-1) is a cube root of any cubic residue a."""
    m = (P - 1) // 3
    x = pow(-6 % P, pow(3, -1, m), P)
    if x ** 3 % P != -6 % P:
        raise AssertionError("fixture: cube root failed")
    return x


def expect_raise(fn, exc_type, text):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        if type(exc) is not exc_type or text not in str(exc):
            raise AssertionError("raised %s(%r), expected %s containing %r" % (type(exc).__name__, str(exc), exc_type.__name__, text))
        return
    raise AssertionError("did not raise; expected %s containing %r" % (exc_type.__name__, text))


def bip340_sign_with_nonce(d_int, m, k):
    """independent BIP340 signature with a chosen nonce k (0 < k < n); returns (pk, sig)"""
    P_ = CM.mul(d_int)
    d = d_int if P_[1] % 2 == 0 else N - d_int
    pk = ser32(P_[0])
    R = CM.mul(k)
    kk = k if R[1] % 2 == 0 else N - k
    r = ser32(R[0])
    e = int.from_bytes(tagged("BIP0340/challenge", r + pk + m), "big") % N
    return pk, r + ser32((kk + e * d) % N)


def ecdsa_sign_with_nonce(d_int, z, k):
    """independent low-s ECDSA signature with nonce k; returns sig bytes"""
    W = CM.mul(k)
    r = W[0] % N
    s = pow(k, -1, N) * (z + r * d_int) % N
    if s > H:
        s = N - s
    return ser32(r) + ser32(s)


# ---- the fixture world: hash seam fixes k0 and t, so every value is known --------------
def ecdsa_world(mod, d, v, tv, z):
    """returns (sig_or_exception, R0_bytes, pk) for a signer with key d, k0 = v, t = tv, m = bytes32(z)"""
    sk, m = ser32(d), ser32(z)
    with CM.HashSeam(mod, {"s2c/ecdsa/nonce": v, "s2c/ecdsa/point": tv}):
        r0 = mod.ecdsa_device_commit(sk, m, ser32(9))
        pk = mod.ecdsa_public_key(sk)
        try:
            sig = mod.ecdsa_device_sign(sk, m, RHO)
        except ValueError as exc:
            sig = exc
    return sig, r0, pk


def z_for_s(d, v, tv, s_target):
    kp = (v + tv) % N
    W = CM.mul(kp)
    r = W[0] % N
    return (s_target * kp - r * d) % N, r


# ---- api tests -------------------------------------------------------------------------
def t_schnorr_offcurve_pk_rejected(mod):
    # pk = x 5 has no curve point. R0 = aG, t = H(R0 || rho), W = (a + t)G. A signature (x(W), s)
    # with sG = W (even y) satisfies the verifier equation when the pk term vanishes, so only the
    # lift_x failure refuses it.
    for a in range(1, 50):
        r0 = CM.ser33(CM.mul(a))
        t = int.from_bytes(tagged("s2c/schnorr/point", r0 + RHO), "big")
        if t >= N:
            continue
        s = (a + t) % N
        W = CM.mul(s)
        if W is None:
            continue
        if W[1] % 2:
            s = N - s
        break
    else:
        raise AssertionError("no fixture")
    sig = ser32(W[0]) + ser32(s)
    for label, pk in (("x = 5", ser32(5)), ("x = 7", ser32(7)), ("x = 9", ser32(9))):
        got = mod.host_verify(pk, b"\x01", RHO, r0, sig)
        if got is not False:
            raise AssertionError("host_verify accepted an off-curve public key (%s)" % label)


def t_schnorr_s_equal_n_rejected(mod):
    # s = n reduces to 0, so R = s*G - e*P = -e*P. With the challenge forced to e and t forced to 0,
    # R0 = R and sig = (x(R), n). Only the range check s >= n refuses it.
    pk = mod.public_key(SK1)  # P = G, even y
    for e in range(2, 40):
        R = CM.mul(e, neg(G))
        if R[1] % 2 == 0:
            break
    sig = ser32(R[0]) + ser32(N)
    with CM.HashSeam(mod, {"BIP0340/challenge": e, "s2c/schnorr/point": 0}):
        got = mod.host_verify(pk, b"\x01", RHO, CM.ser33(R), sig)
    if got is not False:
        raise AssertionError("host_verify accepted s = n")


def t_schnorr_garbage_r0_rejected(mod):
    # The nonce of this signature is t itself, so with no R0 the relation x(W) = x(tG) holds and
    # BIP340 verification passes. Only the parse33 failure on R0_bytes refuses it.
    d = 7
    pk = mod.public_key(ser32(d))
    for label, r0 in (("prefix 04", b"\x04" + ser32(G[0])), ("x off curve", b"\x02" + ser32(5)),
                      ("x >= p", b"\x02" + ser32(P)), ("prefix 00", b"\x00" + ser32(G[0]))):
        t = int.from_bytes(tagged("s2c/schnorr/point", r0 + RHO), "big")
        if t >= N:
            raise AssertionError("fixture: t out of range")
        _, sig = bip340_sign_with_nonce(d, b"\x01", t)
        got = mod.host_verify(pk, b"\x01", RHO, r0, sig)
        if got is not False:
            raise AssertionError("schnorr host_verify accepted unparsable R0_bytes (%s)" % label)


def t_ecdsa_garbage_r0_rejected(mod):
    d = 7
    pk = mod.ecdsa_public_key(ser32(d))
    z = 1
    for label, r0 in (("prefix 04", b"\x04" + ser32(G[0])), ("x off curve", b"\x02" + ser32(5)),
                      ("x >= p", b"\x02" + ser32(P)), ("prefix 00", b"\x00" + ser32(G[0]))):
        t = int.from_bytes(tagged("s2c/ecdsa/point", r0 + RHO), "big")
        if t >= N:
            raise AssertionError("fixture: t out of range")
        sig = ecdsa_sign_with_nonce(d, z, t)
        got = mod.ecdsa_host_verify(pk, ser32(z), RHO, r0, sig)
        if got is not False:
            raise AssertionError("ecdsa host_verify accepted unparsable R0_bytes (%s)" % label)


def t_doubling_in_w(mod):
    # t forced to 5 and R0 = 5G, so W = R0 + 5G is the doubling case of the Jacobian add: W = 10G.
    # R0 = -5G gives W = infinity, which must be refused even for a signature with nonce -10.
    d, z, tv = 7, 1, 5
    tG = CM.mul(tv)
    pk_e = mod.ecdsa_public_key(ser32(d))
    pk_s, sig_s = bip340_sign_with_nonce(d, b"\x01", 2 * tv)
    sig_e = ecdsa_sign_with_nonce(d, z, 2 * tv)
    with CM.HashSeam(mod, {"s2c/ecdsa/point": tv, "s2c/schnorr/point": tv}):
        if mod.ecdsa_host_verify(pk_e, ser32(z), RHO, CM.ser33(tG), sig_e) is not True:
            raise AssertionError("ecdsa: valid signature with W = 2*R0 refused (doubling case)")
        if mod.host_verify(pk_s, b"\x01", RHO, CM.ser33(tG), sig_s) is not True:
            raise AssertionError("schnorr: valid signature with W = 2*R0 refused (doubling case)")
        nG = neg(tG)
        sig_e = ecdsa_sign_with_nonce(d, z, N - 2 * tv)
        _, sig_s = bip340_sign_with_nonce(d, b"\x01", N - 2 * tv)
        if mod.ecdsa_host_verify(pk_e, ser32(z), RHO, CM.ser33(nG), sig_e) is not False:
            raise AssertionError("ecdsa: W = R0 + tG = infinity accepted")
        if mod.host_verify(pk_s, b"\x01", RHO, CM.ser33(nG), sig_s) is not False:
            raise AssertionError("schnorr: W = R0 + tG = infinity accepted")


def _s_target(mod, s_target, expect):
    d, v, tv = 7, 11, 13
    z, _ = z_for_s(d, v, tv, s_target)
    sig, r0, pk = ecdsa_world(mod, d, v, tv, z)
    if expect == "zero":
        if not isinstance(sig, ValueError) or "s is zero" not in str(sig):
            raise AssertionError("s = 0: expected ValueError 's is zero', got %r" % (sig,))
        return
    if isinstance(sig, Exception):
        raise AssertionError("s = %d: signer refused: %r" % (s_target, sig))
    want = min(s_target, N - s_target)
    if int.from_bytes(sig[32:], "big") != want:
        raise AssertionError("s = %d: signature carries s = %d" % (s_target, int.from_bytes(sig[32:], "big")))
    with CM.HashSeam(mod, {"s2c/ecdsa/point": tv}):
        ok = mod.ecdsa_host_verify(pk, ser32(z), RHO, r0, sig)
    if ok is not True:
        raise AssertionError("s = %d: host_verify refused the signature" % want)


def t_ecdsa_sign_s_zero_message(mod):
    _s_target(mod, 0, "zero")


def t_ecdsa_s_one_sign_and_verify(mod):
    _s_target(mod, 1, "ok")


def t_ecdsa_s_at_low_s_limit(mod):
    # s = (n - 1) / 2 is the largest accepted low-s value; s = (n + 1) / 2 flips to it
    _s_target(mod, H, "ok")
    _s_target(mod, H + 1, "ok")


def t_schnorr_zero_nonce_message(mod):
    sk, m = ser32(5), b"\x01"
    for v in (0, N):
        with CM.HashSeam(mod, {"s2c/schnorr/nonce": v}):
            expect_raise(lambda: mod.device_commit(sk, m, ser32(9)), ValueError, "base nonce is zero")
            expect_raise(lambda: mod.device_sign(sk, m, RHO), ValueError, "base nonce is zero")


def t_ecdsa_nonce_range_message(mod):
    sk, m = ser32(5), ser32(1)
    for v in (0, N, N + 1, 2 ** 256 - 1):
        with CM.HashSeam(mod, {"s2c/ecdsa/nonce": v}):
            expect_raise(lambda: mod.ecdsa_device_commit(sk, m, ser32(9)), ValueError, "base nonce out of range")
            expect_raise(lambda: mod.ecdsa_device_sign(sk, m, RHO), ValueError, "base nonce out of range")


def _toy_sign(mod, w_point, d, z):
    """sign on the toy curve with k0 and t forced so that W = w_point"""
    T = CM.load_toy(mod)
    CM.toy_sanity()
    w = CM.toy_dl(w_point)
    tv = 1
    v = (w - tv) % CM.TOY_N
    if v == 0:
        tv, v = 2, (w - 2) % CM.TOY_N
    with CM.HashSeam(T, {"s2c/ecdsa/nonce": v, "s2c/ecdsa/point": tv}):
        try:
            sig = T.ecdsa_device_sign(ser32(d), ser32(z), RHO)
        except ValueError as exc:
            sig = exc
        r0 = T.ecdsa_device_commit(ser32(d), ser32(z), ser32(9))
        pk = T.ecdsa_public_key(ser32(d))
        ok = None if isinstance(sig, Exception) else T.ecdsa_host_verify(pk, ser32(z), RHO, r0, sig)
    return sig, ok


def t_toy_ecdsa_r_zero_sign_message(mod):
    # W with x(W) = n gives r = x(W) mod n = 0; the signer must refuse with its own reason
    sig, _ = _toy_sign(mod, CM.toy_lift(CM.TOY_N), 5, 77)
    if not isinstance(sig, ValueError) or "r is zero" not in str(sig):
        raise AssertionError("expected ValueError 'r is zero', got %r" % (sig,))


def t_toy_ecdsa_r_one_accepted(mod):
    # x(W) = 1 gives r = 1, a valid value: the signer returns it and the host accepts it
    for z in range(77, 200):
        sig, ok = _toy_sign(mod, CM.toy_lift(1), 5, z)
        if isinstance(sig, Exception) and "s is zero" in str(sig):
            continue
        break
    if isinstance(sig, Exception):
        raise AssertionError("signer refused r = 1: %r" % (sig,))
    if int.from_bytes(sig[:32], "big") != 1:
        raise AssertionError("fixture: r is not 1")
    if ok is not True:
        raise AssertionError("host_verify refused a valid signature with r = 1")


def t_mul_terminates(mod):
    # a loop that never shifts k never ends; the alarm turns that into a failure
    if mod._mul(3) != CM.mul(3) or mod.public_key(SK1) != ser32(G[0]):
        raise AssertionError("_mul(3) is wrong")


# ---- helper tests (direct calls of internal functions) ----------------------------------
def t_ser33_infinity_message(mod):
    expect_raise(lambda: mod._ser33(None), ValueError, "point at infinity")


def t_on_curve_infinity(mod):
    if mod._on_curve(None) is not False:
        raise AssertionError("_on_curve(infinity) must be False")


def t_on_curve_negative_y(mod):
    x = cube_root_minus_six()
    if mod._on_curve((x, 1)) is not True or mod._on_curve((x, P - 1)) is not True:
        raise AssertionError("control: (x, 1) and (x, p - 1) are curve points")
    if mod._on_curve((x, -1)) is not False:
        raise AssertionError("_on_curve accepted y = -1")


def t_j_double_edge_coordinates(mod):
    x = cube_root_minus_six()
    for label, y in (("y = 1", 1), ("y = -1 (unreduced p - 1)", -1)):
        pt = (x, y % P)
        want = CM.point_add(pt, pt)
        got = mod._from_j(mod._j_double((x, y, 1)))
        if got != want:
            raise AssertionError("_j_double of a point with %s is wrong" % label)
    # a Jacobian rep of G with z = -1 (affine (X / z^2, Y / z^3) = (Gx, Gy))
    want = CM.point_add(G, G)
    if mod._from_j(mod._j_double((G[0], P - G[1], -1))) != want:
        raise AssertionError("_j_double of a z = -1 representation is wrong")
    # an off-curve triple with X = 0 goes through the formulas, not the infinity guard
    if mod._j_double((0, 5, 1)) != (0, (-8 * 25 * 25) % P, 10):
        raise AssertionError("_j_double((0, 5, 1)) is not the doubling formula")


def t_j_double_infinity_rep(mod):
    if mod._j_double(None) is not None or mod._j_double((G[0], 5, 0)) is not None or mod._j_double((G[0], 0, 1)) is not None:
        raise AssertionError("_j_double must return the infinity marker for infinity, z = 0 and y = 0")


def t_j_add_guards(mod):
    gj = (G[0], G[1], 1)
    zero_z = (G[0], G[1], 0)
    if mod._j_add(zero_z, gj) != gj or mod._j_add(gj, zero_z) != gj:
        raise AssertionError("_j_add must treat z = 0 as infinity on either side")
    m1 = (G[0], P - G[1], -1)  # z = -1 representation of G
    want = CM.point_add(G, G)
    if mod._from_j(mod._j_add(m1, gj)) != want or mod._from_j(mod._j_add(gj, m1)) != want:
        raise AssertionError("_j_add of a z = -1 representation is wrong")


def t_from_j_guards(mod):
    if mod._from_j((G[0], G[1], 0)) is not None:
        raise AssertionError("_from_j of z = 0 must be infinity")
    if mod._from_j((G[0], P - G[1], -1)) != G:
        raise AssertionError("_from_j of a z = -1 representation is wrong")


def t_mul_negative_k(mod):
    five_g = CM.mul(5)
    if mod._mul(-5, G) != neg(five_g) or mod._mul(-1, G) != neg(G):
        raise AssertionError("_mul with negative k must return k * point")
    x = cube_root_minus_six()
    pt = (x, 1)
    if mod._mul(-3, pt) != neg(CM.mul(3, pt)):
        raise AssertionError("_mul(-3, point with y = 1) is wrong")


def t_mul_infinity_negative(mod):
    if mod._mul(-1, None) is not None or mod._mul(0, G) is not None or mod._mul(N, G) is not None:
        raise AssertionError("_mul of infinity, 0 and n must be infinity")


def t_schnorr_verify_direct_guards(mod):
    pk, m = mod.public_key(SK1), b"\x01"
    sig = mod.device_sign(SK1, m, RHO)
    for label, args in (("pk None", (None, m, sig)), ("pk 31 bytes", (pk[:31], m, sig)), ("m None", (pk, None, sig)),
                        ("sig None", (pk, m, None)), ("sig 63 bytes", (pk, m, sig[:63]))):
        if mod._schnorr_verify(*args) is not False:
            raise AssertionError("_schnorr_verify did not return exactly False (%s)" % label)


def t_ecdsa_verify_direct_guards(mod):
    m = ser32(1)
    sig = mod.ecdsa_device_sign(SK1, m, RHO)
    R0 = G
    for label, args in (("pk None", (None, m, sig, R0, 1)), ("m None", (G, None, sig, R0, 1)), ("m 31 bytes", (G, m[:31], sig, R0, 1)),
                        ("sig None", (G, m, None, R0, 1)), ("sig 63 bytes", (G, m, sig[:63], R0, 1))):
        if mod._ecdsa_verify(*args) is not False:
            raise AssertionError("_ecdsa_verify did not return exactly False (%s)" % label)
    # a signature that is valid when the public-key term is dropped: R0 = aG, t, s = z / (a + t)
    a, t, z = 3, 5, 1
    W = CM.mul(a + t)
    s = z * pow(a + t, -1, N) % N
    sig = ser32(W[0] % N) + ser32(min(s, N - s))
    if mod._ecdsa_verify(None, ser32(z), sig, CM.mul(a), t) is not False:
        raise AssertionError("_ecdsa_verify accepted pk = None")


# (id, section, function, [mutant ids it must kill])
TESTS = [
    ("api:schnorr-offcurve-pk-rejected", "api", t_schnorr_offcurve_pk_rejected, ["MM-math-0276", "MM-math-0277"]),
    ("api:schnorr-s-equal-n-rejected", "api", t_schnorr_s_equal_n_rejected, ["MM-math-0271"]),
    ("api:schnorr-garbage-r0-rejected", "api", t_schnorr_garbage_r0_rejected, ["MM-math-0357"]),
    ("api:ecdsa-garbage-r0-rejected", "api", t_ecdsa_garbage_r0_rejected, ["MM-math-0515"]),
    ("api:w-doubling-and-infinity", "api", t_doubling_in_w, ["MM-math-0140", "MM-math-0141"]),
    ("api:ecdsa-sign-s-zero-message", "api", t_ecdsa_sign_s_zero_message, ["MM-math-0480", "MM-math-0483"]),
    ("api:ecdsa-s-one-sign-and-verify", "api", t_ecdsa_s_one_sign_and_verify, ["MM-math-0480", "MM-math-0405"]),
    ("api:ecdsa-s-at-low-s-limit", "api", t_ecdsa_s_at_low_s_limit, ["MM-math-0484", "MM-math-0488", "MM-math-0407", "MM-math-0412"]),
    ("api:schnorr-zero-nonce-message", "api", t_schnorr_zero_nonce_message, ["MM-math-0244", "MM-math-0246"]),
    ("api:ecdsa-nonce-range-message", "api", t_ecdsa_nonce_range_message, ["MM-math-0376", "MM-math-0377", "MM-math-0378"]),
    ("api:toy-ecdsa-r-zero-sign-message", "api", t_toy_ecdsa_r_zero_sign_message, ["MM-math-0475"]),
    ("api:toy-ecdsa-r-one-accepted", "api", t_toy_ecdsa_r_one_accepted, ["MM-math-0472", "MM-math-0401"]),
    ("api:mul-terminates", "api", t_mul_terminates, ["MM-math-0205", "MM-math-0206"]),
    ("helper:ser33-infinity-message", "helper", t_ser33_infinity_message, ["MM-math-0080"]),
    ("helper:on-curve-infinity", "helper", t_on_curve_infinity, ["MM-math-0020", "MM-math-0021"]),
    ("helper:on-curve-negative-y", "helper", t_on_curve_negative_y, ["MM-math-0028"]),
    ("helper:j-double-edge-coordinates", "helper", t_j_double_edge_coordinates, ["MM-math-0091", "MM-math-0094", "MM-math-0095", "MM-math-0096"]),
    ("helper:j-double-infinity-rep", "helper", t_j_double_infinity_rep, ["MM-math-0089", "MM-math-0093", "MM-math-0098"]),
    ("helper:j-add-guards", "helper", t_j_add_guards, ["MM-math-0119", "MM-math-0121", "MM-math-0126", "MM-math-0128"]),
    ("helper:from-j-guards", "helper", t_from_j_guards, ["MM-math-0173", "MM-math-0175"]),
    ("helper:mul-negative-k", "helper", t_mul_negative_k, ["MM-math-0191", "MM-math-0193", "MM-math-0194", "MM-math-0195", "MM-math-0196", "MM-math-0197"]),
    ("helper:mul-infinity-and-multiples", "helper", t_mul_infinity_negative, ["MM-math-0189"]),
    ("helper:schnorr-verify-direct-guards", "helper", t_schnorr_verify_direct_guards, ["MM-math-0255", "MM-math-0256", "MM-math-0260", "MM-math-0261"]),
    ("helper:ecdsa-verify-direct-guards", "helper", t_ecdsa_verify_direct_guards, ["MM-math-0388", "MM-math-0389", "MM-math-0393", "MM-math-0394"]),
]


# ---- runner ----------------------------------------------------------------------------
class Hang(Exception):
    pass


def _on_alarm(*_):
    raise Hang("test did not finish in %d s" % TIMEOUT_S)


def run_test(fn, path):
    """load a fresh copy of the module at path and run one test; returns None on pass, else a reason"""
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.setitimer(signal.ITIMER_REAL, TIMEOUT_S)
    try:
        mod = CM.load_candidate(path)
        fn(mod)
        return None
    except BaseException as exc:  # noqa: BLE001 - any failure is a failure
        if isinstance(exc, KeyboardInterrupt):
            raise
        return "%s: %s" % (type(exc).__name__, str(exc)[:140])
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def mutant_path(mid):
    d = WORK / mid
    d.mkdir(parents=True, exist_ok=True)
    p = d / "anti_exfil.py"
    p.write_text(MM.mutate(PINNED.read_text(), int(mid.rsplit("-", 1)[1])), encoding="utf-8")
    return p


def main(argv):
    only = None
    candidate = PINNED
    if "--only" in argv:
        only = argv[argv.index("--only") + 1]
    if "--candidate" in argv:
        candidate = pathlib.Path(argv[argv.index("--candidate") + 1])
    tests = [t for t in TESTS if only in (None, t[0])]
    if "--confirm" not in argv:
        bad = 0
        for tid, section, fn, _ in tests:
            why = run_test(fn, candidate)
            print("%-6s %-9s %s%s" % ("PASS" if why is None else "FAIL", section, tid, "" if why is None else "  " + why))
            bad += why is not None
        return 1 if bad else 0
    problems = []
    report = {}
    for tid, section, fn, mutants in tests:
        why = run_test(fn, PINNED)
        entry = {"section": section, "original": "pass" if why is None else "FAIL: " + why, "mutants": {}}
        if why is not None:
            problems.append("%s fails on the original: %s" % (tid, why))
        for mid in mutants:
            reason = run_test(fn, mutant_path(mid))
            entry["mutants"][mid] = "killed: " + reason if reason else "SURVIVED"
            if reason is None:
                problems.append("%s does not kill %s" % (tid, mid))
        report[tid] = entry
        print("%-9s %-46s original %-4s  killed %d/%d" % (section, tid, "pass" if why is None else "FAIL",
                                                         sum(1 for r in entry["mutants"].values() if r.startswith("killed")), len(mutants)))
    covered = sorted({m for t in TESTS for m in t[3]})
    print("mutants covered: %d" % len(covered))
    for p in problems:
        print("PROBLEM:", p)
    out = WORK.parent / "confirm_report.json"
    out.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print("confirm:", "FAIL" if problems else "OK", "(report %s)" % out)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
