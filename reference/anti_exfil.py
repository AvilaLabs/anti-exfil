"""Pure Python reference math for the anti-exfil BIP.

NOT FOR PRODUCTION: Python arithmetic is variable-time and secret erasure is
not reliable. This module implements protocol mathematics only; it does not
implement approval, transaction digest computation, transport, or failure
warnings.
"""

import hashlib


_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (_GX, _GY)
_INF = None


def _tagged_hash(tag, data):
    tag_hash = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def _b32(i):
    return i.to_bytes(32, "big")


def _on_curve(point):
    if point is _INF:
        return False
    x, y = point
    return 0 <= x < _P and 0 <= y < _P and (y * y - x * x * x - 7) % _P == 0


def _lift_x(x, odd=False):
    if not 0 <= x < _P:
        return _INF
    c = (pow(x, 3, _P) + 7) % _P
    y = pow(c, (_P + 1) // 4, _P)
    if y * y % _P != c:
        return _INF
    if bool(y & 1) != bool(odd):
        y = _P - y
    return (x, y)


def _parse33(data):
    if not isinstance(data, bytes) or len(data) != 33 or data[0] not in (2, 3):
        return _INF
    return _lift_x(int.from_bytes(data[1:], "big"), data[0] == 3)


def _ser33(point):
    if point is _INF:
        raise ValueError("point at infinity")
    x, y = point
    return bytes((2 | (y & 1),)) + _b32(x)


def _j_double(a):
    if a is _INF or a[2] == 0 or a[1] == 0:
        return _INF
    x, y, z = a
    yy = y * y % _P
    s = 4 * x * yy % _P
    m = 3 * x * x % _P
    nx = (m * m - 2 * s) % _P
    ny = (m * (s - nx) - 8 * yy * yy) % _P
    nz = 2 * y * z % _P
    return (nx, ny, nz)


def _j_add(a, b):
    if a is _INF or a[2] == 0:
        return b
    if b is _INF or b[2] == 0:
        return a
    x1, y1, z1 = a
    x2, y2, z2 = b
    z1z1 = z1 * z1 % _P
    z2z2 = z2 * z2 % _P
    u1 = x1 * z2z2 % _P
    u2 = x2 * z1z1 % _P
    s1 = y1 * z2 * z2z2 % _P
    s2 = y2 * z1 * z1z1 % _P
    if u1 == u2:
        return _j_double(a) if s1 == s2 else _INF
    h = (u2 - u1) % _P
    i = (2 * h) ** 2 % _P
    j = h * i % _P
    r = 2 * (s2 - s1) % _P
    v = u1 * i % _P
    x3 = (r * r - j - 2 * v) % _P
    y3 = (r * (v - x3) - 2 * s1 * j) % _P
    z3 = ((z1 + z2) ** 2 - z1z1 - z2z2) * h % _P
    return (x3, y3, z3)


def _to_j(point):
    return _INF if point is _INF else (point[0], point[1], 1)


def _from_j(point):
    if point is _INF or point[2] == 0:
        return _INF
    x, y, z = point
    zi = pow(z, _P - 2, _P)
    zi2 = zi * zi % _P
    return (x * zi2 % _P, y * zi2 * zi % _P)


def _add(a, b):
    return _from_j(_j_add(_to_j(a), _to_j(b)))


def _mul(k, point=_G):
    if k % _N == 0 or point is _INF:
        return _INF
    if k < 0:
        return _mul(-k, (point[0], (-point[1]) % _P))
    result = _INF
    addend = _to_j(point)
    while k:
        if k & 1:
            result = _j_add(result, addend)
        addend = _j_double(addend)
        k >>= 1
    return _from_j(result)


def _neg(point):
    return _INF if point is _INF else (point[0], (-point[1]) % _P)


def _secret(sk):
    if not isinstance(sk, bytes) or len(sk) != 32:
        raise ValueError("sk must be 32 bytes")
    d = int.from_bytes(sk, "big")
    if not 0 < d < _N:
        raise ValueError("secret key out of range")
    return d


def _require_bytes(name, value, length=None):
    if not isinstance(value, bytes) or (length is not None and len(value) != length):
        raise ValueError("invalid " + name)


def _schnorr_pub(d):
    p = _mul(d)
    d_even = d if p[1] % 2 == 0 else _N - d
    return _b32(p[0]), d_even


def _schnorr_k0(d_even, pk, m, hc):
    mask = _tagged_hash("BIP0340/aux", hc)
    t0 = bytes(a ^ b for a, b in zip(_b32(d_even), mask))
    k0 = int.from_bytes(_tagged_hash("s2c/schnorr/nonce", t0 + pk + m + hc), "big") % _N
    if k0 == 0:
        raise ValueError("base nonce is zero")
    return k0


def _schnorr_t(R0_bytes, rho):
    t = int.from_bytes(_tagged_hash("s2c/schnorr/point", R0_bytes + rho), "big")
    if t >= _N:
        raise ValueError("tweak out of range")
    return t


def _schnorr_verify(pk, m, sig):
    if not isinstance(pk, bytes) or len(pk) != 32 or not isinstance(m, bytes):
        return False
    if not isinstance(sig, bytes) or len(sig) != 64:
        return False
    px = int.from_bytes(pk, "big")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if px >= _P or r >= _P or s >= _N:
        return False
    p = _lift_x(px)
    if p is _INF:
        return False
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", sig[:32] + pk + m), "big") % _N
    R = _add(_mul(s), _neg(_mul(e, p)))
    return R is not _INF and R[1] % 2 == 0 and R[0] == r


def public_key(sk):
    """Return the BIP340 x-only public key for a 32-byte secret scalar."""
    d = _secret(sk)
    return _schnorr_pub(d)[0]


def host_commit(rho):
    _require_bytes("rho", rho, 32)
    return _tagged_hash("s2c/schnorr/data", rho)


def device_commit(sk, m, hc):
    d = _secret(sk)
    _require_bytes("m", m)
    _require_bytes("hc", hc, 32)
    pk, de = _schnorr_pub(d)
    k0 = _schnorr_k0(de, pk, m, hc)
    return _ser33(_mul(k0))


def device_sign(sk, m, rho):
    d0 = _secret(sk)
    _require_bytes("m", m)
    _require_bytes("rho", rho, 32)
    pk, d = _schnorr_pub(d0)
    hc = _tagged_hash("s2c/schnorr/data", rho)
    k0 = _schnorr_k0(d, pk, m, hc)
    R0_bytes = _ser33(_mul(k0))
    kp = (k0 + _schnorr_t(R0_bytes, rho)) % _N
    if kp == 0:
        raise ValueError("final nonce is zero")
    W = _mul(kp)
    k = kp if W[1] % 2 == 0 else _N - kp
    r = _b32(W[0])
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", r + pk + m), "big") % _N
    sig = r + _b32((k + e * d) % _N)
    if not _schnorr_verify(pk, m, sig):
        raise ValueError("internal BIP340 verification failed")
    return sig


def host_verify(pk, m, rho, R0_bytes, sig):
    if (not isinstance(pk, bytes) or len(pk) != 32 or
            not isinstance(m, bytes) or
            not isinstance(rho, bytes) or len(rho) != 32 or
            not isinstance(R0_bytes, bytes) or len(R0_bytes) != 33 or
            not isinstance(sig, bytes) or len(sig) != 64):
        return False
    R0 = _parse33(R0_bytes)
    if R0 is _INF:
        return False
    t = int.from_bytes(_tagged_hash("s2c/schnorr/point", R0_bytes + rho), "big")
    if t >= _N:
        return False
    W = _add(R0, _mul(t))
    if W is _INF or _b32(W[0]) != sig[:32]:
        return False
    return bool(_schnorr_verify(pk, m, sig))


def _ecdsa_k0(d, pk, m, hc):
    mask = _tagged_hash("s2c/ecdsa/aux", hc)
    d_mask = bytes(a ^ b for a, b in zip(_b32(d), mask))
    k0 = int.from_bytes(_tagged_hash("s2c/ecdsa/nonce", d_mask + pk + m + hc), "big")
    if not 0 < k0 < _N:
        raise ValueError("base nonce out of range")
    return k0


def _ecdsa_t(R0_bytes, rho):
    t = int.from_bytes(_tagged_hash("s2c/ecdsa/point", R0_bytes + rho), "big")
    if t >= _N:
        raise ValueError("tweak out of range")
    return t


def _ecdsa_verify(pk, m, sig, R0, t):
    if not _on_curve(pk) or not isinstance(m, bytes) or len(m) != 32:
        return False
    if not isinstance(sig, bytes) or len(sig) != 64:
        return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if not (0 < r < _N and 0 < s <= (_N - 1) // 2):
        return False
    W = _add(R0, _mul(t))
    if W is _INF or W[0] % _N != r:
        return False
    z = int.from_bytes(m, "big") % _N
    si = pow(s, _N - 2, _N)
    V = _add(_mul(z * si % _N), _mul(r * si % _N, pk))
    if V is _INF or V[0] % _N != r:
        return False
    return V == W or V == _neg(W)


def ecdsa_public_key(sk):
    d = _secret(sk)
    return _ser33(_mul(d))


def ecdsa_host_commit(rho):
    _require_bytes("rho", rho, 32)
    return _tagged_hash("s2c/ecdsa/data", rho)


def ecdsa_device_commit(sk, m, hc):
    d = _secret(sk)
    _require_bytes("m", m, 32)
    _require_bytes("hc", hc, 32)
    pk = _ser33(_mul(d))
    k0 = _ecdsa_k0(d, pk, m, hc)
    return _ser33(_mul(k0))


def ecdsa_device_sign(sk, m, rho):
    d = _secret(sk)
    _require_bytes("m", m, 32)
    _require_bytes("rho", rho, 32)
    pk = _ser33(_mul(d))
    hc = _tagged_hash("s2c/ecdsa/data", rho)
    k0 = _ecdsa_k0(d, pk, m, hc)
    R0_bytes = _ser33(_mul(k0))
    kp = (k0 + _ecdsa_t(R0_bytes, rho)) % _N
    if kp == 0:
        raise ValueError("final nonce is zero")
    W = _mul(kp)
    r = W[0] % _N
    if r == 0:
        raise ValueError("r is zero")
    z = int.from_bytes(m, "big") % _N
    s = pow(kp, _N - 2, _N) * (z + r * d) % _N
    if s == 0:
        raise ValueError("s is zero")
    if s > (_N - 1) // 2:
        s = _N - s
    sig = _b32(r) + _b32(s)
    if not _ecdsa_verify(_mul(d), m, sig, _mul(k0), _ecdsa_t(R0_bytes, rho)):
        raise ValueError("internal ECDSA verification failed")
    return sig


def ecdsa_host_verify(pk, m, rho, R0_bytes, sig):
    if (not isinstance(pk, bytes) or len(pk) != 33 or
            not isinstance(m, bytes) or len(m) != 32 or
            not isinstance(rho, bytes) or len(rho) != 32 or
            not isinstance(R0_bytes, bytes) or len(R0_bytes) != 33 or
            not isinstance(sig, bytes) or len(sig) != 64):
        return False
    P = _parse33(pk)
    R0 = _parse33(R0_bytes)
    if P is _INF or R0 is _INF:
        return False
    t = int.from_bytes(_tagged_hash("s2c/ecdsa/point", R0_bytes + rho), "big")
    if t >= _N:
        return False
    return bool(_ecdsa_verify(P, m, sig, R0, t))
