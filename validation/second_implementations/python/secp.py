"""secp256k1 arithmetic, hashes and plain BIP340 / ECDSA verification.

Variable-time test code. Not for real keys.
"""
import hashlib

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def sha256(b):
    return hashlib.sha256(b).digest()


def dsha256(b):
    return sha256(sha256(b))


def tagged_hash(tag, x):
    th = sha256(tag.encode() if isinstance(tag, str) else tag)
    return sha256(th + th + x)


# ---------------------------------------------------------------- ripemd160
def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


_RL = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
       7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
       3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
       1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
       4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
_RR = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
       6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
       15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
       8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
       12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
_SL = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
       7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
       11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
       11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
       9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
_SR = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
       9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
       9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
       15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
       8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def _f(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & 0xFFFFFFFF & z)
    if j < 48:
        return (x | (~y & 0xFFFFFFFF)) ^ z
    if j < 64:
        return (x & z) | (y & (~z & 0xFFFFFFFF))
    return x ^ (y | (~z & 0xFFFFFFFF))


def ripemd160_py(data):
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = data + b"\x80"
    msg += b"\x00" * ((56 - len(msg)) % 64)
    msg += (len(data) * 8).to_bytes(8, "little")
    for off in range(0, len(msg), 64):
        X = [int.from_bytes(msg[off + 4 * i:off + 4 * i + 4], "little") for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            rnd = j // 16
            t = (_rol((al + _f(j, bl, cl, dl) + X[_RL[j]] + _KL[rnd]) & 0xFFFFFFFF, _SL[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t
            t = (_rol((ar + _f(79 - j, br, cr, dr) + X[_RR[j]] + _KR[rnd]) & 0xFFFFFFFF, _SR[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t
        t = (h[1] + cl + dr) & 0xFFFFFFFF
        h[1] = (h[2] + dl + er) & 0xFFFFFFFF
        h[2] = (h[3] + el + ar) & 0xFFFFFFFF
        h[3] = (h[4] + al + br) & 0xFFFFFFFF
        h[4] = (h[0] + bl + cr) & 0xFFFFFFFF
        h[0] = t
    return b"".join(x.to_bytes(4, "little") for x in h)


def ripemd160(b):
    return ripemd160_py(b)


def hash160(b):
    return ripemd160(sha256(b))


# ---------------------------------------------------------------- curve
def int_from(b):
    return int.from_bytes(b, "big")


def bytes32(i):
    return i.to_bytes(32, "big")


def pt_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0:
            return None
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def pt_neg(a):
    return None if a is None else (a[0], (-a[1]) % P)


def pt_mul(k, pt):
    k %= N
    r = None
    add = pt
    while k:
        if k & 1:
            r = pt_add(r, add)
        add = pt_add(add, add)
        k >>= 1
    return r


def lift_x(x):
    """Point with even y and the given x, or None."""
    if not 0 <= x < P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    return (x, y if y % 2 == 0 else P - y)


def ser33(pt):
    return bytes([2 + (pt[1] & 1)]) + bytes32(pt[0])


def parse33(b):
    if not isinstance(b, (bytes, bytearray)) or len(b) != 33 or b[0] not in (2, 3):
        return None
    x = int_from(b[1:])
    if x >= P:
        return None
    pt = lift_x(x)
    if pt is None:
        return None
    if (pt[1] & 1) != (b[0] & 1):
        pt = (pt[0], P - pt[1])
    return pt


def ser65(pt):
    return b"\x04" + bytes32(pt[0]) + bytes32(pt[1])


def pubkey_from_sk(sk_int):
    return pt_mul(sk_int, G)


# ---------------------------------------------------------------- plain verification
def schnorr_verify(pk32, msg, sig):
    if len(pk32) != 32 or len(sig) != 64:
        return False
    Pt = lift_x(int_from(pk32))
    if Pt is None:
        return False
    r = int_from(sig[:32])
    s = int_from(sig[32:])
    if r >= P or s >= N:
        return False
    e = int_from(tagged_hash("BIP0340/challenge", sig[:32] + pk32 + msg)) % N
    R = pt_add(pt_mul(s, G), pt_neg(pt_mul(e, Pt)))
    if R is None or R[1] % 2 != 0 or R[0] != r:
        return False
    return True


def ecdsa_verify(pub_pt, m32, r, s):
    if not (0 < r < N and 0 < s < N):
        return False
    z = int_from(m32) % N
    w = pow(s, -1, N)
    V = pt_add(pt_mul(z * w % N, G), pt_mul(r * w % N, pub_pt))
    return V is not None and V[0] % N == r
