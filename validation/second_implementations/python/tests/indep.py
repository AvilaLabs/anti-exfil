"""Independent test-side code: Jacobian secp256k1, BIP340/ECDSA verification,
signature hashes written in the style of the BIP text, a small PSBT reader/writer.
Shares nothing with the program modules."""
import hashlib
import struct

p = 2**256 - 2**32 - 977
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def H(b):
    return hashlib.sha256(b).digest()


def HH(b):
    return H(H(b))


def TH(tag, b):
    t = H(tag.encode())
    return H(t + t + b)


def h160(b):
    return hashlib.new("ripemd160", H(b)).digest()


# Jacobian (X, Y, Z); affine = X/Z^2, Y/Z^3
def _jdbl(P):
    X, Y, Z = P
    if Y == 0 or Z == 0:
        return (0, 1, 0)
    S = 4 * X * Y * Y % p
    M = 3 * X * X % p
    X2 = (M * M - 2 * S) % p
    return (X2, (M * (S - X2) - 8 * pow(Y, 4, p)) % p, 2 * Y * Z % p)


def _jadd(P, Q):
    if P[2] == 0:
        return Q
    if Q[2] == 0:
        return P
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q
    U1, U2 = X1 * Z2 * Z2 % p, X2 * Z1 * Z1 % p
    S1, S2 = Y1 * pow(Z2, 3, p) % p, Y2 * pow(Z1, 3, p) % p
    if U1 == U2:
        return _jdbl(P) if S1 == S2 else (0, 1, 0)
    Hh, R = U2 - U1, S2 - S1
    X3 = (R * R - Hh ** 3 - 2 * U1 * Hh * Hh) % p
    return (X3, (R * (U1 * Hh * Hh - X3) - S1 * Hh ** 3) % p, Hh * Z1 * Z2 % p)


def _aff(P):
    if P[2] == 0:
        return None
    zi = pow(P[2], -1, p)
    return (P[0] * zi * zi % p, P[1] * zi ** 3 % p)


def mul(k, pt=(Gx, Gy)):
    k %= n
    R = (0, 1, 0)
    Q = (pt[0], pt[1], 1)
    for bit in bin(k)[2:] if k else "":
        R = _jdbl(R)
        if bit == "1":
            R = _jadd(R, Q)
    return _aff(R)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return _aff(_jadd((a[0], a[1], 1), (b[0], b[1], 1)))


def neg(a):
    return None if a is None else (a[0], p - a[1])


def lift(x):
    y2 = (pow(x, 3, p) + 7) % p
    y = pow(y2, (p + 1) // 4, p)
    assert y * y % p == y2
    return (x, y if y % 2 == 0 else p - y)


def comp(pt):
    return bytes([2 + pt[1] % 2]) + pt[0].to_bytes(32, "big")


def pubof(sk):
    return mul(sk)


# ------------------------------------------------------------ verification
def bip340_verify(pk, msg, sig):
    P_ = lift(int.from_bytes(pk, "big"))
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if r >= p or s >= n:
        return False
    e = int.from_bytes(TH("BIP0340/challenge", sig[:32] + pk + msg), "big") % n
    R = add(mul(s), neg(mul(e, P_)))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def ecdsa_verify_der(pub33, m32, der_plus_ht):
    d = der_plus_ht[:-1]
    assert d[0] == 0x30 and d[1] == len(d) - 2 and d[2] == 2
    lr = d[3]
    r = int.from_bytes(d[4:4 + lr], "big")
    assert d[4 + lr] == 2
    ls = d[5 + lr]
    s = int.from_bytes(d[6 + lr:6 + lr + ls], "big")
    assert 6 + lr + ls == len(d)
    if not (0 < r < n and 0 < s <= (n - 1) // 2):
        return False
    P_ = lift(int.from_bytes(pub33[1:], "big"))
    if (P_[1] % 2) != (pub33[0] % 2):
        P_ = neg(P_)
    z = int.from_bytes(m32, "big")
    w = pow(s, -1, n)
    V = add(mul(z * w % n, (Gx, Gy)), mul(r * w % n, P_))
    return V is not None and V[0] % n == r


# ------------------------------------------------------------ tx + sighash (BIP text style)
def cs(k):
    if k < 253:
        return bytes([k])
    return b"\xfd" + struct.pack("<H", k)


class Tx:
    def __init__(self, version=2, locktime=0):
        self.version = version
        self.locktime = locktime
        self.vin = []    # dict(txid, vout, seq)
        self.vout = []   # dict(value, spk)

    def add_in(self, txid, vout, seq=0xFFFFFFFD):
        self.vin.append({"txid": txid, "vout": vout, "seq": seq})
        return self

    def add_out(self, value, spk):
        self.vout.append({"value": value, "spk": spk})
        return self

    def ser(self, ssigs=None):
        b = struct.pack("<I", self.version) + cs(len(self.vin))
        for k, i in enumerate(self.vin):
            ss = ssigs[k] if ssigs else b""
            b += i["txid"] + struct.pack("<I", i["vout"]) + cs(len(ss)) + ss + struct.pack("<I", i["seq"])
        b += cs(len(self.vout))
        for o in self.vout:
            b += struct.pack("<q", o["value"]) + cs(len(o["spk"])) + o["spk"]
        return b + struct.pack("<I", self.locktime)

    def txid(self):
        return HH(self.ser())


def legacy_sighash(tx, idx, script, ht):
    """Core-style: copy the tx and edit it."""
    base = ht & 0x1F
    sigs = [b""] * len(tx.vin)
    sigs[idx] = script
    ins = [dict(i) for i in tx.vin]
    outs = [dict(o) for o in tx.vout]
    if base == 3:
        assert idx < len(outs)
        outs = outs[:idx + 1]
        for k in range(idx):
            outs[k] = {"value": -1, "spk": b""}
    if base == 2:
        outs = []
    if base in (2, 3):
        for k, i in enumerate(ins):
            if k != idx:
                i["seq"] = 0
    if ht & 0x80:
        ins = [ins[idx]]
        sigs = [sigs[idx]]
    t = Tx(tx.version, tx.locktime)
    t.vin, t.vout = ins, outs
    return HH(t.ser(sigs) + struct.pack("<I", ht))


def bip143_sighash(tx, idx, script_code, amount, ht):
    base = ht & 0x1F
    acp = ht & 0x80
    op = lambda i: i["txid"] + struct.pack("<I", i["vout"])
    hp = b"\0" * 32 if acp else HH(b"".join(op(i) for i in tx.vin))
    hs = b"\0" * 32
    if not acp and base not in (2, 3):
        hs = HH(b"".join(struct.pack("<I", i["seq"]) for i in tx.vin))
    so = lambda o: struct.pack("<q", o["value"]) + cs(len(o["spk"])) + o["spk"]
    if base not in (2, 3):
        ho = HH(b"".join(so(o) for o in tx.vout))
    elif base == 3 and idx < len(tx.vout):
        ho = HH(so(tx.vout[idx]))
    else:
        ho = b"\0" * 32
    i = tx.vin[idx]
    pre = (struct.pack("<I", tx.version) + hp + hs + op(i) + cs(len(script_code)) + script_code
           + struct.pack("<q", amount) + struct.pack("<I", i["seq"]) + ho
           + struct.pack("<I", tx.locktime) + struct.pack("<I", ht))
    return HH(pre)


def taproot_sighash(tx, idx, ht, spent, ext=None):
    """spent: list of (amount, spk). ext: leaf hash for script path."""
    op = lambda i: i["txid"] + struct.pack("<I", i["vout"])
    so = lambda o: struct.pack("<q", o["value"]) + cs(len(o["spk"])) + o["spk"]
    out_t = 1 if ht == 0 else ht & 3
    in_t = ht & 0x80
    s = bytes([0, ht]) + struct.pack("<I", tx.version) + struct.pack("<I", tx.locktime)
    if not in_t:
        s += H(b"".join(op(i) for i in tx.vin))
        s += H(b"".join(struct.pack("<q", a) for a, _ in spent))
        s += H(b"".join(cs(len(k)) + k for _, k in spent))
        s += H(b"".join(struct.pack("<I", i["seq"]) for i in tx.vin))
    if out_t not in (2, 3):
        s += H(b"".join(so(o) for o in tx.vout))
    s += bytes([(1 if ext else 0) * 2])
    if in_t:
        s += op(tx.vin[idx]) + struct.pack("<q", spent[idx][0]) + cs(len(spent[idx][1])) + spent[idx][1]
        s += struct.pack("<I", tx.vin[idx]["seq"])
    else:
        s += struct.pack("<I", idx)
    if out_t == 3:
        s += H(so(tx.vout[idx]))
    if ext:
        s += ext + b"\x00" + b"\xff" * 4
    return TH("TapSighash", s)


def tweak_pub(xonly_internal, merkle=b""):
    P_ = lift(int.from_bytes(xonly_internal, "big"))
    t = int.from_bytes(TH("TapTweak", xonly_internal + merkle), "big")
    return add(P_, mul(t))


def leaf_hash(script, ver=0xC0):
    return TH("TapLeaf", bytes([ver]) + cs(len(script)) + script)


# ------------------------------------------------------------ PSBT reader/writer
def read_psbt(b):
    assert b[:5] == b"psbt\xff"
    pos = 5

    def rcs():
        nonlocal pos
        v = b[pos]
        pos += 1
        if v < 253:
            return v
        if v == 253:
            pos += 2
            return struct.unpack("<H", b[pos - 2:pos])[0]
        raise ValueError

    maps = []
    while pos < len(b):
        m = []
        while True:
            kl = rcs()
            if kl == 0:
                break
            k = b[pos:pos + kl]
            pos += kl
            vl = rcs()
            v = b[pos:pos + vl]
            pos += vl
            m.append((k, v))
        maps.append(m)
    return maps   # [global, input maps..., output maps...]


def write_psbt(maps):
    out = b"psbt\xff"
    for m in maps:
        for k, v in m:
            out += cs(len(k)) + k + cs(len(v)) + v
        out += b"\x00"
    return out


def der(r, s):
    def e(x):
        bb = x.to_bytes(32, "big").lstrip(b"\0")
        return (b"\0" + bb) if bb[0] & 0x80 else bb
    rb, sb = e(r), e(s)
    return b"\x30" + bytes([len(rb) + len(sb) + 4]) + b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
