"""Simulated backdoored signers and observers. TEST KEYS ONLY.

Not a signing implementation. Every function here exists to model an attacker
or a defect so that the unmodified public host checks of reference can be
measured against it. Pure Python, standard library only.

The reference module is loaded from its file after its SHA-256 is checked. Its
helpers (tagged hash, nonce derivation, tweak, point constants and arithmetic)
are used as they are. Only fixed-base multiplication of G is replaced here by a
table version, for speed. It is compared with the reference multiplication at
load and again in selftest().
"""

import hashlib
import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REF_PATH = ROOT / "reference" / "anti_exfil.py"
REF_SHA256 = "39d9c6c350133cef4b56110abc4d6a0e713eca2f8faac66493fadc36f68631ce"


def _load_reference():
    data = REF_PATH.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != REF_SHA256:
        raise RuntimeError("reference/anti_exfil.py hash mismatch: " + digest)
    spec = importlib.util.spec_from_loader("anti_exfil_ref", loader=None)
    module = importlib.util.module_from_spec(spec)
    exec(compile(data, str(REF_PATH), "exec"), module.__dict__)
    sys.modules["anti_exfil_ref"] = module
    return module


REF = _load_reference()
P = REF._P
N = REF._N
G = REF._G
HALF_N = (N - 1) // 2


def sha(data):
    return hashlib.sha256(data).digest()


def b32(i):
    return i.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# seeded DRBG and the secret test stream
# ---------------------------------------------------------------------------

class Drbg:
    """SHA-256 counter-mode generator: block i = SHA256(seed || i)."""

    def __init__(self, seed):
        if isinstance(seed, str):
            seed = seed.encode()
        self.seed = seed
        self.ctr = 0
        self.buf = b""

    def read(self, n):
        while len(self.buf) < n:
            self.buf += sha(self.seed + self.ctr.to_bytes(8, "big"))
            self.ctr += 1
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def below(self, bound):
        nbytes = (bound.bit_length() + 7) // 8 + 8
        return int.from_bytes(self.read(nbytes), "big") % bound

    def sub(self, label):
        return Drbg(sha(self.seed + b"/" + label.encode()))


class Stream:
    """Secret bit stream derived from sk. Bit i is bit (i % 8) of byte i // 8."""

    def __init__(self, sk):
        self.sk = sk
        self.data = b""

    def _extend(self, nbytes):
        while len(self.data) < nbytes:
            ctr = len(self.data) // 32
            self.data += sha(b"bd/stream" + self.sk + ctr.to_bytes(8, "big"))

    def byte(self, j):
        self._extend(j + 1)
        return self.data[j]

    def bit(self, i):
        self._extend(i // 8 + 1)
        return (self.data[i // 8] >> (i % 8)) & 1

    def bits(self, start, count):
        """count bits from position start, first bit in the least significant place."""
        value = 0
        for k in range(count):
            value |= self.bit(start + k) << k
        return value


# ---------------------------------------------------------------------------
# fast fixed-base multiplication of G (8-bit windows) and point walking
# ---------------------------------------------------------------------------

def _batch_affine(points):
    zs = [p[2] for p in points]
    prefix = [1]
    for z in zs:
        prefix.append(prefix[-1] * z % P)
    inv = pow(prefix[-1], -1, P)
    out = [None] * len(points)
    for i in range(len(points) - 1, -1, -1):
        zi = inv * prefix[i] % P
        inv = inv * zs[i] % P
        zi2 = zi * zi % P
        x, y, _ = points[i]
        out[i] = (x * zi2 % P, y * zi2 * zi % P)
    return out


def _build_table():
    rows = []
    base = G
    for _w in range(32):
        bj = (base[0], base[1], 1)
        jac = [None, bj]
        for j in range(2, 256):
            jac.append(REF._j_add(jac[j - 1], bj))
        nxt = REF._j_add(jac[255], bj)
        aff = _batch_affine(jac[1:] + [nxt])
        rows.append([None] + aff[:255])
        base = aff[255]
    return rows


_TABLE = _build_table()


def _madd(a, q):
    if a is None:
        return (q[0], q[1], 1)
    x1, y1, z1 = a
    x2, y2 = q
    z1z1 = z1 * z1 % P
    u2 = x2 * z1z1 % P
    if u2 == x1:
        return REF._j_add(a, (x2, y2, 1))
    s2 = y2 * z1 * z1z1 % P
    h = (u2 - x1) % P
    hh = h * h % P
    i = 4 * hh % P
    j = h * i % P
    r = 2 * (s2 - y1) % P
    v = x1 * i % P
    x3 = (r * r - j - 2 * v) % P
    y3 = (r * (v - x3) - 2 * y1 * j) % P
    z3 = ((z1 + h) ** 2 - z1z1 - hh) % P
    return (x3, y3, z3)


def fmul(k):
    """k * G as an affine point, or None for infinity."""
    k %= N
    if k == 0:
        return None
    acc = None
    w = 0
    while k:
        b = k & 255
        if b:
            acc = _madd(acc, _TABLE[w][b])
            if acc is None:
                return None
        k >>= 8
        w += 1
    zi = pow(acc[2], -1, P)
    zi2 = zi * zi % P
    return (acc[0] * zi2 % P, acc[1] * zi2 * zi % P)


def step_add_g(pt):
    """pt + G in affine coordinates, one modular inversion."""
    x, y = pt
    if x == G[0]:
        return REF._add(pt, G)
    lam = (G[1] - y) * pow(G[0] - x, -1, P) % P
    x3 = (lam * lam - x - G[0]) % P
    return (x3, (lam * (x - x3) - y) % P)


def ser33(pt):
    return REF._ser33(pt)


def _check_fmul():
    d = Drbg("bd/fmul-check")
    for _ in range(6):
        k = int.from_bytes(d.read(32), "big") % N
        if fmul(k) != REF._mul(k):
            raise RuntimeError("fixed-base table multiplication disagrees with reference")
    if fmul(N) is not None or fmul(1) != G or fmul(N - 1) != REF._neg(G):
        raise RuntimeError("fixed-base table edge cases disagree with reference")


_check_fmul()


# ---------------------------------------------------------------------------
# the two signature schemes
# ---------------------------------------------------------------------------

class Key:
    def __init__(self, sk, d, pk, point):
        self.sk, self.d, self.pk, self.point = sk, d, pk, point


def labelled_sk(label):
    k = int.from_bytes(sha(b"bd/test-key/" + label.encode()), "big") % (N - 1) + 1
    return b32(k)


class Bip340:
    name = "bip340"

    def keypair(self, label):
        sk = labelled_sk(label)
        d0 = int.from_bytes(sk, "big")
        pt = fmul(d0)
        d = d0 if pt[1] % 2 == 0 else N - d0
        return Key(sk, d, b32(pt[0]), pt)

    host_commit = staticmethod(lambda rho: REF.host_commit(rho))
    host_verify = staticmethod(lambda pk, m, rho, R0b, sig: REF.host_verify(pk, m, rho, R0b, sig))

    def k0_honest(self, key, m, hc):
        return REF._schnorr_k0(key.d, key.pk, m, hc)

    def tweak(self, R0b, rho):
        return REF._schnorr_t(R0b, rho)

    def ref_commit(self, key, m, hc):
        return REF.device_commit(key.sk, m, hc)

    def ref_sign(self, key, m, rho):
        return REF.device_sign(key.sk, m, rho)

    def sign_kp(self, key, m, kp, high_s=False):
        """Return (sig, W). kp is the final nonce scalar before any parity fix."""
        W = fmul(kp)
        k = kp if W[1] % 2 == 0 else N - kp
        r = b32(W[0])
        e = int.from_bytes(REF._tagged_hash("BIP0340/challenge", r + key.pk + m), "big") % N
        return r + b32((k + e * key.d) % N), W

    def r_int(self, sig):
        return int.from_bytes(sig[:32], "big")

    def recover(self, pk, m, sig, cands):
        """Try each candidate nonce and its negation; return a key scalar or None."""
        pkx = int.from_bytes(pk, "big")
        r, s = sig[:32], int.from_bytes(sig[32:], "big")
        e = int.from_bytes(REF._tagged_hash("BIP0340/challenge", r + pk + m), "big") % N
        if e == 0:
            return None
        einv = pow(e, -1, N)
        for c in cands:
            for k in (c % N, (N - c) % N):
                d = (s - k) * einv % N
                pt = fmul(d)
                if pt is not None and pt[0] == pkx:
                    return d
        return None


class Ecdsa:
    name = "ecdsa"

    def keypair(self, label):
        sk = labelled_sk(label)
        d = int.from_bytes(sk, "big")
        pt = fmul(d)
        return Key(sk, d, ser33(pt), pt)

    host_commit = staticmethod(lambda rho: REF.ecdsa_host_commit(rho))
    host_verify = staticmethod(lambda pk, m, rho, R0b, sig: REF.ecdsa_host_verify(pk, m, rho, R0b, sig))

    def k0_honest(self, key, m, hc):
        return REF._ecdsa_k0(key.d, key.pk, m, hc)

    def tweak(self, R0b, rho):
        return REF._ecdsa_t(R0b, rho)

    def ref_commit(self, key, m, hc):
        return REF.ecdsa_device_commit(key.sk, m, hc)

    def ref_sign(self, key, m, rho):
        return REF.ecdsa_device_sign(key.sk, m, rho)

    def sign_kp(self, key, m, kp, high_s=False):
        W = fmul(kp)
        r = W[0] % N
        z = int.from_bytes(m, "big") % N
        s = pow(kp, -1, N) * (z + r * key.d) % N
        if s > HALF_N:
            s = N - s
        if high_s:
            s = N - s
        return b32(r) + b32(s), W

    def r_int(self, sig):
        return int.from_bytes(sig[:32], "big")

    def recover(self, pk, m, sig, cands):
        point = REF._parse33(pk)
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        z = int.from_bytes(m, "big") % N
        rinv = pow(r, -1, N)
        for c in cands:
            for k in (c % N, (N - c) % N):
                for sv in (s, N - s):
                    d = (sv * k - z) * rinv % N
                    if d and fmul(d) == point:
                        return d
        return None


SCHEMES = (Bip340(), Ecdsa())


# ---------------------------------------------------------------------------
# anti-exfil devices: honest base and backdoored variants
# ---------------------------------------------------------------------------

class Derived:
    __slots__ = ("R0b", "sig", "W", "hc", "k0", "t", "kp")

    def __init__(self, R0b, sig, W, hc, k0, t, kp):
        self.R0b, self.sig, self.W, self.hc, self.k0, self.t, self.kp = R0b, sig, W, hc, k0, t, kp


def shared_nonce(K, m, hc=None):
    """The backdoor's nonce function: H(K, m) or H(K, m, hc), reduced mod n."""
    data = b"bd/backdoor-nonce" + K + m + (hc if hc is not None else b"")
    k = int.from_bytes(sha(data), "big") % N
    return k or 1


class Device:
    """Honest two-step device using the reference derivation; base for the others.

    commit(m, hc, idx) is step 2, sign(m, rho, idx) is step 4. idx is the
    position in the secret stream that a backdoored subclass uses. A return of
    None is a refusal.
    """

    label = "honest"

    def __init__(self, scheme, key, K=None, stream=None):
        self.scheme, self.key, self.K = scheme, key, K
        self.stream = stream if stream is not None else Stream(key.sk)

    def k0(self, m, hc, idx):
        return self.scheme.k0_honest(self.key, m, hc)

    def kp_offset(self):
        return 0

    def commit(self, m, hc, idx=0):
        k0 = self.k0(m, hc, idx)
        return ser33(fmul(k0))

    def derive(self, m, rho, idx=0):
        sc = self.scheme
        hc = sc.host_commit(rho)
        k0 = self.k0(m, hc, idx)
        R0b = ser33(fmul(k0))
        t = sc.tweak(R0b, rho)
        kp = (k0 + t) % N
        sig, W = sc.sign_kp(self.key, m, kp)
        return Derived(R0b, sig, W, hc, k0, t, kp)

    def sign(self, m, rho, idx=0):
        return self.derive(m, rho, idx).sig


class KnownK0Device(Device):
    """A1, A10: k0 = H(K, m, hc), otherwise the honest derivation."""

    label = "known_k0"

    def k0(self, m, hc, idx):
        return shared_nonce(self.K, m, hc)


class KnownK0NoHcDevice(Device):
    """A11: k0 = H(K, m). An observer who learns only t can complete the nonce."""

    label = "known_k0_no_hc"

    def k0(self, m, hc, idx):
        return shared_nonce(self.K, m)


class GroundR0Device(Device):
    """A2: grind k0 upward from the honest value until x(R0) mod 256 is the stream byte."""

    label = "ground_r0"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._cache = {}

    def k0(self, m, hc, idx):
        ck = (m, hc, idx)
        if ck not in self._cache:
            base = self.scheme.k0_honest(self.key, m, hc)
            want = self.stream.byte(idx)
            k0, pt = base, fmul(base)
            while pt[0] & 255 != want:
                k0 = (k0 + 1) % N
                pt = step_add_g(pt)
            self._cache[ck] = k0
        return self._cache[ck]


class UnboundDevice(Device):
    """A3: valid signatures whose nonce is not R0 + tG. variant names the defect."""

    VARIANTS = ("k0_only", "k0_t_plus_1", "ground_on_r", "high_s")

    def __init__(self, scheme, key, variant, **kw):
        super().__init__(scheme, key, **kw)
        if variant not in self.VARIANTS or (variant == "high_s" and scheme.name != "ecdsa"):
            raise ValueError("bad variant for scheme")
        self.variant = variant
        self.label = "unbound_" + variant

    def derive(self, m, rho, idx=0):
        sc = self.scheme
        d = super().derive(m, rho, idx)
        v = self.variant
        if v == "k0_only":
            kp = d.k0
        elif v == "k0_t_plus_1":
            kp = (d.kp + 1) % N
        elif v == "ground_on_r":
            want = self.stream.byte(idx)
            kp, W = (d.kp + 1) % N, step_add_g(d.W)
            while W[0] & 255 != want:
                kp = (kp + 1) % N
                W = step_add_g(W)
        else:
            sig, W = sc.sign_kp(self.key, m, d.kp, high_s=True)
            return Derived(d.R0b, sig, W, d.hc, d.k0, d.t, d.kp)
        sig, W = sc.sign_kp(self.key, m, kp)
        return Derived(d.R0b, sig, W, d.hc, d.k0, d.t, kp)


class RefuseOnRDevice(Device):
    """A5, A7, A9: honest derivation, refuses at step 4 unless low bits of r match the stream.

    bits_per_sig is b. The target is Stream.bits(idx * b, b). If budget is not
    None, at most that many refusals are made, then every attempt is accepted.
    """

    label = "refuse_on_r"

    def __init__(self, scheme, key, bits_per_sig=1, budget=None, **kw):
        super().__init__(scheme, key, **kw)
        self.b = bits_per_sig
        self.left = budget
        self.refusals = 0

    def wants(self, derived, idx):
        r = self.scheme.r_int(derived.sig)
        return r & ((1 << self.b) - 1) == self.stream.bits(idx * self.b, self.b)

    def sign(self, m, rho, idx=0):
        d = self.derive(m, rho, idx)
        if self.wants(d, idx):
            return d.sig
        if self.left is not None:
            if self.left <= 0:
                return d.sig
            self.left -= 1
        self.refusals += 1
        return None


class MessageSelectDevice(Device):
    """A8: refuses at step 2 unless the low bit of H(K, m) is the stream bit."""

    label = "message_select"

    def selects(self, m, idx):
        return sha(b"bd/msg-select" + self.K + m)[0] & 1 == self.stream.bit(idx)

    def commit(self, m, hc, idx=0):
        if not self.selects(m, idx):
            return None
        return super().commit(m, hc, idx)

    def sign(self, m, rho, idx=0):
        if not self.selects(m, idx):
            return None
        return super().sign(m, rho, idx)


class KnownRhoDevice(Device):
    """A12, A13: the device can recover rho from hc, so it grinds with the tweak known.

    known maps hc to rho. It is a 16-bit brute-force table for A12 and a list of
    earlier sessions for A13. R0 is ground so the low byte of the final r is the
    stream byte.
    """

    label = "known_rho"

    def __init__(self, scheme, key, known, **kw):
        super().__init__(scheme, key, **kw)
        self.known = known
        self._cache = {}

    def k0(self, m, hc, idx):
        ck = (m, hc, idx)
        if ck in self._cache:
            return self._cache[ck]
        rho = self.known.get(hc)
        if rho is None:
            k0 = self.scheme.k0_honest(self.key, m, hc)
        else:
            sc = self.scheme
            want = self.stream.byte(idx)
            k0 = sc.k0_honest(self.key, m, hc)
            pt = fmul(k0)
            while True:
                t = sc.tweak(ser33(pt), rho)
                W = fmul(k0 + t)
                if W is not None and W[0] & 255 == want:
                    break
                k0 = (k0 + 1) % N
                pt = step_add_g(pt)
        self._cache[ck] = k0
        return k0


class ResamplingDevice(Device):
    """A6: on a retry with the same inputs it derives a different k0 (a silent resample)."""

    label = "resampling"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.attempt = 0

    def retry(self):
        self.attempt += 1

    def k0(self, m, hc, idx):
        return (self.scheme.k0_honest(self.key, m, hc) + self.attempt) % N


class PlainDevice:
    """C1, C2: an ordinary single-step signer with no anti-exfil step."""

    def __init__(self, scheme, key, K, stream=None):
        self.scheme, self.key, self.K = scheme, key, K
        self.stream = stream if stream is not None else Stream(key.sk)

    def known_nonce_sign(self, m):
        kp = shared_nonce(self.K, m)
        sig, _W = self.scheme.sign_kp(self.key, m, kp)
        return sig

    def grinding_sign(self, m, idx):
        want = self.stream.byte(idx)
        kp = shared_nonce(self.K, m)
        W = fmul(kp)
        while W[0] & 255 != want:
            kp = (kp + 1) % N
            W = step_add_g(W)
        sig, _W = self.scheme.sign_kp(self.key, m, kp)
        return sig


# ---------------------------------------------------------------------------
# observers
# ---------------------------------------------------------------------------

def observer_known_k0(scheme, pk, m, sig, K, hc_guess):
    """A1: assume k = k0 or n - k0, k0 = H(K, m, hc_guess), either s branch."""
    return scheme.recover(pk, m, sig, [shared_nonce(K, m, hc_guess)])


def observer_with_rho(scheme, pk, m, sig, K, rho):
    """A10: the observer learns rho and rebuilds the full final nonce."""
    hc = scheme.host_commit(rho)
    k0 = shared_nonce(K, m, hc)
    R0b = ser33(fmul(k0))
    return scheme.recover(pk, m, sig, [(k0 + scheme.tweak(R0b, rho)) % N])


def observer_with_t(scheme, pk, m, sig, K, t):
    """A11: the observer learns only t, and the device's nonce ignores hc."""
    return scheme.recover(pk, m, sig, [(shared_nonce(K, m) + t) % N])


def observer_plain_known_nonce(scheme, pk, m, sig, K):
    """C1: the plain signer used k = H(K, m)."""
    return scheme.recover(pk, m, sig, [shared_nonce(K, m)])


# ---------------------------------------------------------------------------

def selftest():
    """Honest simulated device must reproduce the reference device byte for byte."""
    drbg = Drbg("bd/selftest")
    for sc in SCHEMES:
        key = sc.keypair("selftest/" + sc.name)
        dev = Device(sc, key)
        for _ in range(3):
            m, rho = drbg.read(32), drbg.read(32)
            hc = sc.host_commit(rho)
            if dev.commit(m, hc) != sc.ref_commit(key, m, hc):
                raise RuntimeError("selftest: commit differs from reference for " + sc.name)
            if dev.sign(m, rho) != sc.ref_sign(key, m, rho):
                raise RuntimeError("selftest: signature differs from reference for " + sc.name)
    return True
