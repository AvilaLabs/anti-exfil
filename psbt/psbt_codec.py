"""PSBT v0 and v2 map codec for the reference host and signer.

NOT FOR PRODUCTION. Maps are dicts from key bytes (type byte plus key data) to
value bytes, so comparison is by key and independent of order. Serialization
sorts keys, which makes output reproducible. Fields 0x21, 0x22 and 0x23 are
anti-exfil fields only in input maps; in global and output maps they are
ordinary unknown fields.

Validation here is structural: magic, version 0 or 2, duplicate keys, trailing
bytes, the key data length (and where a BIP fixes it the value length) of every
field BIPs 174, 370 and 371 define, the fields BIP 370 reserves for version 2,
and the fields needed to read the core transaction. Stricter general PSBT
validation is not applied (the PSBT document allows that, if stated).
"""
import hashlib
import struct
from collections import namedtuple

MAGIC = b"psbt\xff"
AE_HC, AE_R0, AE_RHO = 0x21, 0x22, 0x23
AE_TYPES = (AE_HC, AE_R0, AE_RHO)

MAX_INPUTS = 10000     # caps are allowed by the PSBT document; exceeding one fails
MAX_OUTPUTS = 10000
MAX_PSBT_BYTES = 8 * 1024 * 1024


class PsbtError(ValueError):
    """Structural PSBT failure. `code` names the rule."""

    def __init__(self, code, msg=None):
        super().__init__("%s: %s" % (code, msg or code))
        self.code = code


def sha256(b):
    return hashlib.sha256(b).digest()


def dsha(b):
    return sha256(sha256(b))


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def read_compact(b, o):
    if o >= len(b):
        raise PsbtError("truncated_compact", "truncated CompactSize")
    x = b[o]
    o += 1
    if x < 253:
        return x, o
    z = {253: 2, 254: 4, 255: 8}[x]
    if o + z > len(b):
        raise PsbtError("truncated_compact", "truncated CompactSize")
    n = int.from_bytes(b[o:o + z], "little")
    if n < (253 if z == 2 else 0x10000 if z == 4 else 0x100000000):
        raise PsbtError("nonminimal_compact", "non-minimal CompactSize")
    return n, o + z


def read_blob(b, o):
    n, o = read_compact(b, o)
    if n > len(b) - o:
        raise PsbtError("truncated_blob", "blob past end")
    return b[o:o + n], o + n


def blob(b):
    return compact(len(b)) + b


# ------------------------------------------------------------- transactions
# A transaction is (version, inputs, outputs, locktime). An input is
# (prev_txid_internal_order, vout, script_sig, sequence); an output is
# (value, script_pubkey). Witnesses are not kept; they never enter a sighash.
Tx = namedtuple("Tx", "version ins outs locktime")


def ser_tx(tx):
    b = struct.pack("<I", tx.version) + compact(len(tx.ins))
    for h, i, s, q in tx.ins:
        b += h + struct.pack("<I", i) + blob(s) + struct.pack("<I", q)
    b += compact(len(tx.outs))
    for v, s in tx.outs:
        b += struct.pack("<Q", v) + blob(s)
    return b + struct.pack("<I", tx.locktime)


def parse_tx(b):
    """Parse a transaction, with or without witness data. Returns a Tx."""
    if len(b) < 10:
        raise PsbtError("short_tx", "short transaction")
    o = 4
    version = struct.unpack("<I", b[:4])[0]
    witness = b[o:o + 2] == b"\x00\x01"
    if witness:
        o += 2
    ni, o = read_compact(b, o)
    if ni > MAX_INPUTS:
        raise PsbtError("cap_exceeded", "too many inputs")
    ins = []
    for _ in range(ni):
        if o + 36 > len(b):
            raise PsbtError("bad_tx", "truncated input")
        h = b[o:o + 32]
        i = struct.unpack("<I", b[o + 32:o + 36])[0]
        s, o = read_blob(b, o + 36)
        if o + 4 > len(b):
            raise PsbtError("bad_tx", "truncated input")
        q = struct.unpack("<I", b[o:o + 4])[0]
        o += 4
        ins.append((h, i, s, q))
    no, o = read_compact(b, o)
    if no > MAX_OUTPUTS:
        raise PsbtError("cap_exceeded", "too many outputs")
    outs = []
    for _ in range(no):
        if o + 8 > len(b):
            raise PsbtError("bad_tx", "truncated output")
        v = struct.unpack("<Q", b[o:o + 8])[0]
        s, o = read_blob(b, o + 8)
        outs.append((v, s))
    if witness:
        for _ in range(ni):
            c, o = read_compact(b, o)
            for _ in range(c):
                _, o = read_blob(b, o)
    if o + 4 != len(b):
        raise PsbtError("bad_tx", "invalid transaction serialization")
    return Tx(version, ins, outs, struct.unpack("<I", b[o:o + 4])[0])


def txid(tx):
    return dsha(ser_tx(tx))


# -------------------------------------------------------------------- maps
def _parse_map(b, o):
    m = {}
    while True:
        k, o = read_blob(b, o)
        if not k:
            return m, o
        if k[0] >= 0xFD:
            read_compact(k, 0)      # a key type is a CompactSize; a non-minimal one fails here
        v, o = read_blob(b, o)
        if k in m:
            raise PsbtError("duplicate_key", "duplicate PSBT key")
        m[k] = v


def _ser_map(m):
    return b"".join(blob(k) + blob(m[k]) for k in sorted(m)) + b"\x00"


class Psbt:
    """version, glob (dict), inputs (list of dict), outputs (list of dict)."""

    def __init__(self, version, glob, inputs, outputs):
        self.version = version
        self.glob = glob
        self.inputs = inputs
        self.outputs = outputs

    def clone(self):
        return Psbt(self.version, dict(self.glob), [dict(m) for m in self.inputs],
                    [dict(m) for m in self.outputs])

    def serialize(self):
        return (MAGIC + _ser_map(self.glob) + b"".join(_ser_map(m) for m in self.inputs)
                + b"".join(_ser_map(m) for m in self.outputs))


def parse(data):
    if not isinstance(data, (bytes, bytearray)):
        raise PsbtError("not_bytes")
    data = bytes(data)
    if len(data) > MAX_PSBT_BYTES:
        raise PsbtError("cap_exceeded", "PSBT too large")
    if not data.startswith(MAGIC):
        raise PsbtError("bad_magic", "invalid PSBT magic")
    g, o = _parse_map(data, len(MAGIC))
    vb = g.get(b"\xfb", b"\x00\x00\x00\x00")
    if len(vb) != 4:
        raise PsbtError("bad_version", "bad PSBT version field")
    version = int.from_bytes(vb, "little")
    if version not in (0, 2):
        raise PsbtError("unsupported_version", "PSBT version %d" % version)
    if version == 0:
        raw = g.get(b"\x00")
        if raw is None:
            raise PsbtError("missing_tx", "missing unsigned transaction")
        tx = parse_tx(raw)
        if any(a[2] for a in tx.ins):
            raise PsbtError("bad_tx", "unsigned transaction has a scriptSig")
        if raw[4:6] == b"\x00\x01":
            raise PsbtError("bad_tx", "unsigned transaction has witness serialization")
        ni, no = len(tx.ins), len(tx.outs)
    else:
        def count(key):
            raw = g.get(key)
            if raw is None:
                raise PsbtError("missing_count", "missing v2 count")
            n, end = read_compact(raw, 0)
            if end != len(raw):
                raise PsbtError("bad_count", "bad v2 count")
            return n
        ni, no = count(b"\x04"), count(b"\x05")
        if b"\x06" in g and len(g[b"\x06"]) != 1:
            raise PsbtError("bad_modifiable", "bad TX_MODIFIABLE")
        if ni > MAX_INPUTS or no > MAX_OUTPUTS:
            raise PsbtError("cap_exceeded", "too many inputs or outputs")
        if b"\x00" in g:
            raise PsbtError("bad_v2", "v2 PSBT holds the v0 unsigned transaction")
    ins, outs = [], []
    for _ in range(ni):
        m, o = _parse_map(data, o)
        ins.append(m)
    for _ in range(no):
        m, o = _parse_map(data, o)
        outs.append(m)
    if o != len(data):
        raise PsbtError("trailing_bytes", "trailing PSBT bytes")
    check_shapes(version, g, ins, outs)
    p = Psbt(version, g, ins, outs)
    core_tx(p)      # fail now if the core transaction cannot be read
    return p


def core_tx(p):
    """The core transaction: from the v0 unsigned tx or built from v2 fields."""
    if p.version == 0:
        return parse_tx(p.glob[b"\x00"])
    ver, fb = p.glob.get(b"\x02"), p.glob.get(b"\x03")
    if ver is None or len(ver) != 4 or (fb is not None and len(fb) != 4):
        raise PsbtError("bad_v2_tx", "bad v2 transaction fields")
    ins, height, times = [], [], []
    for m in p.inputs:
        h, ix, q = m.get(b"\x0e"), m.get(b"\x0f"), m.get(b"\x10", b"\xff" * 4)
        if h is None or len(h) != 32 or ix is None or len(ix) != 4 or len(q) != 4:
            raise PsbtError("bad_v2_input", "bad v2 input")
        hv, tv = m.get(b"\x12"), m.get(b"\x11")
        if hv is not None:
            n = int.from_bytes(hv, "little")
            if len(hv) != 4 or not 0 < n < 500000000:
                raise PsbtError("bad_v2_input", "bad required height locktime")
            height.append(n)
        if tv is not None:
            n = int.from_bytes(tv, "little")
            if len(tv) != 4 or n < 500000000:
                raise PsbtError("bad_v2_input", "bad required time locktime")
            times.append(n)
        ins.append((h, int.from_bytes(ix, "little"), b"", int.from_bytes(q, "little")))
    if height or times:
        h_ok = bool(height) and all(m.get(b"\x11") is None or m.get(b"\x12") is not None for m in p.inputs)
        t_ok = bool(times) and all(m.get(b"\x12") is None or m.get(b"\x11") is not None for m in p.inputs)
        if not h_ok and not t_ok:
            raise PsbtError("bad_v2_input", "incompatible required locktime types")
        lock = max(height) if h_ok else max(times)
    else:
        lock = int.from_bytes(fb, "little") if fb is not None else 0
    outs = []
    for m in p.outputs:
        v, s = m.get(b"\x03"), m.get(b"\x04")
        if v is None or len(v) != 8 or s is None:
            raise PsbtError("bad_v2_output", "bad v2 output")
        outs.append((int.from_bytes(v, "little"), s))
    return Tx(int.from_bytes(ver, "little"), ins, outs, lock)


# ------------------------------------------------------- field shapes
# Key data lengths (and value lengths where the BIP fixes them) from BIP 174, BIP 370 and BIP 371, by key type. An entry is
# (allowed key data lengths, allowed value lengths or None). Types not listed, including the anti-exfil types in input maps,
# are not checked. Value contents are not checked here.
_K0 = (0,)
_PUB = (33, 65)
_SIG = (64, 65)
_IN_SHAPES = {
    0x00: (_K0, None), 0x01: (_K0, None), 0x02: (_PUB, None), 0x03: (_K0, None), 0x04: (_K0, None), 0x05: (_K0, None),
    0x06: (_PUB, None), 0x07: (_K0, None), 0x08: (_K0, None),
    0x0a: ((20,), None), 0x0b: ((32,), None), 0x0c: ((20,), None), 0x0d: ((32,), None),
    0x0e: (_K0, None), 0x0f: (_K0, None), 0x10: (_K0, None), 0x11: (_K0, None), 0x12: (_K0, None),
    0x13: (_K0, _SIG), 0x14: ((64,), _SIG), 0x16: ((32,), None), 0x17: (_K0, (32,)), 0x18: (_K0, (32,)),
}
_OUT_SHAPES = {0x00: (_K0, None), 0x01: (_K0, None), 0x02: (_PUB, None), 0x03: (_K0, None), 0x04: (_K0, None),
               0x05: (_K0, (32,)), 0x06: (_K0, None), 0x07: ((32,), None)}
_GLOBAL_SHAPES = {0x00: (_K0, None), 0x01: ((78,), None), 0x02: (_K0, None), 0x03: (_K0, None), 0x04: (_K0, None),
                  0x05: (_K0, None), 0x06: (_K0, None), 0xfb: (_K0, None)}
# BIP 370: fields that belong to PSBT version 2 only
_V2_ONLY = ({0x02, 0x03, 0x04, 0x05, 0x06}, set(range(0x0e, 0x13)), {0x03, 0x04})       # global, input, output
_CODES = {(0x18, "value"): "bad_merkle_root"}        # codes the spend layer used before this check moved here


def _check_map(m, shapes, v2_only, where, version):
    for k, v in m.items():
        t = k[0]
        if t >= 0xFD:
            continue
        if version == 0 and t in v2_only:
            raise PsbtError("v2_field_in_v0", "%s field %#04x is defined for PSBT version 2 only" % (where, t))
        if where.startswith("input") and t == 0x15:
            n = len(k) - 1
            if n < 33 or (n - 33) % 32:
                raise PsbtError("tap_control_block", "%s field 0x15 has control block length %d" % (where, n))
            if (n - 33) // 32 > 128:
                raise PsbtError("tap_control_depth", "%s field 0x15 has more than 128 control block path elements" % where)
            continue
        shape = shapes.get(t)
        if shape is None:
            continue
        if len(k) - 1 not in shape[0]:
            raise PsbtError(_CODES.get((t, "key"), "bad_key_data"), "%s field %#04x has key data of length %d" % (where, t, len(k) - 1))
        if shape[1] is not None and len(v) not in shape[1]:
            raise PsbtError(_CODES.get((t, "value"), "bad_value_length"), "%s field %#04x has value of length %d" % (where, t, len(v)))


def check_shapes(version, glob, inputs, outputs):
    """Fail on a known field of the wrong shape, or a version 2 field in a version 0 PSBT."""
    _check_map(glob, _GLOBAL_SHAPES, _V2_ONLY[0], "global", version)
    for i, m in enumerate(inputs):
        _check_map(m, _IN_SHAPES, _V2_ONLY[1], "input %d" % i, version)
    for i, m in enumerate(outputs):
        _check_map(m, _OUT_SHAPES, _V2_ONLY[2], "output %d" % i, version)


def ae_entries(m):
    """Anti-exfil fields of one input map: list of (type, key_identifier, value)."""
    return [(k[0], k[1:], v) for k, v in m.items() if k and k[0] in AE_TYPES]


def strip_ae(m):
    return {k: v for k, v in m.items() if not (k and k[0] in AE_TYPES)}


# BIP 370 flag updates (PSBT_GLOBAL_TX_MODIFIABLE is global type 0x06, one byte)
def apply_modifiable_update(glob, sighash):
    """Apply the flag update for one signature to a global map, in place.

    Bit 0 inputs modifiable, bit 1 outputs modifiable, bit 2 has SIGHASH_SINGLE.
    SIGHASH_DEFAULT counts as SIGHASH_ALL. An absent field is zero and is created
    only if the update leaves a flag set.
    """
    cur = glob.get(b"\x06")
    if cur is not None and len(cur) != 1:
        raise PsbtError("bad_modifiable", "bad TX_MODIFIABLE")
    f = cur[0] if cur is not None else 0
    base = 1 if sighash == 0 else sighash & 3
    if not sighash & 0x80:
        f &= ~1
    if base != 2:
        f &= ~2
    if base == 3:
        f |= 4
    if f or cur is not None:
        glob[b"\x06"] = bytes([f & 0xFF])
