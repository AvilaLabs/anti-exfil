"""PSBT (versions 0 and 2) parsing and serialization, signature hashes and the
per-pair analysis that both the host and the signer run.

Variable-time test code. Not for real keys.
"""
import struct

from secp import (N, G, sha256, dsha256, hash160, tagged_hash, int_from, bytes32,
                  pt_add, pt_mul, lift_x, parse33, ser65)


class PsbtError(Exception):
    pass


MAGIC = b"psbt\xff"

# input field types
IN_NON_WITNESS_UTXO = 0x00
IN_WITNESS_UTXO = 0x01
IN_PARTIAL_SIG = 0x02
IN_SIGHASH_TYPE = 0x03
IN_REDEEM_SCRIPT = 0x04
IN_WITNESS_SCRIPT = 0x05
IN_BIP32_DERIVATION = 0x06
IN_FINAL_SCRIPTSIG = 0x07
IN_FINAL_SCRIPTWITNESS = 0x08
IN_PREVIOUS_TXID = 0x0E
IN_OUTPUT_INDEX = 0x0F
IN_SEQUENCE = 0x10
IN_REQ_TIME_LOCKTIME = 0x11
IN_REQ_HEIGHT_LOCKTIME = 0x12
IN_TAP_KEY_SIG = 0x13
IN_TAP_SCRIPT_SIG = 0x14
IN_TAP_LEAF_SCRIPT = 0x15
IN_TAP_BIP32_DERIVATION = 0x16
IN_TAP_INTERNAL_KEY = 0x17
IN_TAP_MERKLE_ROOT = 0x18
IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1A
IN_AE_HOST_COMMITMENT = 0x21
IN_AE_NONCE_COMMITMENT = 0x22
IN_AE_HOST_RANDOMNESS = 0x23
AE_TYPES = (IN_AE_HOST_COMMITMENT, IN_AE_NONCE_COMMITMENT, IN_AE_HOST_RANDOMNESS)
SIG_TYPES = (IN_PARTIAL_SIG, IN_TAP_KEY_SIG, IN_TAP_SCRIPT_SIG)

# global field types
GL_UNSIGNED_TX = 0x00
GL_FALLBACK_LOCKTIME = 0x03
GL_INPUT_COUNT = 0x04
GL_OUTPUT_COUNT = 0x05
GL_TX_MODIFIABLE = 0x06
GL_TX_VERSION = 0x02
GL_VERSION = 0xFB

OUT_AMOUNT = 0x03
OUT_SCRIPT = 0x04

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ACP = 0x80
ECDSA_HASH_TYPES = (1, 2, 3, 0x81, 0x82, 0x83)
BIP340_HASH_TYPES = (0,) + ECDSA_HASH_TYPES


# ---------------------------------------------------------------- bytes helpers
def cs(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


class Reader:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def read(self, n):
        if n < 0 or self.p + n > len(self.d):
            raise PsbtError("truncated")
        b = self.d[self.p:self.p + n]
        self.p += n
        return b

    def cs(self):
        b = self.read(1)[0]
        if b < 0xFD:
            return b
        if b == 0xFD:
            v = struct.unpack("<H", self.read(2))[0]
            lo = 0xFD
        elif b == 0xFE:
            v = struct.unpack("<I", self.read(4))[0]
            lo = 0x10000
        else:
            v = struct.unpack("<Q", self.read(8))[0]
            lo = 0x100000000
        if v < lo:
            raise PsbtError("non-canonical compact size")
        return v

    def eof(self):
        return self.p == len(self.d)


def le32(b):
    if len(b) != 4:
        raise PsbtError("expected 4 bytes")
    return struct.unpack("<I", b)[0]


# ---------------------------------------------------------------- transactions
class CoreTx:
    """version, locktime, inputs [(txid, vout, sequence)], outputs [(amount, spk)]."""

    def __init__(self, version, locktime, ins, outs):
        self.version = version
        self.locktime = locktime
        self.ins = ins
        self.outs = outs

    def key(self):
        return (self.version, self.locktime, tuple(self.ins), tuple(self.outs))

    def ser_out(self, o):
        return struct.pack("<Q", o[0]) + cs(len(o[1])) + o[1]

    def ser_outpoint(self, j):
        return self.ins[j][0] + struct.pack("<I", self.ins[j][1])


def parse_tx(data):
    """Parses a serialized transaction (with or without witness). Returns
    (CoreTx-like info, txid, scriptsigs)."""
    r = Reader(data)
    version = struct.unpack("<I", r.read(4))[0]
    segwit = False
    if len(data) > 5 and data[4] == 0 and data[5] == 1:
        r.read(2)
        segwit = True
    nin = r.cs()
    ins = []
    sigs = []
    for _ in range(nin):
        txid = r.read(32)
        vout = struct.unpack("<I", r.read(4))[0]
        ssig = r.read(r.cs())
        seq = struct.unpack("<I", r.read(4))[0]
        ins.append((txid, vout, seq))
        sigs.append(ssig)
    nout = r.cs()
    outs = []
    for _ in range(nout):
        amt = struct.unpack("<Q", r.read(8))[0]
        spk = r.read(r.cs())
        outs.append((amt, spk))
    if segwit:
        for _ in range(nin):
            for _ in range(r.cs()):
                r.read(r.cs())
    locktime = struct.unpack("<I", r.read(4))[0]
    if not r.eof():
        raise PsbtError("trailing bytes in transaction")
    tx = CoreTx(version, locktime, ins, outs)
    return tx, txid_of(tx, sigs), sigs


def ser_tx_nowit(tx, sigs=None):
    b = struct.pack("<I", tx.version) + cs(len(tx.ins))
    for j, (txid, vout, seq) in enumerate(tx.ins):
        b += txid + struct.pack("<I", vout) + cs(len(sigs[j]) if sigs else 0) + (sigs[j] if sigs else b"")
        b += struct.pack("<I", seq)
    b += cs(len(tx.outs))
    for o in tx.outs:
        b += tx.ser_out(o)
    return b + struct.pack("<I", tx.locktime)


def txid_of(tx, sigs=None):
    return dsha256(ser_tx_nowit(tx, sigs))


def parse_witness_utxo(v):
    r = Reader(v)
    amt = struct.unpack("<Q", r.read(8))[0]
    spk = r.read(r.cs())
    if not r.eof():
        raise PsbtError("bad witness utxo")
    return (amt, spk)


# ---------------------------------------------------------------- PSBT container
class Psbt:
    def __init__(self):
        self.version = 0
        self.glob = []      # list of [key, value]
        self.ins = []
        self.outs = []
        self.tx = None

    # -- parsing
    @staticmethod
    def parse(data):
        if not data.startswith(MAGIC):
            raise PsbtError("bad magic")
        r = Reader(data)
        r.read(5)

        def read_map():
            m = []
            seen = set()
            while True:
                kl = r.cs()
                if kl == 0:
                    return m
                k = r.read(kl)
                v = r.read(r.cs())
                if k in seen:
                    raise PsbtError("duplicate key")
                seen.add(k)
                m.append([k, v])

        ps = Psbt()
        ps.glob = read_map()
        g = dict((bytes(k), v) for k, v in ps.glob)
        ver = g.get(bytes([GL_VERSION]))
        if ver is not None:
            ps.version = le32(ver)
        if ps.version not in (0, 2):
            raise PsbtError("unsupported PSBT version")
        if ps.version == 0:
            if bytes([GL_INPUT_COUNT]) in g or bytes([GL_OUTPUT_COUNT]) in g:
                raise PsbtError("v2 count fields in a v0 PSBT")
            utx = g.get(bytes([GL_UNSIGNED_TX]))
            if utx is None:
                raise PsbtError("no unsigned transaction")
            if len(utx) > 5 and utx[4] == 0 and utx[5] == 1:
                raise PsbtError("unsigned transaction has witness data")
            tx, _, sigs = parse_tx(utx)
            if any(len(s) for s in sigs):
                raise PsbtError("unsigned transaction has scriptSigs")
            ps.tx = tx
            nin, nout = len(tx.ins), len(tx.outs)
        else:
            if bytes([GL_UNSIGNED_TX]) in g:
                raise PsbtError("unsigned transaction in a v2 PSBT")
            for t in (GL_TX_VERSION, GL_INPUT_COUNT, GL_OUTPUT_COUNT):
                if bytes([t]) not in g:
                    raise PsbtError("missing v2 global field %02x" % t)
            nin = Reader(g[bytes([GL_INPUT_COUNT])]).cs()
            nout = Reader(g[bytes([GL_OUTPUT_COUNT])]).cs()
        if nin > 100000 or nout > 100000:
            raise PsbtError("too many inputs or outputs")
        for _ in range(nin):
            ps.ins.append(read_map())
        for _ in range(nout):
            ps.outs.append(read_map())
        if not r.eof():
            raise PsbtError("trailing bytes after PSBT")
        if ps.version == 2:
            ps.tx = ps._build_v2_tx(g)
        return ps

    def _build_v2_tx(self, g):
        version = le32(g[bytes([GL_TX_VERSION])])
        fb = g.get(bytes([GL_FALLBACK_LOCKTIME]))
        fallback = le32(fb) if fb is not None else 0
        ins = []
        time_lock = 0
        height_lock = 0
        for m in self.ins:
            d = dict((bytes(k), v) for k, v in m)
            txid = d.get(bytes([IN_PREVIOUS_TXID]))
            vout = d.get(bytes([IN_OUTPUT_INDEX]))
            if txid is None or len(txid) != 32 or vout is None:
                raise PsbtError("v2 input lacks previous txid or output index")
            sq = d.get(bytes([IN_SEQUENCE]))
            seq = le32(sq) if sq is not None else 0xFFFFFFFF
            ins.append((txid, le32(vout), seq))
            tl = d.get(bytes([IN_REQ_TIME_LOCKTIME]))
            hl = d.get(bytes([IN_REQ_HEIGHT_LOCKTIME]))
            tl = le32(tl) if tl is not None else None
            hl = le32(hl) if hl is not None else None
            if tl is not None and hl is None:
                height_lock = None
                if time_lock is not None:
                    time_lock = max(time_lock, tl)
            elif tl is None and hl is not None:
                time_lock = None
                if height_lock is not None:
                    height_lock = max(height_lock, hl)
            elif tl is not None and hl is not None:
                if time_lock is not None:
                    time_lock = max(time_lock, tl)
                if height_lock is not None:
                    height_lock = max(height_lock, hl)
        if time_lock is None and height_lock is None:
            raise PsbtError("conflicting required locktimes")
        if height_lock is not None and height_lock > 0:
            locktime = height_lock
        elif time_lock is not None and time_lock > 0:
            locktime = time_lock
        else:
            locktime = fallback
        outs = []
        for m in self.outs:
            d = dict((bytes(k), v) for k, v in m)
            a = d.get(bytes([OUT_AMOUNT]))
            s = d.get(bytes([OUT_SCRIPT]))
            if a is None or len(a) != 8 or s is None:
                raise PsbtError("v2 output lacks amount or script")
            outs.append((struct.unpack("<Q", a)[0], s))
        return CoreTx(version, locktime, ins, outs)

    # -- serialization
    def serialize(self):
        b = MAGIC

        def ser_map(m):
            o = b""
            for k, v in m:
                o += cs(len(k)) + k + cs(len(v)) + v
            return o + b"\x00"

        b += ser_map(self.glob)
        for m in self.ins:
            b += ser_map(m)
        for m in self.outs:
            b += ser_map(m)
        return b

    def copy(self):
        c = Psbt()
        c.version = self.version
        c.glob = [[k, v] for k, v in self.glob]
        c.ins = [[[k, v] for k, v in m] for m in self.ins]
        c.outs = [[[k, v] for k, v in m] for m in self.outs]
        c.tx = self.tx
        return c

    def imap(self, i):
        return dict((bytes(k), v) for k, v in self.ins[i])


def mtype(key):
    """Key type of a map key (first byte; all types we care about are one byte)."""
    return key[0]


def map_set(m, key, value):
    for e in m:
        if e[0] == key:
            e[1] = value
            return
    for idx, e in enumerate(m):
        if e[0] > key:
            m.insert(idx, [key, value])
            return
    m.append([key, value])


def map_del_types(m, types):
    m[:] = [e for e in m if e[0][0] not in types]


# ---------------------------------------------------------------- scripts
def parse_script(s):
    """Returns list of (opcode, data_or_None, is_direct_push)."""
    ops = []
    i = 0
    while i < len(s):
        op = s[i]
        i += 1
        n = None
        direct = False
        if 1 <= op <= 0x4B:
            n = op
            direct = True
        elif op == 0x4C:
            if i + 1 > len(s):
                raise PsbtError("truncated script")
            n = s[i]
            i += 1
        elif op == 0x4D:
            if i + 2 > len(s):
                raise PsbtError("truncated script")
            n = int.from_bytes(s[i:i + 2], "little")
            i += 2
        elif op == 0x4E:
            if i + 4 > len(s):
                raise PsbtError("truncated script")
            n = int.from_bytes(s[i:i + 4], "little")
            i += 4
        data = None
        if n is not None:
            if i + n > len(s):
                raise PsbtError("truncated push")
            data = s[i:i + n]
            i += n
        ops.append((op, data, direct))
    return ops


OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CODESEPARATOR = 0xAB
OP_CHECKSIGADD = 0xBA


def is_op_success(op):
    return (op == 80 or op == 98 or 126 <= op <= 129 or 131 <= op <= 134
            or 137 <= op <= 138 or 141 <= op <= 142 or 149 <= op <= 153
            or 187 <= op <= 254)


def check_ecdsa_script(script, key):
    """The device key (33 bytes) must be in the script in a supported form."""
    ops = parse_script(script)
    if any(op == OP_CODESEPARATOR for op, _, _ in ops):
        raise PsbtError("OP_CODESEPARATOR in script code")

    def is_key_push(o):
        return o[2] and o[0] == 0x21

    # exactly <key> OP_CHECKSIG
    if len(ops) == 2 and is_key_push(ops[0]) and ops[1][0] == OP_CHECKSIG:
        if ops[0][1] != key:
            raise PsbtError("script key is not the device key")
        return "single"
    # OP_m <key>... OP_n OP_CHECKMULTISIG
    if (len(ops) >= 4 and 0x51 <= ops[0][0] <= 0x60 and 0x51 <= ops[-2][0] <= 0x60
            and ops[-1][0] == OP_CHECKMULTISIG and all(is_key_push(o) for o in ops[1:-2])):
        m = ops[0][0] - 0x50
        n = ops[-2][0] - 0x50
        keys = [o[1] for o in ops[1:-2]]
        if 1 <= m <= n <= 16 and len(keys) == n and all(parse33(k) is not None for k in keys):
            c = keys.count(key)
            if c != 1:
                raise PsbtError("device key listed %d times in multisig" % c)
            return "multisig"
    # optional: key as a direct push immediately before a signature opcode
    pos = [j for j, o in enumerate(ops) if is_key_push(o) and o[1] == key]
    if len(pos) != 1:
        raise PsbtError("device key not found exactly once as a direct push")
    j = pos[0]
    if j + 1 >= len(ops) or ops[j + 1][0] not in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
        raise PsbtError("device key not directly before a signature opcode")
    return "generic"


def check_tapleaf_script(script, x):
    ops = parse_script(script)
    for op, _, _ in ops:
        if is_op_success(op):
            raise PsbtError("OP_SUCCESSx in leaf script")
        if op == OP_CODESEPARATOR:
            raise PsbtError("OP_CODESEPARATOR in leaf script")
    n = 0
    for j in range(1, len(ops)):
        if ops[j][0] in (OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD):
            p = ops[j - 1]
            if p[2] and p[0] == 0x20 and p[1] == x:
                n += 1
    if n != 1:
        raise PsbtError("leaf script has %d signature opcodes for the device key" % n)


def leaf_hash(ver, script):
    return tagged_hash("TapLeaf", bytes([ver]) + cs(len(script)) + script)


def tap_tweak(x32, merkle):
    return int_from(tagged_hash("TapTweak", x32 + (merkle or b"")))


# ---------------------------------------------------------------- signature hashes
def sighash_legacy(tx, idx, script_code, ht):
    base = ht & 0x1F
    acp = bool(ht & SIGHASH_ACP)
    if base == SIGHASH_SINGLE and idx >= len(tx.outs):
        raise PsbtError("SIGHASH_SINGLE without matching output")
    b = struct.pack("<I", tx.version)
    idxs = [idx] if acp else list(range(len(tx.ins)))
    b += cs(len(idxs))
    for j in idxs:
        b += tx.ser_outpoint(j)
        if j == idx:
            b += cs(len(script_code)) + script_code
            b += struct.pack("<I", tx.ins[j][2])
        else:
            b += b"\x00"
            seq = tx.ins[j][2] if base not in (SIGHASH_NONE, SIGHASH_SINGLE) else 0
            b += struct.pack("<I", seq)
    if base == SIGHASH_NONE:
        b += cs(0)
    elif base == SIGHASH_SINGLE:
        b += cs(idx + 1)
        for j in range(idx):
            b += struct.pack("<Q", 0xFFFFFFFFFFFFFFFF) + b"\x00"
        b += tx.ser_out(tx.outs[idx])
    else:
        b += cs(len(tx.outs))
        for o in tx.outs:
            b += tx.ser_out(o)
    b += struct.pack("<I", tx.locktime) + struct.pack("<I", ht)
    return dsha256(b)


def sighash_bip143(tx, idx, script_code, amount, ht):
    base = ht & 0x1F
    acp = bool(ht & SIGHASH_ACP)
    if base == SIGHASH_SINGLE and idx >= len(tx.outs):
        raise PsbtError("SIGHASH_SINGLE without matching output")
    zero = b"\x00" * 32
    hp = zero if acp else dsha256(b"".join(tx.ser_outpoint(j) for j in range(len(tx.ins))))
    hs = zero if (acp or base in (SIGHASH_SINGLE, SIGHASH_NONE)) else dsha256(
        b"".join(struct.pack("<I", t[2]) for t in tx.ins))
    if base not in (SIGHASH_SINGLE, SIGHASH_NONE):
        ho = dsha256(b"".join(tx.ser_out(o) for o in tx.outs))
    elif base == SIGHASH_SINGLE:
        ho = dsha256(tx.ser_out(tx.outs[idx]))
    else:
        ho = zero
    b = struct.pack("<I", tx.version) + hp + hs + tx.ser_outpoint(idx)
    b += cs(len(script_code)) + script_code + struct.pack("<Q", amount)
    b += struct.pack("<I", tx.ins[idx][2]) + ho + struct.pack("<I", tx.locktime)
    b += struct.pack("<I", ht)
    return dsha256(b)


def sighash_taproot(tx, idx, ht, prevouts, leaf=None):
    """prevouts: list of (amount, spk) for all inputs (entries other than idx may be
    None when ANYONECANPAY). No annex."""
    if ht not in BIP340_HASH_TYPES:
        raise PsbtError("bad taproot sighash type")
    out_type = SIGHASH_ALL if ht == 0 else ht & 3
    acp = bool(ht & SIGHASH_ACP)
    if out_type == SIGHASH_SINGLE and idx >= len(tx.outs):
        raise PsbtError("SIGHASH_SINGLE without matching output")
    m = bytes([0, ht]) + struct.pack("<I", tx.version) + struct.pack("<I", tx.locktime)
    if not acp:
        m += sha256(b"".join(tx.ser_outpoint(j) for j in range(len(tx.ins))))
        m += sha256(b"".join(struct.pack("<Q", p[0]) for p in prevouts))
        m += sha256(b"".join(cs(len(p[1])) + p[1] for p in prevouts))
        m += sha256(b"".join(struct.pack("<I", t[2]) for t in tx.ins))
    if out_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        m += sha256(b"".join(tx.ser_out(o) for o in tx.outs))
    m += bytes([(2 if leaf is not None else 0) + 0])
    if acp:
        p = prevouts[idx]
        m += tx.ser_outpoint(idx) + struct.pack("<Q", p[0]) + cs(len(p[1])) + p[1]
        m += struct.pack("<I", tx.ins[idx][2])
    else:
        m += struct.pack("<I", idx)
    if out_type == SIGHASH_SINGLE:
        m += sha256(tx.ser_out(tx.outs[idx]))
    if leaf is not None:
        m += leaf + b"\x00" + b"\xff\xff\xff\xff"
    return tagged_hash("TapSighash", m)


# ---------------------------------------------------------------- DER
def der_encode(r, s):
    def enc(x):
        b = x.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
        return (b"\x00" + b) if b[0] & 0x80 else b
    rb, sb = enc(r), enc(s)
    return b"\x30" + bytes([len(rb) + len(sb) + 4]) + b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb


def der_parse_strict(sig):
    """BIP66 strict DER with a trailing sighash byte. Returns (r, s, hashtype)."""
    n = len(sig)
    if n < 9 or n > 73:
        raise PsbtError("bad DER length")
    if sig[0] != 0x30 or sig[1] != n - 3:
        raise PsbtError("bad DER header")
    lr = sig[3]
    if 5 + lr >= n:
        raise PsbtError("bad DER R length")
    ls = sig[5 + lr]
    if lr + ls + 7 != n:
        raise PsbtError("bad DER lengths")
    if sig[2] != 0x02 or lr == 0 or sig[4] & 0x80:
        raise PsbtError("bad DER R")
    if lr > 1 and sig[4] == 0 and not sig[5] & 0x80:
        raise PsbtError("padded DER R")
    if sig[4 + lr] != 0x02 or ls == 0 or sig[6 + lr] & 0x80:
        raise PsbtError("bad DER S")
    if ls > 1 and sig[6 + lr] == 0 and not sig[7 + lr] & 0x80:
        raise PsbtError("padded DER S")
    r = int_from(sig[4:4 + lr])
    s = int_from(sig[6 + lr:6 + lr + ls])
    return r, s, sig[-1]


# ---------------------------------------------------------------- TX_MODIFIABLE (BIP 370)
def update_modifiable(ps, ht):
    if ps.version != 2:
        return
    key = bytes([GL_TX_MODIFIABLE])
    cur = None
    for k, v in ps.glob:
        if k == key:
            cur = v
    if cur is not None and len(cur) != 1:
        raise PsbtError("bad PSBT_GLOBAL_TX_MODIFIABLE")
    v = cur[0] if cur is not None else 0
    new = v
    base = SIGHASH_ALL if ht == 0 else ht & 3
    if not ht & SIGHASH_ACP:
        new &= ~1
    if base != SIGHASH_NONE:
        new &= ~2
    if base == SIGHASH_SINGLE:
        new |= 4
    new &= 0xFF
    if cur is not None:
        if new != v:
            map_set(ps.glob, key, bytes([new]))
    elif new != 0:
        map_set(ps.glob, key, bytes([new]))


# ---------------------------------------------------------------- keys
class Keys:
    """Device keys known to a party: 33-byte compressed public keys."""

    def __init__(self, pubs):
        self.pubs = set()
        self.xs = set()
        self.unc = set()
        for p in pubs:
            pt = parse33(p)
            if pt is None:
                raise PsbtError("invalid device key")
            self.pubs.add(bytes(p))
            self.xs.add(bytes(p[1:]))
            self.unc.add(ser65(pt))


# ---------------------------------------------------------------- per-pair analysis
class PairInfo:
    pass


def prev_output(ps, i):
    """Returns (amount, spk, nwu_verified) for input i from the UTXO fields, or None
    if neither is present. Raises on mismatch. Both fields must agree."""
    m = ps.imap(i)
    wu = m.get(bytes([IN_WITNESS_UTXO]))
    nwu = m.get(bytes([IN_NON_WITNESS_UTXO]))
    out = None
    verified = False
    if wu is not None:
        out = parse_witness_utxo(wu)
    if nwu is not None:
        tx, txid, _ = parse_tx(nwu)
        pt, vout, _ = ps.tx.ins[i]
        if txid != pt:
            raise PsbtError("non-witness utxo does not hash to previous txid")
        if vout >= len(tx.outs):
            raise PsbtError("non-witness utxo lacks the output index")
        o = tx.outs[vout]
        if out is not None and out != o:
            raise PsbtError("witness utxo and non-witness utxo disagree")
        out = o
        verified = True
    if out is None:
        return None
    return (out[0], out[1], verified)


def hash_type_for(m, scheme, idx, nouts):
    v = m.get(bytes([IN_SIGHASH_TYPE]))
    if v is None:
        ht = SIGHASH_ALL if scheme == "ecdsa" else 0
    else:
        if len(v) != 4:
            raise PsbtError("bad sighash type length")
        ht = struct.unpack("<I", v)[0]
        if scheme == "ecdsa" and ht == 0:
            raise PsbtError("zero sighash type for ECDSA")
    allowed = ECDSA_HASH_TYPES if scheme == "ecdsa" else BIP340_HASH_TYPES
    if ht not in allowed:
        raise PsbtError("unsupported sighash type %#x" % ht)
    if (ht & 3) == SIGHASH_SINGLE and idx >= nouts:
        raise PsbtError("SIGHASH_SINGLE with no matching output")
    return ht


def sig_present(m, kind, keyid):
    if kind == "ecdsa":
        return bytes([IN_PARTIAL_SIG]) + keyid in m
    if kind == "tr_key":
        return bytes([IN_TAP_KEY_SIG]) in m
    return bytes([IN_TAP_SCRIPT_SIG]) + keyid in m


def tap_spk_ok(spk):
    return len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20


def find_leaves(m_list, lh):
    """TAP_LEAF_SCRIPT entries whose leaf hash is lh: list of (control, script, ver)."""
    res = []
    for k, v in m_list:
        if k[0] == IN_TAP_LEAF_SCRIPT and len(v) >= 1:
            control, script, ver = k[1:], v[:-1], v[-1]
            if leaf_hash(ver, script) == lh:
                res.append((control, script, ver))
    return res


def analyze_pair(ps, i, keyid, keys, signer=False):
    """Validates one pair and computes what the protocol needs. Raises PsbtError."""
    if i >= len(ps.ins):
        raise PsbtError("input index out of range")
    mlist = ps.ins[i]
    m = ps.imap(i)
    if bytes([IN_FINAL_SCRIPTSIG]) in m or bytes([IN_FINAL_SCRIPTWITNESS]) in m:
        raise PsbtError("requested input is final")
    L = len(keyid)
    info = PairInfo()
    info.i = i
    info.keyid = bytes(keyid)
    nouts = len(ps.tx.outs)
    # uncompressed device key in a derivation record
    for k, _ in mlist:
        if k[0] == IN_BIP32_DERIVATION and len(k) == 66 and k[1:] in keys.unc:
            raise PsbtError("uncompressed form of a device key in a derivation record")
    if L == 33:
        info.kind = "ecdsa"
        info.scheme = "ecdsa"
        _analyze_ecdsa(ps, i, m, mlist, info, keys, signer, nouts)
    elif L in (32, 64):
        info.scheme = "bip340"
        info.kind = "tr_key" if L == 32 else "tr_script"
        _analyze_taproot(ps, i, m, mlist, info, keys, signer, nouts)
    else:
        raise PsbtError("bad key identifier length %d" % L)
    return info


def _purpose_check(mlist, info, signer):
    """SHOULD: keep each key to one scheme using the derivation path purpose."""
    if not signer:
        return
    x = info.keyid if info.kind == "ecdsa" else info.keyid[:32]
    for k, v in mlist:
        path = None
        if info.kind == "ecdsa" and k[0] == IN_BIP32_DERIVATION and k[1:] == info.keyid:
            path = v[4:]
        elif info.kind != "ecdsa" and k[0] == IN_TAP_BIP32_DERIVATION and k[1:] == x:
            try:
                r = Reader(v)
                n = r.cs()
                r.read(32 * n)
                r.read(4)
                path = v[r.p:]
            except PsbtError:
                raise PsbtError("bad taproot derivation record")
        if path is None or len(path) < 4 or len(path) % 4:
            continue
        first = struct.unpack("<I", path[:4])[0]
        if first < 0x80000000:
            continue
        purpose = first - 0x80000000
        if info.kind == "ecdsa" and purpose == 86:
            raise PsbtError("derivation purpose 86' used for an ECDSA pair")
        if info.kind != "ecdsa" and purpose in (44, 49, 84):
            raise PsbtError("derivation purpose %d' used for a Taproot pair" % purpose)


def _analyze_ecdsa(ps, i, m, mlist, info, keys, signer, nouts):
    pub = info.keyid
    if parse33(pub) is None:
        raise PsbtError("invalid key identifier")
    if pub not in keys.pubs:
        raise PsbtError("device does not hold the key")
    if sig_present(m, "ecdsa", pub):
        raise PsbtError("pair already has a signature")
    info.ht = hash_type_for(m, "ecdsa", i, nouts)
    info.sigkey = bytes([IN_PARTIAL_SIG]) + pub
    info.pk = pub
    _purpose_check(mlist, info, signer)
    out = prev_output(ps, i)
    if out is None:
        raise PsbtError("missing utxo")
    amount, spk, nwu_ok = out
    nwu = nwu_ok
    h = hash160(pub)
    tx = ps.tx
    legacy = False
    if len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac":
        if not nwu:
            raise PsbtError("legacy spend needs a non-witness utxo")
        if spk[3:23] != h:
            raise PsbtError("P2PKH hash does not match the key")
        legacy = True
        script_code = spk
    elif len(spk) == 22 and spk[:2] == b"\x00\x14":
        if spk[2:] != h:
            raise PsbtError("P2WPKH hash does not match the key")
        script_code = b"\x76\xa9\x14" + h + b"\x88\xac"
    elif len(spk) == 34 and spk[:2] == b"\x00\x20":
        ws = m.get(bytes([IN_WITNESS_SCRIPT]))
        if ws is None or sha256(ws) != spk[2:]:
            raise PsbtError("witness script missing or mismatched")
        check_ecdsa_script(ws, pub)
        script_code = ws
    elif len(spk) == 23 and spk[:2] == b"\xa9\x14" and spk[22] == 0x87:
        rs = m.get(bytes([IN_REDEEM_SCRIPT]))
        if rs is None or hash160(rs) != spk[2:22]:
            raise PsbtError("redeem script missing or mismatched")
        if len(rs) == 22 and rs[:2] == b"\x00\x14":
            if rs[2:] != h:
                raise PsbtError("P2SH-P2WPKH hash does not match the key")
            script_code = b"\x76\xa9\x14" + h + b"\x88\xac"
        elif len(rs) == 34 and rs[:2] == b"\x00\x20":
            ws = m.get(bytes([IN_WITNESS_SCRIPT]))
            if ws is None or sha256(ws) != rs[2:]:
                raise PsbtError("witness script missing or mismatched")
            check_ecdsa_script(ws, pub)
            script_code = ws
        else:
            if not nwu:
                raise PsbtError("legacy spend needs a non-witness utxo")
            check_ecdsa_script(rs, pub)
            legacy = True
            script_code = rs
    else:
        raise PsbtError("unsupported script type")
    if legacy:
        info.m = sighash_legacy(tx, i, script_code, info.ht)
        info.spend = "legacy"
    else:
        info.m = sighash_bip143(tx, i, script_code, amount, info.ht)
        info.spend = "segwit"
    info.script_code = script_code


def _analyze_taproot(ps, i, m, mlist, info, keys, signer, nouts):
    x = info.keyid[:32]
    if x not in keys.xs:
        raise PsbtError("device does not hold the key")
    if lift_x(int_from(x)) is None:
        raise PsbtError("invalid x-only key")
    if sig_present(m, info.kind, info.keyid):
        raise PsbtError("pair already has a signature")
    info.ht = hash_type_for(m, "bip340", i, nouts)
    _purpose_check(mlist, info, signer)
    out = prev_output(ps, i)
    if out is None:
        raise PsbtError("missing utxo")
    amount, spk, _ = out
    if not tap_spk_ok(spk):
        raise PsbtError("not a Taproot output")
    Q = spk[2:]
    internal = m.get(bytes([IN_TAP_INTERNAL_KEY]))
    if internal is not None and len(internal) != 32:
        raise PsbtError("bad internal key")
    merkle = m.get(bytes([IN_TAP_MERKLE_ROOT]))
    if merkle is not None and len(merkle) != 32:
        raise PsbtError("bad merkle root")
    internals = set()
    if internal is not None:
        internals.add(internal)
    leaf = None
    if info.kind == "tr_key":
        if internal is not None and internal != x:
            raise PsbtError("key identifier differs from the internal key")
        Ipt = lift_x(int_from(x))
        tw = tap_tweak(x, merkle)
        if tw >= N:
            raise PsbtError("tweak out of range")
        Qpt = pt_add(Ipt, pt_mul(tw, G))
        if Qpt is None or bytes32(Qpt[0]) != Q:
            raise PsbtError("internal key does not tweak to the output key")
        info.pk = Q
        info.internal = x
        info.merkle = merkle
        info.sigkey = bytes([IN_TAP_KEY_SIG])
        internals.add(x)
    else:
        lh = info.keyid[32:]
        found = find_leaves(mlist, lh)
        if len(found) != 1:
            raise PsbtError("%d leaf script entries match the leaf hash" % len(found))
        control, script, ver = found[0]
        if ver != 0xC0:
            raise PsbtError("leaf version is not 0xC0")
        if len(control) < 33 or (len(control) - 33) % 32 or (len(control) - 33) // 32 > 128:
            raise PsbtError("bad control block length")
        if control[0] & 0xFE != 0xC0:
            raise PsbtError("control block leaf version is not 0xC0")
        ip = control[1:33]
        Ipt = lift_x(int_from(ip))
        if Ipt is None:
            raise PsbtError("invalid control block internal key")
        k = lh
        for j in range(33, len(control), 32):
            node = control[j:j + 32]
            a, b = (k, node) if k < node else (node, k)
            k = tagged_hash("TapBranch", a + b)
        tw = tap_tweak(ip, k)
        if tw >= N:
            raise PsbtError("tweak out of range")
        Qpt = pt_add(Ipt, pt_mul(tw, G))
        if Qpt is None or bytes32(Qpt[0]) != Q or (Qpt[1] & 1) != (control[0] & 1):
            raise PsbtError("control block does not compute the output key")
        check_tapleaf_script(script, x)
        info.pk = x
        info.sigkey = bytes([IN_TAP_SCRIPT_SIG]) + info.keyid
        info.leaf_script = script
        info.leaf_hash = lh
        leaf = lh
        internals.add(ip)
    # MuSig2 participants
    for k, v in mlist:
        if k[0] == IN_MUSIG2_PARTICIPANT_PUBKEYS:
            if len(k) != 34 or len(v) % 33:
                raise PsbtError("malformed MuSig2 participant field")
            for j in range(0, len(v), 33):
                if v[j + 1:j + 33] in keys.xs:
                    raise PsbtError("MuSig2 participant list holds a device key")
            if k[1:34][1:] in internals:
                raise PsbtError("internal key is a MuSig2 aggregate key")
    # prevouts
    if info.ht & SIGHASH_ACP:
        prevouts = [None] * len(ps.tx.ins)
        prevouts[i] = (amount, spk)
    else:
        prevouts = []
        for j in range(len(ps.tx.ins)):
            o = prev_output(ps, j)
            if o is None:
                raise PsbtError("input %d lacks a previous output" % j)
            prevouts.append((o[0], o[1]))
    info.m = sighash_taproot(ps.tx, i, info.ht, prevouts, leaf)


def known_amounts(ps):
    """Returns (total_in or None, total_out, all_nwu_verified)."""
    total = 0
    allknown = True
    allverified = True
    for j in range(len(ps.ins)):
        try:
            o = prev_output(ps, j)
        except PsbtError:
            o = None
        if o is None:
            allknown = False
            allverified = False
        else:
            total += o[0]
            if not o[2]:
                allverified = False
    tout = sum(o[0] for o in ps.tx.outs)
    return (total if allknown else None), tout, allverified


def check_request_level(ps, infos):
    """Checks shared by host and signer after the per-pair analysis. Returns
    (fee or None, fee_verified)."""
    per_input = {}
    for p in infos:
        per_input.setdefault(p.i, set()).add(p.kind)
    for i, kinds in per_input.items():
        if "tr_key" in kinds and "tr_script" in kinds:
            raise PsbtError("input %d has both a key-path and a script-path pair" % i)
    total_in, total_out, all_verified = known_amounts(ps)
    fee = None
    if total_in is not None:
        if total_out > total_in:
            raise PsbtError("outputs exceed inputs")
        fee = total_in - total_out
    verified = all_verified or any(
        p.scheme == "bip340" and not (p.ht & SIGHASH_ACP) for p in infos)
    return fee, verified
