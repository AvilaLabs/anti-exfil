"""Script classification, signature hashes and pair resolution.

NOT FOR PRODUCTION. Shared by host and signer: both resolve a pair from the
same PSBT data under the same rules. Every refusal raises SpendError with a
distinct `code`, so a test can assert which rule fired.

Rules implemented here are those of spec/bip-anti-exfil-psbt.md "Spends",
"Sighash types" and "Validation scope".
"""
import hashlib
import struct
from collections import namedtuple

import anti_exfil as AE
import psbt_codec as C

SIGHASH_DEFAULT, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ACP = 0, 1, 2, 3, 0x80
ECDSA_TYPES = (1, 2, 3, 0x81, 0x82, 0x83)
BIP340_TYPES = (0,) + ECDSA_TYPES

MAX_SCRIPT = 10000          # caps are allowed; exceeding one fails
MAX_PAIRS = 1000
MAX_MULTISIG_KEYS = 16

OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD = 0xAC, 0xAD, 0xBA
OP_CHECKMULTISIG, OP_CODESEPARATOR = 0xAE, 0xAB
OP_SUCCESS = set([80, 98] + list(range(126, 130)) + list(range(131, 135)) + [137, 138, 141, 142]
                 + list(range(149, 154)) + list(range(187, 255)))


class SpendError(ValueError):
    def __init__(self, code, msg=None):
        super().__init__("%s: %s" % (code, msg or code))
        self.code = code


def hash160(b):
    return hashlib.new("ripemd160", C.sha256(b)).digest()


def tagged(tag, b):
    t = C.sha256(tag.encode())
    return C.sha256(t + t + b)


# ------------------------------------------------------------------ scripts
def parse_script(s):
    """List of (opcode, pushed_data_or_None). Raises on a truncated push."""
    if len(s) > MAX_SCRIPT:
        raise SpendError("cap_exceeded", "script too long")
    out, i = [], 0
    while i < len(s):
        op = s[i]
        i += 1
        if 1 <= op <= 75:
            n = op
        elif op in (0x4C, 0x4D, 0x4E):
            w = {0x4C: 1, 0x4D: 2, 0x4E: 4}[op]
            if i + w > len(s):
                raise SpendError("bad_script", "truncated pushdata length")
            n = int.from_bytes(s[i:i + w], "little")
            i += w
        else:
            out.append((op, None))
            continue
        if i + n > len(s):
            raise SpendError("bad_script", "truncated push")
        out.append((op, s[i:i + n]))
        i += n
    return out


def _no_codesep(ops):
    if any(op == OP_CODESEPARATOR and d is None for op, d in ops):
        raise SpendError("codeseparator", "script code contains OP_CODESEPARATOR")


def _small_int(op):
    return op - 0x50 if 0x51 <= op <= 0x60 else None


def ecdsa_script_check(script, key, optional_forms):
    """Accept `script` for a pair on `key` (33 bytes) or raise SpendError.

    Required: `<K> OP_CHECKSIG`, and standard m-of-n OP_CHECKMULTISIG of 33-byte
    keys. Optional: another script in which exactly one OP_CHECKSIG or
    OP_CHECKSIGVERIFY is immediately preceded by a direct push of the key.
    """
    ops = parse_script(script)
    _no_codesep(ops)
    if len(ops) == 2 and ops[0][0] == 33 and ops[0][1] == key and ops[1][0] == OP_CHECKSIG:
        return "single"
    if len(ops) >= 4 and ops[-1][0] == OP_CHECKMULTISIG:
        m, n = _small_int(ops[0][0]), _small_int(ops[-2][0])
        keys = ops[1:-2]
        if (m is not None and n is not None and 1 <= m <= n <= MAX_MULTISIG_KEYS and len(keys) == n
                and all(op == 33 and len(d) == 33 and AE._parse33(d) is not AE._INF for op, d in keys)):
            hits = sum(1 for _, d in keys if d == key)
            if hits == 1:
                return "multisig"
            raise SpendError("key_not_in_script" if hits == 0 else "key_ambiguous",
                             "key appears %d times in the multisig" % hits)
    if not optional_forms:
        raise SpendError("unsupported_script", "script is not a required form")
    if not any(d == key for _, d in ops):
        raise SpendError("key_not_in_script", "key is not pushed in the script")
    direct = [i for i, (op, d) in enumerate(ops) if op == 33 and d == key and i + 1 < len(ops)
              and ops[i + 1][0] in (OP_CHECKSIG, OP_CHECKSIGVERIFY)]
    if len(direct) != 1:
        raise SpendError("key_ambiguous", "key is not a direct push before exactly one signature opcode")
    return "other"


def tap_leaf_hash(version, script):
    return tagged("TapLeaf", bytes([version]) + C.compact(len(script)) + script)


def tap_leaf_check(script, key):
    """Exactly one sigop preceded by a 32-byte direct push of `key`; no OP_SUCCESSx; no codesep."""
    ops = parse_script(script)
    if any(op in OP_SUCCESS and d is None for op, d in ops):
        raise SpendError("op_success", "leaf contains OP_SUCCESSx")
    _no_codesep(ops)
    n = sum(1 for i in range(1, len(ops))
            if ops[i][0] in (OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD)
            and ops[i - 1][0] == 32 and ops[i - 1][1] == key)
    if n != 1:
        raise SpendError("tap_mapping", "key maps to %d signature opcodes in the leaf" % n)


# ------------------------------------------------------------------- points
def lift_xonly(x32):
    if len(x32) != 32:
        raise SpendError("bad_key", "x-only key length")
    p = AE._lift_x(int.from_bytes(x32, "big"))
    if p is None:
        raise SpendError("bad_key", "x-only key is not on the curve")
    return p


def tap_tweak(internal, root):
    t = int.from_bytes(tagged("TapTweak", internal + root), "big")
    if t >= AE._N:
        raise SpendError("bad_tweak", "tap tweak out of range")
    return t


def tweaked_xonly(internal, root):
    """Return (tweak, output key x-only 32, output key parity)."""
    t = tap_tweak(internal, root)
    q = AE._add(lift_xonly(internal), AE._mul(t))
    if q is None:
        raise SpendError("bad_tweak", "tweaked key is infinity")
    return t, AE._b32(q[0]), q[1] & 1


def control_root(control, leaf_hash):
    root = leaf_hash
    for j in range(33, len(control), 32):
        node = control[j:j + 32]
        root = tagged("TapBranch", min(root, node) + max(root, node))
    return root


# ---------------------------------------------------------------- sighashes
def legacy_sighash(tx, idx, script, h):
    base, anyone = h & 3, h & 0x80
    if base == 3 and idx >= len(tx.outs):
        raise SpendError("sighash_single_no_output", "SIGHASH_SINGLE without a matching output")
    ins = []
    for j in ([idx] if anyone else range(len(tx.ins))):
        a = tx.ins[j]
        seq = a[3] if j == idx or base not in (2, 3) else 0
        ins.append((a[0], a[1], script if j == idx else b"", seq))
    outs = tx.outs
    if base == 2:
        outs = []
    elif base == 3:
        outs = [(0xFFFFFFFFFFFFFFFF, b"")] * idx + [outs[idx]]
    return C.dsha(C.ser_tx(C.Tx(tx.version, ins, outs, tx.locktime)) + struct.pack("<I", h))


def bip143_sighash(tx, idx, script, value, h):
    base, anyone, zero = h & 3, h & 0x80, b"\x00" * 32
    if base == 3 and idx >= len(tx.outs):
        raise SpendError("sighash_single_no_output", "SIGHASH_SINGLE without a matching output")
    hp = zero if anyone else C.dsha(b"".join(a[0] + struct.pack("<I", a[1]) for a in tx.ins))
    hs = zero if anyone or base in (2, 3) else C.dsha(b"".join(struct.pack("<I", a[3]) for a in tx.ins))
    ho = zero if base in (2, 3) else C.dsha(b"".join(struct.pack("<Q", v) + C.blob(s) for v, s in tx.outs))
    if base == 3:
        ho = C.dsha(struct.pack("<Q", tx.outs[idx][0]) + C.blob(tx.outs[idx][1]))
    a = tx.ins[idx]
    pre = (struct.pack("<I", tx.version) + hp + hs + a[0] + struct.pack("<I", a[1]) + C.blob(script)
           + struct.pack("<Q", value) + struct.pack("<I", a[3]) + ho + struct.pack("<I", tx.locktime)
           + struct.pack("<I", h))
    return C.dsha(pre)


def tap_sighash(tx, idx, prevouts, h, leaf_hash=None):
    """BIP341/342 signature hash with no annex. prevouts[j] = (value, spk) or None if unneeded."""
    base, anyone = (0 if h == 0 else h & 3), bool(h & 0x80)
    if base == 3 and idx >= len(tx.outs):
        raise SpendError("sighash_single_no_output", "SIGHASH_SINGLE without a matching output")
    ext = 1 if leaf_hash is not None else 0
    m = bytes([h]) + struct.pack("<I", tx.version) + struct.pack("<I", tx.locktime)
    if not anyone:
        m += C.sha256(b"".join(a[0] + struct.pack("<I", a[1]) for a in tx.ins))
        m += C.sha256(b"".join(struct.pack("<Q", p[0]) for p in prevouts))
        m += C.sha256(b"".join(C.blob(p[1]) for p in prevouts))
        m += C.sha256(b"".join(struct.pack("<I", a[3]) for a in tx.ins))
    if base not in (2, 3):
        m += C.sha256(b"".join(struct.pack("<Q", v) + C.blob(s) for v, s in tx.outs))
    m += bytes([ext * 2])
    if anyone:
        a, p = tx.ins[idx], prevouts[idx]
        m += a[0] + struct.pack("<I", a[1]) + struct.pack("<Q", p[0]) + C.blob(p[1]) + struct.pack("<I", a[3])
    else:
        m += struct.pack("<I", idx)
    if base == 3:
        m += C.sha256(struct.pack("<Q", tx.outs[idx][0]) + C.blob(tx.outs[idx][1]))
    if leaf_hash is not None:
        m += leaf_hash + b"\x00" + b"\xff" * 4
    return tagged("TapSighash", b"\x00" + m)


# -------------------------------------------------------------------- UTXOs
def txout_of(p, j, tx=None):
    """(value, script, nonwitness_verified) for input j. Fails on missing or mismatched UTXO data."""
    tx = tx or C.core_tx(p)
    m = p.inputs[j]
    h, ix = tx.ins[j][0], tx.ins[j][1]
    cand, verified = None, False
    nw = m.get(b"\x00")
    if nw is not None:
        pt = C.parse_tx(nw)
        if C.txid(pt) != h:
            raise SpendError("nonwitness_txid_mismatch", "NON_WITNESS_UTXO does not hash to the previous txid")
        if ix >= len(pt.outs):
            raise SpendError("nonwitness_index", "NON_WITNESS_UTXO has no such output index")
        cand, verified = pt.outs[ix], True
    w = m.get(b"\x01")
    if w is not None:
        if len(w) < 9:
            raise SpendError("bad_witness_utxo", "bad WITNESS_UTXO")
        val = struct.unpack("<Q", w[:8])[0]
        try:
            sc, o = C.read_blob(w, 8)
        except C.PsbtError:
            raise SpendError("bad_witness_utxo", "bad WITNESS_UTXO")
        if o != len(w):
            raise SpendError("bad_witness_utxo", "bad WITNESS_UTXO")
        if cand is not None and cand != (val, sc):
            raise SpendError("utxo_disagree", "WITNESS_UTXO and NON_WITNESS_UTXO disagree")
        cand = (val, sc)
    if cand is None:
        raise SpendError("missing_utxo", "input %d has no UTXO field" % j)
    return cand[0], cand[1], verified


# --------------------------------------------------------------- sighash type
def sighash_type(m, taproot):
    v = m.get(b"\x03")
    if v is None:
        return SIGHASH_DEFAULT if taproot else SIGHASH_ALL
    if len(v) != 4:
        raise SpendError("sighash_bad_length", "SIGHASH_TYPE is not 4 bytes")
    h = int.from_bytes(v, "little")
    if h == 0 and not taproot:
        raise SpendError("sighash_zero_ecdsa", "present zero sighash type for ECDSA")
    if h not in (BIP340_TYPES if taproot else ECDSA_TYPES):
        raise SpendError("sighash_unsupported", "unsupported sighash type %#x" % h)
    return h


Pair = namedtuple("Pair", "index keyid scheme path pk message sighash sigkey value spk "
                          "script leaf internal tweak nw_verified taproot_all_prevouts")


def pair_sigkey(scheme, keyid):
    if scheme == "ecdsa":
        return b"\x02" + keyid
    # PSBT_IN_TAP_KEY_SIG has no key data; PSBT_IN_TAP_SCRIPT_SIG is keyed by x-only key and leaf hash
    return b"\x13" if len(keyid) == 32 else b"\x14" + keyid


def classify_keyid(keyid):
    if len(keyid) == 33:
        return "ecdsa"
    if len(keyid) in (32, 64):
        return "bip340"
    raise SpendError("bad_keyid_length", "key identifier length %d" % len(keyid))


def resolve_pair(p, i, keyid, device_xonly, optional_forms=True):
    """Validate input i for the pair (i, keyid) and compute its message. Returns a Pair."""
    scheme = classify_keyid(keyid)
    m = p.inputs[i]
    for k in m:
        if k[:1] == b"\x06" and len(k) == 66 and k[1] in (4, 6, 7) and k[2:34] in device_xonly:
            raise SpendError("uncompressed_key", "derivation record with the uncompressed form of a device key")
    tx = C.core_tx(p)
    if b"\x07" in m or b"\x08" in m:
        raise SpendError("finalized_input", "input already has a final scriptSig or witness")
    value, spk, nwv = txout_of(p, i, tx)
    if scheme == "ecdsa":
        return _resolve_ecdsa(p, tx, i, keyid, value, spk, nwv, optional_forms)
    return _resolve_taproot(p, tx, i, keyid, value, spk, nwv, device_xonly, optional_forms)


def _resolve_ecdsa(p, tx, i, key, value, spk, nwv, optional_forms):
    m = p.inputs[i]
    if key[0] == 4 or AE._parse33(key) is AE._INF:
        raise SpendError("bad_key", "key is not a compressed public key")
    h = sighash_type(m, False)
    if len(spk) == 34 and spk[:2] == b"\x51\x20":
        raise SpendError("wrong_scheme", "ECDSA pair on a Taproot output")
    path = None
    if len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[-2:] == b"\x88\xac":
        path, script = "legacy", spk
        if hash160(key) != spk[3:23]:
            raise SpendError("key_not_in_script", "key hash does not match P2PKH")
    elif len(spk) == 22 and spk[:2] == b"\x00\x14":
        path = "segwit"
        if hash160(key) != spk[2:]:
            raise SpendError("key_not_in_script", "key hash does not match P2WPKH")
        script = b"\x76\xa9\x14" + spk[2:] + b"\x88\xac"
    elif len(spk) == 34 and spk[:2] == b"\x00\x20":
        path = "segwit"
        script = m.get(b"\x05")
        if script is None or C.sha256(script) != spk[2:]:
            raise SpendError("witness_script_mismatch", "missing or mismatched witness script")
        ecdsa_script_check(script, key, optional_forms)
    elif len(spk) == 23 and spk[:2] == b"\xa9\x14" and spk[-1:] == b"\x87":
        redeem = m.get(b"\x04")
        if redeem is None or hash160(redeem) != spk[2:22]:
            raise SpendError("redeem_script_mismatch", "missing or mismatched redeem script")
        if len(redeem) == 22 and redeem[:2] == b"\x00\x14":
            path = "segwit"
            if hash160(key) != redeem[2:]:
                raise SpendError("key_not_in_script", "key hash does not match P2SH-P2WPKH")
            script = b"\x76\xa9\x14" + redeem[2:] + b"\x88\xac"
        elif len(redeem) == 34 and redeem[:2] == b"\x00\x20":
            path = "segwit"
            script = m.get(b"\x05")
            if script is None or C.sha256(script) != redeem[2:]:
                raise SpendError("witness_script_mismatch", "missing or mismatched witness script")
            ecdsa_script_check(script, key, optional_forms)
        else:
            if not optional_forms:
                raise SpendError("optional_form_unsupported", "legacy P2SH is an optional form")
            path, script = "legacy", redeem
            ecdsa_script_check(script, key, optional_forms)
    else:
        raise SpendError("unsupported_script", "unsupported spent script")
    if path == "legacy":
        if not nwv:
            raise SpendError("legacy_needs_nonwitness", "legacy spend needs NON_WITNESS_UTXO")
        msg = legacy_sighash(tx, i, script, h)
    else:
        msg = bip143_sighash(tx, i, script, value, h)
    return Pair(i, key, "ecdsa", path, key, msg, h, pair_sigkey("ecdsa", key), value, spk,
                script, None, None, None, nwv, False)


def _musig_check(m, device_xonly, internal):
    for k, v in m.items():
        if k[:1] == b"\x1a":
            if len(v) % 33:
                raise SpendError("bad_musig2", "bad MuSig2 participants field")
            if internal is not None and k[2:] == internal:
                raise SpendError("musig2_aggregate", "internal key is a known aggregate")
            if any(v[j + 1:j + 33] in device_xonly for j in range(0, len(v), 33)):
                raise SpendError("musig2_participant", "MuSig2 participant list holds a device key")


def _resolve_taproot(p, tx, i, keyid, value, spk, nwv, device_xonly, optional_forms):
    m = p.inputs[i]
    if not (len(spk) == 34 and spk[:2] == b"\x51\x20"):
        raise SpendError("wrong_scheme", "BIP340 pair on a non-Taproot output")
    program = spk[2:]
    h = sighash_type(m, True)
    key_path = len(keyid) == 32
    xkey = keyid[:32]
    lift_xonly(xkey)
    _musig_check(m, device_xonly, xkey if key_path else None)
    acp = bool(h & 0x80)
    prevouts = None
    if not acp:
        prevouts = []
        for j in range(len(tx.ins)):
            try:
                v, s, _ = txout_of(p, j, tx)
            except SpendError as e:
                raise SpendError("taproot_prevouts_missing", "input %d: %s" % (j, e))
            prevouts.append((v, s))
    else:
        prevouts = [None] * len(tx.ins)
        prevouts[i] = (value, spk)
    if key_path:
        if b"\x17" in m and m[b"\x17"] != xkey:
            raise SpendError("internal_key_mismatch", "TAP_INTERNAL_KEY differs from the key-path identifier")
        root = m.get(b"\x18", b"")
        if len(root) not in (0, 32) or (b"\x18" in m and len(root) != 32):
            raise SpendError("bad_merkle_root", "bad TAP_MERKLE_ROOT")
        tweak, qx, _ = tweaked_xonly(xkey, root)
        if qx != program:
            raise SpendError("tap_output_key_mismatch", "internal key and merkle root do not give the output key")
        msg = tap_sighash(tx, i, prevouts, h)
        return Pair(i, keyid, "bip340", "key", qx, msg, h, pair_sigkey("bip340", keyid), value, spk,
                    None, None, xkey, tweak, nwv, not acp)
    if not optional_forms:
        raise SpendError("optional_form_unsupported", "Taproot script path is an optional form")
    leaf = keyid[32:]
    hits = []
    for k, v in m.items():
        if k[:1] == b"\x15" and len(v) >= 1 and tap_leaf_hash(v[-1], v[:-1]) == leaf:
            hits.append((k[1:], v[:-1], v[-1]))
    if not hits:
        raise SpendError("tap_leaf_missing", "no TAP_LEAF_SCRIPT entry matches the leaf hash")
    if len(hits) > 1:
        raise SpendError("tap_leaf_ambiguous", "more than one TAP_LEAF_SCRIPT entry matches the leaf hash")
    control, script, ver = hits[0]
    if ver != 0xC0 or len(control) < 33 or control[0] & 0xFE != 0xC0:
        raise SpendError("tap_leaf_version", "leaf version is not 0xC0")
    if (len(control) - 33) % 32:
        raise SpendError("tap_control_block", "control block length")
    if (len(control) - 33) // 32 > 128:
        raise SpendError("tap_control_depth", "control block has more than 128 path elements")
    internal = control[1:33]
    _, qx, par = tweaked_xonly(internal, control_root(control, leaf))
    if qx != program or par != (control[0] & 1):
        raise SpendError("tap_control_mismatch", "control block does not compute the spent output key")
    tap_leaf_check(script, xkey)
    msg = tap_sighash(tx, i, prevouts, h, leaf)
    return Pair(i, keyid, "bip340", "script", xkey, msg, h, pair_sigkey("bip340", keyid), value, spk,
                script, leaf, internal, None, nwv, not acp)


# --------------------------------------------------------------------- fees
def fee_info(p, pairs):
    """(fee or None, fee_verified, unverified_input_indexes).

    An input amount counts as verified if it came from a NON_WITNESS_UTXO that
    hashes to the previous txid, or if a Taproot pair without ANYONECANPAY in
    this request commits to every input amount through its signature hash.
    """
    tx = C.core_tx(p)
    covered = any(pr.taproot_all_prevouts for pr in pairs)
    total, unverified, known = 0, [], True
    for j in range(len(tx.ins)):
        try:
            v, _, nwv = txout_of(p, j, tx)
        except SpendError:
            known = False
            unverified.append(j)
            continue
        total += v
        if not (nwv or covered):
            unverified.append(j)
    if not known:
        return None, False, unverified
    fee = total - sum(v for v, _ in tx.outs)
    if fee < 0:
        raise SpendError("outputs_exceed_inputs", "outputs exceed inputs")
    return fee, not unverified, unverified


def sigfield(scheme, h, a, b=None):
    """Signature field bytes from verified values: DER(r, s)+type for ECDSA, sig64(+type) for BIP340."""
    if scheme == "ecdsa":
        return der(a, b) + bytes([h])
    return a + (bytes([h]) if h != 0 else b"")


def _der_int(x):
    b = x.to_bytes((x.bit_length() + 8) // 8, "big")
    return b"\x02" + bytes([len(b)]) + b


def der(r, s):
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def parse_der_sig(field):
    """Strict BIP66 DER plus one sighash byte. Returns (r, s, sighash_byte)."""
    def bad(why):
        raise SpendError("bad_der", why)
    if len(field) < 9 or len(field) > 73:
        bad("length")
    d = field[:-1]
    if d[0] != 0x30 or d[1] != len(d) - 2 or d[2] != 2:
        bad("structure")
    lr = d[3]
    if lr == 0 or 5 + lr >= len(d):
        bad("r length")
    rb = d[4:4 + lr]
    if d[4 + lr] != 2:
        bad("s marker")
    ls = d[5 + lr]
    if ls == 0 or 6 + lr + ls != len(d):
        bad("s length")
    sb = d[6 + lr:]
    for b in (rb, sb):
        if b[0] & 0x80 or (len(b) > 1 and b[0] == 0 and not b[1] & 0x80):
            bad("non-minimal or negative integer")
    return int.from_bytes(rb, "big"), int.from_bytes(sb, "big"), field[-1]
