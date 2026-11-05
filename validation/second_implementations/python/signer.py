"""Signer: reads one request PSBT, answers one pass of the protocol."""
import sys

import proto
from secp import N, G, bytes32, int_from, pt_mul
from psbt import (Psbt, PsbtError, Keys, analyze_pair, check_request_level,
                  tap_tweak, map_set, map_del_types, update_modifiable, der_encode,
                  AE_TYPES, IN_AE_HOST_COMMITMENT, IN_AE_NONCE_COMMITMENT,
                  IN_AE_HOST_RANDOMNESS, SIGHASH_ACP)

VALUE_LEN = {IN_AE_HOST_COMMITMENT: 32, IN_AE_NONCE_COMMITMENT: 33, IN_AE_HOST_RANDOMNESS: 32}


class SignerFail(Exception):
    pass


def collect_ae(ps):
    """Returns {(input, keyid): {type: value}}. Fails on bad lengths."""
    pairs = {}
    for i, mlist in enumerate(ps.ins):
        for k, v in mlist:
            t = k[0]
            if t not in AE_TYPES:
                continue
            keyid = bytes(k[1:])
            if len(keyid) not in (32, 33, 64):
                raise SignerFail("bad key identifier length %d" % len(keyid))
            if len(v) != VALUE_LEN[t]:
                raise SignerFail("bad anti-exfil value length")
            pairs.setdefault((i, keyid), {})[t] = bytes(v)
    return pairs


def _secret_for(info, sk_by_pub, sk_by_x):
    """The secret handed to the protocol function for this pair."""
    if info.kind == "ecdsa":
        return sk_by_pub[info.keyid]
    x = info.keyid[:32]
    sk = sk_by_x[x]
    if info.kind == "tr_script":
        return sk
    # key path: normalize, then add the BIP341 tweak
    dp = int_from(sk)
    Pt = pt_mul(dp, G)
    d = dp if Pt[1] % 2 == 0 else N - dp
    tw = tap_tweak(x, info.merkle)
    if tw >= N:
        raise SignerFail("tweak out of range")
    t = (d + tw) % N
    if t == 0:
        raise SignerFail("tweaked key is zero")
    return bytes32(t)


def _commit(info, sk, hc):
    if info.scheme == "ecdsa":
        d, pk, k0, R0 = proto.ecdsa_base(sk, info.m, hc)
    else:
        d, pk, k0, R0 = proto.schnorr_base(sk, info.m, hc)
    if pk != info.pk:
        raise SignerFail("computed public key differs from the expected one")
    return R0


def _sign(info, sk, rho):
    if info.scheme == "ecdsa":
        r, s = proto.ecdsa_sign(sk, info.m, rho)
        return der_encode(r, s) + bytes([info.ht])
    sig = proto.schnorr_sign(sk, info.m, rho)
    return sig + (bytes([info.ht]) if info.ht != 0 else b"")


def describe(ps, infos, fee, verified):
    lines = ["signer: approval requested"]
    for j, (a, spk) in enumerate(ps.tx.outs):
        lines.append("  output %d: %d sat to %s" % (j, a, spk.hex()))
    if fee is None:
        lines.append("  fee unknown (not every input amount is known)")
    elif verified:
        lines.append("  fee %d sat (verified)" % fee)
    else:
        lines.append("  fee %d sat (UNVERIFIED: not every input amount is verified)" % fee)
    for p in infos:
        extra = ""
        if p.kind == "tr_script":
            extra = " leaf %s" % p.keyid[32:].hex()
        lines.append("  sign input %d with %s path%s, sighash type %#x" % (p.i, p.kind, extra, p.ht))
    return "\n".join(lines)


def run(sk_hexes, decline, line):
    """Returns the response PSBT bytes or raises."""
    sks = []
    for h in sk_hexes:
        b = bytes.fromhex(h)
        if len(b) != 32 or not 0 < int_from(b) < N:
            raise SignerFail("bad secret key")
        sks.append(b)
    if not sks:
        raise SignerFail("no secret key")
    sk_by_pub = {}
    sk_by_x = {}
    from secp import ser33
    for b in sks:
        pub = ser33(pt_mul(int_from(b), G))
        sk_by_pub[pub] = b
        sk_by_x.setdefault(pub[1:], b)
    keys = Keys(list(sk_by_pub))
    ps = Psbt.parse(bytes.fromhex(line.strip()))
    ae = collect_ae(ps)
    if not ae:
        raise SignerFail("not a request under this protocol")
    phases = set()
    for pair, d in ae.items():
        if IN_AE_HOST_RANDOMNESS in d:
            phases.add(2)
        elif IN_AE_HOST_COMMITMENT in d:
            phases.add(1)
        else:
            raise SignerFail("only a nonce commitment")
    if len(phases) != 1:
        raise SignerFail("mixed phases")
    phase = phases.pop()
    infos = [analyze_pair(ps, i, keyid, keys, signer=True) for (i, keyid) in sorted(ae)]
    fee, verified = check_request_level(ps, infos)
    out = ps.copy()
    secrets = {}
    r0s = {}
    for info in infos:
        d = ae[(info.i, info.keyid)]
        sk = _secret_for(info, sk_by_pub, sk_by_x)
        secrets[(info.i, info.keyid)] = sk
        if phase == 1:
            hc = d[IN_AE_HOST_COMMITMENT]
        else:
            rho = d[IN_AE_HOST_RANDOMNESS]
            hc = proto.schnorr_hc(rho) if info.scheme == "bip340" else proto.ecdsa_hc(rho)
            if IN_AE_HOST_COMMITMENT in d and d[IN_AE_HOST_COMMITMENT] != hc:
                raise SignerFail("host commitment differs from the computed value")
        R0 = _commit(info, sk, hc)
        if IN_AE_NONCE_COMMITMENT in d and d[IN_AE_NONCE_COMMITMENT] != R0:
            raise SignerFail("nonce commitment differs from the computed value")
        r0s[(info.i, info.keyid)] = R0
    if phase == 1:
        for info in infos:
            map_set(out.ins[info.i], bytes([IN_AE_NONCE_COMMITMENT]) + info.keyid,
                    r0s[(info.i, info.keyid)])
        return out.serialize()
    # second pass: one approval for the whole PSBT
    sys.stderr.write(describe(ps, infos, fee, verified) + "\n")
    if decline:
        raise SignerFail("user declined")
    for info in infos:
        d = ae[(info.i, info.keyid)]
        val = _sign(info, secrets[(info.i, info.keyid)], d[IN_AE_HOST_RANDOMNESS])
        map_set(out.ins[info.i], info.sigkey, val)
        update_modifiable(out, info.ht)
    for m in out.ins:
        map_del_types(m, AE_TYPES)
    return out.serialize()
