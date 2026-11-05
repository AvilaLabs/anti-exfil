#!/usr/bin/env python3
"""The reference host against Jade's sign_psbt (libjade), with the reference signer as an oracle.

What it does
  1. Every required form, PSBT v0 and v2, with the sighash types Jade accepts, through psbt/host.py
     against libjade. The host must accept; where Bitcoin Core is found, v0 and v2 results are finalized
     and mined on a private regtest node.
  2. The same requests are given to the reference signer (psbt/signer.py) holding the same keys, and
     the anti-exfil fields and signatures of its responses are compared with Jade's.
  3. Approval count: the first pass must not ask for approval, the second must ask once.
  4. Optional forms and sighash types outside Jade's limits must be refused.
  5. Plan traps, as tampered but well-formed PSBTs.
  6. Replay of vectors/bip-anti-exfil-psbt.json. The vector keys are not holdable by a seed, so the vector
     generator's own cases are rebuilt with keys from Jade's test seed (the same code, other keys).

Run:  LD_LIBRARY_PATH=<dir with libjade.so> python check_host_interop.py [--emit DIR] [--no-regtest]
"""
import argparse
import base64
import importlib.util
import json
import os
import pathlib
import shutil
import struct
import sys
import tempfile
from collections import Counter

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import jade_keys as J                          # noqa: E402

J.install()
K, C, T = J.K, J.C, J.T
S, SG, H, AE = K.S, K.SG, K.H, K.AE
JadeError = J.JadeError
AE_TYPES = (0x21, 0x22, 0x23)
SIG_TYPES = (0x02, 0x13)
HASH_OK_ECDSA = (None, 1)
HASH_OK_TAPROOT = (None, 0, 1)


class Report:
    def __init__(self):
        self.passed, self.failed, self.notes = 0, [], []
        self.groups = Counter()

    def check(self, cond, name, detail=""):
        group = name.split(":")[0]
        if cond:
            self.passed += 1
            self.groups[group] += 1
        else:
            self.failed.append("%s %s" % (name, detail))
            print("FAIL", name, detail, flush=True)
        return cond

    def note(self, text):
        self.notes.append(text)


def ae_fields(psbt_bytes):
    p = C.parse(psbt_bytes)
    return {(i, k): v for i, m in enumerate(p.inputs) for k, v in m.items() if k and k[0] in AE_TYPES}


def sig_fields(psbt_bytes):
    p = C.parse(psbt_bytes)
    return {(i, k): v for i, m in enumerate(p.inputs) for k, v in m.items() if k and k[0] in SIG_TYPES}


def modifiable(psbt_bytes):
    p = C.parse(psbt_bytes)
    return p.glob.get(b"\x06")


class Chain:
    """A private regtest node (own datadir) for mining the results."""

    def __init__(self, work):
        import regtest_node as R
        R.WORK = work
        self.node = R.Node()
        self.node.start()

    def stop(self):
        self.node.stop()

    def fund(self, specs):
        outs = [(v, s) for s, v in specs]
        raw = C.ser_tx(C.Tx(2, [], outs, 0)).hex()
        funded = self.node.cli("fundrawtransaction", raw, {"changePosition": len(outs)}, False)
        signed = self.node.cli("signrawtransactionwithwallet", funded["hex"])
        assert signed["complete"]
        txid = self.node.cli("sendrawtransaction", signed["hex"])
        self.node.cli("generatetoaddress", 1, self.node.addr)
        txb = bytes.fromhex(self.node.cli("getrawtransaction", txid))
        tx = C.parse_tx(txb)
        prevs = []
        for s, v in specs:
            ix = next(i for i, o in enumerate(tx.outs) if o == (v, s))
            prevs.append(K.Prev(txb, ix, v, s))
        return prevs

    def dest(self):
        info = self.node.cli("getaddressinfo", self.node.cli("getnewaddress"))
        return bytes.fromhex(info["scriptPubKey"])

    def mine(self, txid, raw):
        acc = self.node.cli("testmempoolaccept", [raw])
        if not acc[0]["allowed"]:
            return False, acc
        sent = self.node.cli("sendrawtransaction", raw)
        self.node.cli("generatetoaddress", 1, self.node.addr)
        info = self.node.cli("getrawtransaction", txid, True)
        return sent == txid and info["confirmations"] >= 1, info.get("confirmations")


class Ctx:
    def __init__(self, jade, rep, tmp, chain, emit):
        self.jade, self.rep, self.tmp, self.chain, self.emit = jade, rep, tmp, chain, emit
        self.have_counter = True
        self.emitted = Counter()

    def prompts(self):
        return J.prompts(self.jade)

    def write_case(self, kind, cid, data):
        if not self.emit:
            return
        d = pathlib.Path(self.emit)
        d.mkdir(parents=True, exist_ok=True)
        (d / ("%s_%s.json" % (kind, cid.replace("-fake", "")))).write_text(json.dumps(data, indent=2) + "\n")
        self.emitted[kind] += 1


def b64(b):
    return "b64:" + base64.b64encode(b).decode()


def try_sign(ctx, request):
    """(response, None) or (None, JadeError), and the change in the approval count. A request libwally's own parser
    rejects is malformed and is never sent to Jade: it comes back as a refusal with a message that says so."""
    if not wally_parses(request):
        return None, JadeError(0, "malformed, not sent to Jade", None), 0
    before = ctx.prompts()
    try:
        out, err = ctx.jade.sign_psbt(J.NETWORK, request), None
    except JadeError as e:
        out, err = None, e
    return out, err, ctx.prompts() - before


def eligible(names, sighashes):
    for n, h in zip(names, sighashes or [None] * len(names)):
        if n not in K.REQUIRED_FORMS:
            return False
        if h not in (HASH_OK_TAPROOT if n.startswith("p2tr") else HASH_OK_ECDSA):
            return False
    return True


# ------------------------------------------------------------------ 1-3: the host against Jade
def exchange(ctx, cid, names, version, sighashes=None, utxo="non", chain=False, mod=None, emit=True):
    rep = ctx.rep
    K._counter[0] = 0
    forms = [K.Form(n, "m") for n in names]
    prevs = ctx.chain.fund([(f.spk, 100000) for f in forms]) if chain else [None] * len(forms)
    inputs = [K.Inp(f, sighash=h, utxo=utxo, prev=p) for f, h, p in zip(forms, sighashes or [None] * len(forms), prevs)]
    kw = {}
    if chain:
        total = 100000 * len(forms)
        kw["outputs"] = [(total // 2 - 1000, ctx.chain.dest()), (total - total // 2 - 1000, ctx.chain.dest())]
    if mod is not None:
        kw["modifiable"] = mod
    rig = K.Rig(inputs, ctx.tmp, version=version, link_cls=J.link_for(ctx.jade), max_retries=0,
                rho_source=K.fixed_rho(cid), device_id="jade-" + cid, **kw)
    n0 = ctx.prompts()
    a = rig.host.start(rig.request_bytes)
    a.commit()
    n1 = ctx.prompts()
    res = a.reveal()
    n2 = ctx.prompts()
    rep.check(n1 == n0, "approvals:first pass makes no prompt", cid)
    rep.check(n2 == n1 + 1, "approvals:second pass prompts once", "%s %d" % (cid, n2 - n1))
    (q1, r1), (q2, r2) = rig.link.transcript[:2]
    ref = rig.signer
    r1ref, r2ref = ref.sign(q1), ref.sign(q2)
    rep.check(ae_fields(r1) == ae_fields(r1ref), "differential:first response fields", cid)
    rep.check(not sig_fields(r1), "first pass:adds no signature", cid)
    rep.check(sig_fields(r2) == sig_fields(r2ref) and sig_fields(r2), "differential:second response signatures", cid)
    rep.check(not ae_fields(r2), "second pass:removes every anti-exfil field", cid)
    rep.check(bool(res.signed), "host:accepts", cid)
    npairs = len(ae_fields(q1))
    rep.check(npairs and len(ae_fields(r1)) == npairs * 2, "first pass:keeps hc and adds one R0 per pair", cid)
    if version == 2:
        before = modifiable(q2)
        after = modifiable(r2)
        if before is not None:
            rep.check(after is None or after[0] & 3 == 0, "flags:v2 inputs/outputs cleared", cid)  # none is zero
    if chain:
        txid, raw = K.final_tx(res.psbt, inputs)
        ok, info = ctx.chain.mine(txid, raw)
        rep.check(ok, "regtest:mined", "%s %s" % (cid, info))
    if emit and not chain and eligible(names, sighashes):
        ctx.write_case("exchange", cid, {
            "description": "%s, PSBT version %d, through the reference host; expected fields from the reference signer" % (
                ", ".join(names), version),
            "input": {"network": J.NETWORK, "first_request": b64(q1), "second_request": b64(q2)},
            "expected_output": {"first_response": b64(r1ref), "second_response": b64(r2ref)}})
    return rig, res


def refused_exchange(ctx, cid, names, version, sighashes=None, utxo="non"):
    """The host starts, Jade must refuse the first pass and nothing must be returned or prompted."""
    rep = ctx.rep
    K._counter[0] = 0
    forms = [K.Form(n, "m") for n in names]
    inputs = [K.Inp(f, sighash=h, utxo=utxo) for f, h in zip(forms, sighashes or [None] * len(forms))]
    rig = K.Rig(inputs, ctx.tmp, version=version, link_cls=J.link_for(ctx.jade), max_retries=0,
                rho_source=K.fixed_rho(cid), device_id="jade-" + cid)
    n0 = ctx.prompts()
    a = rig.host.start(rig.request_bytes)
    try:
        a.commit()
        refused = False
    except H.AttemptFailed:
        refused = True
    rep.check(refused, "refusals:jade refuses outside its limits", cid)
    rep.check(rig.link.transcript and rig.link.transcript[0][1] is None, "refusals:nothing returned", cid)
    rep.check(ctx.prompts() == n0, "approvals:no prompt on a refusal", cid)


def section_matrix(ctx):
    for name in K.REQUIRED_FORMS:
        for v in (0, 2):
            exchange(ctx, "%s-v%d" % (name, v), [name], v, chain=bool(ctx.chain))
            exchange(ctx, "%s-v%d-fake" % (name, v), [name], v, mod=3 if v == 2 else None)
    for name, hashes in (("p2wpkh", HASH_OK_ECDSA), ("p2tr-key", HASH_OK_TAPROOT), ("p2tr-key-root", HASH_OK_TAPROOT)):
        for h in hashes:
            for v in (0, 2):
                exchange(ctx, "%s-sighash-%s-v%d" % (name, h, v), [name], v, [h], chain=bool(ctx.chain))
                exchange(ctx, "%s-sighash-%s-v%d-fake" % (name, h, v), [name], v, [h])
    for v in (0, 2):
        exchange(ctx, "mixed-required-v%d" % v, list(K.REQUIRED_FORMS), v, chain=bool(ctx.chain))
        exchange(ctx, "mixed-required-v%d-fake" % v, list(K.REQUIRED_FORMS), v, mod=3 if v == 2 else None)
    # the utxo fields: segwit forms with a witness utxo only, both, and a non-witness utxo only (the default above)
    for utxo in ("wit", "both"):
        for name in ("p2wpkh", "p2sh-p2wpkh", "p2wsh-2of3", "p2tr-key", "p2tr-key-root"):
            exchange(ctx, "%s-utxo-%s" % (name, utxo), [name], 0, utxo=utxo)
    exchange(ctx, "p2wpkh-p2tr-both-keys-two-inputs", ["p2wpkh", "p2tr-key"], 2)


def section_limits(ctx):
    for name in ("p2sh-single", "p2sh-2of3", "p2tr-script", "p2tr-multi_a"):
        for v in (0, 2):
            refused_exchange(ctx, "%s-v%d" % (name, v), [name], v)
    for name, hashes in (("p2wpkh", (2, 3, 0x81, 0x82, 0x83)), ("p2tr-key", (2, 3, 0x81, 0x82, 0x83))):
        for h in hashes:
            refused_exchange(ctx, "%s-sighash-%#x" % (name, h), [name], 0, [h])
    refused_exchange(ctx, "mixed-with-optional", list(K.ALL_FORMS), 0)


# ------------------------------------------------------------------ 5: traps
def tamper_input(psbt_bytes, fn):
    p = C.parse(psbt_bytes)
    fn(p)
    return p.serialize()


def noncanonical_request(q, key_type):
    """Replace the compact type of the first field of key_type by its three-byte form, keeping the rest."""
    p = C.parse(q)
    m = p.inputs[0]
    key = next(k for k in m if k and k[0] == key_type)
    value = m.pop(key)
    data = p.serialize()
    # splice the key as fd <type u16 le> <id>, writing the field by hand where the codec orders its map
    new_key = b"\xfd" + struct.pack("<H", key_type) + key[1:]
    field = C.compact(len(new_key)) + new_key + C.compact(len(value)) + value
    marker = C.compact(len(key)) + key + C.compact(len(value)) + value
    return data, field, marker


def section_traps(ctx):
    rep = ctx.rep
    K._counter[0] = 0
    f = K.Form("p2wpkh", "m")
    rig = K.Rig([K.Inp(f)], ctx.tmp, link_cls=J.link_for(ctx.jade), rho_source=K.fixed_rho("trap"), device_id="trap")
    pairs = K.pairs_of(rig)
    q1, rhos = K.req_first(rig.psbt, pairs)
    q2 = K.req_second(rig.psbt, pairs, rhos)
    q2hc = K.req_second(rig.psbt, pairs, rhos, keep_hc=True)
    kid = pairs[0].keyid
    r1 = ctx.jade.sign_psbt(J.NETWORK, q1)
    good_r0 = ae_fields(r1)[(0, b"\x22" + kid)]

    def refuse(cid, request, why):
        out, err, dp = try_sign(ctx, request)
        rep.check(err is not None and out is None, "traps:refused", "%s (%s)" % (cid, why))
        rep.check(dp == 0, "approvals:no prompt before the failure", cid)
        if err is not None:
            ctx.write_case("refusal", "trap-" + cid, {
                "description": why, "input": {"network": J.NETWORK, "psbt": b64(request)},
                "expected_error": err.message})
        return err

    def accept(cid, request, prompts):
        out, err, dp = try_sign(ctx, request)
        rep.check(err is None and out is not None, "traps:accepted", cid + (" " + err.message if err else ""))
        rep.check(dp == prompts, "approvals:count", "%s %d" % (cid, dp))
        return out

    # a correct nonce commitment already in the request is accepted and unchanged
    with_r0 = tamper_input(q1, lambda p: p.inputs[0].update({b"\x22" + kid: good_r0}))
    out = accept("first-pass-with-correct-r0", with_r0, 0)
    rep.check(out is not None and ae_fields(out)[(0, b"\x22" + kid)] == good_r0, "traps:correct r0 kept")
    # duplicate wally_map_add is silent, so a wrong R0 must fail and not be hidden
    wrong_r0 = bytes([5 - good_r0[0]]) + good_r0[1:]
    refuse("first-pass-wrong-r0", tamper_input(q1, lambda p: p.inputs[0].update({b"\x22" + kid: wrong_r0})),
           "a first pass request carrying a wrong nonce commitment")
    refuse("second-pass-wrong-r0", tamper_input(q2hc, lambda p: p.inputs[0].update({b"\x22" + kid: wrong_r0})),
           "a second pass request carrying a wrong nonce commitment")
    refuse("nonce-only", tamper_input(q1, lambda p: (p.inputs[0].pop(b"\x21" + kid), p.inputs[0].update({b"\x22" + kid: good_r0}))),
           "a nonce commitment with no host commitment or randomness")
    refuse("second-pass-wrong-hc", tamper_input(q2hc, lambda p: p.inputs[0].update({b"\x21" + kid: bytes(32)})),
           "a second pass request whose host commitment is not that of the randomness")
    # two pairs: the first in its first pass, the second in its second
    K._counter[0] = 0
    r2of3 = K.Rig([K.Inp(K.Form("p2wsh-2of3", "m"))], ctx.tmp, link_cls=J.link_for(ctx.jade), device_id="mixed",
                  rho_source=K.fixed_rho("mixed"))
    pr2 = K.pairs_of(r2of3)
    m1, mrho = K.req_first(r2of3.psbt, pr2)
    mixed = tamper_input(m1, lambda p: p.inputs[0].update({b"\x23" + pr2[1].keyid: mrho[(0, pr2[1].keyid)]}))
    refuse("mixed-phases", mixed, "one pair with only a host commitment and another with host randomness")
    refuse("mixed-phases-second-input", _mixed_inputs(ctx), "two inputs, the first in its first pass, the second in its second")
    # the second pass with hc and r0 present and right, and with neither
    out = accept("second-pass-with-hc-and-r0", tamper_input(q2hc, lambda p: p.inputs[0].update({b"\x22" + kid: good_r0})), 1)
    rep.check(out is not None and not ae_fields(out), "traps:every field removed (hc and r0 present)")
    out = accept("second-pass-rho-only", q2, 1)
    rep.check(out is not None and not ae_fields(out), "traps:every field removed (rho only)")
    # a changed output between the passes changes the signature hash, so R0 no longer matches
    refuse("output-changed-between-passes",
           _change_output_after(q2hc, good_r0, kid),
           "the transaction changed after the first pass: the stored nonce commitment no longer matches")
    # a non-canonical key type is not an ordinary unknown field
    for key_type in AE_TYPES:
        source = {0x21: q1, 0x22: with_r0, 0x23: q2}[key_type]
        data, field, marker = noncanonical_request(source, key_type)
        refuse("noncanonical-type-%#x" % key_type, _splice(data, field), "a non-canonical key type %#x is not ignored" % key_type)
    # utxo variants that change which sighash wally would use
    for utxo in ("non", "wit", "both"):
        K._counter[0] = 0
        r = K.Rig([K.Inp(f, utxo=utxo)], ctx.tmp, link_cls=J.link_for(ctx.jade), rho_source=K.fixed_rho("u" + utxo))
        pr = K.pairs_of(r)
        a, rh = K.req_first(r.psbt, pr)
        out = accept("utxo-" + utxo + "-first", a, 0)
        b = K.req_second(r.psbt, pr, rh)
        out = accept("utxo-" + utxo + "-second", b, 1)
        want = r.signer.sign(a), r.signer.sign(b)
        rep.check(out is not None and sig_fields(out) == sig_fields(want[1]), "traps:segwit sighash by utxo kind " + utxo)
    # qr and usb storage have no process, and must not return the randomness
    out_np = _no_process(ctx, q2)
    rep.check(out_np == "BAD_PARAMETERS", "traps:no process (qr, usb storage): second pass refused", str(out_np))
    out_np = _no_process(ctx, q1)
    rep.check(out_np == "BAD_PARAMETERS", "traps:no process (qr, usb storage): first pass refused", str(out_np))
    # the ordinary request keeps working
    out_plain, err, dp = try_sign(ctx, rig.psbt.serialize())
    rep.check(err is None and dp == 1 and not ae_fields(out_plain) and sig_fields(out_plain),
              "traps:ordinary psbt signed ordinarily", str(err))
    # finalized input, already signed, taproot with a merkle root, key not derivable, extra records
    _more_traps(ctx, refuse)


def _mixed_inputs(ctx):
    K._counter[0] = 0
    inputs = [K.Inp(K.Form("p2wpkh", "m")), K.Inp(K.Form("p2pkh", "m"))]
    r = K.Rig(inputs, ctx.tmp, link_cls=J.link_for(ctx.jade), device_id="mixed2", rho_source=K.fixed_rho("mixed2"))
    pr = K.pairs_of(r)
    q1, rhos = K.req_first(r.psbt, pr)
    return tamper_input(q1, lambda p: p.inputs[1].update({b"\x23" + pr[1].keyid: rhos[(1, pr[1].keyid)]}))


def _splice(data, field):
    """data is a serialized psbt with the field removed; the field goes back at the end of input 0's map."""
    # find the end of the first input map: the first 0x00 separator after the global map and the
    # separator that closes the global map; simpler to rebuild through the codec's own layout
    p = C.parse(data)
    head = C.MAGIC + C._ser_map(p.glob)
    body = C._ser_map(p.inputs[0])
    assert body.endswith(b"\x00")
    rest = b"".join(C._ser_map(m) for m in p.inputs[1:]) + b"".join(C._ser_map(m) for m in p.outputs)
    return head + body[:-1] + field + b"\x00" + rest


def _change_output_after(q2hc, good_r0, kid):
    p = C.parse(q2hc)
    p.inputs[0][b"\x22" + kid] = good_r0
    assert p.version == 0
    tx = C.core_tx(p)
    outs = [(tx.outs[0][0] - 1, tx.outs[0][1]), (tx.outs[1][0] + 1, tx.outs[1][1])]
    p.glob[b"\x00"] = C.ser_tx(C.Tx(tx.version, list(tx.ins), outs, tx.locktime))
    return p.serialize()


def _no_process(ctx, request):
    try:
        ctx.jade._jadeRpc("libjade_request", {"request": "test_sign_psbt_no_process", "bytes": request})
        return "accepted"
    except JadeError as e:
        return "BAD_PARAMETERS" if e.code == JadeError.BAD_PARAMETERS else str(e.code)


def _off_curve_key():
    p = 2**256 - 2**32 - 977
    x = 5
    while pow((x**3 + 7) % p, (p - 1) // 2, p) == 1:
        x += 1
    return b"\x02" + x.to_bytes(32, "big")


def _more_traps(ctx, refuse):
    rep = ctx.rep

    def request_for(name, tweak=None, version=0, **kw):
        K._counter[0] = 0
        form = K.Form(name, "m")
        rig = K.Rig([K.Inp(form, **kw)], ctx.tmp, version=version, link_cls=J.link_for(ctx.jade),
                    rho_source=K.fixed_rho("x" + name), device_id="x-" + name)
        pr = K.pairs_of(rig)
        p = rig.psbt.clone()
        if tweak:
            tweak(p, form)
        return K.req_first(p, pr)[0], p, pr, form, rig

    cases = [
        ("final-scriptsig", "p2wpkh", lambda p, f: p.inputs[0].update({b"\x07": b"\x00"}), "a finalized input"),
        ("final-witness", "p2wpkh", lambda p, f: p.inputs[0].update({b"\x08": b"\x00"}), "a finalized input"),
        ("already-signed-ecdsa", "p2wpkh", lambda p, f: p.inputs[0].update({b"\x02" + K.pub33(f.a): b"\x30" * 70}),
         "a signature of the key is already there"),
        ("already-signed-taproot", "p2tr-key", lambda p, f: p.inputs[0].update({b"\x13": b"\x01" * 64}),
         "a taproot signature is already there"),
        ("taproot-wrong-internal-key", "p2tr-key", lambda p, f: p.inputs[0].update({b"\x17": K.xonly(K.seedkey("other"))}),
         "the internal key field differs from the key"),
        ("taproot-wrong-merkle-root", "p2tr-key-root", lambda p, f: p.inputs[0].update({b"\x18": b"\x09" * 32}),
         "the merkle root does not give the output key"),
        ("taproot-merkle-root-removed", "p2tr-key-root", lambda p, f: p.inputs[0].pop(b"\x18"),
         "the output key needs the merkle root that was removed"),
        ("segwit-utxo-amount-disagrees", "p2wpkh",
         lambda p, f: p.inputs[0].update({b"\x01": (99999).to_bytes(8, "little") + C.compact(len(f.spk)) + f.spk}),
         "the witness and non-witness utxos disagree"),
        ("non-witness-utxo-wrong-txid", "p2wpkh", lambda p, f: p.inputs[0].update({b"\x00": K.fake_prev(f.spk, 100001).txbytes}),
         "the non-witness utxo is not the previous transaction"),
        ("missing-utxo", "p2wpkh", lambda p, f: p.inputs[0].pop(b"\x00"), "no utxo"),
        ("musig2-field", "p2tr-key",
         lambda p, f: p.inputs[0].update({b"\x1a" + b"\x02" + b"\x33" * 32: b"\x02" + f.internal + b"\x03" + b"\x44" * 32}),
         "a MuSig2 participant field"),
        ("uncompressed-record", "p2wpkh", lambda p, f: p.inputs[0].update({b"\x06" + b"\x04" + b"\x01" * 64: b"\x00" * 4}),
         "an uncompressed derivation record"),
        ("redeem-script-mismatch", "p2sh-p2wpkh", lambda p, f: p.inputs[0].update({b"\x04": b"\x00\x14" + b"\x01" * 20}),
         "the redeem script is not the one hashed in the output"),
        ("witness-script-missing", "p2wsh-single", lambda p, f: p.inputs[0].pop(b"\x05"), "no witness script"),
        ("key-not-derivable", "p2wpkh", None, "a derivation record whose path does not give the key"),
    ]
    for cid, name, tweak, why in cases:
        if cid == "key-not-derivable":
            def tweak(p, f):
                k = b"\x06" + K.pub33(f.a)
                v = p.inputs[0][k]
                p.inputs[0][k] = v[:-4] + struct.pack("<I", struct.unpack("<I", v[-4:])[0] ^ 1)
        q, *_ = request_for(name, tweak)
        refuse(cid, q, why)
    # already signed by the key, with a real signature taken from an ordinary signing
    q, p, pr, form, rig = request_for("p2wpkh")
    ordinary = ctx.jade.sign_psbt(J.NETWORK, rig.psbt.serialize())
    (_, sigkey), sigval = next(iter(sig_fields(ordinary).items()))
    refuse("already-signed-valid-ecdsa", tamper_input(q, lambda p: p.inputs[0].update({sigkey: sigval})),
           "a real signature of the key is already there")
    # sighash all given explicitly is the same as none; anything else is refused
    for h in (2, 3, 0x81, 4):
        q, *_ = request_for("p2wpkh", lambda p, f, h=h: p.inputs[0].update({b"\x03": struct.pack("<I", h)}))
        refuse("ecdsa-sighash-%#x" % h, q, "ecdsa sighash %#x" % h)
    q, *_ = request_for("p2wpkh", lambda p, f: p.inputs[0].update({b"\x03": struct.pack("<I", 0)}))
    out, err, dp = try_sign(ctx, q)
    rep.check(err is None, "traps:present-zero sighash read as absent (ecdsa)", str(err))
    # taproot needs every prevout
    K._counter[0] = 0
    mine, other = K.Inp(K.Form("p2tr-key", "m")), K.Inp(K.Form("p2wpkh", "other"))
    r = K.Rig([mine, other], ctx.tmp, link_cls=J.link_for(ctx.jade), signer_keys=K.held_of([mine]),
              rho_source=K.fixed_rho("pv"), device_id="pv")
    pr = K.pairs_of(r)
    p = r.psbt.clone()
    del p.inputs[1][b"\x00"]
    refuse("taproot-needs-all-prevouts", K.req_first(p, pr)[0], "a taproot pair with an input that has no utxo")
    # script path (64 byte identifier) and key not in a pair form
    q, p, pr, form, rig = request_for("p2tr-key")
    kid = pr[0].keyid
    refuse("script-path-identifier", tamper_input(q, lambda p: p.inputs[0].update({b"\x21" + kid + b"\x01" * 32: bytes(32)})),
           "a 64 byte key identifier (script path)")
    # a multisig key in the witness script must be a valid point, not only have a 02 or 03 prefix
    K._counter[0] = 0
    f = K.Form("p2wsh-2of3", "m")
    f.witness_script = K.multisig(2, [K.pub33(f.a), K.pub33(f.b), _off_curve_key()])
    f.spk = b"\x00\x20" + C.sha256(f.witness_script)
    r = K.Rig([K.Inp(f)], ctx.tmp, link_cls=J.link_for(ctx.jade), rho_source=K.fixed_rho("offcurve"), device_id="offcurve")
    refuse("multisig-off-curve-key", K.req_first(r.psbt, K.manual_pairs(r))[0], "a key in the multisig script is not on the curve")
    # purposes: a taproot key at 48' is not refused for its purpose; at 44', 49' and 84' it is
    old_purpose = J.PURPOSE["p2tr-key"]
    try:
        J.PURPOSE["p2tr-key"] = 48
        exchange(ctx, "p2tr-key-purpose-48-v0", ["p2tr-key"], 0)
        for purpose in (44, 49, 84):
            J.PURPOSE["p2tr-key"] = purpose
            K._counter[0] = 0
            f = K.Form("p2tr-key", "pp%d" % purpose)
            r = K.Rig([K.Inp(f)], ctx.tmp, link_cls=J.link_for(ctx.jade), rho_source=K.fixed_rho("pp"), device_id="pp%d" % purpose)
            err = refuse("taproot-key-purpose-%d" % purpose, K.req_first(r.psbt, K.pairs_of(r))[0],
                         "a taproot key under purpose %d'" % purpose)
            rep.check(err is not None and err.message == "Key used for another script type", "traps:purpose is the reason", str(purpose))
    finally:
        J.PURPOSE["p2tr-key"] = old_purpose
    # outputs larger than inputs
    K._counter[0] = 0
    f = K.Form("p2wpkh", "m")
    r = K.Rig([K.Inp(f)], ctx.tmp, link_cls=J.link_for(ctx.jade), outputs=[(60000, K.out_script("d1")), (60000, K.out_script("d2"))],
              rho_source=K.fixed_rho("big"), device_id="big")
    refuse("outputs-exceed-inputs", K.req_first(r.psbt, K.manual_pairs(r))[0], "outputs worth more than the inputs")


# ------------------------------------------------------------------ 6: vectors
def load_generator(work):
    spec = importlib.util.spec_from_file_location("gen_psbt_vectors", str(J.REPO / "scripts/gen_psbt_vectors.py"))
    G = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(G)
    G.WORKDIR = work
    return G


CATEGORY_MESSAGES = ("Unsupported sighash value", "script paths is not supported", "Uncompressed derivation records",
                     "MuSig2 fields are not supported", "Witness script is not a supported form",
                     "Failed to extract psbt")
# The vector's signer holds other keys, but Jade holds the seed, so these are rebuilt with a path Jade does not resolve to the key.
KEY_NOT_HELD = {"signer-key-not-held", "signer-key-not-held-taproot-key-path"}
# Valid requests Jade refuses. A refusal is safe, and each is listed in RESULTS.md as a limit.
JADE_LIMITS = {
    "flags-sighash-default-counts-as-all-and-other-bits-kept-v2": "libwally does not read PSBT_GLOBAL_TX_MODIFIABLE with flags outside bits 0 to 2",
    "p2wpkh-input-without-pair-and-without-utxo-data-v0": "Jade needs UTXO data on every input, including inputs it does not sign",
}
SPECIAL = {
    "signer-no-ae-fields": "not a refusal for Jade: sign_psbt also signs ordinary psbts (spec: outside this document)",
    "signer-not-approved": "cannot be tested: libjade approves every prompt in CI mode",
    "signer-key-not-held": "replaced: the vector's signer holds other keys, Jade holds the seed",
}


def section_vectors(ctx, work):
    rep = ctx.rep
    G = load_generator(work)
    # The generator's own build(), so every exchange and refusal it holds now is replayed, whatever its ids
    doc = G.build(signer_side_only=True)
    try:
        exchanges = doc["exchanges"]
        replay = refused = 0
        for e in exchanges:
            names = [i["form"] for i in e["inputs"]]
            hashes = [i["sighash_type"] for i in e["inputs"]]
            q1, r1 = bytes.fromhex(e["first_request"]), bytes.fromhex(e["first_response"])
            if e["id"] in JADE_LIMITS:
                out1, err, dp = try_sign(ctx, q1)
                rep.check(err is not None and dp == 0, "vectors:exchange refused at a stated Jade limit", e["id"])
                rep.note("exchange %s refused by Jade: %s (%s)" % (e["id"], err.message if err else "ACCEPTED", JADE_LIMITS[e["id"]]))
                refused += 1
                continue
            q2, r2 = bytes.fromhex(e["second_request"]), bytes.fromhex(e["second_response"])
            if eligible(names, hashes):
                replay += 1
                out1, err, dp = try_sign(ctx, q1)
                rep.check(err is None and ae_fields(out1) == ae_fields(r1) and not sig_fields(out1) and dp == 0,
                          "vectors:exchange first pass", e["id"] + (" " + err.message if err else ""))
                out2, err, dp = try_sign(ctx, q2)
                rep.check(err is None and sig_fields(out2) == sig_fields(r2) and not ae_fields(out2) and dp == 1,
                          "vectors:exchange second pass", e["id"] + (" " + err.message if err else ""))
            else:
                refused += 1
                out1, err, dp = try_sign(ctx, q1)
                rep.check(err is not None and dp == 0, "vectors:exchange outside limits refused", e["id"])
                rep.note("exchange %s refused by Jade: %s" % (e["id"], err.message if err else "ACCEPTED"))
        rep.note("vector exchanges (Jade keys): %d replayed inside Jade's limits, %d refused outside them" % (replay, refused))
        reasons = Counter()
        n_ref = 0
        for c in doc["signer_refusals"]:
            cid = c["id"]
            req = bytes.fromhex(c["request"])
            if cid in SPECIAL and cid not in KEY_NOT_HELD:
                rep.note("refusal %s: %s" % (cid, SPECIAL[cid]))
                if cid == "signer-no-ae-fields":
                    out, err, dp = try_sign(ctx, req)
                    rep.check(err is None and not ae_fields(out), "vectors:ordinary psbt is signed ordinarily", cid)
                continue
            if cid == "signer-sighash-present-zero-ecdsa":
                # Allowed by the spec for a library that cannot tell it from absent: read as absent, signs ALL
                out, err, dp = try_sign(ctx, req)
                rep.check(err is None and not sig_fields(out) and dp == 0, "vectors:present zero ecdsa sighash read as absent", cid)
                rep.note("refusal %s: not refused, read as absent (allowed: %s)" % (cid, "the vector's own note"))
                continue
            if cid in KEY_NOT_HELD:
                req = _underive(req)
            # No malformed input goes to Jade. A request libwally's own parser rejects, or one malformed by
            # construction, is checked against the parser here and never sent to libjade.
            if cid in MALFORMED_BY_CONSTRUCTION or not wally_parses(req):
                rep.check(cid in MALFORMED_BY_CONSTRUCTION or not wally_parses(req), "vectors:signer refusal malformed, not sent to Jade", cid)
                rep.note("refusal %s: malformed, not sent to Jade (libwally parses it: %s)" % (cid, wally_parses(req)))
                continue
            out, err, dp = try_sign(ctx, req)
            n_ref += 1
            rep.check(err is not None and out is None and dp == 0, "vectors:signer refusal refused", "%s %s" % (cid, "" if err else "ACCEPTED"))
            if err is not None:
                reasons[err.message] += 1
                rep.note("refusal %s -> %s" % (cid, err.message))
                ctx.write_case("refusal", cid, {"description": c["rule"], "input": {"network": J.NETWORK, "psbt": b64(req)},
                                                 "expected_error": err.message})
        rep.note("vector signer refusals: %d replayed, Jade messages: %s" % (n_ref, dict(reasons)))
        wholesale = [n for n in rep.notes if n.startswith("refusal ") and "->" in n and any(
            m in n for m in CATEGORY_MESSAGES)]
        rep.note("refused only because the whole category is refused (%d): %s" % (
            len(wholesale), ", ".join(n.split()[1] for n in wholesale)))
    finally:
        pass


MALFORMED_BY_CONSTRUCTION = {"signer-unsigned-tx-trailing-byte-v0"}


def wally_parses(req):
    import wallycore
    try:
        wallycore.psbt_from_bytes(req, 0)
    except ValueError:
        return False
    return True


def _underive(req):
    p = C.parse(req)
    for m in p.inputs:
        for k, v in list(m.items()):
            if k[:1] in (b"\x06", b"\x16") and len(v) >= 8:
                m[k] = v[:-4] + struct.pack("<I", struct.unpack("<I", v[-4:])[0] ^ 1)
    return p.serialize()


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit", help="write pytest cases (json) for Jade's tests/rpc/data here")
    ap.add_argument("--no-regtest", action="store_true")
    ap.add_argument("--report", help="write the pass counts and notes as json")
    args = ap.parse_args()

    work = HERE / ".work"
    work.mkdir(exist_ok=True)
    tmp = tempfile.mkdtemp(dir=str(work))
    rep = Report()
    chain = None
    if not args.no_regtest and (pathlib.Path(os.environ.get("BITCOIN_BIN") or "/nonexistent-bitcoin-bin") / "bitcoind").exists():
        chain = Chain(work)
    else:
        rep.note("regtest not run")
    jade = J.open_jade()
    ctx = Ctx(jade, rep, tmp, chain, args.emit)
    try:
        section_matrix(ctx)
        section_limits(ctx)
        section_traps(ctx)
        section_vectors(ctx, work)
    finally:
        if chain:
            chain.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    print("passed %d, failed %d" % (rep.passed, len(rep.failed)))
    for g, n in sorted(rep.groups.items()):
        print("  %-12s %d" % (g, n))
    for n in rep.notes:
        print("note:", n)
    if args.report:
        pathlib.Path(args.report).write_text(json.dumps(
            {"passed": rep.passed, "failed": rep.failed, "groups": rep.groups, "notes": rep.notes,
             "emitted": ctx.emitted}, indent=2, default=dict) + "\n")
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())
