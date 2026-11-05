#!/usr/bin/env python3
"""Generate vectors/bip-anti-exfil-psbt.json, vectors/bip-anti-exfil-psbt-seed.json and vectors/bip-anti-exfil-psbt.README.md, the PSBT test
vectors for revision 0.16 of the anti-exfil PSBT document.

Every key is artificial and derived from a labelled seed with SHA256, and `rho` is derived from a labelled
seed too. `rho` is injected only here, through the host's `rho_source` argument; the host's normal path draws
from `secrets`. Every vector is replayed through psbt/signer.py and host.py while it is generated, so a
vector that the reference code does not reproduce stops the run. Nothing is random.

Usage: gen_psbt_vectors.py [--check | --seed-only]
  --check      compares with the files on disk
  --seed-only  writes only vectors/bip-anti-exfil-psbt-seed.json (and the README if its text changes); the main file is not rebuilt or written
"""
import hashlib
import hmac
import json
import os
import pathlib
import shutil
import struct
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKDIR = ROOT / "psbt" / ".work"
OUT = ROOT / "vectors/bip-anti-exfil-psbt.json"
README = ROOT / "vectors/bip-anti-exfil-psbt.README.md"
SEED_OUT = ROOT / "vectors/bip-anti-exfil-psbt-seed.json"
for p in (ROOT / "psbt", ROOT / "psbt" / "tests", ROOT / "reference"):
    sys.path.insert(0, str(p))

import common as K            # noqa: E402  (fixtures: forms, PSBT builders, finalizer)
import anti_exfil as AE       # noqa: E402
import psbt_codec as C        # noqa: E402
import spend as S             # noqa: E402
import signer as SG           # noqa: E402
import host as H              # noqa: E402
import transport as T         # noqa: E402
from test_host_response import edit_core   # noqa: E402

N = AE._N
hx = lambda b: b.hex()


def rho_source(label):
    n = [0]

    def src():
        n[0] += 1
        return hashlib.sha256(("anti-exfil psbt vector/%s/rho/%d" % (label, n[0])).encode()).digest()
    return src


# ------------------------------------------------------------- seed vectors
# BIP32 test vector 1: the seed and the serialized extended private keys of the chains m, m/0H, m/0H/1 and m/0H/1/2H, each with its
# 4-byte double-SHA256 checksum, as published with the BIP (transcribed from the binary form in libwally-core's src/test/test_bip32.py).
BIP32_SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
# The seed of the seed vectors: the mnemonic of the published BIP84 and BIP86 test vectors, empty passphrase, BIP39 seed
# (PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic" + passphrase). A device that stores a mnemonic can hold this seed.
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PASSPHRASE = ""
TEST_SEED = hashlib.pbkdf2_hmac("sha512", MNEMONIC.encode(), ("mnemonic" + PASSPHRASE).encode(), 2048)
BIP32_PUBLISHED = {
    "m": "0488ADE4000000000000000000873DFF81C02F525623FD1FE5167EAC3A55A049DE3D314BB42EE227FFED37D50800E8F32E723DECF4051AEFAC8E2C93C9C5B214313817CDB01A1494B917C8436B35E77E9D71",
    "m/0H": "0488ADE4013442193E8000000047FDACBD0F1097043B78C63C20C34EF4ED9A111D980047AD16282C7AE623614100EDB2E14F9EE77D26DD93B4ECEDE8D16ED408CE149B6CD80B0715A2D911A0AFEA0A794DEC",
    "m/0H/1": "0488ADE4025C1BD648000000012A7857631386BA23DACAC34180DD1983734E444FDBF774041578E9B6ADB37C19003C6CB8D0F6A264C91EA8B5030FADAA8E538B020F0A387421A12DE9319DC93368B34BC442",
    "m/0H/1/2H": "0488ADE403BEF5A2F98000000204466B9CC8E161E966409CA52986C584F07E9DC81F735DB683C3FF6EC7B1503F00CBCE0D719ECF7431D88E6A89FA1483E02E35092AF60C042B1DF2FF59FA424DCA25814A3A",
}
HARD = 0x80000000


def bip32_master(seed):
    i = hmac.new(b"Bitcoin seed", seed, "sha512").digest()
    return i[:32], i[32:]


def bip32_child(k, c, index):
    data = (b"\x00" + k if index & HARD else K.pub33(k)) + struct.pack(">I", index)
    i = hmac.new(c, data, "sha512").digest()
    il = int.from_bytes(i[:32], "big")
    child = (il + int.from_bytes(k, "big")) % N
    assert il < N and child != 0
    return child.to_bytes(32, "big"), i[32:]


def bip32_path(path):
    out = []
    for part in path.split("/")[1:]:
        out.append(int(part[:-1]) | HARD if part[-1] in "H'h" else int(part))
    return out


def bip32_derive(path, seed=TEST_SEED):
    k, c = bip32_master(seed)
    fp = b"\x00" * 4
    for i in bip32_path(path):
        fp = S.hash160(K.pub33(k))[:4]
        k, c = bip32_child(k, c, i)
    return k, c, fp


def bip32_xprv(path, seed=TEST_SEED):
    """Serialized extended private key (with checksum) for the chain, from this code's derivation."""
    idx = bip32_path(path)
    k, c, parent_fp = bip32_derive(path, seed)
    body = (bytes.fromhex("0488ADE4") + bytes([len(idx)]) + parent_fp + struct.pack(">I", idx[-1] if idx else 0) + c + b"\x00" + k)
    return body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]


def check_bip32_against_published():
    """The derivation used for the seed vectors must reproduce the published keys of BIP32 test vector 1 byte for byte. The published
    strings carry their own checksum, so a mistyped constant fails too."""
    for path, want in BIP32_PUBLISHED.items():
        want = bytes.fromhex(want)
        assert hashlib.sha256(hashlib.sha256(want[:78]).digest()).digest()[:4] == want[78:], "published value for %s has a bad checksum" % path
        assert bip32_xprv(path, BIP32_SEED) == want, "BIP32 derivation of %s differs from the published vector" % path
    return sorted(BIP32_PUBLISHED)


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Published with BIP86 and BIP84 for the mnemonic above (bitcoin/bips, bip-0086.mediawiki and bip-0084.mediawiki).
BIP86_ROOTPRIV = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
BIP86_INTERNAL_KEY = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"       # m/86'/0'/0'/0/0, x-only, before tweaking
BIP84_PUBKEY = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"           # m/84'/0'/0'/0/0


def b58check(body):
    data = body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def check_against_bip84_bip86():
    """The seed of the seed vectors and the derivation must reproduce the root key and the first keys that BIP86 and BIP84 publish for the
    mnemonic. The addresses are not compared: this code has no bech32 encoder."""
    assert len(TEST_SEED) == 64
    root = bip32_xprv("m")
    assert b58check(root[:78]) == BIP86_ROOTPRIV, "root key differs from the published BIP86 root key"
    assert K.xonly(bip32_derive("m/86H/0H/0H/0/0")[0]).hex() == BIP86_INTERNAL_KEY, "m/86'/0'/0'/0/0 differs from BIP86"
    assert K.pub33(bip32_derive("m/84H/0H/0H/0/0")[0]).hex() == BIP84_PUBKEY, "m/84'/0'/0'/0/0 differs from BIP84"
    return {"root_key_bip32_serialization": BIP86_ROOTPRIV, "m/86'/0'/0'/0/0 internal key": BIP86_INTERNAL_KEY,
            "m/84'/0'/0'/0/0 public key": BIP84_PUBKEY}


SEED_PATHS = {
    # form: (BIP32 path of the key at index i of the form's key list a, b, c, internal)
    "p2pkh": "m/44H/0H/0H/0/%d",
    "p2sh-p2wpkh": "m/49H/0H/0H/0/%d",
    "p2wpkh": "m/84H/0H/0H/0/%d",
    "p2tr-key": "m/86H/0H/0H/0/%d",
    "p2tr-key-root": "m/86H/0H/0H/0/%d",
    "p2wsh-single": "m/48H/0H/0H/2H/0/%d",
    "p2wsh-2of3": "m/48H/0H/0H/2H/0/%d",
    "p2sh-p2wsh-single": "m/48H/0H/0H/1H/0/%d",
    "p2sh-p2wsh-2of3": "m/48H/0H/0H/1H/0/%d",
}
ROLE_INDEX = {"a": 0, "b": 1, "c": 2, "internal": 3}


class SeedForm(K.Form):
    """A required spend form whose keys come from the BIP39 test seed (mnemonic "abandon ... about") along the standard path of its script type. The PSBT records carry the
    real master fingerprint and the full derivation path of each key."""

    def __init__(self, name, label="seed"):
        tmpl = SEED_PATHS[name]
        self.paths = {}
        keys = {}
        for role, i in ROLE_INDEX.items():
            path = tmpl % i
            keys["%s/%s/%s" % (name, label, role)] = bip32_derive(path)[0]
            self.paths[role] = path
        real = K.seedkey
        K.seedkey = lambda lab: keys.get(lab) or real(lab)
        try:
            super().__init__(name, label)
        finally:
            K.seedkey = real
        self.master_fp = S.hash160(K.pub33(bip32_master(TEST_SEED)[0]))[:4]
        self.role_of = {self.a: "a", self.b: "b", self.c: "c", self.x: "internal"}

    def origin(self, sk):
        role = self.role_of[sk]
        return self.master_fp + b"".join(struct.pack("<I", i) for i in bip32_path(self.paths[role]))

    def fill(self, m):
        if self.taproot:
            m[b"\x17"] = self.internal
            if self.root:
                m[b"\x18"] = self.root
            m[b"\x16" + self.internal] = C.compact(0) + self.origin(self.a)
            return
        if self.redeem is not None:
            m[b"\x04"] = self.redeem
        if self.witness_script is not None:
            m[b"\x05"] = self.witness_script
        for sk in self.held:
            m[b"\x06" + K.pub33(sk)] = self.origin(sk)

    def derivations(self):
        used = self.held + ([self.b] if self.name == "p2tr-key-root" else [])
        return [{"role": self.role_of[sk], "path": self.paths[self.role_of[sk]].replace("H", "'"),
                 "secret_key": hx(sk), "public_key": hx(K.pub33(sk))} for sk in used]


class Gen:
    def __init__(self):
        WORKDIR.mkdir(exist_ok=True)
        self.tmp = tempfile.mkdtemp(dir=str(WORKDIR))

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def rig(self, label, inputs, version, steps=(), **kw):
        K._counter[0] = 0
        return K.Rig(inputs, self.tmp, version=version, link_cls=T.ScriptedLink, steps=list(steps), max_retries=0,
                     rho_source=rho_source(label), device_id="vector-device-" + label, **kw)

    # ------------------------------------------------------------ exchanges
    @staticmethod
    def witness_prev(cid, k, inp):
        """The previous transaction of input k in network serialization with witness data: its one input carries a synthetic witness.
        The txid is that of the form without witness data, as for any other previous transaction."""
        fund = (hashlib.sha256(("anti-exfil psbt vector/%s/witness-funding/%d" % (cid, k)).encode()).digest(), 0, b"", 0xFFFFFFFF)
        tx = C.Tx(2, [fund], [(7, b"\x6a"), (inp.value, inp.form.spk)], 0)
        raw = K.ser_witness_tx(tx, [[b"\x30" + b"\x11" * 70, b"\x02" + b"\x22" * 32]])
        assert raw[4:6] == b"\x00\x01" and C.parse_tx(raw) == tx
        return K.Prev(raw, 1, inp.value, inp.form.spk)

    def exchange(self, cid, desc, names, version, sighashes=None, utxo="non", tweak=None, host_keys=None, signer_keys=None,
                 partial=False, labels=None, make_form=None, witness_prev=False):
        K._counter[0] = 0
        forms = [(make_form or K.Form)(n, lb) for n, lb in zip(names, labels or ["vec"] * len(names))]
        sighashes = sighashes or [None] * len(forms)
        inputs = [K.Inp(f, sighash=h, utxo=utxo) for f, h in zip(forms, sighashes)]
        if witness_prev:
            for k, inp in enumerate(inputs):
                inp.prev = self.witness_prev(cid, k, inp)
        kw = {}
        if host_keys is not None:
            kw["host_keys"] = host_keys(forms)
        if signer_keys is not None:
            kw["signer_keys"] = signer_keys(forms)
        rig = self.rig(cid, inputs, version, **kw)
        if tweak:
            tweak(rig.psbt, forms)
        pairs = K.pairs_of(rig)
        a = rig.host.start(rig.request_bytes)
        rhos = dict(a._rho)
        hcs = dict(a._hc)
        a.commit()
        r0 = dict(a._r0)
        res = a.reveal()
        (q1, r1), (q2, r2) = rig.link.transcript[:2]
        txid, rawtx = (None, None) if partial else K.final_tx(res.psbt, inputs)      # a partial exchange leaves an input unsigned
        out = C.parse(res.psbt)
        held = lambda f: [hx(sk) for sk in (kw["signer_keys"] if "signer_keys" in kw else f.held)]
        return {
            "id": cid, "description": desc, "psbt_version": version,
            "inputs": [{"form": f.name, "seed": "ae16/%s/vec/*" % f.name, "sighash_type": h,
                        "device_secret_keys": held(f), "spent_script": hx(f.spk),
                        "prev_value": i.value} for f, h, i in zip(forms, sighashes, inputs)],
            "device_keys": sorted(hx(k) for k in rig.wallet.keys),
            "pairs": [{"input": pr.index, "key_identifier": hx(pr.keyid), "scheme": pr.scheme,
                       "spend_path": pr.path, "sighash_type": pr.sighash, "m": hx(pr.message),
                       "protocol_pk": hx(pr.pk),
                       "rho": hx(rhos[(pr.index, pr.keyid)]), "hc": hx(hcs[(pr.index, pr.keyid)]),
                       "R0_bytes": hx(r0[(pr.index, pr.keyid)]),
                       "signature_key": hx(pr.sigkey), "signature_field": hx(out.inputs[pr.index][pr.sigkey])}
                      for pr in pairs],
            "host_psbt": hx(rig.request_bytes), "first_request": hx(q1), "first_response": hx(r1),
            "second_request": hx(q2), "second_response": hx(r2), "host_result": hx(res.psbt),
            "final_transaction": rawtx, "final_txid": txid,
        }

    # ------------------------------------------------------------ seed vectors
    def seed_exchanges(self):
        ex = []
        forms = K.REQUIRED_FORMS
        for name in forms:
            for v in (0, 2):
                e = self.exchange("seed-%s-v%d" % (name, v), "One input spending %s from the BIP32 test seed, PSBT version %d." % (name, v), [name], v,
                                  make_form=SeedForm, labels=["seed"])
                ex.append(self._seedify(e, [name]))
        for v in (0, 2):
            e = self.exchange("seed-mixed-v%d" % v, "All nine required spend forms in one transaction, each from the BIP32 test seed, PSBT version %d." % v,
                              list(forms), v, make_form=SeedForm, labels=["seed"] * len(forms))
            ex.append(self._seedify(e, list(forms)))
        return ex

    def _seedify(self, e, names):
        """Replace the label-derived key description by the seed and the paths."""
        for inp, name in zip(e["inputs"], names):
            f = SeedForm(name)
            inp.pop("seed", None)
            inp["derivations"] = f.derivations()
            assert sorted(d["secret_key"] for d in inp["derivations"] if d["role"] in ("a", "b") and d["secret_key"] in inp["device_secret_keys"]) \
                == sorted(inp["device_secret_keys"]), (e["id"], "derived keys differ from the keys the signer holds")
        return e

    # ------------------------------------------------------------ user facts
    def user_facts(self, ex):
        """What the reference tells the user for some exchanges, read from its own callbacks. Fee verification must be a fact the
        text allows: a party may present a verified fee as unverified, never the reverse."""
        out = []
        pick = ["p2wpkh-witness-utxo-only-v0", "p2wpkh-witness-utxo-only-v2", "p2tr-key-sighash-0x81-witness-utxo-only-v0",
                "p2tr-key-witness-utxo-only-v0", "p2wpkh-v0", "p2tr-key-v0", "p2tr-key-sighash-0x81-v0",
                "p2wpkh-input-without-pair-and-without-utxo-data-v0"]
        approvals = ["p2tr-script-v0", "p2wpkh-sighash-0x03-v0", "p2wsh-2of3-v0"]      # what the approval shows, and how often
        byid = {e["id"]: e for e in ex}
        for cid in pick + approvals:
            e = byid[cid]
            seen = {}

            class Ui(H.UI):
                def notify_request(self, info):
                    seen["host"] = info
            host = H.Host(H.Wallet("facts-" + cid, [bytes.fromhex(k) for k in e["device_keys"]]), H.Store(os.path.join(self.tmp, "facts-" + cid)), Ui(), None)
            host.start(bytes.fromhex(e["host_psbt"]))

            def approve(desc, seen=seen):
                seen["signer"] = desc
                seen["approvals"] = seen.get("approvals", 0) + 1
                return True
            SG.Signer([bytes.fromhex(k) for k in sorted({k for i in e["inputs"] for k in i["device_secret_keys"]})], approve).sign(bytes.fromhex(e["second_request"]))
            assert seen["host"]["anti_exfil"] is True and seen["host"]["fee_verified"] == seen["signer"]["fee_verified"], cid
            verified = seen["host"]["fee_verified"]
            if cid in approvals:
                assert seen["approvals"] == 1, cid
                out.append({"id": "uf-approval-" + cid, "exchange": cid, "requires_contract": 3,
                            "rule": "Approval covers what the signature commits to, including the spend path and leaf. After one approval covering the whole PSBT, "
                                    "run step 4 for each pair.",
                            "fee_verified_by_reference": verified, "fee_may_be_presented_as_verified": verified,
                            "approvals_per_second_pass": 1,
                            "approval_pairs": [{"input": g["input"], "sighash_type": g["sighash_type"], "leaf_hash": g["leaf_hash"]}
                                               for g in seen["signer"]["signatures"]]})
                if cid == "p2tr-script-v0":
                    out[-1]["optional_form"] = True
                continue
            out.append({"id": "uf-" + cid, "exchange": cid, "requires_contract": 3,
                        "rule": "Before sending a request, the host MUST tell the user it is requesting anti-exfil signing. A host or signer MUST NOT present a fee as "
                                "verified unless it verified every input amount, either against PSBT_IN_NON_WITNESS_UTXO, or because the request has at least one "
                                "Taproot pair without ANYONECANPAY.",
                        "fee_verified_by_reference": verified, "fee_may_be_presented_as_verified": verified})
        return out

    # ------------------------------------------------------ signer refusals
    def signer_cases(self):
        cases = []

        def add(cid, rule, reason, rig, request, pass_, note="", approve=True):
            sg = rig.signer
            before = len(rig.approve.seen)
            try:
                sg.sign(request)
            except SG.SignerFail as e:
                assert e.code == reason, (cid, e.code, reason)
            else:
                raise AssertionError("signer accepted " + cid)
            if pass_ == "first" or reason != "not_approved":
                assert len(rig.approve.seen) == before, cid + ": prompted before failing"
            cases.append({"id": cid, "rule": rule, "pass": pass_, "request": hx(request), "expected": "signer fails",
                          "reason_code": reason, "signer_holds_seeds_of": [hx(sk) for sk in rig.signer._by_pub33.values()],
                          "note": note})

        def base(name, label, version=0, **kw):
            K._counter[0] = 0
            form = K.Form(name, "vec")
            inp = K.Inp(form, **kw)
            return form, inp, self.rig(label, [inp], version)

        def reqs(rig, psbt=None, pairs=None):
            pairs = pairs or K.pairs_of(rig)
            q1, rhos = K.req_first(psbt or rig.psbt, pairs)
            return q1, K.req_second(psbt or rig.psbt, pairs, rhos), pairs, rhos

        def modify(data, fn):
            p = C.parse(data)
            fn(p)
            return p.serialize()

        form, inp, rig = base("p2wpkh", "sg-base")
        q1, q2, pairs, rhos = reqs(rig)
        kid = pairs[0].keyid
        add("signer-no-ae-fields", "A PSBT with none of these fields is outside this document. Spec: \"An implementation with no ordinary signing path fails or "
            "returns the PSBT unsigned, and a host treats either as a failed attempt.\" This vector applies to an implementation with no ordinary signing path; "
            "the reference is one.", "not_a_request", rig, rig.request_bytes, "first")
        cases[-1]["conditional"] = True
        cases[-1]["condition"] = ("Applies only to an implementation with no ordinary signing path. A signer that has one may sign the PSBT normally, "
                                  "or return it unsigned; it must not answer with any anti-exfil field, and if it fails it must print nothing.")
        add("signer-nonce-only", "Only a nonce commitment: fail.", "nonce_only", rig,
            modify(q1, lambda p: (p.inputs[0].pop(b"\x21" + kid), p.inputs[0].update({b"\x22" + kid: b"\x02" + b"\x11" * 32}))), "first")
        add("signer-first-pass-nonce-differs", "If one is already present and differs from the computed value, fail.", "r0_mismatch", rig,
            modify(q1, lambda p: p.inputs[0].update({b"\x22" + kid: b"\x02" + b"\x01" * 32})), "first")
        q2hc = K.req_second(rig.psbt, pairs, rhos, keep_hc=True)
        add("signer-second-pass-hc-differs", "If a host commitment ... is present and differs from the computed value, fail.", "hc_mismatch", rig,
            modify(q2hc, lambda p: p.inputs[0].update({b"\x21" + kid: b"\x00" * 32})), "second")
        add("signer-second-pass-nonce-differs", "If a ... nonce commitment is present and differs from the computed value, fail.", "r0_mismatch", rig,
            modify(q2hc, lambda p: p.inputs[0].update({b"\x22" + kid: b"\x02" + b"\x01" * 32})), "second")
        add("signer-key-length", "Any other length fails.", "bad_keyid_length", rig,
            modify(q1, lambda p: p.inputs[0].update({b"\x21" + kid + b"\x00": b"\x00" * 32})), "first")
        add("signer-uncompressed-key", "Unsupported: uncompressed public keys.", "bad_keyid_length", rig,
            modify(q1, lambda p: p.inputs[0].update({b"\x21" + b"\x04" + b"\x01" * 64: b"\x00" * 32})), "first")
        add("signer-value-length", "Values have fixed lengths; a party fails on any other length.", "bad_field_length", rig,
            modify(q1, lambda p: p.inputs[0].update({b"\x21" + kid: b"\x00" * 31})), "first")
        # approval
        form2, inp2, rig2 = base("p2wpkh", "sg-approve")
        rig2.signer._approve = K.Approver(False)
        rig2.approve = rig2.signer._approve
        _, q2b, _, _ = reqs(rig2)
        add("signer-not-approved", "The device MUST obtain the user's approval before every run of step 4.", "not_approved", rig2, q2b, "second",
            note="the approval callback answers no; no signature is returned")
        # mixed phases / both paths / already signed / not held
        form3, inp3, rig3 = base("p2wsh-2of3", "sg-multi")
        q1c, q2c, pairs3, rhos3 = reqs(rig3)
        add("signer-mixed-phases", "A request contains one phase; mixed phases fail.", "mixed_phases", rig3,
            modify(q1c, lambda p: p.inputs[0].update({b"\x23" + pairs3[0].keyid: rhos3[(0, pairs3[0].keyid)]})), "first")
        form4, inp4, rig4 = base("p2tr-script", "sg-both")
        q1d, _, pairs4, _ = reqs(rig4)
        add("signer-key-path-and-script-path", "Fails ... if one input has both a key-path and a script-path pair.", "both_paths", rig4,
            modify(q1d, lambda p: p.inputs[0].update({b"\x21" + pairs4[0].keyid[:32]: b"\x00" * 32})), "first")
        for name in ("p2wpkh", "p2tr-key", "p2tr-script"):
            f, i, r = base(name, "sg-signed-" + name)
            pr = K.pairs_of(r)[0]
            p = r.psbt.clone()
            # a well-formed value, so that only the check this vector names can fail: DER r = 1, s = 1 for ECDSA
            p.inputs[0][pr.sigkey] = b"\x30\x06\x02\x01\x01\x02\x01\x01\x01" if pr.scheme == "ecdsa" else b"\x01" * 64
            q, _ = K.req_first(p, [pr])
            add("signer-already-signed-" + name, "It fails if a pair already has a signature.", "already_signed", r, q, "first")
        f, i, r = base("p2wpkh", "sg-nokey")
        pr = K.pairs_of(r)[0]
        r.signer = SG.Signer([K.seedkey("vectors/other-held")], r.approve)
        add("signer-key-not-held", "It fails ... if it does not hold the key.", "key_not_held", r, K.req_first(r.psbt, [pr])[0], "first")
        # sighash
        for h, cid, reason, rule in ((4, "unsupported-value", "sighash_unsupported", "Each party fails on any other value."),
                                     (0x84, "unsupported-acp-value", "sighash_unsupported", "Each party fails on any other value.")):
            f, i, r = base("p2wpkh", "sg-sh" + cid)
            pr = K.pairs_of(r)[0]
            p = r.psbt.clone()
            p.inputs[0][b"\x03"] = struct.pack("<I", h)
            add("signer-sighash-" + cid, rule, reason, r, K.req_first(p, [pr])[0], "first")
        f, i, r = base("p2wpkh", "sg-shzero")
        pr = K.pairs_of(r)[0]
        p = r.psbt.clone()
        p.inputs[0][b"\x03"] = b"\x00\x00\x00\x00"
        add("signer-sighash-present-zero-ecdsa", "... and on a present zero for ECDSA.", "sighash_zero_ecdsa", r, K.req_first(p, [pr])[0], "first",
            note="A signer whose PSBT library cannot tell a present zero from an absent field MAY treat it as absent and sign SIGHASH_ALL.")
        for name in ("p2wpkh", "p2tr-key"):
            for pass_ in ("first", "second"):
                K._counter[0] = 0
                fa = K.Form(name, "vec")
                inputs = [K.Inp(K.Form("p2wpkh", "pad1")), K.Inp(K.Form("p2wpkh", "pad2")), K.Inp(fa, sighash=3)]
                r = self.rig("sg-single-" + name + pass_, inputs, 0, outputs=[(1000, K.out_script())])
                pr = [p for p in K.manual_pairs(r) if p.index == 2]
                q1x, rh = K.req_first(r.psbt, pr)
                add("signer-sighash-single-no-output-%s-%s-pass" % (name, pass_),
                    "Each party fails ... on SIGHASH_SINGLE with no matching output, on either pass.", "sighash_single_no_output", r,
                    q1x if pass_ == "first" else K.req_second(r.psbt, pr, rh), pass_)
        # validation scope
        def scoped(cid, rule, reason, name, tweak, label=None):
            f, i, r = base(name, "sg-" + cid)
            pairs_ = K.pairs_of(r)
            p = r.psbt.clone()
            tweak(p, f)
            q, _ = K.req_first(p, pairs_)
            add("signer-" + cid, rule, reason, r, q, "first")
        scoped("final-scriptsig", "A requested input with a final scriptSig fails.", "finalized_input", "p2wpkh", lambda p, f: p.inputs[0].update({b"\x07": b"\x00"}))
        scoped("final-witness", "A requested input with a final witness fails.", "finalized_input", "p2wpkh", lambda p, f: p.inputs[0].update({b"\x08": b"\x00"}))
        scoped("missing-utxo", "Missing UTXO data fails.", "missing_utxo", "p2wpkh", lambda p, f: p.inputs[0].pop(b"\x00"))
        scoped("non-witness-utxo-wrong-txid", "A NON_WITNESS_UTXO MUST hash to the input's previous txid.", "nonwitness_txid_mismatch", "p2wpkh",
               lambda p, f: p.inputs[0].update({b"\x00": K.fake_prev(f.spk, 100001).txbytes}))
        scoped("redeem-script-mismatch", "Mismatched redeem script fails.", "redeem_script_mismatch", "p2sh-p2wpkh", lambda p, f: p.inputs[0].update({b"\x04": b"\x00\x14" + b"\x01" * 20}))
        scoped("witness-script-missing", "Missing witness script fails.", "witness_script_mismatch", "p2wsh-single", lambda p, f: p.inputs[0].pop(b"\x05"))
        scoped("key-path-internal-key-differs", "A key-path pair fails if PSBT_IN_TAP_INTERNAL_KEY is present and differs from the identifier.",
               "internal_key_mismatch", "p2tr-key", lambda p, f: p.inputs[0].update({b"\x17": K.xonly(K.seedkey("vectors/other-internal"))}))
        def wide(f, prefix, flip=False):
            x, y = K.AE._mul(int.from_bytes(f.a, "big"))
            y = (2**256 - 2**32 - 977) - y if flip else y
            prefix = prefix + (y & 1) if prefix == 6 else prefix
            return b"\x06" + bytes([prefix]) + x.to_bytes(32, "big") + y.to_bytes(32, "big")
        record = "Unsupported: a derivation record whose 65-byte key, with prefix 0x04, 0x06 or 0x07, has the x coordinate of a device key."
        scoped("derivation-record-uncompressed-device-key", record, "uncompressed_key", "p2wpkh",
               lambda p, f: p.inputs[0].update({wide(f, 4): b"\x00" * 4}))
        scoped("derivation-record-uncompressed-other-y", record, "uncompressed_key", "p2wpkh",
               lambda p, f: p.inputs[0].update({wide(f, 4, True): b"\x00" * 4}))
        scoped("derivation-record-hybrid-device-key", record, "uncompressed_key", "p2wpkh",
               lambda p, f: p.inputs[0].update({wide(f, 6): b"\x00" * 4}))
        for name in ("p2pkh", "p2wpkh"):
            scoped("utxo-fields-disagree-" + name, "If both are present on a requested input they MUST agree.", "utxo_disagree", name,
                   lambda p, f: p.inputs[0].update({b"\x01": (99999).to_bytes(8, "little") + C.compact(len(f.spk)) + f.spk}))
        scoped("taproot-output-key-mismatch", "A mismatched Taproot output key fails.", "tap_output_key_mismatch", "p2tr-key", lambda p, f: p.inputs[0].update({b"\x18": b"\x09" * 32}))
        scoped("leaf-script-missing", "Exactly one TAP_LEAF_SCRIPT entry MUST match the leaf hash.", "tap_leaf_missing", "p2tr-script",
               lambda p, f: [p.inputs[0].pop(k) for k in [k for k in p.inputs[0] if k[:1] == b"\x15" and p.inputs[0][k] == f.leaf_script + b"\xc0"]])
        scoped("leaf-script-duplicated", "Exactly one TAP_LEAF_SCRIPT entry MUST match the leaf hash.", "tap_leaf_ambiguous", "p2tr-script",
               lambda p, f: p.inputs[0].update({b"\x15" + bytes([f.control[0] ^ 1]) + f.control[1:]: f.leaf_script + b"\xc0"}))
        scoped("leaf-script-duplicated-honest-first", "Exactly one TAP_LEAF_SCRIPT entry MUST match the leaf hash.", "tap_leaf_ambiguous", "p2tr-script",
               lambda p, f: p.inputs[0].update({b"\x15" + f.control + b"\x07" * 32: f.leaf_script + b"\xc0"}))
        scoped("control-block-wrong", "Its control block MUST compute the spent output key.", "tap_control_mismatch", "p2tr-script",
               lambda p, f: p.inputs[0].update({b"\x15" + f.control[:-1] + bytes([f.control[-1] ^ 1]): p.inputs[0].pop(b"\x15" + f.control)}))
        scoped("musig2-participant", "Unsupported: a Taproot input whose MUSIG2_PARTICIPANT_PUBKEYS lists a device key.", "musig2_participant", "p2tr-key",
               lambda p, f: p.inputs[0].update({b"\x1a" + b"\x02" + b"\x33" * 32: b"\x02" + f.internal + b"\x03" + b"\x44" * 32}))
        K._counter[0] = 0
        fa = K.Form("p2tr-key", "vec")
        mine, other = K.Inp(fa), K.Inp(K.Form("p2wpkh", "foreign"))
        r = self.rig("sg-prevouts", [mine, other], 0, signer_keys=K.held_of([mine]))
        pairs_ = K.pairs_of(r)
        p = r.psbt.clone()
        del p.inputs[1][b"\x00"]
        add("signer-taproot-needs-all-prevouts", "Taproot pairs without ANYONECANPAY also need every input's previous output.", "taproot_prevouts_missing", r,
            K.req_first(p, pairs_)[0], "first")
        # scripts
        f = K.Form("p2wsh-single", "vec")
        f.witness_script = b"\xab" + K.single(K.pub33(f.a))
        f.spk = b"\x00\x20" + C.sha256(f.witness_script)
        K._counter[0] = 0
        inp5 = K.Inp(f)
        r = self.rig("sg-codesep", [inp5], 0)
        add("signer-codeseparator-ecdsa", "The script code for any pair MUST NOT contain OP_CODESEPARATOR as an opcode.", "codeseparator", r,
            K.req_first(r.psbt, K.manual_pairs(r))[0], "first")
        f = K.Form("p2tr-script", "vec")
        K._counter[0] = 0
        script = b"\x50" + K.push(K.xonly(f.a)) + b"\xac"
        _retarget(f, script)
        r = self.rig("sg-opsuccess", [K.Inp(f)], 0)
        add("signer-op-success", "Scripts containing an OP_SUCCESSx opcode fail.", "op_success", r, K.req_first(r.psbt, K.manual_pairs(r))[0], "first")
        f = K.Form("p2tr-script", "vec")
        script = K.push(K.xonly(f.a)) + b"\x75\xac"
        _retarget(f, script)
        r = self.rig("sg-mapping", [K.Inp(f)], 0)
        add("signer-key-not-before-sigop", "Exactly one signature opcode MUST be immediately preceded by a 32-byte direct push of this key.", "tap_mapping", r,
            K.req_first(r.psbt, K.manual_pairs(r))[0], "first")
        self.signer_cases_added(cases, add, base, modify, scoped)
        self.signer_cases_s3(cases, add, base, modify, scoped)
        self.signer_cases_locktime(cases, add, base, modify, scoped)
        self.signer_cases_script(cases, add, base, modify, scoped)
        return cases

    # rules quoted from BIP 370 and BIP 174 (bip-0370.mediawiki, bip-0174.mediawiki)
    LOCK_HEIGHT = ("BIP 370, PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: \"32 bit unsigned little endian integer greater than 0 and less than 500000000 representing the "
                   "minimum block height that this input requires to be set as the transaction's lock time.\"")
    LOCK_TIME = ("BIP 370, PSBT_IN_REQUIRED_TIME_LOCKTIME: \"32 bit unsigned little endian integer greater than or equal to 500000000 representing the "
                 "minimum Unix timestamp that this input requires to be set as the transaction's lock time.\"")
    LOCK_BOTH = ("BIP 370, Test Vectors: \"The timelock for the following PSBTs cannot be computed:\" Case: \"Input 1 has PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 10000, "
                 "Input 2 has PSBT_IN_REQUIRED_TIME_LOCKTIME of 1657048460\"")
    UNSIGNED_TX = "BIP 174, PSBT_GLOBAL_UNSIGNED_TX: \"The transaction in network serialization.\""

    def signer_cases_locktime(self, cases, add, base, modify, scoped):
        """Refusals for required locktime fields of a PSBT version 2 and for an unsigned transaction with a byte after it. Each is valid except for the one rule it names."""
        for cid, field, value, rule, note in (
                ("v2-required-height-zero", b"\x12", 0, self.LOCK_HEIGHT, "the only input requires height 0"),
                ("v2-required-time-below-500000000", b"\x11", 499999999, self.LOCK_TIME, "the only input requires time 499999999, one below the smallest time-based locktime")):
            f, i, r = base("p2wpkh", "sg-" + cid, version=2)
            p = r.psbt.clone()
            p.inputs[0][field] = struct.pack("<I", value)
            add("signer-" + cid, rule, "bad_v2_input", r, K.req_first(p, K.pairs_of(r))[0], "first", note=note)
        K._counter[0] = 0
        inputs = [K.Inp(K.Form("p2wpkh", "vec")), K.Inp(K.Form("p2wpkh", "vec-2"))]
        r = self.rig("sg-v2-incompatible-locktimes", inputs, 2)
        p = r.psbt.clone()
        p.inputs[0][b"\x12"] = struct.pack("<I", 700000)
        p.inputs[1][b"\x11"] = struct.pack("<I", 600000000)
        add("signer-v2-incompatible-required-locktimes", self.LOCK_BOTH, "bad_v2_input", r, K.req_first(p, K.pairs_of(r))[0], "first",
            note="input 0 requires height 700000 only and input 1 requires time 600000000 only, so no field is supported by all of the inputs")
        f, i, r = base("p2wpkh", "sg-unsigned-tx-trailing-byte")
        p = r.psbt.clone()
        p.glob[b"\x00"] += b"\x00"
        add("signer-unsigned-tx-trailing-byte-v0", self.UNSIGNED_TX, "bad_tx", r, K.req_first(p, K.pairs_of(r))[0], "first",
            note="the unsigned transaction is followed by one zero byte")

    @staticmethod
    def nested_witness_script_form(label):
        """A P2SH-P2WSH form whose witness script hashes to the redeem script and holds one key that is not the device's."""
        f = K.Form("p2sh-p2wsh-single", label)
        f.witness_script = K.single(K.pub33(K.seedkey("vectors/not-the-device-key")))
        f.redeem = b"\x00\x20" + C.sha256(f.witness_script)
        f.spk = b"\xa9\x14" + S.hash160(f.redeem) + b"\x87"
        return f

    def signer_cases_script(self, cases, add, base, modify, scoped):
        """A refusal for the witness script of a nested pair. Valid except for the one rule it names."""
        K._counter[0] = 0
        f = self.nested_witness_script_form("vec")
        r = self.rig("sg-key-not-in-witness-script", [K.Inp(f)], 0)
        add("signer-key-not-in-witness-script-p2sh-p2wsh",
            "It fails ... if the script of a non-Taproot pair neither hashes nor pushes its key.", "key_not_in_script", r,
            K.req_first(r.psbt, K.manual_pairs(r))[0], "first",
            note="the witness script hashes to the redeem script, which the P2SH output hashes, and pushes one key that is not the device's")

    def signer_cases_added(self, cases, add, base, modify, scoped):
        """Refusals that are each valid except for the one rule it names."""
        xa = K.xonly
        # a key path and a script path, both held and each valid alone, in one input
        K._counter[0] = 0
        f = K.Form("p2tr-key-root", "vec")
        leaf_hash = S.tap_leaf_hash(0xC0, f.leaf_script)
        r = self.rig("sg-both-valid", [K.Inp(f)], 0, signer_keys=[f.a, f.b])
        p = r.psbt.clone()
        p.inputs[0][b"\x15" + bytes([0xC0 | f.parity]) + f.internal] = f.leaf_script + b"\xc0"
        p.inputs[0][b"\x16" + xa(f.b)] = C.compact(1) + leaf_hash + b"\x00" * 4 + struct.pack("<I", 0x80000000)
        both = [K.KP(0, f.internal, "bip340"), K.KP(0, xa(f.b) + leaf_hash, "bip340")]
        add("signer-key-path-and-script-path-both-valid", "Fails ... if one input has both a key-path and a script-path pair.", "both_paths", r,
            K.req_first(p, both)[0], "first",
            note="the key-path pair and the script-path pair each resolve and are held; only their coexistence is wrong")

        def with_tx(p, fn):
            tx = C.core_tx(p)
            ins = [fn(i) for i in tx.ins]
            p.glob[b"\x00"] = C.ser_tx(C.Tx(tx.version, ins, tx.outs, tx.locktime))
        scoped("non-witness-utxo-index-missing", "A PSBT_IN_NON_WITNESS_UTXO MUST hash to the input's previous txid and contain its output index.",
               "nonwitness_index", "p2wpkh", lambda p, f: with_tx(p, lambda i: (i[0], 9, i[2], i[3])))
        K._counter[0] = 0
        f = K.Form("p2sh-p2wpkh", "vec")
        f.spk = b"\xa9\x14" + S.hash160(b"another redeem script") + b"\x87"
        r = self.rig("sg-redeem-hash", [K.Inp(f)], 0)
        add("signer-redeem-script-hash-mismatch", "A redeem script that does not hash to the spent output's script fails.", "redeem_script_mismatch", r,
            K.req_first(r.psbt, K.manual_pairs(r))[0], "first",
            note="the redeem script is the correct P2WPKH program for the key; the spent output commits to another script")
        # Taproot script path variants
        K._counter[0] = 0
        f = K.Form("p2tr-script", "vec")
        path, node = [], f.leaf_hash
        for j in range(129):
            sib = bytes([j]) * 32
            path.append(sib)
            node = S.tagged("TapBranch", min(node, sib) + max(node, sib))
        _, q, par = S.tweaked_xonly(f.internal, node)
        ctrl = bytes([0xC0 | par]) + f.internal + b"".join(path)
        f.spk, f.control, f.root = b"\x51\x20" + q, ctrl, node
        r = self.rig("sg-depth", [K.Inp(f)], 0)
        p = r.psbt.clone()
        for k in [k for k in p.inputs[0] if k[:1] == b"\x15"]:
            del p.inputs[0][k]
        p.inputs[0][b"\x15" + ctrl] = f.leaf_script + b"\xc0"
        add("signer-control-block-129-elements", "Its control block MUST compute the spent output key, with at most 128 path elements.", "tap_control_depth", r,
            K.req_first(p, [K.KP(0, xa(f.a) + f.leaf_hash, "bip340")])[0], "first",
            note="the 129 siblings do compute the spent output key; only the depth is wrong")
        K._counter[0] = 0
        f = K.Form("p2tr-script", "vec")
        lh = S.tap_leaf_hash(0xC2, f.leaf_script)
        sh = S.tap_leaf_hash(0xC0, f.sibling)
        root = S.tagged("TapBranch", min(lh, sh) + max(lh, sh))
        _, q, par = S.tweaked_xonly(f.internal, root)
        ctrl = bytes([0xC2 | par]) + f.internal + sh
        f.spk, f.control, f.root, f.leaf_hash = b"\x51\x20" + q, ctrl, root, lh
        r = self.rig("sg-leafver", [K.Inp(f)], 0)
        p = r.psbt.clone()
        for k in [k for k in p.inputs[0] if k[:1] == b"\x15"]:
            del p.inputs[0][k]
        p.inputs[0][b"\x15" + ctrl] = f.leaf_script + b"\xc2"
        add("signer-leaf-version-not-c0", "Its leaf version MUST be 0xC0.", "tap_leaf_version", r,
            K.req_first(p, [K.KP(0, xa(f.a) + lh, "bip340")])[0], "first",
            note="the output key is computed with leaf version 0xC2, so the control block and output key agree; only the version is wrong")
        f = K.Form("p2tr-script", "vec")
        K._counter[0] = 0
        _retarget(f, K.push(xa(f.a)) + b"\xac" + K.push(xa(f.a)) + b"\xad")
        r = self.rig("sg-mapping-twice", [K.Inp(f)], 0)
        add("signer-key-before-two-sigops", "Exactly one signature opcode MUST be immediately preceded by a 32-byte direct push of this key.", "tap_mapping", r,
            K.req_first(r.psbt, K.manual_pairs(r))[0], "first",
            note="the key is pushed directly before a CHECKSIG and again before a CHECKSIGADD")
        # SIGHASH_TYPE length
        for name, raw, cid in (("p2wpkh", b"\x01", "ecdsa-one-byte"), ("p2tr-key", b"\x01\x00\x00\x00\x00", "bip340-five-bytes")):
            f, i, r = base(name, "sg-shlen-" + cid)
            pr = K.pairs_of(r)[0]
            p = r.psbt.clone()
            p.inputs[0][b"\x03"] = raw
            add("signer-sighash-length-" + cid, "PSBT_IN_SIGHASH_TYPE is a 32-bit little-endian value; any other length fails.", "sighash_bad_length", r,
                K.req_first(p, [pr])[0], "first", note="read as a little-endian integer the field is 1, a supported value")
        scoped("musig2-aggregate-internal-key", "Unsupported: a key-path input whose internal key is known to be an aggregate.", "musig2_aggregate", "p2tr-key",
               lambda p, f: p.inputs[0].update({b"\x1a" + b"\x02" + f.internal: b"\x02" + b"\x44" * 32 + b"\x03" + b"\x55" * 32}))
        f, i, r = base("p2pkh", "sg-legacy-wit", utxo="wit")
        add("signer-legacy-input-needs-non-witness-utxo", "A legacy input needs PSBT_IN_NON_WITNESS_UTXO.", "legacy_needs_nonwitness", r,
            K.req_first(r.psbt, K.manual_pairs(r))[0], "first", note="the input holds only a WITNESS_UTXO that agrees with the spent output")
        # a multisig key that is not a point
        K._counter[0] = 0
        f = K.Form("p2wsh-2of3", "vec")
        n = 0
        while True:
            n += 1
            bad = b"\x02" + hashlib.sha256(b"not a point %d" % n).digest()
            if AE._parse33(bad) is AE._INF:
                break
        f.witness_script = K.multisig(2, [K.pub33(f.a), K.pub33(f.b), bad])
        f.spk = b"\x00\x20" + C.sha256(f.witness_script)
        r = self.rig("sg-multisig-bad-key", [K.Inp(f)], 0)
        add("signer-multisig-key-not-a-point", "A multisig script whose keys are not all valid compressed keys is not a required form.", "key_ambiguous", r,
            K.req_first(r.psbt, K.manual_pairs(r))[0], "first",
            note="two held keys and a third 33-byte key with prefix 02 whose x is not on the curve")
        f, i, r = base("p2wpkh", "sg-modifiable", version=2)
        add("signer-malformed-tx-modifiable-flags", "PSBT_GLOBAL_TX_MODIFIABLE is one byte; a malformed field fails at parse, before any prompt.", "bad_modifiable", r,
            modify(K.req_first(r.psbt, K.pairs_of(r))[0], lambda p: p.glob.update({b"\x06": b"\x00\x00"})), "first")
        K._counter[0] = 0
        f = K.Form("p2wsh-single", "vec")
        pk = K.pub33(f.a)
        f.witness_script = K.push(pk) + b"\xad" + K.push(pk) + b"\xac"
        f.spk = b"\x00\x20" + C.sha256(f.witness_script)
        r = self.rig("sg-opt-two", [K.Inp(f)], 0)
        add("signer-key-before-checksigverify-and-checksig", "Exactly one OP_CHECKSIG or OP_CHECKSIGVERIFY MUST be immediately preceded by a direct push of the key.",
            "key_ambiguous", r, K.req_first(r.psbt, K.manual_pairs(r))[0], "first",
            note="<K> CHECKSIGVERIFY <K> CHECKSIG: the key precedes two signature opcodes")
        # a key type written as a non-minimal CompactSize hides a signature
        f, i, r = base("p2wpkh", "sg-nonminimal")
        q1 = K.req_first(r.psbt, K.pairs_of(r))[0]
        pk = K.pub33(f.a)
        add("signer-nonminimal-key-type", "A key type written as a non-minimal CompactSize either fails or is read as the same number, and is never treated as an unknown field.",
            "nonminimal_compact", r, modify(q1, lambda p: p.inputs[0].update({b"\xfd\x02\x00" + pk: b"\x30" + b"\x01" * 70})), "first",
            note="the field is a signature for the pair written with a three-byte type; read as the same number it is an existing signature, which also fails")

    def signer_cases_s3(self, cases, add, base, modify, scoped):
        """Further refusals, each valid except for the one rule it names. A case that needs an optional form carries
        optional_form: a signer that does not support the form fails it for that reason, and the vector then proves nothing about the rule."""
        xa = K.xonly
        # value lengths on the second pass
        form, inp, rig = base("p2wpkh", "s3-len")
        pairs = K.pairs_of(rig)
        q1, rhos = K.req_first(rig.psbt, pairs)
        q2 = K.req_second(rig.psbt, pairs, rhos)
        kid = pairs[0].keyid
        add("signer-value-length-rho-second-pass", "Values have fixed lengths: `rho` is 32 bytes. A party fails on any other length.", "bad_field_length", rig,
            modify(q2, lambda p: p.inputs[0].update({b"\x23" + kid: rhos[(0, kid)][:31]})), "second",
            note="the field is the first 31 bytes of the right `rho`")
        add("signer-value-length-rho-long", "Values have fixed lengths: `rho` is 32 bytes. A party fails on any other length.", "bad_field_length", rig,
            modify(q2, lambda p: p.inputs[0].update({b"\x23" + kid: rhos[(0, kid)] + b"\x00"})), "second",
            note="the field is the right `rho` with one byte added")
        r0 = AE.ecdsa_device_commit(rig.signer._secret_for(pairs[0]), pairs[0].message, AE.ecdsa_host_commit(rhos[(0, kid)]))
        add("signer-value-length-r0-second-pass", "Values have fixed lengths: `R0_bytes` is 33 bytes. A party fails on any other length.", "bad_field_length", rig,
            modify(q2, lambda p: p.inputs[0].update({b"\x22" + kid: r0[1:]})), "second",
            note="the field is the right nonce commitment without its prefix byte, 32 bytes")
        # a Taproot key that is not held
        for name, cid in (("p2tr-key", "key-path"), ("p2tr-script", "script-path")):
            f, i, r = base(name, "s3-nokey-" + cid)
            pr = K.pairs_of(r)[0] if name == "p2tr-key" else K.manual_pairs(r)[0]
            r.signer = SG.Signer([K.seedkey("vectors/other-held")], r.approve)
            add("signer-key-not-held-taproot-" + cid, "It fails ... if it does not hold the key.", "key_not_held", r, K.req_first(r.psbt, [pr])[0], "first")
            if name == "p2tr-script":
                cases[-1]["optional_form"] = True
        # a key pushed with OP_PUSHDATA1 is not a direct push
        direct = "A direct push of a key is the single opcode equal to its length, `0x21` for 33 bytes and `0x20` for 32. `OP_PUSHDATA` forms do not count."
        K._counter[0] = 0
        f = K.Form("p2wsh-single", "vec")
        f.witness_script = b"\x4c\x21" + K.pub33(f.a) + b"\xac"
        f.spk = b"\x00\x20" + C.sha256(f.witness_script)
        r = self.rig("s3-pushdata-single", [K.Inp(f)], 0)
        add("signer-pushdata1-key-in-single-key-script", direct, "key_ambiguous", r, K.req_first(r.psbt, K.manual_pairs(r))[0], "first",
            note="`OP_PUSHDATA1 0x21 <key> OP_CHECKSIG`; the key is in the script and is the held one")
        K._counter[0] = 0
        f = K.Form("p2wsh-2of3", "vec")
        pa, pb, pc = K.pub33(f.a), K.pub33(f.b), K.pub33(f.c)
        f.witness_script = bytes([0x52]) + K.push(pa) + b"\x4c\x21" + pb + K.push(pc) + bytes([0x53, 0xAE])
        f.spk = b"\x00\x20" + C.sha256(f.witness_script)
        r = self.rig("s3-pushdata-multisig", [K.Inp(f)], 0)
        add("signer-pushdata1-key-in-multisig", direct, "key_ambiguous", r, K.req_first(r.psbt, K.manual_pairs(r))[0], "first",
            note="a 2-of-3 script in which the second key is pushed with `OP_PUSHDATA1`")
        K._counter[0] = 0
        f = K.Form("p2tr-script", "vec")
        _retarget(f, b"\x4c\x20" + xa(f.a) + b"\xac")
        r = self.rig("s3-pushdata-leaf", [K.Inp(f)], 0)
        add("signer-pushdata1-key-in-leaf-script", direct, "tap_mapping", r, K.req_first(r.psbt, K.manual_pairs(r))[0], "first",
            note="`OP_PUSHDATA1 0x20 <x-only key> OP_CHECKSIG` in the only leaf")
        cases[-1]["optional_form"] = True
        # multisig shapes
        shape = "`OP_m <key> ... <key> OP_n OP_CHECKMULTISIG`, with `1 <= m <= n <= 16`, ... and each key a direct push of a valid 33-byte key."
        for cid, mk, note in (
                ("m-greater-than-n", lambda a, b: bytes([0x53]) + K.push(a) + K.push(b) + bytes([0x52, 0xAE]), "`OP_3 <a> <b> OP_2 OP_CHECKMULTISIG`"),
                ("n-above-key-count", lambda a, b: bytes([0x52]) + K.push(a) + K.push(b) + bytes([0x53, 0xAE]), "`OP_2 <a> <b> OP_3 OP_CHECKMULTISIG`: n is 3 and two keys follow"),
                ("n-below-key-count", lambda a, b: bytes([0x51]) + K.push(a) + K.push(b) + K.push(K.pub33(K.seedkey("s3/third"))) + bytes([0x52, 0xAE]),
                 "`OP_1 <a> <b> <c> OP_2 OP_CHECKMULTISIG`: n is 2 and three keys precede it")):
            K._counter[0] = 0
            f = K.Form("p2wsh-2of3", "vec")
            f.witness_script = mk(K.pub33(f.a), K.pub33(f.b))
            f.spk = b"\x00\x20" + C.sha256(f.witness_script)
            r = self.rig("s3-shape-" + cid, [K.Inp(f)], 0)
            add("signer-multisig-" + cid, shape, "key_ambiguous", r, K.req_first(r.psbt, K.manual_pairs(r))[0], "first", note=note)
        # MuSig2 participant in the odd-y form
        scoped("musig2-participant-odd-y", "Unsupported: a Taproot input with a pair whose MUSIG2_PARTICIPANT_PUBKEYS lists a device key, in either parity form.",
               "musig2_participant", "p2tr-key",
               lambda p, f: p.inputs[0].update({b"\x1a" + b"\x02" + b"\x33" * 32: b"\x03" + f.internal + b"\x03" + b"\x44" * 32}))
        # outputs exceeding inputs
        f, i, r = base("p2wpkh", "s3-exceed")
        K._counter[0] = 0
        inp = K.Inp(K.Form("p2wpkh", "vec"))
        r = self.rig("s3-exceed", [inp], 0, outputs=[(inp.value + 1, K.out_script())])
        add("signer-outputs-exceed-inputs", "When every input has a valid UTXO field, each party fails if the outputs exceed the inputs.", "outputs_exceed_inputs", r,
            K.req_first(r.psbt, K.pairs_of(r))[0], "first", note="one input of 100000 and one output of 100001")
        # a derivation record that names a key the script does not hash
        for name in ("p2pkh", "p2wpkh", "p2sh-p2wpkh"):
            K._counter[0] = 0
            f = K.Form(name, "vec")
            r = self.rig("s3-keyhash-" + name, [K.Inp(f)], 0, signer_keys=[f.a, f.b])
            p = r.psbt.clone()
            rec = p.inputs[0].pop(b"\x06" + K.pub33(f.a))
            p.inputs[0][b"\x06" + K.pub33(f.b)] = rec
            add("signer-key-hash-mismatch-" + name, "It fails ... if the script of a non-Taproot pair neither hashes nor pushes its key.", "key_not_in_script", r,
                K.req_first(p, [K.KP(0, K.pub33(f.b), "ecdsa")])[0], "first",
                note="the signer holds both keys; the record and the pair name the second, and the script commits to the first")

    def host_cases(self):
        cases = []

        def run(cid, rule, reason, names, version, steps, sighashes=None, max_retries=0, prepare=None, replay_note=""):
            K._counter[0] = 0
            forms = [K.Form(n, "vec") for n in names]
            inputs = [K.Inp(f, sighash=(sighashes or [None] * len(forms))[j]) for j, f in enumerate(forms)]
            rig = K.Rig(inputs, self.tmp, version=version, link_cls=T.ScriptedLink, steps=list(steps), max_retries=max_retries,
                        rho_source=rho_source(cid), device_id="vector-device-" + cid)
            if prepare:
                prepare(rig, forms)
            try:
                rig.host.sign(rig.request_bytes)
            except H.AttemptFailed as e:
                assert e.reasons[0] == reason or reason in e.reasons, (cid, e.reasons)
            else:
                raise AssertionError("host accepted " + cid)
            assert rig.store.failures(rig.wallet.device_id) == 1, cid
            cases.append({"id": cid, "rule": rule, "psbt_version": version, "host_psbt": hx(rig.request_bytes),
                          "device_keys": sorted(hx(k) for k in rig.wallet.keys), "max_retries": max_retries,
                          "exchanges": [{"request": hx(q), "response": hx(r) if r is not None else None} for q, r in rig.link.transcript],
                          "expected": "host fails the attempt, uses no signature, and records one failure",
                          "reason_code": reason, "note": replay_note})

        first_core = lambda how: T.tamper(lambda p: edit_core(p, how))
        for v in (0, 2):
            for pas, steps in (("first", lambda s: [s]), ("second", lambda s: [T.honest, s])):
                run("host-core-tx-changed-%s-pass-v%d" % (pas, v), "The host fails the attempt if the core transaction differs from the request.",
                    "core_tx_changed", ["p2wpkh"], v, steps(first_core("output_value")))
        run("host-commitment-missing", "The host fails the attempt if a requested commitment is missing.", "commitment_missing", ["p2wsh-2of3"], 0,
            [T.tamper(lambda p: p.inputs[0].pop([k for k in p.inputs[0] if k[:1] == b"\x22"][0]))])
        run("host-commitment-not-a-point", "Store each nonce commitment, failing if one fails parse33.", "bad_commitment", ["p2wpkh"], 0,
            [T.change_r0(new=b"\x05" + b"\x01" * 32)])
        run("host-signature-missing", "The host fails the attempt if a requested signature is missing.", "signature_missing", ["p2wsh-2of3"], 0,
            [T.honest, T.tamper(lambda p: p.inputs[0].pop([k for k in p.inputs[0] if k[:1] == b"\x02"][0]))])

        def leftover(typ):
            def f(p):
                f_ = K.Form("p2wpkh", "vec")
                kid = K.pub33(f_.a)
                val = {0x21: b"\x00" * 32, 0x23: b"\x00" * 32}[typ]
                p.inputs[0][bytes([typ]) + kid] = val
            return T.tamper(f)
        run("host-second-pass-holds-hc", "A second-pass response holds any anti-exfil field.", "ae_field_in_second_pass", ["p2wpkh"], 0, [T.honest, leftover(0x21)])
        run("host-second-pass-holds-rho", "A second-pass response holds any anti-exfil field.", "ae_field_in_second_pass", ["p2wpkh"], 0, [T.honest, leftover(0x23)])
        run("host-first-pass-holds-rho", "A first-pass response holds PSBT_IN_AE_HOST_RANDOMNESS.", "rho_in_first_pass", ["p2wpkh"], 0, [leftover(0x23)])
        run("host-unrequested-pair", "Either response holds an anti-exfil field for a pair that was not requested.", "unrequested_pair", ["p2wsh-2of3"], 0,
            [T.tamper(lambda p: p.inputs[0].update({b"\x22" + b"\x02" + b"\x42" * 32: b"\x02" + b"\x01" * 32}))])
        run("host-host-commitment-echo-differs", "A commitment for a pair differs from one the host holds for this attempt.", "commitment_differs", ["p2wpkh"], 0,
            [T.tamper(lambda p: p.inputs[0].update({[k for k in p.inputs[0] if k[:1] == b"\x21"][0]: b"\x00" * 32}))])
        # signature fields
        def foreign(rig, forms):
            f = forms[0]
            rig.psbt.inputs[0][b"\x02" + K.pub33(f.c)] = b"\x30" + b"\x01" * 70
            rig.signer = rig.signer
        def mk2of3(extra):
            return extra
        run("host-first-pass-adds-signature", "A signature field is added ... relative to the request.", "signature_added", ["p2wsh-2of3"], 0,
            [T.tamper(lambda p: p.inputs[0].update({b"\x02" + b"\x02" + b"\x07" * 32: b"\x30" * 70}))])
        def other_final(rig, forms):
            rig.psbt.inputs[0][b"\x02" + K.pub33(forms[0].a)] = b"\x30\x06\x02\x01\x01\x02\x01\x01\x01"
        run("host-signature-removed", "A signature field is removed from an input that has no final scriptSig or final witness in the request.",
            "signature_removed", ["p2wsh-2of3"], 0,
            [T.tamper(lambda p: p.inputs[0].pop(b"\x02" + K.pub33(K.Form("p2wsh-2of3", "vec").c)))],
            prepare=foreign)
        run("host-second-pass-changes-signature", "A signature field is ... changed relative to the request.", "signature_changed", ["p2wsh-2of3"], 0,
            [T.honest, T.tamper(lambda p: p.inputs[0].update({b"\x02" + K.pub33(K.Form("p2wsh-2of3", "vec").c): b"\x31" * 70}))],
            prepare=foreign)
        # step 4
        def sigmut(fn):
            def f(p):
                k = [k for k in p.inputs[0] if k[:1] in (b"\x02", b"\x13", b"\x14")][0]
                p.inputs[0][k] = fn(p.inputs[0][k])
            return T.tamper(f)
        flip = lambda off: (lambda v: v[:off] + bytes([v[off] ^ 1]) + v[off + 1:])
        run("host-ecdsa-bit-flipped", "The host runs step 5; a signature that fails it is rejected.", "verify_failed", ["p2wpkh"], 0, [T.honest, sigmut(flip(10))])
        run("host-bip340-key-path-bit-flipped", "The host runs step 5; a signature that fails it is rejected.", "verify_failed", ["p2tr-key"], 0, [T.honest, sigmut(flip(40))])
        run("host-bip340-script-path-bit-flipped", "The host runs step 5; a signature that fails it is rejected.", "verify_failed", ["p2tr-script"], 0, [T.honest, sigmut(flip(3))])
        run("host-ecdsa-wrong-sighash-byte", "The sighash type in the response MUST be the expected one.", "wrong_sighash", ["p2wpkh"], 0, [T.honest, sigmut(lambda v: v[:-1] + b"\x02")])
        run("host-bip340-wrong-sighash-byte", "The sighash type in the response MUST be the expected one.", "wrong_sighash", ["p2tr-key"], 0,
            [T.honest, sigmut(lambda v: v[:-1] + b"\x02")], sighashes=[1])
        run("host-bip340-default-with-trailing-byte", "A BIP340 signature has a trailing sighash byte unless the type is SIGHASH_DEFAULT.", "bad_sig_length", ["p2tr-key"], 0,
            [T.honest, sigmut(lambda v: v + b"\x01")])
        run("host-ecdsa-not-strict-der", "A field that is not strict DER (BIP 66) fails.", "bad_der", ["p2wpkh"], 0,
            [T.honest, sigmut(lambda v: b"\x30\x81" + v[1:])])

        def high_s(v):
            r, s, h = S.parse_der_sig(v)
            return S.sigfield("ecdsa", h, r, N - s)
        run("host-ecdsa-high-s", "Protocol step 5: 0 < s <= (n - 1) / 2.", "verify_failed", ["p2wpkh"], 0, [T.honest, sigmut(high_s)])
        # a valid signature by the right key whose nonce is not W
        for name in ("p2tr-key", "p2tr-script", "p2wpkh"):
            def wrong_nonce(req, real, name=name):
                resp = real(req)
                if not any(k[:1] == b"\x23" for m in C.parse(req).inputs for k in m):
                    return resp
                f = K.Form(name, "vec")
                K._counter[0] = 0
                inp = K.Inp(f)
                rig0 = K.Rig([inp], self.tmp, version=0)
                pr = K.pairs_of(rig0)[0]
                sk = rig0.signer._secret_for(pr)
                d0 = int.from_bytes(sk, "big")
                k = int.from_bytes(hashlib.sha256(b"anti-exfil psbt vector/other nonce").digest(), "big") % N
                p = C.parse(resp)
                if pr.scheme == "bip340":
                    d = d0 if AE._mul(d0)[1] % 2 == 0 else N - d0
                    W = AE._mul(k)
                    kk = k if W[1] % 2 == 0 else N - k
                    rb = AE._b32(W[0])
                    e = int.from_bytes(AE._tagged_hash("BIP0340/challenge", rb + pr.pk + pr.message), "big") % N
                    sig = rb + AE._b32((kk + e * d) % N)
                    assert AE._schnorr_verify(pr.pk, pr.message, sig)
                    field = S.sigfield("bip340", pr.sighash, sig)
                else:
                    r = AE._mul(k)[0] % N
                    z = int.from_bytes(pr.message, "big") % N
                    s = pow(k, N - 2, N) * (z + r * d0) % N
                    s = s if s <= (N - 1) // 2 else N - s
                    field = S.sigfield("ecdsa", pr.sighash, r, s)
                p.inputs[pr.index][pr.sigkey] = field
                return p.serialize()
            run("host-valid-signature-wrong-nonce-" + name, "Step 5: bytes32(x(W)) equals the first 32 bytes of sig. A valid signature by the right key with another nonce fails.",
                "verify_failed", [name], 0, [T.honest, wrong_nonce],
                replay_note="the signature in the second response verifies as an ordinary signature for the key; it is rejected because its nonce is not W")
        # R0 changes
        def reject_pair1(req, real):
            p = C.parse(real(req))
            ks = sorted(k for k in p.inputs[0] if k[:1] == b"\x22")
            p.inputs[0][ks[1]] = b"\x05" + b"\x01" * 32
            return p.serialize()
        K._counter[0] = 0
        run("host-r0-changed-after-rejected-response", "MUST end the attempt as failed if R0_bytes differs from any value received for that attempt, including one in a response it rejected.",
            "r0_changed", ["p2wsh-2of3"], 0, [reject_pair1, T.change_r0(0)], max_retries=3)
        run("host-r0-changed-in-second-pass-response", "MUST end the attempt as failed if R0_bytes differs from any value received for that attempt.",
            "r0_changed", ["p2wpkh"], 0,
            [T.honest, T.tamper(lambda p: p.inputs[0].update({b"\x22" + K.pub33(K.Form("p2wpkh", "vec").a): b"\x03" + b"\x09" * 32}))], max_retries=3)
        # further cases
        seen_r0 = {}

        def keep_r0(req, real):
            resp = real(req)
            seen_r0.update({k: v for k, v in C.parse(resp).inputs[0].items() if k[:1] == b"\x22"})
            return resp
        run("host-second-pass-holds-r0", "A second-pass response holds any anti-exfil field.", "ae_field_in_second_pass", ["p2wpkh"], 0,
            [keep_r0, T.tamper(lambda p: p.inputs[0].update(seen_r0))],
            replay_note="the second response repeats the nonce commitment the device sent in the first")
        run("host-second-pass-adds-signature-for-unrequested-key", "A signature field is added ... relative to the request.", "signature_added", ["p2wsh-2of3"], 0,
            [T.honest, T.tamper(lambda p: p.inputs[0].update({b"\x02" + K.pub33(K.Form("p2wsh-2of3", "vec").c): b"\x30" + b"\x01" * 70}))],
            replay_note="the signatures for the two requested pairs are valid; the extra one is for the third key of the script")

        def der_int(x):
            b = x.to_bytes(32, "big").lstrip(b"\x00")
            return b if b[0] < 0x80 else b"\x00" + b

        def der(r, s_, h, pad_r=0, tail=b"", outer=0):
            rb, sb = (b"\x00" * pad_r + r.to_bytes(32, "big") if pad_r else der_int(r)), der_int(s_)
            body = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb + tail
            return b"\x30" + bytes([len(body) + outer]) + body + bytes([h])
        for cid, kw, note in (("r-zero-padded", {"pad_r": 4}, "r carries four leading zero bytes"),
                              ("trailing-byte", {"tail": b"\x00"}, "one extra byte inside the sequence"),
                              ("outer-length-short", {"outer": -1}, "the outer length is one less than the contents")):
            def f(v, kw=kw):
                r, s_, h = S.parse_der_sig(v)
                return der(r, s_, h, **kw)
            run("host-ecdsa-der-" + cid, "A field that is not strict DER (BIP 66) fails.", "bad_der", ["p2wpkh"], 0,
                [T.honest, sigmut(f)], replay_note="r and s are those of the valid signature; " + note)

        def tx_changed(req, real):
            return T.tamper(lambda p: edit_core(p, "output_value"))(req, real)
        run("host-r0-changed-after-rejected-response-single-pair", "MUST end the attempt as failed if R0_bytes differs from any value received for that attempt, including one in a response it rejected.",
            "r0_changed", ["p2wpkh"], 0, [tx_changed, T.change_r0(0)], max_retries=3,
            replay_note="the first response is rejected for a changed transaction and carries the device's R0_bytes; the second is otherwise acceptable with the other parity form")
        captured = []

        def not_hex(req, real):
            captured.append(req)
            raise ValueError("the response line is not hex")
        run("host-response-line-is-not-hex", "A failure event is ... a malformed or missing response.", "LinkDisconnected", ["p2wpkh"], 0, [not_hex],
            replay_note="the line the device sent is the text 'not hex', not a PSBT in hex")
        cases[-1]["exchanges"] = [{"request": hx(captured[0]), "response": "not hex"}]
        # integers that parse to a signature that verifies, in a form BIP 66 forbids
        def padded(v):
            r, s_, h = S.parse_der_sig(v)
            return der(r, s_, h, pad_r=1 if r < 1 << 255 else 2)
        run("host-ecdsa-der-non-minimal-integer", "A field that is not strict DER (BIP 66) fails.", "bad_der", ["p2wpkh"], 0, [T.honest, sigmut(padded)],
            replay_note="r is written with a useless leading zero byte (two when its top bit is set); the integers are those of the valid signature")

        def negative(v):
            r, s_, h = S.parse_der_sig(v)
            assert r >= 1 << 255, "this vector needs a signature whose r has its top bit set"
            body = b"\x02\x20" + r.to_bytes(32, "big") + b"\x02" + bytes([len(der_int(s_))]) + der_int(s_)
            return b"\x30" + bytes([len(body)]) + body + bytes([h])
        run("host-ecdsa-der-negative-integer", "A field that is not strict DER (BIP 66) fails.", "bad_der", ["p2pkh"], 0, [T.honest, sigmut(negative)],
            replay_note="r is written in 32 bytes with its top bit set, which DER reads as a negative integer; as an unsigned number it is the valid r")

        # an integer with length byte zero
        def empty_s(v):
            r, s_, h = S.parse_der_sig(v)
            body = b"\x02" + bytes([len(der_int(r))]) + der_int(r) + b"\x02\x00"
            return b"\x30" + bytes([len(body)]) + body + bytes([h])

        def empty_r(v):
            r, s_, h = S.parse_der_sig(v)
            body = b"\x02\x00\x02" + bytes([len(der_int(s_))]) + der_int(s_)
            return b"\x30" + bytes([len(body)]) + body + bytes([h])
        run("host-ecdsa-der-s-length-zero", "A field that is not strict DER (BIP 66) fails.", "bad_der", ["p2wpkh"], 0, [T.honest, sigmut(empty_s)],
            replay_note="the sequence is consistent and r is that of the valid signature; the length byte of s is 0 and s has no bytes")
        run("host-ecdsa-der-r-length-zero", "A field that is not strict DER (BIP 66) fails.", "bad_der", ["p2wpkh"], 0, [T.honest, sigmut(empty_r)],
            replay_note="the sequence is consistent and s is that of the valid signature; the length byte of r is 0 and r has no bytes")

        # a strict DER integer that does not fit in 32 bytes
        def s_two_to_the_256(v):
            r, s_, h = S.parse_der_sig(v)
            body = b"\x02" + bytes([len(der_int(r))]) + der_int(r) + b"\x02\x21\x01" + b"\x00" * 32
            return b"\x30" + bytes([len(body)]) + body + bytes([h])
        run("host-ecdsa-der-s-two-to-the-256", "A field that is not strict DER (BIP 66) fails.", "bad_der", ["p2wpkh"], 0, [T.honest, sigmut(s_two_to_the_256)],
            replay_note="r is that of the valid signature; s is written in 33 bytes as 2^256, which is minimal DER and positive but does not fit in the 32 bytes of the "
                        "protocol's sig")
        return cases

    def host_accepts(self):
        cases = []
        for cid, final, value in (("finalized-witness", b"\x08", b"\x02\x01\x01\x01\x02"), ("finalized-scriptsig", b"\x07", b"\x00")):
            cid = "host-accepts-signature-dropped-from-" + cid
            K._counter[0] = 0
            mine, other = K.Form("p2wpkh", "vec"), K.Form("p2wpkh", "vec-other")
            key = b"\x02" + K.pub33(other.a)
            drop = T.tamper(lambda p: p.inputs[1].pop(key))
            rig = K.Rig([K.Inp(mine), K.Inp(other)], self.tmp, link_cls=T.ScriptedLink, steps=[drop, drop], signer_keys=[mine.a],
                        rho_source=rho_source(cid), device_id="vector-device-" + cid)
            rig.psbt.inputs[1][key] = b"\x30\x06\x02\x01\x01\x02\x01\x01\x01"
            rig.psbt.inputs[1][final] = value
            res = rig.host.sign(rig.request_bytes)
            assert rig.store.failures(rig.wallet.device_id) == 0, cid
            assert key in C.parse(res.psbt).inputs[1], cid
            cases.append({"id": cid,
                          "rule": "A signature field is removed from an input that has no final scriptSig or final witness in the request.",
                          "psbt_version": 0, "host_psbt": hx(rig.request_bytes),
                          "device_keys": sorted(hx(k) for k in rig.wallet.keys), "max_retries": 0,
                          "exchanges": [{"request": hx(q), "response": hx(r)} for q, r in rig.link.transcript],
                          "host_result": hx(res.psbt),
                          "expected": "host accepts and records no failure",
                          "note": "Input 1 has no pair and is finalized. The responses lack its leftover partial signature, as they do from a signer whose PSBT library drops it when serializing."})
        # acceptance cases
        def accept(cid, rule, rig, note, version=0):
            res = rig.host.sign(rig.request_bytes)
            assert rig.store.failures(rig.wallet.device_id) == 0, cid
            cases.append({"id": cid, "rule": rule, "psbt_version": version, "host_psbt": hx(rig.request_bytes),
                          "device_keys": sorted(hx(k) for k in rig.wallet.keys), "max_retries": 0,
                          "exchanges": [{"request": hx(q), "response": hx(r)} for q, r in rig.link.transcript],
                          "host_result": hx(res.psbt), "expected": "host accepts and records no failure", "note": note})
        cid = "host-accepts-uncompressed-record-of-a-key-that-is-not-a-device-key"
        K._counter[0] = 0
        f = K.Form("p2wpkh", "vec")
        rig = K.Rig([K.Inp(f)], self.tmp, link_cls=T.ScriptedLink, steps=[], rho_source=rho_source(cid), device_id="vector-device-" + cid)
        x, y = AE._mul(int.from_bytes(K.seedkey("vectors/not-a-device-key"), "big"))
        rig.psbt.inputs[0][b"\x06" + b"\x04" + AE._b32(x) + AE._b32(y)] = b"\x00" * 8
        accept(cid, "Uncompressed keys that are not device keys are not examined.", rig,
               "Input 0 has a pair and also a derivation record with an uncompressed key that is not a device key. A signer that holds a seed and cannot tell "
               "MAY fail on it (\"A signer that cannot tell whether such a key is a device key, because it holds a seed and not a list of keys, MAY fail on any "
               "uncompressed derivation record\"), so only the host is tested: the responses are those of a signer that holds a list of keys.")

        def unsorted(req, real):
            p = C.parse(real(req))
            body = lambda m: b"".join(C.blob(k) + C.blob(m[k]) for k in sorted(m, reverse=True)) + b"\x00"
            return C.MAGIC + body(p.glob) + b"".join(body(m) for m in p.inputs) + b"".join(body(m) for m in p.outputs)
        cid = "host-accepts-responses-with-maps-in-any-order"
        K._counter[0] = 0
        f = K.Form("p2wsh-2of3", "vec")
        rig = K.Rig([K.Inp(f)], self.tmp, link_cls=T.ScriptedLink, steps=[unsorted, unsorted], rho_source=rho_source(cid), device_id="vector-device-" + cid)
        accept(cid, "The host compares maps by key and does not depend on their order.", rig,
               "Both responses hold the same fields as the honest ones, written with the keys of every map in descending order.")
        return cases

    def request_refusals(self):
        cases = []

        def add(cid, rule, reason, names, version, tweak, host_keys=None, optional=True, labels=None):
            K._counter[0] = 0
            forms = [K.Form(n, lb) for n, lb in zip(names, labels or ["vec"] * len(names))]
            inputs = [K.Inp(f) for f in forms]
            kw = {}
            if host_keys is not None:
                kw["host_keys"] = host_keys(forms)
            rig = K.Rig(inputs, self.tmp, version=version, device_id="vector-device-" + cid, **kw)
            tweak(rig, forms)
            try:
                rig.host.start(rig.request_bytes)
            except H.HostRefusal as e:
                assert e.code == reason, (cid, e.code)
            else:
                raise AssertionError("host started " + cid)
            assert not rig.store.data["devices"], cid
            cases.append({"id": cid, "rule": rule, "psbt_version": version, "host_psbt": hx(rig.request_bytes),
                          "device_keys": sorted(hx(k) for k in rig.wallet.keys),
                          "expected": "host refuses before recording an attempt; no request is sent", "reason_code": reason})
        for v in (0, 2):
            add("host-request-has-ae-field-v%d" % v, "It fails before recording an attempt if its PSBT already holds these fields.", "preexisting_ae_field",
                ["p2wpkh"], v, lambda r, f: r.psbt.inputs[0].update({b"\x21" + b"\x02" + b"\x01" * 32: b"\x00" * 32}))
        add("host-no-pairs", "... or if no pairs remain.", "no_pairs", ["p2wpkh"], 0, lambda r, f: None,
            host_keys=lambda f: [K.pub33(K.seedkey("not the device"))])
        add("host-all-pairs-already-signed", "The host skips a pair whose signature is already in its PSBT; if no pairs remain it refuses.", "no_pairs", ["p2tr-key"], 0,
            lambda r, f: r.psbt.inputs[0].update({b"\x13": b"\x00" * 64}))

        def dup_key(r, f):
            fm = f[0]
            pa = K.pub33(fm.a)
            fm.witness_script = K.multisig(2, [pa, K.pub33(fm.b), pa])
            fm.spk = b"\x00\x20" + C.sha256(fm.witness_script)
        K._counter[0] = 0
        fm = K.Form("p2wsh-2of3", "vec")
        dup_key(None, [fm])
        inp = K.Inp(fm)
        rig = K.Rig([inp], self.tmp, device_id="vector-device-dup")
        try:
            rig.host.start(rig.request_bytes)
        except H.HostRefusal as e:
            assert e.code == "key_ambiguous"
        cases.append({"id": "host-key-twice-in-multisig", "rule": "It fails ... if any pair is ambiguous or unsupported.", "psbt_version": 0,
                      "host_psbt": hx(rig.request_bytes), "device_keys": sorted(hx(k) for k in rig.wallet.keys),
                      "expected": "host refuses before recording an attempt; no request is sent", "reason_code": "key_ambiguous"})

        def unc(r, f):
            P = AE._mul(int.from_bytes(f[0].a, "big"))
            r.psbt.inputs[0][b"\x06" + b"\x04" + AE._b32(P[0]) + AE._b32(P[1])] = b"\x00" * 8
        add("host-uncompressed-device-key", "Unsupported: uncompressed public keys.", "uncompressed_key", ["p2pkh"], 0, unc)
        add("host-musig2-participant", "Unsupported: a Taproot input whose MUSIG2_PARTICIPANT_PUBKEYS lists a device key.", "musig2_participant", ["p2tr-key"], 0,
            lambda r, f: r.psbt.inputs[0].update({b"\x1a" + b"\x02" + b"\x33" * 32: b"\x02" + f[0].internal}))
        add("host-unsupported-sighash", "Each party fails on any other value.", "sighash_unsupported", ["p2wpkh"], 0,
            lambda r, f: r.psbt.inputs[0].update({b"\x03": struct.pack("<I", 4)}))
        # further cases

        def hybrid(r, f):
            x, y = AE._mul(int.from_bytes(f[0].a, "big"))
            r.psbt.inputs[0][b"\x06" + bytes([6 + (y & 1)]) + AE._b32(x) + AE._b32(y)] = b"\x00" * 8
        add("host-hybrid-device-key", "Unsupported: a derivation record whose 65-byte key, with prefix 0x04, 0x06 or 0x07, has the x coordinate of a device key.",
            "uncompressed_key", ["p2wpkh"], 0, hybrid)
        add("host-malformed-tx-modifiable-flags-v2", "PSBT_GLOBAL_TX_MODIFIABLE is one byte; a malformed field fails at parse.", "bad_modifiable", ["p2wpkh"], 2,
            lambda r, f: r.psbt.glob.update({b"\x06": b"\x00\x00"}))
        # further cases
        add("host-musig2-participant-odd-y", "Unsupported: a Taproot input with a pair whose MUSIG2_PARTICIPANT_PUBKEYS lists a device key, in either parity form.",
            "musig2_participant", ["p2tr-key"], 0,
            lambda r, f: r.psbt.inputs[0].update({b"\x1a" + b"\x02" + b"\x33" * 32: b"\x03" + f[0].internal + b"\x03" + b"\x44" * 32}))

        def exceed(r, f):
            tx = C.core_tx(r.psbt)
            r.psbt.glob[b"\x00"] = C.ser_tx(C.Tx(tx.version, tx.ins, [(tx.outs[0][0] + 100000, tx.outs[0][1])] + tx.outs[1:], tx.locktime))
        add("host-outputs-exceed-inputs", "When every input has a valid UTXO field, each party fails if the outputs exceed the inputs.", "outputs_exceed_inputs",
            ["p2wpkh"], 0, exceed)
        for name in ("p2pkh", "p2wpkh", "p2sh-p2wpkh"):
            def other_key(r, f):
                rec = r.psbt.inputs[0].pop(b"\x06" + K.pub33(f[0].a))
                r.psbt.inputs[0][b"\x06" + K.pub33(f[0].b)] = rec
            add("host-key-not-in-script-" + name, "It fails before recording an attempt ... if a derivation record names a device key the input's script does not contain.",
                "key_not_in_script", [name], 0, other_key, host_keys=lambda f: [K.pub33(f[0].b)])

        def custom(cid, rule, reason, f, optional=False):
            rig = K.Rig([K.Inp(f)], self.tmp, device_id="vector-device-" + cid)
            try:
                rig.host.start(rig.request_bytes)
            except H.HostRefusal as e:
                assert e.code == reason, (cid, e.code)
            else:
                raise AssertionError("host started " + cid)
            assert not rig.store.data["devices"], cid
            cases.append({"id": cid, "rule": rule, "psbt_version": 0, "host_psbt": hx(rig.request_bytes),
                          "device_keys": sorted(hx(k) for k in rig.wallet.keys),
                          "expected": "host refuses before recording an attempt; no request is sent", "reason_code": reason})
            if optional:
                cases[-1]["optional_form"] = True
        direct = "A direct push of a key is the single opcode equal to its length, `0x21` for 33 bytes and `0x20` for 32. `OP_PUSHDATA` forms do not count."
        K._counter[0] = 0
        f = K.Form("p2wsh-single", "vec")
        f.witness_script = b"\x4c\x21" + K.pub33(f.a) + b"\xac"
        f.spk = b"\x00\x20" + C.sha256(f.witness_script)
        custom("host-pushdata1-key-in-single-key-script", direct, "key_ambiguous", f)
        K._counter[0] = 0
        f = K.Form("p2wsh-2of3", "vec")
        pa, pb, pc = K.pub33(f.a), K.pub33(f.b), K.pub33(f.c)
        f.witness_script = bytes([0x52]) + K.push(pa) + b"\x4c\x21" + pb + K.push(pc) + bytes([0x53, 0xAE])
        f.spk = b"\x00\x20" + C.sha256(f.witness_script)
        custom("host-pushdata1-key-in-multisig", direct, "key_ambiguous", f)
        K._counter[0] = 0
        f = K.Form("p2tr-script", "vec")
        _retarget(f, b"\x4c\x20" + K.xonly(f.a) + b"\xac")
        custom("host-pushdata1-key-in-leaf-script", direct, "tap_mapping", f, optional=True)
        shape = "`OP_m <key> ... <key> OP_n OP_CHECKMULTISIG`, with `1 <= m <= n <= 16`, ... and each key a direct push of a valid 33-byte key."
        for cid, mk in (("m-greater-than-n", lambda a, b: bytes([0x53]) + K.push(a) + K.push(b) + bytes([0x52, 0xAE])),
                        ("n-above-key-count", lambda a, b: bytes([0x52]) + K.push(a) + K.push(b) + bytes([0x53, 0xAE])),
                        ("n-below-key-count", lambda a, b: bytes([0x51]) + K.push(a) + K.push(b) + K.push(K.pub33(K.seedkey("s3/third"))) + bytes([0x52, 0xAE]))):
            K._counter[0] = 0
            f = K.Form("p2wsh-2of3", "vec")
            f.witness_script = mk(K.pub33(f.a), K.pub33(f.b))
            f.spk = b"\x00\x20" + C.sha256(f.witness_script)
            custom("host-multisig-" + cid, shape, "key_ambiguous", f)
        # the host reads the core transaction at parse, as the signer does
        add("host-v2-required-height-zero", Gen.LOCK_HEIGHT, "bad_v2_input", ["p2wpkh"], 2,
            lambda r, f: r.psbt.inputs[0].update({b"\x12": struct.pack("<I", 0)}))
        add("host-v2-required-time-below-500000000", Gen.LOCK_TIME, "bad_v2_input", ["p2wpkh"], 2,
            lambda r, f: r.psbt.inputs[0].update({b"\x11": struct.pack("<I", 499999999)}))
        add("host-v2-incompatible-required-locktimes", Gen.LOCK_BOTH, "bad_v2_input", ["p2wpkh", "p2wpkh"], 2,
            lambda r, f: (r.psbt.inputs[0].update({b"\x12": struct.pack("<I", 700000)}), r.psbt.inputs[1].update({b"\x11": struct.pack("<I", 600000000)})),
            labels=["vec", "vec-2"])
        add("host-unsigned-tx-trailing-byte-v0", Gen.UNSIGNED_TX, "bad_tx", ["p2wpkh"], 0,
            lambda r, f: r.psbt.glob.update({b"\x00": r.psbt.glob[b"\x00"] + b"\x00"}))
        K._counter[0] = 0
        custom("host-key-not-in-witness-script-p2sh-p2wsh", "It fails ... if the script of a non-Taproot pair neither hashes nor pushes its key.",
               "key_not_in_script", self.nested_witness_script_form("vec"))

        return cases

    # ------------------------------------------------------ lifecycle scenarios
    def lifecycle(self):
        """Host runs against one store Each run is played on the reference with the same answers the
        reference CLI gives, and its outcome is asserted against the expected outcome written here."""
        class Kill(BaseException):
            pass

        class StopNow(BaseException):
            pass

        class Ui(K.AckUI):
            def __init__(self, confirm=True, change=False, **kw):
                super().__init__(**kw)
                self.confirm, self.change = confirm, change

            def confirm_change_after_failure(self, info):
                return self.change

            def confirm_reset(self, text):
                return self.confirm
        unsol = hx(b"hello")
        out = []

        def scenario(sid, rule, build, requires=None):
            K._counter[0] = 0
            form = K.Form("p2wpkh", "vec")
            inp = K.Inp(form)
            rig = K.Rig([inp], self.tmp, link_cls=T.ScriptedLink, device_id="vector-device-" + sid, max_retries=0)
            kid = K.pub33(form.a)
            dev = rig.wallet.device_id
            steps = []
            bad = T.tamper(lambda p: edit_core(p, "output_value"))

            def run(script, expect, ack=False, declined=False, unrelated=False, retries=0, pre=(), stop=None, psbt=None, change=False):
                n = len(steps)
                rho = hashlib.sha256(("anti-exfil psbt vector/%s/run/%d/rho" % (sid, n)).encode()).digest()
                rec = []
                killed = [False]
                att = [None]
                point, _, num = (stop or "").partition(":")

                def wrap(item):
                    kind, extra = (item, ()) if isinstance(item, str) else item

                    def step(req, real):
                        rec.append({"request": hx(req), "response": None, "unsolicited_after_response": list(extra), "kill": False})
                        if kind == "kill":
                            rec[-1]["kill"] = True
                            killed[0] = True
                            raise Kill()
                        try:
                            resp = {"honest": T.honest, "bad": bad, "err": T.refuse}[kind](req, real)
                        except T.LinkError:
                            rec[-1]["response"] = "ERROR"
                            raise
                        rec[-1]["response"] = hx(resp)
                        for u in extra:
                            rig.link.push_unsolicited(bytes.fromhex(u))
                        if point == "outstanding" and len(rec) == int(num or 1):
                            att[0].cancel()                 # the user stops while this response is outstanding
                            raise StopNow()
                        return resp
                    return step

                def unscripted(req, real):
                    raise AssertionError("%s run %d: the host sent an unscripted request" % (sid, n))
                rig.ui = Ui(ack=ack, declined=declined, unrelated=unrelated, change=change)
                rig.rho_source = lambda: rho
                rig.max_retries = retries
                rig.link.steps = [wrap(i) for i in script] + [unscripted]
                rig.link.transcript = []
                for u in pre:
                    rig.link.push_unsolicited(bytes.fromhex(u))
                host = rig.new_host()
                real_take = rig.link.take_unsolicited

                def take():
                    if point == "after_rho" and att[0] is not None and att[0].rho_sent:
                        att[0].abandon()                    # the user stops after rho was sent, nothing outstanding
                        raise StopNow()
                    return real_take()
                rig.link.take_unsolicited = take
                try:
                    if stop:
                        att[0] = host.start(psbt or rig.request_bytes)
                        att[0].commit()
                        if point == "before_rho":
                            att[0].abandon()                # the user stops before rho is sent, nothing outstanding
                            raise StopNow()
                        att[0].reveal()
                    else:
                        host.sign(psbt or rig.request_bytes)
                    got = (0, "RESULT")
                except H.WarningNotAcknowledged:
                    got = (5, "NOT_ACKNOWLEDGED")
                except H.HostRefusal:
                    got = (4, "REFUSED")
                except H.AttemptFailed:
                    got = (3, "FAILED")
                except H.AttemptAbandoned:
                    got = (6, "ABANDONED")
                except Kill:
                    got = None
                except StopNow:
                    got = (6, "ABANDONED") if att[0].state == "abandoned" else (3, "FAILED")
                rig.link.take_unsolicited = real_take
                rig.link._unsolicited = []
                if expect == "killed":
                    assert got is None and killed[0], (sid, n, got)
                    exp = {"killed": True, "requests": len(rec)}
                else:
                    count = rig.store.failures(dev)
                    assert (got[0], got[1], count) == tuple(expect), (sid, n, got, count, expect)
                    exp = {"exit": got[0], "last": got[1], "count": count, "requests": len(rec)}
                step_out = {"do": "run", "host_psbt": hx(psbt or rig.request_bytes), "max_retries": retries, "ack_warning": ack,
                            "declined": declined, "decline_unrelated": unrelated,
                            "rho": [{"input": 0, "key_identifier": hx(kid), "rho": hx(rho)}],
                            "unsolicited_before": list(pre), "exchanges": rec, "expect": exp}
                if stop:
                    step_out["stop"] = stop
                if change:
                    step_out["user_changes_transaction"] = True
                steps.append(step_out)

            def junk():
                open(rig.store_path, "wb").write(b"{not json")
                steps.append({"do": "junk_store", "bytes": hx(b"{not json")})

            def reset(confirm, expect):
                rig.ui = Ui(confirm=confirm)
                host = rig.new_host()
                ok = host.reset_failures()
                got = (0, "RESET") if ok else (7, "NOT_RESET")
                count = rig.store.failures(dev)
                assert (got[0], got[1], count) == tuple(expect), (sid, got, count, expect)
                steps.append({"do": "reset", "confirm": confirm, "expect": {"exit": got[0], "last": got[1], "count": count}})
            build(run, junk, reset)
            sc = {"id": sid, "rule": rule, "psbt_version": 0, "device_keys": [hx(kid)], "steps": steps}
            if requires:
                sc["requires_contract"] = requires
            out.append(sc)
        h2 = ["honest", "honest"]
        cnt = "A host that cannot read its records for a device MUST treat that device as having a count of one."
        scenario("lc-restart-counts-open-attempt", "At startup, an attempt still recorded as open counts as failed.",
                 lambda run, junk, reset: (run(["kill"], "killed"), run([], (5, "NOT_ACKNOWLEDGED", 1))))
        scenario("lc-restart-after-counted-failure-counts-once", "At startup, an attempt still recorded as open counts as failed; an attempt that already holds a failure is not charged again.",
                 lambda run, junk, reset: (run(["bad", "kill"], "killed", retries=1), run([], (5, "NOT_ACKNOWLEDGED", 1))))
        scenario("lc-unreadable-store", cnt,
                 lambda run, junk, reset: (junk(), run([], (5, "NOT_ACKNOWLEDGED", 1)), run(h2, (0, "RESULT", 1), ack=True)))
        scenario("lc-success-keeps-count-and-uses-up-warning",
                 "A later success on that attempt does not undo it. An acknowledgement covers exactly one new attempt and is used up in the write that records it.",
                 lambda run, junk, reset: (run(["bad"], (3, "FAILED", 1)), run(h2, (0, "RESULT", 1), ack=True), run(h2, (0, "RESULT", 1))))
        scenario("lc-unsolicited-line-during-attempt", "A failure event is a message the host did not request. It does not end the attempt.",
                 lambda run, junk, reset: (run([("honest", [unsol]), "honest"], (0, "RESULT", 1)), run([], (5, "NOT_ACKNOWLEDGED", 1))))
        scenario("lc-two-unsolicited-lines-count-once", "The host adds one at the first failure event in an attempt, and at most once per attempt.",
                 lambda run, junk, reset: run([("honest", [unsol]), ("honest", [unsol])], (0, "RESULT", 1)))
        scenario("lc-unsolicited-line-before-attempt", "Outside any attempt the host discards a message it did not request.",
                 lambda run, junk, reset: run(h2, (0, "RESULT", 0), pre=[unsol]))
        scenario("lc-decline-answers", "A host need not count a decline the user confirms was unrelated to what the device showed. A decline because the device showed something unexpected counts.",
                 lambda run, junk, reset: (run(["honest", "err"], (6, "ABANDONED", 0), declined=True, unrelated=True),
                                           run(["honest", "err"], (3, "FAILED", 1), declined=True, unrelated=False)), requires=2)
        scenario("lc-confirmed-decline-after-counted-failure", "An attempt that already holds a failure cannot be abandoned; a confirmed decline is not retried.",
                 lambda run, junk, reset: run(["bad", "honest", "err"], (3, "FAILED", 1), declined=True, unrelated=True, retries=2), requires=2)
        scenario("lc-reset-needs-confirmation", "The count resets only by an explicit user action that states what is being cleared.",
                 lambda run, junk, reset: (run(["bad"], (3, "FAILED", 1)), reset(False, (7, "NOT_RESET", 1)), reset(True, (0, "RESET", 0))), requires=2)
        scenario("lc-reset-clears-pending-warning", "A reset clears any pending warning.",
                 lambda run, junk, reset: (run(["bad"], (3, "FAILED", 1)), run(h2, (0, "RESULT", 1), ack=True), reset(True, (0, "RESET", 0)),
                                           run(["bad"], (3, "FAILED", 1)), run([], (5, "NOT_ACKNOWLEDGED", 1))), requires=2)
        scenario("lc-device-error-then-retry-succeeds", "A device error is a failure event, counted once, and a retry that succeeds completes the attempt: "
                 "\"A later success on that attempt does not undo it.\"",
                 lambda run, junk, reset: (run(["err", "honest", "honest"], (0, "RESULT", 1), retries=1),
                                           run([], (5, "NOT_ACKNOWLEDGED", 1))), requires=3)

        def changed_tx(run, junk, reset):
            alt = K.build_psbt([K.Inp(K.Form("p2wpkh", "vec"))], outputs=[(98000, K.out_script("changed"))]).serialize()
            run(["bad"], (3, "FAILED", 1))
            run([], (5, "NOT_ACKNOWLEDGED", 1), psbt=alt, change=True)
            run(h2, (0, "RESULT", 1), psbt=alt, change=True, ack=True)
        scenario("lc-changed-transaction-after-failure-still-needs-the-warning",
                 "If the failure count has risen since the user last acknowledged a warning, the host MUST warn the user before starting another attempt with that device. "
                 "Changing the message, coins or fee, reconnecting and restarting do not clear this requirement.", changed_tx, requires=3)
        STOP = ("A stop is a user action. It is Abandoned only before rho was sent, with no response outstanding and no failure recorded; "
                "a stop after rho was sent, or a cancellation with a response outstanding, is a failure event, charged once.")
        scenario("lc-stop-before-rho-is-abandoned", STOP,
                 lambda run, junk, reset: (run(["honest"], (6, "ABANDONED", 0), stop="before_rho"),
                                           run(h2, (0, "RESULT", 0))), requires=3)
        scenario("lc-stop-before-rho-after-counted-failure", STOP + " An attempt that already holds a failure ends as failed, charged once.",
                 lambda run, junk, reset: (run(["bad", "honest"], (3, "FAILED", 1), retries=1, stop="before_rho"),
                                           run([], (5, "NOT_ACKNOWLEDGED", 1))), requires=3)
        scenario("lc-stop-after-rho-is-a-failure", STOP,
                 lambda run, junk, reset: (run(h2, (3, "FAILED", 1), stop="after_rho"),
                                           run([], (5, "NOT_ACKNOWLEDGED", 1))), requires=3)
        scenario("lc-stop-with-first-response-outstanding", STOP,
                 lambda run, junk, reset: (run(["honest"], (3, "FAILED", 1), stop="outstanding:1"),
                                           run([], (5, "NOT_ACKNOWLEDGED", 1))), requires=3)
        scenario("lc-stop-with-second-response-outstanding", STOP,
                 lambda run, junk, reset: (run(h2, (3, "FAILED", 1), stop="outstanding:2"),
                                           run([], (5, "NOT_ACKNOWLEDGED", 1))), requires=3)
        return out


def _retarget(form, script):
    form.leaf_script = script
    lh, sh = S.tap_leaf_hash(0xC0, script), S.tap_leaf_hash(0xC0, form.sibling)
    form.leaf_hash = lh
    form.root = S.tagged("TapBranch", min(lh, sh) + max(lh, sh))
    _, q, par = S.tweaked_xonly(form.internal, form.root)
    form.control = bytes([0xC0 | par]) + form.internal + sh
    form.spk = b"\x51\x20" + q


def build(signer_side_only=False):
    """signer_side_only leaves out the host classes: a caller replaying the signer cases with other keys needs only those,
    and some host cases depend on the vector keys (one needs a signature whose r has its top bit set)."""
    g = Gen()
    try:
        ex = []
        for name in K.ALL_FORMS:
            for v in (0, 2):
                ex.append(g.exchange("%s-v%d" % (name, v), "One input spending %s, PSBT version %d." % (name, v), [name], v))
        for v in (0, 2):
            ex.append(g.exchange("p2tr-script-aggregate-internal-v%d" % v,
                                 "Script-path pair under an internal key listed as a MuSig2 aggregate of other parties, PSBT version %d. Allowed." % v,
                                 ["p2tr-script"], v,
                                 tweak=lambda p, fs: p.inputs[0].update({b"\x1a\x02" + fs[0].internal: b"\x02" + b"\x44" * 32 + b"\x03" + b"\x55" * 32})))
            ex.append(g.exchange("mixed-v%d" % v, "All thirteen spend forms in one transaction, PSBT version %d." % v, list(K.ALL_FORMS), v))
        for name, types in (("p2wpkh", K.ECDSA_SIGHASH), ("p2tr-key", K.TAP_SIGHASH)):
            for h in types:
                for v in (0, 2):
                    ex.append(g.exchange("%s-sighash-%#04x-v%d" % (name, h, v), "%s with PSBT_IN_SIGHASH_TYPE %#x, PSBT version %d." % (name, h, v), [name], v, [h]))
        # further cases
        def leaf_also_held(p, fs):
            f = fs[0]
            lh = S.tap_leaf_hash(0xC0, f.leaf_script)
            p.inputs[0][b"\x15" + bytes([0xC0 | f.parity]) + f.internal] = f.leaf_script + b"\xc0"
            p.inputs[0][b"\x16" + K.xonly(f.b)] = C.compact(1) + lh + b"\x00" * 4 + struct.pack("<I", 0x80000000)
        ex.append(g.exchange("p2tr-key-root-leaf-key-also-held-v0",
                             "Key-path pair when the device also holds a key in the one leaf: the host chooses the key-path pair and no script-path pair.",
                             ["p2tr-key-root"], 0, tweak=leaf_also_held,
                             host_keys=lambda fs: [K.pub33(fs[0].a), K.pub33(fs[0].b)], signer_keys=lambda fs: [fs[0].a, fs[0].b]))
        neg = lambda fs: AE._b32(N - int.from_bytes(fs[0].a, "big"))
        ex.append(g.exchange("p2tr-key-both-parity-forms-of-internal-key-v0",
                             "The device keys list both parity forms of one x-only internal key: one identifier, one pair.",
                             ["p2tr-key"], 0, host_keys=lambda fs: [K.pub33(fs[0].a), K.pub33(neg(fs))],
                             signer_keys=lambda fs: [fs[0].a, neg(fs)]))
        ex.append(g.exchange("p2wpkh-signer-holds-key-of-unrequested-input-v0",
                             "Two p2wpkh inputs; the host's wallet lists the key of the first only, the signer holds both. The request names the first input only "
                             "and the response signs nothing else. Input 1 stays unsigned, so there is no final transaction.",
                             ["p2wpkh", "p2wpkh"], 0, partial=True, labels=["vec", "vec-unrequested"], host_keys=lambda fs: [K.pub33(fs[0].a)],
                             signer_keys=lambda fs: [fs[0].a, fs[1].a]))
        def dup_leaf(p, fs):
            k = b"\x16" + K.xonly(fs[0].a)
            v = p.inputs[0][k]
            n, o = C.read_compact(v, 0)
            p.inputs[0][k] = C.compact(n + 1) + v[o:o + 32] + v[o:]
        ex.append(g.exchange("p2tr-script-leaf-hash-listed-twice-v0",
                             "A leaf hash listed twice in the device key's TAP_BIP32_DERIVATION record names the same pair: one pair, one hc.",
                             ["p2tr-script"], 0, tweak=dup_leaf))
        def unc_record_without_pair(p, fs):
            x, y = AE._mul(int.from_bytes(fs[0].a, "big"))
            p.inputs[1][b"\x06" + b"\x04" + AE._b32(x) + AE._b32(y)] = b"\x00" * 8
        ex.append(g.exchange("p2wpkh-uncompressed-key-record-on-input-without-pair-v0",
                             "Input 0 has a pair. Input 1 has no pair and holds only an uncompressed record of a device key. The rule covers an input with a pair, "
                             "so the host tells the user and the exchange completes; input 1 stays unsigned, so there is no final transaction.",
                             ["p2wpkh", "p2wpkh"], 0, partial=True, labels=["vec", "vec-unrequested"], tweak=unc_record_without_pair,
                             host_keys=lambda fs: [K.pub33(fs[0].a)], signer_keys=lambda fs: [fs[0].a]))
        # input amounts that only a witness UTXO states, for the fee the user is told
        for v in (0, 2):
            ex.append(g.exchange("p2wpkh-witness-utxo-only-v%d" % v,
                                 "One p2wpkh input whose amount is stated only by PSBT_IN_WITNESS_UTXO, PSBT version %d. No signature commits to the amount, "
                                 "so the fee is unverified." % v, ["p2wpkh"], v, utxo="wit"))
        ex.append(g.exchange("p2tr-key-sighash-0x81-witness-utxo-only-v0",
                             "A Taproot key-path pair signed with ANYONECANPAY, amount stated only by PSBT_IN_WITNESS_UTXO: the signature does not commit to every "
                             "input amount, so the fee is unverified.", ["p2tr-key"], 0, [0x81], utxo="wit"))
        ex.append(g.exchange("p2tr-key-witness-utxo-only-v0",
                             "A Taproot key-path pair without ANYONECANPAY, amount stated only by PSBT_IN_WITNESS_UTXO: the signature commits to every input "
                             "amount, so the fee is verified.", ["p2tr-key"], 0, utxo="wit"))
        # further cases
        def numbers_in_other_maps(p, fs):
            for m in [p.glob] + list(p.outputs):
                m[b"\x21" + b"\x01" * 33] = b"\x00" * 32
                m[b"\x22" + b"\x02" + b"\x03" * 32] = b"\x02" + b"\x04" * 32
                m[b"\x23" + b"\x05" * 32] = b"\x06" * 32
        for v in (0, 2):
            ex.append(g.exchange("p2wpkh-key-types-0x21-0x23-in-global-and-output-maps-v%d" % v,
                                 "The global map and every output map hold the key types 0x21, 0x22 and 0x23 as unknown fields, PSBT version %d. "
                                 "\"They are defined only for input maps. The same numbers in a global or output map are ordinary unknown fields.\" "
                                 "The host does not refuse them, the signer keeps them and so does the host's result." % v, ["p2wpkh"], v, tweak=numbers_in_other_maps))

        def flags(cid, desc, names, sighashes, init, expect, labels=None):
            e = g.exchange(cid, desc, names, 2, sighashes, tweak=lambda p, fs: p.glob.update({b"\x06": bytes([init])}), labels=labels)
            got = C.parse(bytes.fromhex(e["host_result"])).glob[b"\x06"]
            assert got == bytes([expect]), (cid, got.hex(), expect)
            assert C.parse(bytes.fromhex(e["second_response"])).glob[b"\x06"] == bytes([expect]), cid
            ex.append(e)
        flag_rule = "For PSBT version 2, apply the BIP 370 flag updates to ... `PSBT_GLOBAL_TX_MODIFIABLE`, cumulatively for each signature and using its actual sighash type, "
        flags("flags-two-signatures-update-cumulatively-v2",
              flag_rule + "with `SIGHASH_DEFAULT` counting as `SIGHASH_ALL`. Two inputs, ALL|ANYONECANPAY then NONE, from 0x07: the field ends at 0x04.",
              ["p2wpkh", "p2wpkh"], [0x81, 0x02], 0x07, 0x04, labels=["vec", "vec-2"])
        flags("flags-all-anyonecanpay-keeps-inputs-modifiable-v2",
              flag_rule + "BIP 370: inputs stay modifiable under ANYONECANPAY. SIGHASH_ALL|ANYONECANPAY from 0x07 leaves 0x05.",
              ["p2wpkh"], [0x81], 0x07, 0x05)
        flags("flags-none-keeps-outputs-modifiable-v2",
              flag_rule + "BIP 370: outputs stay modifiable under SIGHASH_NONE. SIGHASH_NONE from 0x07 leaves 0x06.",
              ["p2wpkh"], [0x02], 0x07, 0x06)
        flags("flags-sighash-default-counts-as-all-and-other-bits-kept-v2",
              flag_rule + "with `SIGHASH_DEFAULT` counting as `SIGHASH_ALL`, and \"Preserve other flags\". A Taproot key path with no sighash type, from 0x8f, leaves 0x8c.",
              ["p2tr-key"], [None], 0x8F, 0x8C)

        def one_key_two_leaves(name, label):
            f = K.Form("p2tr-script", label)
            f.sibling = K.push(K.xonly(f.a)) + b"\xad\x51"
            _retarget(f, K.push(K.xonly(f.a)) + b"\xac")
            return f

        def list_both(p, fs):
            f = fs[0]
            p.inputs[0][b"\x16" + K.xonly(f.a)] = C.compact(2) + f.leaf_hash + S.tap_leaf_hash(0xC0, f.sibling) + b"\x00" * 4 + struct.pack("<I", 0x80000000)
        e = g.exchange("p2tr-script-one-key-in-two-leaves-v0",
                       "One key is in two leaves and the derivation record lists both leaf hashes: two pairs, each with its own `rho`.",
                       ["p2tr-script"], 0, tweak=list_both, make_form=one_key_two_leaves)
        assert len(e["pairs"]) == 2, e["pairs"]
        e["optional_form"] = True
        ex.append(e)
        ex.append(g.exchange("legacy-two-inputs-sighash-none-and-single-v0",
                             "Two P2PKH inputs signed with SIGHASH_NONE and SIGHASH_SINGLE: the legacy signature hash zeroes the sequence numbers of the other inputs.",
                             ["p2pkh", "p2pkh"], 0, [0x02, 0x03], labels=["vec", "vec-2"]))

        def sixteen_keys(name, label):
            f = K.Form("p2wsh-2of3", label)
            keys = [K.pub33(f.a), K.pub33(f.b)] + [K.pub33(K.seedkey("vectors/sixteen/%d" % j)) for j in range(14)]
            f.witness_script = K.multisig(2, keys)
            f.spk = b"\x00\x20" + C.sha256(f.witness_script)
            return f
        e = g.exchange("p2wsh-multisig-2-of-16-v0", "A P2WSH multisig with m = 2 and n = 16, the largest the required form allows; the device holds two of the keys.",
                       ["p2wsh-2of3"], 0, make_form=sixteen_keys)
        assert len(e["pairs"]) == 2
        ex.append(e)
        ex.append(g.exchange("p2wpkh-input-without-pair-and-without-utxo-data-v0",
                             "Input 0 has a pair. Input 1 has no pair and no UTXO field at all: the fee cannot be computed, so it is unverified, and signing continues. "
                             "Input 1 stays unsigned, so there is no final transaction.",
                             ["p2wpkh", "p2wpkh"], 0, partial=True, labels=["vec", "vec-unrequested"],
                             tweak=lambda p, fs: p.inputs[1].pop(b"\x00"),
                             host_keys=lambda fs: [K.pub33(fs[0].a)], signer_keys=lambda fs: [fs[0].a]))

        def other_leaf_version(p, fs):
            f = fs[0]
            p.inputs[0][b"\x15" + bytes([0xC2 | (f.control[0] & 1)]) + f.internal + b"\x07" * 32] = f.leaf_script + b"\xc2"
        e = g.exchange("p2tr-script-second-leaf-record-with-another-version-v0",
                       "A second PSBT_IN_TAP_LEAF_SCRIPT record on the input carries the same script with leaf version 0xC2. Leaves other than the requested one are ignored.",
                       ["p2tr-script"], 0, tweak=other_leaf_version)
        e["optional_form"] = True
        ex.append(e)
        # PSBT version 2 locktime from the core transaction, a 1-of-2 multisig, and a witness-serialized previous transaction
        def lock(fields):
            def tweak(p, fs):
                for m, (h, t) in zip(p.inputs, fields):
                    if h is not None:
                        m[b"\x12"] = struct.pack("<I", h)
                    if t is not None:
                        m[b"\x11"] = struct.pack("<I", t)
            return tweak

        def no_fallback(p, fs):
            del p.glob[b"\x03"]
        e = g.exchange("p2wpkh-no-fallback-locktime-v2",
                       "PSBT version 2 with no PSBT_GLOBAL_FALLBACK_LOCKTIME and no required locktime on the input: the transaction locktime is 0.",
                       ["p2wpkh"], 2, tweak=no_fallback)
        assert C.core_tx(C.parse(bytes.fromhex(e["host_psbt"]))).locktime == 0
        ex.append(e)
        e = g.exchange("p2wpkh-required-height-overrides-fallback-v2",
                       "PSBT version 2 whose fallback locktime is 5 and whose input requires height 700000: the transaction locktime is 700000.",
                       ["p2wpkh"], 2, tweak=lambda p, fs: (p.glob.update({b"\x03": struct.pack("<I", 5)}), lock([(700000, None)])(p, fs)))
        assert C.core_tx(C.parse(bytes.fromhex(e["host_psbt"]))).locktime == 700000
        ex.append(e)
        e = g.exchange("p2wpkh-required-time-500000000-v2",
                       "PSBT version 2 whose input requires time 500000000, the smallest time-based locktime: the transaction locktime is 500000000.",
                       ["p2wpkh"], 2, tweak=lock([(None, 500000000)]))
        assert C.core_tx(C.parse(bytes.fromhex(e["host_psbt"]))).locktime == 500000000
        ex.append(e)
        e = g.exchange("p2wpkh-two-inputs-height-wins-v2",
                       "PSBT version 2 with two inputs. Input 0 requires height 100 and time 600000000; input 1 requires height 700000 only. Every input allows "
                       "a height, so the height is chosen and the largest one is used: the transaction locktime is 700000.",
                       ["p2wpkh", "p2wpkh"], 2, labels=["vec", "vec-2"], tweak=lock([(100, 600000000), (700000, None)]))
        assert C.core_tx(C.parse(bytes.fromhex(e["host_psbt"]))).locktime == 700000
        ex.append(e)

        class OneOfTwo(K.Form):
            """A P2WSH 1-of-2 multisig: the device holds the first key, the second belongs to a cosigner."""
            def __init__(self, name, label):
                super().__init__("p2wsh-2of3", label)
                self.witness_script = K.multisig(1, [K.pub33(self.a), K.pub33(self.b)])
                self.spk = b"\x00\x20" + C.sha256(self.witness_script)
                self.held, self.order = [self.a], [self.a]

            def finalize(self, m):
                script_sig, wit = super().finalize(m)
                return script_sig, [b""] + wit          # the CHECKMULTISIG dummy element
        for v in (0, 2):
            e = g.exchange("p2wsh-multisig-1-of-2-v%d" % v,
                           "A P2WSH multisig with m = 1 and n = 2, the smallest m the required form allows; the device holds the first key, PSBT version %d." % v,
                           ["p2wsh-2of3"], v, make_form=OneOfTwo)
            assert len(e["pairs"]) == 1
            ex.append(e)
        for v in (0, 2):
            ex.append(g.exchange("p2pkh-non-witness-utxo-with-witness-data-v%d" % v,
                                 "One p2pkh input whose PSBT_IN_NON_WITNESS_UTXO is the previous transaction in network serialization with witness data, "
                                 "PSBT version %d. Its txid is that of the transaction without witness data, which is what the previous txid names." % v,
                                 ["p2pkh"], v, witness_prev=True))
        for v in (0, 2):
            e = g.exchange("p2tr-key-two-inputs-sighash-0x01-v%d" % v,
                           "Two Taproot key-path inputs, both with PSBT_IN_SIGHASH_TYPE 0x01 (SIGHASH_ALL), amounts stated only by PSBT_IN_WITNESS_UTXO, "
                           "PSBT version %d. Neither type has ANYONECANPAY, so each signature hash commits to every input amount and the fee is verified." % v,
                           ["p2tr-key", "p2tr-key"], v, [0x01, 0x01], utxo="wit", labels=["vec", "vec-2"])
            assert len(e["pairs"]) == 2
            ex.append(e)
        facts = g.user_facts(ex)
        doc = {
            "title": "Anti-exfil PSBT fields: test vectors",
            "specification_revision": "0.16",
            "license": "MIT",
            "keys_are_artificial": True,
            "encoding": "All byte strings are lowercase hex. PSBTs are serialized with keys sorted within each map; a reader must not depend on order.",
            "derivation": ("Secret keys are SHA256(\"ae16/<form>/vec/<name>\") for names a, b, c and internal (see each input's device_secret_keys). "
                           "rho for the n-th pair drawn in an exchange is SHA256(\"anti-exfil psbt vector/<id>/rho/<n>\"). Previous transactions are "
                           "synthetic and numbered from 1 in each exchange."),
            "classes": {
                "exchanges": "host_psbt is the host's own PSBT. A host given host_psbt, the keys in device_keys and the rho values must send first_request, "
                             "accept first_response, send second_request, accept second_response and produce host_result. A signer given a request must produce "
                             "the response. final_transaction is host_result finalized, and was accepted and mined by Bitcoin Core on regtest (see README).",
                "signer_refusals": "A signer holding the secret keys listed must fail on the request, and return nothing. reason_code is a label from the "
                                   "reference code; only the failure is normative. A case marked conditional applies only under the stated condition: "
                                   "a signer that has an ordinary signing path may return the PSBT, signed or not, but never with an anti-exfil field. A case "
                                   "marked optional_form needs a form the text makes optional (the Taproot script path); a signer that does not support it fails "
                                   "for that reason, and Jade's stated limits apply.",
                "host_refusals": "The host runs the exchanges in order; the last response is tampered, or an earlier one is rejected. The host must fail the "
                                 "attempt, copy nothing from the response, and count one failure.",
                "host_accepts": "Responses that differ from the request in an allowed way, and requests the host must go on with. The host must accept them and "
                                "count no failure. Only the host is tested: the responses are those of a signer that holds a list of keys.",
                "request_refusals": "The host must refuse before recording an attempt. This is not an attempt and counts for nothing. A case marked optional_form "
                                    "needs a form the text makes optional.",
                "lifecycle_scenarios": "Host runs against one store, in order. A 'run' starts the host on host_psbt with the stated rho, answers each request "
                                       "with the scripted response (the word ERROR means the device failed), writes unsolicited_before to the host's input before "
                                       "it starts and unsolicited_after_response straight after the response, and ends the process at a request marked kill. "
                                       "'expect' is the outcome and the failure count the host prints; 'requests' is the number of requests it sends. 'junk_store' "
                                       "writes the bytes to the store path. 'reset' asks the host to clear the count, with or without the user's confirmation. "
                                       "A step may carry a stop: before_rho, after_rho or outstanding:<n> (the user stops before rho is sent with nothing outstanding, "
                                       "after rho is sent, or while the response to request n is outstanding). "
                                       "A scenario with requires_contract 2 needs the reset command or the decline answers of CLI contract version 2; "
                                       "requires_contract 3 needs the stop option, or the choice to change the transaction after a failure (user_changes_transaction on a step).",
                "user_facts": "What the user is told, as facts a log can show (CLI contract version 3, requires_contract 3). For the exchange named, a host given host_psbt "
                              "tells the user it is requesting anti-exfil signing before its first request, and neither host nor signer presents the fee as verified "
                              "when fee_may_be_presented_as_verified is false. A party that presents it as unverified, or does not say, passes when the field is true. An entry "
                              "with approval_pairs also fixes what the signer's approval covers: approvals_per_second_pass approvals, together showing exactly the "
                              "listed signatures by input, sighash type and leaf hash.",
            },
            "exchanges": ex,
            "signer_refusals": g.signer_cases(),
            "host_refusals": [] if signer_side_only else g.host_cases(),
            "host_accepts": [] if signer_side_only else g.host_accepts(),
            "request_refusals": [] if signer_side_only else g.request_refusals(),
            "lifecycle_scenarios": [] if signer_side_only else g.lifecycle(),
            "user_facts": facts,
        }
    finally:
        g.close()
    return doc


def build_seed():
    published = check_bip32_against_published()
    bip8x = check_against_bip84_bip86()
    g = Gen()
    try:
        ex = g.seed_exchanges()
    finally:
        g.close()
    master_k, master_c = bip32_master(TEST_SEED)
    return {
        "title": "Anti-exfil PSBT fields: test vectors from the BIP39 test mnemonic",
        "specification_revision": "0.16",
        "license": "MIT",
        "keys_are_artificial": True,
        "note": ("Companion of bip-anti-exfil-psbt.json for a device that holds a seed and cannot load raw keys. Same schema as its `exchanges`, with the "
                 "derivations of each input's keys in place of the label seed. The wallet is the mnemonic that BIP84 and BIP86 publish test vectors for, "
                 "so a device that stores a mnemonic can hold it; the keys have no value and must never hold funds. Previous transactions are synthetic. The ids are not those of the other file."),
        "seed": {"source": "BIP39 mnemonic of the BIP84 and BIP86 test vectors; seed by BIP39 (PBKDF2-HMAC-SHA512, 2048 rounds, salt \"mnemonic\")",
                 "mnemonic": MNEMONIC, "passphrase": PASSPHRASE, "seed_hex": hx(TEST_SEED), "master_fingerprint": hx(S.hash160(K.pub33(master_k))[:4]),
                 "master_chain_code": hx(master_c)},
        "paths": {"p2pkh": "m/44'/0'/0'/0/i", "p2sh-p2wpkh": "m/49'/0'/0'/0/i", "p2wpkh": "m/84'/0'/0'/0/i", "p2tr-key and p2tr-key-root": "m/86'/0'/0'/0/i",
                  "p2wsh-single and p2wsh-2of3": "m/48'/0'/0'/2'/0/i", "p2sh-p2wsh-single and p2sh-p2wsh-2of3": "m/48'/0'/0'/1'/0/i",
                  "roles": "key a is at index 0, b at 1, c at 2, a Taproot internal key at 3; the device holds a, plus b in the 2-of-3 forms; in "
                           "p2tr-key-root key b is the one key of the single leaf (the device does not sign it)"},
        "bip32_check": {"chains_checked": published,
                        "bip84_bip86_checked": bip8x,
                        "check": ("Before the file is written, the derivation code in scripts/gen_psbt_vectors.py serializes the extended private keys of "
                                  "the chains m, m/0H, m/0H/1 and m/0H/1/2H of BIP32 test vector 1 and compares them byte for byte, checksum included, "
                                  "with the published values. This checks the master key, hardened and normal private derivation, chain codes and the "
                                  "parent fingerprint. It then derives the seed of the mnemonic above and compares the root key with the one BIP86 "
                                  "publishes, and the keys at m/86'/0'/0'/0/0 (Taproot internal key, before tweaking) and m/84'/0'/0'/0/0 with those "
                                  "BIP86 and BIP84 publish. Addresses are not compared. The generator stops on a mismatch.")},
        "encoding": "All byte strings are lowercase hex. PSBTs are serialized with keys sorted within each map; a reader must not depend on order.",
        "exchanges": ex,
    }


def readme(doc, seed_doc):
    n_ex = len(doc["exchanges"])
    return """# Anti-exfil PSBT test vectors (revision 0.16)

`bip-anti-exfil-psbt.json` holds the vectors for `bip-anti-exfil-psbt.md`. License: CC0-1.0 or MIT, at your option. All keys are artificial, derived from
labelled seeds, and have no value. `scripts/gen_psbt_vectors.py` writes both files; `--check` compares them with the disk.

## Contents

- `exchanges` (%d): for each spend form and PSBT version 0 and 2, the host's PSBT, both requests, both responses, the
  host's result and the finalized transaction. Further exchanges cover every accepted sighash type for a segwit v0 key and a
  Taproot key path, and a transaction with all thirteen forms.
- `signer_refusals` (%d): requests a signer must fail, each with the rule it tests.
- `host_refusals` (%d): exchanges in which a response breaks a rule under "Handling a response" or fails step 5.
- `host_accepts` (%d): responses that differ from the request in an allowed way, which the host must accept.
- `request_refusals` (%d): host PSBTs the host must refuse before it records an attempt.
- `lifecycle_scenarios` (%d): host runs against one store in order (restart after a kill, an unreadable store, an unsolicited
  line, answers to the decline questions, a reset, a user stop before `rho`, after `rho` and with a response outstanding), each with
  scripted responses and the expected outcome and count.
- `user_facts` (%d): what the user is told, as facts a log can show: the host's notice before its first request, and a fee that is not
  presented as verified when the text forbids it.

A second file, `bip-anti-exfil-psbt-seed.json` (%d exchanges), holds the required spend forms in PSBT versions 0 and 2 with keys derived
from the BIP39 test mnemonic of BIP84 and BIP86 (`abandon ... about`, empty passphrase) along the standard path of each script type, for a
device that holds a mnemonic. It uses the schema of `exchanges`, and
`--check` covers it. The keys are public test data and have no value.

## How to use

Parse each PSBT as a map set keyed by key bytes. Order of maps and of fields inside a map does not matter, so compare parsed
maps. For an exchange, give a signer `first_request` and expect `first_response`, then `second_request` and expect
`second_response`. Give a host `host_psbt`, the listed device keys and the listed `rho` values (a real host draws them
from a secure random source; vectors fix them), and expect it to send the stated requests and to produce `host_result`.
Signatures are deterministic given `rho`, so the bytes are reproducible.

`reason_code` values name the rule in the reference code. They are labels; a conforming implementation needs only to fail.

## Spend forms

p2pkh, p2wpkh, p2sh-p2wpkh, p2tr-key (no merkle root), p2tr-key-root (with a merkle root), p2wsh-single and p2sh-p2wsh-single
(`<K> OP_CHECKSIG`), p2wsh-2of3 and p2sh-p2wsh-2of3 (two device keys of three), and the optional forms p2sh-single and p2sh-2of3
(legacy P2SH), p2tr-script (one device key in a leaf, with a sibling leaf) and p2tr-multi_a (a `multi_a`-style leaf, two device keys).

## Rules the vectors pin down

Signature hashes use no annex. A key-path pair fails if `PSBT_IN_TAP_INTERNAL_KEY` is present and differs from the identifier. A
derivation record with the uncompressed form of a device key fails, for the host before it records an attempt and for the signer.
Attempt records, counts and warnings are pinned by `lifecycle_scenarios`, which needs a harness that can kill the host process, write to its
input and reuse its store; the SHOULD rules of that section (a limit on the count, the same transaction after a failure, the same `rho` on a
retry) are not tested, because a conforming host may do otherwise. `psbt/tests/test_lifecycle.py` holds the rest. A scenario or
fact marked `requires_contract` 2 or 3 needs the reset command, the decline answers, the user stop or the log of the harness's command
line contract (`validation/shortcuts/CLI_CONTRACT.md`). A signer refusal marked `conditional` (`signer-no-ae-fields`) applies only to an
implementation with no ordinary signing path. A case marked `optional_form` needs a form the text makes optional (the Taproot script path), so a
signer that does not support it fails it for that reason. `user_changes_transaction` on a lifecycle step is the user's choice to change the
transaction after a failure. `host-accepts-uncompressed-record-of-a-key-that-is-not-a-device-key` tests the host only, because a signer that holds a seed
MAY fail on any uncompressed derivation record. The host's `host_result`
for PSBT version 2 includes `PSBT_GLOBAL_TX_MODIFIABLE`; compare it. One exchange (`p2wpkh-signer-holds-key-of-unrequested-input-v0`) leaves an
input unsigned on purpose and has null `final_transaction` and `final_txid`.

## Checks on these vectors

Every vector is replayed through the reference host and signer in `psbt/` while the file is generated, and the run stops if the
code disagrees. Every `final_transaction` for a non-optional and optional form was accepted by Bitcoin Core 31.1 on regtest
(`psbt/tests/test_regtest.py`). Core 31.1 could not read PSBT version 2, so for version 2 the final transaction was built
by the test suite's own finalizer from the host's result.

Some exchanges (required locktimes, no fallback locktime, 1-of-2 multisig, a NON_WITNESS_UTXO with witness data, two Taproot
inputs with explicit SIGHASH_ALL) ran through the reference and were not mined.

The vectors do not repeat the lists of invalid PSBTs in BIP 174, BIP 370 and BIP 371. An implementation should pass those too; the
reference does, in `psbt/tests/test_bip_psbt_cases.py`.
""" % (n_ex, len(doc["signer_refusals"]), len(doc["host_refusals"]), len(doc["host_accepts"]), len(doc["request_refusals"]),
       len(doc["lifecycle_scenarios"]), len(doc["user_facts"]), len(seed_doc["exchanges"]))


def write_seed_only():
    """Write the seed file, and the README if its text changes; the main file is neither built nor written. The README counts come from the
    main file on disk."""
    seed_doc = build_seed()
    seed_text = json.dumps(seed_doc, indent=2) + "\n"
    doc = json.loads(OUT.read_text())
    rd = readme(doc, seed_doc)
    for path, body in ((README, rd), (SEED_OUT, seed_text)):
        if path.exists() and path.read_text() == body:
            print("unchanged", path.relative_to(ROOT))
            continue
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(body)
        os.replace(tmp, path)
        print("wrote", path.relative_to(ROOT), hashlib.sha256(body.encode()).hexdigest())
    return 0


def main():
    if "--seed-only" in sys.argv:
        return write_seed_only()
    doc = build()
    seed_doc = build_seed()
    text = json.dumps(doc, indent=2) + "\n"
    seed_text = json.dumps(seed_doc, indent=2) + "\n"
    rd = readme(doc, seed_doc)
    if "--check" in sys.argv:
        same = (OUT.exists() and OUT.read_text() == text and README.exists() and README.read_text() == rd
                and SEED_OUT.exists() and SEED_OUT.read_text() == seed_text)
        print("matches files on disk" if same else "DIFFERS from files on disk")
        return 0 if same else 1
    for path, body in ((OUT, text), (README, rd), (SEED_OUT, seed_text)):
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(body)
        os.replace(tmp, path)
    print("exchanges %d, signer refusals %d, host refusals %d, request refusals %d, lifecycle scenarios %d, user facts %d; seed exchanges %d" % (
        len(doc["exchanges"]), len(doc["signer_refusals"]), len(doc["host_refusals"]), len(doc["request_refusals"]),
        len(doc["lifecycle_scenarios"]), len(doc["user_facts"]), len(seed_doc["exchanges"])))
    print("wrote", OUT.relative_to(ROOT), hashlib.sha256(text.encode()).hexdigest())
    print("wrote", SEED_OUT.relative_to(ROOT), hashlib.sha256(seed_text.encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
