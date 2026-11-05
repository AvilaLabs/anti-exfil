"""Test fixtures: artificial keys, every spend form, PSBT builders, a finalizer.

Keys come from labelled seeds and have no value.
"""
import hashlib
import os
import pathlib
import shutil
from collections import namedtuple
import struct
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SRC = pathlib.Path(os.environ.get("AE_HOST_SRC", str(HERE.parent)))
ROOT = HERE.parent.parent
for p in (str(SRC), str(ROOT / "reference")):
    if p not in sys.path:
        sys.path.insert(0, p)

import anti_exfil as AE          # noqa: E402
import psbt_codec as C           # noqa: E402
import spend as S                # noqa: E402
import signer as SG              # noqa: E402
import host as H                 # noqa: E402
import transport as T            # noqa: E402

N = AE._N


def seedkey(label):
    return hashlib.sha256(("ae16/" + label).encode()).digest()


def pub33(sk):
    return AE.ecdsa_public_key(sk)


def xonly(sk):
    return AE.public_key(sk)


def push(b):
    assert len(b) < 76
    return bytes([len(b)]) + b


def script_push(b):
    if len(b) < 76:
        return push(b)
    if len(b) < 256:
        return b"\x4c" + bytes([len(b)]) + b
    return b"\x4d" + struct.pack("<H", len(b)) + b


def multisig(m, keys33):
    return bytes([0x50 + m]) + b"".join(push(k) for k in keys33) + bytes([0x50 + len(keys33), 0xAE])


def single(key33):
    return push(key33) + b"\xac"


def multi_a(m, xs):
    s = push(xs[0]) + b"\xac"
    for x in xs[1:]:
        s += push(x) + b"\xba"
    return s + bytes([0x50 + m, 0x9C])


def ser_witness_tx(tx, wits):
    b = struct.pack("<I", tx.version) + b"\x00\x01" + C.compact(len(tx.ins))
    for h, i, s, q in tx.ins:
        b += h + struct.pack("<I", i) + C.blob(s) + struct.pack("<I", q)
    b += C.compact(len(tx.outs))
    for v, s in tx.outs:
        b += struct.pack("<Q", v) + C.blob(s)
    for st in wits:
        b += C.compact(len(st)) + b"".join(C.blob(x) for x in st)
    return b + struct.pack("<I", tx.locktime)


def p2wpkh_spk(key33):
    return b"\x00\x14" + S.hash160(key33)


# -------------------------------------------------------------------- forms
class Form:
    """A spend form with its keys. `held` secrets belong to the device."""

    def __init__(self, name, label="f"):
        self.name = name
        k = lambda n: seedkey("%s/%s/%s" % (name, label, n))
        self.a, self.b, self.c, self.x = k("a"), k("b"), k("c"), k("internal")
        self.held = [self.a]
        self.tree = None            # tap leaves
        self.root = b""
        self.internal = None
        self.redeem = self.witness_script = None
        self.optional = False
        self.taproot = False
        self.leaf_script = None
        self.order = []             # key order for multisig/multi_a finalization
        pa, pb, pc = pub33(self.a), pub33(self.b), pub33(self.c)
        n = name
        if n == "p2pkh":
            self.spk = b"\x76\xa9\x14" + S.hash160(pa) + b"\x88\xac"
            self.legacy = True
        elif n == "p2wpkh":
            self.spk = p2wpkh_spk(pa)
        elif n == "p2sh-p2wpkh":
            self.redeem = p2wpkh_spk(pa)
            self.spk = b"\xa9\x14" + S.hash160(self.redeem) + b"\x87"
        elif n in ("p2wsh-single", "p2sh-p2wsh-single", "p2wsh-2of3", "p2sh-p2wsh-2of3"):
            if n.endswith("single"):
                self.witness_script = single(pa)
                self.order = [self.a]
            else:
                self.witness_script = multisig(2, [pa, pb, pc])
                self.held = [self.a, self.b]
                self.order = [self.a, self.b]
            prog = b"\x00\x20" + C.sha256(self.witness_script)
            if n.startswith("p2sh"):
                self.redeem = prog
                self.spk = b"\xa9\x14" + S.hash160(prog) + b"\x87"
            else:
                self.spk = prog
        elif n in ("p2sh-single", "p2sh-2of3"):
            self.optional = True
            self.legacy = True
            self.redeem = single(pa) if n == "p2sh-single" else multisig(2, [pa, pb, pc])
            self.held = [self.a] if n == "p2sh-single" else [self.a, self.b]
            self.order = list(self.held)
            self.spk = b"\xa9\x14" + S.hash160(self.redeem) + b"\x87"
        elif n in ("p2tr-key", "p2tr-key-root"):
            self.taproot = True
            self.internal = xonly(self.a)
            if n == "p2tr-key-root":
                self.leaf_script = push(xonly(self.b)) + b"\xac"
                self.root = S.tap_leaf_hash(0xC0, self.leaf_script)
            _, q, self.parity = S.tweaked_xonly(self.internal, self.root)
            self.spk = b"\x51\x20" + q
        elif n in ("p2tr-script", "p2tr-multi_a"):
            self.taproot = True
            self.optional = True
            self.internal = xonly(self.x)
            if n == "p2tr-script":
                self.leaf_script = push(xonly(self.a)) + b"\xac"
                self.held = [self.a]
                self.order = [self.a]
            else:
                self.leaf_script = multi_a(2, [xonly(self.a), xonly(self.b), xonly(self.c)])
                self.held = [self.a, self.b]
                self.order = [self.a, self.b, self.c]
            sib = push(xonly(self.c)) + b"\xac" if n == "p2tr-script" else push(xonly(self.b)) + b"\xac" + b"\x51"
            lh, sh = S.tap_leaf_hash(0xC0, self.leaf_script), S.tap_leaf_hash(0xC0, sib)
            self.leaf_hash = lh
            self.root = S.tagged("TapBranch", min(lh, sh) + max(lh, sh))
            _, q, par = S.tweaked_xonly(self.internal, self.root)
            self.control = bytes([0xC0 | par]) + self.internal + sh
            self.sibling = sib
            self.spk = b"\x51\x20" + q
        else:
            raise ValueError(n)
        self.legacy = getattr(self, "legacy", False)

    @property
    def held_pub33(self):
        return [pub33(k) for k in self.held]

    def fill(self, m):
        """Add the PSBT records an Updater would add."""
        fp = b"\x00\x00\x00\x00"
        path = struct.pack("<I", 0x80000000)
        if self.taproot:
            m[b"\x17"] = self.internal
            if self.root:
                m[b"\x18"] = self.root
            if self.name in ("p2tr-script", "p2tr-multi_a"):
                m[b"\x15" + self.control] = self.leaf_script + b"\xc0"
                for sk in self.held:
                    m[b"\x16" + xonly(sk)] = C.compact(1) + self.leaf_hash + fp + path
                # a second leaf, other keys: ignored by pairs
                sibcontrol = bytes([self.control[0]]) + self.internal + self.leaf_hash
                m[b"\x15" + sibcontrol] = self.sibling + b"\xc0"
            else:
                m[b"\x16" + self.internal] = C.compact(0) + fp + path
            return
        if self.redeem is not None:
            m[b"\x04"] = self.redeem
        if self.witness_script is not None:
            m[b"\x05"] = self.witness_script
        for sk in self.held:
            m[b"\x06" + pub33(sk)] = fp + path

    def finalize(self, m):
        """(scriptSig, witness) from the signatures in input map m."""
        def sig(sk):
            return m[b"\x02" + pub33(sk)]
        if self.taproot:
            if self.name in ("p2tr-key", "p2tr-key-root"):
                return b"", [m[b"\x13"]]
            wit = []
            for sk in reversed(self.order):
                k = b"\x14" + xonly(sk) + self.leaf_hash
                wit.append(m.get(k, b""))
            return b"", wit + [self.leaf_script, self.control]
        if self.name == "p2pkh":
            return push(sig(self.a)) + push(pub33(self.a)), []
        if self.name == "p2wpkh":
            return b"", [sig(self.a), pub33(self.a)]
        if self.name == "p2sh-p2wpkh":
            return push(self.redeem), [sig(self.a), pub33(self.a)]
        sigs = [sig(k) for k in self.order]
        multi = len(self.order) > 1
        if self.name.startswith("p2sh-p2wsh") or self.name.startswith("p2wsh"):
            wit = ([b""] if multi else []) + sigs + [self.witness_script]
            return (push(self.redeem) if self.redeem else b""), wit
        # legacy p2sh
        return (b"\x00" if multi else b"") + b"".join(push(s) for s in sigs) + script_push(self.redeem), []


class Prev:
    """A previous output: its transaction bytes and index."""

    def __init__(self, txbytes, vout, value, spk):
        self.txbytes, self.vout, self.value, self.spk = txbytes, vout, value, spk
        self.txid = C.txid(C.parse_tx(txbytes))


_counter = [0]


def fake_prev(spk, value=100000):
    _counter[0] += 1
    fake_in = (hashlib.sha256(b"fund%d" % _counter[0]).digest(), 0, b"\x51", 0xFFFFFFFF)
    tx = C.Tx(2, [fake_in], [(7, b"\x6a"), (value, spk)], 0)
    return Prev(C.ser_tx(tx), 1, value, spk)


class Inp:
    def __init__(self, form, value=100000, prev=None, sighash=None, utxo="non", sequence=0xFFFFFFFD):
        self.form, self.value, self.sighash, self.utxo, self.sequence = form, value, sighash, utxo, sequence
        self.prev = prev or fake_prev(form.spk, value)


def out_script(label="dest"):
    return p2wpkh_spk(pub33(seedkey(label)))


def build_psbt(inputs, outputs=None, version=0, fee=1000, locktime=0, tx_version=2, modifiable=None):
    """Return a C.Psbt for the given Inp list. Outputs default to two payments."""
    total = sum(i.value for i in inputs)
    if outputs is None:
        half = (total - fee) // 2
        outputs = [(half, out_script("d1")), (total - fee - half, out_script("d2"))]
    ins = [(i.prev.txid, i.prev.vout, b"", i.sequence) for i in inputs]
    tx = C.Tx(tx_version, ins, list(outputs), locktime)
    ims = []
    for i in inputs:
        m = {}
        if i.utxo in ("non", "both"):
            m[b"\x00"] = i.prev.txbytes
        if i.utxo in ("wit", "both"):
            m[b"\x01"] = struct.pack("<Q", i.prev.value) + C.blob(i.prev.spk)
        if i.sighash is not None:
            m[b"\x03"] = struct.pack("<I", i.sighash)
        i.form.fill(m)
        ims.append(m)
    oms = [{} for _ in outputs]
    if version == 0:
        g = {b"\x00": C.ser_tx(tx)}
        return C.Psbt(0, g, ims, oms)
    g = {b"\xfb": struct.pack("<I", 2), b"\x02": struct.pack("<I", tx.version),
         b"\x03": struct.pack("<I", locktime), b"\x04": C.compact(len(ins)), b"\x05": C.compact(len(outputs))}
    if modifiable is not None:
        g[b"\x06"] = bytes([modifiable])
    for m, (h, ix, _, q) in zip(ims, ins):
        m[b"\x0e"], m[b"\x0f"], m[b"\x10"] = h, struct.pack("<I", ix), struct.pack("<I", q)
    for m, (v, s) in zip(oms, outputs):
        m[b"\x03"], m[b"\x04"] = struct.pack("<Q", v), s
    return C.Psbt(2, g, ims, oms)


def held_of(inputs):
    seen, out = set(), []
    for i in inputs:
        for sk in i.form.held:
            if sk not in seen:
                seen.add(sk)
                out.append(sk)
    return out


class Base(unittest.TestCase):
    """A private scratch directory under psbt/.work for each test."""

    def setUp(self):
        work = HERE.parent / ".work"
        work.mkdir(exist_ok=True)
        self.tmp = tempfile.mkdtemp(dir=str(work))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def mod(self, psbt_bytes, fn):
        """Parse, apply fn(psbt), serialize."""
        p = C.parse(psbt_bytes)
        fn(p)
        return p.serialize()

    def rig(self, forms, **kw):
        inputs = [Inp(f) if isinstance(f, Form) else f for f in forms]
        return Rig(inputs, self.tmp, **kw)


class Approver:
    """Approval callback that records descriptions and answers as told."""

    def __init__(self, answer=True):
        self.answer, self.seen = answer, []

    def __call__(self, desc):
        self.seen.append(desc)
        return self.answer


class AckUI(H.UI):
    def __init__(self, ack=True, declined=False, unrelated=False):
        self.ack, self.declined, self.unrelated = ack, declined, unrelated
        self.asked = []
        self.warnings, self.notices, self.requests, self.resets = [], [], [], []

    def notify_request(self, info):
        self.requests.append(info)

    def notice(self, t):
        self.notices.append(t)

    def warn(self, dev, n):
        self.warnings.append((dev, n))
        return self.ack

    def declined_on_device(self):
        self.asked.append("declined")
        return self.declined

    def decline_unrelated_to_display(self):
        self.asked.append("unrelated")
        return self.unrelated

    def confirm_reset(self, text):
        self.resets.append(text)
        return True


class Rig:
    """Everything for one exchange: inputs, PSBT, signer, link, host, store."""
    count = 0

    def __init__(self, inputs, tmpdir, version=0, signer_keys=None, extra_keys=(), link_cls=T.InProcessLink,
                 steps=None, ui=None, approve=None, device_id="dev-A", store_path=None, max_retries=3,
                 outputs=None, rho_source=None, host_keys=None, **kw):
        self.inputs = inputs
        self.psbt = build_psbt(inputs, outputs=outputs, version=version, **kw)
        keys = signer_keys if signer_keys is not None else held_of(inputs)
        self.approve = approve or Approver(True)
        self.signer = SG.Signer(list(keys) + list(extra_keys), self.approve)
        self.link = T.ScriptedLink(self.signer, steps or []) if link_cls is T.ScriptedLink else link_cls(self.signer)
        self.ui = ui or AckUI()
        Rig.count += 1
        self.store_path = store_path or os.path.join(str(tmpdir), "store-%d.json" % Rig.count)
        self.store = H.Store(self.store_path)
        hk = host_keys if host_keys is not None else [pub33(k) for k in keys]
        self.wallet = H.Wallet(device_id, hk)
        self.max_retries = max_retries
        self.rho_source = rho_source
        self.host = self.new_host()

    def new_host(self, store=None):
        self.store = store or H.Store(self.store_path)
        self.host = H.Host(self.wallet, self.store, self.ui, self.link, max_retries=self.max_retries,
                           rho_source=self.rho_source)
        return self.host

    @property
    def request_bytes(self):
        return self.psbt.serialize()


def final_tx(psbt_bytes, inputs):
    """Finalize every input and return (txid_hex, raw_hex) of the signed transaction."""
    p = C.parse(psbt_bytes)
    tx = C.core_tx(p)
    ss, wits = [], []
    for m, i in zip(p.inputs, inputs):
        s, w = i.form.finalize(m)
        ss.append(s)
        wits.append(w)
    t2 = C.Tx(tx.version, [(h, ix, s, q) for (h, ix, _, q), s in zip(tx.ins, ss)], tx.outs, tx.locktime)
    raw = ser_witness_tx(t2, wits) if any(wits) else C.ser_tx(t2)
    return C.txid(t2)[::-1].hex(), raw.hex()


ALL_FORMS = ["p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2tr-key", "p2tr-key-root", "p2wsh-single", "p2wsh-2of3",
             "p2sh-p2wsh-single", "p2sh-p2wsh-2of3", "p2sh-single", "p2sh-2of3", "p2tr-script", "p2tr-multi_a"]
REQUIRED_FORMS = ["p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2tr-key", "p2tr-key-root", "p2wsh-single", "p2wsh-2of3",
                  "p2sh-p2wsh-single", "p2sh-p2wsh-2of3"]
ECDSA_SIGHASH = [1, 2, 3, 0x81, 0x82, 0x83]
TAP_SIGHASH = [0] + ECDSA_SIGHASH


def pairs_of(rig, psbt=None):
    """Pairs the host would choose for the rig's PSBT (or a modified one)."""
    p = psbt or rig.psbt
    return rig.host.select_pairs(p, [])


def fixed_rho(label="rho"):
    n = [0]

    def src():
        n[0] += 1
        return hashlib.sha256(("%s/%d" % (label, n[0])).encode()).digest()
    return src


def req_first(psbt, pairs, rhos=None):
    """First-pass request bytes built by hand. Returns (bytes, rhos)."""
    rhos = rhos or {(pr.index, pr.keyid): hashlib.sha256(b"rho" + bytes([pr.index]) + pr.keyid).digest()
                    for pr in pairs}
    out = psbt.clone()
    for pr in pairs:
        r = rhos[(pr.index, pr.keyid)]
        hc = AE.ecdsa_host_commit(r) if pr.scheme == "ecdsa" else AE.host_commit(r)
        out.inputs[pr.index][b"\x21" + pr.keyid] = hc
    return out.serialize(), rhos


def req_second(psbt, pairs, rhos, keep_hc=False):
    out = psbt.clone()
    for pr in pairs:
        k = (pr.index, pr.keyid)
        out.inputs[pr.index][b"\x23" + pr.keyid] = rhos[k]
        if keep_hc:
            out.inputs[pr.index][b"\x21" + pr.keyid] = (AE.ecdsa_host_commit(rhos[k]) if pr.scheme == "ecdsa"
                                                        else AE.host_commit(rhos[k]))
    return out.serialize()


KP = namedtuple("KP", "index keyid scheme")


def form_keyids(form):
    if form.taproot and form.name in ("p2tr-script", "p2tr-multi_a"):
        return [xonly(sk) + form.leaf_hash for sk in form.held]
    if form.taproot:
        return [form.internal]
    return [pub33(sk) for sk in form.held]


def manual_pairs(rig):
    """Pairs named by the rig's forms, with no host validation (for PSBTs the host would refuse)."""
    out = []
    for i, inp in enumerate(rig.inputs):
        for kid in form_keyids(inp.form):
            out.append(KP(i, kid, "ecdsa" if len(kid) == 33 else "bip340"))
    return out
