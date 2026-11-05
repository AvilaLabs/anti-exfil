"""Regtest end to end: real outputs funded with test keys, the exchange run, the spend finalized,
and Bitcoin Core asked to accept and mine it.

Spec: "Common spends then complete between any conforming pair" (PSBT document, Rationale), and
"Signers MUST support P2PKH, P2WPKH, P2SH-P2WPKH, the Taproot key path, and P2WSH and P2SH-P2WSH ..."
(Spends, Required forms).

Core 31.1 is driven over localhost. The final transaction is built by this suite's own finalizer from
the host's result, for both PSBT versions, and sent with sendrawtransaction. Core's own PSBT reading is
only probed (decodepsbt / finalizepsbt) and reported, not relied on.
"""
import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as K                       # noqa: E402
import regtest_node as R                 # noqa: E402
import psbt_codec as C                   # noqa: E402
import spend as S                        # noqa: E402
import struct                            # noqa: E402

PROBE = {}


class Regtest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (R.BIN / "bitcoind").exists():
            raise unittest.SkipTest("bitcoind not found")
        cls.node = R.Node()
        cls.node.start()
        cls.tmp = tempfile.mkdtemp(dir=str(R.WORK))

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    # -------------------------------------------------------------
    def fund(self, specs):
        """specs: list of (spk, value_sats). Returns list of K.Prev for those outputs."""
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

    def spend(self, forms, version, sighashes=None, label=""):
        sighashes = sighashes or [None] * len(forms)
        prevs = self.fund([(f.spk, 200000) for f in forms])
        inputs = [K.Inp(f, 200000, prev=p, sighash=h) for f, p, h in zip(forms, prevs, sighashes)]
        total = 200000 * len(forms)
        outs = [(total // 2 - 1000, self.dest()), (total - total // 2 - 1000, self.dest())]
        rig = K.Rig(inputs, self.tmp, version=version, outputs=outs, device_id="regtest-" + label,
                    store_path=os.path.join(self.tmp, "s-%s-%d.json" % (label, version)))
        res = rig.host.sign(rig.request_bytes)
        txid, raw = K.final_tx(res.psbt, inputs)
        acc = self.node.cli("testmempoolaccept", [raw])
        self.assertTrue(acc[0]["allowed"], (label, version, acc))
        sent = self.node.cli("sendrawtransaction", raw)
        self.assertEqual(sent, txid)
        self.node.cli("generatetoaddress", 1, self.node.addr)
        info = self.node.cli("getrawtransaction", txid, True)
        self.assertGreaterEqual(info["confirmations"], 1)
        self.probe_core_psbt(res.psbt, version, label)
        return res

    def probe_core_psbt(self, data, version, label):
        """Report whether Core reads the host's result, and whether finalizepsbt completes it."""
        key = "v%d" % version
        rec = PROBE.setdefault(key, {"decode_ok": 0, "decode_fail": 0, "finalize_complete": 0, "finalize_incomplete": 0})
        b64 = base64.b64encode(data).decode()
        try:
            self.node.cli("decodepsbt", b64)
            rec["decode_ok"] += 1
        except RuntimeError:
            rec["decode_fail"] += 1
            return
        try:
            r = self.node.cli("finalizepsbt", b64, False)
            rec["finalize_complete" if r.get("complete") else "finalize_incomplete"] += 1
        except RuntimeError:
            rec["finalize_incomplete"] += 1

    # -------------------------------------------------------------
    def test_each_form_each_version(self):
        """Every positive spend form is accepted and mined by Core, for PSBT v0 and v2."""
        for name in K.ALL_FORMS:
            for v in (0, 2):
                with self.subTest(form=name, version=v):
                    self.spend([K.Form(name, "rt")], v, label=name)

    def test_mixed_inputs(self):
        """Multiple inputs of mixed types in one transaction."""
        for v in (0, 2):
            forms = [K.Form(n, "mix") for n in K.ALL_FORMS]
            self.spend(forms, v, label="mixed")

    def test_sighash_types(self):
        """Each accepted sighash type, with and without ANYONECANPAY, on ECDSA and BIP340 spends."""
        for name in ("p2pkh", "p2wpkh", "p2wsh-2of3", "p2tr-key", "p2tr-script"):
            tap = name.startswith("p2tr")
            for h in (K.TAP_SIGHASH if tap else K.ECDSA_SIGHASH):
                for v in (0, 2):
                    with self.subTest(form=name, sighash=h, version=v):
                        self.spend([K.Form(name, "sh%d" % h)], v, [h], label="%s-%d" % (name, h))

    def test_zz_report(self):
        # printed so that the probe result can be quoted
        print("\nCORE_PSBT_PROBE " + json.dumps(PROBE, sort_keys=True), file=sys.stderr)


if __name__ == "__main__":
    unittest.main()
