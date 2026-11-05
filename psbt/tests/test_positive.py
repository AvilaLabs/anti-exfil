"""Positive matrix: every spend form, PSBT v0 and v2, mixed inputs, every accepted sighash type."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as K            # noqa: E402
import anti_exfil as AE       # noqa: E402
import psbt_codec as C        # noqa: E402
import spend as S             # noqa: E402
import transport as T         # noqa: E402
from test_host_response import plain_ecdsa_verify   # noqa: E402

N = AE._N


class Positive(K.Base):
    def exchange(self, inputs, version, **kw):
        rig = K.Rig(inputs, self.tmp, version=version, **kw)
        res = rig.host.sign(rig.request_bytes)
        return rig, res

    def check_result(self, rig, res):
        """Independent checks of every signature: plain verification with the host-computed message."""
        out = C.parse(res.psbt)
        pairs = K.pairs_of(rig)
        self.assertEqual(len(res.signed), len(pairs))
        for pr in pairs:
            field = out.inputs[pr.index][pr.sigkey]
            if pr.scheme == "ecdsa":
                r, s, h = S.parse_der_sig(field)
                self.assertEqual(h, pr.sighash)
                self.assertTrue(s <= (N - 1) // 2)
                self.assertTrue(plain_ecdsa_verify(AE._parse33(pr.pk), pr.message, r, s))
            else:
                self.assertEqual(len(field), 64 if pr.sighash == 0 else 65)
                self.assertTrue(AE._schnorr_verify(pr.pk, pr.message, field[:64]))
        self.assertEqual(C.ae_entries(out.inputs[0]), [])
        self.assertEqual(C.core_tx(out), C.core_tx(rig.psbt))

    def check_wire(self, rig):
        """First request: hc only. Second: rho only. Responses: first has R0, second has no AE field."""
        (q1, r1), (q2, r2) = rig.link.transcript[:2]
        n_pairs = len(K.pairs_of(rig))
        def types(data):
            return sorted(t for m in C.parse(data).inputs for t, _, _ in C.ae_entries(m))
        self.assertEqual(types(q1), [0x21] * n_pairs)
        self.assertEqual(types(q2), [0x23] * n_pairs)
        self.assertEqual(types(r1), [0x21] * n_pairs + [0x22] * n_pairs)
        self.assertEqual(types(r2), [])
        # each pair has its own independently drawn rho
        rhos = [v for m in C.parse(q2).inputs for t, _, v in C.ae_entries(m)]
        self.assertEqual(len(set(rhos)), len(rhos))

    def test_each_form_each_version(self):
        """PSBT document: "Required forms. Signers MUST support P2PKH, P2WPKH, P2SH-P2WPKH, the Taproot key path, and P2WSH and P2SH-P2WSH ...\" plus the optional forms."""
        for name in K.ALL_FORMS:
            for version in (0, 2):
                with self.subTest(form=name, version=version):
                    rig, res = self.exchange([K.Inp(K.Form(name))], version)
                    self.check_result(rig, res)
                    self.check_wire(rig)

    def test_key_path_with_and_without_merkle_root(self):
        """Spends: "the signer normalizes and tweaks the secret as in BIP341, using the internal key and PSBT_IN_TAP_MERKLE_ROOT, or an empty script path if that field is absent.\""""
        outs = []
        for name in ("p2tr-key", "p2tr-key-root"):
            rig, res = self.exchange([K.Inp(K.Form(name))], 0)
            pr = K.pairs_of(rig)[0]
            outs.append(pr.pk)
            self.assertNotEqual(pr.pk, pr.internal)
        self.assertNotEqual(outs[0], outs[1])

    def test_mixed_inputs(self):
        """Multiple inputs of mixed types in one transaction."""
        for version in (0, 2):
            inputs = [K.Inp(K.Form(n, "mixed")) for n in K.ALL_FORMS]
            rig, res = self.exchange(inputs, version)
            out = C.parse(res.psbt)
            self.assertEqual(len(res.signed), len(K.pairs_of(rig)))
            for i, m in enumerate(out.inputs):
                self.assertTrue([k for k in m if k[:1] in (b"\x02", b"\x13", b"\x14")], i)
            self.check_result(rig, res)

    def test_each_sighash_type(self):
        """Sighash types: "Accepted values are SIGHASH_ALL, NONE and SINGLE, each with or without ANYONECANPAY, and for BIP340 also SIGHASH_DEFAULT.\""""
        for name in K.ALL_FORMS:
            tap = name.startswith("p2tr")
            for h in (K.TAP_SIGHASH if tap else K.ECDSA_SIGHASH):
                for version in ((0, 2) if name in ("p2wpkh", "p2pkh", "p2tr-key", "p2tr-script") else (0,)):
                    with self.subTest(form=name, sighash=h, version=version):
                        rig, res = self.exchange([K.Inp(K.Form(name, "h%d" % h), sighash=h)], version)
                        self.check_result(rig, res)

    def test_absent_sighash_defaults(self):
        """Sighash types: "If absent, it is SIGHASH_ALL for ECDSA and SIGHASH_DEFAULT for BIP340.\""""
        rig, res = self.exchange([K.Inp(K.Form("p2wpkh"))], 0)
        self.assertEqual({p.sighash for p in K.pairs_of(rig)}, {1})
        rig, res = self.exchange([K.Inp(K.Form("p2tr-key"))], 0)
        self.assertEqual({p.sighash for p in K.pairs_of(rig)}, {0})

    def test_utxo_field_variants(self):
        for utxo in ("non", "wit", "both"):
            for name in ("p2wpkh", "p2sh-p2wpkh", "p2wsh-single", "p2tr-key", "p2tr-script"):
                with self.subTest(utxo=utxo, form=name):
                    rig, res = self.exchange([K.Inp(K.Form(name), utxo=utxo)], 0)
                    self.check_result(rig, res)

    def test_foreign_cosigner_untouched(self):
        """Signer: a signer MUST NOT add a signature for any other pair; the host leaves other signers' data alone."""
        form = K.Form("p2wsh-2of3")
        form.held = [form.a]
        inp = K.Inp(form)
        foreign = b"\x02" + K.pub33(form.b)
        rig = K.Rig([inp], self.tmp, signer_keys=[form.a], extra_keys=[form.b])
        rig.psbt.inputs[0][foreign] = b"\x30" + b"\x05" * 70
        res = rig.host.sign(rig.request_bytes)
        out = C.parse(res.psbt)
        self.assertEqual(out.inputs[0][foreign], b"\x30" + b"\x05" * 70)
        self.assertEqual([k for k in out.inputs[0] if k[:1] == b"\x02"].__len__(), 2)

    def test_regenerated_requests_deterministic_with_fixed_rho(self):
        """Same inputs and the same injected rho give the same bytes (the generator relies on this)."""
        outs = []
        for _ in range(2):
            K._counter[0] = 0
            inp = K.Inp(K.Form("p2wpkh"))
            rig = K.Rig([inp], self.tmp, rho_source=K.fixed_rho())
            outs.append(rig.host.sign(rig.request_bytes).psbt)
        self.assertEqual(outs[0], outs[1])


if __name__ == "__main__":
    unittest.main()
