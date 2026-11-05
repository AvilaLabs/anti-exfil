"""Regression tests for behaviours the reference must enforce. The mutation runner (mutation_check.py)
restores the flawed behaviour in a copy of the code and shows each test fail."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as K            # noqa: E402
import anti_exfil as AE       # noqa: E402
import psbt_codec as C        # noqa: E402
import host as H              # noqa: E402
import signer as SG           # noqa: E402
import transport as T         # noqa: E402


class CodeBugs(K.Base):
    def test_cb1_both_parity_forms_of_a_taproot_internal_key(self):
        """CB-1: the old host made two pairs with one identifier (KeyError after the device answered).
        Now: one pair, the exchange completes, one rho."""
        form = K.Form("p2tr-key")
        neg = AE._b32(AE._N - int.from_bytes(form.a, "big"))
        keys = [K.pub33(form.a), K.pub33(neg)]
        rig = K.Rig([K.Inp(form)], self.tmp, host_keys=keys, signer_keys=[form.a, neg], link_cls=T.ScriptedLink)
        pairs = K.pairs_of(rig)
        self.assertEqual([(p.index, p.keyid) for p in pairs], [(0, form.internal)])
        res = rig.host.sign(rig.request_bytes)
        self.assertEqual(len(res.signed), 1)
        q1 = C.parse(rig.link.transcript[0][0])
        self.assertEqual(len([1 for t, _, _ in C.ae_entries(q1.inputs[0]) if t == 0x21]), 1)
        self.assertEqual(rig.store.failures("dev-A"), 0)

    def test_cb2_repeated_step2_must_check_r0_unchanged(self):
        """CB-2: the old host overwrote R0 values on a repeated step 2, including after a rejected response."""
        form = K.Form("p2wsh-2of3")

        def first(req, real):
            p = C.parse(real(req))
            ks = sorted(k for k in p.inputs[0] if k[:1] == b"\x22")
            p.inputs[0][ks[1]] = b"\x05" + b"\x01" * 32            # pair 1: not a point -> response rejected after pair 0 was read
            return p.serialize()
        rig = K.Rig([K.Inp(form)], self.tmp, link_cls=T.ScriptedLink, steps=[first, T.change_r0(0)], max_retries=3)
        with self.assertRaises(H.AttemptFailed) as cm:
            rig.host.sign(rig.request_bytes)
        self.assertIn("r0_changed", cm.exception.reasons)
        self.assertEqual(rig.link.calls, 2)

    def test_cb2_unchanged_r0_on_repeat_is_accepted(self):
        form = K.Form("p2wsh-2of3")

        def reject_only(req, real):
            p = C.parse(real(req))
            ks = sorted(k for k in p.inputs[0] if k[:1] == b"\x22")
            del p.inputs[0][ks[1]]
            return p.serialize()
        rig = K.Rig([K.Inp(form)], self.tmp, link_cls=T.ScriptedLink, steps=[reject_only], max_retries=3)
        res = rig.host.sign(rig.request_bytes)
        self.assertEqual(len(res.signed), 2)
        self.assertEqual(rig.store.failures("dev-A"), 1)

    def test_cb3_field_order_does_not_matter(self):
        """CB-3: the old spec required AE fields at the end of the map; the document compares by key. Any order is accepted."""
        rig = K.Rig([K.Inp(K.Form("p2wpkh"))], self.tmp, link_cls=T.ScriptedLink)

        def reorder(req, real):
            p = C.parse(real(req))
            # proprietary key sorts after 0x22 in the signer's output; the host must not care where fields sit
            p.inputs[0][b"\xfc\x01z"] = b"x"
            p.inputs[0][b"\x00" + b"\x01"] = b"y"
            raw = C.MAGIC + C._ser_map(p.glob)
            for m in p.inputs:
                raw += b"".join(C.blob(k) + C.blob(m[k]) for k in reversed(sorted(m))) + b"\x00"
            for m in p.outputs:
                raw += C._ser_map(m)
            return raw
        rig.link.steps = [reorder, reorder]
        self.assertEqual(len(rig.host.sign(rig.request_bytes).signed), 1)


class Unimplemented(K.Base):
    def test_um1_failure_state_exists_and_survives_restart(self):
        """UM-1: the old host had no counter, warning or persistence; each attempt was a fresh Host with fresh rho."""
        rig = K.Rig([K.Inp(K.Form("p2wpkh"))], self.tmp, link_cls=T.ScriptedLink, steps=[T.timeout] * 4, ui=H.UI())
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        rig.link = T.ScriptedLink(rig.signer)
        h2 = rig.new_host()
        h2.link = rig.link
        with self.assertRaises(H.WarningNotAcknowledged):
            h2.sign(rig.request_bytes)
        self.assertEqual(rig.link.calls, 0)

    def test_um2_user_told_before_request(self):
        """UM-2: the old start() returned bytes with no notice hook."""
        rig = K.Rig([K.Inp(K.Form("p2wpkh"))], self.tmp, link_cls=T.ScriptedLink)
        rig.link.on_exchange = lambda l, r: self.assertEqual(len(rig.ui.requests), 1)
        rig.host.sign(rig.request_bytes)
        self.assertTrue(rig.ui.requests[0]["anti_exfil"])

    def test_um3_approval_has_no_default_and_covers_what_is_signed(self):
        """UM-3: the old signer took approve=True by default and returned nothing to show."""
        with self.assertRaises(ValueError):
            SG.Signer([K.seedkey("x")], None)
        with self.assertRaises(TypeError):
            SG.Signer([K.seedkey("x")])
        rig = K.Rig([K.Inp(K.Form("p2wpkh"), sighash=2)], self.tmp, approve=K.Approver(False))
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        desc = rig.approve.seen[0]
        self.assertEqual(desc["signatures"][0]["sighash"], "NONE")
        self.assertIn("outputs", desc)
        self.assertEqual(rig.store.failures("dev-A"), 1)         # a refusal costs one failure, as for any device error

    def test_um4_fee_not_presented_as_verified_without_amounts(self):
        """UM-4: the old code accepted WITNESS_UTXO alone and never told anyone the fee was unverified."""
        rig = K.Rig([K.Inp(K.Form("p2wpkh"), utxo="wit")], self.tmp)
        rig.host.sign(rig.request_bytes)
        self.assertFalse(rig.approve.seen[0]["fee_verified"])
        self.assertIsNone(rig.approve.seen[0]["fee"])
        self.assertFalse(rig.ui.requests[0]["fee_verified"])

    def test_um5_unsupported_pairs_fail_not_ignored(self):
        """UM-5: the old host skipped uncompressed and MuSig2 pairs silently."""
        form = K.Form("p2pkh")
        rig = K.Rig([K.Inp(form)], self.tmp)
        P = AE._mul(int.from_bytes(form.a, "big"))
        rig.psbt.inputs[0][b"\x06" + b"\x04" + AE._b32(P[0]) + AE._b32(P[1])] = b"\x00" * 8
        with self.assertRaises(H.HostRefusal) as cm:
            rig.host.start(rig.request_bytes)
        self.assertEqual(cm.exception.code, "uncompressed_key")
        form = K.Form("p2tr-key")
        rig = K.Rig([K.Inp(form)], self.tmp)
        rig.psbt.inputs[0][b"\x1a" + b"\x02" + b"\x33" * 32] = b"\x02" + K.xonly(form.a)
        with self.assertRaises(H.HostRefusal) as cm:
            rig.host.start(rig.request_bytes)
        self.assertEqual(cm.exception.code, "musig2_participant")


if __name__ == "__main__":
    unittest.main()
