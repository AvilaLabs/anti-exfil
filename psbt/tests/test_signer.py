"""Signer section, sighash rules, Unsupported, Validation scope. Every refusal asserts its reason code,
and each tampered PSBT is otherwise valid, so the rule under test is the one that fires."""
import os
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as K            # noqa: E402
import anti_exfil as AE       # noqa: E402
import psbt_codec as C        # noqa: E402
import spend as S             # noqa: E402
import signer as SG           # noqa: E402


class SignerBase(K.Base):
    def setup_form(self, name="p2wpkh", version=0, **kw):
        self.form = K.Form(name)
        self.inp = K.Inp(self.form, **kw)
        self.rig_ = self.rig([self.inp], version=version)
        return self.rig_

    def pairs(self, rig):
        """Pairs from the untampered PSBT; by form when the host would refuse that PSBT."""
        try:
            return K.pairs_of(rig)
        except K.H.HostRefusal:
            return K.manual_pairs(rig)

    def first(self, rig=None, psbt=None):
        rig = rig or self.rig_
        p = psbt or rig.psbt
        pairs = self.pairs(rig)
        data, rhos = K.req_first(p, pairs)
        return data, pairs, rhos

    def second(self, rig=None, psbt=None, keep_hc=False):
        rig = rig or self.rig_
        p = psbt or rig.psbt
        pairs = self.pairs(rig)
        _, rhos = K.req_first(p, pairs)
        return K.req_second(p, pairs, rhos, keep_hc), pairs, rhos

    def fails(self, data, code, rig=None):
        rig = rig or self.rig_
        before = len(rig.approve.seen)
        with self.assertRaises(SG.SignerFail) as cm:
            rig.signer.sign(data)
        self.assertEqual(cm.exception.code, code, str(cm.exception))
        self.assertEqual(len(rig.approve.seen), before, "the signer prompted before failing")

    def ae_set(self, data, fn):
        return self.mod(data, lambda p: fn(p.inputs[0]))


class SignerPhases(SignerBase):
    def test_first_pass_adds_commitment_and_needs_no_approval(self):
        """Signer: "run step 2 of the protocol, keep the commitment, and add PSBT_IN_AE_NONCE_COMMITMENT ... No approval is needed.\""""
        rig = self.setup_form()
        data, pairs, rhos = self.first()
        out = C.parse(rig.signer.sign(data))
        ents = {t: v for t, _, v in C.ae_entries(out.inputs[0])}
        self.assertEqual(set(ents), {0x21, 0x22})
        self.assertEqual(rig.approve.seen, [])
        self.assertFalse([k for k in out.inputs[0] if k[:1] in (b"\x02", b"\x13", b"\x14")])

    def test_second_pass_removes_every_ae_field(self):
        """Signer: "Then remove every anti-exfil field from every input map and return the PSBT.\""""
        for keep in (False, True):
            rig = self.setup_form("p2wsh-2of3")
            data, pairs, rhos = self.second(keep_hc=keep)
            data = self.mod(data, lambda p: p.inputs[0].update({b"\x22" + pairs[0].keyid: AE.ecdsa_device_commit(
                rig.signer._by_pub33[pairs[0].keyid], pairs[0].message, AE.ecdsa_host_commit(rhos[(0, pairs[0].keyid)]))}))
            out = C.parse(rig.signer.sign(data))
            self.assertEqual(C.ae_entries(out.inputs[0]), [])
            self.assertEqual(len([k for k in out.inputs[0] if k[:1] == b"\x02"]), 2)
            self.assertEqual(len(rig.approve.seen), 1, "one approval covers the whole PSBT")

    def test_unknown_fields_preserved(self):
        rig = self.setup_form()
        data, _, _ = self.second()
        data = self.mod(data, lambda p: p.inputs[0].update({b"\xfc\x01x": b"keep"}))
        out = C.parse(rig.signer.sign(data))
        self.assertEqual(out.inputs[0][b"\xfc\x01x"], b"keep")

    def test_nonce_only_fails(self):
        """Signer: "Only a nonce commitment: fail.\""""
        rig = self.setup_form()
        data, pairs, _ = self.first()
        only = self.ae_set(data, lambda m: (m.pop(b"\x21" + pairs[0].keyid), m.update({b"\x22" + pairs[0].keyid: b"\x02" + b"\x11" * 32})))
        self.fails(only, "nonce_only")

    def test_mixed_phases_fail(self):
        """Signer: "A request contains one phase; mixed phases fail.\""""
        rig = self.setup_form("p2wsh-2of3")
        data, pairs, rhos = self.first()
        p0 = pairs[0]
        mixed = self.ae_set(data, lambda m: m.update({b"\x23" + p0.keyid: rhos[(0, p0.keyid)]}))
        self.fails(mixed, "mixed_phases")

    def test_stale_commitments_fail(self):
        """Signer: "if a host commitment or nonce commitment is present and differs from the computed value, fail.\""""
        rig = self.setup_form()
        data, pairs, rhos = self.second(keep_hc=True)
        key = pairs[0].keyid
        self.fails(self.ae_set(data, lambda m: m.update({b"\x21" + key: b"\x00" * 32})), "hc_mismatch")
        self.fails(self.ae_set(data, lambda m: m.update({b"\x22" + key: b"\x02" + b"\x01" * 32})), "r0_mismatch")
        d1, _, _ = self.first()
        self.fails(self.ae_set(d1, lambda m: m.update({b"\x22" + key: b"\x02" + b"\x01" * 32})), "r0_mismatch")
        good = C.parse(rig.signer.sign(d1)).inputs[0][b"\x22" + key]
        again = self.ae_set(d1, lambda m: m.update({b"\x22" + key: good}))
        self.assertEqual(C.parse(rig.signer.sign(again)).inputs[0][b"\x22" + key], good)

    def test_no_request_fields(self):
        """Signer: "An implementation with no ordinary signing path fails or returns the PSBT unsigned\" -- this one fails."""
        rig = self.setup_form()
        self.fails(rig.psbt.serialize(), "not_a_request")
        # fields in a global or output map are ordinary unknown fields: still no request
        data = self.mod(rig.psbt.serialize(), lambda p: (p.outputs[0].update({b"\x21" + b"k" * 33: b"x" * 32}),
                                                         p.glob.update({b"\x23" + b"k" * 33: b"x" * 32})))
        self.fails(data, "not_a_request")

    def test_whole_request_fails_if_any_pair_fails(self):
        """Signer: "If it fails on any pair, it fails for the whole PSBT and returns nothing.\""""
        rig = self.setup_form("p2wsh-2of3")
        data, pairs, _ = self.first()
        bad = self.ae_set(data, lambda m: m.update({b"\x21" + b"\x02" + b"\x77" * 32: b"\x00" * 32}))
        self.fails(bad, "key_not_in_script")

    def codeof(self, rig, data):
        with self.assertRaises(SG.SignerFail) as cm:
            rig.signer.sign(data)
        return cm.exception.code

    def test_pairs_only_for_named(self):
        """Signer: "A signer handles exactly the pairs named by these fields and MUST NOT add a signature for any other pair.\""""
        rig = self.setup_form("p2wsh-2of3")
        pairs = K.pairs_of(rig)
        one = [pairs[0]]
        data, rhos = K.req_first(rig.psbt, one)
        d2 = K.req_second(rig.psbt, one, rhos)
        out = C.parse(rig.signer.sign(d2))
        sigs = [k for k in out.inputs[0] if k[:1] == b"\x02"]
        self.assertEqual(sigs, [b"\x02" + pairs[0].keyid])

    def test_key_not_held(self):
        """Signer: "It fails ... if it does not hold the key\""""
        rig = self.setup_form()
        rig.signer._by_pub33.clear()
        data, _, _ = self.first()
        self.fails(data, "key_not_held")

    def test_already_signed(self):
        """Signer: "It fails if a pair already has a signature\""""
        for name in ("p2wpkh", "p2tr-key", "p2tr-script"):
            rig = self.setup_form(name)
            pr = K.pairs_of(rig)[0]
            p = rig.psbt.clone()
            p.inputs[0][pr.sigkey] = b"\x01" * 64
            data, _, _ = self.first(psbt=p)
            self.fails(data, "already_signed")

    def test_both_paths_in_one_input(self):
        """Signer: "... or if one input has both a key-path and a script-path pair.\""""
        rig = self.setup_form("p2tr-script")
        pr = K.pairs_of(rig)[0]
        data, _, _ = self.first()
        both = self.ae_set(data, lambda m: m.update({b"\x21" + pr.keyid[:32]: b"\x00" * 32}))
        self.fails(both, "both_paths")

    def test_lengths(self):
        """PSBT: "Any other length fails.\" / Protocol: "A party fails on any other length.\""""
        rig = self.setup_form()
        data, pairs, _ = self.first()
        k = pairs[0].keyid
        self.fails(self.ae_set(data, lambda m: m.update({b"\x21" + k + b"\x00": b"\x00" * 32})), "bad_keyid_length")
        self.fails(self.ae_set(data, lambda m: m.update({b"\x21" + k: b"\x00" * 31})), "bad_field_length")
        self.fails(self.ae_set(data, lambda m: m.update({b"\x22" + k: b"\x02" * 32})), "bad_field_length")
        d2, _, _ = self.second()
        self.fails(self.ae_set(d2, lambda m: m.update({b"\x23" + k: b"\x00" * 33})), "bad_field_length")

    def test_approval_rules(self):
        """User approval: "The device MUST obtain the user's approval before every run of step 4.\""""
        with self.assertRaises(ValueError):
            SG.Signer([], None)
        for answer in (False, None, 1, "yes"):
            rig = self.rig([K.Inp(K.Form("p2wpkh"))], approve=K.Approver(answer))
            d2, _, _ = self.second(rig)
            with self.assertRaises(SG.SignerFail) as cm:
                rig.signer.sign(d2)
            self.assertEqual(cm.exception.code, "not_approved")

    def test_approval_describes_path_leaf_sighash(self):
        """Approval and fees: "Approval covers what the signature commits to, including the spend path and leaf.\""""
        rig = self.rig([K.Inp(K.Form("p2tr-script"), sighash=0x83)])
        self.rig_ = rig
        d2, pairs, _ = self.second(rig)
        rig.signer.sign(d2)
        sig = rig.approve.seen[0]["signatures"][0]
        self.assertEqual(sig["spend_path"], "taproot script path")
        self.assertEqual(sig["leaf_hash"], pairs[0].leaf.hex())
        self.assertEqual(sig["leaf_script"], pairs[0].script.hex())
        self.assertEqual(sig["sighash"], "SINGLE|ANYONECANPAY")
        rig = self.rig([K.Inp(K.Form("p2tr-key"))])
        self.rig_ = rig
        d2, _, _ = self.second(rig)
        rig.signer.sign(d2)
        self.assertEqual(rig.approve.seen[0]["signatures"][0]["spend_path"], "taproot key path")
        self.assertIsNone(rig.approve.seen[0]["signatures"][0]["leaf_hash"])

    def test_signer_independent_of_key_order(self):
        """Signer: "It looks up keys by identifier and does not depend on the order it holds them in.\""""
        inp = K.Inp(K.Form("p2wsh-2of3"))
        keys = K.held_of([inp])
        outs = []
        for order in (keys, list(reversed(keys))):
            rig = self.rig([inp], signer_keys=order)
            d2, _, _ = self.second(rig)
            outs.append(rig.signer.sign(d2))
        self.assertEqual(outs[0], outs[1])

    def test_v2_flags_cumulative(self):
        """Signer: "For version 2, apply the BIP 370 flag updates under the same rule as the host, cumulatively.\""""
        inputs = [K.Inp(K.Form("p2wpkh", "x1"), sighash=0x81), K.Inp(K.Form("p2wpkh", "x2"), sighash=3)]
        rig = self.rig(inputs, version=2, modifiable=0b11)
        self.rig_ = rig
        d2, _, _ = self.second(rig)
        out = C.parse(rig.signer.sign(d2))
        self.assertEqual(out.glob[b"\x06"], bytes([0b100]))
        inputs = [K.Inp(K.Form("p2wpkh", "x3"), sighash=1)]
        rig = self.rig(inputs, version=2)
        self.rig_ = rig
        d2, _, _ = self.second(rig)
        self.assertNotIn(b"\x06", C.parse(rig.signer.sign(d2)).glob)


class SighashRules(SignerBase):
    def run_pair(self, name, h_bytes, second=False):
        rig = self.setup_form(name)
        p = rig.psbt.clone()
        if h_bytes is not None:
            p.inputs[0][b"\x03"] = h_bytes
        return rig, (self.second(psbt=p)[0] if second else self.first(psbt=p)[0])

    def test_unsupported_values(self):
        """Sighash types: "Each party fails on any other value\" (on either pass)."""
        for name in ("p2wpkh", "p2pkh", "p2tr-key"):
            for h in (4, 0x84, 0x80, 0x40, 0x101):
                for second in (False, True):
                    rig, data = self.run_pair(name, struct.pack("<I", h), second)
                    self.fails(data, "sighash_unsupported", rig)

    def test_bad_length(self):
        rig, data = self.run_pair("p2wpkh", b"\x01")
        self.fails(data, "sighash_bad_length", rig)
        rig, data = self.run_pair("p2tr-key", b"\x01\x00\x00\x00\x00")
        self.fails(data, "sighash_bad_length", rig)

    def test_present_zero_ecdsa(self):
        """Sighash types: "... on a present zero for ECDSA\""""
        rig, data = self.run_pair("p2wpkh", b"\x00\x00\x00\x00")
        self.fails(data, "sighash_zero_ecdsa", rig)

    def test_zero_ok_for_bip340(self):
        """Sighash types: "and for BIP340 also SIGHASH_DEFAULT.\""""
        rig, data = self.run_pair("p2tr-key", b"\x00\x00\x00\x00", True)
        out = C.parse(rig.signer.sign(data))
        self.assertEqual(len(out.inputs[0][b"\x13"]), 64)

    def test_trailing_byte_unless_default(self):
        """Sighash types: "A BIP340 signature has a trailing sighash byte unless the type is SIGHASH_DEFAULT.\""""
        rig, data = self.run_pair("p2tr-key", struct.pack("<I", 0x81), True)
        out = C.parse(rig.signer.sign(data))
        self.assertEqual(len(out.inputs[0][b"\x13"]), 65)
        self.assertEqual(out.inputs[0][b"\x13"][-1], 0x81)

    def test_single_without_output(self):
        """Protocol: "A device MUST refuse SIGHASH_SINGLE with no matching output.\" PSBT: "on either pass\"."""
        for name in K.ALL_FORMS:
            for h in (3, 0x83):
                if name.startswith("p2tr") or h:
                    for second in (False, True):
                        form = K.Form(name)
                        inputs = [K.Inp(K.Form("p2wpkh", "pad")), K.Inp(K.Form("p2wpkh", "pad2")),
                                  K.Inp(form, sighash=h)]
                        rig = self.rig(inputs, outputs=[(1000, K.out_script())])
                        self.rig_ = rig
                        data = (self.second(rig)[0] if second else self.first(rig)[0])
                        data = self.mod(data, lambda p: [p.inputs[j].pop(k) for j in (0, 1) for k in
                                                         [kk for kk in p.inputs[j] if kk[:1] in (b"\x21", b"\x23")]])
                        self.fails(data, "sighash_single_no_output", rig)


class Unsupported(SignerBase):
    def test_uncompressed_key(self):
        """Unsupported: "uncompressed public keys\""""
        rig = self.setup_form()
        data, _, _ = self.first()
        unc = self.ae_set(data, lambda m: m.update({b"\x21" + b"\x04" + b"\x01" * 64: b"\x00" * 32}))
        self.fails(unc, "bad_keyid_length")

    def test_derivation_record_with_uncompressed_device_key(self):
        """Unsupported: "a derivation record whose 65-byte key, with prefix 0x04, 0x06 or 0x07, has the x coordinate of a device key\"."""
        rig = self.setup_form()
        data, pairs, _ = self.first()
        x, y = AE._mul(int.from_bytes(self.form.a, "big"))
        other_y = (2**256 - 2**32 - 977) - y
        for prefix, yy in ((4, y), (4, other_y), (6 + (y & 1), y)):
            unc = bytes([prefix]) + x.to_bytes(32, "big") + yy.to_bytes(32, "big")
            p = rig.psbt.clone()
            p.inputs[0][b"\x06" + unc] = b"\x00" * 4
            data, _ = K.req_first(p, pairs)
            self.fails(data, "uncompressed_key")
        # an uncompressed key that is not a device key is not examined
        p = rig.psbt.clone()
        x, y = AE._mul(12345)
        p.inputs[0][b"\x06\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")] = b"\x00" * 4
        data, _ = K.req_first(p, pairs)
        self.assertTrue(rig.signer.sign(data))

    def test_codeseparator_ecdsa(self):
        """Unsupported: "The script code for any pair MUST NOT contain OP_CODESEPARATOR as an opcode.\""""
        form = K.Form("p2wsh-single")
        pa = K.pub33(form.a)
        form.witness_script = b"\xab" + K.single(pa)
        form.spk = b"\x00\x20" + C.sha256(form.witness_script)
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        data, _, _ = self.first(psbt=rig.psbt)
        self.fails(data, "codeseparator")

    def test_codeseparator_as_data_is_not_an_opcode(self):
        """Same sentence: "as an opcode\" -- the byte 0xab inside a push is data."""
        form = K.Form("p2wsh-single")
        pa = K.pub33(form.a)
        form.witness_script = K.push(b"\xab\xab") + b"\x75" + K.single(pa)      # <ab ab> DROP <A> CHECKSIG
        form.spk = b"\x00\x20" + C.sha256(form.witness_script)
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        d2, _, _ = self.second(rig=rig, psbt=rig.psbt)
        C.parse(rig.signer.sign(d2))          # optional form, allowed by default

    def test_codeseparator_taproot(self):
        form = K.Form("p2tr-script")
        self.retarget_leaf(form, K.push(K.xonly(form.a)) + b"\xab\xac")
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        data, _, _ = self.first(psbt=rig.psbt)
        self.fails(data, "codeseparator")

    @staticmethod
    def retarget_leaf(form, script):
        """Change the form's leaf script and rebuild the commitments consistently."""
        form.leaf_script = script
        lh, sh = S.tap_leaf_hash(0xC0, script), S.tap_leaf_hash(0xC0, form.sibling)
        form.leaf_hash = lh
        form.root = S.tagged("TapBranch", min(lh, sh) + max(lh, sh))
        _, q, par = S.tweaked_xonly(form.internal, form.root)
        form.control = bytes([0xC0 | par]) + form.internal + sh
        form.spk = b"\x51\x20" + q

    def test_op_success(self):
        """Script-path pairs: "Scripts containing an OP_SUCCESSx opcode fail.\""""
        form = K.Form("p2tr-script")
        self.retarget_leaf(form, b"\x50" + K.push(K.xonly(form.a)) + b"\xac")
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        data, _, _ = self.first(psbt=rig.psbt)
        self.fails(data, "op_success")

    def test_musig2_participant(self):
        """Unsupported: "a Taproot input whose PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS lists a device key\""""
        for name in ("p2tr-key", "p2tr-script"):
            form = K.Form(name)
            rig = self.rig([K.Inp(form)])
            self.rig_ = rig
            p = rig.psbt.clone()
            agg = b"\x02" + b"\x33" * 32
            p.inputs[0][b"\x1a" + agg] = b"\x02" + K.xonly(form.a) + b"\x03" + b"\x44" * 32
            data, _, _ = self.first(psbt=p)
            self.fails(data, "musig2_participant")

    def test_musig2_aggregate_internal_key(self):
        """Unsupported: "... and a key-path input whose internal key is known to be an aggregate.\""""
        form = K.Form("p2tr-key")
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        p = rig.psbt.clone()
        p.inputs[0][b"\x1a" + b"\x02" + form.internal] = b"\x02" + b"\x44" * 32 + b"\x03" + b"\x55" * 32
        data, _, _ = self.first(psbt=p)
        self.fails(data, "musig2_aggregate")

    def test_non_minimal_key_type_fails(self):
        """Fields: "A key type written as a non-minimal CompactSize either fails or is read as the same number, and is never treated as an unknown field.\""""
        rig = self.setup_form()
        data, pairs, _ = self.first()
        pr = pairs[0]
        p = C.parse(data)
        v = p.inputs[0].pop(b"\x21" + pr.keyid)
        for prefix in (b"\xfd\x21\x00", b"\xfe\x21\x00\x00\x00", b"\xff\x21\x00\x00\x00\x00\x00\x00\x00"):
            q = C.parse(data)
            del q.inputs[0][b"\x21" + pr.keyid]
            q.inputs[0][prefix + pr.keyid] = v
            self.fails(q.serialize(), "nonminimal_compact")
        # a minimal key type above 0xfc stays an ordinary unknown field
        q = C.parse(data)
        q.inputs[0][b"\xfd\x00\x01" + pr.keyid] = v
        self.assertTrue(rig.signer.sign(q.serialize()))

    def test_multisig_key_must_be_valid(self):
        """Required forms: "each key a direct push of a valid 33-byte key"."""
        import hashlib
        x = next(i for i in range(1, 100) if AE._parse33(b"\x02" + i.to_bytes(32, "big")) is AE._INF)
        f = K.Form("p2wsh-2of3")
        script = bytes([0x52]) + K.push(K.pub33(f.a)) + K.push(K.pub33(f.b)) + K.push(b"\x02" + x.to_bytes(32, "big")) + bytes([0x53, 0xae])
        f.witness_script = script
        f.spk = b"\x00\x20" + hashlib.sha256(script).digest()
        rig = self.rig([K.Inp(f)])
        self.rig_ = rig
        data, _ = K.req_first(rig.psbt, K.manual_pairs(rig))
        self.fails(data, "key_ambiguous")

    def test_path_purpose_of_the_other_scheme_fails(self):
        """Signer: "A signer SHOULD keep each key to one scheme, by failing on a pair whose derivation path purpose does not match ... where it can tell.\""""
        fp = b"\x01\x02\x03\x04"
        hard = lambda n: (0x80000000 | n).to_bytes(4, "little")
        rig = self.setup_form()
        data, pairs, _ = self.first()
        pub = pairs[0].keyid
        for path, code in ((hard(86), "scheme_purpose_mismatch"), (hard(84), None), ((86).to_bytes(4, "little"), None)):
            p = rig.psbt.clone()
            p.inputs[0][b"\x06" + pub] = fp + path
            q, _ = K.req_first(p, pairs)
            if code:
                self.fails(q, code)
            else:
                self.assertTrue(rig.signer.sign(q))
        form = K.Form("p2tr-key")
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        for path, code in ((hard(84), "scheme_purpose_mismatch"), (hard(44), "scheme_purpose_mismatch"), (hard(49), "scheme_purpose_mismatch"), (hard(86), None)):
            p = rig.psbt.clone()
            p.inputs[0][b"\x16" + form.internal] = C.compact(0) + fp + path
            q, _, _ = self.first(psbt=p)
            if code:
                self.fails(q, code)
            else:
                self.assertTrue(rig.signer.sign(q))

    def test_malformed_modifiable_flags_fail_before_any_prompt(self):
        """Signer: "Before prompting or producing output, the signer validates the structure"."""
        form = K.Form("p2wpkh")
        rig = self.rig([K.Inp(form)], version=2)
        self.rig_ = rig
        data, pairs, _ = self.first()
        p = C.parse(data)
        p.glob[b"\x06"] = b"\x00\x00"
        before = len(rig.approve.seen)
        self.fails(p.serialize(), "bad_modifiable")
        self.assertEqual(len(rig.approve.seen), before)

    def test_optional_form_counts_only_a_key_before_a_signature_opcode(self):
        """Optional forms: "exactly one `OP_CHECKSIG` or `OP_CHECKSIGVERIFY` is immediately preceded by a direct push of the key"."""
        import hashlib
        f = K.Form("p2wsh-single")
        pk = K.pub33(f.a)
        script = K.push(pk) + bytes([0x75]) + K.push(pk) + bytes([0xac])        # <K> DROP <K> CHECKSIG
        f.witness_script = script
        f.spk = b"\x00\x20" + hashlib.sha256(script).digest()
        rig = self.rig([K.Inp(f)])
        self.rig_ = rig
        data, _ = K.req_first(rig.psbt, K.manual_pairs(rig))
        self.assertTrue(rig.signer.sign(data))
        script = K.push(pk) + bytes([0xad]) + K.push(pk) + bytes([0xac])        # <K> CHECKSIGVERIFY <K> CHECKSIG
        f = K.Form("p2wsh-single")
        f.witness_script = script
        f.spk = b"\x00\x20" + hashlib.sha256(script).digest()
        rig = self.rig([K.Inp(f)])
        self.rig_ = rig
        data, _ = K.req_first(rig.psbt, K.manual_pairs(rig))
        self.fails(data, "key_ambiguous")

    def test_aggregate_internal_key_on_a_script_path_is_allowed(self):
        """Unsupported: "A script-path pair under an aggregate internal key is allowed if the device is not a participant.\""""
        form = K.Form("p2tr-script")
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        p = rig.psbt.clone()
        p.inputs[0][b"\x1a" + b"\x02" + form.internal] = b"\x02" + b"\x44" * 32 + b"\x03" + b"\x55" * 32
        data, _, _ = self.first(psbt=p)
        self.assertTrue(rig.signer.sign(data))

    def test_optional_forms_can_be_refused(self):
        """Optional forms: "A signer fails on any form it does not support.\""""
        for name in ("p2sh-single", "p2tr-script", "p2tr-multi_a"):
            rig = self.rig([K.Inp(K.Form(name))])
            rig.signer.optional_forms = False
            self.rig_ = rig
            pr = None
            data, _ = K.req_first(rig.psbt, self.host_pairs(rig))
            with self.assertRaises(SG.SignerFail) as cm:
                rig.signer.sign(data)
            self.assertIn(cm.exception.code, ("optional_form_unsupported",))

    def host_pairs(self, rig):
        rig.host.optional_forms = True
        return K.pairs_of(rig)

    def test_other_script_forms(self):
        """Required forms list: a script that is not a required form is refused unless an optional form applies."""
        form = K.Form("p2wsh-single")
        pa = K.pub33(form.a)
        form.witness_script = b"\x51" + b"\x75" + K.single(pa)          # 1 DROP <A> CHECKSIG: optional-only
        form.spk = b"\x00\x20" + C.sha256(form.witness_script)
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        data, pairs, _ = self.first(rig=rig)
        C.parse(rig.signer.sign(data))
        rig.signer.optional_forms = False
        self.fails(data, "unsupported_script")


class TaprootScriptPair(SignerBase):
    def prep(self, name="p2tr-script"):
        form = K.Form(name)
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        return form, rig

    def test_leaf_missing(self):
        """Script-path pairs: "Exactly one PSBT_IN_TAP_LEAF_SCRIPT entry MUST match the leaf hash.\""""
        form, rig = self.prep()
        p = rig.psbt.clone()
        for k in [k for k in p.inputs[0] if k[:1] == b"\x15" and p.inputs[0][k] == form.leaf_script + b"\xc0"]:
            del p.inputs[0][k]
        data, _, _ = req_with_pairs(self, rig, p, form)
        self.fails(data, "tap_leaf_missing")

    def test_leaf_ambiguous(self):
        form, rig = self.prep()
        p = rig.psbt.clone()
        p.inputs[0][b"\x15" + bytes([form.control[0] ^ 1]) + form.control[1:]] = form.leaf_script + b"\xc0"      # second entry, same leaf, other parity bit
        data, _, _ = req_with_pairs(self, rig, p, form)
        self.fails(data, "tap_leaf_ambiguous")

    def test_leaf_version(self):
        """Script-path pairs: "Its leaf version MUST be 0xC0\""""
        form, rig = self.prep()
        p = rig.psbt.clone()
        k = b"\x15" + form.control
        script = p.inputs[0].pop(k)[:-1]
        # keep the pair's leaf hash fixed by also fixing nothing else: use a leaf under another version
        lh = S.tap_leaf_hash(0xC2, script)
        ctrl = bytes([0xC2 | form.control[0] & 1]) + form.control[1:]
        p.inputs[0][b"\x15" + ctrl] = script + b"\xc2"
        keyid = K.xonly(form.a) + lh
        data = self.mod(p.serialize(), lambda q: q.inputs[0].update({b"\x21" + keyid: b"\x00" * 32}))
        self.fails(data, "tap_leaf_version")

    def test_control_block_mismatch(self):
        """Script-path pairs: "its control block MUST compute the spent output key\" (otherwise valid PSBT)."""
        form, rig = self.prep()
        p = rig.psbt.clone()
        k = b"\x15" + form.control
        bad = bytes(form.control[:-1]) + bytes([form.control[-1] ^ 1])
        p.inputs[0][b"\x15" + bad] = p.inputs[0].pop(k)
        data, _, _ = req_with_pairs(self, rig, p, form)
        self.fails(data, "tap_control_mismatch")

    def test_control_block_depth(self):
        """Script-path pairs: "... with at most 128 path elements.\""""
        form, rig = self.prep()
        p = rig.psbt.clone()
        k = b"\x15" + form.control
        # 129 path elements: build a tree on top of the one leaf so the output key is consistent
        node, path = form.leaf_hash, []
        for j in range(129):
            sib = bytes([j]) * 32
            path.append(sib)
            node = S.tagged("TapBranch", min(node, sib) + max(node, sib))
        _, q, par = S.tweaked_xonly(form.internal, node)
        ctrl = bytes([0xC0 | par]) + form.internal + b"".join(path)
        spk = b"\x51\x20" + q
        form.spk = spk
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        p = rig.psbt.clone()
        for kk in [kk for kk in p.inputs[0] if kk[:1] == b"\x15"]:
            del p.inputs[0][kk]
        p.inputs[0][b"\x15" + ctrl] = form.leaf_script + b"\xc0"
        data, _, _ = req_with_pairs(self, rig, p, form)
        self.fails(data, "tap_control_depth")
        # and 128 is allowed
        ctrl128 = ctrl[:-32]
        node = form.leaf_hash
        for sib in path[:-1]:
            node = S.tagged("TapBranch", min(node, sib) + max(node, sib))
        _, q, par = S.tweaked_xonly(form.internal, node)
        form.spk = b"\x51\x20" + q
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        p = rig.psbt.clone()
        for kk in [kk for kk in p.inputs[0] if kk[:1] == b"\x15"]:
            del p.inputs[0][kk]
        p.inputs[0][b"\x15" + bytes([0xC0 | par]) + ctrl128[1:]] = form.leaf_script + b"\xc0"
        d2, _, _ = req_with_pairs(self, rig, p, form, second=True)
        C.parse(rig.signer.sign(d2))

    def test_key_mapping_zero_and_two(self):
        """Script-path pairs: "Exactly one OP_CHECKSIG, OP_CHECKSIGVERIFY or OP_CHECKSIGADD in the leaf MUST be immediately preceded by a 32-byte direct push of this key.\""""
        for script_fn, name in ((lambda f: K.push(K.xonly(f.b)) + b"\xac", "other key only"),
                                (lambda f: K.push(K.xonly(f.a)) + b"\x75\xac", "key not adjacent to sigop"),
                                (lambda f: K.push(K.xonly(f.a)) + b"\xac" + K.push(K.xonly(f.a)) + b"\xad", "twice"),
                                (lambda f: b"\x4c\x20" + K.xonly(f.a) + b"\xac", "pushdata1 is not a direct push")):
            form = K.Form("p2tr-script")
            new = script_fn(form)
            self.retarget_leaf_and_keyid(form, new)
            rig = self.rig([K.Inp(form)])
            self.rig_ = rig
            data, _, _ = req_with_pairs(self, rig, rig.psbt, form)
            with self.subTest(name):
                self.fails(data, "tap_mapping")

    def retarget_leaf_and_keyid(self, form, script):
        Unsupported.retarget_leaf(form, script)

    def test_other_keys_do_not_count(self):
        """Script-path pairs: "Other keys in the leaf do not count.\" (multi_a: three keys, one pair each)"""
        form, rig = self.prep("p2tr-multi_a")
        d2, pairs, _ = self.second(rig)
        out = C.parse(rig.signer.sign(d2))
        self.assertEqual(len([k for k in out.inputs[0] if k[:1] == b"\x14"]), 2)

    def test_other_leaves_ignored(self):
        """Validation scope: "Leaves other than the requested one are ignored.\""""
        form, rig = self.prep()
        p = rig.psbt.clone()
        p.inputs[0][b"\x15" + b"\xc2" + b"\x01" * 32] = b"\x50\xc2"                 # junk leaf, bad version/control
        p.inputs[0][b"\x15" + b"\xc0" + b"\x01" * 64] = b"\xab\xab\xc0"               # junk with codeseparator
        d2, _, _ = req_with_pairs(self, rig, p, form, second=True)
        C.parse(rig.signer.sign(d2))


def req_with_pairs(tc, rig, p, form, second=False):
    """Build a request for the script-path pair of `form` on psbt p without running host checks."""
    keyid = K.xonly(form.a) + form.leaf_hash
    rho = K.hashlib.sha256(b"r").digest()
    out = p.clone()
    if second:
        out.inputs[0][b"\x23" + keyid] = rho
    else:
        out.inputs[0][b"\x21" + keyid] = AE.host_commit(rho)
    return out.serialize(), None, None


class ValidationScope(SignerBase):
    def prep(self, name, **kw):
        form = K.Form(name)
        rig = self.rig([K.Inp(form, **kw)])
        self.rig_ = rig
        return form, rig

    def test_final_inputs(self):
        """Validation scope: "Each party fails on a requested input with a final scriptSig or final witness\""""
        for key in (b"\x07", b"\x08"):
            form, rig = self.prep("p2wpkh")
            p = rig.psbt.clone()
            p.inputs[0][key] = b"\x00"
            data, _, _ = self.first(psbt=p)
            self.fails(data, "finalized_input")

    def test_missing_and_mismatched_utxo(self):
        """Validation scope: "... missing or mismatched data that the input's signature hash needs: a UTXO field\""""
        form, rig = self.prep("p2wpkh")
        p = rig.psbt.clone()
        del p.inputs[0][b"\x00"]
        data, _, _ = self.first(psbt=p)
        self.fails(data, "missing_utxo")
        form, rig = self.prep("p2wpkh", utxo="both")
        p = rig.psbt.clone()
        p.inputs[0][b"\x01"] = struct.pack("<Q", 5) + C.blob(form.spk)
        data, _, _ = self.first(psbt=p)
        self.fails(data, "utxo_disagree")

    def test_non_witness_utxo_must_hash_to_txid_and_hold_index(self):
        """Validation scope: "A PSBT_IN_NON_WITNESS_UTXO MUST hash to the input's previous txid and contain its output index.\""""
        form, rig = self.prep("p2wpkh")
        other = K.fake_prev(form.spk, 100000)
        p = rig.psbt.clone()
        p.inputs[0][b"\x00"] = other.txbytes
        data, _, _ = self.first(psbt=p)
        self.fails(data, "nonwitness_txid_mismatch")
        tx = C.core_tx(rig.psbt)
        p = rig.psbt.clone()
        p.glob[b"\x00"] = C.ser_tx(C.Tx(tx.version, [(tx.ins[0][0], 9, b"", tx.ins[0][3])], tx.outs, tx.locktime))
        data, _, _ = self.first(psbt=p)
        self.fails(data, "nonwitness_index")

    def test_redeem_and_witness_script_mismatch(self):
        """Validation scope: "... redeem script, witness script or Taproot output key.\""""
        form, rig = self.prep("p2sh-p2wpkh")
        p = rig.psbt.clone()
        p.inputs[0][b"\x04"] = b"\x00\x14" + b"\x01" * 20
        data, _, _ = self.first(psbt=p)
        self.fails(data, "redeem_script_mismatch")
        form, rig = self.prep("p2wsh-single")
        p = rig.psbt.clone()
        del p.inputs[0][b"\x05"]
        data, _, _ = self.first(psbt=p)
        self.fails(data, "witness_script_mismatch")
        form, rig = self.prep("p2sh-p2wsh-single")
        p = rig.psbt.clone()
        p.inputs[0][b"\x05"] = K.single(K.pub33(form.b))
        data, _, _ = self.first(psbt=p)
        self.fails(data, "witness_script_mismatch")

    def test_taproot_output_key_mismatch(self):
        form, rig = self.prep("p2tr-key-root")
        p = rig.psbt.clone()
        del p.inputs[0][b"\x18"]              # the merkle root is needed to reach the output key
        data, _, _ = self.first(psbt=p)
        self.fails(data, "tap_output_key_mismatch")
        form, rig = self.prep("p2tr-key")
        p = rig.psbt.clone()
        p.inputs[0][b"\x18"] = b"\x09" * 32
        data, _, _ = self.first(psbt=p)
        self.fails(data, "tap_output_key_mismatch")

    def test_key_path_identifier_must_equal_present_internal_key(self):
        """PSBT: a key-path pair fails if PSBT_IN_TAP_INTERNAL_KEY is present and differs from the identifier."""
        form, rig = self.prep("p2tr-key")
        pairs = self.pairs(rig)
        p = rig.psbt.clone()
        self.assertEqual(p.inputs[0][b"\x17"], pairs[0].keyid)
        p.inputs[0][b"\x17"] = AE.public_key(b"\x00" * 31 + b"\x07")
        data, _ = K.req_first(p, pairs)
        self.fails(data, "internal_key_mismatch")

    def test_key_path_secret_must_match_internal_key(self):
        """PSBT: key-path pairs use the internal key; the held secret must belong to it (explicit check)."""
        form, rig = self.prep("p2tr-key")
        other = K.seedkey("someone else")
        rig.signer._by_x[form.internal] = other
        data, _, _ = self.first()
        self.fails(data, "key_mismatch")

    def test_legacy_needs_non_witness_utxo(self):
        form, rig = self.prep("p2pkh", utxo="wit")
        data, _, _ = self.first()
        self.fails(data, "legacy_needs_nonwitness")

    def test_taproot_non_acp_needs_every_prevout(self):
        """Validation scope: "Taproot pairs without ANYONECANPAY also need every input's previous output.\""""
        foreign = K.Inp(K.Form("p2wpkh", "foreign"))
        mine = K.Inp(K.Form("p2tr-key"))
        rig = self.rig([foreign, mine], signer_keys=K.held_of([mine]))
        self.rig_ = rig
        p = rig.psbt.clone()
        del p.inputs[0][b"\x00"]
        data, _, _ = self.first(psbt=p)
        self.fails(data, "taproot_prevouts_missing")
        # with ANYONECANPAY only the pair's own prevout is needed
        mine2 = K.Inp(K.Form("p2tr-key", "acp"), sighash=0x81)
        rig = self.rig([K.Inp(K.Form("p2wpkh", "foreign2")), mine2], signer_keys=K.held_of([mine2]))
        self.rig_ = rig
        p = rig.psbt.clone()
        del p.inputs[0][b"\x00"]
        d2, _, _ = self.second(psbt=p)
        C.parse(rig.signer.sign(d2))

    def test_inputs_without_pair_are_unconstrained(self):
        """Validation scope: "Inputs with no pair are not otherwise constrained ... They may be finalized, unclassifiable or held by other signers.\""""
        rig = self.rig([K.Inp(K.Form("p2wpkh", "m")), K.Inp(K.Form("p2wpkh", "f1")), K.Inp(K.Form("p2wpkh", "f2")),
                        K.Inp(K.Form("p2wsh-single", "f3"))])
        self.rig_ = rig
        p = rig.psbt.clone()
        p.inputs[1][b"\x08"] = b"\x00"                    # finalized by someone else
        p.inputs[2][b"\x01"] = b"garbage"                 # unclassifiable UTXO
        p.inputs[2].pop(b"\x00")
        del p.inputs[3][b"\x05"]                          # script missing
        pairs = K.pairs_of(rig, rig.psbt)
        pairs = [pr for pr in pairs if pr.index == 0]
        _, rhos = K.req_first(p, pairs)
        d2 = K.req_second(p, pairs, rhos)
        out = C.parse(rig.signer.sign(d2))
        self.assertIn(b"\x08", out.inputs[1])
        self.assertTrue([k for k in out.inputs[0] if k[:1] == b"\x02"])
        self.assertEqual(rig.approve.seen[0]["fee_verified"], False)

    def test_fee_verification_wording(self):
        """Approval and fees: "MUST NOT present a fee as verified unless it verified every input amount\""""
        form, rig = self.prep("p2wpkh", utxo="wit")
        d2, _, _ = self.second()
        rig.signer.sign(d2)
        desc = rig.approve.seen[-1]
        self.assertFalse(desc["fee_verified"])
        self.assertIsNone(desc["fee"])
        self.assertEqual(desc["unverified_inputs"], [0])
        form, rig = self.prep("p2wpkh", utxo="non")
        d2, _, _ = self.second()
        rig.signer.sign(d2)
        self.assertTrue(rig.approve.seen[-1]["fee_verified"])
        self.assertEqual(rig.approve.seen[-1]["fee"], 1000)
        # Taproot without ANYONECANPAY: the sighash commits to the amounts, so they count as verified
        form, rig = self.prep("p2tr-key", utxo="wit")
        d2, _, _ = self.second()
        rig.signer.sign(d2)
        self.assertTrue(rig.approve.seen[-1]["fee_verified"])
        # with ANYONECANPAY it does not
        form = K.Form("p2tr-key", "acp")
        rig = self.rig([K.Inp(form, utxo="wit", sighash=0x81)])
        self.rig_ = rig
        d2, _, _ = self.second()
        rig.signer.sign(d2)
        self.assertFalse(rig.approve.seen[-1]["fee_verified"])

    def test_outputs_exceeding_inputs(self):
        form = K.Form("p2wpkh")
        rig = self.rig([K.Inp(form)], outputs=[(10**9, K.out_script())])
        self.rig_ = rig
        d2, _, _ = self.second()
        self.fails(d2, "outputs_exceed_inputs")


class MoreRefusals(SignerBase):
    def test_unsupported_spent_script_and_wrong_scheme(self):
        """Spends: "A signer fails on any form it does not support.\""""
        form = K.Form("p2wpkh")
        form.spk = b"\x52\x20" + b"\x01" * 32                 # witness v2
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        data, _, _ = self.first(rig, rig.psbt)
        self.fails(data, "unsupported_script")
        form = K.Form("p2tr-key")
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        a = K.Form("p2wpkh")
        d = K.req_first(rig.psbt, [K.KP(0, K.pub33(form.a), "ecdsa")])[0]
        self.fails(d, "wrong_scheme")
        rig = self.rig([K.Inp(K.Form("p2wpkh"))])
        self.rig_ = rig
        d = K.req_first(rig.psbt, [K.KP(0, K.xonly(rig.inputs[0].form.a), "bip340")])[0]
        self.fails(d, "wrong_scheme")

    def test_ecdsa_key_must_match_script(self):
        rig = self.rig([K.Inp(K.Form("p2wpkh"))])
        self.rig_ = rig
        other = K.pub33(K.seedkey("not in script"))
        rig.signer._by_pub33[other] = K.seedkey("not in script")
        d = K.req_first(rig.psbt, [K.KP(0, other, "ecdsa")])[0]
        self.fails(d, "key_not_in_script")

    def test_caps_fail_and_never_truncate(self):
        """Validation scope: "An implementation MAY cap sizes and counts; exceeding a cap fails and never truncates.\""""
        form = K.Form("p2wsh-single")
        form.witness_script = K.single(K.pub33(form.a)) + b"\x61" * (S.MAX_SCRIPT + 1)
        form.spk = b"\x00\x20" + C.sha256(form.witness_script)
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        data, _, _ = self.first(rig, rig.psbt)
        self.fails(data, "cap_exceeded")

    def test_bad_merkle_root(self):
        form = K.Form("p2tr-key")
        rig = self.rig([K.Inp(form)])
        self.rig_ = rig
        p = rig.psbt.clone()
        p.inputs[0][b"\x18"] = b"\x01" * 31
        data, _, _ = self.first(psbt=p)
        self.fails(data, "bad_merkle_root")


class RuleGaps(SignerBase):
    """Tests added for survivors of the requirement mutants classed test_gap."""

    def script_form(self, script):
        f = K.Form("p2wsh-single")
        f.witness_script = script
        f.spk = b"\x00\x20" + C.sha256(script)
        rig = self.rig([K.Inp(f)])
        self.rig_ = rig
        data, _ = K.req_first(rig.psbt, K.manual_pairs(rig))
        return rig, data

    def not_a_required_form(self, script):
        """A script that is not a required form fails: as unsupported with optional forms off, as an
        ambiguous key (not exactly one direct push before a signature opcode) with them on."""
        rig, data = self.script_form(script)
        self.fails(data, "key_ambiguous")
        rig.signer.optional_forms = False
        self.fails(data, "unsupported_script")

    def test_numbers_in_global_and_output_maps_survive_the_signer(self):
        """Fields: "The same numbers in a global or output map are ordinary unknown fields.\""""
        rig = self.setup_form()
        p = rig.psbt.clone()
        p.glob[b"\x21" + b"k" * 33] = b"g1"
        p.glob[b"\x23" + b"k" * 33] = b"g2"
        p.outputs[0][b"\x22" + b"k" * 33] = b"o1"
        d1, pairs, rhos = self.first(psbt=p)
        for data in (d1, K.req_second(p, pairs, rhos)):
            out = C.parse(rig.signer.sign(data))
            self.assertEqual(out.glob[b"\x21" + b"k" * 33], b"g1")
            self.assertEqual(out.glob[b"\x23" + b"k" * 33], b"g2")
            self.assertEqual(out.outputs[0][b"\x22" + b"k" * 33], b"o1")

    def test_missing_xonly_secret(self):
        """Signer: "It fails ... if it does not hold the key\""""
        for name in ("p2tr-key", "p2tr-script"):
            rig = self.setup_form(name)
            rig.signer._by_x.clear()
            data, _, _ = self.first()
            self.fails(data, "key_not_held")

    def test_pair_cap_fails_and_never_truncates(self):
        """Validation scope: "An implementation MAY cap sizes and counts; exceeding a cap fails and never truncates.\""""
        rig = self.rig([K.Inp(K.Form("p2wsh-2of3")), K.Inp(K.Form("p2wsh-2of3"))])
        self.rig_ = rig
        data, _ = K.req_first(rig.psbt, K.manual_pairs(rig))
        with mock.patch.object(S, "MAX_PAIRS", 3):
            self.fails(data, "cap_exceeded")
        with mock.patch.object(S, "MAX_PAIRS", 4):
            self.assertTrue(rig.signer.sign(data))

    def test_required_forms_work_with_optional_forms_off(self):
        """Required forms: "Signers MUST support P2PKH, P2WPKH, P2SH-P2WPKH, the Taproot key path, and P2WSH and P2SH-P2WSH whose witness script is exactly one of:\""""
        for name in K.REQUIRED_FORMS:
            rig = self.setup_form(name)
            rig.signer.optional_forms = False
            data, _, _ = self.first()
            self.assertTrue(rig.signer.sign(data), name)

    def test_sixteen_key_multisig(self):
        """Required forms: "`OP_m <key> ... <key> OP_n OP_CHECKMULTISIG`, with `1 <= m <= n <= 16`\""""
        keys = [K.pub33(K.seedkey("f/a"))] + [K.pub33(K.seedkey("k%d" % i)) for i in range(15)]
        f = K.Form("p2wsh-single")
        keys[0] = K.pub33(f.a)
        script = K.multisig(2, keys)
        self.assertEqual(script[-2], 0x60)
        rig, data = self.script_form(script)
        self.assertTrue(rig.signer.sign(data))
        rig.signer.optional_forms = False
        self.assertTrue(rig.signer.sign(data))

    def test_multisig_m_greater_than_n_is_not_a_required_form(self):
        """Required forms: "with `1 <= m <= n <= 16`\""""
        f = K.Form("p2wsh-single")
        self.not_a_required_form(bytes([0x53]) + K.push(K.pub33(f.a)) + K.push(K.pub33(f.b)) + bytes([0x52, 0xAE]))

    def test_multisig_n_must_equal_the_number_of_keys(self):
        """Required forms: "`OP_m <key> ... <key> OP_n OP_CHECKMULTISIG`\""""
        f = K.Form("p2wsh-single")
        self.not_a_required_form(bytes([0x52]) + K.push(K.pub33(f.a)) + K.push(K.pub33(f.b)) + K.push(K.pub33(f.c)) + bytes([0x52, 0xAE]))

    def test_multisig_key_with_a_bad_prefix_is_not_a_required_form(self):
        """Required forms: "each key a direct push of a valid 33-byte key\""""
        f = K.Form("p2wsh-single")
        bad = b"\x04" + b"\x11" * 32
        self.not_a_required_form(bytes([0x52]) + K.push(K.pub33(f.a)) + K.push(K.pub33(f.b)) + K.push(bad) + bytes([0x53, 0xAE]))

    def test_op_pushdata_key_is_not_a_direct_push(self):
        """Direct push: "`OP_PUSHDATA` forms do not count.\""""
        f = K.Form("p2wsh-single")
        pa, pb, pc = K.pub33(f.a), K.pub33(f.b), K.pub33(f.c)
        self.not_a_required_form(b"\x4c\x21" + pa + b"\xac")
        self.not_a_required_form(bytes([0x52]) + K.push(pa) + K.push(pb) + b"\x4c\x21" + pc + bytes([0x53, 0xAE]))

    def test_musig2_participant_in_either_parity_form(self):
        """Unsupported: "a Taproot input with a pair whose `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` lists a device key, in either parity form\""""
        for name in ("p2tr-key", "p2tr-script"):
            for prefix in (b"\x02", b"\x03"):
                form = K.Form(name)
                rig = self.rig([K.Inp(form)])
                self.rig_ = rig
                p = rig.psbt.clone()
                p.inputs[0][b"\x1a" + b"\x02" + b"\x33" * 32] = b"\x02" + b"\x44" * 32 + prefix + K.xonly(form.a)
                data, _, _ = self.first(psbt=p)
                self.fails(data, "musig2_participant")

    def test_key_hash_must_match_the_script_in_every_hash_form(self):
        """Fails: "if a derivation record names a device key the input's script does not contain\""""
        for name in ("p2pkh", "p2wpkh", "p2sh-p2wpkh"):
            rig = self.rig([K.Inp(K.Form(name))])
            self.rig_ = rig
            other = K.pub33(K.seedkey("not in script"))
            rig.signer._by_pub33[other] = K.seedkey("not in script")
            d = K.req_first(rig.psbt, [K.KP(0, other, "ecdsa")])[0]
            self.fails(d, "key_not_in_script")


class EdgeCases(SignerBase):
    """Sighash names, step 2 failures, script and WITNESS_UTXO edges and DER integers with length zero."""

    def script_form(self, script):
        f = K.Form("p2wsh-single")
        f.witness_script = script
        f.spk = b"\x00\x20" + C.sha256(script)
        rig = self.rig([K.Inp(f)])
        self.rig_ = rig
        data, _ = K.req_first(rig.psbt, K.manual_pairs(rig))
        return rig, data

    def test_sighash_names_tell_default_from_all(self):
        """Second pass: the approval description names the sighash type; DEFAULT is not ALL."""
        self.assertEqual(SG.sighash_name(0), "DEFAULT")
        self.assertEqual(SG.sighash_name(1), "ALL")
        self.assertNotEqual(SG.sighash_name(0), SG.sighash_name(1))
        self.assertEqual([SG.sighash_name(h) for h in (2, 3, 0x81, 0x82, 0x83)],
                         ["NONE", "SINGLE", "ALL|ANYONECANPAY", "NONE|ANYONECANPAY", "SINGLE|ANYONECANPAY"])
        rig = self.setup_form("p2tr-key", version=0)
        data, pairs, rhos = self.second()
        rig.signer.sign(data)
        self.assertEqual(rig.approve.seen[0]["signatures"][0]["sighash"], "DEFAULT")

    def test_step2_value_error_is_a_signer_fail(self):
        """Signer: it fails the whole PSBT with a reason code; a failure inside step 2 returns nothing."""
        for name in ("p2wpkh", "p2tr-key", "p2tr-script"):
            rig = self.setup_form(name)
            pr = K.pairs_of(rig)[0]
            for hc in (b"\x00" * 31, b""):
                with self.assertRaises(SG.SignerFail) as cm:
                    SG.Signer._commit(pr, self.form.a, hc)
                self.assertEqual(cm.exception.code, "step2_failed", name)
            self.assertEqual(len(SG.Signer._commit(pr, self.form.a, AE.ecdsa_host_commit(b"\x01" * 32))), 33)

    def test_script_of_exactly_the_cap_is_accepted(self):
        """Validation scope: "An implementation MAY cap sizes and counts; exceeding a cap fails and never truncates.\""""
        self.assertEqual(len(S.parse_script(b"\x61" * S.MAX_SCRIPT)), S.MAX_SCRIPT)
        with self.assertRaises(S.SpendError) as cm:
            S.parse_script(b"\x61" * (S.MAX_SCRIPT + 1))
        self.assertEqual(cm.exception.code, "cap_exceeded")

    def test_one_of_two_multisig_is_a_required_form(self):
        """Required forms: "`OP_m <key> ... <key> OP_n OP_CHECKMULTISIG`, with `1 <= m <= n <= 16`\""""
        f = K.Form("p2wsh-single")
        pa, pb = K.pub33(f.a), K.pub33(f.b)
        for keys in ([pa, pb], [pb, pa]):
            script = K.multisig(1, keys)
            self.assertEqual(S.ecdsa_script_check(script, pa, False), "multisig")
            rig, data = self.script_form(script)
            self.assertTrue(rig.signer.sign(data))
            rig.signer.optional_forms = False
            self.assertTrue(rig.signer.sign(data))
            self.assertTrue(rig.signer.sign(self.second(rig)[0]))

    def test_device_key_as_the_last_op_is_ambiguous_not_an_index_error(self):
        """Direct push: a key not directly before a signature opcode is ambiguous; a key push that ends the script has no opcode after it."""
        f = K.Form("p2wsh-single")
        pa, pb = K.pub33(f.a), K.pub33(f.b)
        for script in (K.push(pb) + b"\xad" + K.push(pa), K.push(pb) + b"\xac" + K.push(pa), K.push(pa)):
            with self.assertRaises(S.SpendError) as cm:
                S.ecdsa_script_check(script, pa, True)
            self.assertEqual(cm.exception.code, "key_ambiguous")
            rig, data = self.script_form(script)
            self.fails(data, "key_ambiguous")
            rig.signer.optional_forms = False
            self.fails(data, "unsupported_script")

    def test_witness_utxo_script_running_past_the_end(self):
        """Fields: a WITNESS_UTXO whose script length runs past its end is malformed and fails."""
        rig = self.setup_form("p2wpkh", utxo="wit")
        for tail in (b"\x32" + b"\x00" * 3, b"\xfd\x20\x00" + b"\x00" * 5, b"\x16" + rig.inputs[0].form.spk[1:]):
            p = rig.psbt.clone()
            p.inputs[0][b"\x01"] = struct.pack("<Q", rig.inputs[0].value) + tail
            with self.assertRaises(S.SpendError) as cm:
                S.txout_of(p, 0)
            self.assertEqual(cm.exception.code, "bad_witness_utxo")
            data, _, _ = self.first(psbt=p)
            self.fails(data, "bad_witness_utxo")

    def test_witness_utxo_with_trailing_bytes(self):
        """Fields: bytes after the script of a WITNESS_UTXO are malformed and fail."""
        rig = self.setup_form("p2wpkh", utxo="wit")
        p = rig.psbt.clone()
        p.inputs[0][b"\x01"] = struct.pack("<Q", rig.inputs[0].value) + C.blob(rig.inputs[0].form.spk) + b"\x00"
        with self.assertRaises(S.SpendError) as cm:
            S.txout_of(p, 0)
        self.assertEqual(cm.exception.code, "bad_witness_utxo")

    def test_psbt_version_field_of_the_wrong_length(self):
        """BIP 174: PSBT_GLOBAL_VERSION is 4 bytes."""
        rig = self.setup_form("p2wpkh")
        p = rig.psbt.clone()
        p.glob[b"\xfb"] = b"\x00" * 5
        with self.assertRaises(C.PsbtError) as cm:
            C.parse(p.serialize())
        self.assertEqual(cm.exception.code, "bad_version")

    def test_taproot_single_with_no_output_at_the_exact_index(self):
        """SIGHASH_SINGLE with no matching output fails by name when the index equals the output count."""
        tx = C.Tx(2, [(b"\x00" * 32, 0, b"", 0)], [], 0)
        with self.assertRaises(S.SpendError) as cm:
            S.tap_sighash(tx, 0, [(1, b"\x51\x20" + b"\x00" * 32)], 3)
        self.assertEqual(cm.exception.code, "sighash_single_no_output")

    def test_empty_leaf_script_value_matches_nothing_in_the_signer(self):
        """A TAP_LEAF_SCRIPT entry with an empty value holds no leaf version, so it matches no leaf hash."""
        rig = self.setup_form("p2tr-script")
        pr = K.pairs_of(rig)[0]
        p = rig.psbt.clone()
        for k in [k for k in p.inputs[0] if k[:1] == b"\x15"]:
            p.inputs[0][k] = b""
        with self.assertRaises(S.SpendError) as cm:
            S.resolve_pair(p, 0, pr.keyid, set())
        self.assertEqual(cm.exception.code, "tap_leaf_missing")

    def nested_script_form(self, make):
        """A P2SH-P2WSH input whose witness script, made from the form, hashes correctly to the redeem script."""
        f = K.Form("p2sh-p2wsh-single")
        script = make(f)
        f.witness_script = script
        f.redeem = b"\x00\x20" + C.sha256(script)
        f.spk = b"\xa9\x14" + S.hash160(f.redeem) + b"\x87"
        rig = self.rig([K.Inp(f)])
        self.rig_ = rig
        data, _ = K.req_first(rig.psbt, K.manual_pairs(rig))
        return rig, data

    def test_p2sh_p2wsh_witness_script_is_checked(self):
        """Required forms: a witness script that hashes right but does not contain the device key, or is not a supported form, fails
        inside a P2SH-P2WSH input as it does in a native P2WSH input."""
        other = K.pub33(K.seedkey("not the device key"))
        cases = (
            ("another key only", lambda f: K.single(other), "key_not_in_script", "unsupported_script"),
            ("script without any key", lambda f: b"\x51", "key_not_in_script", "unsupported_script"),
            ("device key not before a signature opcode", lambda f: K.push(K.pub33(f.a)) + b"\x75\x51", "key_ambiguous", "unsupported_script"),
        )
        for name, make, on, off in cases:
            with self.subTest(name):
                rig, data = self.nested_script_form(make)
                self.fails(data, on)
                rig.signer.optional_forms = False
                self.fails(data, off)
        rig, data = self.nested_script_form(lambda f: K.single(K.pub33(f.a)))
        self.assertTrue(rig.signer.sign(data))

    def test_held_secret_that_does_not_match_the_key(self):
        """Signer: a held secret that does not give the key the pair names fails the whole PSBT with key_mismatch."""
        wrong = K.seedkey("a secret for another key")
        for name in ("p2wpkh", "p2tr-key", "p2tr-script"):
            with self.subTest(name):
                rig = self.setup_form(name)
                pr = K.pairs_of(rig)[0]
                held = rig.signer._by_pub33 if pr.scheme == "ecdsa" else rig.signer._by_x
                held[pr.keyid[:33] if pr.scheme == "ecdsa" else pr.keyid[:32]] = wrong
                data, _, _ = self.first(rig)
                self.fails(data, "key_mismatch")

    def test_der_with_an_empty_s_is_a_der_error(self):
        """Second pass: "a field that is not strict DER (BIP 66) fails.\""""
        r = b"\x11" * 32
        for name, field in (("s length 0", b"\x30\x24\x02\x20" + r + b"\x02\x00\x01"),
                            ("r length 0", b"\x30\x06\x02\x00\x02\x02\x01\x01\x01")):
            with self.assertRaises(S.SpendError) as cm:
                S.parse_der_sig(field)
            self.assertEqual(cm.exception.code, "bad_der", name)
            self.assertIn(name[:1] + " length", str(cm.exception))
        self.assertEqual(S.parse_der_sig(S.sigfield("ecdsa", 1, 5, 7)), (5, 7, 1))


if __name__ == "__main__":
    unittest.main()
