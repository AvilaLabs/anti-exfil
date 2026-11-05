"""Protocol arithmetic against the published vectors, and the PSBT codec."""
import json
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

VECTORS = K.ROOT / "vectors/bip-anti-exfil.json"


class Math(unittest.TestCase):
    def test_vectors_bip340(self):
        """Protocol: "The device ... sends R0_bytes"; "sig = r || bytes32(...)" -- vector tuples."""
        d = json.loads(VECTORS.read_text())["bip340"]
        for v in d["valid"]:
            sk, m, rho = (bytes.fromhex(v[k]) for k in ("sk", "m", "rho"))
            self.assertEqual(AE.public_key(sk).hex(), v["pk"])
            self.assertEqual(AE.host_commit(rho).hex(), v["hc"])
            self.assertEqual(AE.device_commit(sk, m, AE.host_commit(rho)).hex(), v["R0_bytes"])
            self.assertEqual(AE.device_sign(sk, m, rho).hex(), v["sig"])
            self.assertTrue(AE.host_verify(*(bytes.fromhex(v[k]) for k in ("pk", "m", "rho", "R0_bytes", "sig"))))
        for v in d["reject"]:
            self.assertIs(AE.host_verify(*(bytes.fromhex(v[k]) for k in ("pk", "m", "rho", "R0_bytes", "sig"))), False, v["id"])

    def test_vectors_ecdsa(self):
        """Protocol ECDSA: "The host fails unless all of these hold" -- vector tuples."""
        d = json.loads(VECTORS.read_text())["ecdsa"]
        for v in d["valid"]:
            sk, m, rho = (bytes.fromhex(v[k]) for k in ("sk", "m", "rho"))
            self.assertEqual(AE.ecdsa_public_key(sk).hex(), v["pk"])
            self.assertEqual(AE.ecdsa_device_commit(sk, m, AE.ecdsa_host_commit(rho)).hex(), v["R0_bytes"])
            self.assertEqual(AE.ecdsa_device_sign(sk, m, rho).hex(), v["sig"])
            self.assertTrue(AE.ecdsa_host_verify(*(bytes.fromhex(v[k]) for k in ("pk", "m", "rho", "R0_bytes", "sig"))))
        for v in d["reject"]:
            self.assertIs(AE.ecdsa_host_verify(*(bytes.fromhex(v[k]) for k in ("pk", "m", "rho", "R0_bytes", "sig"))), False, v["id"])


class Codec(unittest.TestCase):
    def build(self, version):
        return K.build_psbt([K.Inp(K.Form("p2wpkh"))], version=version)

    def test_roundtrip_both_versions(self):
        """PSBT document: "It applies to PSBT versions 0 and 2.\""""
        for v in (0, 2):
            p = self.build(v)
            q = C.parse(p.serialize())
            self.assertEqual(q.version, v)
            self.assertEqual(q.serialize(), p.serialize())
            self.assertEqual(C.core_tx(q), C.core_tx(p))

    def test_maps_compared_by_key_not_order(self):
        """Handling a response: "The host compares maps by key and does not depend on their order.\""""
        p = self.build(0)
        data = p.serialize()
        # re-serialize with the input map's records in reverse order
        q = C.parse(data)
        q.inputs[0] = dict(reversed(list(q.inputs[0].items())))
        out = b"".join(C.blob(k) + C.blob(v) for k, v in q.inputs[0].items()) + b"\x00"
        raw = C.MAGIC + C._ser_map(q.glob) + out + b"".join(C._ser_map(m) for m in q.outputs)
        self.assertNotEqual(raw, data)
        self.assertEqual(C.parse(raw).inputs[0], p.inputs[0])

    def test_ae_fields_only_in_input_maps(self):
        """PSBT document: "They are defined only for input maps. The same numbers in a global or output map are ordinary unknown fields.\""""
        p = self.build(0)
        p.glob[b"\x21" + b"k" * 33] = b"x"
        p.outputs[0][b"\x22" + b"k" * 33] = b"x"
        q = C.parse(p.serialize())
        self.assertEqual(C.ae_entries(q.inputs[0]), [])
        p.inputs[0][b"\x21" + b"k" * 33] = b"\x01" * 32
        self.assertEqual(len(C.ae_entries(C.parse(p.serialize()).inputs[0])), 1)

    def test_structural_failures(self):
        good = self.build(0).serialize()
        for data, code in ((b"nope", "bad_magic"), (good + b"\x00", "trailing_bytes"), (good[:-3], None)):
            with self.assertRaises(C.PsbtError) as cm:
                C.parse(data)
            if code:
                self.assertEqual(cm.exception.code, code)
        p = self.build(2)
        p.glob[b"\xfb"] = (3).to_bytes(4, "little")
        with self.assertRaises(C.PsbtError) as cm:
            C.parse(p.serialize())
        self.assertEqual(cm.exception.code, "unsupported_version")
        p = self.build(0)
        raw = C._ser_map(p.glob)
        dup = C.blob(b"\x07") + C.blob(b"a") + C.blob(b"\x07") + C.blob(b"b") + b"\x00"
        with self.assertRaises(C.PsbtError) as cm:
            C.parse(C.MAGIC + raw[:-1] + dup[:-1] + b"\x00" + b"\x00" + b"\x00")
        self.assertEqual(cm.exception.code, "duplicate_key")

    def test_v2_core_tx_from_fields(self):
        p = K.build_psbt([K.Inp(K.Form("p2wpkh"))], version=2, locktime=77, tx_version=3)
        tx = C.core_tx(C.parse(p.serialize()))
        self.assertEqual((tx.version, tx.locktime), (3, 77))

    def test_modifiable_flags(self):
        """BIP 370 updates: "An absent field has value zero. Preserve other flags, and create the field if an update needs to record a set flag.\""""
        g = {}
        C.apply_modifiable_update(g, 1)
        self.assertNotIn(b"\x06", g)
        C.apply_modifiable_update(g, 3)
        self.assertEqual(g[b"\x06"], b"\x04")
        g = {b"\x06": bytes([0b1000_0011])}
        C.apply_modifiable_update(g, 0x81)           # ALL|ACP: outputs flag cleared, inputs kept
        self.assertEqual(g[b"\x06"], bytes([0b1000_0001]))
        C.apply_modifiable_update(g, 0x82)           # NONE|ACP keeps outputs-modifiable state as is
        self.assertEqual(g[b"\x06"], bytes([0b1000_0001]))
        C.apply_modifiable_update(g, 0)              # DEFAULT counts as ALL: clears inputs flag
        self.assertEqual(g[b"\x06"], bytes([0b1000_0000]))


class RuleGaps(unittest.TestCase):
    """Tests added for survivors of the requirement mutants classed test_gap."""

    def two_inputs(self, version):
        return K.build_psbt([K.Inp(K.Form("p2wpkh")), K.Inp(K.Form("p2wpkh", label="g"))], version=version)

    def test_size_cap_fails_and_never_truncates(self):
        """Validation scope: "An implementation MAY cap sizes and counts; exceeding a cap fails and never truncates.\""""
        data = K.build_psbt([K.Inp(K.Form("p2wpkh"))]).serialize()
        with mock.patch.object(C, "MAX_PSBT_BYTES", len(data) - 1):
            with self.assertRaises(C.PsbtError) as cm:
                C.parse(data)
        self.assertEqual(cm.exception.code, "cap_exceeded")
        with mock.patch.object(C, "MAX_PSBT_BYTES", len(data)):
            C.parse(data)

    def test_input_count_cap_fails_in_both_versions(self):
        """Validation scope: "exceeding a cap fails and never truncates.\""""
        for v in (0, 2):
            data = self.two_inputs(v).serialize()
            with mock.patch.object(C, "MAX_INPUTS", 1):
                with self.assertRaises(C.PsbtError) as cm:
                    C.parse(data)
            self.assertEqual(cm.exception.code, "cap_exceeded", v)
            with mock.patch.object(C, "MAX_INPUTS", 2):
                C.parse(data)

    def test_serialization_does_not_depend_on_insertion_order(self):
        """Codec docstring: "Serialization sorts keys, which makes output reproducible.\""""
        p = self.two_inputs(0)
        q = p.clone()
        q.inputs = [dict(reversed(list(m.items()))) for m in q.inputs]
        self.assertNotEqual(list(p.inputs[0]), list(q.inputs[0]))
        self.assertEqual(p.serialize(), q.serialize())

    def test_absent_flags_field_has_value_zero(self):
        """Step 6: "An absent field has value zero.\""""
        for sighash in (2, 0x81, 0x82, 0x83):
            g = {}
            C.apply_modifiable_update(g, sighash)
            self.assertEqual(g.get(b"\x06"), b"\x04" if sighash == 0x83 else None, hex(sighash))


class CodecEdges(unittest.TestCase):
    """CompactSize boundaries and transaction parsing edges: witness serialization, truncation, trailing bytes."""

    def tx(self):
        return C.Tx(2, [(b"\x11" * 32, 1, b"", 0xFFFFFFFD)], [(5000, b"\x6a"), (6000, b"\x51")], 9)

    def test_compact_size_boundaries(self):
        """Codec: CompactSize is minimal; 0xfc is the largest one-byte value, 0xfd opens the two-byte form."""
        self.assertEqual(C.read_compact(b"\xfc", 0), (252, 1))
        self.assertEqual(C.compact(252), b"\xfc")
        blob252 = b"\xaa" * 252
        self.assertEqual(C.read_blob(C.blob(blob252), 0), (blob252, 253))
        self.assertEqual(C.read_compact(b"\xfd\xfd\x00", 0), (253, 3))
        self.assertEqual(C.read_compact(b"\xfd\xff\xff", 0), (0xFFFF, 3))
        self.assertEqual(C.read_compact(b"\xfe\x00\x00\x01\x00", 0), (0x10000, 5))

    def test_non_minimal_compact_size_at_each_width(self):
        """Codec: a CompactSize that fits a shorter form is refused as non-minimal, at every width."""
        for raw in (b"\xfd" + (252).to_bytes(2, "little"), b"\xfe" + (0xFFFF).to_bytes(4, "little"),
                    b"\xff" + (0xFFFFFFFF).to_bytes(8, "little"), b"\xff" + (0).to_bytes(8, "little")):
            with self.assertRaises(C.PsbtError) as cm:
                C.read_compact(raw, 0)
            self.assertEqual(cm.exception.code, "nonminimal_compact", raw.hex())
        self.assertEqual(C.read_compact(b"\xff" + (0x100000000).to_bytes(8, "little"), 0), (0x100000000, 9))
        self.assertEqual(C.compact(0x100000000), b"\xff" + (0x100000000).to_bytes(8, "little"))

    def test_witness_serialization_parses_to_the_same_transaction(self):
        """Codec: parse_tx reads a transaction with or without witness data; the txid is that of the stripped form."""
        tx = self.tx()
        tx2 = C.Tx(2, tx.ins + [(b"\x33" * 32, 0, b"", 1)], tx.outs, tx.locktime)
        for t, wits in ((tx, [[b"\x30" * 71, b"\x02" * 33]]), (tx2, [[b"\x30" * 71, b"\x02" * 33], []])):
            raw = K.ser_witness_tx(t, wits)
            self.assertEqual(raw[4:6], b"\x00\x01")
            self.assertEqual(C.parse_tx(raw), t)
            self.assertEqual(C.txid(C.parse_tx(raw)), C.txid(t))
            self.assertEqual(C.txid(C.parse_tx(raw)), C.dsha(C.ser_tx(t)))
            self.assertNotEqual(C.dsha(raw), C.txid(t))

    def test_transaction_cut_inside_an_input(self):
        """Codec: a transaction that ends inside an input fails as bad_tx."""
        raw = C.ser_tx(self.tx())
        for cut in (5 + 35, 5 + 36 + 1 + 3):
            with self.assertRaises(C.PsbtError) as cm:
                C.parse_tx(raw[:cut])
            self.assertEqual(cm.exception.code, "bad_tx", cut)

    def test_transaction_cut_inside_an_output_value(self):
        """Codec: a transaction that ends inside an output value fails as bad_tx."""
        raw = C.ser_tx(self.tx())
        start = 4 + 1 + 36 + 1 + 4 + 1          # first output
        for cut in (start + 4, start + 7):
            with self.assertRaises(C.PsbtError) as cm:
                C.parse_tx(raw[:cut])
            self.assertEqual(cm.exception.code, "bad_tx", cut)
        self.assertEqual(C.parse_tx(raw), self.tx())

    def test_trailing_byte_after_a_transaction(self):
        """Codec: a transaction with a byte after the locktime fails as bad_tx."""
        raw = C.ser_tx(self.tx())
        for extra in (b"\x00", b"\xff"):
            with self.assertRaises(C.PsbtError) as cm:
                C.parse_tx(raw + extra)
            self.assertEqual(cm.exception.code, "bad_tx")
        with self.assertRaises(C.PsbtError) as cm:
            C.parse_tx(K.ser_witness_tx(self.tx(), [[b"\x01"]]) + b"\x00")
        self.assertEqual(cm.exception.code, "bad_tx")

    def test_unsigned_transaction_in_witness_serialization_is_refused(self):
        """BIP 174: the unsigned transaction "MUST NOT have any scriptSigs or witness data"; one in witness serialization is bad_tx."""
        p = K.build_psbt([K.Inp(K.Form("p2wpkh"))], version=0)
        self.assertEqual(C.parse(p.serialize()).version, 0)
        tx = C.parse_tx(p.glob[b"\x00"])
        for wits in ([[]], [[b"\x01"]]):
            q = p.clone()
            q.glob[b"\x00"] = K.ser_witness_tx(tx, wits)
            self.assertEqual(q.glob[b"\x00"][4:6], b"\x00\x01")
            self.assertEqual(C.parse_tx(q.glob[b"\x00"]), tx)          # a transaction that parses; the only defect is the form
            with self.assertRaises(C.PsbtError) as cm:
                C.parse(q.serialize())
            self.assertEqual(cm.exception.code, "bad_tx")
            self.assertIn("witness serialization", str(cm.exception))


class RequiredLocktimes(unittest.TestCase):
    """PSBT v2 locktime from the core transaction, BIP 370: required height, required time, fallback."""
    HEIGHT, TIME = b"\x12", b"\x11"

    def psbt(self, fields, fallback=0):
        """A v2 PSBT with one input per (height, time) pair; None leaves the field out. fallback None removes it."""
        inputs = [K.Inp(K.Form("p2wpkh", label="lock%d" % i)) for i in range(len(fields))]
        p = K.build_psbt(inputs, version=2, locktime=fallback or 0)
        if fallback is None:
            del p.glob[b"\x03"]
        for m, (h, t) in zip(p.inputs, fields):
            if h is not None:
                m[self.HEIGHT] = struct.pack("<I", h)
            if t is not None:
                m[self.TIME] = struct.pack("<I", t)
        return p

    def lock(self, fields, fallback=0):
        p = self.psbt(fields, fallback)
        got = C.core_tx(C.parse(p.serialize())).locktime
        self.assertEqual(C.core_tx(p).locktime, got)
        return got

    def refused(self, fields, text, code="bad_v2_input"):
        with self.assertRaises(C.PsbtError) as cm:
            C.parse(self.psbt(fields).serialize())
        self.assertEqual(cm.exception.code, code)
        self.assertIn(text, str(cm.exception))

    def test_required_height_only(self):
        """BIP 370: the locktime is the maximum required height when every input that requires one allows a height."""
        self.assertEqual(self.lock([(700000, None)], fallback=5), 700000)
        self.assertEqual(self.lock([(700000, None), (700001, None)]), 700001)
        self.assertEqual(self.lock([(700001, None), (700000, None)]), 700001)

    def test_required_time_only(self):
        """BIP 370: required time locktimes are at least 500000000; the locktime is the maximum."""
        self.assertEqual(self.lock([(None, 500000000)]), 500000000)
        self.assertEqual(self.lock([(None, 600000000)], fallback=5), 600000000)
        self.assertEqual(self.lock([(None, 600000000), (None, 600000001)]), 600000001)

    def test_input_with_both_fields_gives_height(self):
        """BIP 370: an input with both required fields allows either type; height is chosen when every input allows it."""
        self.assertEqual(self.lock([(700000, 600000000)]), 700000)
        self.assertEqual(self.lock([(700000, 600000000), (None, 600000001)]), 600000001)

    def test_height_only_beside_an_input_with_both_gives_maximum_height(self):
        """BIP 370: height is chosen when every input allows it, and the largest required height is used."""
        self.assertEqual(self.lock([(100, 600000000), (700, None)]), 700)
        self.assertEqual(self.lock([(700, None), (100, 600000000)]), 700)
        self.assertEqual(self.lock([(900, 600000000), (700, None)]), 900)

    def test_required_height_range(self):
        """BIP 370: a required height is above 0 and below 500000000."""
        self.assertEqual(self.lock([(1, None)]), 1)
        self.assertEqual(self.lock([(499999999, None)]), 499999999)
        self.refused([(0, None)], "required height")
        self.refused([(500000000, None)], "required height")

    def test_required_time_range(self):
        """BIP 370: a required time is at least 500000000."""
        self.refused([(None, 499999999)], "required time")
        self.refused([(None, 0)], "required time")
        self.assertEqual(self.lock([(None, 0xFFFFFFFF)]), 0xFFFFFFFF)

    def test_height_only_with_time_only_is_incompatible(self):
        """BIP 370: required height and required time locktimes that no one type satisfies fail."""
        self.refused([(700, None), (None, 600000000)], "incompatible")
        self.refused([(None, 600000000), (700, None)], "incompatible")
        self.refused([(700, None), (None, 600000000), (700, 600000000)], "incompatible")

    def test_no_required_fields_use_the_fallback_or_zero(self):
        """BIP 370: without required locktimes the locktime is the fallback, or zero if there is none."""
        self.assertEqual(self.lock([(None, None)], fallback=None), 0)
        self.assertEqual(self.lock([(None, None), (None, None)], fallback=None), 0)
        self.assertEqual(self.lock([(None, None)], fallback=123456), 123456)
        self.assertEqual(self.lock([(None, None)], fallback=0), 0)

    def test_required_locktime_overrides_the_fallback(self):
        """BIP 370: a required locktime wins over a differing fallback."""
        self.assertEqual(self.lock([(800, None)], fallback=700000), 800)
        self.assertEqual(self.lock([(None, 600000000)], fallback=700000), 600000000)
        self.assertEqual(self.lock([(800, None)], fallback=None), 800)

    def test_length_errors(self):
        """Codec: every fixed-length v2 field of the core transaction has its length checked."""
        def refused(code, edit):
            p = self.psbt([(None, None)])
            edit(p)
            with self.assertRaises(C.PsbtError) as cm:
                C.parse(p.serialize())
            self.assertEqual(cm.exception.code, code)
        refused("bad_v2_tx", lambda p: p.glob.__setitem__(b"\x02", b"\x02\x00\x00"))
        refused("bad_v2_tx", lambda p: p.glob.__setitem__(b"\x02", b"\x02\x00\x00\x00\x00"))
        refused("bad_v2_tx", lambda p: p.glob.__setitem__(b"\x03", b"\x00\x00\x00"))
        refused("bad_v2_tx", lambda p: p.glob.__setitem__(b"\x03", b"\x00" * 5))
        refused("bad_v2_tx", lambda p: p.glob.pop(b"\x02"))
        refused("bad_v2_input", lambda p: p.inputs[0].__setitem__(b"\x0e", b"\x00" * 31))
        refused("bad_v2_input", lambda p: p.inputs[0].__setitem__(b"\x0f", b"\x00" * 3))
        refused("bad_v2_input", lambda p: p.inputs[0].__setitem__(b"\x10", b"\x00" * 5))
        refused("bad_v2_input", lambda p: p.inputs[0].__setitem__(b"\x12", struct.pack("<I", 7)[:3]))
        refused("bad_v2_input", lambda p: p.inputs[0].__setitem__(b"\x12", struct.pack("<I", 7) + b"\x00"))
        refused("bad_v2_input", lambda p: p.inputs[0].__setitem__(b"\x11", struct.pack("<I", 600000000)[:3]))
        refused("bad_v2_input", lambda p: p.inputs[0].__setitem__(b"\x11", struct.pack("<I", 600000000) + b"\x00"))
        refused("bad_v2_output", lambda p: p.outputs[0].__setitem__(b"\x03", b"\x00" * 7))
        refused("bad_v2_output", lambda p: p.outputs[0].pop(b"\x04"))


class PrevoutForms(K.Base):
    def test_non_witness_utxo_in_witness_serialization_passes_the_prevout_check_and_signs(self):
        """Fields: a NON_WITNESS_UTXO is checked by hashing the transaction without witness data."""
        for version in (0, 2):
            for name in ("p2pkh", "p2wpkh"):
                form = K.Form(name)
                ptx = C.Tx(2, [(b"\x22" * 32, 0, b"\x51", 0xFFFFFFFF)], [(7, b"\x6a"), (100000, form.spk)], 0)
                raw = K.ser_witness_tx(ptx, [[b"\x30" * 71, b"\x02" * 33]])
                prev = K.Prev(raw, 1, 100000, form.spk)
                self.assertEqual(prev.txid, C.txid(ptx))
                self.assertNotEqual(C.dsha(raw), prev.txid)
                rig = self.rig([K.Inp(form, prev=prev)], version=version)
                self.assertEqual(rig.psbt.inputs[0][b"\x00"], raw)
                res = rig.host.sign(rig.request_bytes)
                self.assertEqual(len(res.signed), 1, (version, name))
                self.assertEqual(S.txout_of(C.parse(rig.request_bytes), 0), (100000, form.spk, True))

    def test_explicit_sighash_all_commits_to_every_input_amount(self):
        """Spends: a Taproot pair whose type does not have ANYONECANPAY commits to every input amount, so the fee counts as verified;
        0x81 commits to its own input only."""
        fa, fb = K.Form("p2tr-key", "a"), K.Form("p2tr-key", "b")
        for sighash, committed in ((1, True), (0x81, False)):
            inputs = [K.Inp(fa, value=60000, sighash=sighash, utxo="wit"), K.Inp(fb, value=70000, utxo="wit")]
            p = K.build_psbt(inputs, version=0)
            tx = C.core_tx(p)
            pair = S.resolve_pair(p, 0, K.xonly(fa.a), {K.xonly(fa.a)}, True)
            prevouts = [(60000, fa.spk), (70000, fb.spk)]
            self.assertEqual(pair.sighash, sighash)
            self.assertIs(pair.taproot_all_prevouts, committed)
            self.assertEqual(S.fee_info(p, [pair]), (1000, committed, [] if committed else [0, 1]))
            if committed:
                # BIP 341 with hash_type ALL: sha_prevouts, sha_amounts, sha_scriptpubkeys, sha_sequences, sha_outputs, spend_type 0, index
                sha = C.sha256
                msg = (b"\x00" + bytes([sighash]) + struct.pack("<I", tx.version) + struct.pack("<I", tx.locktime)
                       + sha(b"".join(a[0] + struct.pack("<I", a[1]) for a in tx.ins))
                       + sha(b"".join(struct.pack("<Q", v) for v, _ in prevouts))
                       + sha(b"".join(C.blob(sp) for _, sp in prevouts))
                       + sha(b"".join(struct.pack("<I", a[3]) for a in tx.ins))
                       + sha(b"".join(struct.pack("<Q", v) + C.blob(sp) for v, sp in tx.outs))
                       + b"\x00" + struct.pack("<I", 0))
                self.assertEqual(pair.message, S.tagged("TapSighash", msg))
                self.assertEqual(pair.message, S.tap_sighash(tx, 0, prevouts, 1))
            else:
                self.assertEqual(pair.message, S.tap_sighash(tx, 0, [prevouts[0], None], 0x81))
            # the second input is spent with the default type and also commits to every amount
            other = S.resolve_pair(p, 1, K.xonly(fb.a), {K.xonly(fb.a)}, True)
            self.assertTrue(other.taproot_all_prevouts)


class ScriptRules(unittest.TestCase):
    """Script parsing and the OP_SUCCESS list."""

    def test_op_success_is_the_list_in_bip_342(self):
        """BIP 342: "OP_SUCCESSx" are 80, 98, 126-129, 131-134, 137-138, 141-142, 149-153 and 187-254, over all 256 opcode values."""
        listed = {80, 98, 126, 127, 128, 129, 131, 132, 133, 134, 137, 138, 141, 142, 149, 150, 151, 152, 153}
        listed |= set(range(187, 255))
        self.assertEqual({op for op in range(256) if op in S.OP_SUCCESS}, listed)
        self.assertEqual(set(S.OP_SUCCESS), listed)
        for op in (130, 255, 135, 136, 186):
            self.assertNotIn(op, S.OP_SUCCESS)

    def test_direct_push_lengths(self):
        """Scripts: opcodes 1 to 75 push that many bytes; 76 is OP_PUSHDATA1, which takes a length byte."""
        data = bytes(range(75))
        self.assertEqual(S.parse_script(bytes([75]) + data), [(75, data)])
        self.assertEqual(S.parse_script(bytes([1]) + b"\x07"), [(1, b"\x07")])
        self.assertEqual(S.parse_script(b"\x00"), [(0, None)])
        self.assertEqual(S.parse_script(bytes([76, 3]) + b"abc"), [(76, b"abc")])
        self.assertEqual(S.parse_script(bytes([76, 76]) + data + b"z"), [(76, data + b"z")])
        with self.assertRaises(S.SpendError) as cm:
            S.parse_script(bytes([76]))
        self.assertEqual(cm.exception.code, "bad_script")
        with self.assertRaises(S.SpendError) as cm:
            S.parse_script(bytes([75]) + data[:-1])
        self.assertEqual(cm.exception.code, "bad_script")


if __name__ == "__main__":
    unittest.main()
