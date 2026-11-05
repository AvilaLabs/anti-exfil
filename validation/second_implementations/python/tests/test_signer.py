import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import indep as I
import tb
import signer as S
import psbt as P

import proto
EXP = (P.PsbtError, S.SignerFail, proto.ProtoFail, ValueError)
FORMS = ["p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2wsh-single", "p2wsh-multi", "p2sh-p2wsh-single",
         "p2sh-p2wsh-multi", "p2sh-single", "p2sh-multi", "tr-key", "tr-script"]


def signs(c, mutate=None, sks=None, phase=2, decline=False):
    c = tb.clone(c)
    if mutate:
        mutate(c)
    h = tb.req2(c) if phase == 2 else tb.req1(c)
    return tb.inproc_sign(h, sks if sks is not None else c.dev_sks, decline)


class Base(unittest.TestCase):
    def assertSignerFails(self, c, mutate=None, **kw):
        with self.assertRaises(EXP) as cm:
            signs(c, mutate, **kw)
        return cm.exception

    def assertSignerOk(self, c, mutate=None, **kw):
        return signs(c, mutate, **kw)


class TestPasses(Base):
    def test_first_pass_each_form_both_versions(self):
        for v in (0, 2):
            for form in FORMS:
                c = tb.make([{"form": form}], version=v)
                out = tb.inproc_sign(tb.req1(c), c.dev_sks)
                p = c.pairs[0]
                r0 = tb.r0_of(out, p)
                self.assertEqual(len(r0), 33)
                if form != "tr-key":
                    self.assertEqual(r0, tb.expected_r0(p, c.info[0]["dk"]), form)
                # no signature added, host commitment kept
                maps = I.read_psbt(bytes.fromhex(out))
                m = dict(maps[1])
                self.assertNotIn(p["sigkey"], m)
                self.assertIn(b"\x21" + p["keyid"], m)
                # deterministic and stateless
                self.assertEqual(out, tb.inproc_sign(tb.req1(c), c.dev_sks))

    def test_first_pass_needs_no_approval(self):
        c = tb.make([{"form": "p2wpkh"}])
        out = tb.inproc_sign(tb.req1(c), c.dev_sks, decline=True)
        self.assertTrue(out)

    def test_second_pass_each_form_both_versions(self):
        for v in (0, 2):
            for form in FORMS:
                c = tb.make([{"form": form}], version=v)
                out = tb.inproc_sign(tb.req2(c), c.dev_sks)
                tb.check_result(c, out)

    def test_second_pass_with_hc_and_nc_present(self):
        c = tb.make([{"form": "p2wpkh"}])
        r1 = tb.inproc_sign(tb.req1(c), c.dev_sks)
        # take the first-pass response and add the randomness: a pass-2 request that keeps hc and nc
        maps = I.read_psbt(bytes.fromhex(r1))
        p = c.pairs[0]
        maps[1].append((b"\x23" + p["keyid"], tb.rho_for(0, p["keyid"])))
        out = tb.inproc_sign(I.write_psbt(maps).hex(), c.dev_sks)
        tb.check_result(c, out)

    def test_second_pass_without_prior_first_pass_and_same_nonce_as_first(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "tr-script"}])
        r1 = tb.inproc_sign(tb.req1(c), c.dev_sks)
        out = tb.inproc_sign(tb.req2(c), c.dev_sks)
        maps = I.read_psbt(bytes.fromhex(out))
        # ECDSA sig is consistent with the R0 announced in pass 1
        for p in c.pairs:
            R0 = tb.r0_of(r1, p)
            rho = tb.rho_for(p["i"], p["keyid"])
            sig = dict(maps[1 + p["i"]])[p["sigkey"]]
            if p["scheme"] == "bip340":
                t = int.from_bytes(I.TH("s2c/schnorr/point", R0 + rho), "big")
                W = I.add(I.lift(int.from_bytes(R0[1:], "big")) if R0[0] == 2 else I.neg(I.lift(int.from_bytes(R0[1:], "big"))), I.mul(t))
                self.assertEqual(sig[:32], W[0].to_bytes(32, "big"))
            else:
                t = int.from_bytes(I.TH("s2c/ecdsa/point", R0 + rho), "big")
                R0pt = I.lift(int.from_bytes(R0[1:], "big"))
                if R0[0] == 3:
                    R0pt = I.neg(R0pt)
                W = I.add(R0pt, I.mul(t))
                d = sig[:-1]
                lr = d[3]
                r = int.from_bytes(d[4:4 + lr], "big")
                self.assertEqual(r, W[0] % I.n)

    def test_only_requested_pairs_signed(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "p2wpkh", "key": 1}], version=0)
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        # request only input 0 although the signer holds both keys
        c.pairs = c.pairs[:1]
        out = tb.inproc_sign(tb.req2(c), c.dev_sks)
        maps = I.read_psbt(bytes.fromhex(out))
        self.assertIn(c.pairs[0]["sigkey"], dict(maps[1]))
        self.assertFalse(any(k[0] == 2 for k, _ in maps[2]))

    def test_response_removes_ae_fields_and_keeps_other_data(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "p2wpkh", "key": 1}])
        c.imaps[1][b"\xfc\x04test"] = b"unknown"   # proprietary-looking unknown field
        c.gmap[b"\xfc\x04glob"] = b"g"
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        c.pairs = c.pairs[:1]
        c.imaps[1][b"\x21" + b"\x02" * 33] = bytes(32)    # junk AE field for input 1 would fail; remove below
        del c.imaps[1][b"\x21" + b"\x02" * 33]
        out = tb.inproc_sign(tb.req2(c), c.dev_sks)
        maps = I.read_psbt(bytes.fromhex(out))
        self.assertEqual(dict(maps[2])[b"\xfc\x04test"], b"unknown")
        self.assertEqual(dict(maps[0])[b"\xfc\x04glob"], b"g")
        for m in maps[1:3]:
            self.assertFalse(any(k[0] in (0x21, 0x22, 0x23) for k, _ in m))

    def test_ae_numbers_in_global_and_output_maps_are_unknown_fields(self):
        c = tb.make([{"form": "p2wpkh"}])
        c.gmap[b"\x21" + bytes(33)] = bytes(5)
        c.omaps[0][b"\x22" + bytes(3)] = bytes(2)
        out = tb.inproc_sign(tb.req2(c), c.dev_sks)
        maps = I.read_psbt(bytes.fromhex(out))
        self.assertIn(b"\x21" + bytes(33), dict(maps[0]))
        self.assertIn(b"\x22" + bytes(3), dict(maps[-1]))

    def test_multiple_pairs_in_one_input_and_across_inputs(self):
        # 2-of-3 multisig holding two device keys -> two ECDSA pairs on one input
        keys = [tb.pub(tb.DEV[0]), tb.pub(tb.DEV[1]), tb.pub(tb.OTHER[0])]
        ws = tb.multisig(keys, 2)
        c = tb.make([{"form": "p2wsh-multi", "script": ws}, {"form": "p2wpkh", "key": 1}])
        extra = dict(c.pairs[0])
        # second pair on input 0 for DEV[1]
        c.imaps[0][b"\x06" + tb.pub(tb.DEV[1])] = tb.FP + tb.PATH_ECDSA
        mm = I.bip143_sighash(c.tx, 0, ws, 100000, 1)
        p0 = dict(c.pairs[0]); p0["m"] = mm
        p1 = dict(p0); p1.update(keyid=tb.pub(tb.DEV[1]), pk=tb.pub(tb.DEV[1]), sigkey=b"\x02" + tb.pub(tb.DEV[1]))
        c.pairs = [p0, p1, c.pairs[1]]
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        out = tb.inproc_sign(tb.req2(c), c.dev_sks)
        tb.check_result(c, out)


class TestPhases(Base):
    def setUp(self):
        self.c = tb.make([{"form": "p2wpkh"}, {"form": "p2wpkh", "key": 1}])
        self.c.dev_sks = [tb.DEV[0], tb.DEV[1]]

    def test_no_ae_fields_fails(self):
        self.assertSignerFails(self.c, lambda c: None, phase=0) if False else None
        with self.assertRaises(EXP):
            tb.inproc_sign(tb.psbt_hex(self.c), self.c.dev_sks)

    def test_mixed_phases_fail(self):
        c = tb.clone(self.c)
        p0, p1 = c.pairs
        c.imaps[0][b"\x21" + p0["keyid"]] = tb.hc_of(p0, tb.rho_for(0, p0["keyid"]))
        c.imaps[1][b"\x23" + p1["keyid"]] = tb.rho_for(1, p1["keyid"])
        with self.assertRaises(EXP):
            tb.inproc_sign(tb.psbt_hex(c), c.dev_sks)

    def test_nonce_commitment_only_fails(self):
        c = tb.clone(self.c)
        p0 = c.pairs[0]
        c.imaps[0][b"\x22" + p0["keyid"]] = I.comp(I.mul(5))
        with self.assertRaises(EXP):
            tb.inproc_sign(tb.psbt_hex(c), c.dev_sks)

    def test_nonce_only_on_one_pair_while_other_is_first_pass_fails(self):
        c = tb.clone(self.c)
        p0, p1 = c.pairs
        c.imaps[0][b"\x21" + p0["keyid"]] = tb.hc_of(p0, tb.rho_for(0, p0["keyid"]))
        c.imaps[1][b"\x22" + p1["keyid"]] = I.comp(I.mul(5))
        with self.assertRaises(EXP):
            tb.inproc_sign(tb.psbt_hex(c), c.dev_sks)

    def test_value_and_identifier_lengths(self):
        p0 = self.c.pairs[0]
        k = p0["keyid"]
        cases = [(b"\x21" + k, bytes(31)), (b"\x21" + k, bytes(33)), (b"\x23" + k, bytes(31)),
                 (b"\x23" + k, bytes(33)), (b"\x22" + k, bytes(32)), (b"\x22" + k, bytes(34)),
                 (b"\x23" + k + b"\x00", bytes(32)), (b"\x23" + bytes(65), bytes(32)),
                 (b"\x23" + k[:31], bytes(32)), (b"\x23", bytes(32)), (b"\x23" + bytes(34), bytes(32))]
        for key, val in cases:
            c = tb.clone(self.c)
            c.pairs = c.pairs[:1]
            c.imaps[0][key] = val
            if key[0] != 0x23:
                c.imaps[0][b"\x23" + k] = tb.rho_for(0, k)
            with self.assertRaises(EXP, msg=repr((key[:2], len(val)))):
                tb.inproc_sign(tb.psbt_hex(c), c.dev_sks)

    def test_pass1_nonce_present_must_match(self):
        c = tb.clone(self.c)
        c.pairs = c.pairs[:1]
        p = c.pairs[0]
        good = tb.inproc_sign(tb.req1(c), c.dev_sks)
        # feeding the pass-1 response back as a pass-1 request is fine (same nonce)
        again = tb.inproc_sign(good, c.dev_sks)
        self.assertEqual(again, good)
        maps = I.read_psbt(bytes.fromhex(good))
        maps[1] = [(k, (I.comp(I.mul(9)) if k[0] == 0x22 else v)) for k, v in maps[1]]
        with self.assertRaises(EXP):
            tb.inproc_sign(I.write_psbt(maps).hex(), c.dev_sks)

    def test_pass2_hc_or_nc_mismatch_fails(self):
        c = tb.clone(self.c)
        c.pairs = c.pairs[:1]
        p = c.pairs[0]
        base = tb.req2(c, with_hc=True)
        tb.inproc_sign(base, c.dev_sks)      # consistent: fine
        maps = I.read_psbt(bytes.fromhex(base))
        maps1 = [list(m) for m in maps]
        maps1[1] = [(k, (bytes(32) if k[0] == 0x21 else v)) for k, v in maps[1]]
        with self.assertRaises(EXP):
            tb.inproc_sign(I.write_psbt(maps1).hex(), c.dev_sks)
        maps2 = [list(m) for m in maps]
        maps2[1] = maps[1] + [(b"\x22" + p["keyid"], I.comp(I.mul(9)))]
        with self.assertRaises(EXP):
            tb.inproc_sign(I.write_psbt(maps2).hex(), c.dev_sks)
        # correct nc in pass 2 is accepted
        r1 = tb.inproc_sign(tb.req1(c), c.dev_sks)
        nc = tb.r0_of(r1, p)
        maps3 = [list(m) for m in maps]
        maps3[1] = maps[1] + [(b"\x22" + p["keyid"], nc)]
        out = tb.inproc_sign(I.write_psbt(maps3).hex(), c.dev_sks)
        tb.check_result(c, out)

    def test_decline_second_pass(self):
        c = tb.clone(self.c)
        c.pairs = c.pairs[:1]
        with self.assertRaises(EXP):
            tb.inproc_sign(tb.req2(c), c.dev_sks, decline=True)

    def test_pair_failure_fails_whole_psbt(self):
        c = tb.clone(self.c)       # holds only DEV[0]'s secret but both pairs requested
        with self.assertRaises(EXP):
            tb.inproc_sign(tb.req2(c), [tb.DEV[0]])


class TestValidationFailures(Base):
    def check(self, form, mutate, version=0, ok_first=True, **mk):
        c = tb.make([dict(form=form, **mk)], version=version)
        if ok_first:
            self.assertSignerOk(c)
        self.assertSignerFails(c, mutate)

    def test_final_fields(self):
        for t in (b"\x07", b"\x08"):
            self.check("p2wpkh", lambda c, t=t: c.imaps[0].__setitem__(t, b"\x00"))
            self.check("tr-key", lambda c, t=t: c.imaps[0].__setitem__(t, b"\x00"))

    def test_missing_utxo_fields(self):
        self.check("p2wpkh", lambda c: c.imaps[0].pop(b"\x01"))
        self.check("tr-key", lambda c: c.imaps[0].pop(b"\x01"))
        self.check("p2pkh", lambda c: c.imaps[0].pop(b"\x00"))

    def test_legacy_requires_non_witness_utxo(self):
        def only_wu(c):
            d = c.info[0]
            c.imaps[0].pop(b"\x00")
            c.imaps[0][b"\x01"] = (100000).to_bytes(8, "little") + I.cs(len(d["spk"])) + d["spk"]
        self.check("p2pkh", only_wu)
        self.check("p2sh-single", only_wu)

    def test_segwit_accepts_either_utxo_field(self):
        c = tb.make([{"form": "p2wpkh", "nwu": True}])
        self.assertEqual(sorted(k for k in c.imaps[0] if k[0] in (0, 1)), [b"\x00"])
        self.assertSignerOk(c)
        c = tb.make([{"form": "p2wpkh", "nwu": True, "wu": True}])
        self.assertSignerOk(c)
        c = tb.make([{"form": "tr-script", "nwu": True}])
        self.assertSignerOk(c)

    def test_nwu_must_hash_to_prev_txid(self):
        def bad(c):
            t = I.Tx(version=1).add_in(I.H(b"x"), 0).add_out(100000, c.info[0]["spk"])
            c.imaps[0][b"\x00"] = t.ser()
        self.check("p2pkh", bad)
        self.check("p2wpkh", bad, nwu=True)

    def test_nwu_must_contain_output_index(self):
        c = tb.make([{"form": "p2pkh", "vout": 1, "pad": False}])
        # prevtx has one output only but input spends index 1 -> fail
        self.assertSignerFails(c)
        c = tb.make([{"form": "p2pkh", "vout": 1, "pad": True}])
        self.assertSignerOk(c)

    def test_wu_and_nwu_must_agree(self):
        def disagree(c):
            d = c.info[0]
            c.imaps[0][b"\x01"] = (99999).to_bytes(8, "little") + I.cs(len(d["spk"])) + d["spk"]
        self.check("p2wpkh", disagree, nwu=True)
        self.check("tr-key", disagree, nwu=True)

        def agree(c):
            pass
        c = tb.make([{"form": "p2wpkh", "nwu": True, "wu": True}])
        self.assertSignerOk(c)

    def test_key_not_held(self):
        c = tb.make([{"form": "p2wpkh"}])
        for form in ("p2wpkh", "tr-key", "tr-script"):
            c = tb.make([{"form": form}])
            with self.assertRaises(EXP):
                tb.inproc_sign(tb.req2(c), [tb.DEV[2]])

    def test_pair_already_has_signature(self):
        for form, key in (("p2wpkh", None), ("tr-key", None), ("tr-script", None)):
            c = tb.make([{"form": form}])
            p = c.pairs[0]
            self.assertSignerFails(c, lambda c, p=p: c.imaps[0].__setitem__(p["sigkey"], bytes(65)))

    def test_hash_mismatches(self):
        def swap_key(c):
            d = c.info[0]
            spk = b"\x00\x14" + I.h160(tb.pub(tb.OTHER[0]))
            c.imaps[0][b"\x01"] = (100000).to_bytes(8, "little") + I.cs(len(spk)) + spk
        self.check("p2wpkh", swap_key)
        self.check("p2sh-p2wpkh", lambda c: c.imaps[0].__setitem__(b"\x04", b"\x00\x14" + bytes(20)))
        self.check("p2sh-p2wpkh", lambda c: c.imaps[0].pop(b"\x04"))
        self.check("p2wsh-single", lambda c: c.imaps[0].pop(b"\x05"))
        self.check("p2wsh-single", lambda c: c.imaps[0].__setitem__(b"\x05", tb.push(tb.pub(tb.DEV[0])) + b"\xad"))
        self.check("p2sh-p2wsh-multi", lambda c: c.imaps[0].pop(b"\x05"))
        self.check("p2sh-p2wsh-multi", lambda c: c.imaps[0].pop(b"\x04"))
        self.check("p2sh-single", lambda c: c.imaps[0].pop(b"\x04"))
        self.check("p2pkh", lambda c: c.imaps[0].__setitem__(b"\x00", I.Tx(version=1).add_in(c.tx.vin[0]["txid"], 0).add_out(1, b"\x6a").ser()))

    def test_unsupported_spk(self):
        def weird(c):
            spk = b"\x00\x30" + bytes(48)
            c.imaps[0][b"\x01"] = (100000).to_bytes(8, "little") + I.cs(len(spk)) + spk
        self.check("p2wpkh", weird)

    def test_taproot_key_on_ecdsa_input_and_ecdsa_on_taproot(self):
        c = tb.make([{"form": "p2wpkh"}])
        x = tb.xonly(tb.DEV[0])
        c.imaps[0][b"\x23" + x] = tb.rho_for(0, x)
        c.pairs = []
        with self.assertRaises(EXP):
            tb.inproc_sign(tb.psbt_hex(c), c.dev_sks)
        c = tb.make([{"form": "tr-key"}])
        pk = tb.pub(tb.DEV[0])
        c.imaps[0][b"\x23" + pk] = tb.rho_for(0, pk)
        c.pairs = []
        with self.assertRaises(EXP):
            tb.inproc_sign(tb.psbt_hex(c), c.dev_sks)

    def test_script_forms(self):
        P_ = tb.pub(tb.DEV[0])
        O0, O1 = tb.pub(tb.OTHER[0]), tb.pub(tb.OTHER[1])
        ok_scripts = {
            "single": tb.push(P_) + b"\xac",
            "multi 1of1": tb.multisig([P_], 1),
            "multi 1of2": tb.multisig([P_, O0], 1),
            "multi 3of3 any order": tb.multisig([O0, O1, P_], 3),
            "generic checksigverify": tb.push(P_) + b"\xad\x51",
            "generic after other": tb.push(O0) + b"\xad" + tb.push(P_) + b"\xac",
        }
        for name, s in ok_scripts.items():
            for form in ("p2wsh-single", "p2sh-p2wsh-single", "p2sh-single"):
                c = tb.make([{"form": form, "script": s}])
                try:
                    self.assertSignerOk(c)
                except Exception as e:
                    self.fail("%s %s: %s" % (name, form, e))
        bad_scripts = {
            "codesep after": tb.push(P_) + b"\xac\xab",
            "codesep before": b"\xab" + tb.push(P_) + b"\xac",
            "multisig with codesep": tb.multisig([P_, O0], 1) + b"\xab",
            "listed twice multisig": tb.multisig([P_, O0, P_], 2),
            "listed twice generic": tb.push(P_) + b"\xad" + tb.push(P_) + b"\xac",
            "pushdata1 key": b"\x4c\x21" + P_ + b"\xac",
            "key not before sigop": tb.push(P_) + b"\x75\xac",
            "key absent": tb.push(O0) + b"\xac",
            "multisig m>n": bytes([0x53]) + tb.push(P_) + tb.push(O0) + b"\x52\xae",
            "multisig n mismatch": bytes([0x51]) + tb.push(P_) + tb.push(O0) + b"\x53\xae",
            "multisig m=0": bytes([0x00]) + tb.push(P_) + b"\x51\xae",
            "multisig invalid key": bytes([0x51]) + tb.push(P_) + tb.push(b"\x02" + b"\x05".rjust(32, b"\x00")) + b"\x52\xae",
            "multisig uncompressed key": bytes([0x51]) + tb.push(P_) + b"\x41" + b"\x04" + bytes(64) + b"\x52\xae",
            "truncated push": tb.push(P_) + b"\xac\x21\x00",
            "multisig no keys": b"\x51\x51\xae",
            "checkmultisigverify": bytes([0x51]) + tb.push(P_) + b"\x51\xaf",
        }
        for name, s in bad_scripts.items():
            c = tb.make([{"form": "p2wsh-single", "script": s}])
            with self.assertRaises(EXP, msg=name):
                tb.inproc_sign(tb.req2(c), c.dev_sks)

    def test_multisig_n_up_to_16_ok_and_17_fails(self):
        P_ = tb.pub(tb.DEV[0])
        keys = [tb.pub(tb.OTHER[i % 4]) if i != 7 else P_ for i in range(16)]
        # keys must differ? not required; build 16 keys with device key once
        keys = [P_] + [tb.pub(tb.OTHER[0]) for _ in range(15)]
        s = tb.multisig(keys, 16)
        c = tb.make([{"form": "p2wsh-multi", "script": s}])
        tb.inproc_sign(tb.req2(c), c.dev_sks)
        keys17 = keys + [tb.pub(tb.OTHER[1])]
        s17 = bytes([0x51]) + b"".join(tb.push(k) for k in keys17) + b"\x01\x11\xae"
        c = tb.make([{"form": "p2wsh-multi", "script": s17}])
        with self.assertRaises(EXP):
            tb.inproc_sign(tb.req2(c), c.dev_sks)

    def test_sighash_types(self):
        for ht in (1, 2, 3, 0x81, 0x82, 0x83):
            for form in ("p2wpkh", "p2pkh", "p2sh-p2wsh-multi", "tr-key", "tr-script"):
                forms = [{"form": form, "ht": ht}]
                c = tb.make(forms)
                out = self.assertSignerOk(c)
                tb.check_result(c, out)
        for form in ("tr-key", "tr-script"):
            c = tb.make([{"form": form, "ht": 0}])
            tb.check_result(c, self.assertSignerOk(c))
        for ht in (4, 5, 0x80, 0x84, 0x100, 0x101, 0x40, 0xFFFFFFFF, 0x7F):
            for form in ("p2wpkh", "tr-key"):
                c = tb.make([{"form": form, "ht": ht}])
                self.assertSignerFails(c)
        for form in ("p2wpkh", "p2pkh", "p2sh-single"):
            c = tb.make([{"form": form, "ht": 0}])
            self.assertSignerFails(c)
        c = tb.make([{"form": "p2wpkh", "ht": 1}])
        self.assertSignerFails(c, lambda c: c.imaps[0].__setitem__(b"\x03", b"\x01\x00\x00"))
        self.assertSignerFails(c, lambda c: c.imaps[0].__setitem__(b"\x03", b"\x01\x00\x00\x00\x00"))

    def test_sighash_single_needs_matching_output(self):
        for form in ("p2wpkh", "p2pkh", "tr-key", "tr-script"):
            for ht in (3, 0x83):
                c = tb.make([{"form": "p2wpkh", "key": 1}, {"form": form, "ht": ht}])
                c.dev_sks = [tb.DEV[0]]
                c.pairs = c.pairs[1:]
                # one output only: input 1 has no matching output
                with self.assertRaises(EXP):
                    tb.inproc_sign(tb.req2(c), c.dev_sks)
                c2 = tb.make([{"form": "p2wpkh", "key": 1}, {"form": form, "ht": ht}],
                             outs=[(50000, b"\x6a"), (49000, b"\x6a")])
                c2.pairs = c2.pairs[1:]
                out = tb.inproc_sign(tb.req2(c2), c2.dev_sks)
                tb.check_result(c2, out)

    def test_uncompressed_derivation_record(self):
        pt = I.mul(tb.DEV[0])
        unc = b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
        for form in ("p2wpkh", "p2pkh", "tr-key"):
            self.check(form, lambda c: c.imaps[0].__setitem__(b"\x06" + unc, tb.FP + tb.PATH_ECDSA))
        opt = I.mul(tb.OTHER[0])
        other_unc = b"\x04" + opt[0].to_bytes(32, "big") + opt[1].to_bytes(32, "big")
        c = tb.make([{"form": "p2wpkh"}])
        self.assertSignerOk(c, lambda c: c.imaps[0].__setitem__(b"\x06" + other_unc, tb.FP + tb.PATH_ECDSA))
        # a 65-byte key identifier fails
        c = tb.make([{"form": "p2wpkh"}])
        c.imaps[0][b"\x23" + unc] = bytes(32)
        c.pairs = []
        with self.assertRaises(EXP):
            tb.inproc_sign(tb.psbt_hex(c), c.dev_sks)

    def test_outputs_exceed_inputs(self):
        for form in ("p2wpkh", "p2pkh", "tr-key"):
            c = tb.make([{"form": form}], outs=[(100001, b"\x6a")])
            self.assertSignerFails(c)
            c = tb.make([{"form": form}], outs=[(100000, b"\x6a")])
            self.assertSignerOk(c)
        # an unknown amount elsewhere means the check cannot run
        c = tb.make([{"form": "p2wpkh"}, {"form": "p2wpkh", "key": 1}], outs=[(500000, b"\x6a")])
        c.pairs = c.pairs[:1]
        self.assertSignerFails(c)
        c.imaps[1].pop(b"\x01")
        self.assertSignerOk(c)

    def test_taproot_non_acp_needs_every_prevout(self):
        c = tb.make([{"form": "tr-key"}, {"form": "p2wpkh", "key": 1}])
        c.pairs = c.pairs[:1]
        self.assertSignerOk(c)
        self.assertSignerFails(c, lambda c: c.imaps[1].pop(b"\x01"))
        c = tb.make([{"form": "tr-key", "ht": 0x81}, {"form": "p2wpkh", "key": 1}])
        c.pairs = c.pairs[:1]
        c.imaps[1].pop(b"\x01")
        out = self.assertSignerOk(c)
        tb.check_result(c, out)

    def test_inputs_without_pair_are_unconstrained(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "p2wpkh", "key": 1}])
        c.pairs = c.pairs[:1]
        c.imaps[1][b"\x07"] = b"\x00"       # finalized
        c.imaps[1][b"\x08"] = b"\x00"
        tb.check_result(c, self.assertSignerOk(c))
        c.imaps[1][b"\x03"] = tb.le32(77)    # unclassifiable sighash on a non-pair input
        tb.check_result(c, self.assertSignerOk(c))

    def test_other_leaves_ignored(self):
        c = tb.make([{"form": "tr-script"}])
        c.imaps[0][b"\x15" + bytes([0xC0]) + bytes(32)] = b"\x50" + b"\xc0"   # an unrelated leaf with OP_SUCCESS
        tb.check_result(c, self.assertSignerOk(c))

    def test_one_input_both_paths_fails(self):
        # device holds the internal key and also appears in a leaf
        x = tb.xonly(tb.DEV[0])
        L1 = tb.push(x) + b"\xac"
        l1 = I.leaf_hash(L1)
        other = I.leaf_hash(tb.push(tb.xonly(tb.OTHER[2])) + b"\xac")
        a, b = (l1, other) if l1 < other else (other, l1)
        mr = I.TH("TapBranch", a + b)
        Q = I.tweak_pub(x, mr)
        c = tb.make([{"form": "tr-script"}])
        spk = b"\x51\x20" + Q[0].to_bytes(32, "big")
        c.imaps[0][b"\x01"] = (100000).to_bytes(8, "little") + I.cs(34) + spk
        c.imaps[0][b"\x17"] = x
        c.imaps[0][b"\x18"] = mr
        for k in [k for k in c.imaps[0] if k[0] == 0x15]:
            del c.imaps[0][k]
        c.imaps[0][b"\x15" + bytes([0xC0 | (Q[1] & 1)]) + x + other] = L1 + b"\xc0"
        c.info[0]["spk"] = spk
        c.spent = [(100000, spk)]
        # key-path pair alone is fine
        kp = dict(c.pairs[0]); kp.update(kind="tr_key", keyid=x, sigkey=b"\x13", pk=Q[0].to_bytes(32, "big"),
                                         m=I.taproot_sighash(c.tx, 0, 0, c.spent))
        sp = dict(c.pairs[0]); sp.update(kind="tr_script", keyid=x + l1, sigkey=b"\x14" + x + l1,
                                         pk=x, m=I.taproot_sighash(c.tx, 0, 0, c.spent, ext=l1))
        c1 = tb.clone(c); c1.pairs = [kp]
        tb.check_result(c1, tb.inproc_sign(tb.req2(c1), c1.dev_sks))
        c2 = tb.clone(c); c2.pairs = [sp]
        tb.check_result(c2, tb.inproc_sign(tb.req2(c2), c2.dev_sks))
        c3 = tb.clone(c); c3.pairs = [kp, sp]
        with self.assertRaises(EXP):
            tb.inproc_sign(tb.req2(c3), c3.dev_sks)

    def test_taproot_keypath_identifier_rules(self):
        # internal key field present and different from the identifier
        c = tb.make([{"form": "tr-key"}])
        self.assertSignerFails(c, lambda c: c.imaps[0].__setitem__(b"\x17", tb.xonly(tb.OTHER[0])))
        # field absent: identifier is used
        out = self.assertSignerOk(c, lambda c: c.imaps[0].pop(b"\x17"))
        tb.check_result(c, out)
        # wrong merkle root -> tweak does not give the output key
        self.assertSignerFails(c, lambda c: c.imaps[0].__setitem__(b"\x18", bytes(32)))
        c = tb.make([{"form": "tr-key", "merkle": True}])
        out = self.assertSignerOk(c)
        tb.check_result(c, out)
        self.assertSignerFails(c, lambda c: c.imaps[0].pop(b"\x18"))
        self.assertSignerFails(c, lambda c: c.imaps[0].__setitem__(b"\x18", bytes(31)))

    def test_taproot_script_path_rules(self):
        x = tb.xonly(tb.DEV[0])
        o = tb.xonly(tb.OTHER[5])
        ok = {
            "checksigverify": tb.push(x) + b"\xad\x51",
            "checksigadd": b"\x00" + tb.push(x) + b"\xba\x51\x9c",
            "other key first": tb.push(o) + b"\xad" + tb.push(x) + b"\xac",
            "our key elsewhere as data": tb.push(x) + b"\x75" + tb.push(o) + b"\xac" + tb.push(x) + b"\xac" if False else tb.push(x) + b"\x75" + tb.push(o) + b"\xac" + tb.push(x) + b"\xac",
        }
        # last one: key pushed twice, but only the second precedes a sig opcode -> exactly one -> ok
        for name, s in ok.items():
            c = tb.make([{"form": "tr-script", "leaf": s}])
            try:
                tb.check_result(c, self.assertSignerOk(c))
            except Exception as e:
                self.fail("%s: %s" % (name, e))
        bad = {
            "none": tb.push(o) + b"\xac",
            "two": tb.push(x) + b"\xad" + tb.push(x) + b"\xac",
            "op_success80": tb.push(x) + b"\xac\x50",
            "op_success_98": tb.push(x) + b"\xac\x62",
            "op_success_187": tb.push(x) + b"\xac\xbb",
            "op_success_254": tb.push(x) + b"\xac\xfe",
            "op_success_126": tb.push(x) + b"\xac\x7e",
            "codesep": tb.push(x) + b"\xac\xab",
            "pushdata1": b"\x4c\x20" + x + b"\xac",
            "not before sigop": tb.push(x) + b"\x75\xac",
            "truncated": tb.push(x) + b"\xac\x20\x01",
            "x only in data": tb.push(x) + b"\x75\x51",
            "16 byte push": b"\x10" + x[:16] + b"\xac",
        }
        for name, s in bad.items():
            c = tb.make([{"form": "tr-script", "leaf": s}])
            c.pairs[0]  # the pair exists in the case; the leaf fails in the signer
            self.assertSignerFails(c)
        # OP_SUCCESS bytes inside pushed data do not count
        c = tb.make([{"form": "tr-script", "leaf": tb.push(x) + b"\xac" + b"\x01\x50\x75"}])
        tb.check_result(c, self.assertSignerOk(c))

    def test_taproot_leaf_version_and_control_block(self):
        c = tb.make([{"form": "tr-script", "ver": 0xC2}])
        self.assertSignerFails(c)
        c = tb.make([{"form": "tr-script"}])
        # wrong output key in the spent output
        self.assertSignerFails(c, lambda c: c.imaps[0].__setitem__(
            b"\x01", (100000).to_bytes(8, "little") + I.cs(34) + b"\x51\x20" + bytes(32)))
        # control block with a bad length
        def bad_len(c):
            k = [k for k in c.imaps[0] if k[0] == 0x15][0]
            v = c.imaps[0].pop(k)
            c.imaps[0][k + b"\x00"] = v
        self.assertSignerFails(c, bad_len)
        # two entries with the same leaf and different control blocks
        def dup(c):
            k = [k for k in c.imaps[0] if k[0] == 0x15][0]
            v = c.imaps[0][k]
            c.imaps[0][k[:-1] + bytes([k[-1] ^ 1])] = v
        self.assertSignerFails(c, dup)
        # parity bit of the control block wrong
        def parity(c):
            k = [k for k in c.imaps[0] if k[0] == 0x15][0]
            v = c.imaps[0].pop(k)
            c.imaps[0][k[:1] + bytes([k[1] ^ 1]) + k[2:]] = v
        self.assertSignerFails(c, parity)
        # leaf version in the value differs from 0xC0
        def valver(c):
            k = [k for k in c.imaps[0] if k[0] == 0x15][0]
            c.imaps[0][k] = c.imaps[0][k][:-1] + b"\xc2"
        self.assertSignerFails(c, valver)
        # missing leaf script
        self.assertSignerFails(c, lambda c: [c.imaps[0].pop(k) for k in [k for k in c.imaps[0] if k[0] == 0x15]])

    def test_taproot_control_block_depth(self):
        for depth, ok in ((1, True), (128, True), (129, False)):
            nodes = [I.H(b"node%d" % j) for j in range(depth)]
            c = tb.make([{"form": "tr-script", "nodes": nodes}])
            if ok:
                tb.check_result(c, self.assertSignerOk(c))
            else:
                self.assertSignerFails(c)

    def test_musig2_participants(self):
        x0 = tb.xonly(tb.DEV[0])
        agg = tb.pub(tb.OTHER[0])
        k = b"\x1a" + agg
        for form in ("tr-key", "tr-script"):
            c = tb.make([{"form": form}])
            # lists a device key, either parity
            for par in (2, 3):
                v = bytes([par]) + x0 + tb.pub(tb.OTHER[1])
                self.assertSignerFails(c, lambda c, v=v: c.imaps[0].__setitem__(k, v))
            # lists only other keys: fine
            v = tb.pub(tb.OTHER[1]) + tb.pub(tb.OTHER[2])
            tb.check_result(c, self.assertSignerOk(c, lambda c: c.imaps[0].__setitem__(k, v)))
            # malformed participant list
            self.assertSignerFails(c, lambda c: c.imaps[0].__setitem__(k, bytes(34)))
        # internal key equals the x-only aggregate key
        c = tb.make([{"form": "tr-key"}])
        aggk = b"\x1a" + b"\x02" + tb.xonly(tb.DEV[0])
        v = tb.pub(tb.OTHER[1]) + tb.pub(tb.OTHER[2])
        self.assertSignerFails(c, lambda c: c.imaps[0].__setitem__(aggk, v))
        aggk3 = b"\x1a" + b"\x03" + tb.xonly(tb.DEV[0])
        self.assertSignerFails(c, lambda c: c.imaps[0].__setitem__(aggk3, v))
        # ECDSA input: field is not examined
        c = tb.make([{"form": "p2wpkh"}])
        tb.check_result(c, self.assertSignerOk(c, lambda c: c.imaps[0].__setitem__(k, bytes([2]) + x0 + bytes([2]) + x0)))

    def test_derivation_purpose_scheme_split(self):
        c = tb.make([{"form": "p2wpkh"}])
        pub = tb.pub(tb.DEV[0])
        bad = tb.FP + tb.le32(0x80000000 + 86) + tb.le32(0x80000000)
        self.assertSignerFails(c, lambda c: c.imaps[0].__setitem__(b"\x06" + pub, bad))
        c = tb.make([{"form": "tr-key"}])
        x = tb.xonly(tb.DEV[0])
        for purpose in (44, 49, 84):
            bad = b"\x00" + tb.FP + tb.le32(0x80000000 + purpose) + tb.le32(0)
            self.assertSignerFails(c, lambda c, bad=bad: c.imaps[0].__setitem__(b"\x16" + x, bad))
        # non-hardened first element or other purposes are not examined
        good = b"\x00" + tb.FP + tb.le32(5) + tb.le32(0)
        tb.check_result(c, self.assertSignerOk(c, lambda c: c.imaps[0].__setitem__(b"\x16" + x, good)))

    def test_v2_inputs_and_fee(self):
        for v in (0, 2):
            c = tb.make([{"form": "p2wpkh"}], version=v, outs=[(100001, b"\x6a")])
            self.assertSignerFails(c)

    def test_bad_psbt_structure(self):
        c = tb.make([{"form": "p2wpkh"}])
        good = tb.req2(c)
        for h in ("", "zz", good[:-2], good + "00", "70736274fe" + good[10:], good.replace("0100", "01", 1)[:40]):
            with self.assertRaises(EXP):
                tb.inproc_sign(h, c.dev_sks)
        # duplicate key
        b = bytearray(bytes.fromhex(good))
        maps = I.read_psbt(bytes(b))
        maps[1] = maps[1] + [maps[1][0]]
        with self.assertRaises(EXP):
            tb.inproc_sign(I.write_psbt(maps).hex(), c.dev_sks)
        # v1, v3
        maps = I.read_psbt(bytes.fromhex(good))
        for ver in (1, 3):
            m2 = [list(m) for m in maps]
            m2[0].append((b"\xfb", tb.le32(ver)))
            with self.assertRaises(EXP):
                tb.inproc_sign(I.write_psbt(m2).hex(), c.dev_sks)

    def test_bad_secret_keys(self):
        c = tb.make([{"form": "p2wpkh"}])
        h = tb.req2(c)
        for bad in ("00" * 32, "ff" * 32, "01" * 31, "zz" * 32):
            with self.assertRaises(EXP):
                S.run([bad], False, h)


class TestModifiable(Base):
    def flags(self, out):
        maps = I.read_psbt(bytes.fromhex(out))
        v = dict(maps[0]).get(b"\x06")
        return None if v is None else v[0]

    def run_ht(self, hts, initial=None):
        forms = [{"form": "p2wpkh", "ht": h, "key": i % 2} for i, h in enumerate(hts)]
        c = tb.make(forms, version=2, outs=[(10000, b"\x6a")] * (len(hts) + 1))
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        if initial is not None:
            c.gmap[b"\x06"] = bytes([initial])
        return self.flags(tb.inproc_sign(tb.req2(c), c.dev_sks))

    def test_flag_updates(self):
        self.assertEqual(self.run_ht([1], 7), 0b100 + 0)     # ALL clears inputs+outputs, bit2 kept
        self.assertEqual(self.run_ht([0x81], 3), 1)          # ALL|ACP clears outputs only
        self.assertEqual(self.run_ht([2], 3), 2)             # NONE clears inputs only
        self.assertEqual(self.run_ht([0x82], 3), 3)          # NONE|ACP clears nothing
        self.assertEqual(self.run_ht([3], 3), 4)             # SINGLE clears both, sets bit 2
        self.assertEqual(self.run_ht([0x83], 3), 1 | 4)      # SINGLE|ACP clears outputs, sets bit 2
        self.assertEqual(self.run_ht([1, 0x82], 3), 0)       # cumulative
        self.assertEqual(self.run_ht([0x82, 0x83], 3), 4 | 1)
        self.assertEqual(self.run_ht([1], 0xF3), 0xF0 | 0)   # other bits preserved
        self.assertEqual(self.run_ht([0x82], 0x00), 0)       # present zero stays present
        self.assertEqual(self.run_ht([0x82], None), None)    # absent stays absent when nothing is set
        self.assertEqual(self.run_ht([0x83], None), 4)       # absent field created for a set flag
        self.assertEqual(self.run_ht([1], None), None)

    def test_taproot_default_counts_as_all(self):
        c = tb.make([{"form": "tr-key"}], version=2)
        c.gmap[b"\x06"] = b"\x03"
        self.assertEqual(self.flags(tb.inproc_sign(tb.req2(c), c.dev_sks)), 0)

    def test_v0_has_no_modifiable(self):
        c = tb.make([{"form": "p2wpkh", "ht": 3}], version=0)
        self.assertIsNone(self.flags(tb.inproc_sign(tb.req2(c), c.dev_sks)))

    def test_not_changed_in_first_pass(self):
        c = tb.make([{"form": "p2wpkh"}], version=2)
        c.gmap[b"\x06"] = b"\x03"
        self.assertEqual(self.flags(tb.inproc_sign(tb.req1(c), c.dev_sks)), 3)


class TestV2Construction(Base):
    def test_locktime_rules(self):
        def build(locks, fallback=None):
            c = tb.make([{"form": "p2wpkh"}] * len(locks), version=2, outs=[(1000, b"\x6a")])
            for i, (t, h) in enumerate(locks):
                if t is not None:
                    c.imaps[i][b"\x11"] = tb.le32(t)
                if h is not None:
                    c.imaps[i][b"\x12"] = tb.le32(h)
            if fallback is not None:
                c.gmap[b"\x03"] = tb.le32(fallback)
            else:
                c.gmap.pop(b"\x03", None)
            return P.Psbt.parse(tb.serialize(c)).tx.locktime
        self.assertEqual(build([(None, None)]), 0)
        self.assertEqual(build([(None, None)], fallback=77), 77)
        self.assertEqual(build([(500000001, None)], fallback=77), 500000001)
        self.assertEqual(build([(None, 100), (None, 200)]), 200)
        self.assertEqual(build([(500000001, 100)]), 100)
        with self.assertRaises(P.PsbtError):
            build([(500000001, None), (None, 100)])

    def test_sequence_default_and_tx_matches_v0(self):
        c0 = tb.make([{"form": "p2wpkh"}], version=0)
        c2 = tb.make([{"form": "p2wpkh"}], version=2)
        a, b = P.Psbt.parse(tb.serialize(c0)), P.Psbt.parse(tb.serialize(c2))
        self.assertEqual(a.tx.key(), b.tx.key())
        del c2.imaps[0][b"\x10"]
        self.assertEqual(P.Psbt.parse(tb.serialize(c2)).tx.ins[0][2], 0xFFFFFFFF)
        # both signed from the v2 form give the same message as v0 (hence same signatures)
        r0 = tb.inproc_sign(tb.req2(c0), c0.dev_sks)
        c2b = tb.make([{"form": "p2wpkh"}], version=2)
        r2 = tb.inproc_sign(tb.req2(c2b), c2b.dev_sks)
        s0 = dict(I.read_psbt(bytes.fromhex(r0))[1])[c0.pairs[0]["sigkey"]]
        s2 = dict(I.read_psbt(bytes.fromhex(r2))[1])[c2b.pairs[0]["sigkey"]]
        self.assertEqual(s0, s2)

    def test_v2_missing_fields_fail(self):
        for k in (b"\x0e", b"\x0f"):
            c = tb.make([{"form": "p2wpkh"}], version=2)
            c.imaps[0].pop(k)
            with self.assertRaises(EXP):
                tb.inproc_sign(tb.req2(c), c.dev_sks)
        for k in (b"\x02", b"\x04", b"\x05"):
            c = tb.make([{"form": "p2wpkh"}], version=2)
            c.gmap.pop(k)
            with self.assertRaises(EXP):
                tb.inproc_sign(tb.req2(c), c.dev_sks)
        c = tb.make([{"form": "p2wpkh"}], version=2)
        c.omaps[0].pop(b"\x03")
        with self.assertRaises(EXP):
            tb.inproc_sign(tb.req2(c), c.dev_sks)


if __name__ == "__main__":
    unittest.main()
