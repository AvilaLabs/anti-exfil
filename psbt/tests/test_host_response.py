"""Host: Choosing pairs, First/Second pass steps 1 to 6, Handling a response."""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as K            # noqa: E402
import anti_exfil as AE       # noqa: E402
import psbt_codec as C        # noqa: E402
import spend as S             # noqa: E402
import host as H              # noqa: E402
import transport as T         # noqa: E402

N = AE._N


class HostBase(K.Base):
    def mkrig(self, forms, steps=(), version=0, max_retries=0, **kw):
        inputs = [K.Inp(f) if isinstance(f, K.Form) else f for f in forms]
        return K.Rig(inputs, self.tmp, version=version, link_cls=T.ScriptedLink, steps=list(steps),
                     max_retries=max_retries, rho_source=K.fixed_rho(), **kw)

    def fails_with(self, rig, reason):
        with self.assertRaises(H.AttemptFailed) as cm:
            rig.host.sign(rig.request_bytes)
        self.assertEqual(cm.exception.reasons[0], reason, cm.exception.reasons)
        return cm.exception

    def ok(self, rig):
        return rig.host.sign(rig.request_bytes)


def edit_core(p, how):
    """Change the core transaction of a parsed response in place."""
    tx = C.core_tx(p)
    if how == "output_value":
        if p.version == 0:
            p.glob[b"\x00"] = C.ser_tx(C.Tx(tx.version, tx.ins, [(tx.outs[0][0] - 1,) + tx.outs[0][1:]] + tx.outs[1:], tx.locktime))
        else:
            p.outputs[0][b"\x03"] = struct.pack("<Q", tx.outs[0][0] - 1)
    elif how == "output_script":
        if p.version == 0:
            p.glob[b"\x00"] = C.ser_tx(C.Tx(tx.version, tx.ins, [(tx.outs[0][0], b"\x6a")] + tx.outs[1:], tx.locktime))
        else:
            p.outputs[0][b"\x04"] = b"\x6a"
    elif how == "sequence":
        if p.version == 0:
            i = tx.ins[0]
            p.glob[b"\x00"] = C.ser_tx(C.Tx(tx.version, [(i[0], i[1], i[2], 1)] + tx.ins[1:], tx.outs, tx.locktime))
        else:
            p.inputs[0][b"\x10"] = struct.pack("<I", 1)
    elif how == "locktime":
        if p.version == 0:
            p.glob[b"\x00"] = C.ser_tx(C.Tx(tx.version, tx.ins, tx.outs, 5))
        else:
            p.glob[b"\x03"] = struct.pack("<I", 5)
    elif how == "version":
        if p.version == 0:
            p.glob[b"\x00"] = C.ser_tx(C.Tx(1, tx.ins, tx.outs, tx.locktime))
        else:
            p.glob[b"\x02"] = struct.pack("<I", 1)
    elif how == "prevout":
        if p.version == 0:
            i = tx.ins[0]
            p.glob[b"\x00"] = C.ser_tx(C.Tx(tx.version, [(i[0], 9, i[2], i[3])] + tx.ins[1:], tx.outs, tx.locktime))
        else:
            p.inputs[0][b"\x0f"] = struct.pack("<I", 9)
    elif how == "extra_output":
        if p.version == 0:
            p.glob[b"\x00"] = C.ser_tx(C.Tx(tx.version, tx.ins, tx.outs + [(1, b"\x6a")], tx.locktime))
        else:
            p.outputs.append({b"\x03": struct.pack("<Q", 1), b"\x04": b"\x6a"})
            p.glob[b"\x05"] = C.compact(len(p.outputs))
        if p.version == 0:
            p.outputs.append({})


class HandlingResponse(HostBase):
    # ---- core transaction ------------------------------------------------
    def test_core_tx_changed_each_pass(self):
        """Handling a response: "the core transaction differs from the request, whether read from the PSBT version 0 unsigned transaction or built from the version 2 fields\""""
        for version in (0, 2):
            for how in ("output_value", "output_script", "sequence", "locktime", "version", "prevout", "extra_output"):
                for phase in (1, 2):
                    steps = [T.honest] * (phase - 1) + [T.tamper(lambda p, how=how: edit_core(p, how))]
                    with self.subTest(version=version, how=how, phase=phase):
                        rig = self.mkrig([K.Form("p2wpkh")], steps, version=version)
                        self.fails_with(rig, "core_tx_changed")

    # ---- missing -----------------------------------------------------------
    def test_missing_commitment_and_signature(self):
        """Handling a response: "a requested commitment or signature is missing\""""
        rig = self.mkrig([K.Form("p2wsh-2of3")], [T.tamper(lambda p: p.inputs[0].pop(
            [k for k in p.inputs[0] if k[:1] == b"\x22"][0]))])
        self.fails_with(rig, "commitment_missing")
        rig = self.mkrig([K.Form("p2wsh-2of3")], [T.honest, T.tamper(lambda p: p.inputs[0].pop(
            [k for k in p.inputs[0] if k[:1] == b"\x02"][0]))])
        self.fails_with(rig, "signature_missing")

    def test_unmodified_echo_is_a_missing_commitment(self):
        """Backward compatibility: a signer that ignores the fields -> "The host sees no nonce commitment, fails the attempt\""""
        rig = self.mkrig([K.Form("p2wpkh")], [lambda req, real: req])
        self.fails_with(rig, "commitment_missing")

    def test_ordinary_signature_is_refused_no_fallback(self):
        """Host: "If the device returns an ordinary signature ... the attempt fails, and the host MUST NOT fall back\""""
        def ordinary(req, real):
            p = C.parse(req)
            p.inputs[0] = C.strip_ae(p.inputs[0])
            p.inputs[0][b"\x02" + K.pub33(self.sk)] = b"\x30" * 70
            return p.serialize()
        form = K.Form("p2wpkh")
        self.sk = form.a
        rig = self.mkrig([form], [ordinary])
        self.fails_with(rig, "signature_added")
        self.assertEqual(len(rig.link.transcript), 1)       # no second request went out

    def test_malformed_response(self):
        rig = self.mkrig([K.Form("p2wpkh")], [T.garbage])
        self.fails_with(rig, "malformed")

    # ---- commitments -------------------------------------------------------
    def test_bad_commitment(self):
        rig = self.mkrig([K.Form("p2wpkh")], [T.change_r0(new=b"\x05" + b"\x01" * 32)])
        self.fails_with(rig, "bad_commitment")

    def test_commitment_differs_from_held_host_commitment(self):
        """Handling a response: "a commitment for a pair differs from one the host holds for this attempt\""""
        def f(p):
            k = [k for k in p.inputs[0] if k[:1] == b"\x21"][0]
            p.inputs[0][k] = b"\x00" * 32
        rig = self.mkrig([K.Form("p2wpkh")], [T.tamper(f)])
        self.fails_with(rig, "commitment_differs")

    # ---- anti-exfil fields -------------------------------------------------
    def test_second_pass_holds_any_ae_field(self):
        """Handling a response: "a second-pass response holds any anti-exfil field\""""
        for typ in (0x21, 0x22, 0x23):
            def f(p, typ=typ):
                kid = K.pub33(self.k)
                r0 = [v for t, _, v in C.ae_entries(C.parse(rig.link.transcript[0][1]).inputs[0]) if t == 0x22][0]
                p.inputs[0][bytes([typ]) + kid] = {0x21: b"\x00" * 32, 0x22: r0, 0x23: b"\x00" * 32}[typ]
            form = K.Form("p2wpkh")
            self.k = form.a
            rig = self.mkrig([form], [T.honest, T.tamper(f)])
            with self.subTest(typ=typ):
                self.fails_with(rig, "ae_field_in_second_pass")

    def test_first_pass_holds_randomness(self):
        """Handling a response: "a first-pass response holds PSBT_IN_AE_HOST_RANDOMNESS\""""
        form = K.Form("p2wpkh")
        rig = self.mkrig([form], [T.tamper(lambda p: p.inputs[0].update({b"\x23" + K.pub33(form.a): b"\x00" * 32}))])
        self.fails_with(rig, "rho_in_first_pass")

    def test_field_for_pair_not_requested(self):
        """Handling a response: "either response holds an anti-exfil field for a pair that was not requested\""""
        form = K.Form("p2wsh-2of3")
        extra = b"\x02" + b"\x42" * 32
        for typ in (0x21, 0x22):
            rig = self.mkrig([form], [T.tamper(lambda p, typ=typ: p.inputs[0].update({bytes([typ]) + extra: b"\x00" * (32 if typ == 0x21 else 33)}))])
            with self.subTest(typ=typ):
                self.fails_with(rig, "unrequested_pair")
        rig = self.mkrig([form], [T.honest, T.tamper(lambda p: p.inputs[0].update({b"\x22" + extra: b"\x02" + b"\x01" * 32}))])
        self.fails_with(rig, "ae_field_in_second_pass")

    # ---- signature fields --------------------------------------------------
    def with_foreign_sig(self, version=0):
        """2-of-3 where another signer's partial signature is already in the host's PSBT."""
        form = K.Form("p2wsh-2of3")
        form.held = [form.a]
        inp = K.Inp(form)
        rig = K.Rig([inp], self.tmp, version=version, link_cls=T.ScriptedLink, steps=[], max_retries=0,
                    rho_source=K.fixed_rho(), signer_keys=[form.a], extra_keys=[form.b])
        foreign = b"\x02" + K.pub33(form.c)
        rig.psbt.inputs[0][foreign] = b"\x30" + b"\x01" * 70
        return form, rig, foreign

    def test_signature_added_or_changed_in_first_pass(self):
        """Handling a response: "a signature field is added or changed relative to the request, other than a requested signature in a second-pass response\""""
        form, rig, foreign = self.with_foreign_sig()
        added = b"\x02" + K.pub33(form.b)
        rig.link.steps = [T.tamper(lambda p: p.inputs[0].update({added: b"\x30" * 70}))]
        self.fails_with(rig, "signature_added")
        form, rig, foreign = self.with_foreign_sig()
        rig.link.steps = [T.tamper(lambda p: p.inputs[0].update({foreign: b"\x31" * 70}))]
        self.fails_with(rig, "signature_changed")
        form, rig, foreign = self.with_foreign_sig()
        rig.link.steps = [T.tamper(lambda p: p.inputs[0].update({b"\x02" + K.pub33(form.a): b"\x30" * 70}))]
        self.fails_with(rig, "signature_added")          # even the requested one, in a first-pass response
        form, rig, foreign = self.with_foreign_sig()
        rig.link.steps = [T.tamper(lambda p: p.inputs[0].update({b"\x13": b"\x00" * 64, b"\x14" + b"\x01" * 64: b"\x00" * 64}))]
        self.fails_with(rig, "signature_added")

    def test_signature_added_or_changed_in_second_pass(self):
        form, rig, foreign = self.with_foreign_sig()
        added = b"\x02" + K.pub33(form.b)
        rig.link.steps = [T.honest, T.tamper(lambda p: p.inputs[0].update({added: b"\x30" * 70}))]
        self.fails_with(rig, "signature_added")
        form, rig, foreign = self.with_foreign_sig()
        rig.link.steps = [T.honest, T.tamper(lambda p: p.inputs[0].update({foreign: b"\x31" * 70}))]
        self.fails_with(rig, "signature_changed")
        form, rig, foreign = self.with_foreign_sig()
        rig.link.steps = [T.honest, T.tamper(lambda p: p.inputs[0].pop(foreign))]
        self.fails_with(rig, "signature_removed")
        form, rig, foreign = self.with_foreign_sig()
        res = rig.host.sign(rig.request_bytes)          # the requested signature in a second-pass response is allowed
        self.assertIn(foreign, C.parse(res.psbt).inputs[0])

    def test_signature_dropped_from_finalized_input(self):
        """Handling a response: "... or is removed from an input that has no final scriptSig or final witness in the request"."""
        for final, value in ((b"\x08", b"\x02\x01\x01\x01\x02"), (b"\x07", b"\x00")):
            def build():
                mine, other = K.Form("p2wpkh"), K.Form("p2wpkh", "other")
                rig = K.Rig([K.Inp(mine), K.Inp(other)], self.tmp, signer_keys=[mine.a], link_cls=T.ScriptedLink, max_retries=0)
                key = b"\x02" + K.pub33(other.a)
                rig.psbt.inputs[1][key] = b"\x30\x06\x02\x01\x01\x02\x01\x01\x01"
                rig.psbt.inputs[1][final] = value
                return rig, key
            rig, key = build()
            drop = T.tamper(lambda p: p.inputs[1].pop(key))
            rig.link.steps = [drop, drop]
            res = self.ok(rig)
            self.assertIn(key, C.parse(res.psbt).inputs[1])     # the host's own copy keeps it
            rig, key = build()
            rig.link.steps = [T.honest, T.tamper(lambda p: p.inputs[1].update({key: b"\x31" * 70}))]
            self.fails_with(rig, "signature_changed")           # still fails if changed
            rig, key = build()
            added = b"\x02" + b"\x02" + b"\x66" * 32
            rig.link.steps = [T.tamper(lambda p: p.inputs[1].update({added: b"\x30" * 70}))]
            self.fails_with(rig, "signature_added")             # still fails if added

    # ---- ignored differences, nothing copied --------------------------------
    def test_other_differences_ignored_and_never_copied(self):
        """Handling a response: "It ignores other differences.\" Host: nothing is copied except values rebuilt from verified signatures."""
        def noise(p):
            p.glob[b"\xfc\x01g"] = b"global junk"
            p.inputs[0][b"\xfc\x01i"] = b"input junk"
            p.outputs[0][b"\xfc\x01o"] = b"output junk"
            p.outputs[0][b"\x30" + b"z" * 5] = b"unknown output field"
            p.inputs[0][b"\x06" + b"\x02" + b"\x77" * 32] = b"fp" * 2           # extra derivation record
            p.inputs[0][b"\x04"] = b"changed redeem script"
        for version in (0, 2):
            clean = self.mkrig([K.Form("p2wpkh")], version=version)
            base = self.ok(clean)
            rig = self.mkrig([K.Form("p2wpkh")], [T.tamper(noise), T.tamper(noise)], version=version)
            # same keys and prevouts so the host-built result must match byte for byte
            rig.inputs, rig.psbt = clean.inputs, clean.psbt
            rig.host.store_path = None
            res = rig.host.sign(rig.request_bytes)
            self.assertEqual(res.psbt, base.psbt)
            self.assertNotIn(b"junk", res.psbt)

    def test_response_in_another_psbt_version_with_same_core_tx_is_not_in_the_failure_list(self):
        """Handling a response lists the failure conditions; a version change with an equal core transaction is not one of them."""
        rig = self.mkrig([K.Form("p2wpkh")], [T.tamper(lambda p: None)])
        self.ok(rig)

    # ---- step 4 ------------------------------------------------------------
    def sig_key(self, p):
        return [k for k in p.inputs[0] if k[:1] in (b"\x02", b"\x13", b"\x14")][0]

    def mutate_sig(self, fn, form_name="p2wpkh", reason="verify_failed", version=0, sighash=None):
        form = K.Form(form_name)
        def f(p):
            k = self.sig_key(p)
            p.inputs[0][k] = fn(p.inputs[0][k])
        rig = self.mkrig([K.Inp(form, sighash=sighash)], [T.honest, T.tamper(f)], version=version)
        exc = self.fails_with(rig, reason)
        self.assertEqual(rig.store.failures("dev-A"), 1)
        return exc

    def test_der_must_be_strict(self):
        """Second pass: "a field that is not strict DER (BIP 66) fails.\""""
        def der_parts(f):
            d = f[:-1]
            lr = d[3]
            return d[4:4 + lr], d[6 + lr:], f[-1]
        def build(r, s, h, lr=None, ls=None, outer=None, tail=b""):
            body = b"\x02" + bytes([len(r) if lr is None else lr]) + r + b"\x02" + bytes([len(s) if ls is None else ls]) + s + tail
            return b"\x30" + bytes([len(body) if outer is None else outer]) + body + bytes([h])
        cases = {
            "leading zero pad on r": lambda f: build(b"\x00" + der_parts(f)[0], der_parts(f)[1], f[-1]),
            "trailing byte in sequence": lambda f: build(*der_parts(f)[:2], f[-1], tail=b"\x00"),
            "wrong outer length": lambda f: build(*der_parts(f)[:2], f[-1], outer=len(f) - 1),
            "negative s": lambda f: build(der_parts(f)[0], b"\x80" + der_parts(f)[1][1:], f[-1]),
            "long-form length": lambda f: b"\x30\x81" + f[1:],
            "truncated": lambda f: f[:20] + f[-1:],
        }
        for name, fn in cases.items():
            with self.subTest(name):
                self.mutate_sig(fn, reason="bad_der")

    def test_der_integers_of_one_zero_byte_and_of_exactly_two_to_the_256(self):
        """Second pass: "a field that is not strict DER (BIP 66) fails\"; a one-byte zero integer is strict DER, so it reaches
        the signature check, and an integer of exactly 2^256 does not fit in 32 bytes."""
        def parts(f):
            d = f[:-1]
            lr = d[3]
            return d[4:4 + lr], d[6 + lr:]
        def der(r, s, h):
            body = b"\x02" + bytes([len(r)]) + r + b"\x02" + bytes([len(s)]) + s
            return b"\x30" + bytes([len(body)]) + body + bytes([h])
        two_256 = b"\x01" + b"\x00" * 32
        cases = (
            ("r is the single byte 0x00", lambda f: der(b"\x00", parts(f)[1], f[-1]), "verify_failed"),
            ("s is the single byte 0x00", lambda f: der(parts(f)[0], b"\x00", f[-1]), "verify_failed"),
            ("r is exactly 2^256", lambda f: der(two_256, parts(f)[1], f[-1]), "bad_der"),
            ("s is exactly 2^256", lambda f: der(parts(f)[0], two_256, f[-1]), "bad_der"),
        )
        for name, fn, reason in cases:
            with self.subTest(name):
                self.mutate_sig(fn, reason=reason)

    def test_wrong_sighash_byte_each_scheme(self):
        """Second pass: "For either scheme, the sighash type in the response MUST be the expected one.\""""
        self.mutate_sig(lambda f: f[:-1] + b"\x02", reason="wrong_sighash")
        self.mutate_sig(lambda f: f[:-1] + b"\x81", reason="wrong_sighash", sighash=1)
        self.mutate_sig(lambda f: f + b"\x01", "p2tr-key", reason="bad_sig_length")           # DEFAULT must have no trailing byte
        self.mutate_sig(lambda f: f[:-1] + b"\x02", "p2tr-key", reason="wrong_sighash", sighash=1)
        self.mutate_sig(lambda f: f[:-1], "p2tr-key", reason="bad_sig_length", sighash=1)
        self.mutate_sig(lambda f: f[:-1] + b"\x81", "p2tr-script", reason="wrong_sighash", sighash=1)

    def test_high_s_rejected(self):
        """Protocol ECDSA step 5: "0 < s <= (n - 1) / 2\""""
        def high(f):
            r, s, h = S.parse_der_sig(f)
            return S.sigfield("ecdsa", h, r, N - s)
        self.mutate_sig(high)

    def test_flipped_bits(self):
        for name, off in (("p2wpkh", 10), ("p2tr-key", 40), ("p2tr-script", 3)):
            self.mutate_sig(lambda f, off=off: f[:off] + bytes([f[off] ^ 1]) + f[off + 1:], name)

    def test_reject_every_signature_if_one_fails(self):
        """Second pass: "If any check fails, reject every signature in the response and fail the attempt.\""""
        form = K.Form("p2wsh-2of3")
        def f(p):
            k = sorted(k for k in p.inputs[0] if k[:1] == b"\x02")[-1]
            v = p.inputs[0][k]
            p.inputs[0][k] = v[:12] + bytes([v[12] ^ 1]) + v[13:]
        rig = self.mkrig([form], [T.honest, T.tamper(f)])
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)

    def test_valid_signature_with_wrong_nonce(self):
        """Protocol step 5: a valid signature by the right key whose nonce is not W is rejected.
        The signature verifies as an ordinary signature; the host's verify rejects it, and accepts the honest one (control)."""
        for name in ("p2tr-key", "p2tr-key-root", "p2tr-script", "p2wpkh", "p2wsh-single", "p2pkh"):
            form = K.Form(name)
            inp = K.Inp(form)
            rig0 = self.mkrig([inp])
            pr = K.pairs_of(rig0)[0]
            signer = rig0.signer
            sk = signer._secret_for(pr)
            seen = {}

            def evil(req, real, pr=pr, sk=sk):
                resp = real(req)
                if b"\x23" not in b"".join(k[:1] for m in C.parse(req).inputs for k in m):
                    return resp
                p = C.parse(resp)
                d0 = int.from_bytes(sk, "big")
                k = int.from_bytes(K.seedkey("other nonce"), "big") % N
                if pr.scheme == "bip340":
                    P = AE._mul(d0)
                    d = d0 if P[1] % 2 == 0 else N - d0
                    W = AE._mul(k)
                    kk = k if W[1] % 2 == 0 else N - k
                    r = AE._b32(W[0])
                    e = int.from_bytes(AE._tagged_hash("BIP0340/challenge", r + pr.pk + pr.message), "big") % N
                    sig = r + AE._b32((kk + e * d) % N)
                    seen["plain_ok"] = AE._schnorr_verify(pr.pk, pr.message, sig)
                    field = S.sigfield("bip340", pr.sighash, sig)
                else:
                    r = AE._mul(k)[0] % N
                    z = int.from_bytes(pr.message, "big") % N
                    s = pow(k, N - 2, N) * (z + r * d0) % N
                    s = s if s <= (N - 1) // 2 else N - s
                    sig = AE._b32(r) + AE._b32(s)
                    seen["plain_ok"] = plain_ecdsa_verify(AE._parse33(pr.pk), pr.message, r, s)
                    field = S.sigfield("ecdsa", pr.sighash, r, s)
                seen["sig"] = sig
                seen["req"] = req
                p.inputs[pr.index][pr.sigkey] = field
                return p.serialize()
            rig = self.mkrig([inp], [T.honest, evil])
            with self.subTest(name):
                exc = self.fails_with(rig, "verify_failed")
                self.assertTrue(seen["plain_ok"], "the forged signature must be valid on its own")
                rho = C.parse(seen["req"]).inputs[pr.index][b"\x23" + pr.keyid]
                r0 = [v for _, _, v in C.ae_entries(C.parse(rig.link.transcript[0][1]).inputs[pr.index]) if len(v) == 33][0]
                check = AE.host_verify if pr.scheme == "bip340" else AE.ecdsa_host_verify
                self.assertIs(check(pr.pk, pr.message, rho, r0, seen["sig"]), False)
                good = check(pr.pk, pr.message, rho, r0, self.honest_sig(rig0, pr, rho, r0))
                self.assertTrue(good, "control: the host's verify accepts the honest signature")

    def honest_sig(self, rig, pr, rho, r0):
        sk = rig.signer._secret_for(pr)
        return AE.device_sign(sk, pr.message, rho) if pr.scheme == "bip340" else AE.ecdsa_device_sign(sk, pr.message, rho)

    def test_signature_by_another_key_or_message(self):
        """Protocol step 5: pk and m are the host's own."""
        form = K.Form("p2wpkh")
        inp = K.Inp(form)
        other = K.seedkey("intruder")
        def f(p):
            pr = K.pairs_of(rig0)[0]
            rho = C.parse(rig.link.transcript[-1][0]).inputs[0][b"\x23" + pr.keyid] if False else None
        rig0 = self.mkrig([inp])
        pr = K.pairs_of(rig0)[0]
        def evil(req, real):
            resp = real(req)
            p = C.parse(resp)
            rho = [v for _, _, v in C.ae_entries(C.parse(req).inputs[0]) if len(v) == 32][0]
            sig = AE.ecdsa_device_sign(other, pr.message, rho)
            p.inputs[0][pr.sigkey] = S.sigfield("ecdsa", 1, int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            return p.serialize()
        rig = self.mkrig([inp], [T.honest, evil])
        self.fails_with(rig, "verify_failed")

    # ---- steps 5 and 6 -----------------------------------------------------
    def test_result_holds_only_rebuilt_fields_and_no_ae_fields(self):
        """Second pass step 5: "Add to the host's PSBT only fields it builds from the verified (r, s) or sig and the expected sighash type.\""""
        for name in K.ALL_FORMS:
            for version in (0, 2):
                inp = K.Inp(K.Form(name))
                rig = self.mkrig([inp], version=version)
                res = self.ok(rig)
                out = C.parse(res.psbt)
                base = rig.psbt
                new = {k for k in out.inputs[0] if k not in base.inputs[0]}
                self.assertTrue(new and all(k[:1] in (b"\x02", b"\x13", b"\x14") for k in new), (name, new))
                self.assertEqual(C.ae_entries(out.inputs[0]), [])
                self.assertEqual({k: v for k, v in out.inputs[0].items() if k in base.inputs[0]}, base.inputs[0])

    def test_v2_flag_updates_on_hosts_own_psbt(self):
        """Second pass step 6: BIP 370 flag updates, cumulative, SIGHASH_DEFAULT counts as ALL, absent is zero, other flags preserved."""
        cases = [([1], None, None), ([3], None, b"\x04"), ([0x81], 0b11, bytes([0b01])), ([0x82], 0b11, bytes([0b11])),
                 ([0x83], 0b11, bytes([0b101])), ([1, 3], 0b11, b"\x04"), ([1, 0x82], 0b1000_0011, bytes([0b1000_0000])),
                 ([0x81, 0x81], 0b1000_0011, bytes([0b1000_0001]))]
        for hs, start, want in cases:
            inputs = [K.Inp(K.Form("p2wpkh", "fl%d" % j), sighash=h) for j, h in enumerate(hs)]
            rig = self.mkrig(inputs, version=2, modifiable=start)
            res = self.ok(rig)
            got = C.parse(res.psbt).glob.get(b"\x06")
            if want is None:
                self.assertIsNone(got, hs)
            else:
                self.assertEqual(got, want, (hs, start))
        rig = self.mkrig([K.Inp(K.Form("p2tr-key"), sighash=0)], version=2, modifiable=0b11)
        self.assertEqual(C.parse(self.ok(rig).psbt).glob[b"\x06"], b"\x00")     # DEFAULT counts as ALL: clears both flags
        rig = self.mkrig([K.Inp(K.Form("p2wpkh"))], version=0)
        self.assertNotIn(b"\x06", C.parse(self.ok(rig).psbt).glob)

    def test_signer_flag_update_is_not_checked_nor_copied(self):
        """Handling a response: the response's TX_MODIFIABLE is not in the failure list, and the host's result uses its own update."""
        rig = self.mkrig([K.Inp(K.Form("p2wpkh"))], [T.honest, T.tamper(lambda p: p.glob.update({b"\x06": b"\xff"}))], version=2)
        res = self.ok(rig)
        self.assertNotIn(b"\x06", C.parse(res.psbt).glob)


def plain_ecdsa_verify(P, m, r, s):
    z = int.from_bytes(m, "big") % N
    si = pow(s, N - 2, N)
    V = AE._add(AE._mul(z * si % N), AE._mul(r * si % N, P))
    return V is not None and V[0] % N == r


class ChoosingPairs(HostBase):
    def start(self, rig, **kw):
        return rig.host.start(rig.request_bytes, **kw)

    def refuses(self, rig, code):
        with self.assertRaises(H.HostRefusal) as cm:
            rig.host.start(rig.request_bytes)
        self.assertEqual(cm.exception.code, code)
        self.assertEqual(rig.store.data["devices"].get("dev-A", {"open": {}})["open"], {}, "a refused request is not an attempt")
        self.assertEqual(rig.link.calls, 0)

    def test_preexisting_ae_fields(self):
        """Host: "It fails before recording an attempt if its PSBT already holds these fields\""""
        for typ in (0x21, 0x22, 0x23):
            rig = self.mkrig([K.Form("p2wpkh")])
            rig.psbt.inputs[0][bytes([typ]) + b"\x02" + b"\x01" * 32] = b"\x00" * 32
            self.refuses(rig, "preexisting_ae_field")

    def test_ambiguous_or_unsupported(self):
        """Host: "... if any pair is ambiguous or unsupported, or if no pairs remain.\""""
        form = K.Form("p2wsh-2of3")
        pa = K.pub33(form.a)
        form.witness_script = K.multisig(2, [pa, K.pub33(form.b), pa])         # same key twice
        form.spk = b"\x00\x20" + C.sha256(form.witness_script)
        self.refuses(self.mkrig([form]), "key_ambiguous")
        rig = self.mkrig([K.Form("p2sh-single")])
        rig.host.optional_forms = False
        self.refuses(rig, "optional_form_unsupported")
        self.refuses(self.mkrig([K.Inp(K.Form("p2wpkh"), sighash=4)]), "sighash_unsupported")
        form = K.Form("p2wpkh")
        rig = self.mkrig([form], host_keys=[K.pub33(K.seedkey("not ours"))])
        self.refuses(rig, "no_pairs")

    def test_uncompressed_key_in_derivation_record(self):
        """Unsupported: "uncompressed public keys\" fail (not ignored)."""
        form = K.Form("p2pkh")
        rig = self.mkrig([form])
        P = AE._mul(int.from_bytes(form.a, "big"))
        unc = b"\x04" + AE._b32(P[0]) + AE._b32(P[1])
        rig.psbt.inputs[0][b"\x06" + unc] = b"\x00" * 8
        self.refuses(rig, "uncompressed_key")
        # on an input with no pair the host tells the user and goes on: "Inputs with no pair are not otherwise constrained"
        other = K.Form("p2wpkh", label="other")
        rig = self.mkrig([form, other], host_keys=[K.pub33(form.a)], signer_keys=[form.a])
        rig.psbt.inputs[1][b"\x06" + unc] = b"\x00" * 8
        notes = []
        pairs = rig.host.select_pairs(rig.psbt, notes)
        self.assertEqual([p.index for p in pairs], [0])
        self.assertTrue(any("uncompressed" in n for n in notes))

    def test_every_encoding_of_a_device_key_in_a_derivation_record(self):
        """Unsupported: prefixes 0x04, 0x06 and 0x07, either y."""
        form = K.Form("p2wpkh")
        x, y = AE._mul(int.from_bytes(form.a, "big"))
        other_y = (2**256 - 2**32 - 977) - y
        for prefix, yy in ((4, other_y), (6 + (y & 1), y), (6 + (other_y & 1), other_y)):
            rig = self.mkrig([form])
            rig.psbt.inputs[0][b"\x06" + bytes([prefix]) + AE._b32(x) + AE._b32(yy)] = b"\x00" * 8
            self.refuses(rig, "uncompressed_key")
            # only the host's own scan sees an input with no pair, and it tells the user
            other = K.Form("p2wpkh", label="other")
            rig = self.mkrig([form, other], host_keys=[K.pub33(form.a)], signer_keys=[form.a])
            rig.psbt.inputs[1][b"\x06" + bytes([prefix]) + AE._b32(x) + AE._b32(yy)] = b"\x00" * 8
            notes = []
            rig.host.select_pairs(rig.psbt, notes)
            self.assertTrue(any("uncompressed" in n for n in notes), prefix)

    def test_record_with_no_leaf_forms_no_pair_and_is_reported(self):
        """Choosing pairs: a record that lists no leaf and names a device key other than the internal key forms no pair, and the host says so."""
        mine, other = K.Form("p2wpkh"), K.Form("p2tr-key", label="foreign-internal")
        dev = K.Form("p2wpkh", label="device-extra")
        rig = self.mkrig([mine, other], host_keys=[K.pub33(mine.a), K.pub33(dev.a)], signer_keys=[mine.a])
        rig.psbt.inputs[1][b"\x16" + K.xonly(dev.a)] = b"\x00" + b"\x00" * 4
        res = rig.host.start(rig.request_bytes)
        self.assertEqual(len(res.pairs), 1)
        self.assertEqual(res.pairs[0].index, 0)
        self.assertTrue(any("lists no leaf" in n for n in res.notes))

    def test_musig_and_aggregate_fail_not_ignored(self):
        for name in ("p2tr-key", "p2tr-script"):
            form = K.Form(name)
            rig = self.mkrig([form])
            rig.psbt.inputs[0][b"\x1a" + b"\x02" + b"\x33" * 32] = b"\x02" + K.xonly(form.a)
            self.refuses(rig, "musig2_participant")

    def test_key_path_when_device_holds_internal_key(self):
        """Host: "if the device holds the internal key the host chooses the key-path pair and no script-path pair.\""""
        form = K.Form("p2tr-key-root")
        inp = K.Inp(form)
        extra = K.seedkey("p2tr-key-root/f/b")                   # the key in the one leaf, also held
        inp.form.fill(rig_map := {})
        rig = self.mkrig([inp], host_keys=[K.pub33(form.a), K.pub33(extra)], signer_keys=[form.a, extra])
        leaf = S.tap_leaf_hash(0xC0, form.leaf_script)
        sibling_control = bytes([0xC0 | form.parity]) + form.internal
        rig.psbt.inputs[0][b"\x15" + sibling_control] = form.leaf_script + b"\xc0"
        rig.psbt.inputs[0][b"\x16" + K.xonly(extra)] = C.compact(1) + leaf + b"\x00" * 8
        pairs = K.pairs_of(rig)
        self.assertEqual([(p.path, len(p.keyid)) for p in pairs], [("key", 32)])

    def test_two_forms_of_one_xonly_key_make_one_pair(self):
        """Host: "Two forms of one x-only key are one identifier and MUST NOT create two pairs.\""""
        form = K.Form("p2tr-key")
        neg = AE._b32(AE._N - int.from_bytes(form.a, "big"))
        keys = [K.pub33(form.a), K.pub33(neg)]
        self.assertEqual(keys[0][1:], keys[1][1:])
        self.assertNotEqual(keys[0], keys[1])
        rig = self.mkrig([form], host_keys=keys, signer_keys=[form.a, neg])
        self.assertEqual(len(K.pairs_of(rig)), 1)
        res = self.ok(rig)
        self.assertEqual(len(res.signed), 1)

    def test_skip_already_signed_and_tell_user(self):
        """Host: "The host skips a pair whose signature is already in its PSBT and SHOULD tell the user\""""
        form = K.Form("p2wsh-2of3")
        rig = self.mkrig([form])
        rig.psbt.inputs[0][b"\x02" + K.pub33(form.a)] = b"\x30" + b"\x01" * 70
        res = self.ok(rig)
        self.assertEqual([k[1] for k in res.signed], [K.pub33(form.b)])
        self.assertTrue(any("already present" in n for n in rig.ui.notices))
        for name, key in (("p2tr-key", b"\x13"),):
            f = K.Form(name)
            rig = self.mkrig([f])
            rig.psbt.inputs[0][key] = b"\x00" * 64
            self.refuses(rig, "no_pairs")
            self.assertTrue(any("already present" in n for n in rig.ui.notices))

    def test_notices_for_unusable_listed_leaf_and_script_key_without_record(self):
        """Host: "It SHOULD also tell the user about a listed leaf with no script, and a device key found only in a script with no derivation record\""""
        form = K.Form("p2tr-script")
        rig = self.mkrig([form])
        for k in [k for k in rig.psbt.inputs[0] if k[:1] == b"\x15" and rig.psbt.inputs[0][k] == form.leaf_script + b"\xc0"]:
            del rig.psbt.inputs[0][k]
        notes = []
        with self.assertRaises(H.HostRefusal):
            rig.host.select_pairs(rig.psbt, notes)
        self.assertTrue(any("no script" in n for n in notes), notes)
        form = K.Form("p2wsh-2of3")
        rig = self.mkrig([form])
        del rig.psbt.inputs[0][b"\x06" + K.pub33(form.b)]
        notes = []
        pairs = rig.host.select_pairs(rig.psbt, notes)
        self.assertEqual(len(pairs), 1)
        self.assertTrue(any("without a derivation record" in n for n in notes), notes)

    def test_notify_before_first_request(self):
        """Host: "Before sending a request, the host MUST tell the user it is requesting anti-exfil signing.\""""
        rig = self.mkrig([K.Form("p2wpkh")])
        order = []
        rig.ui.notify_request = lambda info: order.append(("notify", rig.link.calls))
        self.ok(rig)
        self.assertEqual(order, [("notify", 0)])

    def test_step3_same_transaction_and_pair_set(self):
        """Second pass: "It MUST have the same transaction and pair set as the first. If either has changed, end the attempt, erase its values, and start over with new rho values.\""""
        form = K.Form("p2wsh-2of3")
        rig = self.mkrig([form])
        a = rig.host.start(rig.request_bytes)
        a.commit()
        changed = rig.psbt.clone()
        tx = C.core_tx(changed)
        changed.glob[b"\x00"] = C.ser_tx(C.Tx(tx.version, tx.ins, [(tx.outs[0][0] - 5,) + tx.outs[0][1:]] + tx.outs[1:], tx.locktime))
        with self.assertRaises(H.AttemptAbandoned) as cm:
            a.reveal(changed.serialize())
        self.assertEqual(cm.exception.code, "request_changed")
        self.assertEqual(a._rho, {})
        self.assertEqual(rig.store.failures("dev-A"), 0)
        calls = rig.link.calls
        self.assertEqual(calls, 1, "rho must not have been sent")
        # pair set changed: a pair's signature appeared in the host PSBT
        rig = self.mkrig([form])
        a = rig.host.start(rig.request_bytes)
        a.commit()
        changed = rig.psbt.clone()
        changed.inputs[0][b"\x02" + K.pub33(form.a)] = b"\x30" + b"\x01" * 70
        with self.assertRaises(H.AttemptAbandoned):
            a.reveal(changed.serialize())
        # starting over draws new rho
        rig.rho_source = None
        b = rig.host.start(rig.request_bytes)
        self.assertNotEqual(sorted(b._rho.values()), sorted(a._rho.values()))

    def test_step3_transaction_change_alone(self):
        """Same sentence, transaction only: with SIGHASH_NONE|ANYONECANPAY the digest ignores the outputs, so
        only the transaction comparison can notice a changed output."""
        rig = self.mkrig([K.Inp(K.Form("p2wpkh"), sighash=0x82)])
        a = rig.host.start(rig.request_bytes)
        a.commit()
        changed = rig.psbt.clone()
        tx = C.core_tx(changed)
        changed.glob[b"\x00"] = C.ser_tx(C.Tx(tx.version, tx.ins, [(tx.outs[0][0] - 5,) + tx.outs[0][1:]] + tx.outs[1:], tx.locktime))
        self.assertEqual([p.message for p in rig.host.select_pairs(changed, [])], [p.message for p in a.pairs])
        with self.assertRaises(H.AttemptAbandoned):
            a.reveal(changed.serialize())

    def test_unchanged_request_proceeds_at_step3(self):
        rig = self.mkrig([K.Form("p2wpkh")])
        a = rig.host.start(rig.request_bytes)
        a.commit()
        self.assertEqual(len(a.reveal(rig.request_bytes).signed), 1)


class RuleFixes(HostBase):
    def test_repeated_leaf_hash_is_one_pair(self):
        """Fields: "A pair is an input index and a full key identifier."; a repeated leaf hash names the same pair."""
        form = K.Form("p2tr-script")
        rig = self.mkrig([form])
        k = b"\x16" + K.xonly(form.a)
        v = rig.psbt.inputs[0][k]
        n, o = C.read_compact(v, 0)
        rig.psbt.inputs[0][k] = C.compact(n + 1) + v[o:o + 32] + v[o:]
        self.assertEqual(len(rig.host.select_pairs(rig.psbt, [])), 1)

    def test_uncompressed_record_of_another_key_is_not_reported(self):
        """Unsupported: "Uncompressed keys that are not device keys are not examined."""
        form = K.Form("p2wpkh")
        rig = self.mkrig([form])
        other = K.Form("p2wpkh", label="other")
        x, y = AE._mul(int.from_bytes(other.a, "big"))
        rig.psbt.inputs[0][b"\x06" + b"\x04" + AE._b32(x) + AE._b32(y)] = b"\x00" * 8
        notes = []
        self.assertEqual(len(rig.host.select_pairs(rig.psbt, notes)), 1)
        self.assertFalse(any("uncompressed" in n for n in notes))

    def test_bad_utxo_on_an_input_with_no_pair_is_a_refusal(self):
        """A party may fail on an unverifiable fee; on the host that is a refusal with nothing recorded, not a raw error."""
        form, other = K.Form("p2wpkh"), K.Form("p2wpkh", label="other")
        rig = self.mkrig([form, other], host_keys=[K.pub33(form.a)], signer_keys=[form.a])
        rig.psbt.inputs[1][b"\x00"] = b"\x01\x02"
        with self.assertRaises(H.HostRefusal):
            rig.host.start(rig.request_bytes)
        self.assertEqual(rig.store.failures(rig.wallet.device_id), 0)

    def test_malformed_modifiable_flags_refused_before_any_request(self):
        """A one-byte field by BIP 370; the host's own PSBT must not get as far as an attempt."""
        form = K.Form("p2wpkh")
        rig = self.mkrig([form], version=2)
        rig.psbt.glob[b"\x06"] = b"\x00\x00"
        with self.assertRaises(H.HostRefusal):
            rig.host.start(rig.request_bytes)
        self.assertEqual(rig.link.calls, 0)


class RuleGaps(HostBase):
    """Tests added for survivors of the requirement mutants classed test_gap."""

    def test_reveal_before_commit_sends_nothing(self):
        """Step 3: "The host MUST NOT send `rho` until it has received `R0_bytes`, checked that `parse33` accepts it, and stored it.\""""
        rig = self.mkrig([K.Form("p2wpkh")])
        a = rig.host.start(rig.request_bytes)
        with self.assertRaises(RuntimeError):
            a.reveal()
        self.assertEqual(rig.link.transcript, [])

    def test_identity_ignores_what_the_link_reports(self):
        """Attempts: "A device is identified by the keys or fingerprint in the host's own wallet data, never by an identifier the device reports.\""""
        import json

        class Reporting(T.InProcessLink):
            device_id = "claimed-by-the-device"
        rig = K.Rig([K.Inp(K.Form("p2wpkh"))], self.tmp, link_cls=Reporting)
        rig.host.sign(rig.request_bytes)
        self.assertEqual(list(json.load(open(rig.store_path))["devices"]), ["dev-A"])

    def test_key_in_two_leaves_forms_two_pairs(self):
        """Fields: "a key used in two leaves forms two pairs.\""""
        f = K.Form("p2tr-script")
        xa = K.xonly(f.a)
        f.sibling = K.push(xa) + b"\xad" + b"\x51"
        sh = S.tap_leaf_hash(0xC0, f.sibling)
        f.root = S.tagged("TapBranch", min(f.leaf_hash, sh) + max(f.leaf_hash, sh))
        _, q, par = S.tweaked_xonly(f.internal, f.root)
        f.control = bytes([0xC0 | par]) + f.internal + sh
        f.spk = b"\x51\x20" + q
        rig = self.mkrig([f])
        old = rig.psbt.inputs[0][b"\x16" + xa]
        rig.psbt.inputs[0][b"\x16" + xa] = C.compact(2) + f.leaf_hash + sh + old[33:]
        pairs = rig.host.select_pairs(rig.psbt, [])
        self.assertEqual(sorted(pr.keyid for pr in pairs), sorted([xa + f.leaf_hash, xa + sh]))
        self.assertEqual(len(rig.host.sign(rig.request_bytes).signed), 2)

    def test_uncompressed_record_for_a_non_device_key_is_not_examined(self):
        """Unsupported: "Uncompressed keys that are not device keys are not examined.\""""
        rig = self.mkrig([K.Form("p2wpkh")])
        P = AE._mul(int.from_bytes(K.seedkey("not a device key"), "big"))
        rig.psbt.inputs[0][b"\x06\x04" + AE._b32(P[0]) + AE._b32(P[1])] = b"\x00" * 8
        self.assertEqual(len(rig.host.select_pairs(rig.psbt, [])), 1)


class EdgeCases(HostBase):
    """Host notices for device keys found only in a script, and malformed TAP_BIP32_DERIVATION values."""
    NOTICE = "input 0: device key in script without a derivation record"

    def test_script_key_notice_only_for_a_device_key_without_a_record(self):
        """Host: "a device key found only in a script with no derivation record\""""
        form = K.Form("p2wsh-2of3")
        # a device key with no record: exactly one notice
        rig = self.mkrig([form])
        del rig.psbt.inputs[0][b"\x06" + K.pub33(form.b)]
        notes = []
        self.assertEqual(len(rig.host.select_pairs(rig.psbt, notes)), 1)
        self.assertEqual(notes, [self.NOTICE])
        # cosigner keys in the same script, and a device key that has its record: no notice
        rig = self.mkrig([form], host_keys=[K.pub33(form.a)], signer_keys=[form.a])
        notes = []
        self.assertEqual(len(rig.host.select_pairs(rig.psbt, notes)), 1)
        self.assertEqual(notes, [])
        # every device key has a record
        rig = self.mkrig([form])
        notes = []
        self.assertEqual(len(rig.host.select_pairs(rig.psbt, notes)), 2)
        self.assertEqual(notes, [])
        # the notice reaches the user before the attempt
        rig = self.mkrig([form])
        del rig.psbt.inputs[0][b"\x06" + K.pub33(form.b)]
        rig.host.start(rig.request_bytes).abandon()
        self.assertEqual(rig.ui.notices, [self.NOTICE])

    def test_listed_leaf_whose_script_is_empty_or_absent(self):
        """Fields: the host tells the user about "a listed leaf with no script". A TAP_LEAF_SCRIPT entry whose value is only the leaf
        version byte is an entry with an empty script: it matches the leaf hash of that empty script and goes on to the pair checks.
        An entry with an empty value is no entry and matches nothing, so the leaf is listed with no script."""
        def empty_script_form():
            form = K.Form("p2tr-script")
            form.leaf_script = b""
            form.leaf_hash = S.tap_leaf_hash(0xC0, b"")
            sh = S.tap_leaf_hash(0xC0, form.sibling)
            form.root = S.tagged("TapBranch", min(form.leaf_hash, sh) + max(form.leaf_hash, sh))
            _, q, par = S.tweaked_xonly(form.internal, form.root)
            form.control = bytes([0xC0 | par]) + form.internal + sh
            form.spk = b"\x51\x20" + q
            return form
        form = empty_script_form()
        rig = self.mkrig([form])
        with self.assertRaises(H.HostRefusal) as cm:
            rig.host.select_pairs(rig.psbt, [])
        self.assertEqual(cm.exception.code, "tap_mapping")        # the entry was found, and the empty script does not contain the key
        listed = "input 0: leaf %s listed with no script" % form.leaf_hash.hex()
        rig = self.mkrig([form])
        rig.psbt.inputs[0][b"\x15" + form.control] = b""
        notes = []
        with self.assertRaises(H.HostRefusal) as cm:
            rig.host.select_pairs(rig.psbt, notes)
        self.assertEqual(cm.exception.code, "no_pairs")
        self.assertEqual(notes, [listed])

    def test_bad_tap_derivation_value_is_refused(self):
        """Fields: a TAP_BIP32_DERIVATION value is a CompactSize count of leaf hashes, the hashes, then the fingerprint and path."""
        form = K.Form("p2tr-script")
        key = b"\x16" + K.xonly(form.a)
        leaf = form.leaf_hash
        bad = {
            "empty": b"",
            "truncated two-byte count": b"\xfd\x01",
            "truncated four-byte count": b"\xfe\x01\x00",
            "four leaf hashes and nothing after": C.compact(4) + leaf * 4,
            "one leaf hash and nothing after": C.compact(1) + leaf,
            "one leaf hash and a short fingerprint": C.compact(1) + leaf + b"\x00" * 3,
            "path not a multiple of four": C.compact(1) + leaf + b"\x00" * 5,
        }
        for name, value in bad.items():
            rig = self.mkrig([form])
            rig.psbt.inputs[0][key] = value
            with self.assertRaises(H.HostRefusal) as cm:
                rig.host.start(rig.request_bytes)
            self.assertEqual(cm.exception.code, "bad_tap_derivation", name)
            self.assertEqual(rig.store.data["devices"].get("dev-A", {"open": {}})["open"], {}, name)
            self.assertEqual(rig.link.calls, 0)
        rig = self.mkrig([form])
        rig.psbt.inputs[0][key] = C.compact(1) + leaf + b"\x00" * 4
        self.assertEqual(len(rig.host.select_pairs(rig.psbt, [])), 1)


if __name__ == "__main__":
    unittest.main()
