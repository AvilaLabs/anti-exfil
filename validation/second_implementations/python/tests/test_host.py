import json
import os
import shutil
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import indep as I
import tb

EOF_ = object()
FORMS = ["p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2wsh-single", "p2wsh-multi", "p2sh-p2wsh-single",
         "p2sh-p2wsh-multi", "p2sh-single", "p2sh-multi", "tr-key", "tr-script"]


def der_flip_s(sig):
    d = sig[:-1]
    lr = d[3]
    r = int.from_bytes(d[4:4 + lr], "big")
    ls = d[5 + lr]
    s = int.from_bytes(d[6 + lr:6 + lr + ls], "big")
    return I.der(r, I.n - s) + sig[-1:]


class HostCase(unittest.TestCase):
    def setUp(self):
        self.store = os.path.join(tb.SCRATCH, "%s.json" % self.id().split(".")[-1])
        for p in (self.store, self.store + ".tmp"):
            if os.path.exists(p):
                os.remove(p)

    def load_store(self):
        with open(self.store) as f:
            return json.load(f)

    def pubs(self, c):
        return [tb.pub(k) for k in c.dev_sks]

    def device(self, c, on1=None, on2=None, sks=None):
        """Honest in-process device with optional hooks that edit the response maps."""
        honest = tb.inproc_device(sks if sks is not None else c.dev_sks)
        calls = {1: 0, 2: 0}
        self.seen = {"r0": {}, "responses": []}

        def dev(req, k):
            resp = honest(req, k)
            if resp == "ERROR":
                return resp
            maps = I.read_psbt(bytes.fromhex(resp))
            req_maps = I.read_psbt(bytes.fromhex(req))
            phase = 2 if any(kk[0] == 0x23 for m in req_maps[1:] for kk, _ in m) else 1
            if phase == 1:
                for p in c.pairs:
                    self.seen["r0"][(p["i"], p["keyid"])] = tb.r0_of(resp, p)
            hook = on1 if phase == 1 else on2
            n = calls[phase]
            calls[phase] += 1
            if hook is None:
                return resp
            out = hook(maps, n)
            if out is EOF_:
                return None
            if isinstance(out, str):
                return out
            return I.write_psbt(maps if out is None else out).hex()
        return dev

    def go(self, c, dev=None, retries=0, ack=False, salt=b"", **kw):
        return tb.run_host(c, self.pubs(c), self.store, device=dev if dev is not None else self.device(c),
                           max_retries=retries, rhos=tb.rho_args(c, salt), ack=ack, **kw)

    def ok(self, r, count=0):
        self.assertEqual(r.rc, 0, r.stderr)
        self.assertEqual(r.count, count)
        self.assertTrue(r.status.startswith("RESULT "))

    def failed(self, r, count=1):
        self.assertEqual(r.status, "FAILED", r.stderr)
        self.assertEqual(r.rc, 3)
        self.assertEqual(r.count, count)


class TestHappyPaths(HostCase):
    def test_every_form_both_versions(self):
        for v in (0, 2):
            for form in FORMS:
                if os.path.exists(self.store):
                    os.remove(self.store)
                c = tb.make([{"form": form}], version=v)
                r = self.go(c)
                self.ok(r)
                tb.check_result(c, r.result)
                self.assertEqual(len(r.requests), 2)

    def test_all_forms_in_one_psbt(self):
        c = tb.make([{"form": f, "key": i % 3} for i, f in enumerate(FORMS)], version=2)
        r = self.go(c)
        self.ok(r)
        tb.check_result(c, r.result)

    def test_with_real_signer_subprocess(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "tr-script", "key": 1}], version=0)
        r = tb.run_host(c, self.pubs(c), self.store, device=tb.honest_device(c.dev_sks),
                        rhos=tb.rho_args(c))
        self.ok(r)
        tb.check_result(c, r.result)

    def test_request_contents(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "tr-key", "key": 1}, {"form": "p2wpkh", "key": 2}])
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        c.pairs = c.pairs[:2]       # input 2 belongs to another device key: no derivation for ours
        del c.imaps[2][b"\x06" + tb.pub(tb.DEV[2])]
        r = self.go(c)
        self.ok(r)
        base = I.read_psbt(bytes.fromhex(tb.psbt_hex(c)))
        r1 = I.read_psbt(bytes.fromhex(r.requests[0]))
        r2 = I.read_psbt(bytes.fromhex(r.requests[1]))
        for p in c.pairs:
            rho = tb.rho_for(p["i"], p["keyid"])
            self.assertEqual(dict(r1[1 + p["i"]])[b"\x21" + p["keyid"]], tb.hc_of(p, rho))
            self.assertEqual(dict(r2[1 + p["i"]])[b"\x23" + p["keyid"]], rho)
        for rq, forbidden in ((r1, (0x22, 0x23)), (r2, (0x21, 0x22))):
            for m in rq[1:]:
                self.assertFalse(any(k[0] in forbidden for k, _ in m))
        # nothing else differs from the host's own PSBT
        for rq in (r1, r2):
            self.assertEqual(rq[0], base[0])
            self.assertEqual(rq[-1], base[-1])
            for a, b in zip(rq[1:], base[1:]):
                self.assertEqual([kv for kv in a if kv[0][0] not in (0x21, 0x23)], b)
        # input 2 untouched
        self.assertFalse(any(k[0] in (0x21, 0x23) for k, _ in r1[3]))

    def test_result_is_host_psbt_plus_verified_signatures(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "p2wsh-multi", "key": 1}])
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        c.imaps[0][b"\xfc\x04keep"] = b"mine"

        def junk(maps, n):
            for m in maps[1:3]:
                m.append((b"\xfc\x05junk1", b"device-chosen"))
            maps[0].append((b"\xfc\x05junk2", b"x"))
            return maps
        r = self.go(c, self.device(c, on1=junk, on2=junk))
        self.ok(r)
        res = I.read_psbt(bytes.fromhex(r.result))
        base = I.read_psbt(bytes.fromhex(tb.psbt_hex(c)))
        self.assertEqual(res[0], base[0])
        for i, p in enumerate(c.pairs):
            extra = [kv for kv in res[1 + i] if kv not in base[1 + i]]
            self.assertEqual([k for k, _ in extra], [p["sigkey"]])
        self.assertEqual(res[3:], base[3:])
        tb.check_result(c, r.result)

    def test_signature_nonce_follows_first_pass_commitment(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "tr-script", "key": 1}])
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        r = self.go(c)
        self.ok(r)
        maps = I.read_psbt(bytes.fromhex(r.result))
        for p in c.pairs:
            R0 = self.seen["r0"][(p["i"], p["keyid"])]
            R0pt = I.lift(int.from_bytes(R0[1:], "big"))
            if R0[0] == 3:
                R0pt = I.neg(R0pt)
            rho = tb.rho_for(p["i"], p["keyid"])
            tag = "s2c/schnorr/point" if p["scheme"] == "bip340" else "s2c/ecdsa/point"
            t = int.from_bytes(I.TH(tag, R0 + rho), "big")
            W = I.add(R0pt, I.mul(t))
            sig = dict(maps[1 + p["i"]])[p["sigkey"]]
            if p["scheme"] == "bip340":
                self.assertEqual(sig[:32], W[0].to_bytes(32, "big"))

    def test_tx_modifiable_updated_in_result(self):
        c = tb.make([{"form": "p2wpkh", "ht": 0x83}, {"form": "tr-key", "ht": 2, "key": 1}], version=2,
                    outs=[(1000, b"\x6a"), (1000, b"\x6a")])
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        c.gmap[b"\x06"] = b"\xf3"
        r = self.go(c)
        self.ok(r)
        res = I.read_psbt(bytes.fromhex(r.result))
        # SINGLE|ACP: clears outputs, sets bit 2; NONE: clears inputs
        self.assertEqual(dict(res[0])[b"\x06"], bytes([0xF3 & ~1 & ~2 | 4]))
        # absent field is created when a set flag must be recorded
        c.gmap.pop(b"\x06")
        os.remove(self.store)
        r = self.go(c)
        res = I.read_psbt(bytes.fromhex(r.result))
        self.assertEqual(dict(res[0])[b"\x06"], b"\x04")

    def test_response_reordering_and_extras_are_ignored(self):
        c = tb.make([{"form": "p2wpkh"}])

        def shuffle(maps, n):
            return [list(reversed(m)) for m in maps] + [] if False else [list(reversed(m)) for m in maps]
        r = self.go(c, self.device(c, on1=shuffle, on2=shuffle))
        self.ok(r)

    def test_response_can_drop_signatures_of_finalized_input_only(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "p2wpkh", "key": 1}])
        c.pairs = c.pairs[:1]
        other = tb.pub(tb.OTHER[0])
        c.imaps[1][b"\x02" + other] = b"\x30" + bytes(70)
        c.imaps[1].pop(b"\x06" + tb.pub(tb.DEV[1]))
        c.imaps[1][b"\x07"] = b"\x00"       # finalized input

        def drop(maps, n):
            maps[2][:] = [kv for kv in maps[2] if kv[0][0] != 2]
            return maps
        r = self.go(c, self.device(c, on1=drop, on2=drop))
        self.ok(r)
        # same drop from a non-final input fails
        os.remove(self.store)
        del c.imaps[1][b"\x07"]
        r = self.go(c, self.device(c, on1=drop, on2=drop))
        self.failed(r)


class TestResponseChecks(HostCase):
    def setUp(self):
        HostCase.setUp(self)
        self.c = tb.make([{"form": "p2wpkh"}, {"form": "tr-key", "key": 1}])
        self.c.dev_sks = [tb.DEV[0], tb.DEV[1]]

    def fails_with(self, on1=None, on2=None, c=None, retries=0, count=1):
        c = c or self.c
        if os.path.exists(self.store):
            os.remove(self.store)
        r = self.go(c, self.device(c, on1=on1, on2=on2), retries=retries)
        self.failed(r, count)
        return r

    def test_pass1_problems(self):
        k0 = self.c.pairs[0]
        def nc_key(p): return b"\x22" + p["keyid"]
        def drop_nc(maps, n): maps[1][:] = [kv for kv in maps[1] if kv[0] != nc_key(k0)]
        def bad_nc(maps, n): maps[1][:] = [(k, (b"\x05" + v[1:] if k == nc_key(k0) else v)) for k, v in maps[1]]
        def short_nc(maps, n): maps[1][:] = [(k, (v[:32] if k == nc_key(k0) else v)) for k, v in maps[1]]
        def bad_hc(maps, n): maps[1][:] = [(k, (bytes(32) if k[0] == 0x21 else v)) for k, v in maps[1]]
        def change_tx(maps, n):
            tx = bytearray(dict(maps[0])[b"\x00"])
            tx[-10] ^= 1
            maps[0][:] = [(k, bytes(tx) if k == b"\x00" else v) for k, v in maps[0]]
        def add_sig(maps, n): maps[1].append((k0["sigkey"], bytes(70)))
        def add_rho(maps, n): maps[1].append((b"\x23" + k0["keyid"], bytes(32)))
        def unrequested(maps, n): maps[1].append((b"\x22" + tb.pub(tb.OTHER[3]), I.comp(I.mul(5))))
        def unrequested_hc(maps, n): maps[1].append((b"\x21" + bytes(32), bytes(32)))
        def other_input_sig(maps, n): maps[2].append((b"\x13", bytes(64)))
        for name, hook in (("drop_nc", drop_nc), ("bad_nc", bad_nc), ("short_nc", short_nc), ("bad_hc", bad_hc),
                           ("change_tx", change_tx), ("add_sig", add_sig), ("add_rho", add_rho),
                           ("unrequested", unrequested), ("unrequested_hc", unrequested_hc),
                           ("other_input_sig", other_input_sig)):
            with self.subTest(name):
                self.fails_with(on1=hook)

    def test_ordinary_signature_or_unknown_fields_fail(self):
        # a device that ignores the fields and signs normally: no nonce commitment
        def strip_ae(maps, n):
            for m in maps[1:3]:
                m[:] = [kv for kv in m if kv[0][0] not in (0x21, 0x22)]
        self.fails_with(on1=strip_ae)
        self.fails_with(on1=lambda maps, n: "70736274ff00")      # garbage
        self.fails_with(on1=lambda maps, n: "not hex")
        self.fails_with(on1=lambda maps, n: EOF_)

    def test_pass2_problems(self):
        p0, p1 = self.c.pairs
        def keep_rho(maps, n): maps[1].append((b"\x23" + p0["keyid"], bytes(32)))
        def keep_hc(maps, n): maps[1].append((b"\x21" + p0["keyid"], bytes(32)))
        def keep_nc(maps, n): maps[1].append((b"\x22" + p0["keyid"], self.seen["r0"][(0, p0["keyid"])]))
        def missing_sig0(maps, n): maps[1][:] = [kv for kv in maps[1] if kv[0] != p0["sigkey"]]
        def missing_sig1(maps, n): maps[2][:] = [kv for kv in maps[2] if kv[0] != p1["sigkey"]]
        def tamper_ecdsa(maps, n):
            maps[1][:] = [(k, (v[:10] + bytes([v[10] ^ 1]) + v[11:] if k == p0["sigkey"] else v)) for k, v in maps[1]]
        def tamper_schnorr(maps, n):
            maps[2][:] = [(k, (v[:40] + bytes([v[40] ^ 1]) + v[41:] if k == p1["sigkey"] else v)) for k, v in maps[2]]
        def high_s(maps, n):
            maps[1][:] = [(k, (der_flip_s(v) if k == p0["sigkey"] else v)) for k, v in maps[1]]
        def wrong_ht(maps, n):
            maps[1][:] = [(k, (v[:-1] + b"\x02" if k == p0["sigkey"] else v)) for k, v in maps[1]]
        def schnorr_with_ht_byte(maps, n):
            maps[2][:] = [(k, (v + b"\x01" if k == p1["sigkey"] else v)) for k, v in maps[2]]
        def schnorr_short(maps, n):
            maps[2][:] = [(k, (v[:63] if k == p1["sigkey"] else v)) for k, v in maps[2]]
        def not_strict_der(maps, n):
            def pad(v):
                d = v[:-1]
                return b"\x30" + bytes([d[1] + 1]) + d[2:4] + b"\x00" + d[4:] + v[-1:]
            maps[1][:] = [(k, (pad(v) if k == p0["sigkey"] else v)) for k, v in maps[1]]
        def swap_sigs(maps, n):
            a = dict(maps[1])[p0["sigkey"]]
            b = dict(maps[2])[p1["sigkey"]]
            maps[1][:] = [(k, (b if k == p0["sigkey"] else v)) for k, v in maps[1]]
            maps[2][:] = [(k, (a if k == p1["sigkey"] else v)) for k, v in maps[2]]
        def change_tx(maps, n):
            tx = bytearray(dict(maps[0])[b"\x00"])
            tx[-6] ^= 1
            maps[0][:] = [(k, bytes(tx) if k == b"\x00" else v) for k, v in maps[0]]
        def extra_sig_for_unrequested(maps, n): maps[1].append((b"\x02" + tb.pub(tb.OTHER[0]), bytes(70)))
        def changed_other_sig(maps, n): pass
        for name, hook in (("keep_rho", keep_rho), ("keep_hc", keep_hc), ("keep_nc", keep_nc),
                           ("missing_sig0", missing_sig0), ("missing_sig1", missing_sig1),
                           ("tamper_ecdsa", tamper_ecdsa), ("tamper_schnorr", tamper_schnorr),
                           ("high_s", high_s), ("wrong_ht", wrong_ht),
                           ("schnorr_with_ht_byte", schnorr_with_ht_byte), ("schnorr_short", schnorr_short),
                           ("not_strict_der", not_strict_der), ("swap_sigs", swap_sigs),
                           ("change_tx", change_tx), ("extra_sig_for_unrequested", extra_sig_for_unrequested)):
            with self.subTest(name):
                self.fails_with(on2=hook)

    def test_one_bad_signature_rejects_all(self):
        # second signature is bad: the host must not output anything built from the first
        p0, p1 = self.c.pairs
        def tamper_schnorr(maps, n):
            maps[2][:] = [(k, (v[:40] + bytes([v[40] ^ 1]) + v[41:] if k == p1["sigkey"] else v)) for k, v in maps[2]]
        r = self.fails_with(on2=tamper_schnorr)
        self.assertFalse(any(l.startswith("RESULT") for l in r.lines))

    def test_sighash_byte_must_be_expected_ecdsa_and_taproot(self):
        c = tb.make([{"form": "p2wpkh", "ht": 0x81}, {"form": "tr-key", "ht": 3, "key": 1}],
                    outs=[(1000, b"\x6a"), (1000, b"\x6a")])
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        r = self.go(c)
        self.ok(r)
        tb.check_result(c, r.result)
        p0, p1 = c.pairs
        def wrong0(maps, n): maps[1][:] = [(k, (v[:-1] + b"\x01" if k == p0["sigkey"] else v)) for k, v in maps[1]]
        def wrong1(maps, n): maps[2][:] = [(k, (v[:-1] + b"\x01" if k == p1["sigkey"] else v)) for k, v in maps[2]]
        for h in (wrong0, wrong1):
            os.remove(self.store)
            self.failed(self.go(c, self.device(c, on2=h)))

    def test_signature_fields_in_request_cannot_change(self):
        c = tb.make([{"form": "p2wsh-multi"}])
        other = tb.pub(tb.OTHER[0])
        sigv = b"\x30" + bytes(70)
        c.imaps[0][b"\x02" + other] = sigv
        r = self.go(c)
        self.ok(r)
        maps = I.read_psbt(bytes.fromhex(r.result))
        self.assertEqual(dict(maps[1])[b"\x02" + other], sigv)
        def change(maps, n): maps[1][:] = [(k, (bytes(71) if k == b"\x02" + other else v)) for k, v in maps[1]]
        def remove(maps, n): maps[1][:] = [kv for kv in maps[1] if kv[0] != b"\x02" + other]
        for h in (change, remove):
            for kw in ({"on1": h}, {"on2": h}):
                if os.path.exists(self.store):
                    os.remove(self.store)
                self.failed(self.go(c, self.device(c, **kw)))


class TestRetriesAndCounts(HostCase):
    def setUp(self):
        HostCase.setUp(self)
        self.c = tb.make([{"form": "p2wpkh"}])

    def err_then_ok(self, c, bad_calls, phase_marker):
        honest = tb.inproc_device(c.dev_sks)
        state = {"n": 0}
        def dev(req, k):
            bad = state["n"] in bad_calls
            state["n"] += 1
            return "ERROR" if bad else honest(req, k)
        return dev

    def test_error_without_retries(self):
        r = self.go(self.c, self.err_then_ok(self.c, {0}, 1), retries=0)
        self.failed(r)
        self.assertEqual(len(r.requests), 1)

    def test_error_then_success_with_retry_counts_once(self):
        r = self.go(self.c, self.err_then_ok(self.c, {0}, 1), retries=1)
        self.ok(r, count=1)
        self.assertEqual(len(r.requests), 3)
        self.assertEqual(r.requests[0], r.requests[1])         # same step-1 request repeated

    def test_pass2_retry_repeats_same_rho(self):
        r = self.go(self.c, self.err_then_ok(self.c, {1}, 2), retries=1)
        self.ok(r, count=1)
        self.assertEqual(len(r.requests), 3)
        self.assertEqual(r.requests[1], r.requests[2])
        tb.check_result(self.c, r.result)

    def test_many_failure_events_count_once(self):
        r = self.go(self.c, self.err_then_ok(self.c, {0, 1, 2}, 1), retries=3)
        self.ok(r, count=1)
        self.assertEqual(len(r.requests), 5)

    def test_retries_run_out(self):
        r = self.go(self.c, lambda req, k: "ERROR", retries=2)
        self.failed(r)
        self.assertEqual(len(r.requests), 3)

    def test_retry_limit_is_per_step(self):
        # two errors in step 1 and two in step 2 with retries=2 still succeeds
        r = self.go(self.c, self.err_then_ok(self.c, {0, 1, 3, 4}, 1), retries=2)
        self.ok(r, count=1)
        self.assertEqual(len(r.requests), 6)

    def test_closed_channel_fails_without_retry_spin(self):
        r = self.go(self.c, lambda req, k: None, retries=5)
        self.failed(r)

    def test_changed_r0_ends_attempt_even_with_retries(self):
        c = self.c
        p = c.pairs[0]
        # a rejected response carries R0, then a retry shows a different R0
        def err_then_change(maps, n):
            if n == 1:
                maps[1][:] = [(k, (I.comp(I.mul(77)) if k[0] == 0x22 else v)) for k, v in maps[1]]
        def hook(maps, n):
            if n == 0:
                maps[1].append((b"\x23" + p["keyid"], bytes(32)))    # rejected response carrying R0
            else:
                err_then_change(maps, 1)
        r = self.go(c, self.device(c, on1=hook), retries=3)
        self.failed(r)
        self.assertEqual(len(r.requests), 2)

    def test_changed_r0_in_pass2_response(self):
        c = self.c
        p = c.pairs[0]
        def add_changed(maps, n): maps[1].append((b"\x22" + p["keyid"], I.comp(I.mul(77))))
        r = self.go(c, self.device(c, on2=add_changed), retries=3)
        self.failed(r)
        self.assertEqual(len(r.requests), 2)

    def test_changed_r0_after_unparsable_first_value(self):
        c = self.c
        p = c.pairs[0]
        def hook(maps, n):
            if n == 0:
                maps[1][:] = [(k, (b"\x05" + v[1:] if k[0] == 0x22 else v)) for k, v in maps[1]]
        r = self.go(c, self.device(c, on1=hook), retries=3)
        self.failed(r)
        self.assertEqual(len(r.requests), 2)

    def test_same_r0_on_retry_is_fine(self):
        c = self.c
        def hook(maps, n):
            if n == 0:
                return "ERROR"
        r = self.go(c, self.device(c, on1=hook), retries=1)
        self.ok(r, count=1)

    def test_count_persists_and_needs_acknowledgement(self):
        c = self.c
        r = self.go(c, lambda req, k: "ERROR")
        self.failed(r, 1)
        r = self.go(c)
        self.assertEqual(r.status, "NOT_ACKNOWLEDGED")
        self.assertEqual(r.rc, 5)
        self.assertEqual(r.count, 1)
        self.assertEqual(r.requests, [])
        r = self.go(c, ack=True)
        self.ok(r, count=1)
        # the acknowledgement was used: no warning owed after a successful attempt
        r = self.go(c)
        self.ok(r, count=1)

    def test_ack_is_used_up_by_one_attempt(self):
        c = self.c
        self.failed(self.go(c, lambda req, k: "ERROR"), 1)
        self.failed(self.go(c, lambda req, k: "ERROR", ack=True), 2)
        r = self.go(c, ack=False)
        self.assertEqual(r.status, "NOT_ACKNOWLEDGED")
        self.assertEqual(r.count, 2)
        self.ok(self.go(c, ack=True), 2)

    def test_ack_without_warning_does_nothing(self):
        r = self.go(self.c, ack=True)
        self.ok(r, 0)

    def test_failure_with_later_success_still_counts(self):
        r = self.go(self.c, self.err_then_ok(self.c, {0}, 1), retries=1)
        self.ok(r, 1)
        r = self.go(self.c)
        self.assertEqual(r.status, "NOT_ACKNOWLEDGED")

    def test_restart_with_open_attempt_counts_as_failed(self):
        c = self.c
        r = tb.run_host(c, self.pubs(c), self.store, device=self.device(c), max_retries=0,
                        rhos=tb.rho_args(c), kill_after_requests=1)
        self.assertEqual(len(r.requests), 1)
        data = self.load_store()
        self.assertIsNotNone(list(data["devices"].values())[0]["open"])
        r = self.go(c)
        self.assertEqual(r.status, "NOT_ACKNOWLEDGED")
        self.assertEqual(r.count, 1)
        r = self.go(c, ack=True)
        self.ok(r, 1)

    def test_restart_after_counted_failure_is_not_counted_twice(self):
        c = self.c
        honest = tb.inproc_device(c.dev_sks)
        def dev(req, k):
            return "ERROR" if k == 0 else honest(req, k)
        r = tb.run_host(c, self.pubs(c), self.store, device=dev, max_retries=1, rhos=tb.rho_args(c),
                        kill_after_requests=2)
        data = self.load_store()
        rec = list(data["devices"].values())[0]
        self.assertEqual(rec["count"], 1)
        self.assertTrue(rec["open"]["counted"])
        r = self.go(c, ack=True)
        self.ok(r, 1)

    def test_attempt_recorded_before_first_request(self):
        c = self.c
        seen = {}
        def dev(req, k):
            seen["data"] = self.load_store()
            return "ERROR"
        self.go(c, dev)
        rec = list(seen["data"]["devices"].values())[0]
        self.assertEqual(rec["open"], {"counted": False})

    def test_unreadable_store_counts_one(self):
        with open(self.store, "w") as f:
            f.write("{not json")
        r = self.go(self.c)
        self.assertEqual(r.status, "NOT_ACKNOWLEDGED")
        self.assertEqual(r.count, 1)
        r = self.go(self.c, ack=True)
        self.ok(r, 1)

    def test_store_as_directory_is_unreadable_and_unwritable(self):
        os.makedirs(self.store, exist_ok=True)
        try:
            r = self.go(self.c, ack=True)
            self.assertEqual(r.status, "REFUSED")
            self.assertEqual(r.rc, 4)
            self.assertEqual(r.requests, [])
            self.assertEqual(r.count, 1)
        finally:
            shutil.rmtree(self.store)

    def test_cannot_write_store_refuses(self):
        blocker = os.path.join(tb.SCRATCH, "blocker_file")
        with open(blocker, "w") as f:
            f.write("x")
        self.store = os.path.join(blocker, "sub", "store.json")
        r = self.go(self.c)
        self.assertEqual(r.status, "REFUSED")
        self.assertEqual(r.requests, [])

    def test_wrong_shape_store_records(self):
        for content in ('[]', '{"devices": []}', '{"devices": 5}'):
            with open(self.store, "w") as f:
                f.write(content)
            r = self.go(self.c)
            self.assertEqual(r.status, "NOT_ACKNOWLEDGED", content)
        # a parseable store without this device is a new device
        with open(self.store, "w") as f:
            f.write('{"devices": {"other": {"count": 5, "acked": 0, "open": null}}}')
        self.ok(self.go(self.c), 0)

    def test_devices_have_separate_counts(self):
        c = self.c
        self.failed(self.go(c, lambda req, k: "ERROR"), 1)
        c2 = tb.make([{"form": "p2wpkh", "key": 1}])
        self.ok(self.go(c2), 0)

    def test_refusal_and_missing_rho_do_not_count(self):
        c = self.c
        c.imaps[0][b"\x21" + c.pairs[0]["keyid"]] = bytes(32)
        r = self.go(c)
        self.assertEqual(r.status, "REFUSED")
        self.assertEqual(r.count, 0)
        self.assertFalse(os.path.exists(self.store))

    def test_reset_count_command(self):
        import subprocess
        c = self.c
        self.failed(self.go(c, lambda req, k: "ERROR"), 1)
        out = subprocess.run([sys.executable, "-B", tb.MAIN, "reset-count", "--store", self.store,
                              "--device-key", self.pubs(c)[0].hex()], capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "COUNT 0")
        self.ok(self.go(c), 0)


class TestRefusals(HostCase):
    def refused(self, c, mutate=None, device_keys=None, **kw):
        c = tb.clone(c)
        if mutate:
            mutate(c)
        r = tb.run_host(c, device_keys or self.pubs(c), self.store, device=self.device(c),
                        rhos=tb.rho_args(c), **kw)
        self.assertEqual(r.status, "REFUSED", r.stderr)
        self.assertEqual(r.rc, 4)
        self.assertEqual(r.requests, [])
        self.assertEqual(r.count, 0)
        self.assertFalse(os.path.exists(self.store))
        return r

    def test_existing_ae_fields(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "p2wpkh", "key": 1}])
        c.dev_sks = [tb.DEV[0]]
        for t in (0x21, 0x22, 0x23):
            self.refused(c, lambda c, t=t: c.imaps[1].__setitem__(bytes([t]) + bytes(33), bytes(32)))

    def test_no_pairs(self):
        c = tb.make([{"form": "p2wpkh"}])
        self.refused(c, lambda c: c.imaps[0].pop(b"\x06" + tb.pub(tb.DEV[0])))
        self.refused(c, device_keys=[tb.pub(tb.DEV[1])])
        c = tb.make([{"form": "tr-key"}])
        self.refused(c, lambda c: (c.imaps[0].pop(b"\x17"), c.imaps[0].pop(b"\x16" + tb.xonly(tb.DEV[0]))))

    def test_already_signed_pairs_are_skipped(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "p2wpkh", "key": 1}])
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        c.imaps[0][c.pairs[0]["sigkey"]] = b"\x30" + bytes(70)
        c.pairs = c.pairs[1:]
        r = tb.run_host(c, self.pubs(c), self.store, device=self.device(c),
                        rhos=tb.rho_args(c))
        self.ok(r)
        res = I.read_psbt(bytes.fromhex(r.result))
        self.assertEqual(dict(res[1])[b"\x02" + tb.pub(tb.DEV[0])], b"\x30" + bytes(70))
        self.assertIn(b"\x02" + tb.pub(tb.DEV[1]), dict(res[2]))
        # when every pair is already signed nothing remains
        os.remove(self.store)
        c2 = tb.make([{"form": "tr-key"}])
        self.refused(c2, lambda c: c.imaps[0].__setitem__(b"\x13", bytes(64)))
        c2 = tb.make([{"form": "tr-script"}])
        self.refused(c2, lambda c: c.imaps[0].__setitem__(c2.pairs[0]["sigkey"], bytes(64)))

    def test_derivation_names_key_not_in_script(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "p2wpkh", "key": 1}])
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        # input 1's record names DEV[1] but the script is for DEV[0]
        def mutate(c):
            c.imaps[1].pop(b"\x06" + tb.pub(tb.DEV[1]))
            c.imaps[1][b"\x06" + tb.pub(tb.DEV[1])] = tb.FP + tb.PATH_ECDSA
            spk = b"\x00\x14" + I.h160(tb.pub(tb.OTHER[0]))
            c.imaps[1][b"\x01"] = (100000).to_bytes(8, "little") + I.cs(len(spk)) + spk
        self.refused(c, mutate, device_keys=[tb.pub(tb.DEV[0]), tb.pub(tb.DEV[1])])
        c = tb.make([{"form": "p2wsh-multi"}])
        def other_in_script(c):
            c.imaps[0][b"\x06" + tb.pub(tb.DEV[3])] = tb.FP + tb.PATH_ECDSA
        self.refused(c, other_in_script, device_keys=[tb.pub(tb.DEV[0]), tb.pub(tb.DEV[3])])

    def test_taproot_derivation_without_leaves_and_not_internal(self):
        c = tb.make([{"form": "tr-script"}])
        x = tb.xonly(tb.DEV[0])
        def mutate(c):
            c.imaps[0][b"\x16" + x] = b"\x00" + tb.FP + tb.PATH_TR
        self.refused(c, mutate)

    def test_listed_leaf_without_script_forms_no_pair(self):
        c = tb.make([{"form": "tr-script"}])
        def mutate(c):
            for k in [k for k in c.imaps[0] if k[0] == 0x15]:
                del c.imaps[0][k]
        r = self.refused(c, mutate)
        self.assertIn("no script", r.stderr)

    def test_device_key_only_in_script_forms_no_pair(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "p2wsh-multi", "key": 1}])
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        c.pairs = c.pairs[:1]
        c.imaps[1].pop(b"\x06" + tb.pub(tb.DEV[1]))
        r = tb.run_host(c, self.pubs(c), self.store, device=self.device(c), rhos=tb.rho_args(c))
        self.ok(r)
        self.assertIn("without derivation record", r.stderr)
        self.assertEqual(len(I.read_psbt(bytes.fromhex(r.requests[0]))[2]), len(c.imaps[1]))

    def test_unsupported_script_or_sighash_or_final(self):
        c = tb.make([{"form": "p2wsh-single", "script": tb.push(tb.pub(tb.DEV[0])) + b"\xac\xab"}])
        self.refused(c)
        c = tb.make([{"form": "p2wpkh", "ht": 4}])
        self.refused(c)
        c = tb.make([{"form": "p2wpkh", "ht": 0}])
        self.refused(c)
        c = tb.make([{"form": "p2wpkh", "key": 1}, {"form": "p2wpkh", "ht": 3}])
        c.dev_sks = [tb.DEV[0]]
        self.refused(c, device_keys=[tb.pub(tb.DEV[0])])
        c = tb.make([{"form": "tr-script", "ht": 0x83}, {"form": "tr-script", "ht": 0x83, "key": 1}])
        c.dev_sks = [tb.DEV[1]]
        self.refused(c, device_keys=[tb.pub(tb.DEV[1])])
        c = tb.make([{"form": "p2wpkh"}])
        self.refused(c, lambda c: c.imaps[0].__setitem__(b"\x08", b"\x00"))
        self.refused(c, lambda c: c.imaps[0].__setitem__(b"\x07", b"\x00"))

    def test_taproot_requires_other_prevouts_unless_acp(self):
        c = tb.make([{"form": "tr-key"}, {"form": "p2wpkh", "key": 1}])
        c.dev_sks = [tb.DEV[0]]
        c.pairs = c.pairs[:1]
        self.refused(c, lambda c: c.imaps[1].pop(b"\x01"))

    def test_outputs_exceed_inputs(self):
        c = tb.make([{"form": "p2wpkh"}], outs=[(100001, b"\x6a")])
        self.refused(c)

    def test_nwu_mismatch(self):
        c = tb.make([{"form": "p2pkh"}])
        t = I.Tx(version=1).add_in(I.H(b"x"), 0).add_out(100000, c.info[0]["spk"])
        self.refused(c, lambda c: c.imaps[0].__setitem__(b"\x00", t.ser()))

    def test_uncompressed_device_key_record(self):
        pt = I.mul(tb.DEV[0])
        unc = b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
        c = tb.make([{"form": "p2wpkh"}])
        self.refused(c, lambda c: c.imaps[0].__setitem__(b"\x06" + unc, tb.FP + tb.PATH_ECDSA))

    def test_musig_participants(self):
        c = tb.make([{"form": "tr-key"}])
        v = tb.pub(tb.OTHER[1]) + b"\x03" + tb.xonly(tb.DEV[0])
        self.refused(c, lambda c: c.imaps[0].__setitem__(b"\x1a" + tb.pub(tb.OTHER[0]), v))

    def test_bad_psbt_and_keys(self):
        for h in ("", "00", "70736274ff"):
            r = tb.run_host(h, [tb.pub(tb.DEV[0])], self.store, rhos=[])
            self.assertEqual(r.status, "REFUSED")

    def test_both_forms_of_an_x_only_key_make_one_pair(self):
        c = tb.make([{"form": "tr-key"}])
        pub = tb.pub(tb.DEV[0])
        other_form = bytes([pub[0] ^ 1]) + pub[1:]
        r = tb.run_host(c, [pub, other_form], self.store, device=self.device(c, sks=[tb.DEV[0]]),
                        rhos=tb.rho_args(c))
        self.ok(r)
        tb.check_result(c, r.result)
        req = I.read_psbt(bytes.fromhex(r.requests[0]))
        self.assertEqual(sum(1 for k, _ in req[1] if k[0] == 0x21), 1)

    def test_key_path_preferred_over_script_path(self):
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
        c.imaps[0][b"\x16" + x] = b"\x01" + l1 + tb.FP + tb.PATH_TR
        c.info[0]["spk"] = spk
        c.spent = [(100000, spk)]
        c.pairs = [dict(c.pairs[0], kind="tr_key", keyid=x, sigkey=b"\x13", pk=Q[0].to_bytes(32, "big"),
                        m=I.taproot_sighash(c.tx, 0, 0, c.spent))]
        r = self.go(c)
        self.ok(r)
        tb.check_result(c, r.result)
        req = I.read_psbt(bytes.fromhex(r.requests[0]))
        ae = [k for k, _ in req[1] if k[0] == 0x21]
        self.assertEqual(ae, [b"\x21" + x])


class TestRhoHandling(HostCase):
    def test_missing_rho(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "tr-key", "key": 1}])
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        args = tb.rho_args(c)[:2]
        r = tb.run_host(c, self.pubs(c), self.store, device=self.device(c), rhos=args)
        self.assertEqual(r.status, "MISSING_RHO")
        self.assertEqual(r.rc, 9)
        self.assertEqual(r.requests, [])
        self.assertFalse(os.path.exists(self.store))

    def test_rho_for_wrong_key_or_input_is_missing(self):
        c = tb.make([{"form": "p2wpkh"}])
        p = c.pairs[0]
        r = tb.run_host(c, self.pubs(c), self.store, rhos=["--rho", "1:%s:%s" % (p["keyid"].hex(), "11" * 32)])
        self.assertEqual(r.status, "MISSING_RHO")
        r = tb.run_host(c, self.pubs(c), self.store, rhos=["--rho", "0:%s:%s" % (tb.pub(tb.DEV[1]).hex(), "11" * 32)])
        self.assertEqual(r.status, "MISSING_RHO")

    def test_extra_rho_values_are_ignored(self):
        c = tb.make([{"form": "p2wpkh"}])
        args = tb.rho_args(c) + ["--rho", "5:%s:%s" % ("02" * 33, "11" * 32)]
        r = tb.run_host(c, self.pubs(c), self.store, device=self.device(c), rhos=args)
        self.ok(r)

    def test_same_rho_for_two_pairs_refused(self):
        c = tb.make([{"form": "p2wpkh"}, {"form": "p2wpkh", "key": 1}])
        c.dev_sks = [tb.DEV[0], tb.DEV[1]]
        args = []
        for p in c.pairs:
            args += ["--rho", "%d:%s:%s" % (p["i"], p["keyid"].hex(), "22" * 32)]
        r = tb.run_host(c, self.pubs(c), self.store, device=self.device(c), rhos=args)
        self.assertEqual(r.status, "REFUSED")

    def test_rho_is_not_stored(self):
        c = tb.make([{"form": "p2wpkh"}])
        self.ok(self.go(c))
        with open(self.store) as f:
            text = f.read()
        for p in c.pairs:
            self.assertNotIn(tb.rho_for(p["i"], p["keyid"]).hex(), text)

    def test_rho_not_printed_before_commitment_received(self):
        c = tb.make([{"form": "p2wpkh"}])
        r = self.go(c)
        rho = tb.rho_for(0, c.pairs[0]["keyid"])
        self.assertNotIn(rho, bytes.fromhex(r.requests[0]))
        self.assertIn(rho, bytes.fromhex(r.requests[1]))
        self.assertNotIn(rho.hex(), r.stderr)

    def test_rho_not_sent_if_commitment_invalid(self):
        c = tb.make([{"form": "p2wpkh"}])
        p = c.pairs[0]
        def bad(maps, n): maps[1][:] = [(k, (b"\x05" + v[1:] if k[0] == 0x22 else v)) for k, v in maps[1]]
        r = self.go(c, self.device(c, on1=bad))
        self.failed(r)
        self.assertEqual(len(r.requests), 1)


if __name__ == "__main__":
    unittest.main()
