"""Attempts and failures: every bullet, with kills between durable steps by re-instantiating the Host."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as K            # noqa: E402
import psbt_codec as C        # noqa: E402
import host as H              # noqa: E402
import transport as T         # noqa: E402


class Kill(Exception):
    """Simulated process death at a durable write."""


class CrashingStore(H.Store):
    """Dies before or after the n-th durable write (counting from construction)."""

    def __init__(self, path, n=None, when="before"):
        self.n, self.when, self.count = n, when, 0
        super().__init__(path)

    def _write(self, data):
        self.count += 1
        if self.n == self.count and self.when == "before":
            raise Kill()
        super()._write(data)
        if self.n == self.count and self.when == "after":
            raise Kill()


class LifeBase(K.Base):
    def mkrig(self, steps=(), forms=("p2wpkh",), max_retries=3, **kw):
        inputs = [K.Inp(K.Form(f)) if isinstance(f, str) else K.Inp(f) for f in forms]
        return K.Rig(inputs, self.tmp, link_cls=T.ScriptedLink, steps=list(steps), max_retries=max_retries,
                     rho_source=kw.pop("rho_source", None), **kw)

    def record(self, rig, dev="dev-A"):
        return json.load(open(rig.store_path))["devices"][dev]

    def restart(self, rig):
        """A host restart: a new Host over the same store file."""
        return rig.new_host()


class Bullets(LifeBase):
    def test_attempt_recorded_open_before_hc_is_sent(self):
        """Attempts: "the host MUST make that record before sending hc.\""""
        rig = self.mkrig()
        seen = []

        def peek(link, req):
            rec = self.record(rig)
            seen.append((len(rec["open"]), bool(any(k[:1] == b"\x21" for m in C.parse(req).inputs for k in m))))
        rig.link.on_exchange = peek
        rig.host.sign(rig.request_bytes)
        self.assertEqual(seen[0], (1, True))
        self.assertEqual(self.record(rig)["open"], {})

    def test_refused_before_the_record_is_not_an_attempt(self):
        """Attempts: "A request the host refuses before making that record is not an attempt.\""""
        rig = self.mkrig()
        rig.psbt.inputs[0][b"\x21" + b"\x02" + b"\x01" * 32] = b"\x00" * 32
        for _ in range(3):
            with self.assertRaises(H.HostRefusal):
                rig.host.start(rig.request_bytes)
        self.assertFalse(os.path.exists(rig.store_path))
        self.assertEqual(rig.link.calls, 0)
        self.assertEqual(rig.store.failures("dev-A"), 0)

    def test_one_durable_increment_at_first_failure(self):
        """Attempts: "add one, durably, at the first failure event in an attempt, and at most once per attempt. A later success on that attempt does not undo it.\""""
        rig = self.mkrig([T.timeout, T.disconnect, T.refuse, T.honest, T.timeout, T.garbage, T.honest])
        counts = []
        rig.link.on_exchange = lambda l, r: counts.append(self.record(rig)["failures"])
        res = rig.host.sign(rig.request_bytes)
        self.assertEqual(len(res.signed), 1)
        self.assertEqual(counts, [0, 1, 1, 1, 1, 1, 1])
        self.assertEqual(self.record(rig)["failures"], 1)
        self.assertEqual(self.record(rig)["open"], {})

    def test_open_attempt_at_startup_counts_as_failed(self):
        """Attempts: "At startup, an attempt still recorded as open counts as failed.\""""
        rig = self.mkrig()
        rig.host.start(rig.request_bytes)                     # recorded open, then the process dies
        self.assertEqual(self.record(rig)["failures"], 0)
        h2 = self.restart(rig)
        self.assertEqual(self.record(rig)["failures"], 1)
        self.assertEqual(self.record(rig)["open"], {})
        self.restart(rig)
        self.assertEqual(self.record(rig)["failures"], 1, "recovery must not count twice")

    def test_kill_between_every_durable_step(self):
        """Attempts: counts survive a restart between any two durable steps and are never doubled or lost.
        Durable writes: begin, count (first failure event), end. Expected failures after a restart per kill point."""
        matrix = {
            # steps, kill point (write number, before/after) -> failures after restart
            "success": ([], {(1, "before"): 0, (1, "after"): 1, (2, "before"): 1, (2, "after"): 0}),
            "timeout then success": ([T.timeout, T.honest, T.honest],
                                     {(1, "before"): 0, (1, "after"): 1, (2, "before"): 1, (2, "after"): 1,
                                      (3, "before"): 1, (3, "after"): 1}),
            "retries exhausted": ([T.timeout] * 4, {(1, "before"): 0, (1, "after"): 1, (2, "before"): 1,
                                                    (2, "after"): 1, (3, "before"): 1, (3, "after"): 1}),
            "changed R0": ([T.honest, T.honest], None),
        }
        for name, (steps, expected) in matrix.items():
            if expected is None:
                continue
            for (n, when), want in expected.items():
                with self.subTest(scenario=name, write=n, when=when):
                    rig = self.mkrig(list(steps), max_retries=3)
                    rig.host = H.Host(rig.wallet, CrashingStore(rig.store_path, n, when), rig.ui, rig.link, rig.max_retries)
                    try:
                        rig.host.sign(rig.request_bytes)
                    except (Kill, H.AttemptFailed):
                        pass
                    rig.new_host()
                    self.assertEqual(rig.store.failures("dev-A"), want)
                    self.assertEqual(self.record(rig)["open"] if os.path.exists(rig.store_path) else {}, {})
                    rig.new_host()
                    self.assertEqual(rig.store.failures("dev-A"), want, "a second restart changes nothing")

    def test_kill_after_each_state_of_a_longer_attempt(self):
        """Restart at each stage without a store fault: open attempts count once, whatever stage they reached."""
        for stage in ("started", "committed", "failed-once"):
            rig = self.mkrig([T.timeout, T.honest] if stage == "failed-once" else [])
            a = rig.host.start(rig.request_bytes)
            if stage != "started":
                a.commit()
            want = 1
            rig.new_host()
            self.assertEqual(rig.store.failures("dev-A"), want, stage)

    def test_unreadable_records_count_as_a_failure(self):
        """Attempts: "A host that cannot read its records for a device MUST treat that device as having a recorded failure.\""""
        for junk in (b"{not json", b"", b'{"format": 2}', b"[]", b"\xff\xfe"):
            rig = self.mkrig()
            open(rig.store_path, "wb").write(junk)
            rig.new_host()
            self.assertEqual(rig.store.failures("dev-A"), 1)         # "a count of one", not more
            self.assertTrue(rig.store.needs_warning("dev-A"))
            self.assertTrue(os.path.exists(rig.store_path + ".unreadable.0"), "evidence kept aside")
            with self.assertRaises(H.WarningNotAcknowledged):
                rig.ui.ack = False
                rig.host.start(rig.request_bytes)
        rig = self.mkrig()
        rig.host.sign(rig.request_bytes)
        d = json.load(open(rig.store_path))
        d["devices"]["dev-A"]["failures"] = "many"                 # one device's record unreadable
        json.dump(d, open(rig.store_path, "w"))
        rig.new_host()
        self.assertEqual(rig.store.failures("dev-A"), 1)
        self.assertTrue(rig.store.needs_warning("dev-A"))

    def test_store_that_cannot_be_written_stops_before_hc(self):
        """Attempts: the record is made before hc is sent; if it cannot be made nothing is sent."""
        rig = self.mkrig()
        rig.store._write = lambda d: (_ for _ in ()).throw(OSError("disk full"))
        with self.assertRaises(OSError):
            rig.host.start(rig.request_bytes)
        self.assertEqual(rig.link.calls, 0)

    def test_warning_before_next_attempt_and_acknowledgement_covers_one(self):
        """Attempts: "the host MUST warn ... An acknowledgement covers exactly one new attempt.\""""
        rig = self.mkrig([T.timeout] * 4, max_retries=3)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        self.assertEqual(rig.ui.warnings, [])                       # no warning on the first-ever attempt
        # refused acknowledgement: no attempt, nothing sent
        rig.ui.ack = False
        calls = rig.link.calls
        with self.assertRaises(H.WarningNotAcknowledged):
            rig.host.sign(rig.request_bytes)
        self.assertEqual(rig.link.calls, calls)
        self.assertEqual(self.record(rig)["open"], {})
        # acknowledged: exactly one attempt
        rig.ui.ack = True
        rig.host.sign(rig.request_bytes)
        self.assertEqual(len(rig.ui.warnings), 2)
        rig.host.sign(rig.request_bytes)                            # count did not rise: no new warning
        self.assertEqual(len(rig.ui.warnings), 2)

    def test_acknowledgement_is_used_up_in_the_write_that_records_the_attempt(self):
        """Attempts: "An acknowledgement ... is used up in the same durable write that records it.\""""
        for when in ("before", "after"):
            rig = self.mkrig([T.timeout] * 4, max_retries=3)
            with self.assertRaises(H.AttemptFailed):
                rig.host.sign(rig.request_bytes)
            self.assertTrue(rig.store.needs_warning("dev-A"))
            rig.host = H.Host(rig.wallet, CrashingStore(rig.store_path, 1, when), rig.ui, rig.link, rig.max_retries)
            with self.assertRaises(Kill):
                rig.host.start(rig.request_bytes)               # the first write of the new host is the record
            rec = self.record(rig)
            if when == "before":
                # no record, and the acknowledgement was not used up either
                self.assertEqual((rec["warned"], rec["open"]), (0, {}))
            else:
                # the record exists and the acknowledgement is spent in that same write
                self.assertEqual((rec["warned"], len(rec["open"])), (1, 1))
            rig.new_host()
            self.assertTrue(rig.store.needs_warning("dev-A"), when)   # a restart cannot reuse the acknowledgement

    def test_reset_clears_a_pending_warning(self):
        """Attempts: "A reset clears any pending warning.\""""
        rig = self.mkrig([T.timeout] * 4)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        self.assertTrue(rig.store.needs_warning("dev-A"))
        rig.host.sign(rig.request_bytes)                        # acknowledged and used up: the host has now warned once
        self.assertTrue(rig.host.reset_failures())
        self.assertFalse(rig.store.needs_warning("dev-A"))
        rig.ui.ack = False                                      # nothing to acknowledge any more
        rig.host.sign(rig.request_bytes)
        self.assertEqual(len(rig.ui.warnings), 1)               # only the earlier one
        # and the next failure is a new one that needs a warning again
        rig.link.steps = [T.timeout] * 4
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        self.assertTrue(rig.store.needs_warning("dev-A"))
        # a reset in the middle of an acknowledged attempt: the next failure still owes a warning
        rig = self.mkrig([T.timeout] * 4)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        a = rig.host.start(rig.request_bytes)                   # acknowledged, so the host has warned once
        self.assertTrue(rig.host.reset_failures())
        rig.link.steps = [T.timeout] * 4
        with self.assertRaises(H.AttemptFailed):
            a.commit()
        self.assertEqual(rig.store.failures("dev-A"), 1)
        self.assertTrue(rig.store.needs_warning("dev-A"))
        # a refused reset clears nothing
        rig = self.mkrig([T.timeout] * 4, ui=H.UI())
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        rig.host.reset_failures()
        self.assertTrue(rig.store.needs_warning("dev-A"))

    def test_acknowledged_attempt_that_fails_needs_a_new_acknowledgement(self):
        rig = self.mkrig([T.timeout] * 4 + [T.timeout] * 4, max_retries=3)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        self.assertEqual(len(rig.ui.warnings), 1)
        rig.host.sign(rig.request_bytes)                             # honest again, but only after a second warning
        self.assertEqual(len(rig.ui.warnings), 2)
        self.assertEqual(rig.store.failures("dev-A"), 2)

    def test_warning_not_cleared_by_change_reconnect_restart(self):
        """Attempts: "Changing the message, coins or fee, reconnecting and restarting do not clear this requirement.\""""
        rig = self.mkrig([T.timeout] * 4)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        rig.ui.ack = False
        other = K.build_psbt(rig.inputs, version=2, fee=5000)       # different message, fee and PSBT version
        for data in (other.serialize(), rig.request_bytes):
            rig.link = T.ScriptedLink(rig.signer)                    # reconnect
            rig.host = rig.new_host()                                # restart
            rig.host.link = rig.link
            with self.assertRaises(H.WarningNotAcknowledged):
                rig.host.start(data, user_chose_change=True)
        self.assertEqual(rig.link.calls, 0)

    def test_no_silent_new_attempt_after_failure(self):
        """Attempts: "The host MUST NOT start a new attempt silently in response to a failure.\" The default UI refuses."""
        rig = self.mkrig([T.timeout] * 4, ui=H.UI())
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        with self.assertRaises(H.WarningNotAcknowledged):
            rig.host.sign(rig.request_bytes)

    def test_retries_are_bounded_and_reuse_rho(self):
        """Attempts: "the host MAY retry a bounded number of times ... repeat steps 3 and 4 with the same rho ... When retries run out, the attempt has failed.\""""
        for retries in (0, 1, 3):
            rig = self.mkrig([T.timeout] * 20, max_retries=retries)
            with self.assertRaises(H.AttemptFailed) as cm:
                rig.host.sign(rig.request_bytes)
            self.assertEqual(rig.link.calls, retries + 1)
            self.assertEqual(cm.exception.code, "retries_exhausted")
            rig = self.mkrig([T.honest] + [T.timeout] * 20, max_retries=retries)
            with self.assertRaises(H.AttemptFailed):
                rig.host.sign(rig.request_bytes)
            self.assertEqual(rig.link.calls, 1 + retries + 1)
        rig = self.mkrig([T.honest, T.timeout, T.disconnect, T.honest])
        rig.host.sign(rig.request_bytes)
        reqs = [r for r, _ in rig.link.transcript if any(k[:1] == b"\x23" for m in C.parse(r).inputs for k in m)]
        self.assertEqual(len(reqs), 3)
        self.assertEqual(len(set(reqs)), 1, "every retry of steps 3 and 4 sends the same rho")

    def test_new_attempt_new_rho(self):
        """Host randomness: "The host MUST draw a new rho for every attempt and for every message and key within it.\""""
        rig = self.mkrig(forms=("p2wsh-2of3",))
        rhos = []
        for _ in range(3):
            rig.host.sign(rig.request_bytes)
        for r, _ in rig.link.transcript:
            p = C.parse(r)
            rhos += [v for m in p.inputs for t, _, v in C.ae_entries(m) if t == 0x23]
        self.assertEqual(len(rhos), 6)
        self.assertEqual(len(set(rhos)), 6)

    def test_rho_comes_from_secrets(self):
        import secrets
        calls = []
        real = secrets.token_bytes
        secrets.token_bytes = lambda n=32: (calls.append(n), real(n))[1]
        try:
            rig = self.mkrig()
            rig.host.sign(rig.request_bytes)
        finally:
            secrets.token_bytes = real
        self.assertEqual(calls, [32])

    def test_r0_compared_across_all_responses_including_rejected(self):
        """Attempts: "MUST end the attempt as failed if R0_bytes differs from any value received for that attempt, including one in a response it rejected.\""""
        form = K.Form("p2wsh-2of3")

        def reject_second_pair(req, real):
            p = C.parse(real(req))
            ks = sorted(k for k in p.inputs[0] if k[:1] == b"\x22")
            p.inputs[0][ks[1]] = b"\x05" + b"\x01" * 32            # rejected: not a point
            return p.serialize()
        rig = self.mkrig([reject_second_pair, T.change_r0(0)], forms=(form,))
        with self.assertRaises(H.AttemptFailed) as cm:
            rig.host.sign(rig.request_bytes)
        self.assertEqual(cm.exception.reasons[0], "bad_commitment")
        self.assertIn("r0_changed", cm.exception.reasons)
        self.assertEqual(rig.link.calls, 2, "no further retries after a changed R0")
        self.assertEqual(rig.store.failures("dev-A"), 1)

    def test_r0_changed_in_second_pass_response(self):
        # a second-pass response holding a different 0x22 is rejected twice over; the changed value ends the attempt
        def f(req, real):
            p = C.parse(real(req))
            k = b"\x22" + K.pub33(self.skey)
            p.inputs[0][k] = b"\x03" + b"\x09" * 32
            return p.serialize()
        rig = self.mkrig([T.honest, f])
        self.skey = rig.inputs[0].form.a
        with self.assertRaises(H.AttemptFailed) as cm:
            rig.host.sign(rig.request_bytes)
        self.assertEqual(cm.exception.reasons[0], "r0_changed")
        self.assertEqual(rig.link.calls, 2)

    def test_refusal_presented_as_disconnect_costs_the_same(self):
        """Failure event: "The host does not try to separate transport faults from refusals, because a device can present one as the other.\""""
        counts = []
        for first in (T.timeout, T.disconnect, T.refuse, T.garbage):
            rig = self.mkrig([T.honest, first, T.honest])
            rig.host.sign(rig.request_bytes)
            counts.append(rig.store.failures("dev-A"))
        self.assertEqual(counts, [1, 1, 1, 1])

    def test_retry_then_succeed_cannot_clear_the_count(self):
        """Attempts: "A later success on that attempt does not undo it.\" and the next attempt warns."""
        rig = self.mkrig([T.refuse, T.honest, T.honest])
        rig.host.sign(rig.request_bytes)
        self.assertEqual(rig.store.failures("dev-A"), 1)
        rig.ui.ack = False
        with self.assertRaises(H.WarningNotAcknowledged):
            rig.host.sign(rig.request_bytes)

    def test_repeat_step2_after_failure_with_unchanged_r0(self):
        """Attempts: "It MAY do so after a repeated step 2 returns an unchanged R0_bytes.\""""
        rig = self.mkrig([T.honest, T.timeout, T.honest, T.honest])
        rig.host.repeat_step2_on_retry = True
        rig.host.sign(rig.request_bytes)
        kinds = ["hc" if any(k[:1] == b"\x21" for m in C.parse(r).inputs for k in m) else "rho" for r, _ in rig.link.transcript]
        self.assertEqual(kinds, ["hc", "rho", "hc", "rho"])
        rig = self.mkrig([T.honest, T.timeout, T.change_r0(0)])
        rig.host.repeat_step2_on_retry = True
        with self.assertRaises(H.AttemptFailed) as cm:
            rig.host.sign(rig.request_bytes)
        self.assertIn("r0_changed", cm.exception.reasons)

    def test_repeated_step2_shares_the_step2_retry_budget(self):
        """Attempts: "the host MAY retry a bounded number of times"; step 2 is sent at most 1 + retries times, repeats included."""
        rig = self.mkrig([T.timeout, T.timeout, T.honest, T.timeout, T.honest], max_retries=2)
        rig.host.repeat_step2_on_retry = True
        res = rig.host.sign(rig.request_bytes)
        self.assertEqual(len(res.signed), 1)
        kinds = ["hc" if any(k[:1] == b"\x21" for m in C.parse(r).inputs for k in m) else "rho" for r, _ in rig.link.transcript]
        self.assertEqual(kinds.count("hc"), 3, kinds)               # 1 + 2 retries, and no repeat left for the second pass

    def test_failed_repeat_of_step2_leaves_the_step4_budget_alone(self):
        """Attempts: "Three retries for each of steps 2 and 4"; a failed repeat of step 2 uses step 2's budget."""
        rig = self.mkrig([T.honest, T.timeout, T.timeout, T.timeout, T.honest], max_retries=2)
        rig.host.repeat_step2_on_retry = True
        res = rig.host.sign(rig.request_bytes)
        self.assertEqual(len(res.signed), 1)
        kinds = ["hc" if any(k[:1] == b"\x21" for m in C.parse(r).inputs for k in m) else "rho" for r, _ in rig.link.transcript]
        self.assertEqual(kinds, ["hc", "rho", "hc", "hc", "rho"])
        self.assertEqual(rig.store.failures("dev-A"), 1)

    def test_abandon_is_not_charged_and_failed_is(self):
        """Attempts: Abandoned: "the user stopped or changed the request for a reason independent of the device, with no response outstanding and no failure recorded.\""""
        rig = self.mkrig()
        a = rig.host.start(rig.request_bytes)
        a.abandon()
        self.assertEqual(a.state, "abandoned")
        self.assertEqual(self.record(rig)["open"], {})
        self.assertEqual(rig.store.failures("dev-A"), 0)
        a = rig.host.start(rig.request_bytes)
        a.commit()
        a.abandon()                                                  # between the two passes, nothing outstanding
        self.assertEqual((a.state, rig.store.failures("dev-A")), ("abandoned", 0))
        self.assertEqual(rig.ui.warnings, [])
        # after a counted failure the attempt cannot be abandoned: it ends failed, no second increment
        rig = self.mkrig([T.timeout, T.honest])
        a = rig.host.start(rig.request_bytes)
        a.commit()                                                   # retry succeeds
        a.abandon()
        self.assertEqual((a.state, rig.store.failures("dev-A")), ("failed", 1))

    def test_cancel_with_response_outstanding_is_a_failure(self):
        """Failure event: "a cancellation on either side while a response is outstanding\""""
        rig = self.mkrig()
        holder = {}
        rig.link.on_exchange = lambda l, r: holder["a"].cancel()
        a = rig.host.start(rig.request_bytes)
        holder["a"] = a
        with self.assertRaises(H.AttemptFailed) as cm:
            a.commit()
        self.assertEqual(cm.exception.reasons[0], "cancelled")
        self.assertEqual(rig.store.failures("dev-A"), 1)
        self.assertEqual(rig.link.calls, 1)
        # device-side cancel
        rig = self.mkrig([lambda req, real: (_ for _ in ()).throw(T.LinkCancelled("device cancelled"))], max_retries=0)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        self.assertEqual(rig.store.failures("dev-A"), 1)
        self.assertEqual(rig.link.calls, 1, "a cancellation ends the attempt without retries")

    def test_cancel_with_nothing_outstanding_is_an_abandon(self):
        rig = self.mkrig()
        a = rig.host.start(rig.request_bytes)
        a.cancel()
        self.assertEqual((a.state, rig.store.failures("dev-A")), ("abandoned", 0))

    def test_message_the_host_did_not_request(self):
        """Failure event: "a message the host did not request\""""
        rig = self.mkrig()
        rig.link.on_exchange = lambda l, r: l.push_unsolicited(b"hello") if l.calls == 1 else None
        res = rig.host.sign(rig.request_bytes)
        self.assertEqual(len(res.signed), 1)
        self.assertEqual(rig.store.failures("dev-A"), 1)

    def test_message_outside_any_attempt_is_discarded_and_charged_nothing(self):
        """Attempts: "outside any attempt the host discards it.\""""
        rig = self.mkrig()
        rig.link.push_unsolicited(b"hello")
        self.assertEqual(rig.host.discard_unsolicited(), 1)
        self.assertEqual(rig.store.failures("dev-A"), 0)
        rig.link.push_unsolicited(b"again")
        res = rig.host.sign(rig.request_bytes)            # start discards it too
        self.assertEqual(len(res.signed), 1)
        self.assertEqual(rig.store.failures("dev-A"), 0)
        self.assertEqual(rig.ui.warnings, [])

    def test_decline_counts_unless_user_confirms_it_was_unrelated(self):
        """Attempts: "need not count a decline the user confirms was unrelated to what the device showed ... A decline because the device showed something unexpected counts, because a device can induce it.\""""
        # two separate answers: declined on the device, and unrelated to what it showed
        ui = K.AckUI(declined=True, unrelated=True)
        rig = self.mkrig([T.honest, T.refuse], ui=ui)
        with self.assertRaises(H.AttemptAbandoned) as cm:
            rig.host.sign(rig.request_bytes)
        self.assertEqual(cm.exception.code, "declined_on_device")      # ends as Abandoned: "A decline left uncounted ... also ends this way"
        self.assertEqual(ui.asked, ["declined", "unrelated"])
        self.assertEqual(rig.store.failures("dev-A"), 0)
        self.assertEqual(self.record(rig)["open"], {})
        self.assertIsNone(self.record(rig).get("last", {}).get("failed") or None)   # arms nothing
        # so a different transaction is allowed next, with no warning and no choice asked
        other = K.build_psbt(rig.inputs, version=0, fee=9000).serialize()
        rig.link.steps = [T.honest, T.honest]
        rig.host.sign(other)
        self.assertEqual(rig.ui.warnings, [])
        # declined because the device showed something unexpected: counts
        ui = K.AckUI(declined=True, unrelated=False)
        rig = self.mkrig([T.honest, T.refuse], ui=ui, max_retries=0)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        self.assertEqual(ui.asked, ["declined", "unrelated"])
        self.assertEqual(rig.store.failures("dev-A"), 1)
        # the user says they did not decline: counts, and the second question is not asked
        ui = K.AckUI(declined=False, unrelated=True)
        rig = self.mkrig([T.honest, T.refuse], ui=ui, max_retries=0)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        self.assertEqual(ui.asked, ["declined"])
        self.assertEqual(rig.store.failures("dev-A"), 1)
        # a refusal in step 2 shows the user nothing, so no decline can be claimed
        ui = K.AckUI(declined=True, unrelated=True)
        rig = self.mkrig([T.refuse], ui=ui, max_retries=0)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        self.assertEqual(ui.asked, [])
        self.assertEqual(rig.store.failures("dev-A"), 1)
        # the default UI answers no to both
        rig = self.mkrig([T.honest, T.refuse], ui=H.UI(), max_retries=0)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)

    def test_confirmed_decline_after_a_counted_failure_ends_the_attempt_charged_once(self):
        """Attempts: the attempt already holds a failure, so it cannot be Abandoned; the declined request is not retried."""
        ui = K.AckUI(declined=True, unrelated=True)
        rig = self.mkrig([T.honest, T.timeout, T.refuse], ui=ui)
        with self.assertRaises(H.AttemptFailed) as cm:
            rig.host.sign(rig.request_bytes)
        self.assertEqual(cm.exception.code, "declined_on_device")
        self.assertEqual(rig.link.calls, 3, "no retry after the user declined")
        self.assertEqual(rig.store.failures("dev-A"), 1)
        self.assertEqual(self.record(rig)["open"], {})

    def test_unsolicited_message_during_an_attempt_via_poll(self):
        """Attempts: "A message the host did not request does not end the attempt\"; outside one it is discarded."""
        rig = self.mkrig()
        a = rig.host.start(rig.request_bytes)
        rig.link.push_unsolicited(b"x")
        self.assertEqual(a.poll(), 1)
        self.assertEqual((a.state, rig.store.failures("dev-A")), ("ready", 1))
        rig.link.push_unsolicited(b"y")
        a.poll()
        self.assertEqual(rig.store.failures("dev-A"), 1, "at most one increment per attempt")
        a.commit()
        res = a.reveal()
        self.assertEqual(len(res.signed), 1)
        rig.link.push_unsolicited(b"z")
        self.assertEqual(a.poll(), 1)                               # attempt over: discarded
        self.assertEqual(rig.store.failures("dev-A"), 1)

    def test_device_identity_is_the_wallets_not_the_devices(self):
        """Attempts: "A device is identified by the keys or fingerprint in the host's own wallet data, never by an identifier the device reports.\""""
        def claims_new_identity(req, real):
            p = C.parse(real(req))
            p.glob[b"\xfc\x06device-id"] = b"fresh-device-" + os.urandom(4).hex().encode()
            p.inputs[0][b"\xfc\x06device-id"] = p.glob[b"\xfc\x06device-id"]
            return p.serialize()
        rig = self.mkrig([claims_new_identity, T.timeout] + [T.timeout] * 3, max_retries=3)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        self.assertEqual(list(json.load(open(rig.store_path))["devices"]), ["dev-A"])
        self.assertEqual(rig.store.failures("dev-A"), 1)
        # another wallet identity has its own count
        other = H.Wallet("dev-B", rig.wallet.keys)
        h = H.Host(other, rig.store, rig.ui, rig.link)
        self.assertEqual(rig.store.failures("dev-B"), 0)

    def test_reset_is_an_explicit_user_action_that_states_what_is_cleared(self):
        """Attempts: "The count resets only by an explicit user action that states what is being cleared.\""""
        rig = self.mkrig([T.timeout] * 4)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        rig.ui.resets = []
        self.assertTrue(rig.host.reset_failures())
        self.assertIn("1 recorded failure", rig.ui.resets[0])
        self.assertIn("dev-A", rig.ui.resets[0])
        self.assertEqual(rig.store.failures("dev-A"), 0)
        rig = self.mkrig([T.timeout] * 4, ui=H.UI())
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        self.assertFalse(rig.host.reset_failures())          # default UI refuses
        self.assertEqual(rig.store.failures("dev-A"), 1)

    def test_failure_limit(self):
        """Attempts: "It SHOULD refuse further attempts past a small limit on the count.\""""
        rig = self.mkrig([T.timeout] * 40, max_retries=0)
        rig.host.failure_limit = 3
        for _ in range(3):
            with self.assertRaises(H.AttemptFailed):
                rig.host.sign(rig.request_bytes)
        calls = rig.link.calls
        with self.assertRaises(H.HostRefusal) as cm:
            rig.host.sign(rig.request_bytes)
        self.assertEqual(cm.exception.code, "failure_limit")
        self.assertEqual(rig.link.calls, calls)

    def test_rho_and_r0_never_reach_the_store(self):
        """Host randomness: "rho MUST NOT ... be written to durable storage\" and R0_bytes stays in memory with rho."""
        rig = self.mkrig([T.timeout, T.honest, T.honest, T.honest, T.timeout, T.honest, T.honest],
                         forms=("p2wsh-2of3",))
        rig.host.sign(rig.request_bytes)
        rig.host.sign(rig.request_bytes)
        rhos, r0s = set(), set()
        for req, resp in rig.link.transcript:
            for data, sink, typs in ((req, rhos, (0x23,)), (resp, r0s, (0x22,))):
                if data:
                    for m in C.parse(data).inputs:
                        for t, _, v in C.ae_entries(m):
                            if t in typs:
                                sink.add(v)
        self.assertEqual((len(rhos), len(r0s)), (4, 4))
        blobs = [open(os.path.join(self.tmp, f), "rb").read() for f in os.listdir(self.tmp)]
        self.assertTrue(blobs)
        for b in blobs:
            for v in rhos | r0s:
                self.assertNotIn(v, b)
                self.assertNotIn(v.hex().encode(), b)
        # and the values are erased from the attempt object when it ends
        a = rig.host.start(rig.request_bytes)
        a.commit()
        a.reveal()
        self.assertEqual((a._rho, a._r0), ({}, {}))

    def test_store_is_durable_and_atomic(self):
        """Durable store: fsync of the file and its directory, atomic rename, no temp file left."""
        rig = self.mkrig()
        syncs, replaces = [], []
        real_fsync, real_replace = os.fsync, os.replace
        os.fsync = lambda fd: (syncs.append(fd), real_fsync(fd))[1]
        os.replace = lambda a, b: (replaces.append((a, b)), real_replace(a, b))[1]
        try:
            rig.host.sign(rig.request_bytes)
        finally:
            os.fsync, os.replace = real_fsync, real_replace
        self.assertEqual(len(replaces), 2)                          # begin, end
        self.assertEqual(len(syncs), 4)                             # file and directory each time
        self.assertTrue(all(a == b + ".tmp" for a, b in replaces))
        self.assertFalse(os.path.exists(rig.store_path + ".tmp"))
        json.load(open(rig.store_path))


class RuleFixes(LifeBase):
    def test_any_link_exception_is_a_failure_event(self):
        """Attempts: "A failure event during an attempt is a timeout, a device error or refusal ..."; the host MUST add one at the first."""
        def boom(req, real):
            raise OSError("framing error")
        rig = self.mkrig([T.honest, boom, T.honest])
        rig.host.sign(rig.request_bytes)
        self.assertEqual(rig.store.failures("dev-A"), 1)

    def test_a_host_for_another_device_leaves_a_live_attempt_alone(self):
        """Attempts: "At startup, an attempt still recorded as open counts as failed" concerns this host's own device."""
        rig = self.mkrig()
        a = rig.host.start(rig.request_bytes)
        store = H.Store(rig.store_path)
        store.recover("dev-B")
        self.assertEqual(rig.store.failures("dev-A"), 0)
        self.assertTrue(self.record(rig)["open"])
        a.abandon()

    def test_failures_after_recovery_are_not_counted_again(self):
        """Attempts: "at most once per attempt", even if recovery closed the record while the attempt was live."""
        def boom(req, real):
            raise T.LinkTimeout("t")
        rig = self.mkrig([boom, boom, boom], max_retries=2)
        a = rig.host.start(rig.request_bytes)
        H.Host(rig.wallet, rig.store, rig.ui, rig.link)     # a second host in this process, on the same store
        self.assertEqual(rig.store.failures("dev-A"), 1)
        with self.assertRaises(H.AttemptFailed):
            a.commit()
        self.assertEqual(rig.store.failures("dev-A"), 1)

    def test_partly_readable_record_keeps_its_count(self):
        """Attempts: "MUST treat that device as having a count of at least one"; a count still readable is not lowered."""
        rig = self.mkrig()
        d = H._fresh()
        d["devices"]["dev-A"] = {"failures": 7, "warned": 0, "open": "junk"}
        json.dump(d, open(rig.store_path, "w"))
        self.assertEqual(H.Store(rig.store_path).failures("dev-A"), 7)
        d["devices"]["dev-A"] = {"failures": "junk"}
        json.dump(d, open(rig.store_path, "w"))
        self.assertEqual(H.Store(rig.store_path).failures("dev-A"), 1)

    def test_rho_request_is_dropped_when_the_attempt_ends(self):
        """Host randomness: "The host SHOULD erase it when the attempt ends."""
        rig = self.mkrig()
        a = rig.host.start(rig.request_bytes)
        a.commit()
        a.reveal()
        self.assertIsNone(a._req2)


class EdgeCases(LifeBase):
    """Attempt records, the failed mark, link exceptions and the state after a confirmed decline."""

    def test_two_open_attempts_have_distinct_records_and_both_count_at_recovery(self):
        """Attempts: "At startup, an attempt still recorded as open counts as failed\"; each attempt has its own record."""
        rig = self.mkrig()
        a1 = rig.host.start(rig.request_bytes)
        a2 = rig.host.start(rig.request_bytes)
        self.assertNotEqual(a1.seq, a2.seq)
        self.assertEqual(sorted(self.record(rig)["open"]), sorted([a1.seq, a2.seq]))
        rig.new_host()                                   # both attempts died with the process
        self.assertEqual(rig.store.failures("dev-A"), 2)
        self.assertEqual(self.record(rig)["open"], {})
        store = H.Store(rig.store_path)
        self.assertNotEqual(store.begin_attempt("dev-B", "t"), store.begin_attempt("dev-B", "t"))

    def test_uncounted_end_of_an_attempt_after_a_failure_keeps_the_failed_mark(self):
        """Attempts: a new attempt after a failure carries the same transaction unless the user chooses; an attempt that ends uncounted does not lift that."""
        for how in ("decline", "abandon"):
            ui = K.AckUI(declined=True, unrelated=True)
            rig = self.mkrig([T.timeout] * 4, ui=ui)
            with self.assertRaises(H.AttemptFailed):
                rig.host.sign(rig.request_bytes)
            self.assertEqual(rig.store.failures("dev-A"), 1)
            if how == "decline":
                rig.link.steps = [T.honest, T.refuse]
                with self.assertRaises(H.AttemptAbandoned):
                    rig.host.sign(rig.request_bytes)       # the same transaction, ended uncounted
            else:
                rig.host.start(rig.request_bytes).abandon()
            self.assertEqual(rig.store.failures("dev-A"), 1, how)
            self.assertEqual(rig.store.last("dev-A")["failed"], True, how)
            other = K.build_psbt(rig.inputs, version=0, fee=9000).serialize()
            with self.assertRaises(H.HostRefusal) as cm:
                rig.host.start(other)
            self.assertEqual(cm.exception.code, "transaction_changed_after_failure", how)
            rig.host.start(other, user_chose_change=True).abandon()

    def test_unreadable_store_that_cannot_be_set_aside_stops_the_host(self):
        """Attempts: unreadable records are kept aside; if they cannot be, the host stops and leaves the file as it is."""
        from unittest import mock
        path = os.path.join(self.tmp, "store.json")
        open(path, "wb").write(b"{not json")
        with mock.patch.object(H.os, "replace", side_effect=OSError("read-only")):
            with self.assertRaises(H.StoreError) as cm:
                H.Store(path)
        self.assertIn("cannot be set aside", str(cm.exception))
        self.assertEqual(open(path, "rb").read(), b"{not json")
        self.assertEqual([n for n in os.listdir(self.tmp) if "unreadable" in n], [])

    def test_link_value_error_is_a_failure_that_names_the_link(self):
        """Attempts: whatever a link raises is a failure event, charged once."""
        def boom(req, real):
            raise ValueError("framing error")
        rig = self.mkrig([boom], max_retries=0)
        with self.assertRaises(H.AttemptFailed) as cm:
            rig.host.sign(rig.request_bytes)
        self.assertEqual(cm.exception.reasons, ["LinkDisconnected", "retries_exhausted"])
        self.assertIn("link failed", str(cm.exception))
        self.assertIn("ValueError", str(cm.exception))
        self.assertEqual(rig.store.failures("dev-A"), 1)
        self.assertEqual(self.record(rig)["open"], {})
        # retried: each failed exchange is an event, one charge for the attempt
        rig = self.mkrig([boom, boom, T.honest, T.honest], max_retries=3)
        rig.host.sign(rig.request_bytes)
        self.assertEqual(rig.store.failures("dev-A"), 1)

    def test_state_after_a_confirmed_unrelated_decline(self):
        """Attempts: a decline left uncounted ends the attempt as Abandoned; after an earlier failure event it stays Failed, charged once."""
        ui = K.AckUI(declined=True, unrelated=True)
        rig = self.mkrig([T.honest, T.refuse], ui=ui)
        a = rig.host.start(rig.request_bytes)
        a.commit()
        with self.assertRaises(H.AttemptAbandoned):
            a.reveal()
        self.assertEqual(a.state, "abandoned")
        self.assertEqual(a.observed()["state"], "abandoned")
        self.assertFalse(a.counted)
        self.assertEqual(rig.store.failures("dev-A"), 0)
        a.abandon()                                              # already ended: nothing changes
        self.assertEqual(a.state, "abandoned")
        ui = K.AckUI(declined=True, unrelated=True)
        rig = self.mkrig([T.honest, T.timeout, T.refuse], ui=ui)
        a = rig.host.start(rig.request_bytes)
        a.commit()
        with self.assertRaises(H.AttemptFailed):
            a.reveal()
        self.assertEqual(a.state, "failed")
        self.assertEqual(a.observed()["state"], "failed")
        self.assertTrue(a.counted)
        self.assertEqual(rig.store.failures("dev-A"), 1)


class AfterFailure(LifeBase):
    def test_stop_after_rho_was_sent_is_a_failure(self):
        """Attempts: "Abandoned: before rho was sent, the user stopped or changed the request ... \" -- after the reveal a stop is a failure."""
        rig = self.mkrig()
        a = rig.host.start(rig.request_bytes)
        a.commit()

        def interrupt(link, req):
            raise KeyboardInterrupt()           # the user stops while the second request is going out
        rig.link.on_exchange = interrupt
        with self.assertRaises(KeyboardInterrupt):
            a.reveal()
        self.assertTrue(a.rho_sent)
        a.abandon()
        self.assertEqual((a.state, rig.store.failures("dev-A")), ("failed", 1))
        self.assertEqual(self.record(rig)["open"], {})
        self.assertEqual(a._rho, {})
        # before the reveal the same stop is an abandon
        rig = self.mkrig()
        a = rig.host.start(rig.request_bytes)
        a.commit()
        self.assertFalse(a.rho_sent)
        a.abandon()
        self.assertEqual((a.state, rig.store.failures("dev-A")), ("abandoned", 0))

    def test_stop_after_rho_sent_counts_once(self):
        rig = self.mkrig([T.honest, T.timeout, T.honest])
        a = rig.host.start(rig.request_bytes)
        a.commit()
        rig.link.on_exchange = lambda l, r: (_ for _ in ()).throw(KeyboardInterrupt()) if l.calls >= 2 else None
        with self.assertRaises(KeyboardInterrupt):
            a.reveal()
        a.abandon()
        a.abandon()
        self.assertEqual(rig.store.failures("dev-A"), 1)

    def test_new_attempt_after_failure_carries_the_same_transaction(self):
        """Attempts: "A new attempt after a failure SHOULD carry the same transaction unless the user chooses to change it\" and the host does not change fee or coins itself."""
        rig = self.mkrig([T.timeout] * 4)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        other = K.build_psbt(rig.inputs, version=0, fee=9000).serialize()      # a higher fee
        calls = rig.link.calls
        with self.assertRaises(H.HostRefusal) as cm:
            rig.host.start(other)
        self.assertEqual(cm.exception.code, "transaction_changed_after_failure")
        self.assertEqual(rig.link.calls, calls)
        self.assertEqual(self.record(rig)["open"], {})
        # a restart does not forget it
        rig.new_host()
        with self.assertRaises(H.HostRefusal):
            rig.host.start(other)
        # the same transaction is carried (after the warning)
        a = rig.host.start(rig.request_bytes)
        first = C.core_tx(C.parse(rig.link.transcript[0][0]))
        a.commit()
        self.assertEqual(C.core_tx(C.parse(rig.link.transcript[-1][0])), first)
        res = a.reveal()
        self.assertEqual(C.core_tx(C.parse(res.psbt)), C.core_tx(rig.psbt))

    def test_user_may_choose_to_change_after_failure(self):
        rig = self.mkrig([T.timeout] * 4)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        other = K.build_psbt(rig.inputs, version=0, fee=9000).serialize()
        a = rig.host.start(other, user_chose_change=True)          # explicit choice by the user
        a.abandon()
        self.assertEqual(rig.ui.warnings and len(rig.ui.warnings), 1, "the warning is still required")
        # the choice is also taken through the UI
        rig = self.mkrig([T.timeout] * 4)
        with self.assertRaises(H.AttemptFailed):
            rig.host.sign(rig.request_bytes)
        rig.ui.confirm_change_after_failure = lambda info: True
        rig.host.start(K.build_psbt(rig.inputs, version=0, fee=9000).serialize()).abandon()

    def test_transaction_rule_applies_to_an_attempt_recovered_as_failed(self):
        rig = self.mkrig()
        rig.host.start(rig.request_bytes)                           # recorded open, process dies
        rig.new_host()
        with self.assertRaises(H.HostRefusal) as cm:
            rig.host.start(K.build_psbt(rig.inputs, version=0, fee=9000).serialize())
        self.assertEqual(cm.exception.code, "transaction_changed_after_failure")

    def test_no_constraint_without_a_failure_or_after_success(self):
        rig = self.mkrig()
        rig.host.sign(rig.request_bytes)
        rig.host.sign(K.build_psbt(rig.inputs, version=0, fee=9000).serialize())          # no failure: any transaction
        rig = self.mkrig([T.timeout, T.honest, T.honest])
        rig.host.sign(rig.request_bytes)                                                    # failed once, then completed
        rig.host.sign(K.build_psbt(rig.inputs, version=0, fee=9000).serialize())          # a completed attempt ends the rule
        rig = self.mkrig()
        a = rig.host.start(rig.request_bytes)
        a.abandon()                                                                         # abandoned: no failure
        rig.host.start(K.build_psbt(rig.inputs, version=0, fee=9000).serialize()).abandon()


def rig_max(rig):
    return rig.max_retries


if __name__ == "__main__":
    unittest.main()
