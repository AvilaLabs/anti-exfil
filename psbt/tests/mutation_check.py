"""Disable one check at a time in a COPY of the code and confirm the named tests go red.

Usage: python3 -B -I psbt/tests/mutation_check.py [id ...]

The real source is never touched and no disabling hook exists in it: each mutant is a textual
patch applied to a copy under psbt/.work/mutants/<id>/, and the tests are run against that
copy through AE_HOST_SRC. A mutant that survives (tests stay green) is reported as SURVIVED and the
script exits 1. Output is one line per mutant, and a summary.
"""
import os
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE.parent
WORK = SRC / ".work" / "mutants"
PY = sys.executable
# a 2 GB memory scope where systemd-run works, none elsewhere
SCOPE = (["systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=2G", "-p", "MemorySwapMax=0"]
         if shutil.which("systemd-run") and subprocess.run(["systemd-run", "--user", "--scope", "-q", "true"], capture_output=True).returncode == 0 else [])

HR = "test_host_response."
LC = "test_lifecycle."
CU = "test_regressions."
SG = "test_signer."

# (id, file, [(old, new, count)], [tests], description)
M = []


def m(mid, file, old, new, tests, desc, count=1):
    pairs = old if isinstance(old, list) else [(old, new, count)]
    M.append((mid, file, pairs, tests, desc))


# ---------------------------------------------------------------- Handling a response
m("H01-core-tx", "host.py", "        if C.core_tx(r) != self.core:\n", "        if False:\n",
  [HR + "HandlingResponse.test_core_tx_changed_each_pass"], "core transaction comparison")
m("H02-commitment-missing", "host.py",
  '                if v is None:\n                    raise ResponseRejected("commitment_missing")\n',
  '                if False:\n                    raise ResponseRejected("commitment_missing")\n',
  [HR + "HandlingResponse.test_missing_commitment_and_signature", HR + "HandlingResponse.test_unmodified_echo_is_a_missing_commitment"],
  "requested commitment missing")
m("H03-signature-missing", "host.py", "                if pr.sigkey not in r.inputs[pr.index]:\n", "                if False:\n",
  [HR + "HandlingResponse.test_missing_commitment_and_signature"], "requested signature missing")
m("H04-hc-echo", "host.py", "                if typ == C.AE_HC and val != self._hc[(i, keyid)]:\n", "                if False:\n",
  [HR + "HandlingResponse.test_commitment_differs_from_held_host_commitment"], "host commitment differs from held")
m("H05-r0-changed", "host.py", "                if old != val:\n", "                if False:\n",
  [LC + "Bullets.test_r0_compared_across_all_responses_including_rejected", CU + "CodeBugs.test_cb2_repeated_step2_must_check_r0_unchanged"],
  "R0 compared across responses (CB-2)")
m("H06-r0-from-rejected", "host.py",
  "        try:\n            r = C.parse(data)\n        except C.PsbtError:\n            return\n        want = set(self.keys)\n",
  "        return\n        try:\n            r = C.parse(data)\n        except C.PsbtError:\n            return\n        want = set(self.keys)\n",
  [LC + "Bullets.test_r0_compared_across_all_responses_including_rejected", LC + "Bullets.test_r0_changed_in_second_pass_response"],
  "R0 observation of every response (disabled entirely)")
m("H07-second-pass-ae", "host.py", "                if phase == 2:\n                    raise ResponseRejected(\"ae_field_in_second_pass\")\n",
  "                if False:\n                    raise ResponseRejected(\"ae_field_in_second_pass\")\n",
  [HR + "HandlingResponse.test_second_pass_holds_any_ae_field"], "second-pass response holds any AE field")
m("H08-rho-first-pass", "host.py", "                if typ == C.AE_RHO:\n", "                if False:\n",
  [HR + "HandlingResponse.test_first_pass_holds_randomness"], "first-pass response holds rho")
m("H09-unrequested-pair", "host.py", "                if (i, keyid) not in want:\n", "                if False:\n",
  [HR + "HandlingResponse.test_field_for_pair_not_requested"], "AE field for a pair not requested")
m("H10-sig-removed", "host.py", "                    if k not in m:\n", "                    if False:\n",
  [HR + "HandlingResponse.test_signature_added_or_changed_in_second_pass"], "signature removed")
m("H10b-removal-always-allowed", "host.py", "                        if b\"\\x07\" in req or b\"\\x08\" in req:\n", "                        if True:\n",
  [HR + "HandlingResponse.test_signature_added_or_changed_in_second_pass"], "removal allowed on an unfinalized input")
m("H10c-removal-never-allowed", "host.py", "                        if b\"\\x07\" in req or b\"\\x08\" in req:\n", "                        if False:\n",
  [HR + "HandlingResponse.test_signature_dropped_from_finalized_input"], "removal refused on a finalized input")
m("H10d-witness-only", "host.py", "                        if b\"\\x07\" in req or b\"\\x08\" in req:\n", "                        if b\"\\x08\" in req:\n",
  [HR + "HandlingResponse.test_signature_dropped_from_finalized_input"], "final scriptSig not treated as finalized")
m("H10e-scriptsig-only", "host.py", "                        if b\"\\x07\" in req or b\"\\x08\" in req:\n", "                        if b\"\\x07\" in req:\n",
  [HR + "HandlingResponse.test_signature_dropped_from_finalized_input"], "final witness not treated as finalized")
m("H11-sig-changed", "host.py", "                    if m[k] != req[k]:\n", "                    if False:\n",
  [HR + "HandlingResponse.test_signature_added_or_changed_in_first_pass", HR + "HandlingResponse.test_signature_added_or_changed_in_second_pass"],
  "signature changed")
m("H12-sig-added", "host.py", "                elif not (phase == 2 and (i, k) in sigkeys):\n", "                elif False:\n",
  [HR + "HandlingResponse.test_signature_added_or_changed_in_first_pass", HR + "HandlingResponse.test_ordinary_signature_is_refused_no_fallback"],
  "signature added")
m("H13-sig-added-unrequested-allowed", "host.py", "                elif not (phase == 2 and (i, k) in sigkeys):\n", "                elif not (phase == 2):\n",
  [HR + "HandlingResponse.test_signature_added_or_changed_in_second_pass"],
  "any added signature allowed in second pass")
# ---------------------------------------------------------------- Step 4 (protocol step 5)
m("V01-der", "host.py", '            except S.SpendError:\n                raise ResponseRejected("bad_der")\n',
  "            except S.SpendError:\n                r, s, hb = int.from_bytes(field[8:40], 'big'), int.from_bytes(field[-33:-1], 'big'), field[-1]\n",
  [HR + "HandlingResponse.test_der_must_be_strict"], "strict DER")
m("V02-ecdsa-sighash", "host.py", "            if hb != pr.sighash:\n", "            if False:\n",
  [HR + "HandlingResponse.test_wrong_sighash_byte_each_scheme"], "expected sighash type, ECDSA")
m("V03-tap-length", "host.py", "        if len(field) != want:\n", "        if False:\n",
  [HR + "HandlingResponse.test_wrong_sighash_byte_each_scheme"], "BIP340 signature length")
m("V04-tap-sighash", "host.py", "        if pr.sighash != 0 and field[64] != pr.sighash:\n", "        if False:\n",
  [HR + "HandlingResponse.test_wrong_sighash_byte_each_scheme"], "expected sighash type, BIP340")
m("V05-ecdsa-verify", "host.py", "            if not AE.ecdsa_host_verify(pr.pk, pr.message, rho, r0, sig):\n", "            if False:\n",
  [HR + "HandlingResponse.test_valid_signature_with_wrong_nonce", HR + "HandlingResponse.test_high_s_rejected",
   HR + "HandlingResponse.test_signature_by_another_key_or_message"], "ECDSA step 5")
m("V06-bip340-verify", "host.py", "        if not AE.host_verify(pr.pk, pr.message, rho, r0, sig):\n", "        if False:\n",
  [HR + "HandlingResponse.test_valid_signature_with_wrong_nonce", HR + "HandlingResponse.test_flipped_bits"], "BIP340 step 5")
m("V08-reject-all", "host.py", "            verified[k] = self._verify(pr, field, self._rho[k], self._r0[k])\n",
  "            try:\n                verified[k] = self._verify(pr, field, self._rho[k], self._r0[k])\n            except ResponseRejected:\n                continue\n",
  [HR + "HandlingResponse.test_reject_every_signature_if_one_fails"], "reject every signature when one fails")
# ---------------------------------------------------------------- steps 5-6 and 3
m("R01-copy-response", "host.py",
  [("        r = self._check(data, 2)\n        verified = {}\n", "        r = self._check(data, 2)\n        self._resp = r\n        verified = {}\n", 1),
   ("        data = out.serialize()\n        signed =", "        out.inputs = [dict(m) for m in self._resp.inputs]\n        out.outputs = [dict(m) for m in self._resp.outputs]\n        out.glob = dict(self._resp.glob)\n        data = out.serialize()\n        signed =", 1)],
  None, [HR + "HandlingResponse.test_other_differences_ignored_and_never_copied",
         HR + "HandlingResponse.test_result_holds_only_rebuilt_fields_and_no_ae_fields"],
  "result copied from the response instead of rebuilt")
m("R02-v2-flags", "host.py", "                C.apply_modifiable_update(out.glob, pr.sighash)\n", "                pass\n",
  [HR + "HandlingResponse.test_v2_flag_updates_on_hosts_own_psbt"], "host applies BIP 370 flag updates")
m("R03-step3-tx", "host.py", "            if C.core_tx(p) != self.core:\n", "            if False:\n",
  [HR + "ChoosingPairs.test_step3_transaction_change_alone"], "step 3 same transaction")
m("R04-step3-pairs", "host.py", "            if [(pr.index, pr.keyid) for pr in pairs] != self.keys or \\\n                    any(a.message != b.message for a, b in zip(pairs, self.pairs)):\n",
  "            if False:\n",
  [HR + "ChoosingPairs.test_step3_same_transaction_and_pair_set"], "step 3 same pair set")
# ---------------------------------------------------------------- pair choice
m("PA01-preexisting-ae", "host.py", "            if C.ae_entries(m):\n", "            if False:\n",
  [HR + "ChoosingPairs.test_preexisting_ae_fields"], "host PSBT already holds AE fields")
m("PA02-no-pairs", "host.py", "        if not pairs:\n            raise HostRefusal(\"no_pairs\"", "        if False:\n            raise HostRefusal(\"no_pairs\"",
  [HR + "ChoosingPairs.test_ambiguous_or_unsupported"], "no pairs remain")
m("PA03-skip-signed", "host.py", "                if sigkey in m:\n", "                if False:\n",
  [HR + "ChoosingPairs.test_skip_already_signed_and_tell_user"], "skip already-signed pair")
m("PA04-keypath-precedence", "host.py", "            else:\n                for k, v in m.items():\n                    if k[:1] == b\"\\x16\"",
  "            if True:\n                for k, v in m.items():\n                    if k[:1] == b\"\\x16\"",
  [HR + "ChoosingPairs.test_key_path_when_device_holds_internal_key"], "key path excludes script path")
m("PA05-cb1-duplicate-pairs", "host.py", "                cands.append(internal)\n",
  "                cands.extend(internal for k in w.keys if k[1:] == internal)\n",
  [CU + "CodeBugs.test_cb1_both_parity_forms_of_a_taproot_internal_key", HR + "ChoosingPairs.test_two_forms_of_one_xonly_key_make_one_pair"],
  "two parity forms make two pairs (CB-1)")
m("PA06b-hybrid", "host.py", "if len(pub) == 65 and pub[0] in (4, 6, 7):", "if len(pub) == 65 and pub[0] == 4:",
  [HR + "ChoosingPairs.test_every_encoding_of_a_device_key_in_a_derivation_record"], "hybrid encoding of a device key fails")
m("PA06c-no-leaf-note", "host.py", "                        if not leaves:\n", "                        if False:\n",
  [HR + "ChoosingPairs.test_record_with_no_leaf_forms_no_pair_and_is_reported"], "record with no leaf is reported")
m("PA06-uncompressed", "host.py", "                        if pub[1:33] in w.xonly:\n", "                        if False:\n",
  [HR + "ChoosingPairs.test_uncompressed_key_in_derivation_record"],
  "device key in an uncompressed record on an input with no pair is reported")
m("PA07-notify", "host.py", "        self.ui.notify_request(", "        (lambda info: None)(",
  [HR + "ChoosingPairs.test_notify_before_first_request", CU + "Unimplemented.test_um2_user_told_before_request"], "user told before request (UM-2)")
# ---------------------------------------------------------------- lifecycle
m("L01-record-before-hc", "host.py", "        seq = self.store.begin_attempt(dev, txh)  # durable BEFORE hc is sent\n",
  "        seq = '0'\n",
  [LC + "Bullets.test_attempt_recorded_open_before_hc_is_sent", LC + "Bullets.test_open_attempt_at_startup_counts_as_failed"],
  "attempt recorded durably before hc")
m("L03-count-once", "host.py", "        o = self.view(dev)[\"open\"].get(seq)\n        if o is None or o[\"counted\"]:\n            return False            # no open record: recovery has already charged this attempt\n", "",
  [LC + "Bullets.test_one_durable_increment_at_first_failure", LC + "Bullets.test_kill_between_every_durable_step"],
  "at most one increment per attempt")
m("L04-recover", "host.py", "                if not v[\"counted\"]:\n                    r[\"failures\"] += 1\n", "                pass\n",
  [LC + "Bullets.test_open_attempt_at_startup_counts_as_failed", LC + "Bullets.test_kill_between_every_durable_step"],
  "open attempt at startup counts as failed")
m("L05-recover-double", "host.py", "                if not v[\"counted\"]:\n", "                if True:\n",
  [LC + "Bullets.test_kill_between_every_durable_step"], "recovery counts an already-counted attempt twice")
m("L06-warn", "host.py", "        if self.store.needs_warning(dev):\n", "        if False:\n",
  [LC + "Bullets.test_warning_before_next_attempt_and_acknowledgement_covers_one", LC + "Bullets.test_no_silent_new_attempt_after_failure"],
  "warn before the next attempt")
m("L07-ack-scope", "host.py", "            r[\"warned\"] = r[\"failures\"]\n", "            r[\"warned\"] = 10 ** 9\n",
  [LC + "Bullets.test_acknowledged_attempt_that_fails_needs_a_new_acknowledgement"], "acknowledgement covers exactly one attempt")
m("L08-unreadable-all", "host.py", "            d[\"lost\"] = True\n", "            d[\"lost\"] = False\n",
  [LC + "Bullets.test_unreadable_records_count_as_a_failure"], "unreadable store counts as failure")
m("L09-unreadable-device", "host.py", "        elif not _valid_rec(r):\n", "        elif False:\n",
  [LC + "Bullets.test_unreadable_records_count_as_a_failure"], "unreadable device record counts as failure")
m("L10-retry-bound", "host.py", "                if tries > self.host.max_retries:\n", "                if False:\n",
  [LC + "Bullets.test_retries_are_bounded_and_reuse_rho"], "retries are bounded")
m("L11-same-rho", "host.py", "                resp = None\n                try:\n                    resp = self._exchange(req)\n",
  "                if phase == 2 and tries:\n                    self._rho = {k: secrets.token_bytes(32) for k in self._rho}\n                    req = self._request(C.AE_RHO, self._rho)\n                resp = None\n                try:\n                    resp = self._exchange(req)\n",
  [LC + "Bullets.test_retries_are_bounded_and_reuse_rho"], "retry reuses the same rho")
m("L12-abandon-charged", "host.py", "        else:\n            self.host.store.end_attempt(self.host.wallet.device_id, self.seq)\n            self.state = \"abandoned\"\n",
  "        else:\n            self._event('abandon')\n            self.host.store.end_attempt(self.host.wallet.device_id, self.seq)\n            self.state = \"abandoned\"\n",
  [LC + "Bullets.test_abandon_is_not_charged_and_failed_is"], "abandon is not charged")
m("L13-cancel", "host.py", "        self._event(\"cancelled\")\n        self._cancel = True\n", "        self._cancel = True\n",
  [LC + "Bullets.test_cancel_with_response_outstanding_is_a_failure"], "cancel with a response outstanding is a failure")
m("L14-unsolicited", "host.py", "            if take and take():\n", "            if False:\n",
  [LC + "Bullets.test_message_the_host_did_not_request"], "unsolicited message is a failure event")
m("L15-decline-always", "host.py", "        return ui.declined_on_device() is True and ui.decline_unrelated_to_display() is True\n",
  "        return True\n",
  [LC + "Bullets.test_decline_counts_unless_user_confirms_it_was_unrelated"], "decline needs the user's confirmation")
m("L15b-decline-related", "host.py", "        return ui.declined_on_device() is True and ui.decline_unrelated_to_display() is True\n",
  "        return ui.declined_on_device() is True\n",
  [LC + "Bullets.test_decline_counts_unless_user_confirms_it_was_unrelated"], "a decline related to the display must count")
m("L21-stop-after-rho", "host.py", "        if self.rho_sent:\n            self._event(\"stopped_after_reveal\")\n", "        if False:\n            self._event(\"stopped_after_reveal\")\n",
  [LC + "AfterFailure.test_stop_after_rho_was_sent_is_a_failure", LC + "AfterFailure.test_stop_after_rho_sent_counts_once"],
  "a stop after rho was sent is a failure")
m("L22-rho-flag", "host.py", "            self.rho_sent = True\n", "            pass\n",
  [LC + "AfterFailure.test_stop_after_rho_was_sent_is_a_failure"], "rho_sent is tracked")
m("L23-same-tx", "host.py", "        if last and last[\"failed\"] and last[\"tx\"] != txh:\n", "        if False:\n",
  [LC + "AfterFailure.test_new_attempt_after_failure_carries_the_same_transaction"], "same transaction after a failure")
m("L24-user-choice", "host.py", "            if not (user_chose_change or self.ui.confirm_change_after_failure({\"previous\": last[\"tx\"], \"new\": txh}) is True):\n",
  "            if False:\n",
  [LC + "AfterFailure.test_new_attempt_after_failure_carries_the_same_transaction"], "the user's choice is required")
m("L25-recovered-failed-mark", "host.py", "                r[\"last\"] = {\"tx\": v.get(\"tx\", \"\"), \"failed\": True}\n", "                pass\n",
  [LC + "AfterFailure.test_transaction_rule_applies_to_an_attempt_recovered_as_failed"], "recovered failure marks the transaction")
m("L26-completed-clears", "host.py", "            if completed and isinstance(r.get(\"last\"), dict):\n                r[\"last\"][\"failed\"] = False\n", "            pass\n",
  [LC + "AfterFailure.test_no_constraint_without_a_failure_or_after_success"], "a completed attempt ends the rule")
m("L27-decline-after-counted", "host.py", "                    if phase == 2 and self._decline_not_counted():\n",
  "                    if phase == 2 and not self.counted and self._decline_not_counted():\n",
  [LC + "Bullets.test_confirmed_decline_after_a_counted_failure_ends_the_attempt_charged_once"], "a confirmed decline ends the attempt even after a counted failure")
m("L28-discard-outside", "host.py", "        self.discard_unsolicited()\n        try:\n            p = C.parse(psbt_bytes)\n",
  "        try:\n            p = C.parse(psbt_bytes)\n",
  [LC + "Bullets.test_message_outside_any_attempt_is_discarded_and_charged_nothing"], "a message outside any attempt is discarded, not charged")
m("L29-poll-counts", "host.py", "        if n:\n            self._event(\"unsolicited\")\n        return n\n", "        return n\n",
  [LC + "Bullets.test_unsolicited_message_during_an_attempt_via_poll"], "an unsolicited message during an attempt is a failure event")
m("L30-ack-not-consumed", "host.py", "            r[\"warned\"] = r[\"failures\"]\n", "",
  [LC + "Bullets.test_acknowledgement_is_used_up_in_the_write_that_records_the_attempt"], "acknowledgement used up in the record write")
m("L31-reset-keeps-warned", "host.py", "            r[\"warned\"] = 0\n            r.pop(\"unreadable\", None)\n", "            r.pop(\"unreadable\", None)\n",
  [LC + "Bullets.test_reset_clears_a_pending_warning"], "a reset clears the pending warning")
m("L32-unreadable-two", "host.py", "kept >= 1 else 1\n", "kept >= 1 else 2\n",
  [LC + "Bullets.test_unreadable_records_count_as_a_failure"], "unreadable records count exactly one")
m("L33b-step2-own-budget", "host.py", "                            self._end_failed(\"cancelled\")\n                        continue\n", "                            self._end_failed(\"cancelled\")\n                        raise\n",
  [LC + "Bullets.test_failed_repeat_of_step2_leaves_the_step4_budget_alone"], "a failed repeat of step 2 leaves the step 4 budget alone")
m("C40-nonminimal-key-type", "psbt_codec.py", "        if k[0] >= 0xFD:\n", "        if False:\n",
  [SG + "Unsupported.test_non_minimal_key_type_fails"], "non-minimal key type fails")
m("S40-multisig-key-valid", "spend.py", "AE._parse33(d) is not AE._INF for op, d in keys", "d[0] in (2, 3) for op, d in keys",
  [SG + "Unsupported.test_multisig_key_must_be_valid"], "multisig keys must be valid points")
m("G40-purpose-check", "signer.py", "            self._check_purpose(p, pr)\n", "            pass\n",
  [SG + "Unsupported.test_path_purpose_of_the_other_scheme_fails"], "path purpose of the other scheme fails")
m("Y1-link-exception", "host.py", "        except Exception as e:      # whatever a link raises is a failure event\n            raise T.LinkDisconnected(\"link failed: %r\" % (e,))\n", "",
  [LC + "RuleFixes.test_any_link_exception_is_a_failure_event"], "any link exception is a failure event")
m("Y2-recover-own-device", "host.py", "    def recover(self, dev):\n", "    def recover(self, dev):\n        dev = next(iter(self.data[\"devices\"]), dev)\n",
  [LC + "RuleFixes.test_a_host_for_another_device_leaves_a_live_attempt_alone"], "recovery touches only this device")
m("Y3-count-after-recovery", "host.py", "        if o is None or o[\"counted\"]:\n", "        if o is not None and o[\"counted\"]:\n",
  [LC + "RuleFixes.test_failures_after_recovery_are_not_counted_again"], "no count once the open record is gone")
m("Y4-keep-count", "host.py", "            kept = kept if isinstance(kept, int) and not isinstance(kept, bool) and kept >= 1 else 1\n", "            kept = 1\n",
  [LC + "RuleFixes.test_partly_readable_record_keeps_its_count"], "a readable count is kept")
m("Y5-erase-req2", "host.py", "        self._r0 = {}\n        self._req2 = None\n", "        self._r0 = {}\n",
  [LC + "RuleFixes.test_rho_request_is_dropped_when_the_attempt_ends"], "the request holding rho is dropped")
m("Y6-duplicate-leaf", "host.py", "for leaf in dict.fromkeys(leaves):", "for leaf in leaves:",
  [HR + "RuleFixes.test_repeated_leaf_hash_is_one_pair"], "a repeated leaf hash is one pair")
m("Y7-fee-raw-error", "host.py", "        except (S.SpendError, C.PsbtError) as e:\n            raise HostRefusal(e.code, str(e))\n        self.ui.notify_request(", "        except S.SpendError as e:\n            raise HostRefusal(e.code, str(e))\n        self.ui.notify_request(",
  [HR + "RuleFixes.test_bad_utxo_on_an_input_with_no_pair_is_a_refusal"], "fee errors become refusals")
m("Y8-modifiable-parse", "psbt_codec.py", "        if b\"\\x06\" in g and len(g[b\"\\x06\"]) != 1:\n", "        if False:\n",
  [SG + "Unsupported.test_malformed_modifiable_flags_fail_before_any_prompt", HR + "RuleFixes.test_malformed_modifiable_flags_refused_before_any_request"], "malformed flags fail at parse")
m("Y9-optional-direct", "spend.py", "    if len(direct) != 1:\n", "    if len(direct) < 1:\n",
  [SG + "Unsupported.test_optional_form_counts_only_a_key_before_a_signature_opcode"], "exactly one direct push before a signature opcode")
m("L33-step2-budget", "host.py", " and self.commit_sends <= self.host.max_retries:\n", ":\n",
  [LC + "Bullets.test_repeated_step2_shares_the_step2_retry_budget"], "a repeated step 2 counts against the step 2 retry budget")
m("L16-fsync", "host.py", "            os.fsync(f.fileno())\n", "            pass\n",
  [LC + "Bullets.test_store_is_durable_and_atomic"], "file fsync")
m("L18-reset-no-confirm", "host.py", "        if self.ui.confirm_reset(text) is True:\n", "        if True:\n",
  [LC + "Bullets.test_reset_is_an_explicit_user_action_that_states_what_is_cleared"], "reset needs confirmation")
m("L19-failure-limit", "host.py", "        if self.failure_limit is not None and fails >= self.failure_limit:\n", "        if False:\n",
  [LC + "Bullets.test_failure_limit"], "failure limit")
m("L20-secrets", "host.py", "(lambda: secrets.token_bytes(32))", "(lambda: b'\\x07' * 32)",
  [LC + "Bullets.test_new_attempt_new_rho", LC + "Bullets.test_rho_comes_from_secrets"], "rho drawn from secrets")
# ---------------------------------------------------------------- signer
m("S01-hc", "signer.py", "            if second and C.AE_HC in t and t[C.AE_HC] != hc:\n", "            if False:\n",
  [SG + "SignerPhases.test_stale_commitments_fail"], "signer: host commitment differs")
m("S02-r0", "signer.py", "            if C.AE_R0 in t and t[C.AE_R0] != r0:\n", "            if False:\n",
  [SG + "SignerPhases.test_stale_commitments_fail"], "signer: nonce commitment differs")
m("S03-already-signed", "signer.py", "            if pr.sigkey in p.inputs[i]:\n", "            if False:\n",
  [SG + "SignerPhases.test_already_signed"], "signer: pair already signed")
m("S04-both-paths", "signer.py", "            if 32 in lens and 64 in lens:\n", "            if False:\n",
  [SG + "SignerPhases.test_both_paths_in_one_input"], "signer: key path and script path in one input")
m("S05-mixed", "signer.py", "        if second and len(second) != len(table):\n", "        if False:\n",
  [SG + "SignerPhases.test_mixed_phases_fail"], "signer: mixed phases")
m("S06-nonce-only", "signer.py", "        if not second and any(C.AE_HC not in t for t in table.values()):\n", "        if False:\n",
  [SG + "SignerPhases.test_nonce_only_fails"], "signer: only a nonce commitment")
m("S07-approval", "signer.py", "is not True:\n            raise SignerFail(\"not_approved\"", "is False:\n            raise SignerFail(\"not_approved\"",
  [SG + "SignerPhases.test_approval_rules"], "signer: approval must be exactly True")
m("S08-key-ownership", "signer.py", "        if AE.public_key(sk) != x:\n", "        if False:\n",
  [SG + "ValidationScope.test_key_path_secret_must_match_internal_key"], "signer: key-path secret belongs to declared internal key")
m("S09-strip", "signer.py", "            out.inputs[i] = C.strip_ae(out.inputs[i])\n", "            pass\n",
  [SG + "SignerPhases.test_second_pass_removes_every_ae_field"], "signer: remove every AE field on second pass")
# ---------------------------------------------------------------- sighash / validation scope / unsupported (spend.py)
def sp(mid, old, new, tests, desc, count=1):
    m(mid, "spend.py", old, new, tests, desc, count)


sp("X01-finalized", '    if b"\\x07" in m or b"\\x08" in m:\n', "    if False:\n", [SG + "ValidationScope.test_final_inputs"], "final scriptSig / witness")
sp("X02-nw-txid", "        if C.txid(pt) != h:\n", "        if False:\n", [SG + "ValidationScope.test_non_witness_utxo_must_hash_to_txid_and_hold_index"], "NON_WITNESS_UTXO hashes to txid")
sp("X03-nw-index", "        if ix >= len(pt.outs):\n", "        if False:\n", [SG + "ValidationScope.test_non_witness_utxo_must_hash_to_txid_and_hold_index"], "NON_WITNESS_UTXO has the index")
sp("X04-utxo-disagree", "        if cand is not None and cand != (val, sc):\n", "        if False:\n", [SG + "ValidationScope.test_missing_and_mismatched_utxo"], "UTXO fields agree")
sp("X05-missing-utxo", "    if cand is None:\n", "    if False:\n", [SG + "ValidationScope.test_missing_and_mismatched_utxo"], "UTXO present")
sp("X06-redeem", "        if redeem is None or hash160(redeem) != spk[2:22]:\n", "        if False:\n", [SG + "ValidationScope.test_redeem_and_witness_script_mismatch"], "redeem script matches")
sp("X07-witness-script", "        if script is None or C.sha256(script) != spk[2:]:\n", "        if False:\n", [SG + "ValidationScope.test_redeem_and_witness_script_mismatch"], "witness script matches (P2WSH)")
sp("X08-output-key", "        if qx != program:\n            raise SpendError(\"tap_output_key_mismatch\"", "        if False:\n            raise SpendError(\"tap_output_key_mismatch\"",
   [SG + "ValidationScope.test_taproot_output_key_mismatch"], "Taproot output key matches")
sp("X30-internal-key", "        if b\"\\x17\" in m and m[b\"\\x17\"] != xkey:\n", "        if False:\n",
   [SG + "ValidationScope.test_key_path_identifier_must_equal_present_internal_key"], "TAP_INTERNAL_KEY agrees with the key-path identifier")
sp("X31b-hybrid-record", "k[1] in (4, 6, 7) and k[2:34] in device_xonly", "k[1] == 4 and k[2:34] in device_xonly",
   [SG + "Unsupported.test_derivation_record_with_uncompressed_device_key"], "signer: hybrid record of a device key fails")
sp("X31-uncompressed-record", "        if k[:1] == b\"\\x06\" and len(k) == 66 and k[1] in (4, 6, 7) and k[2:34] in device_xonly:\n", "        if False:\n",
   [SG + "Unsupported.test_derivation_record_with_uncompressed_device_key"], "signer: derivation record with an uncompressed device key fails")
sp("X09-control-block", "    if qx != program or par != (control[0] & 1):\n", "    if False:\n", [SG + "TaprootScriptPair.test_control_block_mismatch"], "control block computes output key")
sp("X10-depth", "    if (len(control) - 33) // 32 > 128:\n", "    if False:\n", [SG + "TaprootScriptPair.test_control_block_depth"], "at most 128 path elements")
sp("X11-leaf-ambiguous", "    if len(hits) > 1:\n", "    if False:\n", [SG + "TaprootScriptPair.test_leaf_ambiguous"], "exactly one leaf entry")
sp("X12-leaf-missing", "    if not hits:\n", "    if False:\n", [SG + "TaprootScriptPair.test_leaf_missing"], "leaf entry present")
sp("X13-leaf-version", "    if ver != 0xC0 or len(control) < 33 or control[0] & 0xFE != 0xC0:\n", "    if False:\n", [SG + "TaprootScriptPair.test_leaf_version"], "leaf version 0xC0")
sp("X14-op-success", "    if any(op in OP_SUCCESS and d is None for op, d in ops):\n", "    if False:\n", [SG + "Unsupported.test_op_success"], "no OP_SUCCESSx")
sp("X15-codesep", "    if any(op == OP_CODESEPARATOR and d is None for op, d in ops):\n", "    if False:\n",
   [SG + "Unsupported.test_codeseparator_ecdsa", SG + "Unsupported.test_codeseparator_taproot"], "no OP_CODESEPARATOR")
sp("X16-mapping", "    if n != 1:\n        raise SpendError(\"tap_mapping\"", "    if n < 1:\n        raise SpendError(\"tap_mapping\"",
   [SG + "TaprootScriptPair.test_key_mapping_zero_and_two"], "exactly one key-to-sigop mapping")
sp("X17-sighash-unsupported", "    if h not in (BIP340_TYPES if taproot else ECDSA_TYPES):\n", "    if False:\n", [SG + "SighashRules.test_unsupported_values"], "accepted sighash values")
sp("X18-zero-ecdsa", "    if h == 0 and not taproot:\n", "    if False:\n", [SG + "SighashRules.test_present_zero_ecdsa"], "present zero for ECDSA")
sp("X19-sighash-length", "    if len(v) != 4:\n        raise SpendError(\"sighash_bad_length\"", "    if False:\n        raise SpendError(\"sighash_bad_length\"",
   [SG + "SighashRules.test_bad_length"], "sighash field length")
sp("X20-single-legacy", "    if base == 3 and idx >= len(tx.outs):\n", "    if False:\n", [SG + "SighashRules.test_single_without_output"],
   "SIGHASH_SINGLE with no output (all three digests)", count=3)
sp("X21-musig-participant", "            if any(v[j + 1:j + 33] in device_xonly for j in range(0, len(v), 33)):\n", "            if False:\n",
   [SG + "Unsupported.test_musig2_participant"], "MuSig2 participant lists a device key")
sp("X22-musig-aggregate", "            if internal is not None and k[2:] == internal:\n", "            if False:\n",
   [SG + "Unsupported.test_musig2_aggregate_internal_key"], "internal key known aggregate")
sp("X24-legacy-nonwitness", "        if not nwv:\n", "        if False:\n", [SG + "ValidationScope.test_legacy_needs_non_witness_utxo"], "legacy needs NON_WITNESS_UTXO")
m("X26-optional", "spend.py",
  [("    if not optional_forms:\n        raise SpendError(\"optional_form_unsupported\", \"Taproot script path is an optional form\")",
    "    if False:\n        raise SpendError(\"optional_form_unsupported\", \"Taproot script path is an optional form\")", 1)],
  None, [SG + "Unsupported.test_optional_forms_can_be_refused"], "optional form refusal")
sp("X27-multisig-ambiguous", "            if hits == 1:\n                return \"multisig\"\n", "            if hits >= 1:\n                return \"multisig\"\n",
   [HR + "ChoosingPairs.test_ambiguous_or_unsupported"], "multisig key listed twice is ambiguous")
sp("X28-fee-verified", "    covered = any(pr.taproot_all_prevouts for pr in pairs)\n", "    covered = True\n",
   [SG + "ValidationScope.test_fee_verification_wording"], "fee verified only with amounts verified")
sp("X29-fee-nw", "        if not (nwv or covered):\n", "        if False:\n", [SG + "ValidationScope.test_fee_verification_wording", CU + "Unimplemented.test_um4_fee_not_presented_as_verified_without_amounts"],
   "unverified inputs listed")


def run(mid, file, pairs, tests, desc):
    d = WORK / mid
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    for f in SRC.glob("*.py"):
        shutil.copy(f, d / f.name)
    text = (d / file).read_text()
    for old, new, count in pairs:
        if text.count(old) != count:
            return "BAD-ANCHOR", "found %d of %d for %r" % (text.count(old), count, old[:60])
        text = text.replace(old, new)
    (d / file).write_text(text)
    code = ("import sys, unittest; sys.path.insert(0, %r); "
            "s = unittest.defaultTestLoader.loadTestsFromNames(%r); "
            "r = unittest.TextTestRunner(verbosity=0, failfast=True, stream=open('/dev/null', 'w')).run(s); "
            "print('RED' if not r.wasSuccessful() else 'GREEN', len(r.failures), len(r.errors))" % (str(HERE), tests))
    env = dict(os.environ, AE_HOST_SRC=str(d))
    try:
        p = subprocess.run(SCOPE + [PY, "-B", "-I", "-c", code], capture_output=True, text=True, timeout=300, env=env)
    except subprocess.TimeoutExpired:
        return "RED", "timeout (loop)"
    out = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else p.stderr[-200:]
    shutil.rmtree(d, ignore_errors=True)
    return out.split()[0], out


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    want = set(sys.argv[1:])
    bad = []
    n = 0
    for mid, file, pairs, tests, desc in M:
        if want and mid not in want:
            continue
        n += 1
        status, detail = run(mid, file, pairs, tests, desc)
        verdict = {"RED": "KILLED"}.get(status, "SURVIVED" if status == "GREEN" else status)
        print("%-34s %-9s %s" % (mid, verdict, desc))
        if verdict != "KILLED":
            bad.append((mid, verdict, detail))
    print("\n%d mutants, %d killed, %d not killed" % (n, n - len(bad), len(bad)))
    for b in bad:
        print("NOT KILLED:", b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
