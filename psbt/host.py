"""Anti-exfil PSBT host with durable attempt records. NOT FOR PRODUCTION.

Implements the PSBT document's Host and Handling-a-response sections and the
protocol's "Attempts and failures". The failure store is keyed by the device
identity in the host's own wallet data. `rho` and `R0_bytes` live in memory
only. Every refusal carries a reason code.
"""
import copy
import json
import os
import secrets

import anti_exfil as AE
import psbt_codec as C
import spend as S
import transport as T


class HostRefusal(Exception):
    """Refused before an attempt was recorded. Not an attempt."""

    def __init__(self, code, msg=None):
        super().__init__("%s: %s" % (code, msg or code))
        self.code = code


class WarningNotAcknowledged(HostRefusal):
    pass


class AttemptFailed(Exception):
    def __init__(self, code, msg=None, reasons=()):
        super().__init__("%s: %s" % (code, msg or code))
        self.code = code
        self.reasons = list(reasons)      # every failure event, in order; the first is the cause


class AttemptAbandoned(Exception):
    def __init__(self, code, msg=None):
        super().__init__("%s: %s" % (code, msg or code))
        self.code = code


class ResponseRejected(Exception):
    def __init__(self, code, msg=None):
        super().__init__("%s: %s" % (code, msg or code))
        self.code = code


class StoreError(Exception):
    pass


# ------------------------------------------------------------------ wallet
class Wallet:
    """The host's own wallet data: a device identity and the device's compressed keys."""

    def __init__(self, device_id, device_keys):
        self.device_id = device_id
        self.keys = frozenset(device_keys)
        for k in self.keys:
            if len(k) != 33 or AE._parse33(k) is AE._INF:
                raise ValueError("device keys must be valid 33-byte compressed keys")
        # canonical x-only identifiers: two forms of one x-only key are one identifier
        self.xonly = frozenset(k[1:] for k in self.keys)


class UI:
    """User interaction. The defaults refuse, so nothing proceeds by accident."""

    def notify_request(self, info):
        pass

    def notice(self, text):
        pass

    def warn(self, device_id, failures):
        return False

    def declined_on_device(self):
        """Did the user decline on the device? (first of two separate answers)"""
        return False

    def decline_unrelated_to_display(self):
        """Was that decline unrelated to what the device showed? (second answer)"""
        return False

    def confirm_reset(self, text):
        return False

    def confirm_change_after_failure(self, info):
        """The previous attempt failed and this request carries a different transaction.
        True only if the user chooses to change it."""
        return False


# ------------------------------------------------------------------- store
def _fresh():
    return {"format": 1, "lost": False, "seq": 0, "devices": {}}


def _valid_rec(r):
    return (isinstance(r, dict) and set(r) >= {"failures", "warned", "open"}
            and isinstance(r["failures"], int) and not isinstance(r["failures"], bool) and r["failures"] >= 0
            and isinstance(r["warned"], int) and not isinstance(r["warned"], bool) and r["warned"] >= 0
            and isinstance(r["open"], dict)
            and all(isinstance(v, dict) and isinstance(v.get("counted"), bool) for v in r["open"].values()))


class Store:
    """Durable JSON store: write temp file, fsync, atomic rename, fsync directory."""

    def __init__(self, path):
        self.path = os.fspath(path)
        self.data = self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return _fresh()
        try:
            with open(self.path, "rb") as f:
                d = json.loads(f.read().decode("utf-8"))
            if not (isinstance(d, dict) and d.get("format") == 1 and isinstance(d.get("lost"), bool)
                    and isinstance(d.get("seq"), int) and isinstance(d.get("devices"), dict)):
                raise ValueError("bad store schema")
            return d
        except (OSError, ValueError):
            # unreadable: keep the old file aside and remember that records were lost,
            # so every device without a readable record starts with one recorded failure
            n = 0
            while os.path.exists("%s.unreadable.%d" % (self.path, n)):
                n += 1
            try:
                os.replace(self.path, "%s.unreadable.%d" % (self.path, n))
            except OSError as e:
                raise StoreError("store unreadable and cannot be set aside: %s" % e)
            d = _fresh()
            d["lost"] = True
            self._write(d)
            return d

    def _write(self, data):
        tmp = self.path + ".tmp"
        raw = json.dumps(data, sort_keys=True).encode("utf-8")
        with open(tmp, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        fd = os.open(os.path.dirname(os.path.abspath(self.path)), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _mutate(self, fn):
        new = copy.deepcopy(self.data)
        out = fn(new)
        self._write(new)
        self.data = new
        return out

    def _rec(self, data, dev):
        r = data["devices"].get(dev)
        if r is None:
            r = {"failures": 1 if data["lost"] else 0, "warned": 0, "open": {}}
        elif not _valid_rec(r):
            kept = r.get("failures") if isinstance(r, dict) else None
            kept = kept if isinstance(kept, int) and not isinstance(kept, bool) and kept >= 1 else 1
            r = {"failures": kept, "warned": 0, "open": {}, "unreadable": True}
        data["devices"][dev] = r
        return r

    def view(self, dev):
        d = copy.deepcopy(self.data)
        return self._rec(d, dev)

    def needs_warning(self, dev):
        r = self.view(dev)
        return r["failures"] > r["warned"]

    def failures(self, dev):
        return self.view(dev)["failures"]

    def recover(self, dev):
        """At startup an attempt still recorded as open for this device counts as failed (once)."""
        def fn(d):
            r = self._rec(d, dev)
            for v in r["open"].values():
                if not v["counted"]:
                    r["failures"] += 1
                r["last"] = {"tx": v.get("tx", ""), "failed": True}
            r["open"] = {}
        rec = self.data["devices"].get(dev)
        if rec is not None and (not _valid_rec(rec) or rec["open"]):
            self._mutate(fn)

    def last(self, dev):
        """{"tx": hash of the core transaction, "failed": bool} for the latest attempt, or None."""
        last = self.view(dev).get("last")
        if isinstance(last, dict) and isinstance(last.get("tx"), str) and isinstance(last.get("failed"), bool):
            return last
        return None

    def begin_attempt(self, dev, tx):
        """Record an attempt as open and consume the acknowledgement, in one durable write.
        `tx` is a hash of the core transaction (not secret). A changed transaction after a failure
        has been chosen by the user by the time this is called, and clears the failed mark."""
        def fn(d):
            r = self._rec(d, dev)
            d["seq"] += 1
            r["warned"] = r["failures"]
            r["open"][str(d["seq"])] = {"counted": False, "tx": tx}
            last = r.get("last") if isinstance(r.get("last"), dict) else None
            same_failed = bool(last and last.get("failed") is True and last.get("tx") == tx)
            r["last"] = {"tx": tx, "failed": same_failed}
            return str(d["seq"])
        return self._mutate(fn)

    def count_failure(self, dev, seq):
        """One durable increment per attempt. Returns False if already counted."""
        o = self.view(dev)["open"].get(seq)
        if o is None or o["counted"]:
            return False            # no open record: recovery has already charged this attempt

        def fn(d):
            r = self._rec(d, dev)
            o = r["open"].get(seq)
            r["failures"] += 1
            if o is not None:
                o["counted"] = True
                r["last"] = {"tx": o.get("tx", ""), "failed": True}
            return True
        return self._mutate(fn)

    def end_attempt(self, dev, seq, completed=False):
        def fn(d):
            r = self._rec(d, dev)
            r["open"].pop(seq, None)
            if completed and isinstance(r.get("last"), dict):
                r["last"]["failed"] = False
        self._mutate(fn)

    def reset(self, dev):
        def fn(d):
            r = self._rec(d, dev)
            r["failures"] = 0
            r["warned"] = 0
            r.pop("unreadable", None)
        self._mutate(fn)


# ------------------------------------------------------------------- host
class Result:
    def __init__(self, psbt, signed, notes):
        self.psbt, self.signed, self.notes = psbt, signed, notes


class Host:
    def __init__(self, wallet, store, ui, link, max_retries=3, failure_limit=5, rho_source=None,
                 repeat_step2_on_retry=False, optional_forms=True):
        self.wallet, self.store, self.ui, self.link = wallet, store, ui, link
        self.max_retries, self.failure_limit = max_retries, failure_limit
        self._rho_source = rho_source or (lambda: secrets.token_bytes(32))
        self.repeat_step2_on_retry = repeat_step2_on_retry
        self.optional_forms = optional_forms
        self.store.recover(wallet.device_id)

    # -------------------------------------------------------- pair choice
    def select_pairs(self, p, notes):
        w = self.wallet
        pairs = []
        for i, m in enumerate(p.inputs):
            if C.ae_entries(m):
                raise HostRefusal("preexisting_ae_field", "host PSBT already holds anti-exfil fields")
            cands = []
            for k in m:
                if k[:1] == b"\x06":
                    pub = k[1:]
                    if len(pub) == 65 and pub[0] in (4, 6, 7):
                        if pub[1:33] in w.xonly:
                            notes.append("input %d: device key in an uncompressed derivation record" % i)
                    elif pub in w.keys:
                        cands.append(pub)
            internal = m.get(b"\x17")
            if internal is not None and internal in w.xonly:
                cands.append(internal)
            else:
                for k, v in m.items():
                    if k[:1] == b"\x16" and k[1:] in w.xonly:
                        leaves = self._leaf_hashes(v)
                        if not leaves:
                            notes.append("input %d: device key record lists no leaf and is not the internal key" % i)
                        for leaf in dict.fromkeys(leaves):
                            if any(kk[:1] == b"\x15" and len(vv) >= 1 and S.tap_leaf_hash(vv[-1], vv[:-1]) == leaf
                                   for kk, vv in m.items()):
                                cands.append(k[1:] + leaf)
                            else:
                                notes.append("input %d: leaf %s listed with no script" % (i, leaf.hex()))
            have = set(cands)
            for sk in (b"\x04", b"\x05"):
                for op, d in self._pushes(m.get(sk)):
                    if d is not None and len(d) == 33 and d in w.keys and d not in have:
                        notes.append("input %d: device key in script without a derivation record" % i)
            for keyid in cands:
                scheme = S.classify_keyid(keyid)
                sigkey = S.pair_sigkey(scheme, keyid)
                if sigkey in m:
                    notes.append("input %d: signature already present for a device key; skipped" % i)
                    continue
                try:
                    pairs.append(S.resolve_pair(p, i, keyid, w.xonly, self.optional_forms))
                except (S.SpendError, C.PsbtError) as e:
                    raise HostRefusal(e.code, str(e))
        if not pairs:
            raise HostRefusal("no_pairs", "no pairs remain")
        return pairs

    @staticmethod
    def _pushes(script):
        if script is None:
            return []
        try:
            return S.parse_script(script)
        except S.SpendError:
            return []

    @staticmethod
    def _leaf_hashes(v):
        try:
            n, o = C.read_compact(v, 0)
        except C.PsbtError:
            raise HostRefusal("bad_tap_derivation", "bad TAP_BIP32_DERIVATION")
        if len(v) - o < 32 * n + 4 or (len(v) - o - 32 * n) % 4:
            raise HostRefusal("bad_tap_derivation", "bad TAP_BIP32_DERIVATION")
        return [v[o + 32 * j:o + 32 * j + 32] for j in range(n)]

    # ------------------------------------------------------------- start
    def start(self, psbt_bytes, user_chose_change=False):
        """Validate, choose pairs, warn, record the attempt durably. Returns an Attempt.

        After a failed attempt the next one carries the same transaction unless the user chooses to
        change it (`user_chose_change`, or the UI confirms). The host never changes fee or coins itself."""
        self.discard_unsolicited()
        try:
            p = C.parse(psbt_bytes)
        except C.PsbtError as e:
            raise HostRefusal(e.code, str(e))
        notes = []
        try:
            pairs = self.select_pairs(p, notes)
        finally:
            for n in notes:             # the user hears about skipped pairs even if nothing is left to sign
                self.ui.notice(n)
        dev = self.wallet.device_id
        txh = C.sha256(C.ser_tx(C.core_tx(p))).hex()
        last = self.store.last(dev)
        if last and last["failed"] and last["tx"] != txh:
            if not (user_chose_change or self.ui.confirm_change_after_failure({"previous": last["tx"], "new": txh}) is True):
                raise HostRefusal("transaction_changed_after_failure",
                                  "the previous attempt failed; a different transaction needs the user's choice")
        fails = self.store.failures(dev)
        if self.failure_limit is not None and fails >= self.failure_limit:
            raise HostRefusal("failure_limit", "recorded failures reached the limit; reset needed")
        try:
            fee, fee_ok, _ = S.fee_info(p, pairs)
        except (S.SpendError, C.PsbtError) as e:
            raise HostRefusal(e.code, str(e))
        self.ui.notify_request({"anti_exfil": True, "pairs": len(pairs), "fee": fee, "fee_verified": fee_ok})
        if self.store.needs_warning(dev):
            if self.ui.warn(dev, fails) is not True:
                raise WarningNotAcknowledged("warning_not_acknowledged", "the user did not acknowledge the warning")
        rhos = {(pr.index, pr.keyid): self._rho_source() for pr in pairs}
        seq = self.store.begin_attempt(dev, txh)  # durable BEFORE hc is sent
        return Attempt(self, p, pairs, rhos, seq, notes)

    def discard_unsolicited(self):
        """A message the host did not request, outside any attempt, is discarded and charged to nothing."""
        take = getattr(self.link, "take_unsolicited", None)
        return len(take()) if take else 0

    def sign(self, psbt_bytes):
        a = self.start(psbt_bytes)
        a.commit()
        return a.reveal()

    def reset_failures(self):
        dev = self.wallet.device_id
        text = "Clear %d recorded failure(s) for device %s. Past failures will no longer be counted." % (
            self.store.failures(dev), dev)
        if self.ui.confirm_reset(text) is True:
            self.store.reset(dev)
            return True
        return False


class Attempt:
    def __init__(self, host, psbt, pairs, rhos, seq, notes):
        self.host, self.psbt, self.pairs, self.seq, self.notes = host, psbt, pairs, seq, notes
        self.keys = [(pr.index, pr.keyid) for pr in pairs]
        self._rho = rhos
        self._hc = {k: AE.ecdsa_host_commit(r) if len(k[1]) == 33 else AE.host_commit(r)
                    for k, r in rhos.items()}
        self._seen = {}            # nonce commitments received this attempt, any response, any validity
        self._r0 = {}
        self.core = C.core_tx(psbt)
        self.state = "ready"       # ready, committed, completed, abandoned, failed
        self.counted = False
        self.rho_sent = False
        self.reasons = []
        self.awaiting = False
        self._cancel = False
        self.commit_sends = 0       # sends of the first-pass request, repeats of step 2 included, against one budget
        self._req1 = self._request(C.AE_HC, self._hc)
        self._req2 = None

    # ---------------------------------------------------------- requests
    def _request(self, typ, values):
        out = self.psbt.clone()
        for (i, keyid), v in values.items():
            out.inputs[i][bytes([typ]) + keyid] = v
        return out.serialize()

    # ------------------------------------------------------ failure events
    def _event(self, reason):
        """First failure event of the attempt: one durable increment, at most once."""
        self.reasons.append(reason)
        self.host.store.count_failure(self.host.wallet.device_id, self.seq)   # the store counts once per attempt
        self.counted = True

    def _end_failed(self, code, msg=None):
        self._event(code)
        self.host.store.end_attempt(self.host.wallet.device_id, self.seq)
        self.state = "failed"
        self._erase()
        raise AttemptFailed(code, msg, self.reasons)

    def _erase(self):
        self._rho = {}
        self._r0 = {}
        self._req2 = None

    def abandon(self):
        """The user stopped or changed the request. Abandoned only before rho was sent, with no
        response outstanding and no failure recorded; after rho was sent a stop is a failure."""
        if self.awaiting:
            raise RuntimeError("a response is outstanding; use cancel()")
        if self.state in ("completed", "abandoned", "failed"):
            return
        if self.rho_sent:
            self._event("stopped_after_reveal")
            self.host.store.end_attempt(self.host.wallet.device_id, self.seq)
            self.state = "failed"
        elif self.counted:
            self.host.store.end_attempt(self.host.wallet.device_id, self.seq)
            self.state = "failed"
        else:
            self.host.store.end_attempt(self.host.wallet.device_id, self.seq)
            self.state = "abandoned"
        self._erase()

    def poll(self):
        """Handle messages that arrived with no request outstanding: during the attempt each is a
        failure event and the attempt continues; once it has ended they are discarded."""
        if self.state in ("completed", "abandoned", "failed"):
            return self.host.discard_unsolicited()
        take = getattr(self.host.link, "take_unsolicited", None)
        n = len(take()) if take else 0
        if n:
            self._event("unsolicited")
        return n

    def observed(self):
        """Read-only view of the attempt's lifecycle state for tools that check it from outside:
        nonce commitments received in any response, and the ones held for step 5."""
        return {"state": self.state, "counted": self.counted, "rho_sent": self.rho_sent, "awaiting": self.awaiting,
                "cancelled": self._cancel,
                "received_r0": frozenset(self._seen.values()), "held_r0": frozenset(self._r0.values())}

    def cancel(self):
        """Cancel on the host side. With a response outstanding this is a failure event."""
        if not self.awaiting:
            self.abandon()
            return
        self._event("cancelled")
        self._cancel = True

    # ---------------------------------------------------------- exchange
    def _exchange(self, req):
        if self._req2 is not None and req is self._req2:
            self.rho_sent = True
        if req is self._req1:
            self.commit_sends += 1
        self.awaiting = True
        try:
            return self.host.link.exchange(req)
        except T.LinkError:
            raise
        except Exception as e:      # whatever a link raises is a failure event
            raise T.LinkDisconnected("link failed: %r" % (e,))
        finally:
            self.awaiting = False
            take = getattr(self.host.link, "take_unsolicited", None)
            if take and take():
                self._event("unsolicited")       # a message the host did not request

    def _observe_r0(self, data):
        """Compare every nonce commitment received, including from responses about to be rejected."""
        try:
            r = C.parse(data)
        except C.PsbtError:
            return
        want = set(self.keys)
        for i, m in enumerate(r.inputs):
            for typ, keyid, val in C.ae_entries(m):
                if typ != C.AE_R0 or (i, keyid) not in want:
                    continue
                old = self._seen.setdefault((i, keyid), val)
                if old != val:
                    self._end_failed("r0_changed", "R0_bytes differs from a value received earlier")

    def _run(self, phase, req, handler):
        tries = 0
        while True:
            try:
                if phase == 2 and tries and self.host.repeat_step2_on_retry and self.commit_sends <= self.host.max_retries:
                    try:
                        self._probe_step2()
                    except (T.LinkError, ResponseRejected) as e:
                        # step 2 has its own budget, which commit_sends bounds, so this leaves tries alone
                        self._event(getattr(e, "code", type(e).__name__))
                        if self._cancel or isinstance(e, T.LinkCancelled):
                            self._end_failed("cancelled")
                        continue
                resp = None
                try:
                    resp = self._exchange(req)
                    if self._cancel:
                        raise T.LinkCancelled("cancelled")
                    self._observe_r0(resp)
                    return handler(resp)
                except T.DeviceError:
                    if phase == 2 and self._decline_not_counted():
                        # a confirmed-unrelated decline is not a failure event, and the user does not
                        # want the signature, so the attempt is not retried
                        self.host.store.end_attempt(self.host.wallet.device_id, self.seq)
                        self._erase()
                        if self.counted:
                            # an earlier failure event already charged this attempt; it stays Failed, charged once
                            self.state = "failed"
                            raise AttemptFailed("declined_on_device", "user confirmed an unrelated decline after an earlier failure",
                                                self.reasons)
                        # a decline left uncounted ends the attempt as Abandoned: no charge, no failed mark
                        self.state = "abandoned"
                        raise AttemptAbandoned("declined_on_device", "user confirmed an unrelated decline; not counted")
                    raise
            except (T.LinkError, ResponseRejected) as e:
                self._event(getattr(e, "code", type(e).__name__))
                if self._cancel or isinstance(e, T.LinkCancelled):
                    self._end_failed("cancelled")
                tries += 1
                if tries > self.host.max_retries:
                    self._end_failed("retries_exhausted", str(e))

    def _decline_not_counted(self):
        """Two separate answers. Only a decline the user confirms was unrelated to what the device
        showed may go uncounted; a decline because the device showed something unexpected counts."""
        ui = self.host.ui
        return ui.declined_on_device() is True and ui.decline_unrelated_to_display() is True

    def _probe_step2(self):
        resp = self._exchange(self._req1)
        self._observe_r0(resp)
        self._check(resp, 1)

    # ------------------------------------------------------------ step 1-2
    def commit(self):
        if self.state != "ready":
            raise RuntimeError("commit() from state %s" % self.state)
        self._run(1, self._req1, self._handle1)
        self.state = "committed"

    def _handle1(self, data):
        r = self._check(data, 1)
        for k in self.keys:
            v = r.inputs[k[0]][bytes([C.AE_R0]) + k[1]]      # _check has already required it
            if len(v) != 33 or AE._parse33(v) is AE._INF:
                raise ResponseRejected("bad_commitment")
            self._r0[k] = v
        return r

    # ------------------------------------------------------------ step 3-4
    def reveal(self, host_psbt=None):
        if self.state != "committed":
            raise RuntimeError("reveal() from state %s" % self.state)
        if host_psbt is not None:
            self._same_request(host_psbt)
        self._req2 = self._request(C.AE_RHO, self._rho)
        self._result = None
        self._run(2, self._req2, self._handle2)
        return self._finish()

    def _same_request(self, host_psbt):
        try:
            p = C.parse(host_psbt)
            if C.core_tx(p) != self.core:
                raise HostRefusal("request_changed", "transaction changed")
            pairs = self.host.select_pairs(p, [])
            if [(pr.index, pr.keyid) for pr in pairs] != self.keys or \
                    any(a.message != b.message for a, b in zip(pairs, self.pairs)):
                raise HostRefusal("request_changed", "pair set changed")
        except (HostRefusal, C.PsbtError) as e:
            self.abandon()          # end the attempt, erase values; the caller starts over with new rho
            raise AttemptAbandoned("request_changed", str(e))

    def _handle2(self, data):
        r = self._check(data, 2)
        verified = {}
        for pr in self.pairs:
            k = (pr.index, pr.keyid)
            field = r.inputs[pr.index][pr.sigkey]
            verified[k] = self._verify(pr, field, self._rho[k], self._r0[k])
        self._result = verified      # only after every signature passed

    @staticmethod
    def _verify(pr, field, rho, r0):
        """Step 5. Returns the values to rebuild the field from: (r, s) or sig64."""
        if pr.scheme == "ecdsa":
            try:
                r, s, hb = S.parse_der_sig(field)
            except S.SpendError:
                raise ResponseRejected("bad_der")
            if hb != pr.sighash:
                raise ResponseRejected("wrong_sighash")
            if r >= 1 << 256 or s >= 1 << 256:
                raise ResponseRejected("bad_der")
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            if not AE.ecdsa_host_verify(pr.pk, pr.message, rho, r0, sig):
                raise ResponseRejected("verify_failed")
            return (r, s)
        want = 64 if pr.sighash == 0 else 65
        if len(field) != want:
            raise ResponseRejected("bad_sig_length")
        if pr.sighash != 0 and field[64] != pr.sighash:
            raise ResponseRejected("wrong_sighash")
        sig = field[:64]
        if not AE.host_verify(pr.pk, pr.message, rho, r0, sig):
            raise ResponseRejected("verify_failed")
        return sig

    def _finish(self):
        out = self.psbt.clone()
        for pr in self.pairs:
            v = self._result[(pr.index, pr.keyid)]
            out.inputs[pr.index][pr.sigkey] = (S.sigfield("ecdsa", pr.sighash, v[0], v[1])
                                               if pr.scheme == "ecdsa" else S.sigfield("bip340", pr.sighash, v))
        if out.version == 2:
            for pr in self.pairs:
                C.apply_modifiable_update(out.glob, pr.sighash)
        data = out.serialize()
        signed = [(pr.index, pr.keyid) for pr in self.pairs]
        self.host.store.end_attempt(self.host.wallet.device_id, self.seq, completed=True)
        self.state = "completed"
        self._erase()
        return Result(data, signed, self.notes)

    # ------------------------------------------------- handling a response
    def _check(self, data, phase):
        """Fail the response if any condition under 'Handling a response' holds."""
        try:
            r = C.parse(data)
        except C.PsbtError as e:
            raise ResponseRejected("malformed", str(e))
        if C.core_tx(r) != self.core:
            raise ResponseRejected("core_tx_changed")
        want = set(self.keys)
        sigkeys = {(pr.index, pr.sigkey) for pr in self.pairs}
        for i, m in enumerate(r.inputs):
            for typ, keyid, val in C.ae_entries(m):
                if phase == 2:
                    raise ResponseRejected("ae_field_in_second_pass")
                if typ == C.AE_RHO:
                    raise ResponseRejected("rho_in_first_pass")
                if (i, keyid) not in want:
                    raise ResponseRejected("unrequested_pair")
                if typ == C.AE_HC and val != self._hc[(i, keyid)]:
                    raise ResponseRejected("commitment_differs")
        for i, m in enumerate(r.inputs):
            req = self.psbt.inputs[i]
            for k in set(m) | set(req):
                if k[:1] not in (b"\x02", b"\x13", b"\x14"):
                    continue
                if k in req:
                    if k not in m:
                        if b"\x07" in req or b"\x08" in req:
                            continue            # libraries drop these from a finalized input
                        raise ResponseRejected("signature_removed")
                    if m[k] != req[k]:
                        raise ResponseRejected("signature_changed")
                elif not (phase == 2 and (i, k) in sigkeys):
                    raise ResponseRejected("signature_added")
        if phase == 1:
            for k in self.keys:
                v = r.inputs[k[0]].get(bytes([C.AE_R0]) + k[1])
                if v is None:
                    raise ResponseRejected("commitment_missing")
        else:
            for pr in self.pairs:
                if pr.sigkey not in r.inputs[pr.index]:
                    raise ResponseRejected("signature_missing")
        return r
