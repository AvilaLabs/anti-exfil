"""Explicit-state model of the host lifecycle, the ground-truth
judge for invariants I1..I15, and one deliberately broken variant per invariant.

Spec references are line numbers in spec/bip-anti-exfil.md, cited as L<n>; later edits may have
moved lines. The undetermined points are settled the way this model reads them, except where the
results file's spec_undetermined says otherwise. The invariants I1..I15 are the ones judge() checks.

Split of roles
  SpecModel   the spec text as a host state machine (what a correct host does).
  judge()     the invariants, written from the invariants only. It sees events and
              observations (the Obs contract in adapter.py), never model state,
              so the same judge can score a real host through an adapter.
  MUTANTS     SpecModel subclasses that each break exactly one invariant (controls).

Durable (survives restart): D_count, D_owed, D_open. Everything else is volatile.
The device is scripted and never restarts.
"""
from __future__ import annotations

from typing import NamedTuple, Optional

SPEC = 'spec/bip-anti-exfil.md'

HOST_EVENTS = ('begin_attempt', 'send_commit', 'send_reveal', 'user_approve_new',
               'user_cancel', 'user_edit', 'user_reset', 'restart',
               'restart_unreadable')
DEV_EVENTS = ('recv_R0_1', 'recv_R0_2', 'rej_R0_1', 'rej_R0_2', 'bad_R0',
              'recv_sig', 'recv_sig_bad', 'dev_refuse', 'dev_timeout',
              'dev_unsolicited', 'user_decline')
EVENTS = HOST_EVENTS + DEV_EVENTS

INVARIANTS = tuple('I%d' % i for i in range(1, 16))

# Events a device can only produce while a request of that kind is outstanding.
_NEEDS_COMMIT = ('recv_R0_1', 'recv_R0_2', 'bad_R0')
_NEEDS_REVEAL = ('recv_sig', 'recv_sig_bad', 'user_decline')
_NEEDS_ANY = ('rej_R0_1', 'rej_R0_2', 'dev_refuse', 'dev_timeout')

# Points where the spec text does not decide a transition. Each is an explicit,
# labelled choice in the model (never silent). Quotes are lines of the spec file.
SPEC_UNDETERMINED = {
    'U1-ACK-LIFETIME': (
        'Spec: "An acknowledgement covers exactly one new attempt." It does not say '
        'whether an acknowledgement given but not yet used survives a restart, or is '
        'voided by a later failure. Model: it lives in memory only, so a restart voids '
        'it (the safe direction).'),
    'U2-WARNED-WHEN': (
        'Spec: "If the failure count has risen since the host last warned". Whether the '
        'host has "warned" when the warning is shown or when the user acknowledges it is '
        'not stated; if shown, a restart between warning and acknowledgement silently '
        'clears the requirement. Model: warned means acknowledged and consumed by the '
        'attempt that follows.'),
    'U3-RESET-OWED': (
        'Spec: "The count resets only by an explicit user action that states what is '
        'being cleared." It requires a warning when the count "has risen since the '
        'host last warned". After a reset it is not stated whether the next attempt '
        'still needs a warning. Model (cfg.reset_clears_owed, default True): a reset '
        'clears the owed warning. I3 "after any failure" read literally would keep it.'),
    'U4-UNSOLICITED-IDLE': (
        'It lists "a message the host did not request" as a failure event, and '
        'adds one "at the first failure event in an attempt". A message arriving when no '
        'attempt is open has no attempt to charge. Model: ignored, no charge.'),
    'U5-UNSOLICITED-OUTSTANDING': (
        'It does not say whether an unrequested message arriving while a different '
        'response is outstanding answers that request. Model: the unsolicited event '
        'is only produced when nothing is outstanding.'),
    'U6-UNREADABLE-COUNT': (
        'Spec: "A host that cannot read its records for a device MUST treat that device '
        'as having a recorded failure." The prior count is unreadable by definition, so '
        'the count after the event is not determined, and I8/I15 cannot be judged '
        'numerically. Model: the unreadable record stands for a read fault of a record '
        'that still exists, and one failure is added once (not once for the record and '
        'once for any open attempt).'),
    'U7-DECLINE-ATTEMPT': (
        'Spec: "need not count a decline the user confirms was unrelated". Whether the '
        'attempt then counts as Abandoned (the spec requires "no response outstanding", but a '
        'refusal is a response) or Failed is not stated, and "exactly once '
        'for an attempt with any failure event" (I10) conflicts with not counting. '
        'Model: the attempt ends, count unchanged, I10 exempts this event.'),
    'U8-RETRY-TRIGGER': (
        'Spec: "the host MAY retry a bounded number of times. Three retries per step is a '
        'reasonable default." It does not say whether a repeat send without a preceding '
        'failure is a retry, or what "per step" means for step 3 and 4 together. Model: '
        'a retry is a repeat send after a failure event; commit and reveal each have their '
        'own budget of cfg.B retries.'),
    'U9-WRITE-ATOMICITY': (
        'Spec: "add one, durably, at the first failure event ... at most once per '
        'attempt" with "At startup, an attempt still recorded as open counts as '
        'failed". If the increment and the attempt record are separate writes, a restart '
        'between them charges twice. The text does not require one atomic write. Model: '
        'one atomic write (count, owed flag and record state together).'),
    'U10-MARKED-RESTART': (
        'Spec: "It is not started until the host has durably recorded it as open" with '
        '"an attempt still recorded as open counts as failed". A restart after the record '
        'and before hc is sent charges a failure although the device saw nothing. Model: '
        'charged, as the text reads.'),
    'U11-STEP2-AFTER-REVEAL': (
        'It allows repeating step 3 and 4 "after a repeated step 2 returns an unchanged '
        'R0_bytes". It does not say whether a repeated step 2 is required, optional, or '
        'itself counted against the budget. Model: optional; own budget.'),
}


class Cfg(NamedTuple):
    B: int = 2                       # retries per step (the spec default is 3)
    reset_clears_owed: bool = True   # U3, the model's reading
    strict_reset: bool = False       # U3, the judge's reading: a reset never clears a warning


class State(NamedTuple):
    # durable
    D_count: int
    D_owed: bool                     # count rose since the last acknowledged warning
    D_open: Optional[str]            # None | 'open' | 'counted'
    # volatile
    att: Optional[int]               # rho id of the attempt; None when no attempt
    r0: Optional[int]                # R0 stored in memory
    rcv: frozenset                   # every R0 value received this attempt
    failed: bool
    revealed: bool
    cs: int                          # commit sends this attempt
    rs: int                          # reveal sends this attempt
    out: Optional[str]               # device-side: None | 'commit' | 'reveal'
    warn: bool                       # warning shown, waiting for acknowledgement
    ack: bool
    m: int
    last: Optional[int]              # most recent rho the device saw
    nxt: int
    forgive: bool                    # scratch for the I15 control; False in the model


S0 = State(0, False, None, None, None, frozenset(), False, False, 0, 0, None, False,
           False, 0, None, 1, False)


def new_obs(ev):
    return {'ev': ev, 'noop': False, 'sends': [], 'began': False, 'warned': False,
            'durable_leak': False, 'sig_accepted': False, 'reset_stated': None}


class SpecModel:
    """Spec host. Subclasses override single hooks or transitions to break one
    invariant. `cfg` carries the retry bound and reading choices."""
    name = 'model'

    def __init__(self, cfg: Cfg = Cfg()):
        self.cfg = cfg

    # ---- hooks (default = spec) ---------------------------------------------------
    record_at_begin = True       # I9 control turns this off
    reveal_needs_r0 = True       # I1a
    leak_rho = False             # I1b
    reuse_last_rho = False       # I2
    check_owed = True            # I3
    edit_clears_count = False    # I4a
    edit_clears_owed = False     # I4b
    success_erases = False       # I4c
    keep_on_replacement = False  # I5
    lax_step5 = False            # I7
    restart_charges_open = True  # I6a
    unreadable_charges = True    # I6b
    restart_zeroes = False       # I8
    charge_every_failure = False # I10a
    charge_at_end_only = False   # I10b
    restart_keeps_attempt = False  # I11
    cancel_out_free = False      # I12a
    post_reveal_free = False     # I12c
    abandon_charges = False      # I12b
    compare_stored_only = False  # I13
    unbounded_retries = False    # I14a
    send_slack = 0               # I14c: sends allowed beyond the bound
    # reading probes (not controls): other readings of undetermined text
    warned_on_show = False       # U2
    idle_unsolicited_charges = False   # U4
    ack_survives_restart = False       # U1
    exhaust_keeps_open = False   # I14b
    decline_decrements = False   # I15a
    decline_forgives_next = False  # I15b
    reset_unstated = False       # I15c

    # ---- helpers ------------------------------------------------------------------
    def initial(self):
        return S0

    def _charge(self, s):
        """Spec: one durable add; count, owed flag and record state in one write."""
        return s._replace(D_count=s.D_count + 1, D_owed=True,
                          D_open='counted' if s.D_open else None, ack=False, warn=False)

    def _end(self, s):
        """Spec: the attempt ends; rho and R0 are erased."""
        return s._replace(att=None, r0=None, rcv=frozenset(), failed=False,
                          revealed=False, cs=0, rs=0, out=None, D_open=None)

    def _fail_event(self, s):
        """Spec: failure event; one add at the first one in an attempt."""
        if s.att is None:
            return s
        if s.forgive:
            return s._replace(failed=True, forgive=False)
        if self.charge_every_failure:
            return self._charge(s._replace(failed=True))
        if s.failed:
            return s
        s = s._replace(failed=True)
        if self.charge_at_end_only:
            return s
        return self._charge(s)

    def _bound(self):
        return 10**6 if self.unbounded_retries else self.cfg.B

    def _after_failure(self, s):
        """Spec: "When retries run out, the attempt has failed" (U8)."""
        if s.att is None or self.exhaust_keeps_open:
            return s
        exhausted = (s.rs if s.revealed else s.cs) >= 1 + self._bound()
        if exhausted:
            return self._end_failed(s)
        return s

    def _end_failed(self, s):
        if self.charge_at_end_only and not s.D_open == 'counted':
            s = self._charge(s)
        return self._end(s)

    def device_enabled(self, s, ev):
        if ev in _NEEDS_COMMIT:
            return s.out == 'commit'
        if ev in _NEEDS_REVEAL:
            return s.out == 'reveal'
        if ev in _NEEDS_ANY:
            return s.out is not None
        if ev == 'dev_unsolicited':
            return s.out is None
        return True

    def step(self, s, ev):
        o = new_obs(ev)
        if not self.device_enabled(s, ev):
            o['noop'] = True
            s2 = s
        else:
            s2 = getattr(self, 't_' + ev)(s, o)
        o['count_before'] = s.D_count
        o['count_after'] = s2.D_count
        o['stored_r0'] = s2.r0
        o['attempt_open'] = s2.att is not None
        o['warning_pending'] = s2.D_owed
        return s2, o

    # ---- host transitions -----------------------------------------------------------
    def t_begin_attempt(self, s, o):
        # Spec: "A request the host refuses before making that record is not an attempt."
        # Spec: "the host MUST warn the user before starting another attempt".
        if s.att is not None:
            o['noop'] = True
            return s
        if self.check_owed and s.D_owed and not s.ack:
            o['warned'] = True
            o['noop'] = True
            if self.warned_on_show:
                return s._replace(warn=True, D_owed=False)
            return s._replace(warn=True)
        # Spec: "the host MUST make that record before sending hc"; one
        # acknowledgement covers exactly one new attempt.
        rho = s.last if (self.reuse_last_rho and s.last is not None) else s.nxt
        o['began'] = True
        return s._replace(att=rho, nxt=max(s.nxt, rho + 1), r0=None, rcv=frozenset(),
                          failed=False, revealed=False, cs=0, rs=0, out=None,
                          D_open='open' if self.record_at_begin else None,
                          D_owed=False, ack=False, warn=False)

    def t_send_commit(self, s, o):
        # Spec: step 1; record before hc; "MAY repeat step 2 with the same (m, hc)".
        if s.att is None or s.out is not None:
            o['noop'] = True
            return s
        if s.cs == 0:
            pass
        elif not (s.failed and s.cs < 1 + self._bound() + self.send_slack):
            o['noop'] = True
            return s
        o['sends'].append({'kind': 'commit', 'rho': s.att, 'open_durable': s.D_open is not None,
                           'r0_held': s.r0 is not None, 'r0_parsed': s.r0 is not None})
        return s._replace(cs=s.cs + 1, out='commit', last=s.att)

    def t_send_reveal(self, s, o):
        # Spec: "MUST NOT send rho until it has received R0_bytes, checked that parse33
        # accepts it, and stored it". Rho is never written to durable storage.
        # Spec: "SHOULD repeat steps 3 and 4 with the same rho" after a failure.
        if s.att is None or s.out is not None or s.cs == 0:
            o['noop'] = True
            return s
        if self.reveal_needs_r0 and s.r0 is None:
            o['noop'] = True
            return s
        if s.rs > 0 and not (s.failed and s.rs < 1 + self._bound() + self.send_slack):
            o['noop'] = True
            return s
        o['sends'].append({'kind': 'reveal', 'rho': s.att, 'open_durable': s.D_open is not None,
                           'r0_held': s.r0 is not None, 'r0_parsed': s.r0 is not None})
        o['durable_leak'] = self.leak_rho
        return s._replace(rs=s.rs + 1, revealed=True, out='reveal')

    def _got_r0(self, s, o, v, accepted):
        """A response carrying R0 value v. receive, parse and store; "MUST end the
        attempt as failed if R0_bytes differs from any value received for that attempt,
        including one in a response it rejected"."""
        s = s._replace(out=None)
        if self.compare_stored_only:
            differs = s.r0 is not None and v != s.r0
        else:
            differs = bool(s.rcv) and v not in s.rcv
        s = s._replace(rcv=s.rcv | {v})
        if differs:
            s = self._fail_event(s)
            if self.keep_on_replacement and s.revealed:
                return s._replace(r0=v)          # I5 control: replacement accepted
            return self._end(s)
        if accepted:
            if not self.record_at_begin and s.D_open is None:
                s = s._replace(D_open='open')    # I9 control: late record
            return s._replace(r0=v if s.r0 is None else s.r0)
        return self._after_failure(self._fail_event(s))     # Spec: rejected response

    def t_recv_R0_1(self, s, o):
        return self._got_r0(s, o, 1, True)

    def t_recv_R0_2(self, s, o):
        return self._got_r0(s, o, 2, True)

    def t_rej_R0_1(self, s, o):
        return self._got_r0(s, o, 1, False)

    def t_rej_R0_2(self, s, o):
        return self._got_r0(s, o, 2, False)

    def t_bad_R0(self, s, o):
        # Spec: "differs from any value received ..., whatever its form". Value 0 stands for a
        # malformed one, which is received and rejected.
        return self._got_r0(s, o, 0, False)

    def t_dev_refuse(self, s, o):
        # Spec: "a device error or refusal".
        return self._after_failure(self._fail_event(s._replace(out=None)))

    def t_dev_timeout(self, s, o):
        # Spec: "a timeout".
        return self._after_failure(self._fail_event(s._replace(out=None)))

    def t_dev_unsolicited(self, s, o):
        # Spec: "a message the host did not request" (U4, U5).
        if s.att is None:
            if self.idle_unsolicited_charges:
                return s._replace(D_count=s.D_count + 1, D_owed=True)
            o['noop'] = True
            return s
        return self._fail_event(s)

    def t_recv_sig(self, s, o):
        # Spec: step 5 passes; Completed; "A later success on that attempt
        # does not undo it."
        o['sig_accepted'] = True
        s = self._end(s._replace(out=None))
        if self.success_erases:
            s = s._replace(D_count=0, D_owed=False)
        return s

    def t_recv_sig_bad(self, s, o):
        # Spec: "MUST NOT use a signature that fails these checks"; failed host check.
        if self.lax_step5:
            o['sig_accepted'] = True
            return self._end(s._replace(out=None))
        return self._after_failure(self._fail_event(s._replace(out=None)))

    def t_user_approve_new(self, s, o):
        # Spec: acknowledgement of a shown warning.
        if s.warn and s.D_owed:
            return s._replace(ack=True)
        o['noop'] = True
        return s

    def _stop(self, s):
        """Spec: the user stopped or changed the request. Abandoned (free) only with
        no response outstanding and no failure recorded, and only before rho is sent
        ("before rho was sent"); with a response outstanding it is a failure event
        ("a cancellation on either side while a response is outstanding"), and after the
        reveal a stop is a failure ("Failed: anything else that ends it")."""
        if s.att is None:
            return s
        if s.out is not None or (s.revealed and not self.post_reveal_free):
            if not self.cancel_out_free:
                s = self._fail_event(s)
        elif not s.failed and self.abandon_charges:
            s = self._fail_event(s)
        return self._end(s)

    def t_user_cancel(self, s, o):
        if s.att is None:
            o['noop'] = True
            return s
        return self._stop(s)

    def t_user_edit(self, s, o):
        # Spec: "Changing the message, coins or fee ... do not clear this requirement".
        if self.edit_clears_count:
            s = s._replace(D_count=0)
        if self.edit_clears_owed:
            s = s._replace(D_owed=False)
        s = s._replace(m=(s.m + 1) % 3)
        return self._stop(s)

    def t_user_decline(self, s, o):
        # Spec: a decline the user confirms unrelated "need not" be counted (U7).
        s = s._replace(out=None)
        if self.decline_decrements:
            s = s._replace(D_count=max(0, s.D_count - 1))
        if self.decline_forgives_next:
            s = s._replace(forgive=True)
        return self._end(s)

    def t_user_reset(self, s, o):
        # Spec: "resets only by an explicit user action that states what is being cleared".
        o['reset_stated'] = not self.reset_unstated
        return s._replace(D_count=0, D_owed=False if self.cfg.reset_clears_owed else s.D_owed)

    def _wipe(self, s):
        return s._replace(att=None, r0=None, rcv=frozenset(), failed=False, revealed=False,
                          cs=0, rs=0, out=None, warn=False, ack=False)

    def t_restart(self, s, o):
        # Spec: "a restart ends the attempt"; "At startup, an attempt still recorded
        # as open counts as failed" (a 'counted' record adds nothing: once per attempt).
        n, owed = s.D_count, s.D_owed
        if s.D_open == 'open' and self.restart_charges_open:
            n, owed = n + 1, True
        if self.restart_zeroes:
            n = 0
        s2 = s._replace(D_count=n, D_owed=owed, D_open=None)
        if self.restart_keeps_attempt:
            return s2._replace(warn=False, ack=False, D_open=s.D_open, out=None)
        s3 = self._wipe(s2)
        if self.ack_survives_restart:
            s3 = s3._replace(ack=s.ack, warn=s.warn)
        return s3

    def t_restart_unreadable(self, s, o):
        # Spec: "A host that cannot read its records for a device MUST treat that device as
        # having a recorded failure" (U6).
        n = s.D_count + (1 if self.unreadable_charges else 0)
        return self._wipe(s._replace(D_count=n, D_owed=True if self.unreadable_charges else s.D_owed,
                                     D_open=None))

    # ---- state key ----------------------------------------------------------------
    def key(self, s):
        """(hashable host key, tuple of rho ids to canonicalise). The count enters the
        key capped at 2: behaviour depends on it only through deltas and zero."""
        k = (min(s.D_count, 2), s.D_owed, s.D_open, s.r0, s.rcv, s.failed, s.revealed,
             s.cs, s.rs, s.out, s.warn, s.ack, s.m, s.forgive, s.att is None,
             s.last is None)
        return k, (s.att, s.last)


# ------------------------------------------------------------------------------
# Ground truth. Built only from events and observations.

class Truth(NamedTuple):
    att: bool                    # an attempt is open
    rho: Optional[int]
    failed: bool                 # a failure event occurred in this attempt
    revealed: bool
    rcv: frozenset
    r0: Optional[int]            # first value accepted and stored
    cs: int
    rs: int
    out: Optional[str]
    owed: bool                   # a failure since the last acknowledged warning
    ack: bool
    warn: bool
    rest: Optional[int]          # rho of the attempt a restart ended
    nxt: int                     # ids below this are device-seen
    decl: bool                   # a confirmed decline has occurred (I15 "only that event")


T0 = Truth(False, None, False, False, frozenset(), None, 0, 0, None, False, False, False,
           None, 1, False)

CANCEL_FAMILY = ('user_cancel', 'user_edit')


def truth_key(t: Truth):
    return (t.att, t.failed, t.revealed, t.rcv, t.r0, t.cs, t.rs, t.out, t.owed, t.ack,
            t.warn, t.decl), (t.rho, t.rest)


def judge(t: Truth, ev: str, o: dict, cfg: Cfg):
    """Apply one event to the truth and return (truth', [(invariant, message)])."""
    V = []
    B = cfg.B
    att, rho, failed, revealed, rcv, r0 = t.att, t.rho, t.failed, t.revealed, t.rcv, t.r0
    cs, rs, out, owed, ack, warn, rest, nxt, decl = (t.cs, t.rs, t.out, t.owed, t.ack,
                                                    t.warn, t.rest, t.nxt, t.decl)
    exp = 0                       # charges the spec requires from this event
    allow_extra = 0               # charges the spec permits but does not require
    must_end = False
    clean_abandon = False
    differs_event = False

    def fail_event():
        nonlocal failed, exp, owed, ack, warn
        if att and not failed:
            failed = True
            exp = 1
            owed, ack, warn = True, False, False

    if o['durable_leak']:
        V.append(('I1', 'rho or R0 reached durable storage'))

    if ev == 'begin_attempt':
        if o['warned']:
            warn = owed
        if o['began']:
            if owed and not ack:
                V.append(('I3', 'new attempt after a failure without a warning acknowledgement'))
            att, rho, failed, revealed, rcv, r0 = True, None, False, False, frozenset(), None
            cs = rs = 0
            out = None
            owed, ack, warn = False, False, False
    elif ev in ('send_commit', 'send_reveal'):
        for sd in o['sends']:
            r = sd['rho']
            if sd['kind'] == 'commit':
                if not sd['open_durable']:
                    V.append(('I9', 'hc sent before the attempt was durably recorded as open'))
                if att and cs == 0:
                    if r < nxt:
                        V.append(('I2', 'fresh attempt uses device-seen rho %s' % r))
                    rho = r
                    nxt = max(nxt, r + 1)
                elif att:
                    if r != rho:
                        V.append(('I2', 'repeat commit carries rho %s, attempt rho is %s' % (r, rho)))
                else:
                    V.append(('I11' if r == rest else 'I2',
                              'commit with rho %s outside any open attempt (rho of attempt ended '
                              'by restart: %s)' % (r, rest)))
                cs += 1
                if cs > 1 + B:
                    V.append(('I14', 'commit sent %d times, bound is %d retries' % (cs, B)))
                out = 'commit'
            else:
                if not (sd['r0_held'] and sd['r0_parsed']) or r0 is None:
                    V.append(('I1', 'rho revealed before R0 was received, parsed and stored'))
                if att:
                    if rho is not None and r != rho:
                        V.append(('I2', 'reveal carries rho %s, attempt rho is %s' % (r, rho)))
                else:
                    V.append(('I11' if r == rest else 'I2',
                              'reveal with rho %s outside any open attempt (restart-ended: %s)' % (r, rest)))
                rs += 1
                if rs > 1 + B:
                    V.append(('I14', 'reveal sent %d times, bound is %d retries' % (rs, B)))
                revealed = True
                out = 'reveal'
    elif ev in ('recv_R0_1', 'recv_R0_2', 'rej_R0_1', 'rej_R0_2', 'bad_R0'):
        v = 0 if ev == 'bad_R0' else int(ev[-1])     # a malformed value is a value received
        accepted = ev.startswith('recv')
        out = None
        differs_event = bool(rcv) and v not in rcv
        rcv = rcv | {v}
        if differs_event:
            fail_event()
            must_end = True
        elif accepted:
            if r0 is None:
                r0 = v
        else:
            fail_event()
    elif ev in ('dev_refuse', 'dev_timeout', 'recv_sig_bad'):
        out = None
        fail_event()
        if ev == 'recv_sig_bad' and o['sig_accepted']:
            V.append(('I7', 'signature accepted although step 5 failed against the stored R0'))
    elif ev == 'recv_sig':
        out = None
        att = False
        must_end = True
    elif ev == 'dev_unsolicited':
        fail_event()
    elif ev == 'user_approve_new':
        if warn and owed:
            ack = True
    elif ev in CANCEL_FAMILY:
        if att:
            if out is not None or revealed:
                fail_event()
            elif not failed:
                clean_abandon = True
            must_end = True
    elif ev == 'user_decline':
        out = None
        decl = True
        if not failed and o['count_after'] > o['count_before']:
            allow_extra = 1
            owed, ack, warn = True, False, False
        must_end = True
    elif ev == 'user_reset':
        if o['reset_stated'] is False:
            V.append(('I15', 'count cleared without an explicit statement of what is cleared'))
        owed = owed and (cfg.strict_reset or not cfg.reset_clears_owed)
        ack = ack and owed
        warn = warn and owed
    elif ev in ('restart', 'restart_unreadable'):
        if att:
            rest = rho if rho is not None else rest
        if ev == 'restart' and att and not failed:
            exp = 1
            owed = True
        if ev == 'restart_unreadable':
            owed = True
        att = False
        out = None
        ack = warn = False
        failed = revealed = False
        rcv = frozenset()
        r0 = None
        cs = rs = 0
        rho = None
        if o['attempt_open']:
            V.append(('I11', 'host still holds an open attempt after a restart'))
    # retry budget after a failure that left the attempt open
    if (ev in ('rej_R0_1', 'rej_R0_2', 'bad_R0', 'dev_refuse', 'dev_timeout', 'recv_sig_bad')
            and att and not must_end):
        if (rs if revealed else cs) >= 1 + B:
            must_end = True
            if o['attempt_open']:
                V.append(('I14', 'retries ran out and the attempt is still open'))
    if must_end and att and ev not in ('restart', 'restart_unreadable'):
        if o['attempt_open'] and ev in ('rej_R0_1', 'rej_R0_2', 'recv_R0_1', 'recv_R0_2', 'bad_R0'):
            if differs_event:
                V.append(('I13', 'R0 %d differs from a value already received (%s) and the '
                                 'attempt did not end' % (v, sorted(t.rcv))))
                if t.revealed:
                    V.append(('I5', 'replacement R0 accepted after reveal'))
        if o['attempt_open'] and ev in CANCEL_FAMILY + ('user_decline',):
            V.append(('I12' if ev in CANCEL_FAMILY else 'I15',
                      '%s left the attempt open' % ev))
    if must_end:
        att = False
        failed = revealed = False
        rcv = frozenset()
        r0 = None
        rho = None
        cs = rs = 0
        out = None
    # I5: stored R0 must not change after reveal while the attempt continues
    if t.revealed and att and o['attempt_open'] and o['stored_r0'] != t.r0:
        V.append(('I5', 'stored R0 changed from %s to %s after reveal' % (t.r0, o['stored_r0'])))

    # ---- count (I4, I6, I8, I10, I12, I15) -------------------------------------
    delta = o['count_after'] - o['count_before']
    if ev == 'user_reset':
        if delta > 0:
            V.append(('I15', 'reset raised the count'))
    elif ev == 'restart_unreadable':
        # Spec: sets "a count of one". Records are gone, so nothing below one is
        # acceptable and nothing more can be asked.
        if o['count_after'] < 1:
            V.append(('I6', 'unreadable record left a count of %d' % o['count_after']))
    elif delta < 0:
        tag = ['I15']
        if ev == 'restart':
            tag.append('I8')
        if ev in ('user_edit', 'recv_sig'):
            tag.append('I4')
        for i in tag:
            V.append((i, '%s reduced the count by %d' % (ev, -delta)))
    else:
        lo, hi = exp, exp + allow_extra
        if delta > hi:
            tag = 'I12' if clean_abandon else 'I10'
            V.append((tag, '%s raised the count by %d, spec requires %d' % (ev, delta, exp)))
        elif delta < lo:
            if ev in CANCEL_FAMILY:
                tag = 'I12'
            elif ev == 'restart':
                tag = 'I6'
            else:
                tag = 'I10'
            V.append((tag, '%s raised the count by %d, spec requires %d' % (ev, delta, exp)))
            if decl and tag == 'I10':
                V.append(('I15', 'a failure went uncounted after an earlier confirmed decline'))
    if o.get('warning_pending') is False and owed and ev != 'user_reset':
        tag = 'I4' if ev in ('user_edit', 'recv_sig') else 'I3'
        V.append((tag, 'warning no longer pending after %s although a failure is unacknowledged' % ev))
    t2 = Truth(att, rho, failed, revealed, rcv, r0, cs, rs, out, owed, ack, warn, rest, nxt, decl)
    return t2, V


# ------------------------------------------------------------------------------
# Broken variants, at least one per invariant (the controls).

def _mut(name, **flags):
    return type(name, (SpecModel,), dict(flags, name=name))


MUTANTS = {
    'I1': [_mut('mut-I1a-reveal-before-R0', reveal_needs_r0=False),
           _mut('mut-I1b-rho-written-durably', leak_rho=True)],
    'I2': [_mut('mut-I2-reuse-last-rho', reuse_last_rho=True)],
    'I3': [_mut('mut-I3-no-warning', check_owed=False)],
    'I4': [_mut('mut-I4a-edit-clears-count', edit_clears_count=True),
           _mut('mut-I4b-edit-clears-warning', edit_clears_owed=True),
           _mut('mut-I4c-success-erases-failure', success_erases=True)],
    'I5': [_mut('mut-I5-replacement-kept', keep_on_replacement=True)],
    'I6': [_mut('mut-I6a-open-at-startup-free', restart_charges_open=False),
           _mut('mut-I6b-unreadable-free', unreadable_charges=False)],
    'I7': [_mut('mut-I7-lax-step5', lax_step5=True)],
    'I8': [_mut('mut-I8-restart-zeroes-count', restart_zeroes=True)],
    'I9': [_mut('mut-I9-record-after-hc', record_at_begin=False)],
    'I10': [_mut('mut-I10a-count-every-failure', charge_every_failure=True),
            _mut('mut-I10b-success-uncounts', charge_at_end_only=True)],
    'I11': [_mut('mut-I11-restart-keeps-attempt', restart_keeps_attempt=True)],
    'I12': [_mut('mut-I12a-cancel-outstanding-free', cancel_out_free=True),
            _mut('mut-I12b-clean-abandon-charged', abandon_charges=True)],
    'I13': [_mut('mut-I13-compare-stored-only', compare_stored_only=True)],
    'I14': [_mut('mut-I14a-unbounded-retries', unbounded_retries=True),
            _mut('mut-I14b-exhaustion-keeps-open', exhaust_keeps_open=True),
            _mut('mut-I14c-one-extra-send', send_slack=1)],
    'I15': [_mut('mut-I15a-decline-decrements', decline_decrements=True),
            _mut('mut-I15b-decline-forgives-next', decline_forgives_next=True),
            _mut('mut-I15c-reset-unstated', reset_unstated=True)],
}


# Reading probes: the honest model with one undetermined point read the other way
# (or the judge read strictly). A violation here is evidence of a spec gap.
READINGS = {
    'U1-ack-survives-restart': (_mut('read-U1', ack_survives_restart=True), {}),
    'U2-warned-when-shown': (_mut('read-U2', warned_on_show=True), {}),
    'U3-reset-keeps-warning': (SpecModel, {'strict_reset': True}),
    'U4-idle-unsolicited-charged': (_mut('read-U4', idle_unsolicited_charges=True), {}),
}

# Variants that cannot be caught because the model has no state in which they differ
# from the spec. Reported, not counted as controls.
EQUIVALENT_VARIANTS = {
    'I12c-stop-after-reveal-free': (
        _mut('mut-I12c-stop-after-reveal-free', post_reveal_free=True),
        'Spec: "before rho was sent". With one signature per attempt, every state after a '
        'reveal either has the reveal outstanding or has already recorded a failure, so '
        '"stopped after the reveal with nothing outstanding and no failure" is unreachable. '
        'It becomes reachable only with several requested signatures in one attempt, which '
        'the event set of this model does not cover.'),
}
