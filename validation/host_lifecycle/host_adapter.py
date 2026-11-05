"""Adapter that drives the reference host (psbt/host.py) through the
explorer in adapter.py.

    python3 -B -I validation/host_lifecycle/check.py \
        --adapter host_adapter:factory            # default host
    ... --adapter host_adapter:factory_probe      # host repeats step 2 before a step 3/4 retry

What is real and what is scripted
  Real: the host (Host, Attempt, Store with its JSON file, rename and directory handling) and the
  signing arithmetic it uses, run unchanged. A host source tree other than psbt can be
  selected with AE_HOST_SRC, which is how host mutants are run.
  Scripted: the device, the link and the user. The device answers every request as the event
  says. Its two nonce values are two fixed base nonces k1 and k2 (both valid points), so it can
  also sign with either one; a signature "that passes step 5" uses the nonce the device announced
  first for that attempt, "recv_sig_bad" uses the other one.
  The judge sees only events and observations (Obs contract in adapter.py).

How the host's blocking calls become events
  Host.commit() and Host.reveal() block on the link. Each runs in a worker thread, and the link
  blocks the worker at every exchange until the explorer's event releases it. A retry the host
  decides on after a failure is therefore reported at the explorer's next send_commit or send_reveal
  event, not at the failure event; the host's own decision is not changed, only when it becomes
  visible. A kill (restart) answers the blocked exchange with an exception no host code catches, so
  the host does nothing more before the new Host starts over the same store.

State merging
  Threads cannot be cloned, so can_clone is False and the explorer replays the event trace from a
  fresh session for every node. Nodes are merged by key(), which is built from the host's own
  records, not from the model: the store record for the device (failure count and the count last
  acknowledged, each capped at 2, and which of the two is larger, open attempts and their counted flags, the failed mark), Attempt.observed() (state,
  counted, rho sent, cancel flag, nonce commitments received and held), the number of sends of each
  kind, what the link is holding, the scripted device's first announced nonce, and the
  user-interface flags. Merging is sound only if equal keys always behave alike, which cannot be
  proved from outside, so it is probed: `python3 -B -I validation/host_lifecycle/host_adapter.py
  merge-probe DEPTH [probe]` replays two traces that reach one key and compares the next event's
  observation and successor key for every event (a one-step bisimulation check over the explored
  nodes). A host mutant that hid in a coarser key (a store whose acknowledged count was reset wrongly)
  was found this way and the key was widened.

Where the judge's model and the host differ (resolved here in the host's favour)
  restart_unreadable: the host treats an unreadable store as "a count of one" (the settled text),
  so a second unreadable restart leaves the count at one and I6 ("raised the count") fails.
  bad_R0: the host counts a malformed R0_bytes as a value received, "whatever its form", so a later
  valid value ends the attempt; the model keeps the attempt open. The judge's picture of that attempt
  is then stale, which can show up as a false I5 (only in the probe variant, where bad_R0 can answer
  a repeated step 2 after the reveal).
  user_cancel while a retry is held: the host has already begun the send, the explorer has not yet
  seen it; the adapter cancels the held exchange (the transport raises LinkCancelled), as a real
  transport must, and the host counts the cancellation once.

Deviations from production that exist only to make exploration fast
  os.fsync is replaced by a no-op unless AE_REAL_FSYNC=1 (the temp file, rename and directory open
  still happen). Kills are exceptions at a link exchange, not a process death, so a kill between
  two lines of host code is covered by psbt/tests/test_lifecycle.py (CrashingStore), not here.
  rho comes from a counter-based source so a replayed trace reproduces the same bytes.
"""
from __future__ import annotations

import atexit
import hashlib
import itertools
import json
import os
import shutil
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for _p in (str(ROOT / 'psbt' / 'tests'), str(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import common as K                    # noqa: E402  (puts the host source and reference on sys.path)
import adapter as A             # noqa: E402
import model as M               # noqa: E402

H, T, C, S, AE = K.H, K.T, K.C, K.S, K.AE

if not os.environ.get('AE_REAL_FSYNC'):
    H.os.fsync = lambda fd: None

DEV = 'dev-A'
B = 2
WORK = ROOT / '.work' / 'host_lifecycle' / 'stores' / str(os.getpid())
atexit.register(lambda: shutil.rmtree(WORK, ignore_errors=True))
_SERIAL = itertools.count()
_N = AE._N


class AdapterError(RuntimeError):
    """The harness itself went wrong (not a finding about the host)."""


class Kill(BaseException):
    """Answers a blocked exchange when the host process 'dies'. No host code catches it."""


# ------------------------------------------------------------------ fixtures (built once)
_FORM = K.Form('p2wpkh')
_INP = K.Inp(_FORM)
PSBT_BYTES = K.build_psbt([_INP]).serialize()
SECRETS = K.held_of([_INP])
WALLET_KEYS = [K.pub33(k) for k in SECRETS]
_D = int.from_bytes(SECRETS[0], 'big')
K0 = {v: int.from_bytes(hashlib.sha256(b'lifecycle/base-nonce/%d' % v).digest(), 'big') % _N for v in (1, 2)}
R0 = {v: AE._ser33(AE._mul(K0[v])) for v in (1, 2)}
R0_ID = {R0[1]: 1, R0[2]: 2}
BAD_R0 = b'\x05' + b'\x00' * 32            # parse33 rejects the prefix
_SIGS = {}


def _entries(data):
    p = C.parse(data)
    return p, [(i, typ, keyid, val) for i, m in enumerate(p.inputs) for typ, keyid, val in C.ae_entries(m)]


def kind_of(req):
    _, es = _entries(req)
    return 'reveal' if any(t == C.AE_RHO for _, t, _, _ in es) else 'commit'


def hc_of(req):
    """The host commitment (or the one rho gives) of the request's first pair."""
    _, es = _entries(req)
    for _, t, _, val in es:
        if t == C.AE_RHO:
            return AE.ecdsa_host_commit(val)
    for _, t, _, val in es:
        if t == C.AE_HC:
            return val
    raise AdapterError('request without anti-exfil fields')


def with_r0(req, value, add_rho=False):
    p, es = _entries(req)
    for i, t, keyid, _ in es:
        if t == C.AE_HC or t == C.AE_RHO:
            p.inputs[i][bytes([C.AE_R0]) + keyid] = value
            if add_rho and t == C.AE_HC:
                p.inputs[i][bytes([C.AE_RHO]) + keyid] = b'\x00' * 32
    return p.serialize()


def signed_second_pass(req, v):
    """What a device that announced base nonce k_v returns for a second-pass request."""
    p, es = _entries(req)
    out = p.clone()
    for i in range(len(out.inputs)):
        out.inputs[i] = C.strip_ae(out.inputs[i])
    for i, t, keyid, rho in es:
        if t != C.AE_RHO:
            continue
        key = (rho, v, keyid)
        if key not in _SIGS:
            pr = S.resolve_pair(p, i, keyid, {k[1:] for k in WALLET_KEYS})
            t_ = AE._ecdsa_t(R0[v], rho)
            kp = (K0[v] + t_) % _N
            r = AE._mul(kp)[0] % _N
            s = pow(kp, _N - 2, _N) * (int.from_bytes(pr.message, 'big') % _N + r * _D) % _N
            if s > (_N - 1) // 2:
                s = _N - s
            _SIGS[key] = (pr.sigkey, S.sigfield('ecdsa', pr.sighash, r, s))
        sk, field = _SIGS[key]
        out.inputs[i][sk] = field
    return out.serialize()


# ------------------------------------------------------------------ link with a gate
class Runner:
    """The host's link, and the worker thread that runs one blocking host call."""

    TIMEOUT = 30

    def __init__(self):
        self.cv = threading.Condition()
        self.thread = None
        self.pending = None          # request the worker is blocked on
        self.released = False        # the explorer has let it go (it counts as sent)
        self.response = None         # ('ok', bytes) or ('exc', BaseException)
        self.done = True
        self.result = None
        self.exc = None
        self.unsolicited = []
        self.kind = None             # 'commit' | 'reveal': which host call the worker runs

    # --- the host's side
    def exchange(self, req):
        with self.cv:
            self.pending, self.released, self.response = req, False, None
            self.cv.notify_all()
            if not self.cv.wait_for(lambda: self.response is not None, self.TIMEOUT):
                raise AdapterError('worker was never answered')
            how, val = self.response
            self.pending, self.response = None, None
            self.cv.notify_all()
        if how == 'exc':
            raise val
        return val

    def take_unsolicited(self):
        out, self.unsolicited = self.unsolicited, []
        return out

    # --- the explorer's side
    def start(self, fn, kind):
        self.done, self.result, self.exc, self.kind = False, None, None, kind

        def run():
            try:
                self.result = fn()
            except BaseException as e:           # noqa: BLE001 - recorded, classified by the adapter
                self.exc = e
            finally:
                with self.cv:
                    self.done = True
                    self.cv.notify_all()
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        self.wait_idle()

    def wait_idle(self):
        with self.cv:
            if not self.cv.wait_for(lambda: self.done or (self.pending is not None and not self.released
                                                          and self.response is None), self.TIMEOUT):
                raise AdapterError('worker neither blocked nor finished')

    def live(self):
        return not self.done

    def holding(self):
        return self.live() and self.pending is not None

    def release(self):
        with self.cv:
            self.released = True

    def respond(self, how, val):
        with self.cv:
            self.released = True
            self.response = (how, val)
            self.cv.notify_all()
            if not self.cv.wait_for(lambda: self.response is None, self.TIMEOUT):
                raise AdapterError('worker did not take the answer')
        self.wait_idle()

    def reset(self):
        self.done, self.result, self.exc, self.kind = True, None, None, None

    def kill(self):
        t = self.thread
        if t is not None and t.is_alive():
            with self.cv:
                if self.pending is not None and self.response is None:
                    self.response = ('exc', Kill())
                    self.cv.notify_all()
            t.join(self.TIMEOUT)


# ------------------------------------------------------------------ the user
class AdapterUI(H.UI):
    def __init__(self):
        self.shown_for = None        # the failure count the user was last warned at
        self.acked_for = None
        self.shows = 0
        self.decline = False
        self.reset_text = None

    def warn(self, dev, fails):
        if self.acked_for == fails:
            return True
        self.shown_for = fails
        self.shows += 1
        return False

    def approve_warning(self, fails):
        if self.shown_for is not None and self.shown_for == fails:
            self.acked_for = fails
            return True
        return False

    def clear(self):
        self.shown_for = self.acked_for = None

    def declined_on_device(self):
        return self.decline

    def decline_unrelated_to_display(self):
        return self.decline

    def confirm_reset(self, text):
        self.reset_text = text
        return True


# ------------------------------------------------------------------ session
class HostSession(A.Session):
    can_clone = False

    def __init__(self, target):
        self.target = target
        self.dir = WORK / str(next(_SERIAL))
        self.dir.mkdir(parents=True, exist_ok=True)
        self.store_path = str(self.dir / 'store.json')
        self.wallet = H.Wallet(DEV, WALLET_KEYS)
        self.ids = {}                # host commitment -> rho id, by first sight
        self.drawn = []              # every rho the host drew
        self.draws = itertools.count()
        self.last_id = None          # most recent rho the device saw
        self.att_id = None
        self.dev_first = {}          # hc -> id of the nonce the device announced first
        self.cs = self.rs = 0
        self.out = None              # kind of the request released and awaiting a response
        self.att = None
        self.new_host()

    def __del__(self):
        try:
            if threading.current_thread() is not self.runner.thread:
                self.runner.kill()
        except Exception:                       # noqa: BLE001
            pass
        finally:
            shutil.rmtree(self.dir, ignore_errors=True)

    # --- plumbing
    def _rho(self):
        r = hashlib.sha256(b'lifecycle/rho/%d' % next(self.draws)).digest()
        self.drawn.append(r)
        return r

    def new_host(self):
        self.runner = Runner()
        self.ui = AdapterUI()
        self.host = H.Host(self.wallet, H.Store(self.store_path), self.ui, self.runner, max_retries=B,
                           failure_limit=None, rho_source=self._rho,
                           repeat_step2_on_retry=self.target.probe)
        self.att = None
        self.out = None
        self.cs = self.rs = 0
        self.att_id = None

    def _count(self):
        return self.host.store.failures(DEV)

    def _open_durable(self):
        try:
            with open(self.store_path, 'rb') as f:
                return bool(json.loads(f.read().decode())['devices'][DEV]['open'])
        except (OSError, ValueError, KeyError):
            return False

    def _leak(self):
        secrets_ = set(self.drawn) | set(R0.values()) | {BAD_R0}
        for f in self.dir.iterdir():
            try:
                blob = f.read_bytes()
            except OSError:
                continue
            for s in secrets_:
                if s in blob or s.hex().encode() in blob:
                    return True
        return False

    def _rho_id(self, hc):
        if hc not in self.ids:
            self.ids[hc] = len(self.ids) + 1
        return self.ids[hc]

    def _r0_ids(self, vals):
        return tuple(sorted(R0_ID.get(v, 9) for v in vals))

    # --- the Session interface
    def device_enabled(self, ev):
        if ev in M._NEEDS_COMMIT:
            return self.out == 'commit'
        if ev in M._NEEDS_REVEAL:
            return self.out == 'reveal'
        if ev in M._NEEDS_ANY:
            return self.out is not None
        if ev == 'dev_unsolicited':
            return self.out is None
        return True

    def apply(self, ev):
        o = {'ev': ev, 'noop': False, 'sends': [], 'began': False, 'warned': False,
             'durable_leak': False, 'sig_accepted': False, 'reset_stated': None}
        before = self._count()
        o['count_before'] = before
        self._dispatch(ev, o)
        after = self._count()
        o['count_after'] = after
        if after != before or ev in ('user_reset', 'restart', 'restart_unreadable'):
            self.ui.clear()                  # a warning is for the count the user saw
        o['stored_r0'] = self._stored_r0()
        o['attempt_open'] = self.att is not None
        o['warning_pending'] = self.host.store.needs_warning(DEV)
        o['durable_leak'] = self._leak()
        return o

    def _stored_r0(self):
        if self.att is None:
            return None
        held = self.att.observed()['held_r0']
        ids = self._r0_ids(held)
        return ids[0] if ids else None

    def _dispatch(self, ev, o):
        if ev.startswith(('recv_R0_', 'rej_R0_')):
            return self._answer_r0(o, int(ev[-1]), ev.startswith('recv'))
        return getattr(self, 'e_' + ev)(o)

    # --- host-initiated events
    def e_begin_attempt(self, o):
        if self.att is not None:
            o['noop'] = True
            return
        shows = self.ui.shows
        try:
            a = self.host.start(PSBT_BYTES)
        except H.WarningNotAcknowledged:
            o['noop'], o['warned'] = True, self.ui.shows > shows
            return
        except H.HostRefusal as e:
            raise AdapterError('host refused a request the model expects to start: %s' % e)
        o['began'], o['warned'] = True, self.ui.shows > shows
        self.att, self.att_id, self.cs, self.rs = a, None, 0, 0
        self.ui.clear()

    def _release(self, o):
        r = self.runner
        req = r.pending
        kind = kind_of(req)
        hc = hc_of(req)
        rid = self._rho_id(hc)
        held = self.att.observed()['held_r0'] if self.att else frozenset()
        o['sends'].append({'kind': kind, 'rho': rid, 'open_durable': self._open_durable(),
                           'r0_held': bool(held),
                           'r0_parsed': bool(held) and all(AE._parse33(v) is not AE._INF for v in held)})
        r.release()
        self.out, self.last_id, self.att_id = kind, rid, rid
        if kind == 'commit':
            self.cs += 1
        else:
            self.rs += 1

    def _launch(self, o, fn, kind):
        self.runner.start(fn, kind)
        if self.runner.holding() and not self.runner.released:
            self._release(o)
        else:
            self._settle(o)

    def e_send_commit(self, o):
        r = self.runner
        if self.att is None or self.out is not None:
            o['noop'] = True
        elif r.holding():
            if kind_of(r.pending) == 'commit':
                self._release(o)
            else:
                o['noop'] = True
        elif not r.live() and self.att.state == 'ready':
            self._launch(o, self.att.commit, 'commit')
        else:
            o['noop'] = True

    def e_send_reveal(self, o):
        r = self.runner
        if self.att is None or self.out is not None:
            o['noop'] = True
        elif r.holding():
            if kind_of(r.pending) == 'reveal':
                self._release(o)
            else:
                o['noop'] = True
        elif not r.live() and self.att.state == 'committed':
            self._launch(o, self.att.reveal, 'reveal')
        else:
            o['noop'] = True

    def _settle(self, o):
        """The worker finished: classify how, and drop the attempt if it is over."""
        r = self.runner
        if not r.done:
            return
        exc, kind = r.exc, r.kind
        r.reset()
        if exc is None:
            if kind == 'reveal':
                o['sig_accepted'] = True
        elif isinstance(exc, (H.AttemptFailed, H.AttemptAbandoned)):
            pass
        elif isinstance(exc, RuntimeError):
            o['noop'] = True
        else:
            raise AdapterError('unexpected %r from %s()' % (exc, kind))
        a = self.att
        if a is not None and a.state in ('completed', 'abandoned', 'failed'):
            self.att = None
            self.cs = self.rs = 0
            self.att_id = None

    # --- user events
    def e_user_approve_new(self, o):
        if not self.ui.approve_warning(self._count()):
            o['noop'] = True

    def _stop(self, o):
        a = self.att
        if a is None:
            o['noop'] = True
            return
        r = self.runner
        if r.holding():
            a.cancel()                                   # a response is outstanding: a failure event
            r.respond('exc', T.LinkCancelled('cancelled'))   # the transport gives up the wait
            self.out = None
            self._settle(o)
        else:
            a.cancel()
            self._settle_idle(o)

    def _settle_idle(self, o):
        a = self.att
        if a is not None and a.state in ('completed', 'abandoned', 'failed'):
            self.att = None
            self.cs = self.rs = 0
            self.att_id = None

    def e_user_cancel(self, o):
        self._stop(o)

    def e_user_edit(self, o):
        self._stop(o)

    def e_user_reset(self, o):
        n = self._count()
        self.ui.reset_text = None
        self.host.reset_failures()
        text = self.ui.reset_text or ''
        o['reset_stated'] = bool(text) and str(n) in text and DEV in text

    def e_restart(self, o):
        self.runner.kill()
        self.new_host()

    def e_restart_unreadable(self, o):
        self.runner.kill()
        with open(self.store_path, 'wb') as f:
            f.write(b'{ not a store')
        self.new_host()

    # --- device events
    def _deliver(self, o, how, val):
        self.runner.respond(how, val)
        self.out = None
        self._settle(o)

    def _answer_r0(self, o, v, accepted):
        req = self.runner.pending
        if accepted:
            self.dev_first.setdefault(hc_of(req), v)
            self._deliver(o, 'ok', with_r0(req, R0[v]))
        else:
            self._deliver(o, 'ok', with_r0(req, R0[v], add_rho=True))

    def e_bad_R0(self, o):
        self._deliver(o, 'ok', with_r0(self.runner.pending, BAD_R0))

    def e_recv_sig(self, o):
        req = self.runner.pending
        self._deliver(o, 'ok', signed_second_pass(req, self.dev_first.get(hc_of(req), 1)))

    def e_recv_sig_bad(self, o):
        req = self.runner.pending
        self._deliver(o, 'ok', signed_second_pass(req, 3 - self.dev_first.get(hc_of(req), 1)))

    def e_dev_refuse(self, o):
        self._deliver(o, 'exc', T.DeviceError('refused'))

    def e_dev_timeout(self, o):
        self._deliver(o, 'exc', T.LinkTimeout('timeout'))

    def e_user_decline(self, o):
        self.ui.decline = True
        try:
            self._deliver(o, 'exc', T.DeviceError('declined on the device'))
        finally:
            self.ui.decline = False

    def e_dev_unsolicited(self, o):
        self.runner.unsolicited.append(b'unrequested')
        if self.att is not None:
            self.att.poll()
        else:
            self.host.discard_unsolicited()

    # --- state key
    def key(self):
        rec = self.host.store.view(DEV)
        last = rec.get('last') if isinstance(rec.get('last'), dict) else {}
        store = (min(rec['failures'], 2), min(rec['warned'], 2), rec['failures'] > rec['warned'], rec['warned'] > rec['failures'],
                 tuple(sorted(v['counted'] for v in rec['open'].values())), last.get('failed'),
                 bool(self.host.store.data['lost']), bool(rec.get('unreadable')))
        att = None
        if self.att is not None:
            ob = self.att.observed()
            att = (ob['state'], ob['counted'], ob['rho_sent'], ob['cancelled'],
                   self._r0_ids(ob['received_r0']), self._r0_ids(ob['held_r0']), self.cs, self.rs,
                   self.dev_first.get(self._hc_now()))
        r = self.runner
        link = (r.live(), None if not r.holding() else kind_of(r.pending), r.released, self.out)
        n = self._count()
        ui = (self.ui.shown_for == n, self.ui.acked_for == n)
        return (store, att, link, ui, bool(r.unsolicited)), (self.att_id, self.last_id)

    def _hc_now(self):
        for hc, i in self.ids.items():
            if i == self.att_id:
                return hc
        return None


class HostTarget(A.Target):
    merge_states = True
    cfg = M.Cfg(B=B)

    def __init__(self, probe=False, merge=True, skip=()):
        self.probe = probe
        self.merge_states = merge
        self.events = tuple(e for e in M.EVENTS if e not in skip)
        self.name = ('host' + ('-probe' if probe else '') + ('' if merge else '-nomerge')
                     + ('-without-' + ','.join(skip) if skip else ''))

    def new_session(self):
        return HostSession(self)


def factory():
    return HostTarget()


def factory_probe():
    return HostTarget(probe=True)


def factory_nomerge():
    return HostTarget(merge=False)


def factory_without_unreadable():
    """Analysis only: every event except restart_unreadable (see the I6 finding in the report)."""
    return HostTarget(skip=('restart_unreadable',))


def factory_probe_without_unreadable():
    return HostTarget(probe=True, skip=('restart_unreadable',))


def _merge_probe(depth, probe):
    """Dev tool. When two traces reach the same key, one more event from each must give the same
    observation (rho ids aside) and the same successor key."""
    t = factory_probe() if probe else factory()

    def replay(tr):
        s = t.new_session()
        for e in tr:
            s.apply(e)
        return s

    def norm(o):
        o = dict(o)
        o['sends'] = [{k: v for k, v in sd.items() if k != 'rho'} for sd in o['sends']]
        return o

    def canon(k):
        hk, ids = k
        m = {}
        return hk, tuple(None if i is None else m.setdefault(i, len(m)) for i in ids)

    seen = {canon(t.new_session().key()): ()}
    frontier, coll, checked, bad = [()], 0, 0, 0
    for d in range(depth):
        nxt = []
        for tr in frontier:
            for ev in t.events:
                s = replay(tr)
                if not s.device_enabled(ev):
                    continue
                s.apply(ev)
                tr2 = tr + (ev,)
                k = canon(s.key())
                if k not in seen:
                    seen[k] = tr2
                    nxt.append(tr2)
                    continue
                coll += 1
                for ev2 in t.events:
                    a, b = replay(seen[k]), replay(tr2)
                    if a.device_enabled(ev2) != b.device_enabled(ev2):
                        bad += 1
                        print('ENABLED DIFFERS', seen[k], tr2, ev2)
                    elif a.device_enabled(ev2):
                        oa, ob = norm(a.apply(ev2)), norm(b.apply(ev2))
                        checked += 1
                        if oa != ob or canon(a.key()) != canon(b.key()):
                            bad += 1
                            print('DIFFERS', seen[k], tr2, ev2, oa, ob)
        frontier = nxt
        print('depth', d + 1, 'new', len(nxt), 'collisions', coll, 'one-step checks', checked, 'mismatches', bad, flush=True)
    print('keys %d, collisions %d, one-step checks %d, mismatches %d' % (len(seen), coll, checked, bad))
    return 1 if bad else 0


if __name__ == '__main__':
    if len(sys.argv) >= 3 and sys.argv[1] == 'merge-probe':
        raise SystemExit(_merge_probe(int(sys.argv[2]), 'probe' in sys.argv[3:]))
    print(__doc__)
