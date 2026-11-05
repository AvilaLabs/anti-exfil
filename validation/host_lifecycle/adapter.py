"""Target-adapter interface and the exhaustive explorer.

The explorer knows nothing about the model. It drives any `Target` through
`Session.apply(event)` and judges the returned observation with model.judge,
so a real host can later be checked by the same code that checks the spec model.

Writing a real adapter (not done here)
  class MyTarget(Target):
      name = 'host'
      def new_session(self): ...            # fresh host + fresh scripted device + empty store
  class MySession(Session):
      def apply(self, ev): ...              # drive the host's PUBLIC interface only
      def device_enabled(self, ev): ...     # does the scripted device have a request pending?
      def key(self): ...                    # (hashable host abstraction, tuple of rho ids)
      def clone(self): ...                  # optional; omit and set can_clone = False

If a host cannot be cloned or its state cannot be abstracted soundly, set
`can_clone = False` and `merge_states = False`: the explorer then replays the event
trace from a fresh session for every node and does not merge nodes. That is sound but
costs O(depth) per transition and explores the full tree.

Event semantics (what the adapter must make the scripted device do). Values 1 and 2
stand for two distinct R0_bytes strings, both valid points.
  begin_attempt     user asks to sign; host runs its warning check, and if allowed records
                    the attempt open and draws rho. A refusal for want of a warning
                    acknowledgement is noop=True, warned=True.
  send_commit       host sends (m, hc) for the open attempt (first send or a retry).
  send_reveal       host sends (m, rho) (first send or a retry).
  user_approve_new  user acknowledges the warning the host showed.
  user_cancel       user stops the request; user_edit: user changes m, coins or fee
                    (also stops the request); user_reset: explicit reset of the count.
  restart           the host process dies and starts again over the same store.
  restart_unreadable  as restart, but the store for this device cannot be read.
  recv_R0_v         device answers the pending commit with parseable R0_bytes v.
  rej_R0_v          device answers the pending request with a response the host must
                    reject (wrong kind, bad framing) that carries R0_bytes v.
  bad_R0            device answers the pending commit with bytes parse33 rejects.
  recv_sig          device answers the pending reveal with a signature that passes step 5.
  recv_sig_bad      same, but it fails step 5 against the stored R0.
  dev_refuse        device returns an error or refusal; dev_timeout: no answer arrives.
  dev_unsolicited   device sends a message no request is pending for.
  user_decline      device refuses the pending reveal and the user, asked, confirms the
                    decline was unrelated to what the device showed.

Obs contract: apply() returns a dict with these keys (all required unless marked).
  ev                the event name
  noop              True if the host did nothing with a host-initiated event
  sends             list, in order, of dicts {kind: 'commit'|'reveal', rho: int id,
                    open_durable: bool (the attempt was durably recorded open when this
                    was sent), r0_held: bool, r0_parsed: bool (R0 held in memory and
                    accepted by parse33 when this was sent)}. rho is an id the adapter
                    assigns by first sight of the 32 bytes, 1, 2, 3 ... in order.
  began             True if a new attempt was recorded this event
  warned            True if a warning was shown this event
  durable_leak      True if any durable write this event contained rho or R0_bytes
  count_before, count_after   the durable failure count read through the public interface
  stored_r0         value (1, 2) of the R0 held in memory for the attempt, or None
  attempt_open      True if the host still treats an attempt as in progress
  sig_accepted      True if the host accepted/forwarded a signature this event
  reset_stated      True/False for user_reset (the host stated what is cleared), else None
  warning_pending   optional: True/False if the host exposes whether a warning is owed,
                    else None (the judge then skips that check)
"""
from __future__ import annotations

import importlib
import sys
import time

import model as M

REQUIRED_OBS = ('ev', 'noop', 'sends', 'began', 'warned', 'durable_leak', 'count_before',
                'count_after', 'stored_r0', 'attempt_open', 'sig_accepted', 'reset_stated')


def validate_obs(o):
    miss = [k for k in REQUIRED_OBS if k not in o]
    if miss:
        raise ValueError('observation lacks %s' % miss)
    return o


class Session:
    can_clone = True

    def apply(self, ev):
        raise NotImplementedError

    def device_enabled(self, ev):
        raise NotImplementedError

    def key(self):
        raise NotImplementedError

    def clone(self):
        raise NotImplementedError


class Target:
    name = 'target'
    merge_states = True
    events = M.EVENTS
    cfg = M.Cfg()

    def new_session(self):
        raise NotImplementedError


# ---- the spec model (and its mutants) behind the same interface ------------------------

class ModelSession(Session):
    def __init__(self, model, state):
        self.model, self.state = model, state

    def apply(self, ev):
        self.state, o = self.model.step(self.state, ev)
        return o

    def device_enabled(self, ev):
        return self.model.device_enabled(self.state, ev)

    def key(self):
        return self.model.key(self.state)

    def clone(self):
        return ModelSession(self.model, self.state)


class ModelTarget(Target):
    def __init__(self, model_cls=M.SpecModel, cfg=M.Cfg(), replay=False):
        self.model = model_cls(cfg)
        self.cfg = cfg
        self.name = self.model.name + ('-replay' if replay else '')
        self.replay = replay
        self.merge_states = True

    def new_session(self):
        s = ModelSession(self.model, self.model.initial())
        if self.replay:
            s.can_clone = False
        return s


def load_target(spec):
    """'package.module:factory' -> Target. The module must be importable from sys.path."""
    mod, _, fn = spec.partition(':')
    return getattr(importlib.import_module(mod), fn)()


# ---- explorer -------------------------------------------------------------------------

def _canon(ids):
    m, out = {}, []
    for i in ids:
        if i is None:
            out.append(None)
        else:
            out.append(m.setdefault(i, len(m)))
    return tuple(out)


def node_key(sess, t):
    hk, hids = sess.key()
    tk, tids = M.truth_key(t)
    return hk, tk, _canon(tuple(hids) + tuple(tids))


def explore(target, depth, stop_on=None, deadline=None, events=None):
    """Breadth-first over every event sequence up to `depth`. Nodes with the same
    (host key, truth key) are merged, so the first (shortest) trace to a node is kept.
    Violating steps are recorded and their successors still explored. Returns a dict."""
    events = events or target.events
    cfg = target.cfg
    root = target.new_session()
    clone = root.can_clone
    seen = {node_key(root, M.T0)} if target.merge_states else set()
    frontier = [(root if clone else None, M.T0, ())]
    first = {}            # inv -> record
    first_by_ev = {}      # (inv, last event) -> record
    per_depth = []
    transitions = 0
    reached = 0
    truncated = False
    for d in range(depth):
        nxt = []
        for sess, t, trace in frontier:
            for ev in events:
                if clone:
                    s2 = sess.clone()
                else:
                    s2 = target.new_session()
                    for e in trace:
                        s2.apply(e)
                if not s2.device_enabled(ev):
                    continue
                o = validate_obs(s2.apply(ev))
                transitions += 1
                t2, viols = M.judge(t, ev, o, cfg)
                tr = trace + (ev,)
                for inv, msg in viols:
                    rec = first.get(inv)
                    if rec is None:
                        first[inv] = {'trace': tr, 'msg': msg, 'count': 1}
                    else:
                        rec['count'] += 1
                    k2 = (inv, ev)
                    if k2 not in first_by_ev:
                        first_by_ev[k2] = {'trace': tr, 'msg': msg}
                if target.merge_states:
                    k = node_key(s2, t2)
                    if k in seen:
                        continue
                    seen.add(k)
                nxt.append((s2 if clone else None, t2, tr))
        per_depth.append(len(nxt))
        frontier = nxt
        reached = d + 1
        if stop_on is not None and stop_on <= set(first):
            break
        if deadline is not None and time.monotonic() > deadline:
            truncated = True
            break
        if not frontier:
            break
    return {'states': len(seen), 'depth': reached, 'requested_depth': depth,
            'per_depth_new': per_depth, 'transitions': transitions,
            'violations': first,
            'violations_by_last_event': {'%s@%s' % k: v for k, v in first_by_ev.items()},
            'truncated': truncated, 'exhausted': not frontier}


def format_trace(trace):
    return ' > '.join(trace) if trace else '(empty)'
