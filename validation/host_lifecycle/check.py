#!/usr/bin/env python3
"""Checker: exhaustive exploration of the host lifecycle model
(or of an adapter target), judged against I1..I15, plus mutation controls.

    nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 \
        python3 -B -I validation/host_lifecycle/check.py [--depth N] [--out FILE]

--out FILE  where the result is written (default .work/host_lifecycle/result.json).
--adapter pkg.module:factory  drive a real host instead of the spec model. Without it
            the result is labelled MODEL-ONLY.

OVERALL is PASS only if the target shows no violation of I1..I15 up to the depth and
every control (every broken variant of every invariant) is caught.
"""
import argparse
import hashlib
import json
import platform
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

import adapter as A      # noqa: E402
import model as M        # noqa: E402

SPEC_PATH = ROOT / 'spec' / 'bip-anti-exfil.md'
FULL = dict(depth=18, control_depth=12, B=2, budget_s=9 * 60)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def rec_json(v):
    return {'trace': list(v['trace']), 'length': len(v['trace']), 'message': v['msg'],
            'violating_steps': v['count']}


def run_controls(cfg, depth, deadline):
    out = {}
    for inv in M.INVARIANTS:
        out[inv] = []
        for cls in M.MUTANTS[inv]:
            r = A.explore(A.ModelTarget(cls, cfg), depth, stop_on={inv}, deadline=deadline)
            v = r['violations'].get(inv)
            out[inv].append({
                'variant': cls.name, 'caught': v is not None, 'states': r['states'],
                'depth_reached': r['depth'],
                'trace': list(v['trace']) if v else None,
                'message': v['msg'] if v else None,
                'also_flagged': sorted(set(r['violations']) - {inv}),
            })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out')
    ap.add_argument('--depth', type=int, default=FULL['depth'])
    ap.add_argument('--control-depth', type=int, default=FULL['control_depth'])
    ap.add_argument('--retries', type=int, default=FULL['B'])
    ap.add_argument('--budget-s', type=int, default=FULL['budget_s'])
    ap.add_argument('--adapter')
    ap.add_argument('--no-reset-clears-owed', action='store_true',
                    help='reading U3 the other way (for comparison only)')
    ap.add_argument('--replay-check', type=int, default=0,
                    help='also run the model in replay (no-clone) mode to this depth and '
                         'require identical violations (adapter interface self-test)')
    a = ap.parse_args()
    out = Path(a.out) if a.out else ROOT / '.work' / 'host_lifecycle' / 'result.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    cfg = M.Cfg(B=a.retries, reset_clears_owed=not a.no_reset_clears_owed)
    t0 = time.monotonic()
    deadline = t0 + a.budget_s
    spec_sha = sha(SPEC_PATH)
    if a.adapter:
        target = A.load_target(a.adapter)
        scope = 'ADAPTER:' + a.adapter
    else:
        target = A.ModelTarget(M.SpecModel, cfg)
        scope = 'MODEL-ONLY'
    print('lifecycle check  %s  depth=%d B=%d  spec sha256 %s' % (
        scope, a.depth, cfg.B, spec_sha))

    res = A.explore(target, a.depth, deadline=deadline)
    print('--- target %s: states=%d depth=%d transitions=%d exhausted=%s truncated=%s' % (
        target.name, res['states'], res['depth'], res['transitions'], res['exhausted'],
        res['truncated']))
    any_violation = False
    for inv in M.INVARIANTS:
        v = res['violations'].get(inv)
        if v is None:
            print('%-4s PASS' % inv)
        else:
            any_violation = True
            print('%-4s FAIL shortest trace (%d steps): %s | %s' % (
                inv, len(v['trace']), A.format_trace(v['trace']), v['msg']))
    for k, v in sorted(res['violations_by_last_event'].items()):
        print('  by-event %s (%d steps): %s | %s' % (k, len(v['trace']), A.format_trace(v['trace']), v['msg']))

    deadline = time.monotonic() + a.budget_s      # controls get their own budget
    controls = run_controls(cfg, a.control_depth, deadline)
    missed = []
    for inv in M.INVARIANTS:
        for c in controls[inv]:
            print('CONTROL %-4s %-36s %s (states=%d, trace %d steps, also %s)' % (
                inv, c['variant'], 'CAUGHT' if c['caught'] else 'NOT CAUGHT', c['states'],
                len(c['trace'] or ()), ','.join(c['also_flagged']) or '-'))
            if not c['caught']:
                missed.append(c['variant'])

    equivalent = {}
    for ename, (cls, why) in M.EQUIVALENT_VARIANTS.items():
        r = A.explore(A.ModelTarget(cls, cfg), a.control_depth, deadline=deadline)
        equivalent[ename] = {'violations': sorted(r['violations']), 'states': r['states'],
                             'reason': why}
        print('EQUIVALENT %s: violations %s (not a control)' % (ename, sorted(r['violations']) or 'none'))
    readings = {}
    for rname, (cls, over) in M.READINGS.items():
        rcfg = cfg._replace(**over)
        r = A.explore(A.ModelTarget(cls, rcfg), a.depth, deadline=deadline)
        readings[rname] = {k: rec_json(v) for k, v in r['violations'].items()}
        readings[rname] = {'states': r['states'], 'violations': readings[rname]}
        if not r['violations']:
            print('READING %-30s no violation' % rname)
        for inv, v in sorted(r['violations'].items()):
            print('READING %-30s %-4s (%d steps): %s | %s' % (
                rname, inv, len(v['trace']), A.format_trace(v['trace']), v['msg']))

    replay = None
    if a.replay_check and not a.adapter:
        r1 = A.explore(A.ModelTarget(M.SpecModel, cfg), a.replay_check)
        r2 = A.explore(A.ModelTarget(M.SpecModel, cfg, replay=True), a.replay_check)
        replay = {'depth': a.replay_check, 'same_states': r1['states'] == r2['states'],
                  'same_violations': {k: v['trace'] for k, v in r1['violations'].items()} ==
                                     {k: v['trace'] for k, v in r2['violations'].items()}}
        print('replay-mode self-test depth %d: %s' % (a.replay_check, replay))

    reasons = []
    if any_violation:
        reasons.append('violation reachable')
    if missed:
        reasons.append('controls not caught: ' + ', '.join(missed))
    if res['truncated'] or (res['depth'] < res['requested_depth'] and not res['exhausted']):
        reasons.append('exploration incomplete')
    if replay and not (replay['same_states'] and replay['same_violations']):
        reasons.append('replay-mode self-test differs')
    overall = 'PASS' if not reasons else 'FAIL'
    if not a.adapter:
        overall_label = overall + ' (model-only)'
    else:
        overall_label = overall
    for k, text in M.SPEC_UNDETERMINED.items():
        print('UNDETERMINED %s: %s' % (k, text))
    print('OVERALL: %s%s' % (overall_label, '' if not reasons else ' (' + '; '.join(reasons) + ')'))
    elapsed = time.monotonic() - t0
    print('elapsed %.1f s' % elapsed)

    doc = {
        'scope': scope,
        'overall': overall, 'reasons': reasons, 'elapsed_s': round(elapsed, 1),
        'python': platform.python_version(),
        'config': {'depth': a.depth, 'control_depth': a.control_depth, 'B': cfg.B,
                   'reset_clears_owed': cfg.reset_clears_owed},
        'spec_sha256': spec_sha, 'events': list(target.events),
        'invariants': {inv: (None if inv not in res['violations'] else rec_json(res['violations'][inv]))
                       for inv in M.INVARIANTS},
        'violations_by_last_event': {k: {'trace': list(v['trace']), 'message': v['msg']}
                                     for k, v in res['violations_by_last_event'].items()},
        'result': {k: v for k, v in res.items() if k not in ('violations', 'violations_by_last_event')},
        'controls': controls, 'reading_probes': readings, 'equivalent_variants': equivalent, 'replay_self_test': replay,
        'spec_undetermined': M.SPEC_UNDETERMINED,
        'assumptions': ['one atomic durable write per count change (U9)',
                        'rollback of the store to an older snapshot and multiple hosts are outside the model (known limits)',
                        'rho ids are device-visible; rho is volatile by the spec, so durable_leak models a host that writes it'],
    }
    with open(out, 'w') as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write('\n')
    print('wrote ' + str(out))
    return 0 if overall == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
