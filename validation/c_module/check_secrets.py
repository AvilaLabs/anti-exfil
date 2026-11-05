#!/usr/bin/env python3
"""constant_time (constant time under Valgrind) and residue (residue scan) on the module.
Reuses the helpers (case lists, pattern derivation,
Valgrind report parser) from validation/c_module/secrets_scan.py unchanged.

usage: python3 -B -I check_secrets.py [--smoke] [--out DIR] [--bases benma zkp] [--opts O0 O2 Os]
Needs `build.sh BASE ctime` and `build.sh BASE memscan` for each base and opt
(OPT=-O0 etc.), and Valgrind (a system install, or the prefix in VALGRIND_ROOT). Writes under
.work/c_module/ unless --out. Exit 0 only if the constant-time check passes.

Constant-time rules: both controls flagged and the declassified control
silent in every configuration, every driver call returns the expected value,
and every report matches an entry of CLASSES below (a written reason). An
unlisted report is UNCLASSIFIED and fails. A class bug_ours fails."""
import argparse, importlib.util, json, os, re, subprocess, sys, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), '..', '..'))
sp = importlib.util.spec_from_file_location('ss', os.path.join(ROOT, 'validation/c_module/secrets_scan.py'))
ss = importlib.util.module_from_spec(sp)
saved = sys.argv; sys.argv = [os.path.join(ROOT, 'validation/c_module/x.py')]
sp.loader.exec_module(ss)
sys.argv = saved
BUILD = os.environ.get('C_BUILD', os.path.join(ROOT, '.work/c/build'))
VG = os.environ.get('VALGRIND_ROOT', '/')     # prefix of a valgrind install (default: the system)

# (function, source line) -> (class, reason, opts where the class applies). A report at any other
# optimization level is UNCLASSIFIED. Filled from the reports of the runs.
_CN = ('artefact', 'Base function used unchanged by the base\'s own schnorrsig_sign and ecdsa signing; reported at -O0 only '
       '(no report at -O2 or -Os in this run): the masks are computed by arithmetic that gcc -O0 turns into code memcheck sees as a '
       'jump on the undefined flag; the flag here is the parity of a secret-derived point, applied as a mask.', ('O0',))
CLASSES = {
    ('secp256k1_scalar_cond_negate', 'uint64_t nonzero = (secp256k1_scalar_is_zero(r) != 0) - 1;'): _CN,
    ('secp256k1_scalar_cond_negate', 'return 2 * (mask == 0) - 1;'): _CN,
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--smoke', action='store_true')
    ap.add_argument('--out', default=os.path.join(ROOT, '.work/c_module'))
    ap.add_argument('--bases', nargs='+', default=['benma', 'zkp'])
    ap.add_argument('--opts', nargs='+', default=['O0', 'O2', 'Os'])
    ap.add_argument('--skip-scan', action='store_true')
    ap.add_argument('--skip-constant_time', action='store_true', help='residue only (the sensitivity runs)')
    ap.add_argument('--tag', default=None, help='label in the results (default run, smoke with --smoke)')
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    tag = a.tag or ('smoke' if a.smoke else 'run')
    env = dict(os.environ, VALGRIND_LIB=os.path.join(VG, 'usr/libexec/valgrind'), PATH=os.path.join(VG, 'usr/bin') + ':' + os.environ['PATH'])
    vg = ['valgrind', '-q', '--error-limit=no', '--num-callers=12', '--track-origins=yes']
    ver = subprocess.run(['valgrind', '--version'], capture_output=True, text=True, env=env).stdout.strip()
    log = open(os.path.join(a.out, 'secrets_log.txt'), 'w')
    def say(s):
        print(s); log.write(s + '\n'); log.flush()
    say('constant time and residue scan, %s  %s' % (tag, ver))
    cases = ss.make_cases(a.smoke)
    results = {'label': tag, 'valgrind': ver, 'constant_time': [], 'residue': []}
    unclassified = bugs = control_fail = driver_fail = 0
    verdict = 'SKIPPED'
    for base in ([] if a.skip_c5 else a.bases):
        for O in a.opts:
            for scheme, K in (('schnorr', 'SCHNORR'), ('ecdsa', 'ECDSA')):
                exe = os.path.join(BUILD, '%s-ctime%s' % (base, O), 'ctime_check_' + K)
                stdin = ''.join(c[1] + '\n' for c in cases[scheme])
                p, dt = ss.run(vg + [exe], input=stdin, env=env)
                open(os.path.join(a.out, 'constant_time_%s_%s_%s_%s.stderr' % (tag, base, scheme, O)), 'w').write(p.stderr)
                hits = ss.parse_valgrind(p.stderr)
                stages, seen = {}, {}
                tree = os.path.join(ROOT, '.work/c', base)
                for h in hits:
                    if not h['frames']: continue
                    top = h['frames'][0]
                    if h['stage'].startswith('control'):
                        stages.setdefault(h['stage'], []).append(h); continue
                    fn = ss.clean_func(top[0])
                    sl = ss.src_line(tree, top[1], top[2], fn) if top[1] else None
                    text = sl[1] if sl else '?'
                    cls, reason, opts = CLASSES.get((fn, text), ('UNCLASSIFIED', '', ()))
                    if O not in opts: cls, reason = 'UNCLASSIFIED', ''
                    k = (fn, text, cls)
                    e = seen.setdefault(k, {'function': fn, 'source': text, 'file_line': '%s:%s' % (top[1], top[2]), 'class': cls,
                                            'reason': reason, 'stages': set(), 'trace': ['%s (%s:%s)' % x for x in h['frames'][:6]]})
                    e['stages'].add(h['stage'])
                uniq = [dict(v, stages=sorted(v['stages'])) for v in seen.values()]
                cb = any('control_branch' in f[0] for h in stages.get('control_branch', []) for f in h['frames'][:1])
                ci = any('control_index' in f[0] for h in stages.get('control_index', []) for f in h['frames'][:1])
                cd = len(stages.get('control_declassified', [])) == 0
                m = re.search(r'@@CASES (\d+)', p.stderr)
                ncase = int(m.group(1)) if m else -1
                drv = 'DRIVER-ERROR' in p.stderr or p.returncode != 0 or ncase != len(cases[scheme])
                control_fail += (not (cb and ci and cd)); driver_fail += bool(drv)
                for u in uniq:
                    bugs += u['class'] == 'bug_ours'; unclassified += u['class'] == 'UNCLASSIFIED'
                results['constant_time'].append({'base': base, 'opt': O, 'scheme': scheme, 'cases': ncase, 'control_branch': cb, 'control_index': ci,
                                      'control_declassified_clean': cd, 'driver_ok': not drv, 'hits': uniq, 'seconds': round(dt, 1)})
                say('[constant_time] %s %s %s: %d cases, %d distinct hit sites, controls branch=%s index=%s declassified-clean=%s driver_ok=%s, %.0fs' %
                    (base, O, scheme, ncase, len(uniq), cb, ci, cd, not drv, dt))
                for u in uniq:
                    say('    %-14s %-40s %s [%s] %s' % (u['class'], u['file_line'], u['function'], ','.join(u['stages']), u['source']))
    if not a.skip_c5:
        verdict = 'PASS' if not (unclassified or bugs or control_fail or driver_fail) else 'FAIL'
    reasons = [r for r, n in (('control failures', control_fail), ('driver failures', driver_fail), ('bug_ours sites', bugs), ('UNCLASSIFIED sites', unclassified)) if n]
    results['constant_time_verdict'] = {'verdict': verdict, 'reasons': reasons}
    say('constant_time (%s) %s %s' % (tag, verdict, reasons))

    # ------------------------------------------------ residue
    ctl_fail = 0
    if not a.skip_scan:
        scases = ss.make_scan_cases(a.smoke)
        for scheme, K in (('schnorr', 'SCHNORR'), ('ecdsa', 'ECDSA')):
            for c in scases[scheme]:
                for base in a.bases:
                    for O in a.opts:
                        b = os.path.join(BUILD, '%s-memscan%s' % (base, O), 'memscan_check_' + K)
                        p, _ = ss.run([b, '--emit'], input=c[1] + '\n')
                        pub = json.loads(p.stdout)
                        pats = ss.derive_patterns(scheme, c, pub)
                        pf = os.path.join(a.out, 'patterns.tmp')
                        open(pf, 'w').write(''.join('%s %d %s\n' % (n, mr, bb.hex()) for n, (bb, mr) in pats.items()))
                        p, _ = ss.run([b, pf], input=c[1] + '\n')
                        os.remove(pf)
                        rows = [json.loads(l) for l in p.stdout.split('\n') if l.strip()]
                        results['residue'].append({'scheme': scheme, 'case': c[0], 'base': base, 'opt': O, 'rows': rows, 'rc': p.returncode})
                        basehit = [r for r in rows if r['fn'] == 'control_baseline' and r.get('full', 0) + r.get('fragments', 0)]
                        plant = [r for r in rows if r['fn'] == 'control_plant' and r.get('pattern') == 'sk/be' and r['region'] == 'stack' and r['full'] >= 1]
                        if basehit or not plant or p.returncode:
                            ctl_fail += 1
                            say('[residue] CONTROL FAIL %s %s %s %s' % (scheme, c[0], base, O))
        secrets = ['sk', 'd_norm', 'dmask', 't0', 'rho', 'k0', 't', "k'", "k'neg", "k'inv", 'sha_t_state', 'sha_t_buf']
        fns = ['host_commit', 'signer_commit', 'signer_sign', 'host_verify']
        cols = [(b, O) for b in a.bases for O in a.opts]
        tbl, full_left = [], []
        for scheme in ('schnorr', 'ecdsa'):
            nc = len(scases[scheme])
            tbl.append('\n### %s: residue at function exit (%d cases; S = dead stack, H = heap; Sk/n = whole 32-byte value found in k of n cases, ~b = longest partial run)\n' % (scheme, nc))
            tbl.append('| function | secret | ' + ' | '.join('%s %s' % x for x in cols) + ' |')
            tbl.append('|---|---|' + '---|' * len(cols))
            for fn in fns:
                for sname in secrets:
                    if scheme == 'ecdsa' and sname in ('d_norm', 't0', "k'neg"): continue
                    if scheme == 'schnorr' and sname in ('dmask', "k'inv"): continue
                    cells = []
                    for base, O in cols:
                        cell = []
                        for reg, t in (('stack', 'S'), ('heap', 'H')):
                            pc = {}
                            for e in results['residue']:
                                if (e['scheme'], e['base'], e['opt']) != (scheme, base, O): continue
                                rs = [r for r in e['rows'] if r['fn'] == fn and r.get('region') == reg and r.get('pattern', '').split('/')[0] == sname]
                                pc[e['case']] = (max([r['full'] for r in rs] + [0]), max([r['max_fragment'] for r in rs] + [0]))
                            nf = sum(1 for f, _ in pc.values() if f); mf = max([m for _, m in pc.values()] + [0])
                            s = '%s%d/%d' % (t, nf, nc) + ('~%d' % mf if mf and not nf else '')
                            if nf and sname in ('sk', 'd_norm', 'dmask', 'k0', "k'", "k'neg", "k'inv", 't', 'rho', 't0'):
                                full_left.append((scheme, fn, sname, base, O, reg, nf))
                            cell.append(s)
                        cells.append(' '.join(cell))
                    tbl.append('| %s | %s | ' % (fn, sname) + ' | '.join(cells) + ' |')
        table = '\n'.join(tbl)
        open(os.path.join(a.out, 'residue_table.md'), 'w').write(table)
        say(table)
        results['residue_full_length_found'] = full_left
        say('residue controls failed: %d; full-length secrets found in dead memory: %d entries (see table and results json)' % (ctl_fail, len(full_left)))
    results['residue_control_failures'] = ctl_fail
    json.dump(results, open(os.path.join(a.out, 'secrets_results.json'), 'w'), indent=1)
    return 0 if verdict in ('PASS', 'SKIPPED') and not ctl_fail else 1

if __name__ == '__main__':
    sys.exit(main())
