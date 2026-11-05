import json, re, shlex, subprocess, sys, os
e = json.load(open(sys.argv[1])); out = sys.argv[2]
args = shlex.split(e['command'])
# drop -o/-MF/-MT/-MD outputs, add callgraph info
res = []; skip = 0
for a in args:
    if skip:
        skip -= 1; continue
    if a in ('-o', '-MF', '-MT'):
        skip = 1; continue
    if a == '-MD':
        continue
    res.append(a)
res += ['-o', out, '-fcallgraph-info=su']
env = dict(os.environ)
tools = os.environ['XTENSA_BIN']      # the bin folder of xtensa-esp-elf 14.2.0 (Espressif tools)
env['PATH'] = tools + ':/usr/bin:/bin'
r = subprocess.run(['nice', '-n', '15', 'systemd-run', '--user', '--scope', '-q', '-p', 'MemoryMax=2G', '-p', 'MemorySwapMax=0'] + res,
                   cwd=e['directory'], env=env, capture_output=True, text=True)
print(r.returncode, r.stderr[-500:])
