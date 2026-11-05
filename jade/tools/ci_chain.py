#!/usr/bin/env python3
"""Deepest static stack chain from a gcc -fcallgraph-info=su .ci file.
usage: ci_chain.py FILE.ci ROOT [ROOT...]"""
import re, sys, collections
txt = open(sys.argv[1], errors="replace").read()
size, edges, dyn, titles = {}, collections.defaultdict(set), {}, {}
for m in re.finditer(r'node: \{ title: "([^"]+)" label: "([^"]*)"', txt):
    t, lab = m.group(1), m.group(2)
    mm = re.search(r"(\d+) bytes \((static|dynamic[^)]*)\)", lab)
    size[t] = int(mm.group(1)) if mm else 0
    dyn[t] = bool(mm and mm.group(2) != "static")
    titles[t] = lab.split("\\n")[0]
for m in re.finditer(r'edge: \{ sourcename: "([^"]+)" targetname: "([^"]+)"', txt):
    edges[m.group(1)].add(m.group(2))
sys.setrecursionlimit(100000)
def best(f, stack):
    if f in stack:
        return 0, []
    b = (0, [])
    for c in edges.get(f, ()):
        if c == f:
            continue
        d = best(c, stack | {f})
        if d[0] > b[0]:
            b = d
    return size.get(f, 0) + b[0], [(f, size.get(f, 0))] + b[1]
for r in sys.argv[2:]:
    ts = [t for t in size if t == r or t.endswith(r) or titles.get(t) == r]
    ts = [t for t in ts if titles.get(t) == r] or ts
    for t in ts[:1]:
        total, chain = best(t, frozenset())
        print("%s: %d bytes in %d frames" % (r, total, len(chain)))
        for f, s in chain:
            print("   %6d  %s%s" % (s, titles.get(f, f), "  (dynamic)" if dyn.get(f) else ""))
        if len(sys.argv) < 0: pass
