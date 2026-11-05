#!/usr/bin/env python3
"""Stack use of the public anti-exfil functions from gcc's -fstack-usage / -fcallgraph-info=su output
(secp256k1.ci beside the object). Worst case = own frame + the deepest callee chain, plus the return
address per call level (8 bytes on 64-bit, 4 on 32-bit, set --word). The call through the
hash_ctx function pointer is added by hand (sha256_write/finalize -> secp256k1_sha256_transform).
Callees outside the translation unit (memcpy, memset, strlen) are leaves not counted; they are listed.
Usage: stack_usage.py FILE.ci [--word 8]   (FILE.su beside it)"""
import re, sys, argparse
ap = argparse.ArgumentParser(); ap.add_argument("ci"); ap.add_argument("--word", type=int, default=8)
a = ap.parse_args()
def base(n):
    n = n.split(":")[-1]
    return re.sub(r"\.\d+$", "", n)  # .su drops the numeric suffix of .isra.0 / .constprop.0
own, kind, edges = {}, {}, {}
for line in open(a.ci[:-3] + ".su"):
    parts = line.rstrip("\n").split("\t")
    if len(parts) == 3:
        own[base(parts[0])] = int(parts[1]); kind[base(parts[0])] = parts[2]
txt = open(a.ci).read()
for m in re.finditer(r'edge:\s*\{\s*sourcename:\s*"([^"]+)"\s*targetname:\s*"([^"]+)"', txt):
    edges.setdefault(base(m.group(1)), set()).add(base(m.group(2)))
for f in ("secp256k1_sha256_write", "secp256k1_sha256_finalize", "secp256k1_sha256_initialize_tagged"):
    if f in own and "secp256k1_sha256_transform" in own:
        edges.setdefault(f, set()).add("secp256k1_sha256_transform")
memo, ext = {}, set()
def depth(f, stack=()):
    if f in memo: return memo[f]
    if f in stack: raise SystemExit("recursion through " + f)
    if f not in own: ext.add(f)
    best, bf = 0, None
    for c in edges.get(f, ()):
        d, _ = depth(c, stack + (f,))
        if d + a.word > best: best, bf = d + a.word, c
    memo[f] = (own.get(f, 0) + best, bf)
    return memo[f]
pub = sorted(n for n in own if re.match(r"secp256k1_anti_exfil_(schnorr|ecdsa)_(host_commit|signer_commit|sign|host_verify)$", n))
print("%-52s %8s %8s  deepest chain" % ("function", "own", "worst"))
for f in pub:
    d, _ = depth(f)
    chain, g = [], f
    while g and len(chain) < 12:
        chain.append(g.replace("secp256k1_", "")); g = memo[g][1] if g in memo else None
    print("%-52s %8d %8d  %s%s" % (f, own[f], d, " > ".join(chain[1:]), "" ))
print("callees without a frame figure (libc leaves, indirect call, stack protector): " + ", ".join(sorted(ext)))
