#!/usr/bin/env python3
"""Helpers for check_secrets.py: the case lists of the ctime-style Valgrind check and of the secret
memory scan, the derivation of the byte patterns searched for, and the Valgrind report parser."""
import argparse, hashlib, json, os, re, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(sys.argv[0]))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
WORK = os.path.join(ROOT, '.work', 'ss')
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 2**256 - 2**32 - 977
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# ---------------------------------------------------------------- helpers
def sha(b): return hashlib.sha256(b).digest()
def tagged(tag, *parts):
    h = sha(tag.encode()); return sha(h + h + b''.join(parts))
def i2b(x): return x.to_bytes(32, 'big')

def ec_add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    l = (3 * a[0] * a[0] * pow(2 * a[1], -1, P) if a == b else (b[1] - a[1]) * pow(b[0] - a[0], -1, P)) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)
def ec_mul(k, pt=G):
    r = None
    while k:
        if k & 1: r = ec_add(r, pt)
        pt = ec_add(pt, pt); k >>= 1
    return r
def comp(pt): return bytes([2 + (pt[1] & 1)]) + i2b(pt[0])

K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
IV = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
def compress(st, blk):
    M = 0xFFFFFFFF
    rr = lambda x, n: ((x >> n) | (x << (32 - n))) & M
    w = [int.from_bytes(blk[4*i:4*i+4], 'big') for i in range(16)]
    for i in range(16, 64):
        s0 = rr(w[i-15], 7) ^ rr(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = rr(w[i-2], 17) ^ rr(w[i-2], 19) ^ (w[i-2] >> 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & M)
    a, b, c, d, e, f, g, h = st
    for i in range(64):
        t1 = (h + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & f) ^ (~e & M & g)) + K[i] + w[i]) & M
        t2 = ((rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & M
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & M, c, b, a, (t1 + t2) & M
    return [(x + y) & M for x, y in zip(st, [a, b, c, d, e, f, g, h])]
def tagged_midstate_after(tag, data64):
    h = sha(tag.encode())
    st = compress(IV, h + h)
    st = compress(st, data64)
    return b''.join(x.to_bytes(4, 'little') for x in st)   # memory layout on little-endian x86

def make_cases(smoke):
    keys = [1, 2, N - 1]
    cases = {'schnorr': [], 'ecdsa': []}
    smsgs = [b'', b'\x00', bytes(range(32)), bytes(range(65))]
    emsgs = [bytes(32), i2b(1), i2b(N - 1), i2b(N + 5)]
    for ki, k in enumerate(keys):
        for mi in range(4):
            rs = sha(f'Protocol29/S/{ki}/{mi}'.encode()); re_ = sha(f'Protocol29/E/{ki}/{mi}'.encode())
            m = smsgs[mi]
            cases['schnorr'].append((f's{ki}m{mi}', f'S s{ki}m{mi} {i2b(k).hex()} {rs.hex()} {m.hex() or "-"}', k, rs, m))
            cases['ecdsa'].append((f'e{ki}m{mi}', f'E e{ki}m{mi} {i2b(k).hex()} {emsgs[mi].hex()} {re_.hex()}', k, re_, emsgs[mi]))
    if smoke:  # one odd-parity key (n-1 has the same x as 1, other parity) and the empty message
        pick = lambda sch: [c for c in cases[sch] if c[0][1] in '02' and c[0][3] in '02']
        cases = {s: pick(s)[:1] + [c for c in cases[s] if c[0] in ('s1m3', 'e1m3')] for s in cases}
    return cases

def make_scan_cases(smoke):
    """Memory-scan cases: keys with no zero-heavy bytes (the keys 1, 2, n-1 are mostly zeros and
    useless as byte patterns). Keys come from SHA256("Protocol56/key/<i>"), chosen so that both
    public-key parities occur (3 cases, or 1 for smoke)."""
    keys = []
    for i in range(64):
        k = int.from_bytes(sha(f'Protocol56/key/{i}'.encode()), 'big') % (N - 1) + 1
        keys.append((i, k, ec_mul(k)[1] & 1))
    pick = [x for x in keys if x[2] == 0][:2] + [x for x in keys if x[2] == 1][:1]
    if smoke: pick = pick[:1]
    cases = {'schnorr': [], 'ecdsa': []}
    smsgs = [b'', bytes(range(32)), bytes(range(65))]
    for j, (i, k, par) in enumerate(pick):
        rho = sha(f'Protocol56/rho/{i}'.encode()); em = sha(f'Protocol56/msg/{i}'.encode())
        cases['schnorr'].append((f'k{i}p{par}', f'S k{i}p{par} {i2b(k).hex()} {rho.hex()} {smsgs[j].hex() or "-"}', k, rho, smsgs[j]))
        cases['ecdsa'].append((f'k{i}p{par}', f'E k{i}p{par} {i2b(k).hex()} {em.hex()} {rho.hex()}', k, rho, em))
    return cases

def derive_patterns(scheme, c, pub):
    """Secret byte patterns for one case, from public outputs; cross-checked against R0."""
    _, _, sk, rho, msg = c
    hc, pkb, R0, sigb = (bytes.fromhex(pub[x]) for x in ('hc', 'pk', 'R0', 'sig'))
    pt = ec_mul(sk)
    if scheme == 'schnorr':
        assert pkb == i2b(pt[0]), 'pk mismatch'
        d = sk if pt[1] % 2 == 0 else N - sk
        t0 = bytes(a ^ b for a, b in zip(i2b(d), tagged('BIP0340/aux', hc)))
        k0d = tagged('s2c/schnorr/nonce', t0, pkb, msg, hc)
        ptag = 's2c/schnorr/point'
        extra = {'d_norm': d, 't0': t0}
    else:
        assert pkb == comp(pt), 'pk mismatch'
        d = sk
        dmask = bytes(a ^ b for a, b in zip(i2b(d), tagged('s2c/ecdsa/aux', hc)))
        pk33 = comp(pt)
        k0d = tagged('s2c/ecdsa/nonce', dmask, pk33, msg, hc)
        ptag = 's2c/ecdsa/point'
        extra = {'dmask': dmask}
    k0 = int.from_bytes(k0d, 'big') % N
    R = ec_mul(k0)
    assert R0 == comp(R), 'R0 does not match derived k0 (pattern derivation wrong)'
    t = int.from_bytes(tagged(ptag, R0, rho), 'big')
    assert t < N
    kp = (k0 + t) % N
    assert sigb[:32] == i2b(ec_mul(kp)[0] % (N if scheme == 'ecdsa' else P)), "signature r does not match x(k'G): t or k' derivation wrong"
    pats = {}
    def scal(name, v, be=True):
        b = v if isinstance(v, bytes) else i2b(v)
        pats[name + '/be'] = (b, 8)
        pats[name + '/le'] = (b[::-1], 8)   # secp256k1_scalar limbs, little-endian in memory
    scal('sk', sk)
    pats['rho'] = (rho, 8)
    if 'd_norm' in extra and extra['d_norm'] != sk: scal('d_norm', extra['d_norm'])
    for k, v in extra.items():
        if isinstance(v, bytes): pats[k] = (v, 8)
    scal('k0', k0d); scal('t', t); scal("k'", kp)
    if scheme == 'schnorr': scal("k'neg", N - kp)
    else: scal("k'inv", pow(kp, -1, N))
    data = R0 + rho
    pats['sha_t_state'] = (tagged_midstate_after(ptag, data[:64]), 8)
    pats['sha_t_buf'] = (bytes([rho[31], 0x80]) + bytes(7), 9)
    return pats

def run(cmd, **kw):
    t = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return p, time.time() - t

ERR_HEAD = re.compile(r'==\d+== (Conditional jump or move depends on uninitialised value\(s\)|Use of uninitialised value of size \d+)')
FRAME = re.compile(r'==\d+==\s+(?:at|by) 0x[0-9A-Fa-f]+: (\S+) \((?:in .*|(\S+?):(\d+))\)')

def parse_valgrind(text):
    hits, stage, cur = [], None, None
    for ln in text.split('\n'):
        m = re.match(r'@@STAGE (\S+) (\S+)', ln)
        if m: stage = m.group(1); cur = None; continue
        if ERR_HEAD.match(ln):
            cur = {'stage': stage, 'kind': ERR_HEAD.match(ln).group(1)[:12], 'frames': []}; hits.append(cur); continue
        f = FRAME.match(ln)
        if f and cur is not None and 'origin' not in cur:
            cur['frames'].append((f.group(1), f.group(2), int(f.group(3)) if f.group(3) else None))
        elif cur is not None and 'Uninitialised value was created' in ln:
            cur['origin'] = True
        elif cur is not None and ln.strip() == '==%s==' % ln.split('==')[1]:
            pass
    return hits

def src_line(tree, base, line, func):
    cands = []
    for dp, _, fs in os.walk(tree):
        if base in fs: cands.append(os.path.join(dp, base))
    best = None
    for c in cands:
        lines = open(c).read().split('\n')
        if line - 1 < len(lines):
            if best is None or func in '\n'.join(lines): best = (c, lines[line - 1].strip())
            if func in '\n'.join(lines): break
    return best

def clean_func(f): return re.sub(r'\.(constprop|isra|part|cold)\.\d+', '', f)
