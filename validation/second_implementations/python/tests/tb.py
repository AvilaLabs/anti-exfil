"""Test builder and drivers: builds PSBTs of every spend form, runs the program
as a subprocess, and checks results with independent code."""
import copy
import os
import struct
import subprocess
import sys

import indep as I

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MAIN = os.path.join(ROOT, "main.py")
SCRATCH = os.path.join(ROOT, "tests", "scratch")
os.makedirs(SCRATCH, exist_ok=True)

DEV = [int.from_bytes(I.H(b"aexf-dev-key" + bytes([i])), "big") % I.n for i in range(4)]
OTHER = [int.from_bytes(I.H(b"aexf-other-key" + bytes([i])), "big") % I.n for i in range(6)]


def pub(sk):
    return I.comp(I.pubof(sk))


def xonly(sk):
    return pub(sk)[1:]


def sk_hex(sk):
    return sk.to_bytes(32, "big").hex()


def push(b):
    assert len(b) < 76
    return bytes([len(b)]) + b


def le32(v):
    return struct.pack("<I", v)


PATH_ECDSA = le32(0x80000000 + 84) + le32(0x80000000) + le32(0) + le32(0)
PATH_TR = le32(0x80000000 + 86) + le32(0x80000000) + le32(0) + le32(0)
FP = b"\x01\x02\x03\x04"


def multisig(keys, m):
    s = bytes([0x50 + m])
    for k in keys:
        s += push(k)
    return s + bytes([0x50 + len(keys), 0xAE])


class Case:
    pass


def make(forms, version=0, outs=None, locktime=0, fee=1000, nwu_all=False):
    """forms: list of dict(form, ht=None, key=0, amount=100000, seq=...). Returns Case."""
    c = Case()
    c.version = version
    c.forms = forms
    tx = I.Tx(version=2, locktime=locktime)
    prevtxs = []
    info = []
    total = 0
    for n_, f in enumerate(forms):
        form = f["form"]
        amount = f.get("amount", 100000)
        total += amount
        dk = DEV[f.get("key", 0)]
        P = pub(dk)
        h = I.h160(P)
        d = {"form": form, "amount": amount, "dk": dk, "pub": P}
        if form == "p2pkh":
            spk = b"\x76\xa9\x14" + h + b"\x88\xac"
            d["script_code"] = spk
        elif form == "p2wpkh":
            spk = b"\x00\x14" + h
            d["script_code"] = b"\x76\xa9\x14" + h + b"\x88\xac"
        elif form == "p2sh-p2wpkh":
            rs = b"\x00\x14" + h
            spk = b"\xa9\x14" + I.h160(rs) + b"\x87"
            d["redeem"] = rs
            d["script_code"] = b"\x76\xa9\x14" + h + b"\x88\xac"
        elif form in ("p2wsh-single", "p2sh-p2wsh-single", "p2sh-single"):
            ws = f.get("script") or (push(P) + b"\xac")
            d["ws"] = ws
        elif form in ("p2wsh-multi", "p2sh-p2wsh-multi", "p2sh-multi"):
            keys = [pub(OTHER[0]), P, pub(OTHER[1])]
            ws = f.get("script") or multisig(keys, 2)
            d["ws"] = ws
        elif form == "tr-key":
            x = xonly(dk)
            mr = b"" if not f.get("merkle") else I.H(b"merkle-root-" + bytes([n_]))
            Q = I.tweak_pub(x, mr)
            spk = b"\x51\x20" + Q[0].to_bytes(32, "big")
            d.update(x=x, merkle=mr, Q=Q)
        elif form == "tr-script":
            x = xonly(dk)
            L1 = f.get("leaf") or (push(x) + b"\xac")
            ver = f.get("ver", 0xC0)
            nodes = f.get("nodes") or [I.leaf_hash(push(xonly(OTHER[2])) + b"\xac")]
            l1 = I.leaf_hash(L1, ver)
            k = l1
            for nd in nodes:
                a, b = (k, nd) if k < nd else (nd, k)
                k = I.TH("TapBranch", a + b)
            mr = k
            ip = f.get("ip") or xonly(OTHER[3])
            Q = I.tweak_pub(ip, mr)
            spk = b"\x51\x20" + Q[0].to_bytes(32, "big")
            control = bytes([ver | (Q[1] & 1)]) + ip + b"".join(nodes)
            d.update(x=x, L1=L1, l1=l1, control=control, ip=ip, merkle=mr, Q=Q, ver=ver)
        else:
            raise ValueError(form)
        if form.endswith("-single") or form.endswith("-multi"):
            if form.startswith("p2wsh"):
                spk = b"\x00\x20" + I.H(ws)
                d["script_code"] = ws
            elif form.startswith("p2sh-p2wsh"):
                rs = b"\x00\x20" + I.H(ws)
                spk = b"\xa9\x14" + I.h160(rs) + b"\x87"
                d["redeem"] = rs
                d["script_code"] = ws
            else:
                spk = b"\xa9\x14" + I.h160(ws) + b"\x87"
                d["redeem"] = ws
                d["script_code"] = ws
        d["spk"] = spk
        legacy = form in ("p2pkh", "p2sh-single", "p2sh-multi")
        d["legacy"] = legacy
        if legacy or nwu_all or f.get("nwu"):
            pt = I.Tx(version=1)
            pt.add_in(I.H(b"funding" + bytes([n_])), 0)
            for _ in range(f.get("vout", 0) if f.get("pad", True) else 0):
                pt.add_out(1, b"\x6a")
            pt.add_out(amount, spk)
            d["prevtx"] = pt
            txid = pt.txid()
        else:
            txid = I.H(b"fund-" + bytes([n_]) + form.encode())
        d["txid"] = txid
        tx.add_in(txid, f.get("vout", 0), f.get("seq", 0xFFFFFFFD - n_))
        info.append(d)
    if outs is None:
        outs = [(total - fee, b"\x00\x14" + I.h160(pub(OTHER[4])))]
    for v, s in outs:
        tx.add_out(v, s)
    c.tx = tx
    c.info = info
    spent = [(d["amount"], d["spk"]) for d in info]
    c.spent = spent
    # input maps
    imaps = []
    pairs = []
    for n_, (f, d) in enumerate(zip(forms, info)):
        m = {}
        ht = f.get("ht")
        form = d["form"]
        if ht is not None:
            m[b"\x03"] = le32(ht)
        scheme = "bip340" if form.startswith("tr") else "ecdsa"
        eff_ht = ht if ht is not None else (0 if scheme == "bip340" else 1)
        if "prevtx" in d:
            m[b"\x00"] = d["prevtx"].ser()
        if not d["legacy"] and (not d.get("prevtx") or f.get("wu")):
            m[b"\x01"] = struct.pack("<q", d["amount"]) + I.cs(len(d["spk"])) + d["spk"]
        if form.startswith("tr") and "prevtx" in d and not f.get("wu"):
            pass
        if "redeem" in d:
            m[b"\x04"] = d["redeem"]
        if "ws" in d and form.startswith(("p2wsh", "p2sh-p2wsh")):
            m[b"\x05"] = d["ws"]
        pair = {"i": n_, "scheme": scheme, "ht": eff_ht, "pub": d["pub"]}
        if scheme == "ecdsa":
            m[b"\x06" + d["pub"]] = FP + PATH_ECDSA
            try:
                if d["legacy"]:
                    mm = I.legacy_sighash(tx, n_, d["script_code"], eff_ht)
                else:
                    mm = I.bip143_sighash(tx, n_, d["script_code"], d["amount"], eff_ht)
            except (AssertionError, ValueError, struct.error):
                mm = bytes(32)
            pair.update(kind="ecdsa", keyid=d["pub"], m=mm, pk=d["pub"], sigkey=b"\x02" + d["pub"])
        elif form == "tr-key":
            m[b"\x17"] = d["x"]
            if d["merkle"]:
                m[b"\x18"] = d["merkle"]
            m[b"\x16" + d["x"]] = b"\x00" + FP + PATH_TR
            try:
                mm = I.taproot_sighash(tx, n_, eff_ht, spent)
            except (AssertionError, ValueError, struct.error, IndexError):
                mm = bytes(32)
            pair.update(kind="tr_key", keyid=d["x"], m=mm, pk=d["Q"][0].to_bytes(32, "big"),
                        sigkey=b"\x13")
        else:
            m[b"\x17"] = d["ip"]
            m[b"\x15" + d["control"]] = d["L1"] + bytes([d["ver"]])
            m[b"\x16" + d["x"]] = b"\x01" + d["l1"] + FP + PATH_TR
            try:
                mm = I.taproot_sighash(tx, n_, eff_ht, spent, ext=d["l1"])
            except (AssertionError, ValueError, struct.error, IndexError):
                mm = bytes(32)
            keyid = d["x"] + d["l1"]
            pair.update(kind="tr_script", keyid=keyid, m=mm, pk=d["x"], sigkey=b"\x14" + keyid)
        pairs.append(pair)
        imaps.append(m)
    c.imaps = imaps
    c.pairs = pairs
    c.gmap = {}
    c.omaps = [dict() for _ in tx.vout]
    if version == 0:
        c.gmap[b"\x00"] = tx.ser()
    else:
        c.gmap[b"\xfb"] = le32(2)
        c.gmap[b"\x02"] = le32(tx.version)
        c.gmap[b"\x04"] = I.cs(len(tx.vin))
        c.gmap[b"\x05"] = I.cs(len(tx.vout))
        if locktime:
            c.gmap[b"\x03"] = le32(locktime)
        for n_, i in enumerate(tx.vin):
            imaps[n_][b"\x0e"] = i["txid"]
            imaps[n_][b"\x0f"] = le32(i["vout"])
            imaps[n_][b"\x10"] = le32(i["seq"])
        for o, m in zip(tx.vout, c.omaps):
            m[b"\x03"] = struct.pack("<q", o["value"])
            m[b"\x04"] = o["spk"]
    c.dev_sks = sorted(set(d["dk"] for d in info))
    return c


def serialize(c):
    maps = [sorted(c.gmap.items())] + [sorted(m.items()) for m in c.imaps] + [sorted(m.items()) for m in c.omaps]
    return I.write_psbt(maps)


def psbt_hex(c):
    return serialize(c).hex()


def clone(c):
    return copy.deepcopy(c)


def sks_args(sks):
    a = []
    for s in sks:
        a += ["--secret-key", sk_hex(s)]
    return a


def rho_for(i, keyid, salt=b""):
    return I.H(b"rho" + salt + bytes([i]) + keyid)


def rho_args(c, salt=b""):
    a = []
    for p in c.pairs:
        a += ["--rho", "%d:%s:%s" % (p["i"], p["keyid"].hex(), rho_for(p["i"], p["keyid"], salt).hex())]
    return a


def run_signer(psbt_hex_, sks, decline=False, timeout=120):
    args = [sys.executable, "-B", MAIN, "signer"] + sks_args(sks) + (["--decline"] if decline else [])
    r = subprocess.run(args, input=psbt_hex_ + "\n", capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr


class HostResult:
    pass


def run_host(c_or_hex, dev_pubs, store, device=None, max_retries=0, rhos=None, ack=False,
             extra=None, timeout=240, kill_after_requests=None):
    """Runs the host. device(req_hex, k) -> response line string, or None to close the
    pipe. Returns HostResult with .lines, .rc, .requests, .status, .count, .result."""
    if isinstance(c_or_hex, str):
        psbt = c_or_hex
    else:
        psbt = psbt_hex(c_or_hex)
    args = [sys.executable, "-B", MAIN, "host"]
    for k in dev_pubs:
        args += ["--device-key", k.hex()]
    args += ["--store", store, "--max-retries", str(max_retries), "--psbt", psbt]
    args += rhos or []
    if ack:
        args.append("--ack-warning")
    args += extra or []
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    res = HostResult()
    res.lines = []
    res.requests = []
    k = 0
    while True:
        line = proc.stdout.readline()
        if line == "":
            break
        line = line.rstrip("\n")
        res.lines.append(line)
        if line.startswith("REQUEST "):
            req = line[8:]
            res.requests.append(req)
            if kill_after_requests is not None and len(res.requests) >= kill_after_requests:
                proc.kill()
                break
            resp = device(req, k) if device else None
            k += 1
            try:
                if resp is None:
                    proc.stdin.close()
                else:
                    proc.stdin.write(resp + "\n")
                    proc.stdin.flush()
            except BrokenPipeError:
                pass
    try:
        proc.stdin.close()
    except Exception:
        pass
    res.stderr = proc.stderr.read()
    proc.wait(timeout=timeout)
    proc.stdout.close()
    proc.stderr.close()
    res.rc = proc.returncode
    res.status = res.lines[-1] if res.lines else ""
    res.count = None
    for ln in res.lines:
        if ln.startswith("COUNT "):
            res.count = int(ln.split()[1])
    res.result = res.status[7:] if res.status.startswith("RESULT ") else None
    return res


def honest_device(sks):
    def dev(req, k):
        rc, out, err = run_signer(req, sks)
        return out if rc == 0 else "ERROR"
    return dev


def check_result(c, result_hex, r0s=None, rhos=None):
    """Independent verification of every pair's signature in a result PSBT."""
    maps = I.read_psbt(bytes.fromhex(result_hex))
    imaps = maps[1:1 + len(c.imaps)]
    for p in c.pairs:
        m = dict(imaps[p["i"]])
        assert p["sigkey"] in m, "signature missing for %r" % p["kind"]
        v = m[p["sigkey"]]
        if p["scheme"] == "ecdsa":
            assert v[-1] == p["ht"]
            assert I.ecdsa_verify_der(p["pk"], p["m"], v), "bad ecdsa signature"
        else:
            if p["ht"] == 0:
                assert len(v) == 64
                sig = v
            else:
                assert len(v) == 65 and v[64] == p["ht"]
                sig = v[:64]
            assert I.bip340_verify(p["pk"], p["m"], sig), "bad bip340 signature"
        for t in (0x21, 0x22, 0x23):
            assert not any(k[0] == t for k in m), "AE field left in result"
    return maps


# ------------------------------------------------------------ request helpers (in-process)
sys.path.insert(0, ROOT)


def hc_of(p, rho):
    tag = "s2c/schnorr/data" if p["scheme"] == "bip340" else "s2c/ecdsa/data"
    return I.TH(tag, rho)


def req1(c, salt=b"", with_nc=None):
    c2 = clone(c)
    for p in c2.pairs:
        rho = rho_for(p["i"], p["keyid"], salt)
        c2.imaps[p["i"]][b"\x21" + p["keyid"]] = hc_of(p, rho)
    return psbt_hex(c2)


def req2(c, salt=b"", with_hc=False):
    c2 = clone(c)
    for p in c2.pairs:
        rho = rho_for(p["i"], p["keyid"], salt)
        c2.imaps[p["i"]][b"\x23" + p["keyid"]] = rho
        if with_hc:
            c2.imaps[p["i"]][b"\x21" + p["keyid"]] = hc_of(p, rho)
    return psbt_hex(c2)


def inproc_sign(hex_, sks, decline=False):
    import signer
    old = sys.stderr
    sys.stderr = open(os.devnull, "w")
    try:
        return signer.run([sk_hex(s) for s in sks], decline, hex_).hex()
    finally:
        sys.stderr.close()
        sys.stderr = old


def inproc_device(sks, decline=False):
    def dev(req, k):
        try:
            return inproc_sign(req, sks, decline)
        except Exception:
            return "ERROR"
    return dev


def r0_of(resp_hex, p):
    maps = I.read_psbt(bytes.fromhex(resp_hex))
    return dict(maps[1 + p["i"]])[b"\x22" + p["keyid"]]


def expected_r0(p, dk, salt=b""):
    """Independent replay of step 2 for the pair, from the case's own expected m."""
    rho = rho_for(p["i"], p["keyid"], salt)
    hc = hc_of(p, rho)
    if p["scheme"] == "bip340":
        sk = dk
        if p["kind"] == "tr_key":
            raise NotImplementedError
        Pt = I.mul(sk)
        d = sk if Pt[1] % 2 == 0 else I.n - sk
        t0 = bytes(a ^ b for a, b in zip(d.to_bytes(32, "big"), I.TH("BIP0340/aux", hc)))
        k0 = int.from_bytes(I.TH("s2c/schnorr/nonce", t0 + Pt[0].to_bytes(32, "big") + p["m"] + hc), "big") % I.n
    else:
        pk = I.comp(I.mul(dk))
        mask = bytes(a ^ b for a, b in zip(dk.to_bytes(32, "big"), I.TH("s2c/ecdsa/aux", hc)))
        k0 = int.from_bytes(I.TH("s2c/ecdsa/nonce", mask + pk + p["m"] + hc), "big")
    return I.comp(I.mul(k0))
