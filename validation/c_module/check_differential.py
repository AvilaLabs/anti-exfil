#!/usr/bin/env python3
"""differential: byte-for-byte comparison of the module (both bases) with the
Python reference (reference/anti_exfil.py, unchanged).
Inputs are deterministic: SHA256("differential-input/<scheme>/<i>/<field>"). BIP340 messages
cycle through empty, 1, 31, 32, 33, 64, 65, 119, 120, 1000 bytes and random lengths;
key parity is recorded. Usage: check_differential.py [--n 10000] [--out FILE]"""
import argparse, hashlib, json, os, pathlib, subprocess, sys, time
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference"))
import anti_exfil as ref  # noqa: E402 (unchanged reference)
B = pathlib.Path(os.environ.get("C_BUILD", ROOT / ".work/c/build"))
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
LENS = [0, 1, 31, 32, 33, 64, 65, 119, 120, 1000]

def h(*p):
    return hashlib.sha256("/".join(map(str, p)).encode()).digest()

def stream(tag, i, n):
    out, j = b"", 0
    while len(out) < n:
        out += h("differential-input", tag, i, "m", j); j += 1
    return out[:n]

def run(exe, lines):
    p = subprocess.run([str(exe)], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True, timeout=1500)
    return p.stdout.strip().split("\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=10000)
    ap.add_argument("--out")
    ap.add_argument("--label", default="run")
    a = ap.parse_args()
    rep = {"label": a.label, "n_per_scheme": a.n, "schemes": {}}
    bad = 0
    for scheme, vcmd in (("bip340", "VB"), ("ecdsa", "VE")):
        cases = []
        for i in range(a.n):
            sk = (int.from_bytes(h("differential-input", scheme, i, "sk"), "big") % (N - 1)) + 1
            rho = h("differential-input", scheme, i, "rho")
            if scheme == "ecdsa":
                m = h("differential-input", scheme, i, "msg")
            else:
                ln = LENS[i % len(LENS)] if i % 3 else int.from_bytes(h("differential-input", i, "len")[:2], "big") % 1100
                m = stream(scheme, i, ln)
            cases.append((i, sk.to_bytes(32, "big"), rho, m))
        hx = lambda b: b.hex() or "-"
        lines = ["%s %d %s %s %s" % (vcmd, i, sk.hex(), rho.hex(), hx(m)) for i, sk, rho, m in cases]
        t0 = time.time()
        outs = {b: run(B / ("%s-driverO2" % b) / "vector_driver", lines) for b in ("benma", "zkp")}
        t1 = time.time()
        mism = {"module_benma_vs_zkp": 0, "module_vs_python": 0}
        pk_parity = {0: 0, 1: 0}
        r0_parity = {0: 0, 1: 0}
        for (i, sk, rho, m), lb, lz in zip(cases, outs["benma"], outs["zkp"]):
            fb, fz = lb.split()[3:7], lz.split()[3:7]
            if lb.split()[2] != "ok=1" or lz.split()[2] != "ok=1":
                mism["module_vs_python"] += 1; continue
            mism["module_benma_vs_zkp"] += fb != fz
            pk = ref.public_key(sk) if scheme == "bip340" else ref.ecdsa_public_key(sk)
            if scheme == "bip340":
                hc = ref.host_commit(rho); r0 = ref.device_commit(sk, m, hc); sig = ref.device_sign(sk, m, rho)
                pk_parity[(int.from_bytes(sk, "big") * 1 and ref._mul(int.from_bytes(sk, "big"))[1]) & 1] += 1
            else:
                hc = ref.ecdsa_host_commit(rho); r0 = ref.ecdsa_device_commit(sk, m, hc); sig = ref.ecdsa_device_sign(sk, m, rho)
                pk_parity[pk[0] & 1] += 1
            r0_parity[r0[0] & 1] += 1
            mism["module_vs_python"] += fb != [pk.hex(), hc.hex(), r0.hex(), sig.hex()]
        t2 = time.time()
        bad += sum(mism.values())
        rep["schemes"][scheme] = {"cases": a.n, "mismatches": mism, "pk_parity_counts_odd_even": pk_parity, "R0_parity_counts": r0_parity,
                                  "message_lengths": sorted(set(len(c[3]) for c in cases))[:12] if scheme == "bip340" else "32",
                                  "message_length_range": [min(len(c[3]) for c in cases), max(len(c[3]) for c in cases)],
                                  "seconds_c": round(t1 - t0, 1), "seconds_python": round(t2 - t1, 1)}
        print(scheme, rep["schemes"][scheme], flush=True)
    rep["total_mismatches"] = bad
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(rep, indent=1) + "\n")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
