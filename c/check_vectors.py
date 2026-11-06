#!/usr/bin/env python3
"""Run vectors/bip-anti-exfil.json against the module on each base.

For every valid vector the driver must give the same pk, hc, R0_bytes and sig
and the host check must accept. Every reject tuple must be rejected, or be
listed as not expressible with its reason. Forced-hash cases run in the
library's own tests built with the test seam (tests-seam target); this script
runs that binary and checks the generated vector header is for this file.

Usage: check_vectors.py [--bases benma zkp] [--opt O2] [--out FILE.json]
Exit 0 only if nothing mismatched and the seam tests passed."""
import argparse, collections, hashlib, json, os, pathlib, re, shlex, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
B = pathlib.Path(os.environ.get("C_BUILD", ROOT / ".work/c/build"))
HDR = ROOT / "c/module/src/modules/anti_exfil/tests_vectors.h"
NOT_IN_SEAM = {"bip340-forced-isolated-s-equals-n":
               "needs the BIP340 challenge hash forced; host_verify uses the base's own schnorrsig_verify for that, outside the module"}


def h(x):
    return x if x else "-"


def run(exe, lines):
    p = subprocess.run(RUNNER + [str(exe)], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True, timeout=600)
    out = p.stdout.strip().split("\n") if p.stdout.strip() else []
    # one result row per input, in order, each naming its command and vector id
    if [l.split()[:2] for l in out] != [l.split()[:2] for l in lines]:
        raise SystemExit("%s: %d result rows for %d inputs, or rows out of order" % (exe, len(out), len(lines)))
    return out


# C_RUNNER: command prefix for foreign-CPU binaries, for example "qemu-s390x" (cross_arch)
RUNNER = shlex.split(os.environ.get("C_RUNNER", ""))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bases", nargs="+", default=["benma", "zkp"])
    ap.add_argument("--opt", default="O2")
    ap.add_argument("--out")
    ap.add_argument("--san", help="use the sanitizers sanitizer builds BASE-SAN-driver and BASE-SAN-tests (san_build.sh)")
    a = ap.parse_args()
    raw = (ROOT / "vectors/bip-anti-exfil.json").read_bytes()
    vhash = hashlib.sha256(raw).hexdigest()
    doc = json.loads(raw)
    mism, report = [], {"vector_file_sha256": vhash, "bases": {}}
    stale = vhash not in HDR.read_text()
    if stale:
        mism.append("tests_vectors.h was generated from a different vector file; run gen_test_vectors.py")
    for base in a.bases:
        exe = B / (("%s-%s-driver" % (base, a.san)) if a.san else ("%s-driver%s" % (base, a.opt))) / "vector_driver"
        rep = report["bases"][base] = {}
        for scheme, v, hv in (("bip340", "VB", "HB"), ("ecdsa", "VE", "HE")):
            sec, s = doc[scheme], collections.OrderedDict()
            res = run(exe, ["%s %s %s %s %s" % (v, c["id"], c["sk"], c["rho"], h(c["m"])) for c in sec["valid"]])
            same = 0
            for c, line in zip(sec["valid"], res):
                f = line.split()
                if f[2:3] == ["ok=1"] and f[3:7] == [c["pk"], c["hc"], c["R0_bytes"], c["sig"]]:
                    same += 1
                else:
                    mism.append("%s/%s: derivation differs: %s" % (base, c["id"], line))
            s["valid_derivation_match"] = "%d of %d" % (same, len(sec["valid"]))
            tup = lambda c: "%s %s %s %s %s %s %s" % (hv, c["id"], h(c["pk"]), h(c["m"]), h(c["rho"]), h(c["R0_bytes"]), h(c["sig"]))
            res = run(exe, [tup(c) for c in sec["valid"]])
            acc = 0
            for c, line in zip(sec["valid"], res):
                if line.split()[2] == "ACCEPT":
                    acc += 1
                else:
                    mism.append("%s/%s: host rejects a valid vector: %s" % (base, c["id"], line))
            s["valid_host_accept"] = "%d of %d" % (acc, len(sec["valid"]))
            res = run(exe, [tup(c) for c in sec["reject"]])
            cls, na = collections.defaultdict(collections.Counter), []
            for c, line in zip(sec["reject"], res):
                vd = line.split(None, 2)[2]
                if vd == "ACCEPT":
                    mism.append("%s/%s: host ACCEPTS a rejection case" % (base, c["id"]))
                    cls[c["defect"]]["ACCEPTED (mismatch)"] += 1
                elif vd.startswith("NA"):
                    cls[c["defect"]]["not expressible"] += 1
                    na.append("%s (%s)" % (c["id"], vd[3:]))
                elif vd.startswith("REJECT parse"):
                    cls[c["defect"]]["rejected at parse"] += 1
                else:
                    cls[c["defect"]]["rejected by host_verify"] += 1
            s["reject_by_class"] = {k: dict(x) for k, x in sorted(cls.items())}
            s["reject_not_expressible"] = na
            s["forced_hash_cases"] = {c["id"]: ("not run: " + NOT_IN_SEAM[c["id"]]) if c["id"] in NOT_IN_SEAM else "seam test"
                                      for c in sec["forced_hash"]}
            rep[scheme] = s
        t = B / (("%s-%s-tests" % (base, a.san)) if a.san else ("%s-tests-seam%s" % (base, a.opt))) / "tests"
        p = subprocess.run(RUNNER + [str(t), "-t=anti_exfil", "-i=64"], capture_output=True, text=True, timeout=1200)
        rep["seam_tests"] = {"returncode": p.returncode, "tail": p.stdout.strip().splitlines()[-3:]}
        if p.returncode:
            mism.append("%s: seam tests failed: %s" % (base, p.stdout[-400:] + p.stderr[-400:]))
    report["mismatches"] = mism
    txt = json.dumps(report, indent=2)
    print(txt)
    if a.out:
        pathlib.Path(a.out).write_text(txt + "\n")
    print("mismatches: %d" % len(mism))
    return 1 if mism else 0


if __name__ == "__main__":
    sys.exit(main())
