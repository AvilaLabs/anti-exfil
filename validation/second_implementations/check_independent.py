#!/usr/bin/env python3
"""Run an implementation through the PSBT vectors using CLI_CONTRACT.md.

    check_independent.py run <name> <folder> <out.json>     one implementation against the vectors
    check_independent.py interop <hostdir> <signerdir>      live pair, results compared with the vectors
    check_independent.py controls <out.json>                the harness against the reference and broken references
"""
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "psbt"))
sys.path.insert(0, str(ROOT / "reference"))
import anti_exfil as AE         # noqa: E402
import psbt_codec as C          # noqa: E402

VECTORS = ROOT / "vectors" / "bip-anti-exfil-psbt.json"
WORK = ROOT / ".work" / "second_implementations" / "harness"
TIMEOUT = 120
SIG_TYPES = (b"\x02", b"\x13", b"\x14")


def cmd_of(folder):
    folder = pathlib.Path(folder)
    if folder.name == "REFERENCE":
        return [sys.executable, "-B", str(pathlib.Path(__file__).with_name("reference_cli.py"))], str(ROOT)
    return shlex.split((folder / "RUN").read_text().strip()), str(folder)


def relevant(data):
    """What the vectors pin: core transaction, anti-exfil fields and signature fields, by input."""
    p = C.parse(bytes.fromhex(data) if isinstance(data, str) else data)
    fields = []
    for m in p.inputs:
        fields.append(sorted((k.hex(), v.hex()) for k, v in m.items()
                             if k[:1] in SIG_TYPES or k[:1] in (b"\x21", b"\x22", b"\x23")))
    return C.ser_tx(C.core_tx(p)).hex(), fields


def same(a, b):
    try:
        return relevant(a) == relevant(b)
    except Exception as e:      # a response we cannot parse is a mismatch
        return False


def signer_call(prog, cwd, keys, request, decline=False, env=None):
    args = list(prog) + ["signer"]
    for k in keys:
        args += ["--secret-key", k]
    if decline:
        args.append("--decline")
    try:
        p = subprocess.run(args, input=request + "\n", capture_output=True, text=True, timeout=TIMEOUT, cwd=cwd, env=env)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    return p.returncode, p.stdout.strip()


class HostProc:
    """Runs a host, and answers each REQUEST through answer(index, request hex)."""

    def __init__(self, prog, cwd, keys, store, retries, psbt, rhos, ack=False, env=None):
        args = list(prog) + ["host", "--store", str(store), "--max-retries", str(retries), "--psbt", psbt]
        for k in keys:
            args += ["--device-key", k]
        for i, kid, r in rhos:
            args += ["--rho", "%d:%s:%s" % (i, kid, r)]
        if ack:
            args.append("--ack-warning")
        self.args, self.cwd, self.env = args, cwd, env

    def run(self, answer):
        """Returns dict(code, last, count, requests)."""
        p = subprocess.Popen(self.args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, cwd=self.cwd, env=self.env, bufsize=1)
        out = {"code": None, "last": None, "count": None, "requests": []}
        try:
            for line in p.stdout:
                line = line.strip()
                if line.startswith("REQUEST "):
                    req = line[8:]
                    out["requests"].append(req)
                    resp = answer(len(out["requests"]) - 1, req)
                    if resp is None:
                        out["last"] = "HARNESS_NO_MORE_RESPONSES"
                        p.kill()
                        break
                    p.stdin.write(resp + "\n")
                    p.stdin.flush()
                elif line.startswith("COUNT "):
                    out["count"] = int(line[6:])
                elif line:
                    out["last"] = line
            out["code"] = p.wait(timeout=TIMEOUT)
        except (BrokenPipeError, subprocess.TimeoutExpired, ValueError) as e:
            p.kill()
            out["last"] = out["last"] or "HARNESS_ERROR %s" % type(e).__name__
        return out


def rhos_from_hashes(cid, first_request, n_max=64):
    """rho values for a vector whose pairs are not listed: n-th hash, matched to each hc in the request."""
    p = C.parse(bytes.fromhex(first_request))
    want = {}
    for i, m in enumerate(p.inputs):
        for typ, keyid, val in C.ae_entries(m):
            if typ == C.AE_HC:
                want[val] = (i, keyid.hex())
    out = []
    for n in range(1, n_max):
        rho = hashlib.sha256(("anti-exfil psbt vector/%s/rho/%d" % (cid, n)).encode()).digest()
        for hc in (AE.host_commit(rho), AE.ecdsa_host_commit(rho)):
            if hc in want:
                i, kid = want[hc]
                out.append((i, kid, rho.hex()))
    return out


def secrets_of(ex):
    seen = []
    for inp in ex["inputs"]:
        for k in inp["device_secret_keys"]:
            if k not in seen:
                seen.append(k)
    return seen


def run_impl(folder, env=None):
    prog, cwd = cmd_of(folder)
    v = json.loads(VECTORS.read_text())
    res = {"signer_exchanges": {}, "signer_refusals": {}, "host_exchanges": {}, "host_refusals": {},
           "host_accepts": {}, "request_refusals": {}, "lifecycle": {}}
    WORK.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(WORK)) as tmp:
        def store(name):
            return pathlib.Path(tmp) / (name + ".store")

        for ex in v["exchanges"]:
            keys = secrets_of(ex)
            why = []
            for q, r in (("first_request", "first_response"), ("second_request", "second_response")):
                code, out = signer_call(prog, cwd, keys, ex[q], env=env)
                if code != 0:
                    why.append("%s: exit %s" % (q, code))
                elif not same(out, ex[r]):
                    why.append("%s: response differs" % q)
            res["signer_exchanges"][ex["id"]] = why

            rhos = rhos_from_hashes(ex["id"], ex["first_request"])      # in draw order, which the reference CLI relies on
            assert sorted(rhos) == sorted((pr["input"], pr["key_identifier"], pr["rho"]) for pr in ex["pairs"]), ex["id"]
            seq = [ex["first_response"], ex["second_response"]]
            reqs = [ex["first_request"], ex["second_request"]]
            why = []

            def ans(i, req):
                if i >= 2:
                    return None
                if not same(req, reqs[i]):
                    why.append("request %d differs" % i)
                return seq[i]
            h = HostProc(prog, cwd, ex["device_keys"], store(ex["id"]), 0, ex["host_psbt"], rhos, env=env).run(ans)
            if h["code"] != 0 or not (h["last"] or "").startswith("RESULT "):
                why.append("exit %s last %s" % (h["code"], (h["last"] or "")[:40]))
            elif not same(h["last"][7:], ex["host_result"]):
                why.append("result differs")
            if h["count"] != 0:
                why.append("count %s" % h["count"])
            res["host_exchanges"][ex["id"]] = why

        for c in v["signer_refusals"]:
            pre = c.get("reason_code") == "not_approved"
            code, out = signer_call(prog, cwd, c["signer_holds_seeds_of"], c["request"], decline=pre, env=env)
            why = []
            if code == 0 or out:
                why.append("signed or answered (exit %s)" % code)
            elif code != 3:
                why.append("exit %s" % code)
            res["signer_refusals"][c["id"]] = why

        for cls, accept in (("host_refusals", False), ("host_accepts", True)):
            for c in v[cls]:
                rhos = rhos_from_hashes(c["id"], c["exchanges"][0]["request"])
                resp = [e["response"] for e in c["exchanges"]]

                def ans(i, req, resp=resp):
                    if i >= len(resp):
                        return None
                    return resp[i] if resp[i] is not None else "ERROR"
                h = HostProc(prog, cwd, c["device_keys"], store(c["id"]), c.get("max_retries", 0), c["host_psbt"], rhos, env=env).run(ans)
                why = []
                if accept:
                    if h["code"] != 0:
                        why.append("exit %s last %s" % (h["code"], (h["last"] or "")[:40]))
                    elif not same(h["last"][7:], c["host_result"]):
                        why.append("result differs")
                    if h["count"] != 0:
                        why.append("count %s" % h["count"])
                else:
                    if h["code"] != 3 or h["last"] != "FAILED":
                        why.append("exit %s last %s" % (h["code"], (h["last"] or "")[:40]))
                    if h["count"] != 1:
                        why.append("count %s" % h["count"])
                res[cls][c["id"]] = why

        for c in v["request_refusals"]:
            h = HostProc(prog, cwd, c["device_keys"], store(c["id"]), 0, c["host_psbt"], [], env=env).run(lambda i, r: "ERROR")
            why = []
            if h["requests"]:
                why.append("sent a request")
            if h["code"] != 4 or h["last"] != "REFUSED":
                why.append("exit %s last %s" % (h["code"], (h["last"] or "")[:40]))
            res["request_refusals"][c["id"]] = why

        # Lifecycle, as far as the contract can see it: the first refusal vector, then again on one store.
        c = v["host_refusals"][0]
        rhos = rhos_from_hashes(c["id"], c["exchanges"][0]["request"])
        resp = [e["response"] for e in c["exchanges"]]
        ans = lambda i, req: resp[i] if i < len(resp) else None
        st = store("lifecycle")

        def fresh(run):
            """A real host draws new values for each attempt, so each run gets its own."""
            return [(i, kid, hashlib.sha256(("lifecycle/%d/" % run + r).encode()).hexdigest()) for i, kid, r in rhos]

        def life(run, **kw):
            return HostProc(prog, cwd, c["device_keys"], st, 0, c["host_psbt"], rhos if run == 1 else fresh(run), env=env, **kw).run(ans)
        h1 = life(1)
        h2 = life(2)
        h3 = life(3, ack=True)
        h4 = life(4)
        res["lifecycle"]["L1-first-failure-counted"] = [] if (h1["code"], h1["count"]) == (3, 1) else ["%s %s" % (h1["code"], h1["count"])]
        res["lifecycle"]["L2-warning-blocks-next-attempt"] = [] if (h2["code"], h2["count"], h2["requests"]) == (5, 1, []) else ["%s %s %d requests" % (h2["code"], h2["count"], len(h2["requests"]))]
        res["lifecycle"]["L3-acknowledged-attempt-runs-and-counts"] = [] if (h3["code"], h3["count"]) == (3, 2) and h3["requests"] else ["%s %s" % (h3["code"], h3["count"])]
        res["lifecycle"]["L4-acknowledgement-used-up"] = [] if (h4["code"], h4["count"], h4["requests"]) == (5, 2, []) else ["%s %s" % (h4["code"], h4["count"])]
    return res


def tally(res):
    out = {}
    for cls, d in res.items():
        out[cls] = {"pass": sum(1 for w in d.values() if not w), "total": len(d),
                    "failed": {k: w for k, w in d.items() if w}}
    out["all_pass"] = all(not w for d in res.values() for w in d.values())
    return out


def interop(hostdir, signerdir):
    hprog, hcwd = cmd_of(hostdir)
    sprog, scwd = cmd_of(signerdir)
    v = json.loads(VECTORS.read_text())
    bad = {}
    WORK.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(WORK)) as tmp:
        for ex in v["exchanges"]:
            keys = secrets_of(ex)
            rhos = rhos_from_hashes(ex["id"], ex["first_request"])      # in draw order, which the reference CLI relies on
            assert sorted(rhos) == sorted((pr["input"], pr["key_identifier"], pr["rho"]) for pr in ex["pairs"]), ex["id"]

            def ans(i, req):
                code, out = signer_call(sprog, scwd, keys, req)
                return out if code == 0 else "ERROR"
            st = pathlib.Path(tmp) / (ex["id"] + ".store")
            h = HostProc(hprog, hcwd, ex["device_keys"], st, 0, ex["host_psbt"], rhos).run(ans)
            why = []
            if h["code"] != 0:
                why.append("exit %s last %s" % (h["code"], (h["last"] or "")[:40]))
            elif not same(h["last"][7:], ex["host_result"]):
                why.append("result differs")
            if why:
                bad[ex["id"]] = why
    return {"total": len(v["exchanges"]), "failed": bad}


def controls(out):
    """The reference must pass everything. Each broken reference must fail where named."""
    ref = pathlib.Path("REFERENCE")
    rec = {}
    base = tally(run_impl(ref))
    rec["reference"] = base
    expect = {"signer_never_fails": "signer_refusals", "signer_flips_byte": "signer_exchanges",
              "host_never_fails": "host_refusals", "host_no_count": "host_refusals"}
    fired = {}
    for mutant, cls in expect.items():
        env = dict(os.environ, CLI_MUTANT=mutant)
        t = tally(run_impl(ref, env=env))
        rec[mutant] = {k: {"pass": t[k]["pass"], "total": t[k]["total"]} for k in t if k != "all_pass"}
        fired[mutant] = t[cls]["pass"] < t[cls]["total"]
    rec["interop_reference"] = interop(ref, ref)
    rec["controls_fired"] = fired
    rec["verdict"] = "PASS" if base["all_pass"] and all(fired.values()) and not rec["interop_reference"]["failed"] else "INVALID"
    pathlib.Path(out).write_text(json.dumps(rec, indent=1, sort_keys=True) + "\n")
    print(rec["verdict"], {k: "%d/%d" % (v["pass"], v["total"]) for k, v in base.items() if k != "all_pass"}, fired)
    for k, v in base.items():
        if k != "all_pass" and v["failed"]:
            print(k, json.dumps(v["failed"])[:1500])


def main():
    what = sys.argv[1]
    if what == "controls":
        return controls(sys.argv[2])
    if what == "run":
        name, folder, out = sys.argv[2:5]
        t = tally(run_impl(folder))
        t["name"] = name
        t["run_sha256"] = hashlib.sha256((pathlib.Path(folder) / "RUN").read_bytes()).hexdigest()
        pathlib.Path(out).write_text(json.dumps(t, indent=1, sort_keys=True) + "\n")
        print(name, {k: "%d/%d" % (v["pass"], v["total"]) for k, v in t.items() if isinstance(v, dict)})
    elif what == "interop":
        r = interop(sys.argv[2], sys.argv[3])
        print(sys.argv[2], sys.argv[3], "%d/%d" % (r["total"] - len(r["failed"]), r["total"]), json.dumps(r["failed"])[:800])


if __name__ == "__main__":
    main()
