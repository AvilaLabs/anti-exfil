#!/usr/bin/env python3
"""Harness for the lazy-implementer cases: the base harness (check_independent.py) plus further classes of vectors/bip-anti-exfil-psbt.json.

check_independent.py is not edited; this file imports its helpers (HostProc is replaced by HostProcV2, which
can write lines the host did not ask for, kill the process at a request and pass the decline answers).
Differences from check_independent.run_impl, and only these:
  - the global PSBT_GLOBAL_TX_MODIFIABLE field is compared as well (relevant2), and so are the key types 0x21 to 0x23 in the global and
    output maps, which are ordinary unknown fields there and must be kept;
  - the new class `lifecycle_scenarios` is run (CLI_CONTRACT.md version 2);
  - units can be skipped by kind (signer or host) when a case's code for that kind equals the control's, and run in a
    cheap-first order, and a run can stop at its first failed unit.
"""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[0] / "second_implementations"))
import check_independent as H            # noqa: E402
C = H.C

CLASSES = ["signer_refusals", "request_refusals", "host_refusals", "host_accepts", "lifecycle", "lifecycle_scenarios",
           "signer_exchanges", "host_exchanges", "user_facts"]
BASE_CLASSES = ["signer_exchanges", "signer_refusals", "host_exchanges", "host_refusals", "host_accepts", "request_refusals", "lifecycle"]
KIND = {"signer_refusals": "signer", "signer_exchanges": "signer", "user_facts": "both"}   # every other class runs the host
SIGNER_FILES = ["psbt/signer.py", "psbt/spend.py", "psbt/psbt_codec.py", "reference/anti_exfil.py",
                "psbt/transport.py", "a/b/reference_cli.py"]
HOST_FILES = ["psbt/host.py", "psbt/spend.py", "psbt/psbt_codec.py", "reference/anti_exfil.py",
              "psbt/transport.py", "a/b/reference_cli.py"]


def digest(folder, kind):
    h = hashlib.sha256()
    for f in (SIGNER_FILES if kind == "signer" else HOST_FILES):
        h.update((pathlib.Path(folder) / f).read_bytes())
    return h.hexdigest()


def relevant2(data):
    """relevant() of check_independent plus the global TX_MODIFIABLE field."""
    p = C.parse(bytes.fromhex(data) if isinstance(data, str) else data)
    ae = lambda m: sorted((k.hex(), v.hex()) for k, v in m.items() if k[:1] in (b"\x21", b"\x22", b"\x23"))
    # the key types 0x21 to 0x23 are ordinary unknown fields in a global or output map: they must be kept
    return H.relevant(data) + (p.glob.get(b"\x06"), ae(p.glob), [ae(m) for m in p.outputs])


def same2(a, b):
    try:
        return relevant2(a) == relevant2(b)
    except Exception:
        return False


class HostProcV2:
    """Like check_independent.HostProc, plus: decline answers, lines written before the run and straight after a response,
    and a kill at a named request. `exchanges` are the scripted exchanges of a lifecycle scenario run."""

    def __init__(self, prog, cwd, keys, store, retries, psbt, rhos, ack=False, declined=False, unrelated=False, env=None,
                 stop=None, log=None, change=False):
        args = list(prog) + ["host", "--store", str(store), "--max-retries", str(retries), "--psbt", psbt]
        for k in keys:
            args += ["--device-key", k]
        for i, kid, r in rhos:
            args += ["--rho", "%d:%s:%s" % (i, kid, r)]
        for flag, on in (("--ack-warning", ack), ("--declined", declined), ("--decline-unrelated", unrelated), ("--change-transaction", change)):
            if on:
                args.append(flag)
        if stop:
            args += ["--stop", stop]
        if log:
            args += ["--log", str(log)]
        self.args, self.cwd, self.env = args, cwd, env

    def run(self, exchanges, pre=()):
        p = subprocess.Popen(self.args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             cwd=self.cwd, env=self.env, bufsize=-1)
        timer = threading.Timer(H.TIMEOUT, p.kill)
        timer.start()
        out = {"code": None, "last": None, "count": None, "requests": [], "killed": False, "mismatch": []}
        try:
            if pre:
                p.stdin.write(("".join(u + "\n" for u in pre)).encode())
                p.stdin.flush()
            for raw in iter(p.stdout.readline, b""):
                line = raw.decode().strip()
                if line.startswith("REQUEST "):
                    n = len(out["requests"])
                    out["requests"].append(line[8:])
                    if n >= len(exchanges):
                        out["last"] = "HARNESS_NO_MORE_RESPONSES"
                        p.kill()
                        break
                    ex = exchanges[n]
                    if not same2(line[8:], ex["request"]):
                        out["mismatch"].append("request %d differs" % n)
                    if ex.get("kill"):
                        out["killed"] = True
                        p.kill()
                        break
                    resp = ex["response"] if ex["response"] is not None else "ERROR"
                    p.stdin.write((resp + "\n" + "".join(u + "\n" for u in ex.get("unsolicited_after_response", []))).encode())
                    p.stdin.flush()
                elif line.startswith("COUNT "):
                    out["count"] = int(line[6:])
                elif line:
                    out["last"] = line
            out["code"] = p.wait(timeout=H.TIMEOUT)
        except (BrokenPipeError, subprocess.TimeoutExpired, ValueError) as e:
            p.kill()
            out["last"] = out["last"] or "HARNESS_ERROR %s" % type(e).__name__
        finally:
            timer.cancel()
            try:
                p.stdin.close()
            except OSError:
                pass
            p.wait()
        return out


def _events(path):
    try:
        return [json.loads(line) for line in pathlib.Path(path).read_text().splitlines() if line.strip()]
    except (OSError, ValueError):
        return []


def _fee_facts(events, party, may_verify):
    """The facts of the log that the text pins: a party that is not allowed to present the fee as verified never does, and says it is unverified."""
    fees = [e.get("verified") for e in events if e.get("event") in ("fee", "approval") and e.get("party") == party]
    why = []
    if not may_verify:
        if True in fees:
            why.append("%s presented the fee as verified" % party)
        if False not in fees:
            why.append("%s did not tell the user the fee is unverified" % party)
    return why


def _ae_fields(data):
    try:
        p = C.parse(bytes.fromhex(data))
    except Exception:
        return True                 # not a PSBT: not an acceptable answer
    return any(k[:1] in (b"\x21", b"\x22", b"\x23") for m in p.inputs for k in m)


def units(v):
    """(class, vector id, function(prog, cwd, tmp, env) -> reasons or dict of reasons) in run order."""
    store = lambda tmp, name: pathlib.Path(tmp) / (name + ".store")

    def sref(c):
        def f(prog, cwd, tmp, env):
            pre = c.get("reason_code") == "not_approved"
            code, out = H.signer_call(prog, cwd, c["signer_holds_seeds_of"], c["request"], decline=pre, env=env)
            why = []
            if c.get("conditional") and code == 0 and out and not _ae_fields(out):
                return why              # a signer with an ordinary signing path may return the PSBT, with no anti-exfil field
            if code == 0 or out:
                why.append("signed or answered (exit %s)" % code)
            elif code != 3:
                why.append("exit %s" % code)
            return why
        return f

    def rref(c):
        def f(prog, cwd, tmp, env):
            h = H.HostProc(prog, cwd, c["device_keys"], store(tmp, c["id"]), 0, c["host_psbt"], [], env=env).run(lambda i, r: "ERROR")
            why = []
            if h["requests"]:
                why.append("sent a request")
            if h["code"] != 4 or h["last"] != "REFUSED":
                why.append("exit %s last %s" % (h["code"], (h["last"] or "")[:40]))
            return why
        return f

    def href(c, accept):
        def f(prog, cwd, tmp, env):
            rhos = H.rhos_from_hashes(c["id"], c["exchanges"][0]["request"])
            resp = [e["response"] for e in c["exchanges"]]

            def ans(i, req):
                if i >= len(resp):
                    return None
                return resp[i] if resp[i] is not None else "ERROR"
            h = H.HostProc(prog, cwd, c["device_keys"], store(tmp, c["id"]), c.get("max_retries", 0), c["host_psbt"], rhos, env=env).run(ans)
            why = []
            if accept:
                if h["code"] != 0:
                    why.append("exit %s last %s" % (h["code"], (h["last"] or "")[:40]))
                elif not same2(h["last"][7:], c["host_result"]):
                    why.append("result differs")
                if h["count"] != 0:
                    why.append("count %s" % h["count"])
            else:
                if h["code"] != 3 or h["last"] != "FAILED":
                    why.append("exit %s last %s" % (h["code"], (h["last"] or "")[:40]))
                if h["count"] != 1:
                    why.append("count %s" % h["count"])
            return why
        return f

    def sex(ex):
        def f(prog, cwd, tmp, env):
            keys = H.secrets_of(ex)
            why = []
            for q, r in (("first_request", "first_response"), ("second_request", "second_response")):
                code, out = H.signer_call(prog, cwd, keys, ex[q], env=env)
                if code != 0:
                    why.append("%s: exit %s" % (q, code))
                elif not same2(out, ex[r]):
                    why.append("%s: response differs" % q)
            return why
        return f

    def hex_ex(ex):
        def f(prog, cwd, tmp, env):
            rhos = H.rhos_from_hashes(ex["id"], ex["first_request"])
            seq = [ex["first_response"], ex["second_response"]]
            reqs = [ex["first_request"], ex["second_request"]]
            why = []

            def ans(i, req):
                if i >= 2:
                    return None
                if not same2(req, reqs[i]):
                    why.append("request %d differs" % i)
                return seq[i]
            h = H.HostProc(prog, cwd, ex["device_keys"], store(tmp, ex["id"]), 0, ex["host_psbt"], rhos, env=env).run(ans)
            if h["code"] != 0 or not (h["last"] or "").startswith("RESULT "):
                why.append("exit %s last %s" % (h["code"], (h["last"] or "")[:40]))
            elif not same2(h["last"][7:], ex["host_result"]):
                why.append("result differs")
            if h["count"] != 0:
                why.append("count %s" % h["count"])
            return why
        return f

    def life(prog, cwd, tmp, env):
        c = v["host_refusals"][0]
        rhos = H.rhos_from_hashes(c["id"], c["exchanges"][0]["request"])
        resp = [e["response"] for e in c["exchanges"]]
        ans = lambda i, req: resp[i] if i < len(resp) else None
        st = store(tmp, "lifecycle")

        def fresh(run):
            return [(i, kid, hashlib.sha256(("lifecycle/%d/" % run + r).encode()).hexdigest()) for i, kid, r in rhos]

        def one(run, **kw):
            return H.HostProc(prog, cwd, c["device_keys"], st, 0, c["host_psbt"], rhos if run == 1 else fresh(run), env=env, **kw).run(ans)
        h1, h2, h3, h4 = one(1), one(2), one(3, ack=True), one(4)
        return {"L1-first-failure-counted": [] if (h1["code"], h1["count"]) == (3, 1) else ["%s %s" % (h1["code"], h1["count"])],
                "L2-warning-blocks-next-attempt": [] if (h2["code"], h2["count"], h2["requests"]) == (5, 1, []) else ["%s %s %d requests" % (h2["code"], h2["count"], len(h2["requests"]))],
                "L3-acknowledged-attempt-runs-and-counts": [] if (h3["code"], h3["count"]) == (3, 2) and h3["requests"] else ["%s %s" % (h3["code"], h3["count"])],
                "L4-acknowledgement-used-up": [] if (h4["code"], h4["count"], h4["requests"]) == (5, 2, []) else ["%s %s" % (h4["code"], h4["count"])]}

    def scen(sc):
        def f(prog, cwd, tmp, env):
            st = store(tmp, sc["id"])
            keys = sc["device_keys"]
            for n, step in enumerate(sc["steps"]):
                tag = "step %d" % n
                if step["do"] == "junk_store":
                    st.write_bytes(bytes.fromhex(step["bytes"]))
                    continue
                exp = step["expect"]
                if step["do"] == "reset":
                    args = list(prog) + ["reset", "--store", str(st)]
                    for k in keys:
                        args += ["--device-key", k]
                    if step["confirm"]:
                        args.append("--confirm")
                    try:
                        p = subprocess.run(args, capture_output=True, text=True, timeout=H.TIMEOUT, cwd=cwd, env=env)
                    except subprocess.TimeoutExpired:
                        return ["%s: timeout" % tag]
                    lines = p.stdout.split()
                    got = (p.returncode, lines[-1] if lines else None, int(lines[1]) if len(lines) > 2 and lines[0] == "COUNT" else None)
                    if got != (exp["exit"], exp["last"], exp["count"]):
                        return ["%s: reset gave %s" % (tag, got)]
                    continue
                rhos = [(r["input"], r["key_identifier"], r["rho"]) for r in step["rho"]]
                h = HostProcV2(prog, cwd, keys, st, step["max_retries"], step["host_psbt"], rhos, ack=step["ack_warning"],
                               declined=step["declined"], unrelated=step["decline_unrelated"], env=env, stop=step.get("stop"),
                               change=step.get("user_changes_transaction", False)).run(step["exchanges"], step["unsolicited_before"])
                why = list(h["mismatch"])
                if len(h["requests"]) != exp["requests"]:
                    why.append("%d requests, expected %d" % (len(h["requests"]), exp["requests"]))
                if exp.get("killed"):
                    if not h["killed"]:
                        why.append("not killed: exit %s last %s" % (h["code"], (h["last"] or "")[:40]))
                elif (h["code"], "RESULT" if (h["last"] or "").startswith("RESULT ") else h["last"], h["count"]) != (exp["exit"], exp["last"], exp["count"]):
                    why.append("exit %s last %s count %s" % (h["code"], (h["last"] or "")[:40], h["count"]))
                if why:
                    return ["%s: %s" % (tag, w) for w in why]
            return []
        return f

    exby = {e["id"]: e for e in v["exchanges"]}

    def fact(uf):
        ex = exby[uf["exchange"]]

        def f(prog, cwd, tmp, env):
            may = uf["fee_may_be_presented_as_verified"]
            hlog, slog = pathlib.Path(tmp) / (uf["id"] + ".host.log"), pathlib.Path(tmp) / (uf["id"] + ".signer.log")
            rhos = H.rhos_from_hashes(ex["id"], ex["first_request"])
            pairs = [{"request": ex["first_request"], "response": ex["first_response"]}, {"request": ex["second_request"], "response": ex["second_response"]}]
            HostProcV2(prog, cwd, ex["device_keys"], store(tmp, uf["id"]), 0, ex["host_psbt"], rhos, env=env, log=hlog).run(pairs)
            ev = _events(hlog)
            why = []
            names = [e.get("event") for e in ev]
            notice = next((i for i, e in enumerate(ev) if e.get("event") == "notice" and e.get("anti_exfil") is True), None)
            if notice is None:
                why.append("host did not tell the user it is requesting anti-exfil signing")
            elif "request" in names and names.index("request") < notice:
                why.append("host sent a request before telling the user")
            why += _fee_facts(ev, "host", may)
            args = list(prog) + ["signer", "--log", str(slog)]
            for k in H.secrets_of(ex):
                args += ["--secret-key", k]
            try:
                subprocess.run(args, input=ex["second_request"] + "\n", capture_output=True, text=True, timeout=H.TIMEOUT, cwd=cwd, env=env)
            except subprocess.TimeoutExpired:
                why.append("signer timeout")
            sev = _events(slog)
            why += _fee_facts(sev, "signer", may)
            if "approval_pairs" in uf:
                appr = [e for e in sev if e.get("event") == "approval"]
                if len(appr) != uf["approvals_per_second_pass"]:
                    why.append("signer logged %d approvals, expected %d" % (len(appr), uf["approvals_per_second_pass"]))
                elif appr:
                    key = lambda g: (g.get("input"), g.get("sighash_type"), g.get("leaf_hash") or "")
                    if sorted(map(key, appr[0].get("pairs", []))) != sorted(map(key, uf["approval_pairs"])):
                        why.append("approval shows pairs %s, expected %s" % (appr[0].get("pairs"), uf["approval_pairs"]))
            return why
        return f

    out = []
    for c in v["signer_refusals"]:
        out.append(("signer_refusals", c["id"], sref(c)))
    for c in v["request_refusals"]:
        out.append(("request_refusals", c["id"], rref(c)))
    for c in v["host_refusals"]:
        out.append(("host_refusals", c["id"], href(c, False)))
    for c in v["host_accepts"]:
        out.append(("host_accepts", c["id"], href(c, True)))
    out.append(("lifecycle", "lifecycle", life))
    for sc in v.get("lifecycle_scenarios", []):
        out.append(("lifecycle_scenarios", sc["id"], scen(sc)))
    for ex in v["exchanges"]:
        out.append(("signer_exchanges", ex["id"], sex(ex)))
    for ex in v["exchanges"]:
        out.append(("host_exchanges", ex["id"], hex_ex(ex)))
    for uf in v.get("user_facts", []):
        out.append(("user_facts", uf["id"], fact(uf)))
    return out


def run_all(folder, env=None, stop_early=True, skip_kinds=(), classes=None):
    """Runs the units on the folder. Returns (results by class, first failure or None). Units of a skipped kind are not run."""
    prog, cwd = H.cmd_of(folder)
    v = json.loads(H.VECTORS.read_text())
    res = {c: {} for c in CLASSES}
    first = None
    with tempfile.TemporaryDirectory(dir=str(H.ROOT / ".work" / "shortcuts")) as tmp:
        for cls, vid, fn in units(v):
            kind = KIND.get(cls, "host")
            if (all(k in skip_kinds for k in ("signer", "host")) if kind == "both" else kind in skip_kinds) or (classes and cls not in classes):
                continue
            r = fn(prog, cwd, tmp, env)
            if cls == "lifecycle":
                res["lifecycle"].update(r)
                bad = [(k, w) for k, w in r.items() if w]
                if bad and first is None:
                    first = {"class": cls, "vector": bad[0][0], "why": bad[0][1]}
            else:
                res[cls][vid] = r
                if r and first is None:
                    first = {"class": cls, "vector": vid, "why": r}
            if first and stop_early:
                break
    return res, first


def tally(res):
    return H.tally({c: d for c, d in res.items()})
