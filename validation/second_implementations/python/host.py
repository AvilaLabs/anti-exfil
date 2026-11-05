"""Host: runs one anti-exfil signing attempt against a device on stdin/stdout."""
import json
import os
import sys

import proto
from secp import tagged_hash, parse33
from psbt import (Psbt, PsbtError, Keys, Reader, analyze_pair, check_request_level,
                  find_leaves, parse_script, sig_present, map_set, update_modifiable,
                  der_encode, der_parse_strict, AE_TYPES, SIG_TYPES,
                  IN_AE_HOST_COMMITMENT, IN_AE_NONCE_COMMITMENT, IN_AE_HOST_RANDOMNESS,
                  IN_BIP32_DERIVATION, IN_TAP_BIP32_DERIVATION, IN_TAP_INTERNAL_KEY,
                  IN_FINAL_SCRIPTSIG, IN_FINAL_SCRIPTWITNESS, IN_REDEEM_SCRIPT,
                  IN_WITNESS_SCRIPT, IN_TAP_LEAF_SCRIPT)


def note(msg):
    sys.stderr.write("host: " + msg + "\n")
    sys.stderr.flush()


class HostFail(Exception):
    def __init__(self, msg, fatal=False):
        Exception.__init__(self, msg)
        self.fatal = fatal


# ---------------------------------------------------------------- store
class Store:
    """JSON file: {"devices": {id: {"count", "acked", "open": null | {"counted"}}}}."""

    def __init__(self, path):
        self.path = path
        self.data = {"devices": {}}
        self.unreadable = False
        if os.path.lexists(path):
            try:
                with open(path, "r") as f:
                    d = json.load(f)
                if not isinstance(d, dict) or not isinstance(d.get("devices"), dict):
                    raise ValueError("bad store")
                self.data = d
            except Exception:
                self.unreadable = True

    def device(self, dev_id):
        """The record for a device. If the records cannot be read the count is one."""
        if self.unreadable:
            return {"count": 1, "acked": 0, "open": None}
        r = self.data["devices"].get(dev_id)
        if r is None:
            return {"count": 0, "acked": 0, "open": None}
        try:
            c, a, o = r["count"], r["acked"], r["open"]
            if (type(c) is not int or type(a) is not int or c < 0 or a < 0
                    or not (o is None or (isinstance(o, dict) and type(o.get("counted")) is bool))):
                raise ValueError
            return {"count": c, "acked": a, "open": o}
        except Exception:
            return {"count": 1, "acked": 0, "open": None}

    def save(self, dev_id, rec):
        """Atomic durable write. Returns True on success."""
        data = self.data if not self.unreadable else {"devices": {}}
        data["devices"][dev_id] = {"count": rec["count"], "acked": rec["acked"], "open": rec["open"]}
        tmp = self.path + ".tmp"
        try:
            d = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(d, exist_ok=True)
            with open(tmp, "w") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            try:
                fd = os.open(d, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError:
                pass
        except Exception as e:
            note("cannot write store: %s" % e)
            return False
        self.data = data
        self.unreadable = False
        return True


# ---------------------------------------------------------------- pair selection
def _tap_record(v):
    r = Reader(v)
    n = r.cs()
    hashes = [r.read(32) for _ in range(n)]
    r.read(4)
    return hashes


def select_pairs(ps, keys):
    """Returns the list of (input, keyid, kind) pairs to request. Raises PsbtError
    for a refusal."""
    for i, mlist in enumerate(ps.ins):
        for k, _ in mlist:
            if k[0] in AE_TYPES:
                raise PsbtError("PSBT already holds anti-exfil fields")
    found = {}
    for i, mlist in enumerate(ps.ins):
        m = ps.imap(i)
        cand = []
        for k, v in mlist:
            if k[0] == IN_BIP32_DERIVATION and len(k) == 34 and bytes(k[1:]) in keys.pubs:
                cand.append(("ecdsa", bytes(k[1:])))
        internal = m.get(bytes([IN_TAP_INTERNAL_KEY]))
        if internal is not None and len(internal) == 32 and internal in keys.xs:
            cand.append(("tr_key", bytes(internal)))
        else:
            for k, v in mlist:
                if k[0] == IN_TAP_BIP32_DERIVATION and len(k) == 33 and bytes(k[1:]) in keys.xs:
                    x = bytes(k[1:])
                    hashes = _tap_record(v)
                    if not hashes:
                        raise PsbtError("derivation record names a device key the output does not contain")
                    for lh in hashes:
                        if find_leaves(mlist, lh):
                            cand.append(("tr_script", x + lh))
                        else:
                            note("input %d lists leaf %s with no script; no pair formed" % (i, lh.hex()))
        # a device key found only in a script
        for t in (IN_REDEEM_SCRIPT, IN_WITNESS_SCRIPT):
            s = m.get(bytes([t]))
            if s is None:
                continue
            try:
                for op, data, direct in parse_script(s):
                    if direct and op == 0x21 and data in keys.pubs and ("ecdsa", data) not in cand:
                        note("input %d: device key in script without derivation record; no pair formed" % i)
            except PsbtError:
                pass
        for kind, keyid in cand:
            found[(i, keyid)] = kind
    pairs = []
    for (i, keyid), kind in sorted(found.items()):
        if sig_present(ps.imap(i), kind, keyid):
            note("input %d already holds a signature for key %s; skipped (unknown how it was made)"
                 % (i, keyid.hex()))
            continue
        pairs.append((i, keyid, kind))
    if not pairs:
        raise PsbtError("no pairs remain")
    return pairs


# ---------------------------------------------------------------- the run
class Run:
    def __init__(self, ps, infos, rhos, store, dev_id, rec, max_retries):
        self.ps = ps
        self.infos = infos
        self.rhos = rhos          # {(i, keyid): rho}
        self.store = store
        self.dev_id = dev_id
        self.rec = rec
        self.max_retries = max_retries
        self.counted = False
        self.r0 = {}              # raw first-seen nonce commitment per pair
        self.hc = {}
        for p in infos:
            rho = rhos[(p.i, p.keyid)]
            self.hc[(p.i, p.keyid)] = (proto.schnorr_hc(rho) if p.scheme == "bip340"
                                       else proto.ecdsa_hc(rho))
        self.requested = set((p.i, p.keyid) for p in infos)
        self.sigkeys = set((p.i, p.sigkey) for p in infos)
        self.final_values = {}

    # -- counting
    def fail_event(self):
        if not self.counted:
            self.counted = True
            self.rec["count"] += 1
            if self.rec["open"] is not None:
                self.rec["open"]["counted"] = True
            self.store.save(self.dev_id, self.rec)

    def erase(self):
        """Best effort: drop the host's copies of rho and the nonce commitments."""
        self.rhos.clear()
        self.hc.clear()
        self.r0.clear()

    def close(self):
        self.rec["open"] = None
        self.store.save(self.dev_id, self.rec)

    # -- requests
    def build_request(self, ftype, values):
        req = self.ps.copy()
        for p in self.infos:
            map_set(req.ins[p.i], bytes([ftype]) + p.keyid, values[(p.i, p.keyid)])
        return req

    def talk(self, req):
        sys.stdout.write("REQUEST %s\n" % req.serialize().hex())
        sys.stdout.flush()
        line = sys.stdin.readline()
        if line == "":
            return "eof", None
        line = line.strip()
        if line == "ERROR":
            return "error", None
        try:
            return "ok", Psbt.parse(bytes.fromhex(line))
        except Exception:
            return "bad", None

    # -- response checks
    def track_r0(self, resp):
        if len(resp.ins) != len(self.ps.ins):
            return
        for i, mlist in enumerate(resp.ins):
            for k, v in mlist:
                if k[0] == IN_AE_NONCE_COMMITMENT and (i, bytes(k[1:])) in self.requested:
                    pair = (i, bytes(k[1:]))
                    if pair in self.r0 and self.r0[pair] != v:
                        raise HostFail("nonce commitment changed", fatal=True)
                    self.r0.setdefault(pair, bytes(v))

    def check_response(self, resp, passno):
        if resp.tx.key() != self.ps.tx.key():
            raise HostFail("core transaction differs")
        if len(resp.ins) != len(self.ps.ins):
            raise HostFail("input count differs")
        for i in range(len(self.ps.ins)):
            qm = self.ps.imap(i)
            rm = resp.imap(i)
            for k, v in resp.ins[i]:
                t = k[0]
                if t not in AE_TYPES:
                    continue
                pair = (i, bytes(k[1:]))
                if pair not in self.requested:
                    raise HostFail("anti-exfil field for a pair that was not requested")
                if passno == 2:
                    raise HostFail("second-pass response holds an anti-exfil field")
                if t == IN_AE_HOST_RANDOMNESS:
                    raise HostFail("first-pass response holds host randomness")
                if t == IN_AE_HOST_COMMITMENT and v != self.hc[pair]:
                    raise HostFail("host commitment differs")
            req_sigs = dict((k, v) for k, v in qm.items() if k[0] in SIG_TYPES)
            resp_sigs = dict((k, v) for k, v in rm.items() if k[0] in SIG_TYPES)
            for k, v in resp_sigs.items():
                if k not in req_sigs:
                    if not (passno == 2 and (i, k) in self.sigkeys):
                        raise HostFail("signature field added")
                elif req_sigs[k] != v:
                    raise HostFail("signature field changed")
            final = bytes([IN_FINAL_SCRIPTSIG]) in qm or bytes([IN_FINAL_SCRIPTWITNESS]) in qm
            for k in req_sigs:
                if k not in resp_sigs and not final:
                    raise HostFail("signature field removed")
        if passno == 1:
            for p in self.infos:
                pair = (p.i, p.keyid)
                nc = resp.imap(p.i).get(bytes([IN_AE_NONCE_COMMITMENT]) + p.keyid)
                if nc is None:
                    raise HostFail("nonce commitment missing")
                if parse33(nc) is None:
                    raise HostFail("nonce commitment fails parse33")
                if self.r0.get(pair) != nc:
                    raise HostFail("nonce commitment changed", fatal=True)
        else:
            vals = {}
            for p in self.infos:
                pair = (p.i, p.keyid)
                v = resp.imap(p.i).get(p.sigkey)
                if v is None:
                    raise HostFail("signature missing")
                rho = self.rhos[pair]
                R0 = self.r0[pair]
                if p.scheme == "ecdsa":
                    try:
                        r, s, htb = der_parse_strict(v)
                    except PsbtError as e:
                        raise HostFail("signature not strict DER: %s" % e)
                    if htb != p.ht:
                        raise HostFail("unexpected sighash type in signature")
                    if not proto.ecdsa_host_check(p.pk, p.m, rho, R0, r, s):
                        raise HostFail("step 5 check failed")
                    vals[pair] = der_encode(r, s) + bytes([p.ht])
                else:
                    want = 64 if p.ht == 0 else 65
                    if len(v) != want:
                        raise HostFail("signature has the wrong length for the sighash type")
                    if p.ht != 0 and v[64] != p.ht:
                        raise HostFail("unexpected sighash type in signature")
                    if not proto.schnorr_host_check(p.pk, p.m, rho, R0, v[:64]):
                        raise HostFail("step 5 check failed")
                    vals[pair] = bytes(v)
            self.final_values = vals

    def run_pass(self, passno, req):
        tries = 0
        while True:
            status, resp = self.talk(req)
            fatal = False
            err = None
            if status == "eof":
                err, fatal = "no response", True
            elif status == "error":
                err = "device error"
            elif status == "bad":
                err = "malformed response"
            else:
                try:
                    self.track_r0(resp)
                    self.check_response(resp, passno)
                    return True
                except HostFail as e:
                    err, fatal = str(e), e.fatal
                except Exception as e:      # a response that breaks a check is a malformed response
                    err = "malformed response (%s)" % e
            note("failure event: %s" % err)
            self.fail_event()
            if fatal or tries >= self.max_retries:
                return False
            tries += 1

    def execute(self):
        """Returns the result PSBT bytes or None when the attempt failed."""
        note("requesting anti-exfil signing for %d pair(s)" % len(self.infos))
        req1 = self.build_request(IN_AE_HOST_COMMITMENT, self.hc)
        if not self.run_pass(1, req1):
            return None
        req2 = self.build_request(IN_AE_HOST_RANDOMNESS, self.rhos)
        if not self.run_pass(2, req2):
            return None
        res = self.ps.copy()
        for p in self.infos:
            map_set(res.ins[p.i], p.sigkey, self.final_values[(p.i, p.keyid)])
            update_modifiable(res, p.ht)
        return res.serialize()


def parse_rho_args(items):
    out = {}
    for it in items:
        parts = it.split(":")
        if len(parts) != 3:
            raise ValueError("bad --rho")
        out[(int(parts[0]), bytes.fromhex(parts[1]))] = bytes.fromhex(parts[2])
    return out


def main(args):
    """args: argparse namespace. Returns the exit code."""
    def emit(s):
        sys.stdout.write(s + "\n")
        sys.stdout.flush()

    devkeys = [bytes.fromhex(k) for k in args.device_key]
    keys = Keys(devkeys)
    dev_id = ",".join(sorted(set(k.hex() for k in devkeys)))
    store = Store(args.store)
    rec = store.device(dev_id)
    # an attempt still recorded as open counts as failed
    if rec["open"] is not None:
        if not rec["open"]["counted"]:
            rec["count"] += 1
        rec["open"] = None
        store.save(dev_id, rec)

    def finish(label, code):
        emit("COUNT %d" % rec["count"])
        emit(label)
        return code

    # refusals before any attempt
    try:
        ps = Psbt.parse(bytes.fromhex(args.psbt))
        pairs = select_pairs(ps, keys)
        infos = [analyze_pair(ps, i, keyid, keys) for (i, keyid, kind) in pairs]
        fee, verified = check_request_level(ps, infos)
    except Exception as e:
        note("refused: %s" % e)
        return finish("REFUSED", 4)
    if fee is None:
        note("fee unknown: not every input amount is known")
    elif verified:
        note("fee %d sat (verified)" % fee)
    else:
        note("fee %d sat is UNVERIFIED: not every input amount is verified" % fee)
    try:
        given = parse_rho_args(args.rho)
    except Exception as e:
        emit("MISSING_RHO")
        return 9
    rhos = {}
    for p in infos:
        r = given.get((p.i, p.keyid))
        if r is None or len(r) != 32:
            emit("MISSING_RHO")
            return 9
        rhos[(p.i, p.keyid)] = r
    if len(set(rhos.values())) != len(rhos):
        note("refused: one rho value given for more than one pair")
        return finish("REFUSED", 4)
    # warning owed?
    owed = rec["count"] > rec["acked"]
    if owed:
        note("WARNING: a previous attempt with this device failed (failure count %d). "
             "Repeated failures can mean a malicious device." % rec["count"])
        if not args.ack_warning:
            return finish("NOT_ACKNOWLEDGED", 5)
    # record the attempt as open, using up any acknowledgement in the same write
    new = {"count": rec["count"], "acked": rec["count"] if owed else rec["acked"],
           "open": {"counted": False}}
    if not store.save(dev_id, new):
        return finish("REFUSED", 4)
    rec = new
    run = Run(ps, infos, rhos, store, dev_id, rec, args.max_retries)
    try:
        result = run.execute()
    except Exception as e:
        note("internal error: %s" % e)
        run.fail_event()
        result = None
    run.close()
    run.erase()
    if result is None:
        return finish("FAILED", 3)
    return finish("RESULT %s" % result.hex(), 0)


def reset(args):
    devkeys = [bytes.fromhex(k) for k in args.device_key]
    dev_id = ",".join(sorted(set(k.hex() for k in devkeys)))
    store = Store(args.store)
    old = store.device(dev_id)
    note("resetting the failure count (%d) and any pending warning for device %s" % (old["count"], dev_id))
    ok = store.save(dev_id, {"count": 0, "acked": 0, "open": None})
    sys.stdout.write("COUNT 0\n" if ok else "RESET_FAILED\n")
    return 0 if ok else 1
