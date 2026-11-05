#!/usr/bin/env python3
"""The reference host and signer behind CLI_CONTRACT.md (validation/shortcuts/CLI_CONTRACT.md), levels 1 to 3.

Level 2 adds the reset command, the answers to the two decline questions, and unsolicited lines on standard input.
Level 3 adds the host's user stop (--stop), a log file of facts for both roles (--log) and the user's choice to change the transaction after a failure
(--change-transaction).
CLI_MUTANT breaks one behaviour, for the harness's controls.
"""
import argparse
import json
import os
import pathlib
import select
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "psbt"))
sys.path.insert(0, str(ROOT / "reference"))
import host as H                # noqa: E402
import psbt_codec as C          # noqa: E402
import signer as SG             # noqa: E402
import transport as T           # noqa: E402

MUTANT = os.environ.get("CLI_MUTANT", "")


class StopNow(BaseException):
    """The user stopped the host; the process reports how the attempt ended and exits."""


class Log:
    """JSON lines of facts (version 3): one object per line, appended and flushed at once."""

    def __init__(self, path):
        self.path = path

    def write(self, **fact):
        if self.path:
            with open(self.path, "a") as f:
                f.write(json.dumps(fact) + "\n")


def signer_main(a):
    line = sys.stdin.readline().strip()
    log = Log(a.log)

    def approve(desc):
        log.write(event="approval", party="signer", verified=bool(desc["fee_verified"]), unverified_inputs=list(desc["unverified_inputs"]),
                  pairs=[{"input": g["input"], "sighash_type": g["sighash_type"], "leaf_hash": g["leaf_hash"]} for g in desc["signatures"]])
        return not a.decline
    s = SG.Signer([bytes.fromhex(k) for k in a.secret_key], approve)
    try:
        out = s.sign(bytes.fromhex(line))
    except SG.SignerFail as e:
        if MUTANT == "signer_never_fails":
            print(line)
            return 0
        print(e, file=sys.stderr)
        return 3
    if MUTANT == "signer_flips_byte":
        p = C.parse(out)
        for m in p.inputs:
            for k in list(m):
                if k[:1] in (b"\x02", b"\x13", b"\x22"):
                    m[k] = m[k][:-2] + bytes([m[k][-2] ^ 1]) + m[k][-1:]
        out = p.serialize()
    print(out.hex())
    return 0


class Link:
    """Lines come from standard input through a private buffer, so that a line which arrives when no response is owed
    can be told from a response: the host looks for those after every exchange and at the start of a run."""

    def __init__(self, log=None, stop=None):
        self.buf = b""
        self.log, self.stop = log or Log(None), stop     # stop: (point, request number) or None
        self.sent, self.attempt, self.carried_rho = 0, None, False

    def _fill(self, block):
        if not block and not select.select([0], [], [], 0)[0]:
            return False
        data = os.read(0, 65536)
        self.buf += data
        return bool(data)

    def _line(self):
        while b"\n" not in self.buf:
            if not self._fill(True):
                line, self.buf = self.buf, b""
                return line.decode().strip()
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode().strip()

    def exchange(self, request):
        self.sent += 1
        self.carried_rho = any(k[:1] == b"\x23" for m in C.parse(request).inputs for k in m)     # this request is the one that sends rho
        self.log.write(event="request", n=self.sent)
        print("REQUEST " + request.hex(), flush=True)
        line = self._line()
        if self.stop and self.stop[0] == "outstanding" and self.stop[1] == self.sent:
            self.attempt.cancel()               # the user stops while the response is outstanding
            raise StopNow()
        if line == "ERROR" or not line:
            raise T.DeviceError("device reported failure")
        return bytes.fromhex(line)

    def take_unsolicited(self):
        if self.stop and self.stop[0] == "after_rho" and self.attempt is not None and self.carried_rho:
            self.attempt.abandon()              # the user stops after rho was sent, with nothing outstanding
            raise StopNow()
        while self._fill(False):
            pass
        out = []
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            if line.strip():
                out.append(line)
        return out


class UI(H.UI):
    def __init__(self, ack, declined=False, unrelated=False, confirm=False, log=None, change=False):
        self.ack, self.declined, self.unrelated, self.confirm, self.change = ack, declined, unrelated, confirm, change
        self.log = log or Log(None)

    def notify_request(self, info):
        self.log.write(event="notice", what="anti_exfil_request", anti_exfil=bool(info["anti_exfil"]))
        self.log.write(event="fee", party="host", verified=bool(info["fee_verified"]))

    def notice(self, text):
        pass

    def warn(self, device_id, failures):
        return self.ack

    def declined_on_device(self):
        return self.declined

    def decline_unrelated_to_display(self):
        return self.unrelated

    def confirm_reset(self, text):
        return self.confirm

    def confirm_change_after_failure(self, info):
        return self.change


def host_main(a):
    keys = [bytes.fromhex(k) for k in a.device_key]
    rhos = [bytes.fromhex(r.split(":")[2]) for r in a.rho]      # the reference draws in harness order
    device = "device"
    store = H.Store(a.store)
    src = iter(rhos)
    log = Log(a.log)
    stop = None
    if a.stop:
        point, _, n = a.stop.partition(":")
        stop = (point, int(n or 1))
    link = Link(log, stop)
    h = H.Host(H.Wallet(device, keys), store, UI(a.ack_warning, a.declined, a.decline_unrelated, log=log, change=a.change_transaction), link, max_retries=a.max_retries,
               rho_source=lambda: next(src))
    code, last = 0, ""
    try:
        if stop:
            att = link.attempt = h.start(bytes.fromhex(a.psbt))
            att.commit()
            if stop[0] == "before_rho":
                att.abandon()                   # the user stops before rho is sent, with nothing outstanding
                raise StopNow()
            res = att.reveal()
        else:
            res = h.sign(bytes.fromhex(a.psbt))
        last = "RESULT " + res.psbt.hex()
    except StopNow:
        code, last = (6, "ABANDONED") if link.attempt.state == "abandoned" else (3, "FAILED")
    except H.WarningNotAcknowledged:
        code, last = 5, "NOT_ACKNOWLEDGED"
    except H.HostRefusal as e:
        print(e, file=sys.stderr)
        code, last = 4, "REFUSED"
    except H.AttemptFailed as e:
        print(e, getattr(e, "reasons", ""), file=sys.stderr)
        code, last = 3, "FAILED"
        if MUTANT == "host_never_fails":
            code, last = 0, "RESULT " + a.psbt
    except H.AttemptAbandoned:
        code, last = 6, "ABANDONED"
    count = store.failures(device)
    if MUTANT == "host_no_count":
        count = 0
    print("COUNT %d" % count)
    print(last)
    return code


def reset_main(a):
    device = "device"
    store = H.Store(a.store)
    h = H.Host(H.Wallet(device, [bytes.fromhex(k) for k in a.device_key]), store, UI(False, confirm=a.confirm), Link())
    ok = h.reset_failures()
    print("COUNT %d" % store.failures(device))
    print("RESET" if ok else "NOT_RESET")
    return 0 if ok else 7


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("signer")
    s.add_argument("--secret-key", action="append", default=[])
    s.add_argument("--decline", action="store_true")
    s.add_argument("--log")
    h = sub.add_parser("host")
    h.add_argument("--device-key", action="append", default=[])
    h.add_argument("--store", required=True)
    h.add_argument("--max-retries", type=int, default=0)
    h.add_argument("--psbt", required=True)
    h.add_argument("--rho", action="append", default=[])
    h.add_argument("--ack-warning", action="store_true")
    h.add_argument("--declined", action="store_true")
    h.add_argument("--decline-unrelated", action="store_true")
    h.add_argument("--change-transaction", action="store_true")
    h.add_argument("--stop")
    h.add_argument("--log")
    r = sub.add_parser("reset")
    r.add_argument("--device-key", action="append", default=[])
    r.add_argument("--store", required=True)
    r.add_argument("--confirm", action="store_true")
    a = ap.parse_args()
    return {"signer": signer_main, "host": host_main, "reset": reset_main}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
