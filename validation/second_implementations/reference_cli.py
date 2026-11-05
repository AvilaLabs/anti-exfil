#!/usr/bin/env python3
"""The reference host and signer behind CLI_CONTRACT.md (levels 1 to 3), so the harness can be tested.

CLI_MUTANT breaks one behaviour, for the harness's controls.
"""
import argparse
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "psbt"))
sys.path.insert(0, str(ROOT / "reference"))
import host as H                # noqa: E402
import psbt_codec as C          # noqa: E402
import signer as SG             # noqa: E402
import transport as T           # noqa: E402

MUTANT = os.environ.get("CLI_MUTANT", "")


def signer_main(a):
    line = sys.stdin.readline().strip()
    s = SG.Signer([bytes.fromhex(k) for k in a.secret_key], lambda desc: not a.decline)
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
    def exchange(self, request):
        print("REQUEST " + request.hex(), flush=True)
        line = sys.stdin.readline().strip()
        if line == "ERROR" or not line:
            raise T.DeviceError("device reported failure")
        return bytes.fromhex(line)

    def take_unsolicited(self):
        return []


class UI(H.UI):
    def __init__(self, ack):
        self.ack = ack

    def notify_request(self, info):
        pass

    def notice(self, text):
        pass

    def warn(self, device_id, failures):
        return self.ack

    def declined_on_device(self):
        return False

    def decline_unrelated_to_display(self):
        return False

    def confirm_reset(self, text):
        return False


def host_main(a):
    keys = [bytes.fromhex(k) for k in a.device_key]
    rhos = [bytes.fromhex(r.split(":")[2]) for r in a.rho]      # the reference draws in harness order
    device = "device"
    store = H.Store(a.store)
    src = iter(rhos)
    h = H.Host(H.Wallet(device, keys), store, UI(a.ack_warning), Link(), max_retries=a.max_retries,
               rho_source=lambda: next(src))
    code, last = 0, ""
    try:
        res = h.sign(bytes.fromhex(a.psbt))
        last = "RESULT " + res.psbt.hex()
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


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("signer")
    s.add_argument("--secret-key", action="append", default=[])
    s.add_argument("--decline", action="store_true")
    h = sub.add_parser("host")
    h.add_argument("--device-key", action="append", default=[])
    h.add_argument("--store", required=True)
    h.add_argument("--max-retries", type=int, default=0)
    h.add_argument("--psbt", required=True)
    h.add_argument("--rho", action="append", default=[])
    h.add_argument("--ack-warning", action="store_true")
    a = ap.parse_args()
    return signer_main(a) if a.cmd == "signer" else host_main(a)


if __name__ == "__main__":
    sys.exit(main())
