#!/usr/bin/env python3
"""Anti-exfil PSBT host and signer. The command line is in validation/second_implementations/CLI_CONTRACT.md."""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main(argv):
    ap = argparse.ArgumentParser(prog="main.py")
    sub = ap.add_subparsers(dest="role", required=True)
    s = sub.add_parser("signer")
    s.add_argument("--secret-key", action="append", required=True)
    s.add_argument("--decline", action="store_true")
    h = sub.add_parser("host")
    h.add_argument("--device-key", action="append", required=True)
    h.add_argument("--store", required=True)
    h.add_argument("--max-retries", type=int, required=True)
    h.add_argument("--psbt", required=True)
    h.add_argument("--rho", action="append", default=[])
    h.add_argument("--ack-warning", action="store_true")
    r = sub.add_parser("reset-count")   # explicit user action; not part of the contract
    r.add_argument("--device-key", action="append", required=True)
    r.add_argument("--store", required=True)
    args = ap.parse_args(argv)
    if args.role == "signer":
        import signer
        try:
            line = sys.stdin.readline()
            out = signer.run(args.secret_key, args.decline, line)
        except Exception as e:
            sys.stderr.write("signer: failed: %s\n" % e)
            return 3
        sys.stdout.write(out.hex() + "\n")
        sys.stdout.flush()
        return 0
    import host
    if args.role == "reset-count":
        return host.reset(args)
    return host.main(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
