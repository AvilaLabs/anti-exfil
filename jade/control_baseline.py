#!/usr/bin/env python3
"""Control: a baseline Jade (before the port) signs a request for anti-exfil signing in the ordinary way.

Run against a libjade built from the commit before the port, with LD_LIBRARY_PATH set to it. Uses the cases
that the port's tests hold (tests/rpc/data/sign_psbt_anti_exfil in the Jade tree). The first request holds
the host commitments; the second holds the host randomness. A baseline signer ignores the fields, signs, and
returns the fields it was given, so the second response carries the randomness and an ordinary signature.
"""
import json
import pathlib
import sys

import jade_keys as J

DATA = pathlib.Path(sys.argv[1])


def fields(psbt, types=(0x21, 0x22, 0x23)):
    return {k: v for m in J.C.parse(psbt).inputs for k, v in m.items() if k[0] in types}


def load(name):
    case = json.loads((DATA / name).read_text())
    return {k: __import__("base64").b64decode(v[4:]) for k, v in case["input"].items() if k != "network"}


jade = J.open_jade()
for name in ("exchange_p2wpkh-v0.json", "exchange_p2tr-key-v0.json", "exchange_p2wsh-2of3-v2.json"):
    req = load(name)
    first = jade.sign_psbt(J.NETWORK, req["first_request"])
    second = jade.sign_psbt(J.NETWORK, req["second_request"])
    print(name,
          "first pass: nonce commitments added=%s, signatures=%d;" % (
              any(k[0] == 0x22 for k in fields(first)), len(fields(first, (0x02, 0x13)))),
          "second pass: signatures=%d, host randomness returned=%s" % (
              len(fields(second, (0x02, 0x13))), any(k[0] == 0x23 for k in fields(second))))
