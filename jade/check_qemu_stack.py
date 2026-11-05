#!/usr/bin/env python3
"""Valid anti-exfil flows on Jade's firmware in QEMU, with the main task stack high water mark.

Needs the QEMU build with CONFIG_AE_STACK_TEST (the separate test-only patch). The firmware image runs in
Espressif's qemu-system-xtensa through tools/qemu_jade.py (127.0.0.1 only). Only valid, well-formed requests
are sent: the reference host's exchanges, as in check_host_interop.py. Nothing is sent to any other device.

  python check_qemu_stack.py FLASH_IMAGE EFUSE_IMAGE [--report FILE]
"""
import argparse
import json
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "tools"))
import jade_keys as J                      # noqa: E402
import qemu_jade                           # noqa: E402

K, C, T = J.K, J.C, J.T
J.install()
STACK = 12288


def decode(v):
    return {"free_last_call": v & 0xFFFFFF, "free_task_lifetime": (v >> 24) & 0xFFFFFF, "approvals": v >> 48}


class QemuLink(J.JadeLink):
    pass


def stats(jade):
    return decode(jade._jadeRpc("debug_ae_stack_test"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("flash")
    ap.add_argument("efuse")
    ap.add_argument("--port", type=int, default=30121)
    ap.add_argument("--report")
    a = ap.parse_args()
    q = qemu_jade.Qemu(a.flash, a.efuse, a.port)
    q.start()
    rows, ok = [], True
    try:
        jade = J.JadeAPI.create_serial(device="tcp:127.0.0.1:%d" % a.port, timeout=240)
        jade.connect()
        assert jade.set_mnemonic(J.MNEMONIC) is True
        tmp = tempfile.mkdtemp(dir=str(HERE / ".work"))

        def flow(name, names, version, sighashes=None, ordinary=False):
            nonlocal ok
            K._counter[0] = 0
            forms = [K.Form(n, "m") for n in names]
            inputs = [K.Inp(f, sighash=h) for f, h in zip(forms, sighashes or [None] * len(forms))]
            rig = K.Rig(inputs, tmp, version=version, link_cls=J.link_for(jade), max_retries=0,
                        rho_source=K.fixed_rho(name), device_id="q-" + name)
            before = stats(jade)
            if ordinary:
                jade.sign_psbt(J.NETWORK, rig.request_bytes)
                mid = after = stats(jade)
                mid_row = None
            else:
                at = rig.host.start(rig.request_bytes)
                at.commit()
                mid = stats(jade)
                res = at.reveal()
                after = stats(jade)
                ok &= bool(res.signed)
            row = {"flow": name, "version": version, "inputs": len(names),
                   "pairs": None if ordinary else len(K.pairs_of(rig)),
                   "first_pass": None if ordinary else {"approvals_added": mid["approvals"] - before["approvals"],
                                                       "stack_free": mid["free_last_call"]},
                   "second_pass": {"approvals_added": after["approvals"] - (before["approvals"] if ordinary else mid["approvals"]),
                                   "stack_free": after["free_last_call"]},
                   "used_bytes": STACK - min(after["free_last_call"], mid["free_last_call"] if not ordinary else STACK)}
            rows.append(row)
            print(json.dumps(row), flush=True)

        flow("ordinary-p2wpkh", ["p2wpkh"], 0, ordinary=True)
        for name in ("p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2wsh-single", "p2wsh-2of3", "p2sh-p2wsh-2of3", "p2tr-key",
                     "p2tr-key-root"):
            for v in (0, 2):
                flow("%s-v%d" % (name, v), [name], v)
        flow("multi-input-ecdsa-v0", ["p2wpkh", "p2pkh", "p2sh-p2wpkh", "p2wsh-2of3"], 0)
        flow("multi-input-mixed-v2", list(K.REQUIRED_FORMS), 2)
        flow("multi-input-taproot-v0", ["p2tr-key", "p2tr-key-root", "p2tr-key", "p2tr-key-root"], 0)
        flow("ordinary-p2wpkh-again", ["p2wpkh"], 0, ordinary=True)
        final = stats(jade)
        print("final", json.dumps(final))
        worst = max(r["used_bytes"] for r in rows)
        print("worst depth over the flows: %d bytes of %d (free %d); task lifetime free %d" % (
            worst, STACK, STACK - worst, final["free_task_lifetime"]))
        if a.report:
            pathlib.Path(a.report).write_text(json.dumps({"rows": rows, "final": final, "worst_used": worst, "all_accepted": ok}, indent=2) + "\n")
    finally:
        q.stop()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
