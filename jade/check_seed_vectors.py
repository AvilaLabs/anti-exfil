#!/usr/bin/env python3
"""Replay vectors/bip-anti-exfil-psbt-seed.json against Jade's sign_psbt (libjade, not hardware) and compare bytes.

Question answered: does Jade, holding the mnemonic of the vector file, produce exactly the PSBTs in the file?

For each exchange the file's first_request goes to sign_psbt and the answer is compared with first_response, then second_request with
second_response. The comparison is on the parsed PSBT: the core transaction, every global, input and output map entry (so every anti-exfil
field 0x21, 0x22 and 0x23 and every signature field 0x02 and 0x13). Whether the serialized bytes are also identical is reported on its own;
the file says a reader must not depend on map order, so an order-only difference is a note and not a failure. A refusal by Jade is recorded
with its exact message and counts as not passed.

Controls: one byte of an expected R0 and one byte of an expected signature are flipped, and the same comparison must report a mismatch
against Jade's real answer.

Run:  LD_LIBRARY_PATH=<dir with libjade.so> python check_seed_vectors.py [--report FILE]
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import jade_keys as J                          # noqa: E402  (not installed: the reference fixtures stay as they are)

C = J.C
wally = J.wally
JadeError = J.JadeError
REPO = J.REPO
VECTORS = REPO / "vectors/bip-anti-exfil-psbt-seed.json"
AE_TYPES = (0x21, 0x22, 0x23)
SIG_TYPES = (0x02, 0x13)


def kind(scope, key):
    """Name the field class for a report: anti-exfil, signature or other."""
    if scope == "input" and key[:1] and key[0] in AE_TYPES:
        return "anti-exfil"
    if scope == "input" and key[:1] and key[0] in SIG_TYPES:
        return "signature"
    return "other"


def diff_maps(scope, index, want, got):
    out = []
    for k in sorted(set(want) | set(got)):
        if want.get(k) == got.get(k):
            continue
        out.append({"scope": scope, "index": index, "key": k.hex(), "class": kind(scope, k),
                    "expected": want[k].hex() if k in want else None, "actual": got[k].hex() if k in got else None})
    return out


def compare(expected, actual):
    """Exact comparison of two serialized PSBTs by their parsed maps. Returns (same_parsed, same_bytes, diffs)."""
    pe, pa = C.parse(expected), C.parse(actual)
    diffs = diff_maps("global", None, pe.glob, pa.glob)
    if len(pe.inputs) != len(pa.inputs) or len(pe.outputs) != len(pa.outputs):
        diffs.append({"scope": "shape", "expected": [len(pe.inputs), len(pe.outputs)], "actual": [len(pa.inputs), len(pa.outputs)]})
    else:
        for i, (w, g) in enumerate(zip(pe.inputs, pa.inputs)):
            diffs += diff_maps("input", i, w, g)
        for i, (w, g) in enumerate(zip(pe.outputs, pa.outputs)):
            diffs += diff_maps("output", i, w, g)
    tx_same = C.ser_tx(C.core_tx(pe)) == C.ser_tx(C.core_tx(pa))
    if not tx_same:
        diffs.append({"scope": "core transaction", "expected": C.ser_tx(C.core_tx(pe)).hex(), "actual": C.ser_tx(C.core_tx(pa)).hex()})
    return not diffs, expected == actual, diffs


def sign(jade, request):
    try:
        return jade.sign_psbt(J.NETWORK, request), None
    except JadeError as e:
        return None, e.message if hasattr(e, "message") else str(e)


def one_pass(jade, request, expected):
    before = J.prompts(jade)
    out, err = sign(jade, request)
    result = {"prompts": J.prompts(jade) - before}
    if err is not None:
        result.update(status="refused", refusal=err)
        return result, None
    same, same_bytes, diffs = compare(expected, bytes(out))
    result.update(status="match" if same else "mismatch", bytes_identical=same_bytes, diffs=diffs)
    if same and not same_bytes:
        result["note"] = "parsed maps identical, serialization differs (map order or encoding only)"
    return result, bytes(out)


def loaded_libjade():
    """Path of the libjade.so the process has mapped."""
    for line in pathlib.Path("/proc/self/maps").read_text().splitlines():
        if line.rstrip().endswith("libjade.so"):
            return pathlib.Path(line.split()[-1]).resolve()
    return None


def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def flip(blob, needle):
    """blob with the last byte of the first occurrence of needle flipped, or None if needle is absent."""
    at = blob.find(needle)
    if at < 0:
        return None
    i = at + len(needle) - 1
    return blob[:i] + bytes([blob[i] ^ 0x01]) + blob[i + 1:]


def controls(jade, doc):
    """The comparison must fail when one byte of an expected R0, or of an expected signature, is changed."""
    out = []
    by_id = {e["id"]: e for e in doc["exchanges"]}
    for cid in ("seed-p2wpkh-v0", "seed-p2tr-key-v0", "seed-p2wsh-2of3-v2"):
        e = by_id[cid]
        pair = e["pairs"][0]
        q1, r1 = bytes.fromhex(e["first_request"]), bytes.fromhex(e["first_response"])
        q2, r2 = bytes.fromhex(e["second_request"]), bytes.fromhex(e["second_response"])
        for what, request, expected, needle in (("R0", q1, r1, bytes.fromhex(pair["R0_bytes"])),
                                                ("signature", q2, r2, bytes.fromhex(pair["signature_field"]))):
            bad = flip(expected, needle)
            row = {"exchange": cid, "flipped": what}
            if bad is None:
                row["result"] = "control not run: expected value not found in the expected response"
                row["detected"] = False
            else:
                clean, _ = one_pass(jade, request, expected)
                res, _ = one_pass(jade, request, bad)
                row.update(unmodified_expected=clean["status"], modified_expected=res["status"],
                           detected=clean["status"] == "match" and res["status"] == "mismatch",
                           diff_fields=[(d["scope"], d["index"], d["key"], d["class"]) for d in res.get("diffs", [])])
            out.append(row)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default=str(HERE / "seed_vectors_report.json"))
    args = ap.parse_args()

    doc = json.loads(VECTORS.read_text())
    seed = doc["seed"]
    jade = J.JadeAPI.create_libjade()
    jade.connect()
    assert jade.clean_reset() is True
    assert jade.set_mnemonic(seed["mnemonic"], seed["passphrase"] or None) is True
    lib = loaded_libjade()

    head = subprocess.run(["git", "-C", str(J.JADE_TREE), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(J.JADE_TREE), "status", "--short", "--untracked-files=no"], capture_output=True, text=True).stdout.strip()
    # Jade must hold the file's wallet: its root key's fingerprint is the file's master fingerprint
    xpub = jade.get_xpub(J.NETWORK, [])
    fp = bytes(wally.bip32_key_get_fingerprint(wally.bip32_key_from_base58(xpub))).hex()

    report = {
        "vector_file": str(VECTORS.relative_to(REPO)),
        "vector_file_sha256": sha256(VECTORS),
        "libjade": str(lib),
        "libjade_sha256": sha256(lib) if lib else None,
        "jade_tree": str(J.JADE_TREE),
        "jade_tree_head": head,
        "jade_tree_tracked_changes": dirty or None,
        "wallet": {"mnemonic_from_file": seed["mnemonic"], "master_fingerprint_expected": seed["master_fingerprint"],
                   "master_fingerprint_on_jade": fp},
        "exchanges": [],
    }
    if fp != seed["master_fingerprint"]:
        report["summary"] = {"verdict": "wallet mismatch: Jade does not hold the file's wallet, no exchange was replayed"}
        pathlib.Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
        print(report["summary"]["verdict"])
        return 1

    for e in doc["exchanges"]:
        q1, r1 = bytes.fromhex(e["first_request"]), bytes.fromhex(e["first_response"])
        q2, r2 = bytes.fromhex(e["second_request"]), bytes.fromhex(e["second_response"])
        first, _ = one_pass(jade, q1, r1)
        second, _ = one_pass(jade, q2, r2)
        row = {"id": e["id"], "forms": [i["form"] for i in e["inputs"]], "psbt_version": e["psbt_version"],
               "first": first, "second": second}
        row["status"] = "match" if first["status"] == second["status"] == "match" else (
            "refused" if "refused" in (first["status"], second["status"]) else "mismatch")
        row["bytes_identical"] = bool(first.get("bytes_identical") and second.get("bytes_identical"))
        report["exchanges"].append(row)
        print("%-28s %-9s bytes identical: %s" % (e["id"], row["status"], row["bytes_identical"]), flush=True)
        for d in first.get("diffs", []) + second.get("diffs", []):
            print("   diff", d, flush=True)
        for p in (first, second):
            if p["status"] == "refused":
                print("   refused:", p["refusal"], flush=True)

    report["controls"] = controls(jade, doc)
    ex = report["exchanges"]
    count = lambda s: sum(1 for r in ex if r["status"] == s)
    summary = {"exchanges": len(ex), "match": count("match"), "mismatch": count("mismatch"), "refused": count("refused"),
               "parsed_match_and_bytes_identical": sum(1 for r in ex if r["status"] == "match" and r["bytes_identical"]),
               "parsed_match_but_bytes_differ": [r["id"] for r in ex if r["status"] == "match" and not r["bytes_identical"]],
               "controls_run": len(report["controls"]), "controls_detected": sum(1 for c in report["controls"] if c["detected"])}
    summary["verdict"] = ("all %d exchanges match" % len(ex)) if summary["match"] == len(ex) else "not all exchanges match"
    report["summary"] = summary
    pathlib.Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    ok = summary["match"] == len(ex) and summary["controls_detected"] == summary["controls_run"]
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
