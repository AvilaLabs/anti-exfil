"""Signature hashes against data written by others: BIP 341 wallet test vectors (Taproot key path), the BIP 143 worked examples
(segwit v0) and Bitcoin Core's sighash.json at v31.1 (legacy). Sources, commits and sha256 are in outside_sighash_data/SOURCES.json.

A case outside what the reference function computes is counted with its reason, never dropped silently."""
import hashlib
import json
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as K            # noqa: E402
import psbt_codec as C        # noqa: E402
import spend as S             # noqa: E402

DATA = K.HERE / "outside_sighash_data"
SOURCES = json.loads((DATA / "SOURCES.json").read_text())["files"]
COUNTS = {}


def verified(name):
    raw = (DATA / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SOURCES[name]["sha256"], name + " is not the file named in SOURCES.json"
    return raw


def count(group, key, n=1):
    COUNTS.setdefault(group, {}).setdefault(key, 0)
    COUNTS[group][key] += n


class Bip341(unittest.TestCase):
    D = json.loads(verified("bip341_wallet-test-vectors.json"))

    def test_key_path_sighashes(self):
        """BIP 341 wallet test vectors, keyPathSpending: sigHash of every input, and the message that is hashed."""
        for case in self.D["keyPathSpending"]:
            tx = C.parse_tx(bytes.fromhex(case["given"]["rawUnsignedTx"]))
            prevouts = [(u["amountSats"], bytes.fromhex(u["scriptPubKey"])) for u in case["given"]["utxosSpent"]]
            for spend in case["inputSpending"]:
                idx, h = spend["given"]["txinIndex"], spend["given"]["hashType"]
                want = bytes.fromhex(spend["intermediary"]["sigHash"])
                msg = bytes.fromhex(spend["intermediary"]["sigMsg"])
                self.assertEqual(S.tagged("TapSighash", msg), want, "data check, input %d" % idx)
                seen = []
                real = S.tagged
                with mock.patch.object(S, "tagged", lambda tag, b: (seen.append((tag, b)), real(tag, b))[1]):
                    got = S.tap_sighash(tx, idx, prevouts, h)
                self.assertEqual(got, want, "sigHash of input %d, hashType %d" % (idx, h))
                self.assertEqual(seen[-1], ("TapSighash", msg), "sigMsg of input %d" % idx)
                count("bip341 key path", "inputs compared")
                self.assertEqual(S.tap_tweak(bytes.fromhex(spend["intermediary"]["internalPubkey"]),
                                             bytes.fromhex(spend["given"]["merkleRoot"] or "")), int(spend["intermediary"]["tweak"], 16))

    def test_script_pubkey_tweaks(self):
        """BIP 341 wallet test vectors, scriptPubKey: leaf hashes, merkle root, tweak, output key, control blocks."""
        def root(tree, leaves):
            if isinstance(tree, dict):
                lh = S.tap_leaf_hash(tree["leafVersion"], bytes.fromhex(tree["script"]))
                leaves.append(lh)
                return lh
            a, b = root(tree[0], leaves), root(tree[1], leaves)
            return S.tagged("TapBranch", min(a, b) + max(a, b))
        for case in self.D["scriptPubKey"]:
            internal = bytes.fromhex(case["given"]["internalPubkey"])
            tree, inter = case["given"]["scriptTree"], case["intermediary"]
            leaves = []
            mroot = root(tree, leaves) if tree is not None else b""
            self.assertEqual(mroot.hex(), inter["merkleRoot"] or "")
            self.assertEqual([x.hex() for x in leaves], inter.get("leafHashes", []))
            t, qx, par = S.tweaked_xonly(internal, mroot)
            self.assertEqual(t, int(inter["tweak"], 16))
            self.assertEqual(qx.hex(), inter["tweakedPubkey"])
            self.assertEqual(b"\x51\x20" + qx, bytes.fromhex(case["expected"]["scriptPubKey"]))
            for lh, cb in zip(leaves, case["expected"].get("scriptPathControlBlocks", [])):
                cb = bytes.fromhex(cb)
                self.assertEqual(S.control_root(cb, lh), mroot)
                self.assertEqual(cb[0] & 1, par)
                self.assertEqual(cb[1:33], internal)
                count("bip341 script path", "control blocks checked")
            count("bip341 script path", "output keys compared")


class Bip143(unittest.TestCase):
    TEXT = verified("bip-0143.mediawiki").decode()

    def examples(self):
        """(tx, fields) for every sigHash line in the Example section, up to the FindAndDelete section (a legacy-style script, not a
        different algorithm). fields holds the latest outpoint, amount, nHashType, scriptCode and preimage lines before the sigHash line."""
        text = self.TEXT[self.TEXT.index("=== Native P2WPKH ==="):self.TEXT.index("=== No FindAndDelete ===")]
        out, tx, f = [], None, {}
        lines = text.split("\n")
        for n, line in enumerate(lines):
            m = re.match(r"\s*The following is an unsigned transaction:\s*([0-9a-f]*)\s*$", line)
            if m:
                hx = m.group(1) or lines[n + 1].strip()
                tx, f = C.parse_tx(bytes.fromhex(hx)), {}
                continue
            m = re.match(r"\s*(hash preimage[^:]*|preimage|outpoint|amount|nHashType|scriptCode|hashOutputs):\s*([0-9a-f]+)\s*(\(.*)?$", line)
            if m:
                f["preimage" if "preimage" in m.group(1) else m.group(1)] = m.group(2)
                continue
            m = re.match(r"\s*sigHash:\s*([0-9a-f]{64})\s*$", line)
            if m:
                out.append((tx, dict(f, sigHash=m.group(1))))
        return out

    def test_worked_examples(self):
        """BIP 143 worked examples: native P2WPKH, P2SH-P2WPKH, native P2WSH and the P2SH-P2WSH example with six sighash types."""
        ex = self.examples()
        self.assertEqual(len(ex), 12)
        types = set()
        for tx, f in ex:
            label = f["sigHash"]
            outpoint = bytes.fromhex(f["outpoint"])
            idx = [j for j, a in enumerate(tx.ins) if a[0] + a[1].to_bytes(4, "little") == outpoint]
            self.assertEqual(len(idx), 1, label)
            script, o = C.read_blob(bytes.fromhex(f["scriptCode"]), 0)
            self.assertEqual(o, len(f["scriptCode"]) // 2)
            amount = int.from_bytes(bytes.fromhex(f["amount"]), "little")
            h = int.from_bytes(bytes.fromhex(f["nHashType"]), "little")
            want = bytes.fromhex(f["sigHash"])
            self.assertEqual(C.dsha(bytes.fromhex(f["preimage"])), want, "data check: " + label)
            if h & 3 == 3 and idx[0] >= len(tx.outs):
                # BIP 143 hashes 32 zero bytes here; the document's rule is to fail, so the function refuses
                self.assertEqual(f["hashOutputs"], "00" * 32)
                with self.assertRaises(S.SpendError) as cm:
                    S.bip143_sighash(tx, idx[0], script, amount, h)
                self.assertEqual(cm.exception.code, "sighash_single_no_output")
                count("bip143", "outside: SIGHASH_SINGLE with no matching output (function refuses, BIP 143 hashes zeros)")
                continue
            self.assertEqual(S.bip143_sighash(tx, idx[0], script, amount, h), want, label)
            types.add(h)
            count("bip143", "examples compared")
        self.assertEqual(types, {1, 2, 3, 0x81, 0x82, 0x83})


class CoreLegacy(unittest.TestCase):
    ROWS = json.loads(verified("core_v31.1_sighash.json"))[1:]

    @staticmethod
    def strip_codeseparators(script):
        """The script code as Bitcoin Core serializes it for the legacy signature hash: OP_CODESEPARATOR opcodes removed."""
        out, begin, i = b"", 0, 0
        while i < len(script):
            op = script[i]
            i += 1
            if 1 <= op <= 75:
                i += op
            elif op in (0x4C, 0x4D, 0x4E):
                w = {0x4C: 1, 0x4D: 2, 0x4E: 4}[op]
                if i + w > len(script):
                    break
                i += w + int.from_bytes(script[i:i + w], "little")
            if i > len(script):
                break
            if op == 0xAB:
                out += script[begin:i - 1]
                begin = i
        return out + script[begin:]

    def test_legacy_sighash(self):
        """Bitcoin Core v31.1 src/test/data/sighash.json: raw_transaction, script, input_index, hashType, signature_hash."""
        for n, (rawtx, script, idx, h, want) in enumerate(self.ROWS):
            h &= 0xFFFFFFFF
            want = bytes.fromhex(want)[::-1]                      # the file holds uint256::GetHex, the reverse of the hash bytes
            try:
                tx = C.parse_tx(bytes.fromhex(rawtx))
            except C.PsbtError as e:
                count("core legacy", "outside: transaction the codec refuses (%s)" % e.code)
                continue
            script = bytes.fromhex(script)
            code = self.strip_codeseparators(script)
            if code != script:
                count("core legacy", "adapter removed OP_CODESEPARATOR before hashing")
            core_base = {2: "NONE", 3: "SINGLE"}.get(h & 0x1F, "ALL")
            fn_base = {2: "NONE", 3: "SINGLE"}.get(h & 3, "ALL")
            if h & 3 == 3 and core_base == "SINGLE" and idx >= len(tx.outs):
                with self.assertRaises(S.SpendError) as cm:
                    S.legacy_sighash(tx, idx, code, h)
                self.assertEqual(cm.exception.code, "sighash_single_no_output")
                self.assertEqual(want, b"\x01" + b"\x00" * 31, "Core returns the constant 1 here (case %d)" % n)
                count("core legacy", "outside: SIGHASH_SINGLE with no matching output (function refuses, Core returns 1)")
                continue
            if core_base != fn_base:
                count("core legacy", "outside: base type read from five bits by Core, two bits by the function")
                continue
            self.assertEqual(S.legacy_sighash(tx, idx, code, h), want, "case %d hashType %#x" % (n, h))
            count("core legacy", "compared")
        self.assertGreater(COUNTS["core legacy"]["compared"], 0)

    @classmethod
    def tearDownClass(cls):
        print("outside sighash counts:", json.dumps(COUNTS, sort_keys=True), file=sys.stderr)


if __name__ == "__main__":
    unittest.main()
