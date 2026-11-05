"""Pins the signature hash, protocol key and signature-field key of every published exchange.

Reads vectors/bip-anti-exfil-psbt.json (it is not regenerated and the generator is not called) and checks
that, for each pair of each exchange, spend.resolve_pair on the exchange's host PSBT returns the `m`,
`protocol_pk` and `signature_key` the vector file states.

This is a regression pin, not an independent derivation. The values were produced by this reference code;
they are also reproduced by the two second implementations and spent on regtest, which is the evidence
that they are right. This test only makes sure a later change to the digest code, the Taproot tweak or the
field keys cannot go unnoticed in the no-regtest suite.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as K            # noqa: E402
import psbt_codec as C        # noqa: E402
import spend as S             # noqa: E402

VECTORS = K.ROOT / "vectors/bip-anti-exfil-psbt.json"


class KnownAnswers(unittest.TestCase):
    def test_every_exchange_pair(self):
        """Spends: the signature hash `m` of each spend form, the protocol key (the tweaked key for a key path) and the field that carries the signature, as pinned by the published vectors."""
        vec = json.loads(VECTORS.read_text())
        pairs = 0
        for ex in vec["exchanges"]:
            p = C.parse(bytes.fromhex(ex["host_psbt"]))
            device_xonly = {bytes.fromhex(k)[1:] for k in ex["device_keys"]}
            for pair in ex["pairs"]:
                pr = S.resolve_pair(p, pair["input"], bytes.fromhex(pair["key_identifier"]), device_xonly, True)
                where = "%s input %d" % (ex["id"], pair["input"])
                self.assertEqual(pr.message.hex(), pair["m"], where + " m")
                self.assertEqual(pr.pk.hex(), pair["protocol_pk"], where + " protocol_pk")
                self.assertEqual(pr.sigkey.hex(), pair["signature_key"], where + " signature_key")
                pairs += 1
        self.assertGreaterEqual(pairs, len(vec["exchanges"]))


class LegacyDigestProperties(unittest.TestCase):
    """The published vectors hold no multi-input legacy exchange with SIGHASH_NONE or SINGLE, so the
    sequence rule of the legacy digest is pinned here by its consensus property, not by a stored value."""

    def test_other_sequences_are_zeroed_under_none_and_single(self):
        """Spends: "Legacy | ECDSA | Legacy signature hash\" (consensus: with SIGHASH_NONE or SINGLE the other inputs' sequences are not signed)."""
        def tx(seq1):
            ins = [(b"\x01" * 32, 0, b"", 5), (b"\x02" * 32, 1, b"", seq1)]
            return C.Tx(2, ins, [(7, b"\x6a"), (8, b"\x6b")], 0)
        script = b"\x51"
        for h in (2, 3):
            self.assertEqual(S.legacy_sighash(tx(1), 0, script, h), S.legacy_sighash(tx(9), 0, script, h), h)
        self.assertNotEqual(S.legacy_sighash(tx(1), 0, script, 1), S.legacy_sighash(tx(9), 0, script, 1))
        self.assertNotEqual(S.legacy_sighash(tx(1), 1, script, 3), S.legacy_sighash(tx(9), 1, script, 3))


if __name__ == "__main__":
    unittest.main()
