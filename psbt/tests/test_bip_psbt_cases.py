"""The test cases printed in BIP 174, BIP 370 and BIP 371, in bip_psbt_cases.json: every invalid PSBT is refused by the codec,
every valid one is read, and every BIP 370 locktime case gives the stated locktime."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as K            # noqa: E402
import psbt_codec as C        # noqa: E402

CASES = json.loads((K.HERE / "bip_psbt_cases.json").read_text())["cases"]


def label(c):
    return "BIP %d: %s [%s]" % (c["source_bip"], c["case"], c["section"])


class BipCases(unittest.TestCase):
    def test_cases_were_loaded(self):
        for bip, invalid, valid in ((174, 20, 10), (370, 25, 22), (371, 11, 6)):
            self.assertEqual(sum(1 for c in CASES if c["source_bip"] == bip and c["expect"] == "invalid"), invalid, bip)
            self.assertEqual(sum(1 for c in CASES if c["source_bip"] == bip and c["expect"] == "valid"), valid, bip)

    def test_invalid_psbts_are_refused(self):
        """BIPs 174, 370 and 371, "The following are invalid PSBTs", and the BIP 370 locktime case that cannot be computed."""
        for c in CASES:
            if c["expect"] != "invalid":
                continue
            with self.subTest(label(c)):
                with self.assertRaises(C.PsbtError):
                    C.parse(bytes.fromhex(c["hex"]))

    def test_valid_psbts_are_read(self):
        """BIPs 174, 370 and 371, "The following are valid PSBTs"."""
        for c in CASES:
            if c["expect"] != "valid":
                continue
            with self.subTest(label(c)):
                p = C.parse(bytes.fromhex(c["hex"]))
                self.assertEqual(p.version, 2 if c["source_bip"] == 370 and b"\xfb" in p.glob else 0)

    def test_locktime_determination(self):
        """BIP 370, Determining Lock Time: the stated locktime of each case."""
        got = 0
        for c in CASES:
            if "locktime" not in c:
                continue
            got += 1
            with self.subTest(label(c)):
                self.assertEqual(C.core_tx(C.parse(bytes.fromhex(c["hex"]))).locktime, c["locktime"])
        self.assertEqual(got, 8)


class FieldShapes(unittest.TestCase):
    """The key data and value lengths BIPs 174, 370 and 371 fix, from the codec's table, one field at a time."""

    def psbt(self, version=0):
        return K.build_psbt([K.Inp(K.Form("p2wpkh"))], version=version)

    def test_key_data_length_of_every_known_field(self):
        values = {("inputs", 0x17): 32, ("inputs", 0x18): 32, ("outputs", 0x05): 32, ("inputs", 0x13): 64, ("inputs", 0x14): 64}
        base = self.psbt(2)
        for where, shapes in (("inputs", C._IN_SHAPES), ("outputs", C._OUT_SHAPES), ("glob", C._GLOBAL_SHAPES)):
            for t, (klens, _) in shapes.items():
                for n in range(0, 80):
                    p = base.clone()
                    m = p.glob if where == "glob" else getattr(p, where)[0]
                    for k in [k for k in m if k[0] == t]:
                        del m[k]
                    m[bytes([t]) + b"\x02" * n] = b"\x00" * values.get((where, t), 4)
                    try:
                        C.check_shapes(2, p.glob, p.inputs, p.outputs)
                        got = True
                    except C.PsbtError:
                        got = False
                    self.assertEqual(got, n in klens, (where, hex(t), n))

    def test_control_block_lengths(self):
        for n, code in ((32, "tap_control_block"), (33, None), (65, None), (34, "tap_control_block"), (33 + 32 * 128, None),
                        (33 + 32 * 129, "tap_control_depth")):
            p = self.psbt()
            p.inputs[0][b"\x15" + b"\x01" * n] = b"\x51\xc0"
            try:
                C.check_shapes(0, p.glob, p.inputs, p.outputs)
                got = None
            except C.PsbtError as e:
                got = e.code
            self.assertEqual(got, code, n)

    def test_value_lengths_that_are_fixed(self):
        for t, bad, good in ((0x13, (63, 66), (64, 65)), (0x14, (63, 66), (64, 65)), (0x17, (31, 33), (32,)), (0x18, (31, 33), (32,))):
            key = b"\x13" if t == 0x13 else b"\x14" + b"\x01" * 64 if t == 0x14 else bytes([t])
            for n in bad + good:
                p = self.psbt()
                p.inputs[0][key] = b"\x00" * n
                try:
                    C.check_shapes(0, p.glob, p.inputs, p.outputs)
                    got = True
                except C.PsbtError as e:
                    got = False
                    self.assertEqual(e.code, "bad_merkle_root" if t == 0x18 else "bad_value_length")
                self.assertEqual(got, n in good, (hex(t), n))

    def test_version_2_fields_in_a_version_0_psbt(self):
        for t, where in ((0x02, "glob"), (0x03, "glob"), (0x04, "glob"), (0x05, "glob"), (0x06, "glob"), (0x0e, "inputs"), (0x0f, "inputs"),
                         (0x10, "inputs"), (0x11, "inputs"), (0x12, "inputs"), (0x03, "outputs"), (0x04, "outputs")):
            p = self.psbt()
            m = p.glob if where == "glob" else getattr(p, where)[0]
            m.pop(bytes([t]), None)
            m[bytes([t])] = b"\x00" * 4
            with self.assertRaises(C.PsbtError) as cm:
                C.check_shapes(0, p.glob, p.inputs, p.outputs)
            self.assertEqual(cm.exception.code, "v2_field_in_v0", (where, hex(t)))


# The shapes below are written out from the BIPs and do not read the codec's tables. For each type: (allowed key data lengths,
# allowed value lengths or None). BIP 174 types are 0x00-0x0d for inputs, 0x00-0x02 for outputs and 0x00, 0x01, 0xfb for
# the global map; BIP 370 adds the version 2 fields; BIP 371 adds 0x13-0x18 for inputs and 0x05-0x07 for outputs.
IN_SHAPES = {
    0x00: ([0], None), 0x01: ([0], None), 0x02: ([33, 65], None), 0x03: ([0], None), 0x04: ([0], None), 0x05: ([0], None),
    0x06: ([33, 65], None), 0x07: ([0], None), 0x08: ([0], None), 0x0a: ([20], None), 0x0b: ([32], None), 0x0c: ([20], None),
    0x0d: ([32], None), 0x0e: ([0], None), 0x0f: ([0], None), 0x10: ([0], None), 0x11: ([0], None), 0x12: ([0], None),
    0x13: ([0], [64, 65]), 0x14: ([64], [64, 65]), 0x16: ([32], None), 0x17: ([0], [32]), 0x18: ([0], [32]),
}
OUT_SHAPES = {0x00: ([0], None), 0x01: ([0], None), 0x02: ([33, 65], None), 0x03: ([0], None), 0x04: ([0], None),
              0x05: ([0], [32]), 0x06: ([0], None), 0x07: ([32], None)}
GLOBAL_SHAPES = {0x00: ([0], None), 0x01: ([78], None), 0x02: ([0], None), 0x03: ([0], None), 0x04: ([0], None),
                 0x05: ([0], None), 0x06: ([0], None), 0xfb: ([0], None)}
# BIP 370: defined for version 2 only
V2_GLOBAL, V2_INPUT, V2_OUTPUT = [0x02, 0x03, 0x04, 0x05, 0x06], [0x0e, 0x0f, 0x10, 0x11, 0x12], [0x03, 0x04]


class LiteralShapes(unittest.TestCase):
    """The same checks as FieldShapes, with the expected shapes written out in this file, one field at a time."""

    def base(self, version):
        return K.build_psbt([K.Inp(K.Form("p2wpkh"))], version=version)

    def accepted(self, version, p):
        try:
            C.check_shapes(version, p.glob, p.inputs, p.outputs)
            return True
        except C.PsbtError:
            return False

    def maps(self, p, where):
        return p.glob if where == "glob" else p.inputs[0] if where == "input" else p.outputs[0]

    def test_key_data_length_of_every_known_field(self):
        """BIPs 174, 370, 371: a known field with key data of the wrong length is refused and with a right one is not."""
        base = self.base(2)
        for where, shapes in (("input", IN_SHAPES), ("output", OUT_SHAPES), ("glob", GLOBAL_SHAPES)):
            for t, (klens, vlens) in shapes.items():
                for n in range(0, 80):
                    p = base.clone()
                    m = self.maps(p, where)
                    for k in [k for k in m if k[0] == t]:
                        del m[k]
                    m[bytes([t]) + b"\x02" * n] = b"\x00" * (vlens[0] if vlens else 4)
                    self.assertEqual(self.accepted(2, p), n in klens, (where, hex(t), n))

    def test_fixed_value_lengths(self):
        """BIPs 371: the Taproot signature, internal key and merkle root values have fixed lengths."""
        base = self.base(2)
        for where, shapes in (("input", IN_SHAPES), ("output", OUT_SHAPES)):
            for t, (klens, vlens) in shapes.items():
                if vlens is None:
                    continue
                for n in range(0, 80):
                    p = base.clone()
                    m = self.maps(p, where)
                    for k in [k for k in m if k[0] == t]:
                        del m[k]
                    m[bytes([t]) + b"\x02" * klens[0]] = b"\x00" * n
                    self.assertEqual(self.accepted(2, p), n in vlens, (where, hex(t), n))

    def test_version_2_fields_one_at_a_time(self):
        """BIP 370: a field defined for version 2 only is refused in a version 0 PSBT and accepted in a version 2 one."""
        for where, types in (("glob", V2_GLOBAL), ("input", V2_INPUT), ("output", V2_OUTPUT)):
            for t in types:
                p0 = self.base(0)
                m = self.maps(p0, where)
                m[bytes([t])] = b"\x00" * 4
                with self.assertRaises(C.PsbtError) as cm:
                    C.check_shapes(0, p0.glob, p0.inputs, p0.outputs)
                self.assertEqual(cm.exception.code, "v2_field_in_v0", (where, hex(t)))
                p2 = self.base(2)
                self.maps(p2, where)[bytes([t])] = b"\x00" * 4
                self.assertTrue(self.accepted(2, p2), (where, hex(t)))
        # and nothing else in a clean version 0 PSBT is taken for a version 2 field
        self.assertTrue(self.accepted(0, self.base(0)))
        for where, shapes, v2 in (("input", IN_SHAPES, V2_INPUT), ("output", OUT_SHAPES, V2_OUTPUT), ("glob", GLOBAL_SHAPES, V2_GLOBAL)):
            for t, (klens, vlens) in shapes.items():
                if t in v2:
                    continue
                p = self.base(0)
                m = self.maps(p, where)
                for k in [k for k in m if k[0] == t]:
                    del m[k]
                m[bytes([t]) + b"\x02" * klens[0]] = b"\x00" * (vlens[0] if vlens else 4)
                self.assertTrue(self.accepted(0, p), (where, hex(t)))


if __name__ == "__main__":
    unittest.main()
