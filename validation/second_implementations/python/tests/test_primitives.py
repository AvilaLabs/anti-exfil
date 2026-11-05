import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import indep as I
import proto
import secp
import psbt as P


def th(tag, *parts):
    return I.TH(tag, b"".join(parts))


def x32(i):
    return i.to_bytes(32, "big")


def keyset(count):
    return [int.from_bytes(I.H(b"prim-key" + bytes([i])), "big") % I.n for i in range(count)]


class TestHashes(unittest.TestCase):
    def test_ripemd160_vectors(self):
        self.assertEqual(secp.ripemd160(b"").hex(), "9c1185a5c5e9fc54612808977ee8f548b2258d31")
        self.assertEqual(secp.ripemd160(b"abc").hex(), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        self.assertEqual(secp.ripemd160(b"a" * 1000), __import__("hashlib").new("ripemd160", b"a" * 1000).digest())

    def test_curve_agrees_with_independent_jacobian(self):
        for k in (1, 2, 3, 12345, I.n - 1, I.n - 2, 2**200 + 17):
            self.assertEqual(secp.pt_mul(k, secp.G), I.mul(k))

    def test_bip340_published_vector0(self):
        pk = bytes.fromhex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
        sig = bytes.fromhex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
        self.assertTrue(secp.schnorr_verify(pk, bytes(32), sig))
        self.assertFalse(secp.schnorr_verify(pk, bytes(31) + b"\x01", sig))

    def test_parse33(self):
        pt = secp.pt_mul(7, secp.G)
        b = secp.ser33(pt)
        self.assertEqual(secp.parse33(b), pt)
        self.assertIsNone(secp.parse33(b[:32]))
        self.assertIsNone(secp.parse33(b"\x04" + b[1:]))
        self.assertIsNone(secp.parse33(b"\x02" + x32(secp.P)))      # x = p
        self.assertIsNone(secp.parse33(b"\x02" + x32(5)))           # 5 is not an x coordinate
        self.assertIsNone(secp.parse33(b + b"\x00"))


class TestSchnorrProtocol(unittest.TestCase):
    seen = set()

    def run_one(self, sk, m, rho):
        skb = x32(sk)
        hc = proto.schnorr_hc(rho)
        self.assertEqual(hc, th("s2c/schnorr/data", rho))
        # independent replay of step 2
        Pt = I.mul(sk)
        d = sk if Pt[1] % 2 == 0 else I.n - sk
        pk = x32(Pt[0])
        t0 = bytes(a ^ b for a, b in zip(x32(d), I.TH("BIP0340/aux", hc)))
        k0 = int.from_bytes(I.TH("s2c/schnorr/nonce", t0 + pk + m + hc), "big") % I.n
        R0pt = I.mul(k0)
        R0 = I.comp(R0pt)
        self.assertEqual(proto.schnorr_commit(skb, m, hc), R0)
        sig = proto.schnorr_sign(skb, m, rho)
        t = int.from_bytes(I.TH("s2c/schnorr/point", R0 + rho), "big")
        W = I.add(R0pt, I.mul(t))
        self.assertEqual(sig[:32], x32(W[0]))
        self.assertTrue(I.bip340_verify(pk, m, sig))
        self.assertTrue(proto.schnorr_host_check(pk, m, rho, R0, sig))
        TestSchnorrProtocol.seen.add((Pt[1] % 2, R0pt[1] % 2, W[1] % 2))
        return pk, R0, sig

    def test_many_cases_cover_all_parities(self):
        for i, sk in enumerate(keyset(60)):
            m = I.H(b"m%d" % i)
            self.run_one(sk, m, I.H(b"rho%d" % i))
        self.assertEqual(len(TestSchnorrProtocol.seen), 8)

    def test_empty_and_long_message(self):
        sk = keyset(1)[0]
        self.run_one(sk, b"", I.H(b"r1"))
        self.run_one(sk, bytes(range(256)) * 5, I.H(b"r2"))

    def test_host_rejections(self):
        sk = keyset(2)[1]
        m = I.H(b"msg")
        rho = I.H(b"rho")
        pk, R0, sig = self.run_one(sk, m, rho)
        ok = proto.schnorr_host_check
        self.assertTrue(ok(pk, m, rho, R0, sig))
        self.assertFalse(ok(pk, m, I.H(b"other"), R0, sig))
        flipped = bytes([R0[0] ^ 1]) + R0[1:]
        self.assertFalse(ok(pk, m, rho, flipped, sig))                 # R0 parity changed
        self.assertFalse(ok(pk, m, rho, b"\x05" + R0[1:], sig))        # unparsable
        self.assertFalse(ok(pk, m + b"x", rho, R0, sig))
        bad = sig[:63] + bytes([sig[63] ^ 1])
        self.assertFalse(ok(pk, m, rho, R0, bad))
        bad = bytes([sig[0] ^ 1]) + sig[1:]
        self.assertFalse(ok(pk, m, rho, R0, bad))
        self.assertFalse(ok(pk, m, rho, R0, sig[:63]))
        self.assertFalse(ok(pk, m, rho[:31], R0, sig))
        # a valid BIP340 signature whose nonce is not R0 + tG
        other = x32(5)
        plain = I.TH("BIP0340/aux", b"")  # any valid-looking plain signature via the program's own signer
        other_sig = proto.schnorr_sign(x32(sk), m, I.H(b"different rho"))
        self.assertFalse(ok(pk, m, rho, R0, other_sig))

    def test_failure_rules(self):
        sk = x32(keyset(1)[0])
        m = b"m"
        rho = I.H(b"rho")
        for bad in (bytes(32), x32(I.n), b"\xff" * 32, sk[:31]):
            with self.assertRaises(proto.ProtoFail):
                proto.schnorr_commit(bad, m, proto.schnorr_hc(rho))
        with self.assertRaises(proto.ProtoFail):
            proto.schnorr_commit(sk, m, bytes(31))
        with self.assertRaises(proto.ProtoFail):
            proto.schnorr_sign(sk, m, rho[:31])
        real = secp.tagged_hash

        def fake(zero_tag, value):
            def f(tag, x):
                if tag == zero_tag:
                    return value
                return real(tag, x)
            return f
        # k0 = 0 (hash is a multiple of n, reduced to zero)
        with mock.patch.object(proto, "tagged_hash", fake("s2c/schnorr/nonce", x32(I.n))):
            with self.assertRaises(proto.ProtoFail):
                proto.schnorr_commit(sk, m, proto.schnorr_hc(rho))
        # t >= n
        with mock.patch.object(proto, "tagged_hash", fake("s2c/schnorr/point", x32(I.n))):
            with self.assertRaises(proto.ProtoFail):
                proto.schnorr_sign(sk, m, rho)
        # k' = 0
        k0 = proto.schnorr_base(sk, m, proto.schnorr_hc(rho))[2]
        with mock.patch.object(proto, "tagged_hash", fake("s2c/schnorr/point", x32(I.n - k0))):
            with self.assertRaises(proto.ProtoFail):
                proto.schnorr_sign(sk, m, rho)
        # host: t >= n and W at infinity
        pk, R0, sig = self.run_one(keyset(1)[0], m, rho)
        with mock.patch.object(proto, "tagged_hash", fake("s2c/schnorr/point", x32(I.n))):
            self.assertFalse(proto.schnorr_host_check(pk, m, rho, R0, sig))
        R0pt = secp.parse33(R0)
        with mock.patch.object(proto, "tagged_hash", fake("s2c/schnorr/point", x32(I.n - 0))):
            pass
        # W = R0 + tG = infinity when t = n - k0 (R0 = k0 G)
        k0 = proto.schnorr_base(x32(keyset(1)[0]), m, proto.schnorr_hc(rho))[2]
        with mock.patch.object(proto, "tagged_hash", fake("s2c/schnorr/point", x32(I.n - k0))):
            self.assertFalse(proto.schnorr_host_check(pk, m, rho, R0, sig))

    def test_nonce_is_not_negated(self):
        # find a key where k0*G has odd y, and check R0_bytes records it
        for i, sk in enumerate(keyset(10)):
            hc = proto.schnorr_hc(I.H(b"x%d" % i))
            d, pk, k0, R0 = proto.schnorr_base(x32(sk), b"m", hc)
            self.assertEqual(R0[0], 2 + (I.mul(k0)[1] & 1))


class TestEcdsaProtocol(unittest.TestCase):
    seen = set()

    def run_one(self, sk, m, rho):
        skb = x32(sk)
        hc = proto.ecdsa_hc(rho)
        self.assertEqual(hc, th("s2c/ecdsa/data", rho))
        Pt = I.mul(sk)
        pk = I.comp(Pt)
        d_mask = bytes(a ^ b for a, b in zip(x32(sk), I.TH("s2c/ecdsa/aux", hc)))
        buf = d_mask + pk + m + hc
        self.assertEqual(len(buf), 129)
        k0 = int.from_bytes(I.TH("s2c/ecdsa/nonce", buf), "big")
        self.assertTrue(0 < k0 < I.n)
        R0pt = I.mul(k0)
        R0 = I.comp(R0pt)
        self.assertEqual(proto.ecdsa_commit(skb, m, hc), R0)
        r, s = proto.ecdsa_sign(skb, m, rho)
        t = int.from_bytes(I.TH("s2c/ecdsa/point", R0 + rho), "big")
        W = I.add(R0pt, I.mul(t))
        self.assertEqual(r, W[0] % I.n)
        self.assertTrue(0 < s <= (I.n - 1) // 2)
        self.assertTrue(I.ecdsa_verify_der(pk, m, I.der(r, s) + b"\x01"))
        self.assertTrue(proto.ecdsa_host_check(pk, m, rho, R0, r, s))
        TestEcdsaProtocol.seen.add((Pt[1] % 2, R0pt[1] % 2, W[1] % 2))
        return pk, R0, r, s

    def test_many_cases_cover_all_parities(self):
        for i, sk in enumerate(keyset(60)):
            self.run_one(sk, I.H(b"m%d" % i), I.H(b"rho%d" % i))
        self.assertEqual(len(TestEcdsaProtocol.seen), 8)

    def test_host_rejections(self):
        sk = keyset(3)[2]
        m = I.H(b"msg")
        rho = I.H(b"rho")
        pk, R0, r, s = self.run_one(sk, m, rho)
        ok = proto.ecdsa_host_check
        self.assertTrue(ok(pk, m, rho, R0, r, s))
        self.assertFalse(ok(pk, m, rho, R0, r, I.n - s))          # high s
        self.assertFalse(ok(pk, m, rho, R0, r, 0))
        self.assertFalse(ok(pk, m, rho, R0, 0, s))
        self.assertFalse(ok(pk, m, rho, R0, I.n, s))
        self.assertFalse(ok(pk, m, rho, R0, r + 1, s))
        self.assertFalse(ok(pk, m, I.H(b"o"), R0, r, s))
        self.assertFalse(ok(pk, I.H(b"o"), rho, R0, r, s))
        self.assertFalse(ok(pk, m, rho, bytes([R0[0] ^ 1]) + R0[1:], r, s))
        self.assertFalse(ok(b"\x02" + pk[1:2] + pk[2:], m + b"x", rho, R0, r, s))
        self.assertFalse(ok(pk[:32], m, rho, R0, r, s))
        self.assertFalse(ok(pk, m[:31], rho, R0, r, s))
        # a valid ordinary-looking signature with a different nonce
        r2, s2 = proto.ecdsa_sign(x32(sk), m, I.H(b"different"))
        self.assertFalse(ok(pk, m, rho, R0, r2, s2))

    def test_m_is_not_reduced_in_hash(self):
        sk = x32(keyset(1)[0])
        big = x32(I.n + 5)
        small = x32(5)
        hc = proto.ecdsa_hc(I.H(b"r"))
        self.assertNotEqual(proto.ecdsa_commit(sk, big, hc), proto.ecdsa_commit(sk, small, hc))

    def test_failure_rules(self):
        sk = x32(keyset(1)[0])
        m = I.H(b"m")
        rho = I.H(b"rho")
        hc = proto.ecdsa_hc(rho)
        for bad in (bytes(32), x32(I.n), sk[:31]):
            with self.assertRaises(proto.ProtoFail):
                proto.ecdsa_commit(bad, m, hc)
        with self.assertRaises(proto.ProtoFail):
            proto.ecdsa_commit(sk, m[:31], hc)
        real = secp.tagged_hash

        def fake(zero_tag, value):
            def f(tag, x):
                return value if tag == zero_tag else real(tag, x)
            return f
        for v in (bytes(32), x32(I.n), b"\xff" * 32):     # k0 = 0, k0 = n, k0 > n: no retry
            with mock.patch.object(proto, "tagged_hash", fake("s2c/ecdsa/nonce", v)):
                with self.assertRaises(proto.ProtoFail):
                    proto.ecdsa_commit(sk, m, hc)
        with mock.patch.object(proto, "tagged_hash", fake("s2c/ecdsa/point", x32(I.n))):
            with self.assertRaises(proto.ProtoFail):
                proto.ecdsa_sign(sk, m, rho)
        k0 = proto.ecdsa_base(sk, m, hc)[2]
        with mock.patch.object(proto, "tagged_hash", fake("s2c/ecdsa/point", x32(I.n - k0))):
            with self.assertRaises(proto.ProtoFail):
                proto.ecdsa_sign(sk, m, rho)
        pk, R0, r, s = self.run_one(keyset(1)[0], m, rho)
        with mock.patch.object(proto, "tagged_hash", fake("s2c/ecdsa/point", x32(I.n))):
            self.assertFalse(proto.ecdsa_host_check(pk, m, rho, R0, r, s))
        with mock.patch.object(proto, "tagged_hash", fake("s2c/ecdsa/point", x32(I.n - k0))):
            self.assertFalse(proto.ecdsa_host_check(pk, m, rho, R0, r, s))


class TestEncodings(unittest.TestCase):
    def test_der_roundtrip_and_strictness(self):
        for r, s in ((1, 1), (I.n - 1, 5), (0x80, 0x7F), (2**255, 2**255 + 3), (2**248, 7)):
            enc = P.der_encode(r, s) + b"\x01"
            self.assertEqual(enc[:-1], I.der(r, s))
            self.assertEqual(P.der_parse_strict(enc), (r, s, 1))
        good = I.der(0x80, 0x90) + b"\x01"
        bads = [
            good[:-1],                                         # too short to carry sighash (still parses?)
            b"\x31" + good[1:],
            good[:1] + bytes([good[1] + 1]) + good[2:],
            good[:2] + b"\x03" + good[3:],
            b"\x30\x08\x02\x01\x00\x02\x01\x01\x01",         # padded zero not needed? R=0x00 length1 ok -> r=0
        ]
        self.assertEqual(P.der_parse_strict(good)[:2], (0x80, 0x90))
        for b in bads[1:4]:
            with self.assertRaises(P.PsbtError):
                P.der_parse_strict(b)
        # negative R
        with self.assertRaises(P.PsbtError):
            P.der_parse_strict(b"\x30\x06\x02\x01\x80\x02\x01\x01\x01")
        # excess padding in R
        with self.assertRaises(P.PsbtError):
            P.der_parse_strict(b"\x30\x07\x02\x02\x00\x01\x02\x01\x01\x01")
        # excess padding in S
        with self.assertRaises(P.PsbtError):
            P.der_parse_strict(b"\x30\x07\x02\x01\x01\x02\x02\x00\x01\x01")
        # zero-length R
        with self.assertRaises(P.PsbtError):
            P.der_parse_strict(b"\x30\x05\x02\x00\x02\x01\x01\x01\x00")
        # trailing garbage / too long
        with self.assertRaises(P.PsbtError):
            P.der_parse_strict(good + b"\x00")
        with self.assertRaises(P.PsbtError):
            P.der_parse_strict(b"\x30" + bytes([71]) + b"\x02" + b"\x20" + bytes(32) + b"\x02\x20" + bytes(32) + b"\x01" * 8)

    def test_compact_size_canonical(self):
        r = P.Reader(b"\xfd\x01\x00")
        with self.assertRaises(P.PsbtError):
            r.cs()
        self.assertEqual(P.Reader(P.cs(300)).cs(), 300)

    def test_script_parse(self):
        ops = P.parse_script(b"\x21" + bytes(33) + b"\xac")
        self.assertEqual([o[0] for o in ops], [0x21, 0xAC])
        with self.assertRaises(P.PsbtError):
            P.parse_script(b"\x21" + bytes(10))
        ops = P.parse_script(b"\x4c\x21" + bytes(33) + b"\xac")
        self.assertFalse(ops[0][2])      # PUSHDATA1 is not a direct push


if __name__ == "__main__":
    unittest.main()
