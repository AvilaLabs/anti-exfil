"""Shared set-up for the Jade checks: Jade-derived keys for the reference fixtures, and a link
that sends the host's requests to the libjade signer.

The fixtures in psbt/tests/common.py take their keys from labelled seeds and write one made-up
derivation record. Here the keys that the device should hold come from Jade's test seed instead, at a path
by script type, and the records carry the seed's fingerprint and that path. Nothing in psbt is edited:
the key function and the record writer are replaced at run time.
"""
import hashlib
import os
import pathlib
import struct
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
JADE_TREE = pathlib.Path(os.environ.get("JADE_TREE", str(REPO / ".work/jade")))
for p in (REPO / "psbt", REPO / "psbt/tests", REPO / "reference", JADE_TREE):
    sys.path.insert(0, str(p))

import wallycore as wally                      # noqa: E402
import common as K                             # noqa: E402
import psbt_codec as C                         # noqa: E402
import transport as T                          # noqa: E402
from jadepy import JadeAPI, JadeError          # noqa: E402

MNEMONIC = ("paddle puppy easily actor poet apart screen drastic city front predict damp")
NETWORK = "localtest"
HARD = 0x80000000
PURPOSE = {"p2pkh": 44, "p2wpkh": 84, "p2sh-p2wpkh": 49, "p2tr-key": 86, "p2tr-key-root": 86}

_seed = wally.bip39_mnemonic_to_seed512(MNEMONIC, None)
_root = wally.bip32_key_from_seed(_seed, wally.BIP32_VER_TEST_PRIVATE, 0)
FINGERPRINT = wally.bip32_key_get_fingerprint(_root)
PATHS = {}             # private key bytes -> path
_orig_seedkey = K.seedkey
_orig_fill = K.Form.fill


def derive(path):
    key = wally.bip32_key_from_parent_path(_root, path, wally.BIP32_FLAG_KEY_PRIVATE)
    return bytes(wally.bip32_key_get_priv_key(key))


def jade_seedkey(label):
    """Keys named a (and b of the 2-of-3 forms) are Jade's; all others stay artificial."""
    parts = label.split("/")
    if len(parts) == 3 and (parts[2] == "a" or (parts[2] == "b" and parts[0].endswith("2of3"))):
        name, tag, which = parts
        purpose = PURPOSE.get(name, 48)
        digest = hashlib.sha256(label.encode()).digest()
        index = int.from_bytes(digest[:2], "big")
        path = [purpose | HARD, 1 | HARD, 0 | HARD, 0, index]
        sk = derive(path)
        PATHS[sk] = path
        return sk
    return _orig_seedkey(label)


def path_bytes(sk):
    return FINGERPRINT + b"".join(struct.pack("<I", p) for p in PATHS[sk])


def jade_fill(self, m):
    """Form.fill with the derivation record of each held key written for Jade's seed."""
    if self.taproot and self.name in ("p2tr-script", "p2tr-multi_a"):
        _orig_fill(self, m)
        fix = b"\x00\x00\x00\x00" + struct.pack("<I", 0x80000000)
        for k, v in list(m.items()):
            if k[:1] == b"\x16" and v.endswith(fix) and self.a in PATHS:
                m[k] = v[:-len(fix)] + path_bytes(self.a)
        return
    _orig_fill(self, m)
    fix = b"\x00\x00\x00\x00" + struct.pack("<I", 0x80000000)
    for k, v in list(m.items()):
        if v.endswith(fix) and (k[:1] == b"\x06" or k[:1] == b"\x16"):
            for sk in PATHS:
                if k[:1] == b"\x06" and K.pub33(sk) == k[1:] or k[:1] == b"\x16" and K.xonly(sk) == k[1:]:
                    m[k] = v[:-len(fix)] + path_bytes(sk)


def install():
    K.seedkey = jade_seedkey
    K.Form.fill = jade_fill


class JadeLink:
    """The host's link: every request goes to the libjade signer through sign_psbt."""

    def __init__(self, jade, _signer=None):
        self.jade = jade
        self.transcript = []
        self._unsolicited = []

    def exchange(self, request):
        try:
            response = self.jade.sign_psbt(NETWORK, request)
        except JadeError as e:
            self.transcript.append((request, None))
            raise T.DeviceError(str(e))
        self.transcript.append((request, response))
        return response

    def take_unsolicited(self):
        out, self._unsolicited = self._unsolicited, []
        return out


def link_for(jade):
    return lambda signer: JadeLink(jade, signer)


def open_jade():
    jade = JadeAPI.create_libjade()
    jade.connect()
    assert jade.clean_reset() is True
    assert jade.set_mnemonic(MNEMONIC) is True
    return jade


def prompts(jade):
    """How many times sign_psbt has asked for approval since the library was loaded."""
    reply = jade._jadeRpc("libjade_request", {"request": "get_test_sign_psbt_prompts"})
    return int.from_bytes(bytes(reply), "little")
