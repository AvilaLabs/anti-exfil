# Jade port

A patch series that adds anti-exfil signing to `sign_psbt` in Blockstream Jade, on commit `a59d14c2b39715060e6721a309a7d49bedd3ee5b`. It works over USB serial only. Nothing has been flashed to a device.

| Path | Contents |
|---|---|
| `patches/series/` | The series: the vendored C module, parsing and validation, first and second pass, the fee warning, the Taproot key path, tests and docs |
| `patches/test-build-only/` | A zlib link fix needed for the native test build. Not part of the series |
| `patches/test-only-qemu-stack/` | Stack measurement under emulation. Not part of the series |
| `check_host_interop.py` | Runs the reference host and signer against the native build |
| `check_seed_vectors.py` | Replays `vectors/bip-anti-exfil-psbt-seed.json` against the native build |
| `control_baseline.py` | Runs the same requests on a build without the series |
| `tools/` | Build scripts for the native library and firmware |

## Limits

These are in addition to the limits of ordinary PSBT signing, and `docs/index.rst` in the series has the full list.

- Forms: P2PKH, P2WPKH, P2SH-P2WPKH, P2WSH and P2SH-P2WSH with a single key and `OP_CHECKSIG`, or `OP_CHECKMULTISIG` with the key once, and the Taproot key path. The optional forms, including Taproot script paths, are refused.
- Sighash ALL for ECDSA, and DEFAULT or ALL for Taproot.
- Every input needs a UTXO.
- BLE, QR, USB storage and Liquid refuse any PSBT holding these fields.
- At most 256 inputs and 64 outputs.
