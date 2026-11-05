# Anti-exfil signing

A signing device picks the nonce in every signature it makes. A compromised device can pick nonces that reveal its key to an attacker, and the signatures still look normal. Anti-exfil signing has the host add its own randomness to each nonce and check that the device used it, so the device can no longer choose the nonce on its own.

This handbook explains two draft BIPs from Avila Labs:

- **The protocol** ([`spec/bip-anti-exfil.md`](https://github.com/AvilaLabs/anti-exfil/blob/main/spec/bip-anti-exfil.md)), for BIP340 and ECDSA signatures.
- **The PSBT fields** ([`spec/bip-anti-exfil-psbt.md`](https://github.com/AvilaLabs/anti-exfil/blob/main/spec/bip-anti-exfil-psbt.md)), three input fields that carry the protocol between a wallet and a signing device.

The BIPs are the normative text. This handbook is a guide to them. Where the two differ, the BIPs are right and the handbook needs fixing.

## Status

Both are drafts with no BIP number. No cryptographer has reviewed them and there has been no outside audit. Nothing has run on a hardware device yet. The Python code in the repository uses variable-time arithmetic and must not be used with real keys.

## Where to start

| If you are | Read |
|---|---|
| Reviewing the cryptography | [The protocol](protocol.md), then [`spec/security-argument.md`](https://github.com/AvilaLabs/anti-exfil/blob/main/spec/security-argument.md) and [What isn't proved or tested](limits.md) |
| Writing wallet software | [The protocol](protocol.md), [Host rules](host.md), [PSBT fields](psbt.md) |
| Writing device firmware | [The protocol](protocol.md), [Device rules](device.md), [PSBT fields](psbt.md), [Test vectors](vectors.md) |
| Checking the work | [Running the checks](checks.md) and [`EVIDENCE.md`](https://github.com/AvilaLabs/anti-exfil/blob/main/EVIDENCE.md) |

[Reviewing the drafts](review.md) lists the questions where comments would help most.

## What's in the repository

| Folder | Contents |
|---|---|
| `spec/` | The two BIPs, the security argument and the transport analysis |
| `vectors/` | Test vectors for the protocol and the PSBT fields |
| `reference/`, `psbt/` | Reference arithmetic, and a reference host and signer, in Python |
| `c/` | A C module for libsecp256k1 |
| `jade/` | A patch series adding the protocol to Blockstream Jade's `sign_psbt` |
| `secp1140/` | The host checks, run against secp256k1 pull request 1140 and secp256k1-zkp |
| `proof/`, `validation/` | Proof documents and their checks, and the testing behind `EVIDENCE.md` |
