# Reviewing the drafts

Comments are welcome on the bitcoin-dev mailing list thread, or as [issues on GitHub](https://github.com/AvilaLabs/anti-exfil/issues). Corrections to the security argument would help most.

## Open questions

- **The security argument.** Does the reduction hold? Part 2, on what a malicious device can leak, is shorter and less reviewed than Part 1. The related-key extension rests on an assumption that hasn't been proved.
- **Hashed or plain tweak.** This protocol uses `k0 + hash(R0_bytes, rho)` to match sign-to-contract and the existing libraries. Sjors Provoost's draft uses `k0 + rho`. Is there a reason to prefer one?
- **Failure counting.** Are the rules for attempts, counts and warnings practical for wallet software, and are they strict enough? There's no overall bound on leakage without a cap on failed attempts, and the drafts don't set one.
- **A separate nonce derivation.** This protocol's derivation differs from the one Jade and BitBox02 ship. That keeps its nonces apart from ordinary signing, but existing devices would need to change to match the test vectors. Is that the right trade?
- **PSBT fields.** Are the proposed key types, key identifiers and required spend forms right? Should the PSBT BIP stay separate from the protocol?
- **QR and file transports.** These are left undefined because `rho` would be visible. Is there a workable profile for air-gapped devices?

## Reading order

For the cryptography, start with [The protocol](protocol.md) and the protocol BIP, then `spec/security-argument.md`. For the PSBT side, read [PSBT fields](psbt.md) and the PSBT BIP, then try the vectors against your own implementation.
