# Related work

## The schemes

Pieter Wuille's 2020 overview, [Overview of anti-covert-channel signing techniques](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-March/017667.html), compares the main approaches. Its Scheme 6 is two round trips, a deterministic nonce bound to a precommitted host value, and the host value added to the nonce. The overview describes a variant that uses a sign-to-contract tweak in place of the addition. This protocol is that variant. The overview credits earlier work by Stepan Snigirev and Andrew Poelstra, among others.

True2F's firewalled ECDSA ([Dauterman et al., 2019](https://arxiv.org/abs/1810.04660v4)) is earlier prior art for collaborative nonces in hardware tokens.

## Devices and libraries

- **Blockstream Jade** and **BitBox02** already ship anti-exfil for ECDSA, built on secp256k1-zkp's sign-to-contract module. Their messages have the same layout as this protocol, but their nonce derivation differs, so their bytes don't match these test vectors. A host running this protocol's step 5 accepts their signatures.
- **secp256k1 pull request 1140**, by Marko Bencun and Jonas Nick, proposes sign-to-contract and anti-exfil for BIP340 in libsecp256k1. Review there asked for a specification and a security argument. The `secp1140/` folder runs this protocol's host checks against it unmodified.
- **Trezor** has an [open pull request](https://github.com/trezor/trezor-firmware/pull/4826) adding ECDSA anti-exfil on the same secp256k1-zkp module.

## Other drafts

- **Sjors Provoost's draft** ([Sjors/bips#2](https://github.com/Sjors/bips/pull/2), October 2026) covers single-signer Taproot key-path signing, with proprietary PSBT fields and experimental implementations for HWI, Bitcoin Core and several devices. It adds the host value directly, so it doesn't interoperate with this protocol. Sjors plans to align those implementations with these drafts.
- **Non-interactive anti-exfil** ([Delving Bitcoin, 2024](https://delvingbitcoin.org/t/non-interactive-anti-exfil-airgap-compatible/1081)) uses one round, which suits air-gapped signing over QR. In that thread, Wuille pointed out that a device can still grind: `2^b` tries per signature leak `b` bits per signature.
- **[BIP 461](https://github.com/bitcoin/bips/blob/master/bip-0461.md)** standardizes deterministic ECDSA, so that two signers holding the same key can be compared. It detects a bad nonce only on messages both have signed, and doesn't help a watch-only wallet. A signature made under this protocol includes host randomness, so it differs from a BIP 461 signature by design.
