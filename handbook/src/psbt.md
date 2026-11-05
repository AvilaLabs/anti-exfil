# PSBT fields

The PSBT BIP carries the protocol between one host and one signer, in PSBT versions 0 and 2.

## The three fields

| Name | Key type | Key data | Value |
|---|---|---|---|
| `PSBT_IN_AE_HOST_COMMITMENT` | `0x21` | key identifier | `hc`, 32 bytes |
| `PSBT_IN_AE_NONCE_COMMITMENT` | `0x22` | key identifier | `R0_bytes`, 33 bytes |
| `PSBT_IN_AE_HOST_RANDOMNESS` | `0x23` | key identifier | `rho`, 32 bytes |

The key type numbers are proposed and depend on assignment. The fields belong only in input maps.

The key identifier is the 33-byte public key for ECDSA, the 32-byte x-only internal key for a Taproot key path, and the x-only key followed by the leaf hash for a Taproot script path. An input index and a key identifier make a **pair**, and each pair gets its own `rho`.

## Keeping them private

`rho` has to stay secret, so these fields must never appear in a PSBT given to anyone other than the host and the signer. The host keeps its own PSBT, which never contains them, and builds a separate request for each exchange.

## Two passes

**First pass.** The host sends a request with a host commitment for each pair. The signer runs step 2 and adds a nonce commitment for each one. It adds no signature and needs no approval. The host stores the nonce commitments and discards the response.

**Second pass.** The host sends a new request with the same transaction and pairs, holding only the randomness field for each pair. The signer gets one approval for the whole PSBT, runs step 4 for each pair, adds the signatures, removes every anti-exfil field and returns the PSBT. The host runs step 5 on each signature and adds to its own PSBT only fields it builds itself from the verified signatures.

If the transaction or the pairs change between passes, the host ends the attempt and starts over with new `rho` values.

## What the host takes from a response

Only the requested commitments or signatures. It fails the attempt if the core transaction changed, a requested value is missing, a commitment changed, a response holds an anti-exfil field it shouldn't, or a signature field was added, changed or removed where it shouldn't be. It ignores other differences, such as reserialized fields or added metadata, because it discards the response anyway.

## Signer rules

- Handle exactly the pairs named by these fields, and add no other signature. If any pair fails, fail the whole PSBT and return nothing.
- Validate everything before prompting the user: structure, pairs, key ownership, transaction data, sighash types and script paths.
- Fail if a pair already has a signature, if you don't hold the key, or if one input has both a key-path and a script-path pair.
- Don't present a fee as verified unless every input amount was verified, either against `PSBT_IN_NON_WITNESS_UTXO` or because a Taproot pair without `ANYONECANPAY` commits to them all. Otherwise tell the user the fee is unverified, or fail.

## Spend forms

Signers must support P2PKH, P2WPKH, P2SH-P2WPKH, the Taproot key path, and P2WSH and P2SH-P2WSH with a witness script that is either `<key> OP_CHECKSIG` or a bare `OP_CHECKMULTISIG` of up to 16 keys. The Taproot script path and some other scripts are optional. A host shouldn't request an optional form unless it knows the signer supports it, because a refusal counts as a failed attempt.

Accepted sighash types are `ALL`, `NONE` and `SINGLE`, with or without `ANYONECANPAY`, and `DEFAULT` for BIP340. A signer may accept only `ALL` and `DEFAULT` if it says so.

## Transports

The PSBT BIP assumes a direct link, such as USB, that keeps the exchange from third parties. On a QR code or a file, `rho` is visible to anything that can see the screen or keep the file. A QR or file profile needs its own specification. [`spec/transport-analysis.md`](https://github.com/AvilaLabs/anti-exfil/blob/main/spec/transport-analysis.md) looks at the options.
