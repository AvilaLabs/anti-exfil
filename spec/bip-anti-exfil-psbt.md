```
BIP: ?
Layer: Applications
Title: PSBT Fields for Anti-Exfil Signing
Authors: Connor Avila <Connoravila@gmail.com>
Status: Draft
Type: Specification
Assigned: ?
License: MIT
Version: 0.16.0
Requires: 66, 143, 174, 340, 341, 342, 370, 371, 373
```

Requires the anti-exfil signing BIP, called "the protocol" here, whose steps and failure rules apply throughout.

## Abstract

This document defines three per-input PSBT fields and the rules for running the anti-exfil signing protocol between one host and one signer over PSBT. It applies to PSBT versions 0 and 2.

## Motivation

Wallets pass transactions to signing devices as PSBTs, so a device can only offer anti-exfil signing on that path if both sides agree on an encoding. Without public fields, each pairing of wallet and device would need its own extension, and a mistake in the exchange, such as an exposed `rho`, can cancel the protection the protocol exists to give. BIP 174 expects non-proprietary fields to be defined in a BIP.

## Specification

### Fields

| Name | Keytype | Keydata | Value |
|---|---|---|---|
| `PSBT_IN_AE_HOST_COMMITMENT` | `0x21` | key identifier | `hc`, 32 bytes |
| `PSBT_IN_AE_NONCE_COMMITMENT` | `0x22` | key identifier | `R0_bytes`, 33 bytes |
| `PSBT_IN_AE_HOST_RANDOMNESS` | `0x23` | key identifier | `rho`, 32 bytes |

The key types are proposed and depend on assignment. They are defined only for input maps. The same numbers in a global or output map are ordinary unknown fields. An implementation either fails on a key type written as a non-minimal CompactSize or reads it as the same number. It never treats it as an unknown field.

The key identifier is:

- for ECDSA, the 33-byte public key, as in `PSBT_IN_PARTIAL_SIG`
- for a Taproot key-path spend, the 32-byte x-only internal key
- for a Taproot script-path spend, the 32-byte x-only key followed by the 32-byte leaf hash, as in `PSBT_IN_TAP_SCRIPT_SIG`

Any other length fails. A **pair** is an input index and a full key identifier. Each pair has its own independently drawn `rho`, and a key used in two leaves forms two pairs.

These fields are private to one host and one signer. They MUST NOT appear in a PSBT given to any other party, because `rho` has to stay secret. The host achieves this by keeping its own PSBT, which never contains them, and building a separate request for each exchange.

### Spends

| Spend | Protocol | `m` | Key | Signature field |
|---|---|---|---|---|
| Legacy, including P2SH | ECDSA | Legacy signature hash | The key | `PSBT_IN_PARTIAL_SIG` |
| Segwit v0, including wrapped | ECDSA | BIP143 signature hash | The key | `PSBT_IN_PARTIAL_SIG` |
| Taproot key path | BIP340 | BIP341 signature hash | The tweaked key | `PSBT_IN_TAP_KEY_SIG` |
| Taproot script path | BIP340 | BIP342 signature hash for the leaf | The key | `PSBT_IN_TAP_SCRIPT_SIG` |

For a key-path spend, the signer normalizes and tweaks the secret as in BIP341, using the internal key and `PSBT_IN_TAP_MERKLE_ROOT`, or an empty script path if that field is absent. `pk` in the protocol is the output key. Signature hashes are computed with no annex.

A **direct push** of a key is the single opcode equal to its length, `0x21` for 33 bytes and `0x20` for 32. `OP_PUSHDATA` forms do not count.

**Required forms.** Signers MUST support P2PKH, P2WPKH, P2SH-P2WPKH, the Taproot key path, and P2WSH and P2SH-P2WSH whose witness script is exactly one of:

- `<key> OP_CHECKSIG`
- `OP_m <key> ... <key> OP_n OP_CHECKMULTISIG`, with `1 <= m <= n <= 16`, `OP_m` and `OP_n` being `OP_1` to `OP_16`, and each key a direct push of a valid 33-byte key. Key order is not constrained. A device key listed twice fails.

**Optional forms.** Signers MAY support the Taproot script path, the required script forms under legacy P2SH, and other scripts in which exactly one `OP_CHECKSIG` or `OP_CHECKSIGVERIFY` is immediately preceded by a direct push of the key. A signer fails on any form it does not support. A host SHOULD NOT request an optional form unless it knows the signer supports it, because a refusal is a failed attempt.

**Script-path pairs.** Exactly one `PSBT_IN_TAP_LEAF_SCRIPT` entry MUST match the leaf hash. Its leaf version MUST be `0xC0`, and its control block MUST compute the spent output key with at most 128 path elements. Exactly one `OP_CHECKSIG`, `OP_CHECKSIGVERIFY` or `OP_CHECKSIGADD` in the leaf MUST be immediately preceded by a 32-byte direct push of this key. Other keys in the leaf do not count. Scripts containing an `OP_SUCCESSx` opcode fail. Leaf version `0xC0` and the limit of 128 elements come from BIP 341 and BIP 342. Requiring one position means the signature has one role in the leaf that the user can be shown.

**Unsupported.** The script code for any pair MUST NOT contain `OP_CODESEPARATOR` as an opcode, because it changes what the signature hash covers. Each of these also fails:

- a 65-byte key identifier
- on an input with a pair, a derivation record whose 65-byte key, with prefix `0x04`, `0x06` or `0x07`, has the x coordinate of a device key, because that is the same secret under another encoding
- a Taproot input with a pair whose `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` lists a device key, in either parity form, because the protocol covers single signers only
- a key-path pair whose internal key is the x-only form of the aggregate key in that field's key data, for the same reason

A script-path pair under an aggregate internal key is allowed if the device is not a participant. Uncompressed keys that are not device keys are not examined. A signer that cannot tell whether such a key is a device key, because it holds a seed and not a list of keys, MAY fail on any uncompressed derivation record or `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` field on an input with a pair.

### Sighash types

For each input with a pair, the type is the input's `PSBT_IN_SIGHASH_TYPE`, a 32-bit little-endian value, if present. If absent, it is `SIGHASH_ALL` for ECDSA and `SIGHASH_DEFAULT` for BIP340. Accepted values are `SIGHASH_ALL`, `NONE` and `SINGLE`, each with or without `ANYONECANPAY`, and for BIP340 also `SIGHASH_DEFAULT`. Each party fails on any other value, on a present zero for ECDSA, and on `SIGHASH_SINGLE` with no matching output, on either pass. The exception is a signer whose PSBT library cannot tell a present zero from an absent field: it MAY treat a present zero as absent, and it then signs `SIGHASH_ALL`. A signer MAY accept only `SIGHASH_ALL` and, for BIP340, `SIGHASH_DEFAULT`, and fail on the rest, stating that it does. A host SHOULD NOT request another type unless it knows the signer supports it, because a refusal is a failed attempt. A BIP340 signature has a trailing sighash byte unless the type is `SIGHASH_DEFAULT`.

### Validation scope

Each party fails on a requested input with a final scriptSig or final witness, or on missing or mismatched data that the input's signature hash needs: a UTXO field, redeem script, witness script or Taproot output key. Legacy spends need `PSBT_IN_NON_WITNESS_UTXO`. Segwit v0 and Taproot spends need either UTXO field. If both are present on a requested input they MUST agree. A `PSBT_IN_NON_WITNESS_UTXO` MUST hash to the input's previous txid and contain its output index. Taproot pairs without `ANYONECANPAY` also need every input's previous output. When every input has a valid UTXO field, each party fails if the outputs exceed the inputs.

Inputs with no pair are not otherwise constrained by this document. They may be finalized, unclassifiable or held by other signers. Leaves other than the requested one are ignored. An implementation MAY apply stricter general PSBT validation, but MUST state in its documentation that it does, because a stricter party fails where a conforming one would not. An implementation MAY cap sizes and counts; exceeding a cap fails and never truncates.

### Host

**Choosing pairs.** The host holds a set of device keys, each with a canonical identifier: the 33-byte key for ECDSA and the x-only key for Taproot. Two forms of one x-only key are one identifier and MUST NOT create two pairs. Membership is by public key equality with these sources:

- an ECDSA pair from `PSBT_IN_BIP32_DERIVATION`
- a key-path pair from `PSBT_IN_TAP_INTERNAL_KEY`
- a script-path pair from a leaf hash listed in `PSBT_IN_TAP_BIP32_DERIVATION`, if a matching leaf script is present

For a Taproot input, if the device holds the internal key the host chooses the key-path pair and no script-path pair. Only one path can spend the input.

The host skips a pair whose signature is already in its PSBT and SHOULD tell the user, because it cannot tell how that signature was made. For a key-path pair, that means `PSBT_IN_TAP_KEY_SIG` is present. It SHOULD also tell the user about a listed leaf with no script, a `PSBT_IN_TAP_BIP32_DERIVATION` record that lists no leaf and names a device key other than the internal key, a device key found only in an uncompressed derivation record, and a device key found only in a script with no derivation record, since none of these forms a pair. It fails before recording an attempt if its PSBT already holds these fields, if any pair is ambiguous or unsupported, if a derivation record names a device key the input's script does not contain, or if no pairs remain.

Before sending a request, the host MUST tell the user it is requesting anti-exfil signing. If the device returns an ordinary signature, or does not recognize the fields, the attempt fails, and the host MUST NOT fall back without a separate user decision.

**First pass.**

1. Build a request from the host's PSBT with `PSBT_IN_AE_HOST_COMMITMENT` for each pair, and send it.
2. Handle the response as below. Store each `PSBT_IN_AE_NONCE_COMMITMENT`, failing if any is missing or fails `parse33`. Discard the response.

**Second pass.**

3. Build a new request with `PSBT_IN_AE_HOST_RANDOMNESS` for each pair and no other anti-exfil field. It MUST have the same transaction and pair set as the first. If either has changed, end the attempt, erase its values, and start over with new `rho` values. That attempt ends as abandoned unless a failure was already counted for it.
4. Handle the response as below. Read the signature for each pair and run step 5 of the protocol with the signature hash the host computed itself. For ECDSA, the field is the DER encoding of `(r, s)` plus a sighash byte, and a field that is not strict DER (BIP 66) fails. For BIP340, the field is `sig` alone for `SIGHASH_DEFAULT` and `sig` plus the sighash byte otherwise. For either scheme, the sighash type in the response MUST be the expected one. If any check fails, reject every signature in the response and fail the attempt.
5. Add to the host's PSBT only fields it builds from the verified `(r, s)` or `sig` and the expected sighash type.
6. For PSBT version 2, apply the BIP 370 flag updates to the host's own `PSBT_GLOBAL_TX_MODIFIABLE`, cumulatively for each signature and using its actual sighash type, with `SIGHASH_DEFAULT` counting as `SIGHASH_ALL`. An absent field has value zero. Preserve other flags, and create the field if an update needs to record a set flag.

### Handling a response

The host takes only the requested commitments or signatures from a response, and copies nothing else. It fails the attempt if:

- the core transaction differs from the request, whether read from the PSBT version 0 unsigned transaction or built from the version 2 fields
- a requested commitment or signature is missing
- a host commitment or nonce commitment for a pair differs from one the host holds for this attempt
- a second-pass response holds any anti-exfil field
- a first-pass response holds `PSBT_IN_AE_HOST_RANDOMNESS`, or either response holds an anti-exfil field for a pair that was not requested
- a signature field is added or changed relative to the request, other than a requested signature in a second-pass response, or is removed from an input that has no final scriptSig or final witness in the request. Signature fields are `PSBT_IN_PARTIAL_SIG`, `PSBT_IN_TAP_KEY_SIG` and `PSBT_IN_TAP_SCRIPT_SIG`

The host compares maps by key and does not depend on their order. It ignores other differences. PSBT libraries reserialize and add metadata, and these fields reach nobody because the host discards the response. Some libraries also drop signature fields from a finalized input when they serialize, as BIP 174 asks of a finalizer, which is why removal from such an input is allowed. A conforming signer never triggers the conditions above, so they do not fail an honest exchange.

### Signer

A signer SHOULD keep each key to one scheme, by failing on a pair whose derivation path purpose does not match the input's script type where it can tell. The security argument does not cover one key used under both schemes.

A PSBT with any of these fields in an input map is a request under this protocol. A signer handles exactly the pairs named by these fields and MUST NOT add a signature for any other pair. If it fails on any pair, it fails for the whole PSBT and returns nothing.

Before prompting or producing output, the signer validates the structure, every pair, key ownership, required transaction data, sighashes and script-path mappings. The failures inside step 4 of the protocol, such as `t >= n`, need the computation itself, so they may follow approval. It fails if a pair already has a signature, if it does not hold the key, if the script of a non-Taproot pair neither hashes nor pushes its key, if a key-path pair's identifier differs from a `PSBT_IN_TAP_INTERNAL_KEY` that is present, or if one input has both a key-path and a script-path pair. It looks up keys by identifier and does not depend on the order it holds them in. A request contains one phase; mixed phases fail.

- **Host commitment present, randomness absent (first pass):** run step 2 of the protocol, keep the commitment, and add `PSBT_IN_AE_NONCE_COMMITMENT`. If one is already present and differs from the computed value, fail. Add no signature. No approval is needed.
- **Randomness present (second pass):** if a host commitment or nonce commitment is present and differs from the computed value, fail. After one approval covering the whole PSBT, run step 4 for each pair and add each signature in its field. For version 2, apply the BIP 370 flag updates under the same rule as the host, cumulatively. Then remove every anti-exfil field from every input map and return the PSBT.
- **Only a nonce commitment:** fail.

A PSBT with none of these fields is outside this document. An implementation with no ordinary signing path fails or returns the PSBT unsigned, and a host treats either as a failed attempt.

**Approval and fees.** Approval covers what the signature commits to, including the spend path and leaf. A host or signer MUST NOT present a fee as verified unless it verified every input amount, either against `PSBT_IN_NON_WITNESS_UTXO`, or because the request has at least one Taproot pair without `ANYONECANPAY`, since that signature commits to every input amount and is invalid if any is wrong. Otherwise it MUST tell the user the fee is unverified, or fail.

### Other roles

In a conforming exchange these fields reach no other role. A role implementing this document that receives them SHOULD warn its user. A Finalizer implementing this document MUST remove them and MUST NOT add an annex to a Taproot spend signed under this protocol, because the signature hash was computed with no annex. This does not make such a PSBT safe, since `rho` has already been exposed.

### Transports

This document assumes a direct link that keeps the exchange from third parties. `PSBT_IN_AE_HOST_RANDOMNESS` holds `rho`. On QR and file transports it is visible to anything that can see the screen or keep the file, and together with a backdoored device that exposes the key. A QR or file profile needs its own specification.

## Rationale

**Why public fields.** Proprietary keys would leave hosts and devices to agree privately on the encoding, and BIP 174 reserves them for private use.

**Why a signer removes fields.** A Signer normally only adds data. Returning `rho` in a response would serve no purpose and would leave a copy of a value that has to stay secret in another buffer.

**Why the host rebuilds its result and ignores the rest.** Anything copied from a response is device-chosen data that could later be published. Rebuilding removes that channel, so an exact comparison of the response would add nothing to security. It would fail honest exchanges whenever a library reserializes a field or adds metadata, and each such failure would count against the device.

**Why one spend path per input.** Only one path can spend an input, so nothing is lost. This does not make related keys safe across inputs or requests; see the protocol's Security considerations.

**Why a required list of scripts.** Common spends then complete between any conforming host and signer. Other forms need the host to know its signer.

## Backward compatibility

A signer that does not know these fields ignores them as unknown fields and may sign in the ordinary way or not at all. The host sees no nonce commitment, fails the attempt, and does not use any signature. Other software never sees the fields, because the host does not release them.

The removal step departs from the BIP 174 Signer role, and applies only to these fields in this exchange.

## Reference implementation

`psbt/` holds a host and a signer in Python, for reading and test generation. They use variable-time arithmetic and MUST NOT be used with real keys.

## Test vectors

`vectors/bip-anti-exfil-psbt.json` gives, for each spend form and PSBT version, both requests, both responses and the host's result, plus each signer and host refusal and each difference a host must accept.

## Copyright

This document is licensed under the MIT license. Its test vectors are available under CC0-1.0 or MIT, at your option.
