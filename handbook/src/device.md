# Device rules

The rules for an honest device protect its key from a malicious host. The full rules are in the protocol BIP, under The message, steps 2 and 4, User approval and Key separation.

## The message

Compute `m` yourself from data the user approves, such as the transaction. Don't offer an entry point that signs a hash the host supplies, because the user can't read it. Refuse `SIGHASH_SINGLE` with no matching output.

## Step 2

- Derive `k0` exactly as the BIP specifies, from the key, `m` and `hc`. The derivation masks the key with a hash of `hc` and uses tags reserved for this protocol.
- Send `R0_bytes` with the real parity of `k0 * G`. Don't negate `k0` at this step.
- You don't need to keep any state, or ask for approval.

## Step 4

- Get the user's approval first. Approval has to cover everything the signature commits to, including a non-default sighash type and, for a Taproot script path, the leaf. Approval given around step 2 doesn't count for step 4.
- Recompute `hc` from `rho`, and `k0` and `R0_bytes` as in step 2. Never use a stored value, and never accept any of these from the host. A host that could supply them could get two signatures on one base nonce and solve for the key.
- Sign with `k0 + t`. For ECDSA, normalize to low `s`.
- It's recommended to run the host's checks on your own signature before sending it, to catch faults.

## Key separation

Don't expose these nonce functions through an ordinary signing interface, and don't use them for any signature outside this protocol. An ordinary signing interface under the same key mustn't let a host choose inputs that make it produce `k0`.

A device that keeps an older derivation, such as the one in secp256k1-zkp, must make sure no ordinary signing interface lets a host supply `hc` as extra nonce data under the same key, because equal inputs can produce an equal base nonce.

## Secrets

Don't log or disclose `t`, `k0`, `k'`, the masked key or intermediate hash states, and erase them after use. Process `rho` and values derived from it in constant time. A signing library can leave such values on the stack, so a device concerned about memory readout has to clear them.
