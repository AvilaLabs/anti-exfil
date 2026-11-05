# Design

The module is additive: it does not patch the signing code inside the two libraries, and it does not expose versioned entry points beside the existing ones.

## One additive module

`include/secp256k1_anti_exfil.h` and `src/modules/anti_exfil/`, built with the same source on two bases: benma/secp256k1 at the pin in `secp1140/run.sh`, and the secp256k1-zkp vendored by Jade at its pin.

Reasons:
- **No existing signing path changes.** A patch of the Schnorr code would rewrite `secp256k1_schnorrsig_sign_internal`. An additive module leaves `schnorrsig_sign` and `ecdsa_sign` byte for byte alone, so a reviewer can see that ordinary signing can't have regressed.
- **One source for Jade and upstream.** Jade's library has no Schnorr sign-to-contract, and PR 1140 has no ECDSA form. The module needs only internals both have.
- **Smaller review.** One new directory, and build glue of a few lines.

The cost is a little duplicated signing arithmetic, about 40 lines per scheme. Vectors, and comparison with the Python reference on random valid inputs, guard against drift.

## API

Every function returns int with `SECP256K1_WARN_UNUSED_RESULT` and `SECP256K1_ARG_NONNULL` where upstream uses them. On failure, outputs are zeroed or unspecified as upstream's convention requires, and the caller must not use them.

    secp256k1_anti_exfil_schnorr_host_commit(ctx, hc32, rho32)
    secp256k1_anti_exfil_ecdsa_host_commit(ctx, hc32, rho32)

    secp256k1_anti_exfil_schnorr_signer_commit(ctx, r0_33, msg, msglen, keypair, hc32)
    secp256k1_anti_exfil_schnorr_sign(ctx, sig64, msg, msglen, keypair, rho32)
    secp256k1_anti_exfil_schnorr_host_verify(ctx, sig64, msg, msglen, xonly_pk, rho32, r0_33)

    secp256k1_anti_exfil_ecdsa_signer_commit(ctx, r0_33, msg32, seckey, hc32)
    secp256k1_anti_exfil_ecdsa_sign(ctx, sig, msg32, seckey, rho32)
    secp256k1_anti_exfil_ecdsa_host_verify(ctx, sig, msg32, pubkey, rho32, r0_33)

Rules these encode:
- **No nonce crosses the API.** Nothing exports or accepts `k0`, `t` or `k'`. No function takes a nonce callback, auxiliary randomness or an opening.
- **`sign` takes `rho` only.** It computes `hc` from `rho` and `k0` from that, so a stateless device has nothing stored to get wrong. It takes no `R0`, so it cannot be given a stale one.
- **No retry.** Failure in signing ends the call. There is no attempt counter.
- **`host_verify` does the whole of step 5**, including ordinary verification and for ECDSA the low-s and `V = ±W` checks. A host can't accidentally do half of it.
- **`r0_33` is exact bytes** in the host-facing API, since the proof and tags bind the serialized form. It is parsed with the spec's `parse33` rule.

The `ctx` must have signing precomputation for `host_verify`, because `rho` is secret and `tG` must use the constant-time path. `host_verify` compares `W` with the constant-time field comparison.

**Alignment with existing interfaces.** The module keeps its interface as close as it can to the libsecp interfaces that other signers already use, so that the underlying interface stays common and well exercised. The module keeps the same four-step shape as PR 1140 and secp256k1-zkp: host commit, signer commit, sign, host verify. Argument order follows theirs where the design allows. `c/API_MAPPING.md` maps each function to its counterparts and states each difference with its reason. Names stay distinct on purpose: the nonce derivation differs from both, so a shared name would let a caller get different bytes without noticing.

Rejected, with reason: sharing a struct for "commit state" (more to misuse, and it invites storing `k0`).

## Secrets

Cleared on every exit path using the library's explicit clear: normalized key, mask, `k0`, `t`, `k'`, hash state fed with secrets, group elements derived from `rho`. This is the point of `validation/c_module`, and its fragment scan is rerun on the module.

## Style

C89, `-Wall -Wextra -pedantic` clean. No heap, no global state, no variable-length arrays. `VERIFY_CHECK` and `ARG_CHECK` as upstream uses them. Bounded stack.

## Not in this module

Parsing PSBTs, approval, attempt counting, failure records: these belong to the caller. That split is what keeps the secret-handling part small enough to check thoroughly.
