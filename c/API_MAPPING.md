# API mapping: the module against PR 1140 and secp256k1-zkp

Checked against the headers of the two pinned bases:
`include/secp256k1_schnorrsig.h` of benma/secp256k1 at `b4d2b22e` (PR 1140 branch, "benma" below) and
`include/secp256k1_ecdsa_s2c.h` of secp256k1-zkp at `45f6f0f1` (the Jade pin, "zkp" below). The zkp pin has no Schnorr
anti-exfil functions, and benma has no ECDSA ones, so each module function has one counterpart in one base, and the
other column says so.

Argument order follows the counterparts everywhere. Where the module has no counterpart argument, that argument is
absent and the others keep their relative order. No argument is reordered.
Types: `ctx` first and `const` as in the counterparts, outputs before inputs.

Common to every row, and the reason for it: the nonce derivation differs from both (spec "Why a derivation of its own"),
so the names stay distinct. There is no `opening` and no `nonce_is_negated` flag: R0 is exchanged as the exact 33 bytes
`ser33(k0 * G)` with its real parity, which the spec binds in the tags, and the host compares x(W) only.

| Module function | PR 1140 (benma) | secp256k1-zkp | Differences and reason |
|---|---|---|---|
| `secp256k1_anti_exfil_schnorr_host_commit(ctx, hc32, rho32)` | `secp256k1_schnorrsig_anti_exfil_host_commit(ctx, rand_commitment32, rand32)` | none | Same arguments and same hash (`s2c/schnorr/data`). Only the name and the parameter names differ; `hc` and `rho` are the spec's names. Adds `SECP256K1_WARN_UNUSED_RESULT`, which the counterpart lacks. |
| `secp256k1_anti_exfil_ecdsa_host_commit(ctx, hc32, rho32)` | none | `secp256k1_ecdsa_anti_exfil_host_commit(ctx, rand_commitment32, rand32)` | Same arguments and same hash (`s2c/ecdsa/data`). The design listed one `host_commit`; the two schemes hash under different tags, so the module has one per scheme (decision, see the report). |
| `secp256k1_anti_exfil_schnorr_signer_commit(ctx, r0_33, msg, msglen, keypair, hc32)` | `secp256k1_schnorrsig_anti_exfil_signer_commit(ctx, signer_commitment, msg, msglen, keypair, rand_commitment32)` | none | Same order. The output is 33 bytes instead of a `secp256k1_pubkey` (`signer_commitment`), because the bytes are what the spec binds, and the host then needs no serialization step. The nonce is derived by the spec's `s2c/schnorr/nonce` with the aux mask, not by `BIP0340/nonce`. |
| `secp256k1_anti_exfil_ecdsa_signer_commit(ctx, r0_33, msg32, seckey, hc32)` | none | `secp256k1_ecdsa_anti_exfil_signer_commit(ctx, s2c_opening, msg32, seckey32, rand_commitment32)` | Same order. Output is the 33 bytes of R0, not a `secp256k1_ecdsa_s2c_opening` (which holds R0 as a pubkey). Nonce is the spec's 129-byte `s2c/ecdsa/nonce` hash with range failure, not RFC 6979. |
| `secp256k1_anti_exfil_schnorr_sign(ctx, sig64, msg, msglen, keypair, rho32)` | `secp256k1_schnorrsig_sign_custom(ctx, sig64, msg, msglen, keypair, extraparams)` with `extraparams.s2c_opening` and `extraparams.s2c_data32` | none | Same leading arguments as `sign_custom`. `rho32` replaces the `extraparams` struct: no nonce callback, no auxiliary data and no opening can be passed (design rule). The module recomputes `hc`, `d`, `pk`, `k0` and R0 from `rho32`, takes no R0, and checks its own signature before returning. |
| `secp256k1_anti_exfil_ecdsa_sign(ctx, sig, msg32, seckey, rho32)` | none | `secp256k1_anti_exfil_sign(ctx, sig, msg32, seckey, host_data32)` | Same order and types. Differences: no nonce function can be used (zkp's runs RFC 6979 with `host_data32` mixed in); the module's own self-check is part of the call; there is no retry counter, so failures end the call. |
| `secp256k1_anti_exfil_schnorr_host_verify(ctx, sig64, msg, msglen, xonly_pk, rho32, r0_33)` | `secp256k1_schnorrsig_anti_exfil_host_verify(ctx, sig64, msg, msglen, pubkey, host_data32, signer_commitment, opening)` | none | Same order up to `host_data32`. The last two arguments (`signer_commitment`, `opening`) become one: the stored R0 bytes. The counterpart accepts an opening supplied by the device (with a negation flag); the module takes nothing from the device except `sig64`. Requires a context with signing precomputation because `t * G` uses the constant-time generator path. |
| `secp256k1_anti_exfil_ecdsa_host_verify(ctx, sig, msg32, pubkey, rho32, r0_33)` | none | `secp256k1_anti_exfil_host_verify(ctx, sig, msg32, pubkey, host_data32, opening)` | Same order and types, with the opening replaced by R0 bytes. Also checks low s, `x(W) mod n = r` and `V = ±W`, which the counterpart does not (it checks the opening's commitment and ordinary verification). Needs signing precomputation, as above. |

Naming: the module's names do not repeat the counterparts' because the bytes differ; a caller who switches libraries by
changing a name sees a compile error instead of different signatures. Parameter names follow the spec (`rho`, `hc`,
`r0`) in the module, and the counterparts' (`rand32`, `rand_commitment32`, `host_data32`) are listed above.

Verified by reading the two headers, not by compiling a call against both. The tests in `tests_impl.h` call every module
function; they do not call the counterparts.
