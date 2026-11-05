#ifndef SECP256K1_ANTI_EXFIL_H
#define SECP256K1_ANTI_EXFIL_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This module implements the two-round anti-exfil signing protocol of
 *  spec/bip-anti-exfil.md, revision 0.16, for BIP340 and ECDSA.
 *
 *  A device commits to a base nonce point R0 after the host has committed to
 *  its randomness rho. The device later signs with a nonce that is R0 plus a
 *  tweak derived from R0 and rho, and the host checks that it did.
 *
 *  Rules of the module:
 *  - No nonce, tweak or opening crosses this API. Nothing takes a nonce
 *    callback, auxiliary randomness or an opening.
 *  - The sign functions take rho only. They recompute hc and the base nonce
 *    from it and keep no state, so there is no stored value to get wrong, and
 *    no way to hand them a stale R0.
 *  - A failure in signing ends the call. There is no retry and no counter.
 *  - r0_33 is the exact 33 bytes of the specification (prefix 0x02 or 0x03
 *    followed by the x coordinate), parsed with the specification's parse33
 *    rule.
 *  - rho is secret. The sign and host_verify functions need a context that
 *    has the signing precomputation, so that every point multiplication on a
 *    value derived from rho uses the constant-time generator path. Any
 *    context from secp256k1_context_create has it. The static context has
 *    not, and these functions reject it with an illegal-argument callback.
 *
 *  On failure an output is zeroed. A caller must not use it.
 *
 *  The caller keeps the protocol state: approval, attempt counting, failure
 *  records and erasing rho belong to the caller (see the specification).
 */

/** Host step 1 for BIP340: hc = tagged_hash("s2c/schnorr/data", rho).
 *
 *  Returns: 1 always, for valid arguments.
 *  Args:    ctx: a secp256k1 context object.
 *  Out:    hc32: pointer to a 32-byte array to store the commitment.
 *  In:    rho32: pointer to the 32 random bytes of the host.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_anti_exfil_schnorr_host_commit(
    const secp256k1_context *ctx,
    unsigned char *hc32,
    const unsigned char *rho32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Host step 1 for ECDSA: hc = tagged_hash("s2c/ecdsa/data", rho).
 *  Same arguments as the BIP340 function.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_anti_exfil_ecdsa_host_commit(
    const secp256k1_context *ctx,
    unsigned char *hc32,
    const unsigned char *rho32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Device step 2 for BIP340: computes R0_bytes = ser33(k0 * G).
 *
 *  Returns: 1: success.
 *           0: the keypair gives a zero k0 (then no commitment is made).
 *  Args:    ctx: a secp256k1 context object with signing precomputation.
 *  Out:   r0_33: pointer to a 33-byte array. Zeroed on failure.
 *  In:      msg: the message, of any length (can be NULL if msglen is 0).
 *        msglen: length of msg.
 *       keypair: the signing keypair.
 *          hc32: the host commitment.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_anti_exfil_schnorr_signer_commit(
    const secp256k1_context *ctx,
    unsigned char *r0_33,
    const unsigned char *msg,
    size_t msglen,
    const secp256k1_keypair *keypair,
    const unsigned char *hc32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Device step 4 for BIP340. Recomputes hc, d, pk, k0 and R0 from rho, then
 *  signs with k' = k0 + t. Checks the result with the host checks before
 *  returning it, which guards against faults.
 *
 *  Returns: 1: success.
 *           0: failure (k0 = 0, t >= n, k' = 0, or the self-check failed).
 *  Args:    ctx: a secp256k1 context object with signing precomputation.
 *  Out:   sig64: pointer to a 64-byte array. Zeroed on failure.
 *  In:      msg: the message, of any length (can be NULL if msglen is 0).
 *        msglen: length of msg.
 *       keypair: the signing keypair.
 *         rho32: the 32 bytes of the host.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_anti_exfil_schnorr_sign(
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const unsigned char *msg,
    size_t msglen,
    const secp256k1_keypair *keypair,
    const unsigned char *rho32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Host step 5 for BIP340, all five checks: R0 parses, t < n, W = R0 + t*G is
 *  not infinity, x(W) equals the first 32 bytes of sig64, and the signature
 *  verifies for the key and message.
 *
 *  Returns: 1: every check passed.
 *           0: otherwise.
 *  Args:    ctx: a secp256k1 context object with signing precomputation.
 *  In:    sig64: the signature.
 *           msg: the message (can be NULL if msglen is 0).
 *        msglen: length of msg.
 *     xonly_pk: the host's own x-only public key.
 *         rho32: the host's 32 bytes.
 *        r0_33: the R0_bytes the host stored in step 2.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_anti_exfil_schnorr_host_verify(
    const secp256k1_context *ctx,
    const unsigned char *sig64,
    const unsigned char *msg,
    size_t msglen,
    const secp256k1_xonly_pubkey *xonly_pk,
    const unsigned char *rho32,
    const unsigned char *r0_33
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7);

/** Device step 2 for ECDSA. msg32 is the 32-byte message, not reduced.
 *
 *  Returns: 1: success.
 *           0: invalid seckey, or k0 = 0 or k0 >= n (no retry).
 *  Out:   r0_33: pointer to a 33-byte array. Zeroed on failure.
 *  In:     msg32: the 32-byte message.
 *        seckey: the 32-byte secret key.
 *          hc32: the host commitment.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_anti_exfil_ecdsa_signer_commit(
    const secp256k1_context *ctx,
    unsigned char *r0_33,
    const unsigned char *msg32,
    const unsigned char *seckey,
    const unsigned char *hc32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Device step 4 for ECDSA. Recomputes hc, k0 and R0 from rho, signs with
 *  k' = k0 + t, normalizes to low s, and checks the result with the host
 *  checks before returning it.
 *
 *  Returns: 1: success.
 *           0: failure (invalid seckey, k0 invalid, t >= n, k' = 0, r = 0,
 *              s = 0, or the self-check failed).
 *  Out:     sig: pointer to a signature object. Zeroed on failure.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_anti_exfil_ecdsa_sign(
    const secp256k1_context *ctx,
    secp256k1_ecdsa_signature *sig,
    const unsigned char *msg32,
    const unsigned char *seckey,
    const unsigned char *rho32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Host step 5 for ECDSA, all five checks: R0 parses, t < n, W is not
 *  infinity, 0 < r, 0 < s <= (n-1)/2 and x(W) mod n = r, and V = u1*G + u2*P
 *  is not infinity, x(V) mod n = r and V = W or V = -W.
 *
 *  Returns: 1: every check passed.
 *           0: otherwise.
 *  In:       sig: the signature (as parsed by the caller).
 *          msg32: the 32-byte message.
 *         pubkey: the host's own public key.
 *          rho32: the host's 32 bytes.
 *          r0_33: the R0_bytes the host stored in step 2.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_anti_exfil_ecdsa_host_verify(
    const secp256k1_context *ctx,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkey,
    const unsigned char *rho32,
    const unsigned char *r0_33
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ANTI_EXFIL_H */
