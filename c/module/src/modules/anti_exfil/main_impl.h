/***********************************************************************
 * Anti-exfil signing module, specification revision 0.16.             *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ANTI_EXFIL_MAIN_H
#define SECP256K1_MODULE_ANTI_EXFIL_MAIN_H

#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_schnorrsig.h"
#include "../../../include/secp256k1_anti_exfil.h"

#if !defined(ENABLE_MODULE_EXTRAKEYS) || !defined(ENABLE_MODULE_SCHNORRSIG)
# error The anti_exfil module needs the extrakeys and schnorrsig modules.
#endif

/* The two supported libraries differ in the name of the internal function that
 * multiplies the generator by a scalar in constant time. Every other internal
 * used here has the same name and signature in both. The build glue defines
 * SECP256K1_ANTI_EXFIL_ECMULT_GEN_PLAIN for the library that names it
 * secp256k1_ecmult_gen (the Jade secp256k1-zkp pin). */
#ifdef SECP256K1_ANTI_EXFIL_ECMULT_GEN_PLAIN
# define secp256k1_anti_exfil_mulgen(ecmult_gen_ctx, rj, k) secp256k1_ecmult_gen((ecmult_gen_ctx), (rj), (k))
#else
# define secp256k1_anti_exfil_mulgen(ecmult_gen_ctx, rj, k) secp256k1_ecmult_gen_gej((ecmult_gen_ctx), (rj), (k))
#endif

/* The tagged hashes of the specification. They are implemented here and share
 * nothing with the sign-to-contract code of either library. */
enum {
    SECP256K1_ANTI_EXFIL_TAG_BIP340_AUX,
    SECP256K1_ANTI_EXFIL_TAG_BIP340_CHALLENGE,
    SECP256K1_ANTI_EXFIL_TAG_SCHNORR_DATA,
    SECP256K1_ANTI_EXFIL_TAG_SCHNORR_NONCE,
    SECP256K1_ANTI_EXFIL_TAG_SCHNORR_POINT,
    SECP256K1_ANTI_EXFIL_TAG_ECDSA_DATA,
    SECP256K1_ANTI_EXFIL_TAG_ECDSA_AUX,
    SECP256K1_ANTI_EXFIL_TAG_ECDSA_NONCE,
    SECP256K1_ANTI_EXFIL_TAG_ECDSA_POINT,
    SECP256K1_ANTI_EXFIL_TAG_COUNT
};

static const char * const secp256k1_anti_exfil_tags[SECP256K1_ANTI_EXFIL_TAG_COUNT] = {
    "BIP0340/aux",
    "BIP0340/challenge",
    "s2c/schnorr/data",
    "s2c/schnorr/nonce",
    "s2c/schnorr/point",
    "s2c/ecdsa/data",
    "s2c/ecdsa/aux",
    "s2c/ecdsa/nonce",
    "s2c/ecdsa/point"
};

#ifdef SECP256K1_ANTI_EXFIL_TEST_SEAM
/* Test seam, compiled only when SECP256K1_ANTI_EXFIL_TEST_SEAM is defined. It
 * replaces the output of up to three tagged hashes, so that the cases that
 * real hashes cannot reach (k0 = 0, t >= n, W at infinity, ...) can be run.
 * A normal build has none of it. */
typedef struct {
    int tag;                /* -1: unused */
    int skip;               /* matching calls to leave alone first */
    int calls;              /* calls to replace after that, -1 for all */
    unsigned char out[32];
} secp256k1_anti_exfil_force_t;
static secp256k1_anti_exfil_force_t secp256k1_anti_exfil_force[3] = {{-1, 0, -1, {0}}, {-1, 0, -1, {0}}, {-1, 0, -1, {0}}};
#endif

static void secp256k1_anti_exfil_hash_init(const secp256k1_hash_ctx *hash_ctx, secp256k1_sha256 *sha, int tag) {
    const char *name = secp256k1_anti_exfil_tags[tag];
    secp256k1_sha256_initialize_tagged(hash_ctx, sha, (const unsigned char *)name, strlen(name));
}

/* Finalizes and clears the hash state, which may have absorbed secrets. */
static void secp256k1_anti_exfil_hash_final(const secp256k1_hash_ctx *hash_ctx, secp256k1_sha256 *sha, unsigned char *out32, int tag) {
    secp256k1_sha256_finalize(hash_ctx, sha, out32);
    secp256k1_sha256_clear(sha);
#ifdef SECP256K1_ANTI_EXFIL_TEST_SEAM
    {
        int i;
        for (i = 0; i < 3; i++) {
            secp256k1_anti_exfil_force_t *f = &secp256k1_anti_exfil_force[i];
            if (f->tag != tag) continue;
            if (f->skip > 0) {
                f->skip--;
            } else if (f->calls != 0) {
                memcpy(out32, f->out, 32);
                if (f->calls > 0) f->calls--;
            }
        }
    }
#else
    (void)tag;
#endif
}

/* hc = tagged_hash(tag, rho). */
static void secp256k1_anti_exfil_host_commit_internal(const secp256k1_hash_ctx *hash_ctx, unsigned char *hc32, const unsigned char *rho32, int tag) {
    secp256k1_sha256 sha;
    secp256k1_anti_exfil_hash_init(hash_ctx, &sha, tag);
    secp256k1_sha256_write(hash_ctx, &sha, rho32, 32);
    secp256k1_anti_exfil_hash_final(hash_ctx, &sha, hc32, tag);
}

/* t = int(tagged_hash(tag, R0_bytes || rho)), without reduction. Returns 0
 * if t >= n; t then holds the reduced value, which callers must not use. */
static int secp256k1_anti_exfil_tweak(const secp256k1_hash_ctx *hash_ctx, secp256k1_scalar *t, const unsigned char *r0_33, const unsigned char *rho32, int tag) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    int overflow = 0;
    secp256k1_anti_exfil_hash_init(hash_ctx, &sha, tag);
    secp256k1_sha256_write(hash_ctx, &sha, r0_33, 33);
    secp256k1_sha256_write(hash_ctx, &sha, rho32, 32);
    secp256k1_anti_exfil_hash_final(hash_ctx, &sha, buf, tag);
    secp256k1_scalar_set_b32(t, buf, &overflow);
    secp256k1_memclear_explicit(buf, sizeof(buf));
    return !overflow;
}

/* parse33 of the specification: 33 bytes, prefix 0x02 or 0x03, x below p and
 * the x coordinate of a curve point. The input is public. */
static int secp256k1_anti_exfil_parse33(secp256k1_ge *r, const unsigned char *in33) {
    secp256k1_fe x;
    if (in33[0] != 0x02 && in33[0] != 0x03) {
        return 0;
    }
    if (!secp256k1_fe_set_b32_limit(&x, &in33[1])) {
        return 0;
    }
    return secp256k1_ge_set_xo_var(r, &x, in33[0] == 0x03);
}

/* ser33 of the specification. The point must not be infinity. */
static void secp256k1_anti_exfil_ser33(unsigned char *out33, secp256k1_ge *ge) {
    secp256k1_fe_normalize(&ge->x);
    secp256k1_fe_normalize(&ge->y);
    out33[0] = (unsigned char)(0x02 | secp256k1_fe_is_odd(&ge->y));
    secp256k1_fe_get_b32(&out33[1], &ge->x);
}

/* out33 = ser33(k * G), for a scalar k that is not zero. */
static void secp256k1_anti_exfil_ser33_mulgen(const secp256k1_context *ctx, unsigned char *out33, const secp256k1_scalar *k) {
    secp256k1_gej rj;
    secp256k1_ge r;
    secp256k1_anti_exfil_mulgen(&ctx->ecmult_gen_ctx, &rj, k);
    secp256k1_ge_set_gej(&r, &rj);
    secp256k1_anti_exfil_ser33(out33, &r);
    secp256k1_gej_clear(&rj);
    secp256k1_ge_clear(&r);
}

/* BIP340 step 2 (also the first half of step 4). Loads the keypair and
 * derives d, pk, k0 and R0_bytes. The outputs d and k0 are secret, pk32 and
 * r0_33 are public. Returns 0 if the keypair is unusable or k0 = 0. On a
 * zero return the outputs are placeholders and the caller must not use them. */
static int secp256k1_anti_exfil_schnorr_base(const secp256k1_context *ctx, secp256k1_scalar *d, unsigned char *pk32, secp256k1_scalar *k0, unsigned char *r0_33, const unsigned char *msg, size_t msglen, const secp256k1_keypair *keypair, const unsigned char *hc32) {
    secp256k1_ge pk;
    secp256k1_sha256 sha;
    unsigned char t0[32];
    unsigned char mask[32];
    unsigned char buf[32];
    int i;
    int ret = 1;

    ret &= secp256k1_keypair_load(ctx, d, &pk, keypair);
    /* x-only key: d is negated if the point of the key has odd y. pk is
     * public, and the negation is not a branch. */
    secp256k1_scalar_cond_negate(d, secp256k1_fe_is_odd(&pk.y));
    secp256k1_fe_get_b32(pk32, &pk.x);

    /* t0 = bytes32(d) xor tagged_hash("BIP0340/aux", hc) */
    secp256k1_anti_exfil_hash_init(&ctx->hash_ctx, &sha, SECP256K1_ANTI_EXFIL_TAG_BIP340_AUX);
    secp256k1_sha256_write(&ctx->hash_ctx, &sha, hc32, 32);
    secp256k1_anti_exfil_hash_final(&ctx->hash_ctx, &sha, mask, SECP256K1_ANTI_EXFIL_TAG_BIP340_AUX);
    secp256k1_scalar_get_b32(t0, d);
    for (i = 0; i < 32; i++) {
        t0[i] ^= mask[i];
    }

    /* k0 = int(tagged_hash("s2c/schnorr/nonce", t0 || pk || m || hc)) mod n */
    secp256k1_anti_exfil_hash_init(&ctx->hash_ctx, &sha, SECP256K1_ANTI_EXFIL_TAG_SCHNORR_NONCE);
    secp256k1_sha256_write(&ctx->hash_ctx, &sha, t0, 32);
    secp256k1_sha256_write(&ctx->hash_ctx, &sha, pk32, 32);
    secp256k1_sha256_write(&ctx->hash_ctx, &sha, msg, msglen);
    secp256k1_sha256_write(&ctx->hash_ctx, &sha, hc32, 32);
    secp256k1_anti_exfil_hash_final(&ctx->hash_ctx, &sha, buf, SECP256K1_ANTI_EXFIL_TAG_SCHNORR_NONCE);
    secp256k1_scalar_set_b32(k0, buf, NULL);
    ret &= !secp256k1_scalar_is_zero(k0);
    /* Avoid the point at infinity if k0 is unusable. */
    secp256k1_scalar_cmov(k0, &secp256k1_scalar_one, !ret);

    /* R0_bytes records the actual parity of k0 * G. */
    secp256k1_anti_exfil_ser33_mulgen(ctx, r0_33, k0);

    secp256k1_ge_clear(&pk);
    secp256k1_memclear_explicit(t0, sizeof(t0));
    secp256k1_memclear_explicit(mask, sizeof(mask));
    secp256k1_memclear_explicit(buf, sizeof(buf));
    return ret;
}

/* BIP340 step 5. Every input is public except rho, which is used only for
 * hashing and for the constant-time generator multiplication. */
static int secp256k1_anti_exfil_schnorr_host_verify_internal(const secp256k1_context *ctx, const unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_xonly_pubkey *xonly_pk, const unsigned char *rho32, const unsigned char *r0_33) {
    secp256k1_ge r0;
    secp256k1_ge w;
    secp256k1_gej tj;
    secp256k1_gej wj;
    secp256k1_scalar t;
    secp256k1_fe rx;
    int ret;

    /* 1. R0 = parse33(R0_bytes). */
    if (!secp256k1_anti_exfil_parse33(&r0, r0_33)) {
        return 0;
    }
    /* 2. t < n. */
    ret = secp256k1_anti_exfil_tweak(&ctx->hash_ctx, &t, r0_33, rho32, SECP256K1_ANTI_EXFIL_TAG_SCHNORR_POINT);
    /* 3. W = R0 + t * G is not infinity. The multiplication of t is constant
     * time, and the addition has no case split on t, including t = 0. */
    secp256k1_anti_exfil_mulgen(&ctx->ecmult_gen_ctx, &tj, &t);
    secp256k1_gej_add_ge(&wj, &tj, &r0);
    ret &= !secp256k1_gej_is_infinity(&wj);
    secp256k1_ge_set_gej(&w, &wj);
    /* 4. x(W) equals the first 32 bytes of sig, by the constant-time field
     * comparison. sig64 is public, but W is derived from rho. */
    if (secp256k1_fe_set_b32_limit(&rx, sig64)) {
        ret &= secp256k1_fe_equal(&rx, &w.x);
    } else {
        ret = 0;
    }
    /* 5. BIP340 verification. All inputs are public. */
    ret &= secp256k1_schnorrsig_verify(ctx, sig64, msg, msglen, xonly_pk);

    secp256k1_scalar_clear(&t);
    secp256k1_gej_clear(&tj);
    secp256k1_gej_clear(&wj);
    secp256k1_ge_clear(&w);
    secp256k1_ge_clear(&r0);
    secp256k1_fe_clear(&rx);
    return ret;
}

/* ECDSA step 2 (also the first half of step 4). Derives d, pk, k0 and
 * R0_bytes. d and k0 are secret; the point p, pk33 and r0_33 are public. Returns
 * 0 on an invalid key, k0 = 0 or k0 >= n. */
static int secp256k1_anti_exfil_ecdsa_base(const secp256k1_context *ctx, secp256k1_scalar *d, secp256k1_ge *p, unsigned char *pk33, secp256k1_scalar *k0, unsigned char *r0_33, const unsigned char *msg32, const unsigned char *seckey, const unsigned char *hc32) {
    secp256k1_gej pj;
    secp256k1_sha256 sha;
    unsigned char dmask[32];
    unsigned char mask[32];
    unsigned char buf[32];
    int overflow = 0;
    int i;
    int ret;

    ret = secp256k1_scalar_set_b32_seckey(d, seckey);
    secp256k1_scalar_cmov(d, &secp256k1_scalar_one, !ret);

    secp256k1_anti_exfil_mulgen(&ctx->ecmult_gen_ctx, &pj, d);
    secp256k1_ge_set_gej(p, &pj);
    secp256k1_anti_exfil_ser33(pk33, p);
    /* The public key is public. */
    secp256k1_declassify(ctx, p, sizeof(*p));
    secp256k1_declassify(ctx, pk33, 33);

    /* d_mask = bytes32(d) xor tagged_hash("s2c/ecdsa/aux", hc) */
    secp256k1_anti_exfil_hash_init(&ctx->hash_ctx, &sha, SECP256K1_ANTI_EXFIL_TAG_ECDSA_AUX);
    secp256k1_sha256_write(&ctx->hash_ctx, &sha, hc32, 32);
    secp256k1_anti_exfil_hash_final(&ctx->hash_ctx, &sha, mask, SECP256K1_ANTI_EXFIL_TAG_ECDSA_AUX);
    secp256k1_scalar_get_b32(dmask, d);
    for (i = 0; i < 32; i++) {
        dmask[i] ^= mask[i];
    }

    /* k0 = int(tagged_hash("s2c/ecdsa/nonce", d_mask || pk || m || hc)), 129
     * bytes, not reduced. k0 = 0 and k0 >= n fail, and nothing retries. */
    secp256k1_anti_exfil_hash_init(&ctx->hash_ctx, &sha, SECP256K1_ANTI_EXFIL_TAG_ECDSA_NONCE);
    secp256k1_sha256_write(&ctx->hash_ctx, &sha, dmask, 32);
    secp256k1_sha256_write(&ctx->hash_ctx, &sha, pk33, 33);
    secp256k1_sha256_write(&ctx->hash_ctx, &sha, msg32, 32);
    secp256k1_sha256_write(&ctx->hash_ctx, &sha, hc32, 32);
    secp256k1_anti_exfil_hash_final(&ctx->hash_ctx, &sha, buf, SECP256K1_ANTI_EXFIL_TAG_ECDSA_NONCE);
    secp256k1_scalar_set_b32(k0, buf, &overflow);
    ret &= !overflow;
    ret &= !secp256k1_scalar_is_zero(k0);
    secp256k1_scalar_cmov(k0, &secp256k1_scalar_one, !ret);

    secp256k1_anti_exfil_ser33_mulgen(ctx, r0_33, k0);

    secp256k1_gej_clear(&pj);
    secp256k1_memclear_explicit(dmask, sizeof(dmask));
    secp256k1_memclear_explicit(mask, sizeof(mask));
    secp256k1_memclear_explicit(buf, sizeof(buf));
    return ret;
}

/* ECDSA step 5. The signature scalars, message and public key are public. */
static int secp256k1_anti_exfil_ecdsa_host_verify_internal(const secp256k1_context *ctx, const secp256k1_scalar *r, const secp256k1_scalar *s, const unsigned char *msg32, const secp256k1_ge *p, const unsigned char *rho32, const unsigned char *r0_33) {
    secp256k1_ge r0;
    secp256k1_ge w;
    secp256k1_ge v;
    secp256k1_gej tj;
    secp256k1_gej wj;
    secp256k1_gej pj;
    secp256k1_gej vj;
    secp256k1_scalar t;
    secp256k1_scalar z;
    secp256k1_scalar sinv;
    secp256k1_scalar u1;
    secp256k1_scalar u2;
    secp256k1_scalar xw;
    secp256k1_scalar xv;
    unsigned char xbuf[32];
    int ret;

    /* 1. R0 = parse33(R0_bytes). */
    if (!secp256k1_anti_exfil_parse33(&r0, r0_33)) {
        return 0;
    }
    /* 2. t < n. */
    ret = secp256k1_anti_exfil_tweak(&ctx->hash_ctx, &t, r0_33, rho32, SECP256K1_ANTI_EXFIL_TAG_ECDSA_POINT);
    /* 3. W = R0 + t * G is not infinity. */
    secp256k1_anti_exfil_mulgen(&ctx->ecmult_gen_ctx, &tj, &t);
    secp256k1_gej_add_ge(&wj, &tj, &r0);
    ret &= !secp256k1_gej_is_infinity(&wj);
    secp256k1_ge_set_gej(&w, &wj);
    /* 4. 0 < r < n, 0 < s <= (n - 1) / 2 and x(W) mod n = r. */
    ret &= !secp256k1_scalar_is_zero(r);
    ret &= !secp256k1_scalar_is_zero(s);
    ret &= !secp256k1_scalar_is_high(s);
    secp256k1_fe_normalize(&w.x);
    secp256k1_fe_get_b32(xbuf, &w.x);
    secp256k1_scalar_set_b32(&xw, xbuf, NULL);
    ret &= secp256k1_scalar_eq(&xw, r);
    /* 5. V = u1 * G + u2 * P is not infinity, x(V) mod n = r, and V = W or
     * V = -W, that is x(V) = x(W) as field elements. */
    secp256k1_scalar_set_b32(&z, msg32, NULL);
    secp256k1_scalar_inverse(&sinv, s);
    secp256k1_scalar_mul(&u1, &z, &sinv);
    secp256k1_scalar_mul(&u2, r, &sinv);
    secp256k1_gej_set_ge(&pj, p);
    secp256k1_ecmult(&vj, &pj, &u2, &u1);
    ret &= !secp256k1_gej_is_infinity(&vj);
    secp256k1_ge_set_gej(&v, &vj);
    secp256k1_fe_normalize(&v.x);
    secp256k1_fe_get_b32(xbuf, &v.x);
    secp256k1_scalar_set_b32(&xv, xbuf, NULL);
    ret &= secp256k1_scalar_eq(&xv, r);
    ret &= secp256k1_fe_equal(&v.x, &w.x);

    secp256k1_scalar_clear(&t);
    secp256k1_gej_clear(&tj);
    secp256k1_gej_clear(&wj);
    secp256k1_ge_clear(&w);
    secp256k1_ge_clear(&r0);
    secp256k1_scalar_clear(&xw);
    secp256k1_memclear_explicit(xbuf, sizeof(xbuf));
    return ret;
}

int secp256k1_anti_exfil_schnorr_host_commit(const secp256k1_context *ctx, unsigned char *hc32, const unsigned char *rho32) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(hc32 != NULL);
    ARG_CHECK(rho32 != NULL);
    secp256k1_anti_exfil_host_commit_internal(&ctx->hash_ctx, hc32, rho32, SECP256K1_ANTI_EXFIL_TAG_SCHNORR_DATA);
    return 1;
}

int secp256k1_anti_exfil_ecdsa_host_commit(const secp256k1_context *ctx, unsigned char *hc32, const unsigned char *rho32) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(hc32 != NULL);
    ARG_CHECK(rho32 != NULL);
    secp256k1_anti_exfil_host_commit_internal(&ctx->hash_ctx, hc32, rho32, SECP256K1_ANTI_EXFIL_TAG_ECDSA_DATA);
    return 1;
}

int secp256k1_anti_exfil_schnorr_signer_commit(const secp256k1_context *ctx, unsigned char *r0_33, const unsigned char *msg, size_t msglen, const secp256k1_keypair *keypair, const unsigned char *hc32) {
    secp256k1_scalar d;
    secp256k1_scalar k0;
    unsigned char pk32[32];
    int ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(r0_33 != NULL);
    ARG_CHECK(msg != NULL || msglen == 0);
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(hc32 != NULL);

    ret = secp256k1_anti_exfil_schnorr_base(ctx, &d, pk32, &k0, r0_33, msg, msglen, keypair, hc32);
    secp256k1_memczero(r0_33, 33, !ret);

    secp256k1_scalar_clear(&d);
    secp256k1_scalar_clear(&k0);
    secp256k1_memclear_explicit(pk32, sizeof(pk32));
    return ret;
}

int secp256k1_anti_exfil_schnorr_sign(const secp256k1_context *ctx, unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_keypair *keypair, const unsigned char *rho32) {
    secp256k1_scalar d;
    secp256k1_scalar k0;
    secp256k1_scalar t;
    secp256k1_scalar k;
    secp256k1_scalar e;
    secp256k1_gej wj;
    secp256k1_ge w;
    secp256k1_xonly_pubkey xonly_pk;
    secp256k1_sha256 sha;
    unsigned char hc[32];
    unsigned char pk32[32];
    unsigned char r0[33];
    unsigned char buf[32];
    int ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg != NULL || msglen == 0);
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(rho32 != NULL);

    /* Recompute hc, d, pk, k0 and R0_bytes from rho. Nothing is stored or
     * accepted from the caller. */
    secp256k1_anti_exfil_host_commit_internal(&ctx->hash_ctx, hc, rho32, SECP256K1_ANTI_EXFIL_TAG_SCHNORR_DATA);
    ret = secp256k1_anti_exfil_schnorr_base(ctx, &d, pk32, &k0, r0, msg, msglen, keypair, hc);
    /* R0 is a public output of step 2. */
    secp256k1_declassify(ctx, r0, sizeof(r0));

    /* t = int(tagged_hash("s2c/schnorr/point", R0_bytes || rho)), fail if t >= n */
    ret &= secp256k1_anti_exfil_tweak(&ctx->hash_ctx, &t, r0, rho32, SECP256K1_ANTI_EXFIL_TAG_SCHNORR_POINT);
    /* k' = (k0 + t) mod n, fail if k' = 0 */
    secp256k1_scalar_add(&k, &k0, &t);
    ret &= !secp256k1_scalar_is_zero(&k);
    secp256k1_scalar_cmov(&k, &secp256k1_scalar_one, !ret);

    /* W = k' * G; k = k' if y(W) is even, otherwise n - k' */
    secp256k1_anti_exfil_mulgen(&ctx->ecmult_gen_ctx, &wj, &k);
    secp256k1_ge_set_gej(&w, &wj);
    secp256k1_fe_normalize(&w.x);
    secp256k1_fe_normalize(&w.y);
    secp256k1_scalar_cond_negate(&k, secp256k1_fe_is_odd(&w.y));
    secp256k1_fe_get_b32(&sig64[0], &w.x);

    /* e = int(tagged_hash("BIP0340/challenge", r || pk || m)) mod n */
    secp256k1_anti_exfil_hash_init(&ctx->hash_ctx, &sha, SECP256K1_ANTI_EXFIL_TAG_BIP340_CHALLENGE);
    secp256k1_sha256_write(&ctx->hash_ctx, &sha, &sig64[0], 32);
    secp256k1_sha256_write(&ctx->hash_ctx, &sha, pk32, 32);
    secp256k1_sha256_write(&ctx->hash_ctx, &sha, msg, msglen);
    secp256k1_anti_exfil_hash_final(&ctx->hash_ctx, &sha, buf, SECP256K1_ANTI_EXFIL_TAG_BIP340_CHALLENGE);
    secp256k1_scalar_set_b32(&e, buf, NULL);
    /* sig = r || bytes32((k + e * d) mod n) */
    secp256k1_scalar_mul(&e, &e, &d);
    secp256k1_scalar_add(&e, &e, &k);
    secp256k1_scalar_get_b32(&sig64[32], &e);

    /* The signature is a public output; the host checks below may branch on it. */
    secp256k1_declassify(ctx, sig64, 64);
    /* The host checks, to catch faults. */
    ret &= secp256k1_keypair_xonly_pub(ctx, &xonly_pk, NULL, keypair);
    ret &= secp256k1_anti_exfil_schnorr_host_verify_internal(ctx, sig64, msg, msglen, &xonly_pk, rho32, r0);

    secp256k1_memczero(sig64, 64, !ret);
    secp256k1_scalar_clear(&d);
    secp256k1_scalar_clear(&k0);
    secp256k1_scalar_clear(&t);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&e);
    secp256k1_gej_clear(&wj);
    secp256k1_ge_clear(&w);
    secp256k1_memclear_explicit(hc, sizeof(hc));
    secp256k1_memclear_explicit(pk32, sizeof(pk32));
    secp256k1_memclear_explicit(r0, sizeof(r0));
    secp256k1_memclear_explicit(buf, sizeof(buf));
    return ret;
}

int secp256k1_anti_exfil_schnorr_host_verify(const secp256k1_context *ctx, const unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_xonly_pubkey *xonly_pk, const unsigned char *rho32, const unsigned char *r0_33) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg != NULL || msglen == 0);
    ARG_CHECK(xonly_pk != NULL);
    ARG_CHECK(rho32 != NULL);
    ARG_CHECK(r0_33 != NULL);
    return secp256k1_anti_exfil_schnorr_host_verify_internal(ctx, sig64, msg, msglen, xonly_pk, rho32, r0_33);
}

int secp256k1_anti_exfil_ecdsa_signer_commit(const secp256k1_context *ctx, unsigned char *r0_33, const unsigned char *msg32, const unsigned char *seckey, const unsigned char *hc32) {
    secp256k1_scalar d;
    secp256k1_scalar k0;
    secp256k1_ge p;
    unsigned char pk33[33];
    int ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(r0_33 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(hc32 != NULL);

    ret = secp256k1_anti_exfil_ecdsa_base(ctx, &d, &p, pk33, &k0, r0_33, msg32, seckey, hc32);
    secp256k1_memczero(r0_33, 33, !ret);

    secp256k1_scalar_clear(&d);
    secp256k1_scalar_clear(&k0);
    secp256k1_ge_clear(&p);
    secp256k1_memclear_explicit(pk33, sizeof(pk33));
    return ret;
}

int secp256k1_anti_exfil_ecdsa_sign(const secp256k1_context *ctx, secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const unsigned char *seckey, const unsigned char *rho32) {
    secp256k1_scalar d;
    secp256k1_scalar k0;
    secp256k1_scalar t;
    secp256k1_scalar k;
    secp256k1_scalar z;
    secp256k1_scalar r;
    secp256k1_scalar s;
    secp256k1_ge p;
    unsigned char hc[32];
    unsigned char pk33[33];
    unsigned char r0[33];
    int ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(rho32 != NULL);

    secp256k1_anti_exfil_host_commit_internal(&ctx->hash_ctx, hc, rho32, SECP256K1_ANTI_EXFIL_TAG_ECDSA_DATA);
    ret = secp256k1_anti_exfil_ecdsa_base(ctx, &d, &p, pk33, &k0, r0, msg32, seckey, hc);
    /* R0 is a public output of step 2. */
    secp256k1_declassify(ctx, r0, sizeof(r0));

    /* t = int(tagged_hash("s2c/ecdsa/point", R0_bytes || rho)), fail if t >= n */
    ret &= secp256k1_anti_exfil_tweak(&ctx->hash_ctx, &t, r0, rho32, SECP256K1_ANTI_EXFIL_TAG_ECDSA_POINT);
    /* k' = (k0 + t) mod n, fail if k' = 0 */
    secp256k1_scalar_add(&k, &k0, &t);
    ret &= !secp256k1_scalar_is_zero(&k);
    secp256k1_scalar_cmov(&k, &secp256k1_scalar_one, !ret);

    /* r = x(W) mod n, s = k'^-1 * (z + r * d) mod n, fail if r = 0 or s = 0,
     * and s is replaced by n - s if it is above (n - 1) / 2. */
    secp256k1_scalar_set_b32(&z, msg32, NULL);
    ret &= secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, &r, &s, &d, &z, &k, NULL);

    /* The signature is a public output; the host checks below may branch on it. */
    secp256k1_declassify(ctx, &r, sizeof(r));
    secp256k1_declassify(ctx, &s, sizeof(s));
    /* The host checks, to catch faults. */
    ret &= secp256k1_anti_exfil_ecdsa_host_verify_internal(ctx, &r, &s, msg32, &p, rho32, r0);

    secp256k1_scalar_cmov(&r, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_cmov(&s, &secp256k1_scalar_zero, !ret);
    secp256k1_ecdsa_signature_save(sig, &r, &s);

    secp256k1_scalar_clear(&d);
    secp256k1_scalar_clear(&k0);
    secp256k1_scalar_clear(&t);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&z);
    secp256k1_scalar_clear(&r);
    secp256k1_scalar_clear(&s);
    secp256k1_ge_clear(&p);
    secp256k1_memclear_explicit(hc, sizeof(hc));
    secp256k1_memclear_explicit(pk33, sizeof(pk33));
    secp256k1_memclear_explicit(r0, sizeof(r0));
    return ret;
}

int secp256k1_anti_exfil_ecdsa_host_verify(const secp256k1_context *ctx, const secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pubkey, const unsigned char *rho32, const unsigned char *r0_33) {
    secp256k1_scalar r;
    secp256k1_scalar s;
    secp256k1_ge p;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(rho32 != NULL);
    ARG_CHECK(r0_33 != NULL);

    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    if (!secp256k1_pubkey_load(ctx, &p, pubkey)) {
        return 0;
    }
    return secp256k1_anti_exfil_ecdsa_host_verify_internal(ctx, &r, &s, msg32, &p, rho32, r0_33);
}

#endif /* SECP256K1_MODULE_ANTI_EXFIL_MAIN_H */
