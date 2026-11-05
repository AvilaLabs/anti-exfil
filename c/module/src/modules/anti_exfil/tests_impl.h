/***********************************************************************
 * Anti-exfil module tests, specification revision 0.16.               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ANTI_EXFIL_TESTS_H
#define SECP256K1_MODULE_ANTI_EXFIL_TESTS_H

#include "../../../include/secp256k1_anti_exfil.h"
#include "../../unit_test.h"
#include "tests_vectors.h"

#define AE_MAXMSG 1100

static size_t ae_unhex(unsigned char *out, const char *hex) {
    size_t n = strlen(hex) / 2, i;
    for (i = 0; i < n; i++) {
        unsigned int v = 0;
        char pair[3];
        pair[0] = hex[2 * i];
        pair[1] = hex[2 * i + 1];
        pair[2] = 0;
        CHECK(sscanf(pair, "%2x", &v) == 1);
        out[i] = (unsigned char)v;
    }
    return n;
}

static void ae_tag_hash_plain(unsigned char *out, const unsigned char *in, size_t inlen) {
    secp256k1_sha256 sha;
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&CTX->hash_ctx, &sha, in, inlen);
    secp256k1_sha256_finalize(&CTX->hash_ctx, &sha, out);
}

/* The message of a valid vector; "@long" is SHA256(seed/m/j) for j = 0..31, joined. */
static size_t ae_vec_msg(unsigned char *m, const anti_exfil_test_valid *v) {
    int j;
    if (strcmp(v->m, "@long") != 0) return ae_unhex(m, v->m);
    for (j = 0; j < 32; j++) {
        char text[256];
        sprintf(text, "%s/m/%d", v->seed, j);
        ae_tag_hash_plain(m + 32 * j, (const unsigned char *)text, strlen(text));
    }
    return 1024;
}

static void ae_random_seckey(unsigned char *sk) {
    do {
        testrand256(sk);
    } while (!secp256k1_ec_seckey_verify(CTX, sk));
}

static const size_t ae_msglens[] = {0, 1, 31, 32, 33, 63, 64, 65, 119, 120, 128, 1000};

static void ae_tag_hash(unsigned char *out, const char *tag, const unsigned char *in, size_t inlen) {
    CHECK(secp256k1_tagged_sha256(CTX, out, (const unsigned char *)tag, strlen(tag), in, inlen));
}

static void ae_pubkey33(unsigned char *out33, const unsigned char *scalar32) {
    secp256k1_pubkey pub;
    size_t len = 33;
    CHECK(secp256k1_ec_pubkey_create(CTX, &pub, scalar32));
    CHECK(secp256k1_ec_pubkey_serialize(CTX, out33, &len, &pub, SECP256K1_EC_COMPRESSED));
}

/* ---- argument checks and failure outputs ---- */
static void test_anti_exfil_api(void) {
    unsigned char sk[32], rho[32], hc[32], r0[33], sig64[64], msg[32];
    secp256k1_keypair keypair, bad_keypair;
    secp256k1_xonly_pubkey xpk;
    secp256k1_pubkey pub;
    secp256k1_ecdsa_signature esig;

    ae_random_seckey(sk);
    testrand256(rho);
    testrand256(msg);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk));
    CHECK(secp256k1_keypair_xonly_pub(CTX, &xpk, NULL, &keypair));
    CHECK(secp256k1_ec_pubkey_create(CTX, &pub, sk));

    /* host_commit needs no signing precomputation; the others do. */
    CHECK(secp256k1_anti_exfil_schnorr_host_commit(STATIC_CTX, hc, rho) == 1);
    CHECK(secp256k1_anti_exfil_ecdsa_host_commit(STATIC_CTX, hc, rho) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_host_commit(CTX, NULL, rho));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_host_commit(CTX, hc, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_host_commit(CTX, NULL, rho));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_host_commit(CTX, hc, NULL));

    CHECK(secp256k1_anti_exfil_schnorr_host_commit(CTX, hc, rho));
    CHECK(secp256k1_anti_exfil_schnorr_signer_commit(CTX, r0, msg, 32, &keypair, hc));
    CHECK(secp256k1_anti_exfil_schnorr_sign(CTX, sig64, msg, 32, &keypair, rho));
    CHECK(secp256k1_anti_exfil_schnorr_host_verify(CTX, sig64, msg, 32, &xpk, rho, r0));

    CHECK_ILLEGAL(STATIC_CTX, secp256k1_anti_exfil_schnorr_signer_commit(STATIC_CTX, r0, msg, 32, &keypair, hc));
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_anti_exfil_schnorr_sign(STATIC_CTX, sig64, msg, 32, &keypair, rho));
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_anti_exfil_schnorr_host_verify(STATIC_CTX, sig64, msg, 32, &xpk, rho, r0));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_signer_commit(CTX, NULL, msg, 32, &keypair, hc));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_signer_commit(CTX, r0, NULL, 1, &keypair, hc));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_signer_commit(CTX, r0, msg, 32, NULL, hc));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_signer_commit(CTX, r0, msg, 32, &keypair, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_sign(CTX, NULL, msg, 32, &keypair, rho));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_sign(CTX, sig64, NULL, 1, &keypair, rho));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_sign(CTX, sig64, msg, 32, NULL, rho));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_sign(CTX, sig64, msg, 32, &keypair, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_host_verify(CTX, NULL, msg, 32, &xpk, rho, r0));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_host_verify(CTX, sig64, NULL, 1, &xpk, rho, r0));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_host_verify(CTX, sig64, msg, 32, NULL, rho, r0));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_host_verify(CTX, sig64, msg, 32, &xpk, NULL, r0));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_host_verify(CTX, sig64, msg, 32, &xpk, rho, NULL));
    /* NULL message of length 0 is fine. */
    CHECK(secp256k1_anti_exfil_schnorr_signer_commit(CTX, r0, NULL, 0, &keypair, hc));
    CHECK(secp256k1_anti_exfil_schnorr_sign(CTX, sig64, NULL, 0, &keypair, rho));
    CHECK(secp256k1_anti_exfil_schnorr_host_verify(CTX, sig64, NULL, 0, &xpk, rho, r0));
    /* An all-zero keypair is rejected by the keypair check. */
    memset(&bad_keypair, 0, sizeof(bad_keypair));
    memset(r0, 0xff, 33);
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_schnorr_signer_commit(CTX, r0, msg, 32, &bad_keypair, hc));
    {
        unsigned char zero33[33] = {0};
        CHECK(secp256k1_memcmp_var(r0, zero33, 33) == 0);
    }

    CHECK(secp256k1_anti_exfil_ecdsa_host_commit(CTX, hc, rho));
    CHECK(secp256k1_anti_exfil_ecdsa_signer_commit(CTX, r0, msg, sk, hc));
    CHECK(secp256k1_anti_exfil_ecdsa_sign(CTX, &esig, msg, sk, rho));
    CHECK(secp256k1_anti_exfil_ecdsa_host_verify(CTX, &esig, msg, &pub, rho, r0));
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_anti_exfil_ecdsa_signer_commit(STATIC_CTX, r0, msg, sk, hc));
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_anti_exfil_ecdsa_sign(STATIC_CTX, &esig, msg, sk, rho));
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_anti_exfil_ecdsa_host_verify(STATIC_CTX, &esig, msg, &pub, rho, r0));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_signer_commit(CTX, NULL, msg, sk, hc));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_signer_commit(CTX, r0, NULL, sk, hc));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_signer_commit(CTX, r0, msg, NULL, hc));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_signer_commit(CTX, r0, msg, sk, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_sign(CTX, NULL, msg, sk, rho));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_sign(CTX, &esig, NULL, sk, rho));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_sign(CTX, &esig, msg, NULL, rho));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_sign(CTX, &esig, msg, sk, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_host_verify(CTX, NULL, msg, &pub, rho, r0));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_host_verify(CTX, &esig, NULL, &pub, rho, r0));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_host_verify(CTX, &esig, msg, NULL, rho, r0));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_host_verify(CTX, &esig, msg, &pub, NULL, r0));
    CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_host_verify(CTX, &esig, msg, &pub, rho, NULL));
    /* A public key object that was never filled in is refused by the pubkey loader (illegal callback), result 0. */
    {
        secp256k1_pubkey blank;
        memset(&blank, 0, sizeof(blank));
        CHECK_ILLEGAL(CTX, secp256k1_anti_exfil_ecdsa_host_verify(CTX, &esig, msg, &blank, rho, r0));
    }
}

/* Invalid ECDSA keys fail without output, in both device steps. */
static void test_anti_exfil_ecdsa_bad_key(void) {
    unsigned char rho[32], hc[32], msg[32], r0[33], zero33[33] = {0}, bad[32];
    unsigned char order[32] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
                               0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41};
    secp256k1_ecdsa_signature sig;
    unsigned char sigb[64], zero64[64] = {0};
    int i;
    testrand256(rho);
    testrand256(msg);
    CHECK(secp256k1_anti_exfil_ecdsa_host_commit(CTX, hc, rho));
    for (i = 0; i < 2; i++) {
        if (i == 0) memset(bad, 0, 32); else memcpy(bad, order, 32);
        memset(r0, 0xff, 33);
        CHECK(secp256k1_anti_exfil_ecdsa_signer_commit(CTX, r0, msg, bad, hc) == 0);
        CHECK(secp256k1_memcmp_var(r0, zero33, 33) == 0);
        CHECK(secp256k1_anti_exfil_ecdsa_sign(CTX, &sig, msg, bad, rho) == 0);
        CHECK(secp256k1_ecdsa_signature_serialize_compact(CTX, sigb, &sig));
        CHECK(secp256k1_memcmp_var(sigb, zero64, 64) == 0);
    }
}

/* ---- known answers ---- */
static void test_anti_exfil_vectors(void) {
    unsigned char sk[32], m[AE_MAXMSG], rho[32], pk[33], hc[32], r0[33], sig[64];
    unsigned char got_hc[32], got_r0[33], got_sig[64], got_pk[33];
    size_t i, mlen;
    for (i = 0; i < sizeof(anti_exfil_vectors_schnorr_valid) / sizeof(anti_exfil_vectors_schnorr_valid[0]); i++) {
        const anti_exfil_test_valid *v = &anti_exfil_vectors_schnorr_valid[i];
        secp256k1_keypair kp;
        secp256k1_xonly_pubkey xpk;
        ae_unhex(sk, v->sk); ae_unhex(rho, v->rho); ae_unhex(pk, v->pk); ae_unhex(hc, v->hc);
        ae_unhex(r0, v->r0); ae_unhex(sig, v->sig);
        mlen = ae_vec_msg(m, v);
        CHECK(secp256k1_keypair_create(CTX, &kp, sk));
        CHECK(secp256k1_keypair_xonly_pub(CTX, &xpk, NULL, &kp));
        CHECK(secp256k1_xonly_pubkey_serialize(CTX, got_pk, &xpk));
        CHECK(secp256k1_memcmp_var(got_pk, pk, 32) == 0);
        CHECK(secp256k1_anti_exfil_schnorr_host_commit(CTX, got_hc, rho));
        CHECK(secp256k1_memcmp_var(got_hc, hc, 32) == 0);
        CHECK(secp256k1_anti_exfil_schnorr_signer_commit(CTX, got_r0, m, mlen, &kp, hc));
        CHECK(secp256k1_memcmp_var(got_r0, r0, 33) == 0);
        CHECK(secp256k1_anti_exfil_schnorr_sign(CTX, got_sig, m, mlen, &kp, rho));
        CHECK(secp256k1_memcmp_var(got_sig, sig, 64) == 0);
        CHECK(secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, mlen, &xpk, rho, r0));
    }
    for (i = 0; i < sizeof(anti_exfil_vectors_ecdsa_valid) / sizeof(anti_exfil_vectors_ecdsa_valid[0]); i++) {
        const anti_exfil_test_valid *v = &anti_exfil_vectors_ecdsa_valid[i];
        secp256k1_pubkey pub;
        secp256k1_ecdsa_signature es;
        ae_unhex(sk, v->sk); ae_unhex(rho, v->rho); ae_unhex(pk, v->pk); ae_unhex(hc, v->hc);
        ae_unhex(r0, v->r0); ae_unhex(sig, v->sig);
        mlen = ae_vec_msg(m, v);
        CHECK(mlen == 32);
        ae_pubkey33(got_pk, sk);
        CHECK(secp256k1_memcmp_var(got_pk, pk, 33) == 0);
        CHECK(secp256k1_ec_pubkey_parse(CTX, &pub, pk, 33));
        CHECK(secp256k1_anti_exfil_ecdsa_host_commit(CTX, got_hc, rho));
        CHECK(secp256k1_memcmp_var(got_hc, hc, 32) == 0);
        CHECK(secp256k1_anti_exfil_ecdsa_signer_commit(CTX, got_r0, m, sk, hc));
        CHECK(secp256k1_memcmp_var(got_r0, r0, 33) == 0);
        CHECK(secp256k1_anti_exfil_ecdsa_sign(CTX, &es, m, sk, rho));
        CHECK(secp256k1_ecdsa_signature_serialize_compact(CTX, got_sig, &es));
        CHECK(secp256k1_memcmp_var(got_sig, sig, 64) == 0);
        CHECK(secp256k1_anti_exfil_ecdsa_host_verify(CTX, &es, m, &pub, rho, r0));
    }
}

/* ---- random honest runs, determinism and tampering ---- */
static void ae_flip_in(unsigned char *buf, size_t len) {
    if (len == 0) return;
    buf[testrand_int((uint32_t)len)] ^= (unsigned char)(1 << testrand_int(8));
}

static void test_anti_exfil_schnorr_roundtrip_internal(void) {
    unsigned char sk[32], rho[32], hc[32], r0[33], r0b[33], sig[64], sigb[64], tmp[64], m[AE_MAXMSG], pk[32];
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpk;
    size_t mlen = ae_msglens[testrand_int(sizeof(ae_msglens) / sizeof(ae_msglens[0]))];
    unsigned char rho2[32];
    ae_random_seckey(sk);
    testrand256(rho);
    testrand_bytes_test(m, sizeof(m));
    CHECK(secp256k1_keypair_create(CTX, &kp, sk));
    CHECK(secp256k1_keypair_xonly_pub(CTX, &xpk, NULL, &kp));
    CHECK(secp256k1_xonly_pubkey_serialize(CTX, pk, &xpk));
    CHECK(secp256k1_anti_exfil_schnorr_host_commit(CTX, hc, rho));
    CHECK(secp256k1_anti_exfil_schnorr_signer_commit(CTX, r0, m, mlen, &kp, hc));
    CHECK(secp256k1_anti_exfil_schnorr_signer_commit(CTX, r0b, m, mlen, &kp, hc));
    CHECK(secp256k1_memcmp_var(r0, r0b, 33) == 0);
    CHECK(secp256k1_anti_exfil_schnorr_sign(CTX, sig, m, mlen, &kp, rho));
    CHECK(secp256k1_anti_exfil_schnorr_sign(CTX, sigb, m, mlen, &kp, rho));
    CHECK(secp256k1_memcmp_var(sig, sigb, 64) == 0);
    CHECK(secp256k1_schnorrsig_verify(CTX, sig, m, mlen, &xpk));
    CHECK(secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, mlen, &xpk, rho, r0));
    /* Tampering with any input is rejected. */
    memcpy(rho2, rho, 32); ae_flip_in(rho2, 32);
    CHECK(!secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, mlen, &xpk, rho2, r0));
    memcpy(tmp, sig, 64); ae_flip_in(tmp, 64);
    CHECK(!secp256k1_anti_exfil_schnorr_host_verify(CTX, tmp, m, mlen, &xpk, rho, r0));
    memcpy(tmp, r0, 33); ae_flip_in(tmp, 33);
    CHECK(!secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, mlen, &xpk, rho, tmp));
    if (mlen > 0) {
        memcpy(tmp, m, 1); m[0] ^= 1;
        CHECK(!secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, mlen, &xpk, rho, r0));
        m[0] = tmp[0];
    }
    /* A plain BIP340 signature is valid but not a signature on W. */
    {
        unsigned char aux[32];
        testrand256(aux);
        CHECK(secp256k1_schnorrsig_sign_custom(CTX, tmp, m, mlen, &kp, NULL));
        CHECK(!secp256k1_anti_exfil_schnorr_host_verify(CTX, tmp, m, mlen, &xpk, rho, r0));
    }
}

static void test_anti_exfil_ecdsa_roundtrip_internal(void) {
    unsigned char sk[32], rho[32], hc[32], r0[33], tmp33[33], m[32], m2[32], rho2[32], sigb[64], sigc[64];
    secp256k1_pubkey pub;
    secp256k1_ecdsa_signature sig, sigd, sig2;
    unsigned char pk[33];
    ae_random_seckey(sk);
    testrand256(rho);
    testrand256(m);
    ae_pubkey33(pk, sk);
    CHECK(secp256k1_ec_pubkey_parse(CTX, &pub, pk, 33));
    CHECK(secp256k1_anti_exfil_ecdsa_host_commit(CTX, hc, rho));
    CHECK(secp256k1_anti_exfil_ecdsa_signer_commit(CTX, r0, m, sk, hc));
    CHECK(secp256k1_anti_exfil_ecdsa_sign(CTX, &sig, m, sk, rho));
    CHECK(secp256k1_anti_exfil_ecdsa_sign(CTX, &sigd, m, sk, rho));
    CHECK(secp256k1_ecdsa_signature_serialize_compact(CTX, sigb, &sig));
    CHECK(secp256k1_ecdsa_signature_serialize_compact(CTX, sigc, &sigd));
    CHECK(secp256k1_memcmp_var(sigb, sigc, 64) == 0);
    CHECK(secp256k1_ecdsa_verify(CTX, &sig, m, &pub));
    CHECK(secp256k1_anti_exfil_ecdsa_host_verify(CTX, &sig, m, &pub, rho, r0));
    memcpy(rho2, rho, 32); ae_flip_in(rho2, 32);
    CHECK(!secp256k1_anti_exfil_ecdsa_host_verify(CTX, &sig, m, &pub, rho2, r0));
    memcpy(tmp33, r0, 33); ae_flip_in(tmp33, 33);
    CHECK(!secp256k1_anti_exfil_ecdsa_host_verify(CTX, &sig, m, &pub, rho, tmp33));
    memcpy(m2, m, 32); ae_flip_in(m2, 32);
    CHECK(!secp256k1_anti_exfil_ecdsa_host_verify(CTX, &sig, m2, &pub, rho, r0));
    ae_flip_in(sigb, 64);
    if (secp256k1_ecdsa_signature_parse_compact(CTX, &sig2, sigb)) {
        CHECK(!secp256k1_anti_exfil_ecdsa_host_verify(CTX, &sig2, m, &pub, rho, r0));
    }
    /* High s is rejected, although ordinary verification would accept the
     * negated signature after normalization. */
    {
        secp256k1_scalar r, s;
        secp256k1_ecdsa_signature_load(CTX, &r, &s, &sig);
        secp256k1_scalar_negate(&s, &s);
        secp256k1_ecdsa_signature_save(&sig2, &r, &s);
        CHECK(!secp256k1_anti_exfil_ecdsa_host_verify(CTX, &sig2, m, &pub, rho, r0));
        /* r = 0 and s = 0 */
        s = secp256k1_scalar_zero;
        secp256k1_ecdsa_signature_save(&sig2, &r, &s);
        CHECK(!secp256k1_anti_exfil_ecdsa_host_verify(CTX, &sig2, m, &pub, rho, r0));
        r = secp256k1_scalar_zero;
        secp256k1_ecdsa_signature_load(CTX, &s, &s, &sig);
        secp256k1_ecdsa_signature_save(&sig2, &r, &s);
        CHECK(!secp256k1_anti_exfil_ecdsa_host_verify(CTX, &sig2, m, &pub, rho, r0));
    }
}

/* ---- R0 and signature formats ---- */
static void test_anti_exfil_formats(void) {
    unsigned char sk[32], rho[32], hc[32], r0[33], bad[33], m[32], sig[64], p_be[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F};
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpk;
    unsigned char prefixes[] = {0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xFF};
    size_t i;
    secp256k1_fe x;
    ae_random_seckey(sk);
    testrand256(rho);
    testrand256(m);
    CHECK(secp256k1_keypair_create(CTX, &kp, sk));
    CHECK(secp256k1_keypair_xonly_pub(CTX, &xpk, NULL, &kp));
    CHECK(secp256k1_anti_exfil_schnorr_host_commit(CTX, hc, rho));
    CHECK(secp256k1_anti_exfil_schnorr_signer_commit(CTX, r0, m, 32, &kp, hc));
    CHECK(secp256k1_anti_exfil_schnorr_sign(CTX, sig, m, 32, &kp, rho));
    CHECK(secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, 32, &xpk, rho, r0));
    for (i = 0; i < sizeof(prefixes); i++) {
        memcpy(bad, r0, 33);
        bad[0] = prefixes[i];
        CHECK(!secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, 32, &xpk, rho, bad));
    }
    /* x = p, p + 1 and 2^256 - 1 are not below p. */
    bad[0] = 0x02;
    memcpy(&bad[1], p_be, 32);
    CHECK(!secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, 32, &xpk, rho, bad));
    bad[32] += 1;
    CHECK(!secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, 32, &xpk, rho, bad));
    memset(&bad[1], 0xff, 32);
    CHECK(!secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, 32, &xpk, rho, bad));
    /* An x with no point on the curve. */
    for (i = 1; i < 100; i++) {
        secp256k1_ge ge;
        memset(&bad[1], 0, 32);
        bad[32] = (unsigned char)i;
        CHECK(secp256k1_fe_set_b32_limit(&x, &bad[1]));
        if (!secp256k1_ge_set_xo_var(&ge, &x, 0)) break;
    }
    CHECK(i < 100);
    bad[0] = 0x02;
    CHECK(!secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, 32, &xpk, rho, bad));
    /* The first 32 bytes of the signature must be below p. */
    memcpy(sig, p_be, 32);
    CHECK(!secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, 32, &xpk, rho, r0));
}

/* ---- an independent derivation of both schemes from the specification,
 * using only public functions for the point and signing steps ---- */
static int ae_nonce_fixed(unsigned char *nonce32, const unsigned char *msg, size_t msglen, const unsigned char *key32, const unsigned char *xonly_pk32, const unsigned char *algo, size_t algolen, void *data) {
    (void)msg; (void)msglen; (void)key32; (void)xonly_pk32; (void)algo; (void)algolen;
    memcpy(nonce32, data, 32);
    return 1;
}

static int ae_ecdsa_nonce_fixed(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int attempt) {
    (void)msg32; (void)key32; (void)algo16; (void)attempt;
    memcpy(nonce32, data, 32);
    return 1;
}

static void test_anti_exfil_independent_internal(void) {
    unsigned char sk[32], rho[32], hc[32], aux[32], t0[32], pk[33], buf[32 + 33 + AE_MAXMSG + 32], h[32];
    unsigned char k0b[32], tb[32], kpb[32], r0[33], r0_got[33], pt[65], m[AE_MAXMSG], sig[64], sig_got[64];
    size_t mlen = ae_msglens[testrand_int(sizeof(ae_msglens) / sizeof(ae_msglens[0]))];
    secp256k1_scalar d, k0, t, kp_s;
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpk;
    secp256k1_schnorrsig_extraparams ep = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
    int parity, overflow, i;

    ae_random_seckey(sk);
    testrand256(rho);
    testrand_bytes_test(m, sizeof(m));

    /* BIP340 */
    CHECK(secp256k1_keypair_create(CTX, &kp, sk));
    CHECK(secp256k1_keypair_xonly_pub(CTX, &xpk, &parity, &kp));
    CHECK(secp256k1_xonly_pubkey_serialize(CTX, pk, &xpk));
    secp256k1_scalar_set_b32(&d, sk, NULL);
    secp256k1_scalar_cond_negate(&d, parity);
    ae_tag_hash(hc, "s2c/schnorr/data", rho, 32);
    ae_tag_hash(aux, "BIP0340/aux", hc, 32);
    secp256k1_scalar_get_b32(t0, &d);
    for (i = 0; i < 32; i++) t0[i] ^= aux[i];
    memcpy(buf, t0, 32); memcpy(buf + 32, pk, 32); memcpy(buf + 64, m, mlen); memcpy(buf + 64 + mlen, hc, 32);
    ae_tag_hash(h, "s2c/schnorr/nonce", buf, 96 + mlen);
    secp256k1_scalar_set_b32(&k0, h, NULL);
    CHECK(!secp256k1_scalar_is_zero(&k0));
    secp256k1_scalar_get_b32(k0b, &k0);
    ae_pubkey33(r0, k0b);
    CHECK(secp256k1_anti_exfil_schnorr_signer_commit(CTX, r0_got, m, mlen, &kp, hc));
    CHECK(secp256k1_memcmp_var(r0, r0_got, 33) == 0);
    memcpy(pt, r0, 33); memcpy(pt + 33, rho, 32);
    ae_tag_hash(tb, "s2c/schnorr/point", pt, 65);
    secp256k1_scalar_set_b32(&t, tb, &overflow);
    CHECK(!overflow);
    secp256k1_scalar_add(&kp_s, &k0, &t);
    CHECK(!secp256k1_scalar_is_zero(&kp_s));
    secp256k1_scalar_get_b32(kpb, &kp_s);
    ep.noncefp = ae_nonce_fixed;
    ep.ndata = kpb;
    CHECK(secp256k1_schnorrsig_sign_custom(CTX, sig, m, mlen, &kp, &ep));
    CHECK(secp256k1_anti_exfil_schnorr_sign(CTX, sig_got, m, mlen, &kp, rho));
    CHECK(secp256k1_memcmp_var(sig, sig_got, 64) == 0);

    /* ECDSA */
    {
        unsigned char dmask[32], ebuf[129], msg32[32], sg[64], sg_got[64];
        secp256k1_ecdsa_signature es, es_got;
        testrand256(msg32);
        ae_pubkey33(pk, sk);
        ae_tag_hash(hc, "s2c/ecdsa/data", rho, 32);
        ae_tag_hash(aux, "s2c/ecdsa/aux", hc, 32);
        for (i = 0; i < 32; i++) dmask[i] = sk[i] ^ aux[i];
        memcpy(ebuf, dmask, 32); memcpy(ebuf + 32, pk, 33); memcpy(ebuf + 65, msg32, 32); memcpy(ebuf + 97, hc, 32);
        ae_tag_hash(h, "s2c/ecdsa/nonce", ebuf, 129);
        secp256k1_scalar_set_b32(&k0, h, &overflow);
        CHECK(!overflow && !secp256k1_scalar_is_zero(&k0));
        ae_pubkey33(r0, h);
        CHECK(secp256k1_anti_exfil_ecdsa_signer_commit(CTX, r0_got, msg32, sk, hc));
        CHECK(secp256k1_memcmp_var(r0, r0_got, 33) == 0);
        memcpy(pt, r0, 33); memcpy(pt + 33, rho, 32);
        ae_tag_hash(tb, "s2c/ecdsa/point", pt, 65);
        secp256k1_scalar_set_b32(&t, tb, &overflow);
        CHECK(!overflow);
        secp256k1_scalar_add(&kp_s, &k0, &t);
        secp256k1_scalar_get_b32(kpb, &kp_s);
        CHECK(secp256k1_ecdsa_sign(CTX, &es, msg32, sk, ae_ecdsa_nonce_fixed, kpb));
        CHECK(secp256k1_anti_exfil_ecdsa_sign(CTX, &es_got, msg32, sk, rho));
        CHECK(secp256k1_ecdsa_signature_serialize_compact(CTX, sg, &es));
        CHECK(secp256k1_ecdsa_signature_serialize_compact(CTX, sg_got, &es_got));
        CHECK(secp256k1_memcmp_var(sg, sg_got, 64) == 0);
    }
}

#ifdef SECP256K1_ANTI_EXFIL_TEST_SEAM
/* ---- forced hash outputs, compiled only with the test seam ---- */
static void ae_force(int slot, const char *tag, const unsigned char *out32) {
    int i, found = -1;
    for (i = 0; i < SECP256K1_ANTI_EXFIL_TAG_COUNT; i++) {
        if (strcmp(secp256k1_anti_exfil_tags[i], tag) == 0) found = i;
    }
    CHECK(found >= 0);
    secp256k1_anti_exfil_force[slot].tag = found;
    secp256k1_anti_exfil_force[slot].skip = 0;
    secp256k1_anti_exfil_force[slot].calls = -1;
    memcpy(secp256k1_anti_exfil_force[slot].out, out32, 32);
}

static void ae_unforce(void) {
    int i;
    for (i = 0; i < 3; i++) {
        secp256k1_anti_exfil_force[i].tag = -1;
        secp256k1_anti_exfil_force[i].skip = 0;
        secp256k1_anti_exfil_force[i].calls = -1;
    }
}

/* extra is "tag:hexoutput,tag:hexoutput" */
static void ae_force_extra(const char *extra) {
    char tag[64];
    unsigned char out[32];
    int slot = 1;
    const char *p = extra;
    while (*p != 0) {
        const char *colon = strchr(p, ':');
        size_t n;
        CHECK(colon != NULL && (size_t)(colon - p) < sizeof(tag) && slot < 3);
        n = (size_t)(colon - p);
        memcpy(tag, p, n);
        tag[n] = 0;
        ae_unhex(out, colon + 1);
        ae_force(slot++, tag, out);
        p = colon + 65;
        if (*p == ',') p++;
    }
}

static int ae_has(const char *ops, const char *op) {
    return strstr(ops, op) != NULL;
}

static void ae_run_forced(const anti_exfil_test_forced *v, int is_schnorr) {
    unsigned char out[32], sk[32], m[AE_MAXMSG], rho[32], hc[32], pk[33], r0[33], sig[64], got[64], zero[64] = {0};
    size_t mlen;
    int accept = strcmp(v->expected, "accept") == 0;
    int produces = strcmp(v->expected, "device_produces") == 0;
    ae_unforce();
    ae_unhex(out, v->output);
    ae_force(0, v->tag, out);
    ae_force_extra(v->extra);
    if (ae_has(v->ops, "device_commit") || ae_has(v->ops, "device_sign")) {
        ae_unhex(sk, v->sk); ae_unhex(rho, v->rho); ae_unhex(hc, v->hc);
        mlen = ae_unhex(m, v->m);
        ae_unhex(r0, v->r0); ae_unhex(sig, v->sig);
        if (is_schnorr) {
            secp256k1_keypair kp;
            CHECK(secp256k1_keypair_create(CTX, &kp, sk));
            if (ae_has(v->ops, "device_commit")) {
                memset(got, 0xff, 33);
                CHECK(secp256k1_anti_exfil_schnorr_signer_commit(CTX, got, m, mlen, &kp, hc) == produces);
                CHECK(secp256k1_memcmp_var(got, produces ? r0 : zero, 33) == 0);
            }
            if (ae_has(v->ops, "device_sign")) {
                memset(got, 0xff, 64);
                CHECK(secp256k1_anti_exfil_schnorr_sign(CTX, got, m, mlen, &kp, rho) == produces);
                CHECK(secp256k1_memcmp_var(got, produces ? sig : zero, 64) == 0);
            }
        } else {
            secp256k1_ecdsa_signature es;
            if (ae_has(v->ops, "device_commit")) {
                memset(got, 0xff, 33);
                CHECK(secp256k1_anti_exfil_ecdsa_signer_commit(CTX, got, m, sk, hc) == produces);
                CHECK(secp256k1_memcmp_var(got, produces ? r0 : zero, 33) == 0);
            }
            if (ae_has(v->ops, "device_sign")) {
                CHECK(secp256k1_anti_exfil_ecdsa_sign(CTX, &es, m, sk, rho) == produces);
                CHECK(secp256k1_ecdsa_signature_serialize_compact(CTX, got, &es));
                CHECK(secp256k1_memcmp_var(got, produces ? sig : zero, 64) == 0);
            }
        }
    }
    if (ae_has(v->ops, "host_verify")) {
        ae_unhex(pk, v->pk); ae_unhex(rho, v->rho); ae_unhex(r0, v->r0); ae_unhex(sig, v->sig);
        mlen = ae_unhex(m, v->m);
        if (is_schnorr) {
            secp256k1_xonly_pubkey xpk;
            CHECK(secp256k1_xonly_pubkey_parse(CTX, &xpk, pk));
            CHECK(secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, mlen, &xpk, rho, r0) == accept);
        } else {
            secp256k1_pubkey pub;
            secp256k1_ecdsa_signature es;
            CHECK(secp256k1_ec_pubkey_parse(CTX, &pub, pk, 33));
            CHECK(secp256k1_ecdsa_signature_parse_compact(CTX, &es, sig));
            CHECK(secp256k1_anti_exfil_ecdsa_host_verify(CTX, &es, m, &pub, rho, r0) == accept);
        }
    }
    ae_unforce();
}

static void test_anti_exfil_forced(void) {
    size_t i;
    for (i = 0; i < sizeof(anti_exfil_vectors_schnorr_forced) / sizeof(anti_exfil_vectors_schnorr_forced[0]); i++) {
        /* The challenge hash of the s = n case is computed by the base's own
         * BIP340 verification, outside this module, so it cannot be forced. */
        if (strcmp(anti_exfil_vectors_schnorr_forced[i].id, "bip340-forced-isolated-s-equals-n") == 0) continue;
        ae_run_forced(&anti_exfil_vectors_schnorr_forced[i], 1);
    }
    for (i = 0; i < sizeof(anti_exfil_vectors_ecdsa_forced) / sizeof(anti_exfil_vectors_ecdsa_forced[0]); i++) {
        ae_run_forced(&anti_exfil_vectors_ecdsa_forced[i], 0);
    }
}

/* t = 0 is allowed: k' = k0 and W = R0. A fault that makes the device and the
 * host disagree on t is caught by the device's own check. */
static void test_anti_exfil_t_zero_and_selfcheck(void) {
    unsigned char sk[32], rho[32], hc[32], r0[33], m[32], zero[32] = {0}, other[32], sig[64], pk[33];
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpk;
    secp256k1_pubkey pub;
    secp256k1_ecdsa_signature es;
    ae_random_seckey(sk);
    testrand256(rho);
    testrand256(m);
    memset(other, 0, 32);
    other[31] = 5;
    CHECK(secp256k1_keypair_create(CTX, &kp, sk));
    CHECK(secp256k1_keypair_xonly_pub(CTX, &xpk, NULL, &kp));
    ae_pubkey33(pk, sk);
    CHECK(secp256k1_ec_pubkey_parse(CTX, &pub, pk, 33));

    ae_unforce();
    ae_force(0, "s2c/schnorr/point", zero);
    CHECK(secp256k1_anti_exfil_schnorr_host_commit(CTX, hc, rho));
    CHECK(secp256k1_anti_exfil_schnorr_signer_commit(CTX, r0, m, 32, &kp, hc));
    CHECK(secp256k1_anti_exfil_schnorr_sign(CTX, sig, m, 32, &kp, rho));
    CHECK(secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, 32, &xpk, rho, r0));
    CHECK(secp256k1_memcmp_var(sig, &r0[1], 32) == 0);
    /* The device uses t = 5 for its signing and the host's check sees the real t. */
    ae_force(0, "s2c/schnorr/point", other);
    secp256k1_anti_exfil_force[0].calls = 1;
    CHECK(secp256k1_anti_exfil_schnorr_sign(CTX, sig, m, 32, &kp, rho) == 0);
    ae_unforce();

    ae_force(0, "s2c/ecdsa/point", zero);
    CHECK(secp256k1_anti_exfil_ecdsa_host_commit(CTX, hc, rho));
    CHECK(secp256k1_anti_exfil_ecdsa_signer_commit(CTX, r0, m, sk, hc));
    CHECK(secp256k1_anti_exfil_ecdsa_sign(CTX, &es, m, sk, rho));
    CHECK(secp256k1_anti_exfil_ecdsa_host_verify(CTX, &es, m, &pub, rho, r0));
    ae_force(0, "s2c/ecdsa/point", other);
    secp256k1_anti_exfil_force[0].calls = 1;
    CHECK(secp256k1_anti_exfil_ecdsa_sign(CTX, &es, m, sk, rho) == 0);
    ae_unforce();
    /* The first matching call is left alone and the second is replaced. */
    ae_force(0, "s2c/ecdsa/point", other);
    secp256k1_anti_exfil_force[0].skip = 1;
    secp256k1_anti_exfil_force[0].calls = 1;
    CHECK(secp256k1_anti_exfil_ecdsa_sign(CTX, &es, m, sk, rho) == 0);
    ae_unforce();
}

/* t >= n isolated from every other host check. The device signs with a forced t (0 or 1), so the signature is
 * good for W = R0 + tG. The host then sees the hash value t + n, which fits in 256 bits for these t and reduces
 * to the same t. Every check but t < n passes, so only that check can reject. */
static void test_anti_exfil_t_overflow_isolated(void) {
    static const char *lo[2] = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001"
    };
    static const char *hi[2] = {
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"
    };
    unsigned char sk[32], rho[32], hc[32], r0[33], m[32], tlo[32], thi[32], sig[64], pk[33];
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpk;
    secp256k1_pubkey pub;
    secp256k1_ecdsa_signature es;
    int i;
    for (i = 0; i < 2; i++) {
        ae_random_seckey(sk);
        testrand256(rho);
        testrand256(m);
        ae_unhex(tlo, lo[i]);
        ae_unhex(thi, hi[i]);
        CHECK(secp256k1_keypair_create(CTX, &kp, sk));
        CHECK(secp256k1_keypair_xonly_pub(CTX, &xpk, NULL, &kp));
        ae_pubkey33(pk, sk);
        CHECK(secp256k1_ec_pubkey_parse(CTX, &pub, pk, 33));

        ae_unforce();
        ae_force(0, "s2c/schnorr/point", tlo);
        CHECK(secp256k1_anti_exfil_schnorr_host_commit(CTX, hc, rho));
        CHECK(secp256k1_anti_exfil_schnorr_signer_commit(CTX, r0, m, 32, &kp, hc));
        CHECK(secp256k1_anti_exfil_schnorr_sign(CTX, sig, m, 32, &kp, rho));
        CHECK(secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, 32, &xpk, rho, r0));
        ae_force(0, "s2c/schnorr/point", thi);
        CHECK(!secp256k1_anti_exfil_schnorr_host_verify(CTX, sig, m, 32, &xpk, rho, r0));
        ae_unforce();

        ae_force(0, "s2c/ecdsa/point", tlo);
        CHECK(secp256k1_anti_exfil_ecdsa_host_commit(CTX, hc, rho));
        CHECK(secp256k1_anti_exfil_ecdsa_signer_commit(CTX, r0, m, sk, hc));
        CHECK(secp256k1_anti_exfil_ecdsa_sign(CTX, &es, m, sk, rho));
        CHECK(secp256k1_anti_exfil_ecdsa_host_verify(CTX, &es, m, &pub, rho, r0));
        ae_force(0, "s2c/ecdsa/point", thi);
        CHECK(!secp256k1_anti_exfil_ecdsa_host_verify(CTX, &es, m, &pub, rho, r0));
        ae_unforce();
    }
}
#endif

REPEAT_TEST(test_anti_exfil_schnorr_roundtrip)
REPEAT_TEST(test_anti_exfil_ecdsa_roundtrip)
REPEAT_TEST(test_anti_exfil_independent)

static const struct tf_test_entry tests_anti_exfil[] = {
    CASE1(test_anti_exfil_api),
    CASE1(test_anti_exfil_ecdsa_bad_key),
    CASE1(test_anti_exfil_vectors),
    CASE1(test_anti_exfil_schnorr_roundtrip),
    CASE1(test_anti_exfil_ecdsa_roundtrip),
    CASE1(test_anti_exfil_formats),
    CASE1(test_anti_exfil_independent),
#ifdef SECP256K1_ANTI_EXFIL_TEST_SEAM
    CASE1(test_anti_exfil_forced),
    CASE1(test_anti_exfil_t_zero_and_selfcheck),
    CASE1(test_anti_exfil_t_overflow_isolated),
#endif
};

#endif
