/***********************************************************************
 * Anti-exfil module exhaustive tests on the library's small test groups. *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ANTI_EXFIL_TESTS_EXHAUSTIVE_H
#define SECP256K1_MODULE_ANTI_EXFIL_TESTS_EXHAUSTIVE_H

#include "../../../include/secp256k1_anti_exfil.h"

#ifndef SECP256K1_ANTI_EXFIL_TEST_SEAM
# error The anti_exfil exhaustive tests need SECP256K1_ANTI_EXFIL_TEST_SEAM.
#endif

/* Here n = EXHAUSTIVE_TEST_ORDER, real hashes give essentially random scalars and
 * ECDSA would almost always fail on k0 >= n, so the nonce hash and the tweak
 * hash are forced to chosen small values by the seam. Covered, for every key d:
 *   k0 in 0..n    (0 and n fail)
 *   t  in 0..n    (n fails; k0 + t = 0 mod n fails)
 *   messages: the empty message, one byte 0x42, and bytes 0..31 (BIP340); three
 *             32-byte messages (ECDSA)
 *   rho:      32 bytes of 0x11 and of 0x22
 * and for every signature the device produces, host_verify must accept it and
 * reject every other (R, s) pair of the group order. For orders above 13 the
 * (k0, t) pairs, messages, rho values and exhaustive host checks are cut down
 * to the subset in ae_ex_pairs and the first message and rho. */

#define AE_EX_N ((int)EXHAUSTIVE_TEST_ORDER)
#define AE_EX_FULL (AE_EX_N <= 13)

static unsigned int ae_ex_val(const secp256k1_scalar *s) {
    unsigned char b[32];
    secp256k1_scalar_get_b32(b, s);
    return ((unsigned int)b[28] << 24) | ((unsigned int)b[29] << 16) | ((unsigned int)b[30] << 8) | b[31];
}

static void ae_ex_be32(unsigned char *out32, unsigned int v) {
    memset(out32, 0, 32);
    out32[28] = (unsigned char)(v >> 24); out32[29] = (unsigned char)(v >> 16);
    out32[30] = (unsigned char)(v >> 8); out32[31] = (unsigned char)v;
}

static void ae_ex_force(int slot, int tag, unsigned int v) {
    secp256k1_anti_exfil_force[slot].tag = tag;
    secp256k1_anti_exfil_force[slot].skip = 0;
    secp256k1_anti_exfil_force[slot].calls = -1;
    ae_ex_be32(secp256k1_anti_exfil_force[slot].out, v);
}

static void ae_ex_unforce(void) {
    int i;
    for (i = 0; i < 3; i++) secp256k1_anti_exfil_force[i].tag = -1;
}

static int ae_ex_inv(int a) {
    int i;
    for (i = 1; i < AE_EX_N; i++) if ((a * i) % AE_EX_N == 1) return i;
    return 0;
}

/* Affine point i * G: ser33 and x as a number reduced mod n. */
static void ae_ex_point(const secp256k1_ge *group, int i, unsigned char *ser33, unsigned int *x_mod_n, int *odd) {
    secp256k1_ge g = group[i];
    unsigned char xb[32];
    secp256k1_scalar xs;
    secp256k1_fe_normalize(&g.x);
    secp256k1_fe_normalize(&g.y);
    *odd = secp256k1_fe_is_odd(&g.y);
    ser33[0] = (unsigned char)(0x02 | *odd);
    secp256k1_fe_get_b32(&ser33[1], &g.x);
    memcpy(xb, &ser33[1], 32);
    secp256k1_scalar_set_b32(&xs, xb, NULL);
    *x_mod_n = ae_ex_val(&xs);
}

static const unsigned char ae_ex_msgs[3][32] = {
    {0},
    {0x42},
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31}
};
static const size_t ae_ex_msglens[3] = {0, 1, 32};

/* (k0, t) pairs used for orders above 13. */
static int ae_ex_pair(int idx, int k0, unsigned int *t) {
    unsigned int ts[7];
    if (AE_EX_FULL) {
        if (idx > AE_EX_N) return 0;
        *t = (unsigned int)idx;
        return 1;
    }
    ts[0] = 0; ts[1] = 1; ts[2] = 2; ts[3] = (unsigned int)AE_EX_N - 1; ts[4] = (unsigned int)AE_EX_N;
    ts[5] = (unsigned int)((AE_EX_N - k0) % AE_EX_N); ts[6] = (unsigned int)((k0 * 7) % AE_EX_N);
    if (idx >= 7) return 0;
    *t = ts[idx];
    return 1;
}

static void test_exhaustive_anti_exfil_schnorr(const secp256k1_context *ctx, const secp256k1_ge *group) {
    int d, k0v, mi, ri, ti;
    unsigned char rhos[2][32];
    uint64_t iter = 0;
    memset(rhos[0], 0x11, 32);
    memset(rhos[1], 0x22, 32);
    for (d = 1; d < AE_EX_N; d++) {
        unsigned char sk[32], pk_ser[33], tmp33[33];
        unsigned int xd;
        int dodd, deff;
        secp256k1_keypair kp;
        secp256k1_xonly_pubkey xpk;
        ae_ex_be32(sk, (unsigned int)d);
        CHECK(secp256k1_keypair_create(ctx, &kp, sk));
        CHECK(secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp));
        ae_ex_point(group, d, pk_ser, &xd, &dodd);
        deff = dodd ? AE_EX_N - d : d;
        for (mi = 0; mi < (AE_EX_FULL ? 3 : 1); mi++) {
            for (ri = 0; ri < (AE_EX_FULL ? 2 : 1); ri++) {
                for (k0v = 0; k0v <= AE_EX_N; k0v++) {
                    unsigned int tv;
                    for (ti = 0; ae_ex_pair(ti, k0v, &tv); ti++) {
                        unsigned char hc[32], r0[33], sig[64], exp_r0[33], exp_sig[64], tmp[64];
                        unsigned int xr, es, e_val;
                        int k0 = k0v % AE_EX_N, kpr, wodd, k, s, ok_commit, ok_sign, rodd;
                        secp256k1_scalar e;
                        unsigned char kpx[33];
                        if (skip_section(&iter)) continue;
                        ae_ex_force(0, SECP256K1_ANTI_EXFIL_TAG_SCHNORR_NONCE, (unsigned int)k0v);
                        ae_ex_force(1, SECP256K1_ANTI_EXFIL_TAG_SCHNORR_POINT, tv);
                        CHECK(secp256k1_anti_exfil_schnorr_host_commit(ctx, hc, rhos[ri]));
                        ok_commit = k0 != 0;
                        memset(r0, 0xff, 33);
                        CHECK(secp256k1_anti_exfil_schnorr_signer_commit(ctx, r0, ae_ex_msgs[mi], ae_ex_msglens[mi], &kp, hc) == ok_commit);
                        if (ok_commit) {
                            ae_ex_point(group, k0, exp_r0, &xr, &rodd);
                            CHECK(secp256k1_memcmp_var(r0, exp_r0, 33) == 0);
                        } else {
                            memset(exp_r0, 0, 33);
                            CHECK(secp256k1_memcmp_var(r0, exp_r0, 33) == 0);
                        }
                        kpr = (k0 + (int)(tv % (unsigned int)AE_EX_N)) % AE_EX_N;
                        ok_sign = ok_commit && tv < (unsigned int)AE_EX_N && kpr != 0;
                        memset(sig, 0xff, 64);
                        CHECK(secp256k1_anti_exfil_schnorr_sign(ctx, sig, ae_ex_msgs[mi], ae_ex_msglens[mi], &kp, rhos[ri]) == ok_sign);
                        if (!ok_sign) {
                            memset(tmp, 0, 64);
                            CHECK(secp256k1_memcmp_var(sig, tmp, 64) == 0);
                            continue;
                        }
                        ae_ex_point(group, kpr, kpx, &xr, &wodd);
                        k = wodd ? AE_EX_N - kpr : kpr;
                        secp256k1_schnorrsig_challenge(&ctx->hash_ctx, &e, &kpx[1], ae_ex_msgs[mi], ae_ex_msglens[mi], &pk_ser[1]);
                        e_val = ae_ex_val(&e);
                        s = (int)((k + (unsigned long)e_val * (unsigned long)deff) % (unsigned long)AE_EX_N);
                        memcpy(exp_sig, &kpx[1], 32);
                        ae_ex_be32(&exp_sig[32], (unsigned int)s);
                        CHECK(secp256k1_memcmp_var(sig, exp_sig, 64) == 0);
                        CHECK(secp256k1_anti_exfil_schnorr_host_verify(ctx, sig, ae_ex_msgs[mi], ae_ex_msglens[mi], &xpk, rhos[ri], r0));
                        /* Every other s is rejected; s = n is out of range. */
                        if (AE_EX_FULL || (k0v <= 2 && ti == 1)) {
                            for (es = 0; es <= (unsigned int)AE_EX_N; es++) {
                                memcpy(tmp, sig, 64);
                                ae_ex_be32(&tmp[32], es);
                                CHECK(secp256k1_anti_exfil_schnorr_host_verify(ctx, tmp, ae_ex_msgs[mi], ae_ex_msglens[mi], &xpk, rhos[ri], r0) == (es == (unsigned int)s));
                            }
                        }
                        /* The opposite parity of R0 gives a different W, except when t = 0:
                         * W is then -R0 and has the same x. */
                        memcpy(tmp33, r0, 33);
                        tmp33[0] ^= 1;
                        CHECK(secp256k1_anti_exfil_schnorr_host_verify(ctx, sig, ae_ex_msgs[mi], ae_ex_msglens[mi], &xpk, rhos[ri], tmp33) == (tv == 0));
                    }
                }
            }
        }
    }
    ae_ex_unforce();
}

static void test_exhaustive_anti_exfil_ecdsa(const secp256k1_context *ctx, const secp256k1_ge *group) {
    int d, k0v, mi, ri, ti;
    unsigned char rhos[2][32];
    uint64_t iter = 0;
    memset(rhos[0], 0x11, 32);
    memset(rhos[1], 0x22, 32);
    for (d = 1; d < AE_EX_N; d++) {
        unsigned char sk[32], pk_ser[33];
        unsigned int xd;
        int dodd;
        secp256k1_pubkey pub;
        secp256k1_ge dpt = group[d];
        ae_ex_be32(sk, (unsigned int)d);
        secp256k1_pubkey_save(&pub, &dpt);
        ae_ex_point(group, d, pk_ser, &xd, &dodd);
        for (mi = 0; mi < (AE_EX_FULL ? 3 : 1); mi++) {
            secp256k1_scalar zs;
            int z;
            secp256k1_scalar_set_b32(&zs, ae_ex_msgs[mi], NULL);
            z = (int)ae_ex_val(&zs);
            for (ri = 0; ri < (AE_EX_FULL ? 2 : 1); ri++) {
                for (k0v = 0; k0v <= AE_EX_N; k0v++) {
                    unsigned int tv;
                    for (ti = 0; ae_ex_pair(ti, k0v, &tv); ti++) {
                        unsigned char hc[32], r0[33], exp_r0[33], cs[64], exp_cs[64], zero[64] = {0};
                        unsigned int xw, xr, rr, ss;
                        int kpr, wodd, rodd, ok_commit, ok_sign, rexp = 0, sexp = 0;
                        secp256k1_ecdsa_signature sig, cand;
                        unsigned char wser[33];
                        if (skip_section(&iter)) continue;
                        ae_ex_force(0, SECP256K1_ANTI_EXFIL_TAG_ECDSA_NONCE, (unsigned int)k0v);
                        ae_ex_force(1, SECP256K1_ANTI_EXFIL_TAG_ECDSA_POINT, tv);
                        CHECK(secp256k1_anti_exfil_ecdsa_host_commit(ctx, hc, rhos[ri]));
                        /* k0 = 0 and k0 >= n fail; no reduction */
                        ok_commit = k0v >= 1 && k0v < AE_EX_N;
                        memset(r0, 0xff, 33);
                        CHECK(secp256k1_anti_exfil_ecdsa_signer_commit(ctx, r0, ae_ex_msgs[mi], sk, hc) == ok_commit);
                        if (ok_commit) {
                            ae_ex_point(group, k0v, exp_r0, &xr, &rodd);
                            CHECK(secp256k1_memcmp_var(r0, exp_r0, 33) == 0);
                        } else {
                            memset(exp_r0, 0, 33);
                            CHECK(secp256k1_memcmp_var(r0, exp_r0, 33) == 0);
                        }
                        kpr = ok_commit ? (k0v + (int)(tv % (unsigned int)AE_EX_N)) % AE_EX_N : 0;
                        ok_sign = ok_commit && tv < (unsigned int)AE_EX_N && kpr != 0;
                        if (ok_sign) {
                            ae_ex_point(group, kpr, wser, &xw, &wodd);
                            rexp = (int)xw;
                            sexp = (int)(((unsigned long)ae_ex_inv(kpr) * (unsigned long)((z + rexp * d) % AE_EX_N)) % (unsigned long)AE_EX_N);
                            if (rexp == 0 || sexp == 0) ok_sign = 0;
                            if (sexp > (AE_EX_N - 1) / 2) sexp = AE_EX_N - sexp;
                        }
                        CHECK(secp256k1_anti_exfil_ecdsa_sign(ctx, &sig, ae_ex_msgs[mi], sk, rhos[ri]) == ok_sign);
                        CHECK(secp256k1_ecdsa_signature_serialize_compact(ctx, cs, &sig));
                        if (!ok_sign) {
                            CHECK(secp256k1_memcmp_var(cs, zero, 64) == 0);
                        } else {
                            ae_ex_be32(exp_cs, (unsigned int)rexp);
                            ae_ex_be32(&exp_cs[32], (unsigned int)sexp);
                            CHECK(secp256k1_memcmp_var(cs, exp_cs, 64) == 0);
                            CHECK(secp256k1_anti_exfil_ecdsa_host_verify(ctx, &sig, ae_ex_msgs[mi], &pub, rhos[ri], r0));
                        }
                        /* Exactly the device's signature verifies, over all (r, s). A failed
                         * device leaves no signature that verifies. */
                        if (AE_EX_FULL || (k0v <= 2 && ti == 1)) {
                            if (ok_commit) {
                                for (rr = 0; rr < (unsigned int)AE_EX_N; rr++) {
                                    for (ss = 0; ss < (unsigned int)AE_EX_N; ss++) {
                                        secp256k1_scalar rs, sc;
                                        int acc, want;
                                        secp256k1_scalar_set_int(&rs, rr);
                                        secp256k1_scalar_set_int(&sc, ss);
                                        secp256k1_ecdsa_signature_save(&cand, &rs, &sc);
                                        acc = secp256k1_anti_exfil_ecdsa_host_verify(ctx, &cand, ae_ex_msgs[mi], &pub, rhos[ri], r0);
                                        want = ok_sign && rr == (unsigned int)rexp && ss == (unsigned int)sexp;
                                        CHECK(acc == want);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    ae_ex_unforce();
}

static void test_exhaustive_anti_exfil(const secp256k1_context *ctx, const secp256k1_ge *group) {
    test_exhaustive_anti_exfil_schnorr(ctx, group);
    test_exhaustive_anti_exfil_ecdsa(ctx, group);
}

#endif
