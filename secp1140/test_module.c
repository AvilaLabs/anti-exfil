/* The same tables against this repository's own anti-exfil module, built on
 * the PR 1140 tree (both schemes). The module uses the spec's derivation, so
 * here the signer must reproduce pk, hc, R0 and the signature byte for byte. */
#include <stdio.h>
#include <string.h>

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_anti_exfil.h"

#include "ae_common.h"

#define LEN(a) (sizeof(a) / sizeof((a)[0]))

static int mod_verify_schnorr(const secp256k1_context *ctx, const ae_tuple *t, const char **where) {
    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpk, t->pk)) { *where = "pk parse"; return 0; }
    if (!secp256k1_anti_exfil_schnorr_host_verify(ctx, t->sig, t->m, t->mlen, &xpk, t->rho, t->r0)) { *where = "host_verify"; return 0; }
    *where = "";
    return 1;
}

static int mod_verify_ecdsa(const secp256k1_context *ctx, const ae_tuple *t, const char **where) {
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, t->pk, 33)) { *where = "pk parse"; return 0; }
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, t->sig)) { *where = "signature parse"; return 0; }
    if (!secp256k1_anti_exfil_ecdsa_host_verify(ctx, &sig, t->m, &pk, t->rho, t->r0)) { *where = "host_verify"; return 0; }
    *where = "";
    return 1;
}

/* The signer side for one valid case; compares every output with the table. */
static int mod_derive_schnorr(const secp256k1_context *ctx, const ae_valid *v, char *detail) {
    unsigned char sk[32], rho[32], hc[32], r0[33], sig[64], pk[32];
    ae_tuple s;
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpk;
    ae_from_valid(&s, v);
    ae_unhex(v->sk, sk, 32);
    ae_unhex(v->rho, rho, 32);
    if (!secp256k1_keypair_create(ctx, &kp, sk) || !secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp) ||
        !secp256k1_xonly_pubkey_serialize(ctx, pk, &xpk)) { strcpy(detail, "key"); return 0; }
    if (!secp256k1_anti_exfil_schnorr_host_commit(ctx, hc, rho)) { strcpy(detail, "host_commit"); return 0; }
    if (!secp256k1_anti_exfil_schnorr_signer_commit(ctx, r0, s.m, s.mlen, &kp, hc)) { strcpy(detail, "signer_commit"); return 0; }
    if (!secp256k1_anti_exfil_schnorr_sign(ctx, sig, s.m, s.mlen, &kp, rho)) { strcpy(detail, "sign"); return 0; }
    if (memcmp(pk, s.pk, 32) != 0) { strcpy(detail, "pk differs"); return 0; }
    {
        unsigned char want_hc[32];
        ae_unhex(v->hc, want_hc, 32);
        if (memcmp(hc, want_hc, 32) != 0) { strcpy(detail, "hc differs"); return 0; }
    }
    if (memcmp(r0, s.r0, 33) != 0) { strcpy(detail, "R0 differs"); return 0; }
    if (memcmp(sig, s.sig, 64) != 0) { strcpy(detail, "signature differs"); return 0; }
    return 1;
}

static int mod_derive_ecdsa(const secp256k1_context *ctx, const ae_valid *v, char *detail) {
    unsigned char sk[32], rho[32], hc[32], r0[33], sig64[64], pk33[33], want_hc[32];
    ae_tuple s;
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig;
    size_t len = 33;
    ae_from_valid(&s, v);
    ae_unhex(v->sk, sk, 32);
    ae_unhex(v->rho, rho, 32);
    ae_unhex(v->hc, want_hc, 32);
    if (!secp256k1_ec_pubkey_create(ctx, &pk, sk) || !secp256k1_ec_pubkey_serialize(ctx, pk33, &len, &pk, SECP256K1_EC_COMPRESSED)) {
        strcpy(detail, "key"); return 0;
    }
    if (!secp256k1_anti_exfil_ecdsa_host_commit(ctx, hc, rho)) { strcpy(detail, "host_commit"); return 0; }
    if (!secp256k1_anti_exfil_ecdsa_signer_commit(ctx, r0, s.m, sk, hc)) { strcpy(detail, "signer_commit"); return 0; }
    if (!secp256k1_anti_exfil_ecdsa_sign(ctx, &sig, s.m, sk, rho)) { strcpy(detail, "sign"); return 0; }
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, sig64, &sig)) { strcpy(detail, "serialize"); return 0; }
    if (memcmp(pk33, s.pk, 33) != 0) { strcpy(detail, "pk differs"); return 0; }
    if (memcmp(hc, want_hc, 32) != 0) { strcpy(detail, "hc differs"); return 0; }
    if (memcmp(r0, s.r0, 33) != 0) { strcpy(detail, "R0 differs"); return 0; }
    if (memcmp(sig64, s.sig, 64) != 0) { strcpy(detail, "signature differs"); return 0; }
    return 1;
}

static void run_schnorr(const secp256k1_context *ctx, const char *pfx, const ae_valid *valid, size_t nv,
                        const ae_reject *reject, size_t nr, int is_main) {
    static ae_tuple t;
    size_t i;
    const char *where;
    char detail[32];
    int ok;

    ae_sectionp(pfx, "schnorr_signer_known_answers");
    for (i = 0; i < nv; i++) {
        detail[0] = '\0';
        ae_check(valid[i].id, mod_derive_schnorr(ctx, &valid[i], detail), detail);
    }
    ae_sectionp(pfx, "schnorr_verify_accept");
    for (i = 0; i < nv; i++) {
        ae_from_valid(&t, &valid[i]);
        if (is_main) ae_control_accept(i, &t);
        ok = mod_verify_schnorr(ctx, &t, &where);
        ae_check(valid[i].id, ok, where);
    }
    ae_sectionp(pfx, "schnorr_verify_reject");
    for (i = 0; i < nr; i++) {
        const ae_reject *r = &reject[i];
        const char *na;
        ae_from_reject(&t, r);
        if (is_main) ae_control_reject(r, valid, nv, &t, AE_CONTROL_SCHNORR_ID);
        na = ae_fixed_size_reason(&t, 32, 0);
        if (na != NULL) { ae_not_run(r->id, na); continue; }
        ok = mod_verify_schnorr(ctx, &t, &where);
        ae_check(r->id, !ok, "accepted");
    }
    if (is_main) {
        /* Not from the vector file: R0 with the same x and the other parity (02 <-> 03). */
        ae_section("schnorr_extra_r0_parity_flipped");
        for (i = 0; i < nv; i++) {
            ae_from_valid(&t, &valid[i]);
            t.r0[0] ^= 1;
            ok = mod_verify_schnorr(ctx, &t, &where);
            ae_check(valid[i].id, !ok, "accepted");
        }
    }
}

static void run_ecdsa(const secp256k1_context *ctx, const char *pfx, const ae_valid *valid, size_t nv,
                      const ae_reject *reject, size_t nr, int is_main) {
    static ae_tuple t;
    size_t i;
    const char *where;
    char detail[32];
    int ok;

    ae_sectionp(pfx, "ecdsa_signer_known_answers");
    for (i = 0; i < nv; i++) {
        detail[0] = '\0';
        ae_check(valid[i].id, mod_derive_ecdsa(ctx, &valid[i], detail), detail);
    }
    ae_sectionp(pfx, "ecdsa_verify_accept");
    for (i = 0; i < nv; i++) {
        ae_from_valid(&t, &valid[i]);
        if (is_main) ae_control_accept(i, &t);
        ok = mod_verify_ecdsa(ctx, &t, &where);
        ae_check(valid[i].id, ok, where);
    }
    ae_sectionp(pfx, "ecdsa_verify_reject");
    for (i = 0; i < nr; i++) {
        const ae_reject *r = &reject[i];
        const char *na;
        ae_from_reject(&t, r);
        if (is_main) ae_control_reject(r, valid, nv, &t, AE_CONTROL_ECDSA_ID);
        na = ae_fixed_size_reason(&t, 33, 1);
        if (na != NULL) { ae_not_run(r->id, na); continue; }
        ok = mod_verify_ecdsa(ctx, &t, &where);
        ae_check(r->id, !ok, "accepted");
    }
    if (is_main) {
        ae_section("ecdsa_extra_r0_parity_flipped");
        for (i = 0; i < nv; i++) {
            ae_from_valid(&t, &valid[i]);
            t.r0[0] ^= 1;
            ok = mod_verify_ecdsa(ctx, &t, &where);
            ae_check(valid[i].id, !ok, "accepted");
        }
    }
}

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    static ae_tuple t;
    size_t i;
    const char *where;
    int ok;

    if (ctx == NULL) return 2;
    ae_start("module");
    run_schnorr(ctx, "", ae_schnorr_valid, LEN(ae_schnorr_valid), ae_schnorr_reject, LEN(ae_schnorr_reject), 1);
    run_ecdsa(ctx, "", ae_ecdsa_valid, LEN(ae_ecdsa_valid), ae_ecdsa_reject, LEN(ae_ecdsa_reject), 1);
    run_schnorr(ctx, "boundary_", ae_b_schnorr_valid, LEN(ae_b_schnorr_valid), ae_b_schnorr_reject, LEN(ae_b_schnorr_reject), 0);
    run_ecdsa(ctx, "boundary_", ae_b_ecdsa_valid, LEN(ae_b_ecdsa_valid), ae_b_ecdsa_reject, LEN(ae_b_ecdsa_reject), 0);

    ae_section("boundary_ecdsa_host_accept_only");
    for (i = 0; i < AE_B_ECDSA_NHOSTOK; i++) {
        ae_from_reject(&t, &ae_b_ecdsa_hostok[i]);
        ok = mod_verify_ecdsa(ctx, &t, &where);
        ae_check(ae_b_ecdsa_hostok[i].id, ok, where);
    }

    /* The Schnorr functions take a keypair, so the key is refused when the keypair is made. */
    ae_section("boundary_schnorr_device_fail");
    for (i = 0; i < LEN(ae_b_schnorr_devfail); i++) {
        unsigned char sk[32];
        secp256k1_keypair kp;
        ae_unhex(ae_b_schnorr_devfail[i].sk, sk, 32);
        ae_check(ae_b_schnorr_devfail[i].id, !secp256k1_keypair_create(ctx, &kp, sk), "keypair_create accepted the key");
    }
    ae_section("boundary_ecdsa_device_fail");
    for (i = 0; i < LEN(ae_b_ecdsa_devfail); i++) {
        const ae_devfail *f = &ae_b_ecdsa_devfail[i];
        unsigned char sk[32], rho[32], hc[32], r0[33];
        secp256k1_ecdsa_signature sig;
        int c, g;
        char msg[80];
        ae_unhex(f->sk, sk, 32);
        ae_unhex(f->rho, rho, 32);
        ae_unhex(f->hc, hc, 32);
        c = secp256k1_anti_exfil_ecdsa_signer_commit(ctx, r0, f->m, sk, hc);
        g = secp256k1_anti_exfil_ecdsa_sign(ctx, &sig, f->m, sk, rho);
        sprintf(msg, "signer_commit returned %d, sign returned %d (both must be 0)", c, g);
        ae_check(f->id, !c && !g, msg);
    }

    for (i = 0; i < LEN(ae_schnorr_forced); i++) ae_note("SKIP", ae_schnorr_forced[i].id, "forced-hash case, needs the module's test seam; expected %s", ae_schnorr_forced[i].expected);
    for (i = 0; i < LEN(ae_ecdsa_forced); i++) ae_note("SKIP", ae_ecdsa_forced[i].id, "forced-hash case, needs the module's test seam; expected %s", ae_ecdsa_forced[i].expected);
    secp256k1_context_destroy(ctx);
    return ae_finish();
}
