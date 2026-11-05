/* BIP340 tables against the unmodified API of PR 1140 (benma/secp256k1).
 *
 * The spec and PR 1140 derive the signer's nonce differently, so the signer
 * bytes are not compared. What is run: the host commitment (exact bytes), the
 * host check on tuples made under the spec's derivation, and the same
 * failure cases on a signature made by PR 1140's own signer.
 *
 * PR 1140 holds the signer's R0 as a pubkey (signer_commitment) and as an
 * s2c_opening. The opening is the 33 bytes of R0 with bit 2 of the first byte
 * set when the final nonce point W = R0 + t*G has odd y ("nonce_is_negated"),
 * parsed with secp256k1_schnorrsig_s2c_opening_parse. The spec has no flag; the
 * host derives it here from R0 and rho through the public API. */
#include <stdio.h>
#include <string.h>

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"

#include "ae_common.h"

#define LEN(a) (sizeof(a) / sizeof((a)[0]))
#define NF LEN(ae_schnorr_forced)

/* Parity of W = R0 + t*G, t = tagged_hash("s2c/schnorr/point", R0 || rho). 1 if W is odd, 0 if even, -1 if undefined. */
static int pr_w_odd(const secp256k1_context *ctx, const unsigned char *r0, const unsigned char *rho) {
    unsigned char buf[65], t[32], ser[33];
    secp256k1_pubkey w;
    size_t len = 33;
    memcpy(buf, r0, 33);
    memcpy(buf + 33, rho, 32);
    if (!secp256k1_tagged_sha256(ctx, t, (const unsigned char *)"s2c/schnorr/point", 17, buf, 65)) return -1;
    if (!secp256k1_ec_pubkey_parse(ctx, &w, r0, 33)) return -1;
    if (!secp256k1_ec_pubkey_tweak_add(ctx, &w, t)) return -1;
    if (!secp256k1_ec_pubkey_serialize(ctx, ser, &len, &w, SECP256K1_EC_COMPRESSED)) return -1;
    return ser[0] == 0x03;
}

/* Host check through PR 1140's API from the spec's bytes and a flag. */
static int pr_verify(const secp256k1_context *ctx, const ae_tuple *t, int negated, const char **where) {
    secp256k1_xonly_pubkey xpk;
    secp256k1_pubkey commitment;
    secp256k1_schnorrsig_s2c_opening opening;
    unsigned char ser[33];
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpk, t->pk)) { *where = "pk parse"; return 0; }
    if (!secp256k1_ec_pubkey_parse(ctx, &commitment, t->r0, 33)) { *where = "R0 parse"; return 0; }
    memcpy(ser, t->r0, 33);
    if (negated) ser[0] |= 0x04;
    if (!secp256k1_schnorrsig_s2c_opening_parse(ctx, &opening, ser)) { *where = "opening parse"; return 0; }
    if (!secp256k1_schnorrsig_anti_exfil_host_verify(ctx, t->sig, t->m, t->mlen, &xpk, t->rho, &commitment, &opening)) {
        *where = "host_verify";
        return 0;
    }
    *where = "";
    return 1;
}

/* A signature by PR 1140's own signer for the sk, m and rho of a valid case.
 * Fills own with pk, rho, R0 (33 bytes), sig, m and returns the opening's 33 bytes in opening33. */
static int pr_make_own(const secp256k1_context *ctx, const ae_valid *v, ae_tuple *own, unsigned char *opening33, int *direct_ok) {
    unsigned char sk[32], hc[32];
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpk;
    secp256k1_pubkey commit;
    secp256k1_schnorrsig_s2c_opening op;
    secp256k1_schnorrsig_extraparams ep = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
    size_t len = 33;
    ae_tuple spec;
    ae_from_valid(&spec, v);
    ae_unhex(v->sk, sk, 32);
    memcpy(own->rho, spec.rho, 32); own->rholen = 32;
    memcpy(own->m, spec.m, spec.mlen); own->mlen = spec.mlen;
    if (!secp256k1_keypair_create(ctx, &kp, sk)) return 0;
    if (!secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp)) return 0;
    if (!secp256k1_xonly_pubkey_serialize(ctx, own->pk, &xpk)) return 0;
    own->pklen = 32;
    if (!secp256k1_schnorrsig_anti_exfil_host_commit(ctx, hc, own->rho)) return 0;
    if (!secp256k1_schnorrsig_anti_exfil_signer_commit(ctx, &commit, own->m, own->mlen, &kp, hc)) return 0;
    ep.s2c_opening = &op;
    ep.s2c_data32 = own->rho;
    if (!secp256k1_schnorrsig_sign_custom(ctx, own->sig, own->m, own->mlen, &kp, &ep)) return 0;
    own->siglen = 64;
    if (!secp256k1_ec_pubkey_serialize(ctx, own->r0, &len, &commit, SECP256K1_EC_COMPRESSED)) return 0;
    own->r0len = 33;
    if (!secp256k1_schnorrsig_s2c_opening_serialize(ctx, opening33, &op)) return 0;
    *direct_ok = secp256k1_schnorrsig_anti_exfil_host_verify(ctx, own->sig, own->m, own->mlen, &xpk, own->rho, &commit, &op);
    return 1;
}

/* Every section for one pair of tables. The control hooks and the probes that only concern the
 * main file's cases run for the main tables. */
static void run_tables(const secp256k1_context *ctx, const char *pfx, const ae_valid *valid, size_t nv,
                       const ae_reject *reject, size_t nr, int is_main) {
    static ae_tuple t, s, own;
    size_t i;
    int flag[16];
    const char *where;
    int ok;

    if (nv > 16) { fprintf(stderr, "table too long\n"); exit(2); }

    ae_sectionp(pfx, "host_commit");
    for (i = 0; i < nv; i++) {
        unsigned char rho[32], hc[32], want[32];
        ae_unhex(valid[i].rho, rho, 32);
        ae_unhex(valid[i].hc, want, 32);
        ae_check(valid[i].id, secp256k1_schnorrsig_anti_exfil_host_commit(ctx, hc, rho) && memcmp(hc, want, 32) == 0, "hc differs from the table");
    }

    ae_sectionp(pfx, "negation_flag");
    for (i = 0; i < nv; i++) {
        ae_from_valid(&t, &valid[i]);
        flag[i] = pr_w_odd(ctx, t.r0, t.rho);
        ae_check(valid[i].id, flag[i] == valid[i].w_odd, "flag from R0 and rho differs from the table's W parity");
    }

    ae_sectionp(pfx, "verify_accept");
    for (i = 0; i < nv; i++) {
        ae_from_valid(&t, &valid[i]);
        if (is_main) ae_control_accept(i, &t);
        ok = pr_verify(ctx, &t, flag[i] == 1, &where);
        ae_check(valid[i].id, ok, where);
    }

    ae_sectionp(pfx, "wrong_flag_refused");
    for (i = 0; i < nv; i++) {
        ae_from_valid(&t, &valid[i]);
        ok = pr_verify(ctx, &t, flag[i] != 1, &where);
        ae_check(valid[i].id, !ok, "accepted with the opposite flag");
    }

    ae_sectionp(pfx, "verify_reject");
    for (i = 0; i < nr; i++) {
        const ae_reject *r = &reject[i];
        const char *w0, *w1, *na;
        int a0, a1;
        ae_from_reject(&t, r);
        if (is_main) ae_control_reject(r, valid, nv, &t, AE_CONTROL_SCHNORR_ID);
        na = ae_fixed_size_reason(&t, 32, 0);
        if (na != NULL) { ae_not_run(r->id, na); continue; }
        a0 = pr_verify(ctx, &t, 0, &w0);
        a1 = pr_verify(ctx, &t, 1, &w1);
        ae_check(r->id, !a0 && !a1, "accepted");
    }

    ae_sectionp(pfx, "own_roundtrip");
    for (i = 0; i < nv; i++) {
        unsigned char op33[33];
        int direct = 0;
        ae_from_valid(&s, &valid[i]);
        ok = pr_make_own(ctx, &valid[i], &own, op33, &direct);
        ae_check(valid[i].id, ok && direct, "PR 1140 signer output not accepted by its own host_verify");
        if (ok) {
            char a[67], b[67];
            ae_tohex(own.r0, 33, a);
            ae_tohex(s.r0, 33, b);
            ae_note("NOTE", valid[i].id, "own R0 %s, spec R0 %s%s", a, b, memcmp(own.r0, s.r0, 33) == 0 ? " (equal)" : "");
        }
    }

    ae_sectionp(pfx, "own_opening_rule");
    for (i = 0; i < nv; i++) {
        unsigned char op33[33];
        int direct = 0, w;
        ok = pr_make_own(ctx, &valid[i], &own, op33, &direct);
        w = ok ? pr_w_odd(ctx, own.r0, own.rho) : -2;
        ae_check(valid[i].id,
                 ok && w >= 0 && op33[0] == (unsigned char)(own.r0[0] | (w ? 0x04 : 0)) && memcmp(op33 + 1, own.r0 + 1, 32) == 0,
                 "opening bytes are not R0 with bit 2 = W odd");
    }

    ae_sectionp(pfx, "own_reject");
    for (i = 0; i < nr; i++) {
        const ae_reject *r = &reject[i];
        unsigned char op33[33];
        int k, direct = 0, a0, a1;
        const char *w0, *w1;
        ae_from_reject(&t, r);
        if (ae_fixed_size_reason(&t, 32, 0) != NULL) { ae_not_run(r->id, "wrong-length value cannot be passed to a fixed-size API"); continue; }
        if (r->from[0] == '\0') { ae_not_run(r->id, "no source case: the tuple is fixed, not a change to a signature"); continue; }
        k = ae_find(valid, nv, r->from);
        if (k < 0) { ae_not_run(r->id, "source case is a host-only tuple, not a device run"); continue; }
        if (!pr_make_own(ctx, &valid[k], &own, op33, &direct)) { ae_check(r->id, 0, "no own signature"); continue; }
        ae_from_valid(&s, &valid[k]);
        if (!ae_apply_delta(&own, &s, &t)) { ae_not_run(r->id, "length differs"); continue; }
        a0 = pr_verify(ctx, &own, 0, &w0);
        a1 = pr_verify(ctx, &own, 1, &w1);
        ae_check(r->id, !a0 && !a1, "accepted");
    }

    if (!is_main) return;

    /* Not from the vector file: R0 with the same x and the other parity (02 <-> 03). The spec binds the
     * parity in the tag input, so the host must refuse it; here under both flags. */
    ae_section("extra_r0_parity_flipped");
    for (i = 0; i < nv; i++) {
        int a0, a1;
        ae_from_valid(&t, &valid[i]);
        t.r0[0] ^= 1;
        a0 = pr_verify(ctx, &t, 0, &where);
        a1 = pr_verify(ctx, &t, 1, &where);
        ae_check(valid[i].id, !a0 && !a1, "accepted");
    }

    /* An R0 string with the flag bit set is a valid opening for PR 1140 and an invalid R0 for the spec. If a
     * caller takes the commitment from the opening instead of parsing R0 itself, the honest signature is
     * accepted with R0 bytes the spec refuses. */
    ae_section("parse_probe");
    for (i = 0; i < nv; i++) {
        secp256k1_schnorrsig_s2c_opening op;
        secp256k1_xonly_pubkey xpk;
        ae_from_valid(&t, &valid[i]);
        if (flag[i] != 1) continue;
        t.r0[0] |= 0x04;
        if (secp256k1_xonly_pubkey_parse(ctx, &xpk, t.pk) && secp256k1_schnorrsig_s2c_opening_parse(ctx, &op, t.r0) &&
            secp256k1_schnorrsig_anti_exfil_host_verify(ctx, t.sig, t.m, t.mlen, &xpk, t.rho, &op.original_pubnonce, &op)) {
            ae_note("DIFF", valid[i].id, "host_verify accepts with R0 bytes starting %02x when the commitment is taken from the opening (spec: parse33 refuses %02x)", t.r0[0], t.r0[0]);
        }
    }
    for (i = 0; i < nr; i++) {
        const ae_reject *r = &reject[i];
        secp256k1_schnorrsig_s2c_opening op;
        secp256k1_pubkey pk;
        ae_from_reject(&t, r);
        if (t.r0len != 33) continue;
        if (strncmp(r->defect, "R0_", 3) != 0 && strncmp(r->defect, "isolated_R0", 11) != 0) continue;
        if (secp256k1_schnorrsig_s2c_opening_parse(ctx, &op, t.r0) && !secp256k1_ec_pubkey_parse(ctx, &pk, t.r0, 33)) {
            ae_note("DIFF", r->id, "s2c_opening_parse accepts R0 bytes with first byte %02x (it reads 06 and 07 as 02 and 03 plus the flag); parse33 and ec_pubkey_parse refuse them", t.r0[0]);
        }
    }
}

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    size_t i;

    if (ctx == NULL) return 2;
    ae_start("pr1140");
    run_tables(ctx, "", ae_schnorr_valid, LEN(ae_schnorr_valid), ae_schnorr_reject, LEN(ae_schnorr_reject), 1);
    run_tables(ctx, "boundary_", ae_b_schnorr_valid, LEN(ae_b_schnorr_valid), ae_b_schnorr_reject, LEN(ae_b_schnorr_reject), 0);

    /* The API takes a keypair, so an out-of-range key is refused when the keypair is made, before any
     * signer function can be called. */
    ae_section("boundary_device_fail");
    for (i = 0; i < LEN(ae_b_schnorr_devfail); i++) {
        unsigned char sk[32];
        secp256k1_keypair kp;
        ae_unhex(ae_b_schnorr_devfail[i].sk, sk, 32);
        ae_check(ae_b_schnorr_devfail[i].id, !secp256k1_keypair_create(ctx, &kp, sk), "keypair_create accepted the key");
    }

    for (i = 0; i < NF; i++) {
        ae_note("SKIP", ae_schnorr_forced[i].id, "forced-hash case, needs a hash override; expected %s", ae_schnorr_forced[i].expected);
    }
    secp256k1_context_destroy(ctx);
    return ae_finish();
}
