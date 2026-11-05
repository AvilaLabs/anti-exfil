/* ECDSA tables against the unmodified API of secp256k1-zkp (ecdsa_s2c module).
 *
 * As with PR 1140, the signer's nonce derivation differs from the spec's
 * (zkp runs RFC 6979), so signer bytes are not compared. What is run: the
 * host commitment (exact bytes), the host check on tuples made under the
 * spec's derivation, and the same failure cases on a signature made by zkp's
 * own signer. zkp's opening is the 33-byte compressed R0 with no flag, so
 * R0_bytes is passed to secp256k1_ecdsa_s2c_opening_parse as it is. */
#include <stdio.h>
#include <string.h>

#include "secp256k1.h"
#include "secp256k1_ecdsa_s2c.h"

#include "ae_common.h"

#define LEN(a) (sizeof(a) / sizeof((a)[0]))
#define NF LEN(ae_ecdsa_forced)

/* Host check through zkp's API from the spec's bytes. */
static int zkp_verify(const secp256k1_context *ctx, const ae_tuple *t, const char **where) {
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_s2c_opening opening;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, t->pk, 33)) { *where = "pk parse"; return 0; }
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, t->sig)) { *where = "signature parse"; return 0; }
    if (!secp256k1_ecdsa_s2c_opening_parse(ctx, &opening, t->r0)) { *where = "opening parse"; return 0; }
    if (!secp256k1_anti_exfil_host_verify(ctx, &sig, t->m, &pk, t->rho, &opening)) { *where = "host_verify"; return 0; }
    *where = "";
    return 1;
}

/* A signature by zkp's own signer for the sk, m and rho of a valid case. */
static int zkp_make_own(const secp256k1_context *ctx, const ae_valid *v, ae_tuple *own, int *direct_ok) {
    unsigned char sk[32], hc[32];
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_s2c_opening op;
    size_t len = 33;
    ae_tuple spec;
    ae_from_valid(&spec, v);
    ae_unhex(v->sk, sk, 32);
    memcpy(own->rho, spec.rho, 32); own->rholen = 32;
    memcpy(own->m, spec.m, spec.mlen); own->mlen = spec.mlen;
    if (own->mlen != 32) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, sk)) return 0;
    if (!secp256k1_ec_pubkey_serialize(ctx, own->pk, &len, &pk, SECP256K1_EC_COMPRESSED)) return 0;
    own->pklen = 33;
    if (!secp256k1_ecdsa_anti_exfil_host_commit(ctx, hc, own->rho)) return 0;
    if (!secp256k1_ecdsa_anti_exfil_signer_commit(ctx, &op, own->m, sk, hc)) return 0;
    if (!secp256k1_anti_exfil_sign(ctx, &sig, own->m, sk, own->rho)) return 0;
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, own->sig, &sig)) return 0;
    own->siglen = 64;
    if (!secp256k1_ecdsa_s2c_opening_serialize(ctx, own->r0, &op)) return 0;
    own->r0len = 33;
    *direct_ok = secp256k1_anti_exfil_host_verify(ctx, &sig, own->m, &pk, own->rho, &op);
    return 1;
}

static void run_tables(const secp256k1_context *ctx, const char *pfx, const ae_valid *valid, size_t nv,
                       const ae_reject *reject, size_t nr, int is_main) {
    static ae_tuple t, s, own;
    size_t i;
    const char *where;
    int ok;

    ae_sectionp(pfx, "host_commit");
    for (i = 0; i < nv; i++) {
        unsigned char rho[32], hc[32], want[32];
        ae_unhex(valid[i].rho, rho, 32);
        ae_unhex(valid[i].hc, want, 32);
        ae_check(valid[i].id, secp256k1_ecdsa_anti_exfil_host_commit(ctx, hc, rho) && memcmp(hc, want, 32) == 0, "hc differs from the table");
    }

    ae_sectionp(pfx, "verify_accept");
    for (i = 0; i < nv; i++) {
        ae_from_valid(&t, &valid[i]);
        if (is_main) ae_control_accept(i, &t);
        ok = zkp_verify(ctx, &t, &where);
        ae_check(valid[i].id, ok, where);
    }

    ae_sectionp(pfx, "verify_reject");
    for (i = 0; i < nr; i++) {
        const ae_reject *r = &reject[i];
        const char *na;
        ae_from_reject(&t, r);
        if (is_main) ae_control_reject(r, valid, nv, &t, AE_CONTROL_ECDSA_ID);
        na = ae_fixed_size_reason(&t, 33, 1);
        if (na != NULL) { ae_not_run(r->id, na); continue; }
        ok = zkp_verify(ctx, &t, &where);
        ae_check(r->id, !ok, "accepted");
    }

    ae_sectionp(pfx, "own_roundtrip");
    for (i = 0; i < nv; i++) {
        int direct = 0;
        ae_from_valid(&s, &valid[i]);
        ok = zkp_make_own(ctx, &valid[i], &own, &direct);
        ae_check(valid[i].id, ok && direct && zkp_verify(ctx, &own, &where), "zkp signer output not accepted by its own host_verify");
        if (ok) {
            char a[67], b[67];
            ae_tohex(own.r0, 33, a);
            ae_tohex(s.r0, 33, b);
            ae_note("NOTE", valid[i].id, "own R0 %s, spec R0 %s%s", a, b, memcmp(own.r0, s.r0, 33) == 0 ? " (equal)" : "");
        }
    }

    ae_sectionp(pfx, "own_reject");
    for (i = 0; i < nr; i++) {
        const ae_reject *r = &reject[i];
        int k, direct = 0;
        ae_from_reject(&t, r);
        if (ae_fixed_size_reason(&t, 33, 1) != NULL) { ae_not_run(r->id, "wrong-length value cannot be passed to a fixed-size API"); continue; }
        if (r->from[0] == '\0') { ae_not_run(r->id, "no source case: the tuple is fixed, not a change to a signature"); continue; }
        k = ae_find(valid, nv, r->from);
        if (k < 0) { ae_not_run(r->id, "source case is a host-only tuple, not a device run"); continue; }
        if (!zkp_make_own(ctx, &valid[k], &own, &direct)) { ae_check(r->id, 0, "no own signature"); continue; }
        ae_from_valid(&s, &valid[k]);
        if (!ae_apply_delta(&own, &s, &t)) { ae_not_run(r->id, "length differs"); continue; }
        ok = zkp_verify(ctx, &own, &where);
        ae_check(r->id, !ok, "accepted");
    }

    if (!is_main) return;

    /* Not from the vector file: R0 with the same x and the other parity (02 <-> 03). */
    ae_section("extra_r0_parity_flipped");
    for (i = 0; i < nv; i++) {
        ae_from_valid(&t, &valid[i]);
        t.r0[0] ^= 1;
        ok = zkp_verify(ctx, &t, &where);
        ae_check(valid[i].id, !ok, "accepted");
    }
}

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    static ae_tuple t;
    size_t i;
    const char *where;
    int ok;

    if (ctx == NULL) return 2;
    ae_start("zkp");
    run_tables(ctx, "", ae_ecdsa_valid, LEN(ae_ecdsa_valid), ae_ecdsa_reject, LEN(ae_ecdsa_reject), 1);
    run_tables(ctx, "boundary_", ae_b_ecdsa_valid, LEN(ae_b_ecdsa_valid), ae_b_ecdsa_reject, LEN(ae_b_ecdsa_reject), 0);

    ae_section("boundary_host_accept_only");
    for (i = 0; i < AE_B_ECDSA_NHOSTOK; i++) {
        ae_from_reject(&t, &ae_b_ecdsa_hostok[i]);
        ok = zkp_verify(ctx, &t, &where);
        ae_check(ae_b_ecdsa_hostok[i].id, ok, where);
    }

    /* signer_commit and sign take the 32-byte key directly, so both are called with the bad key. */
    ae_section("boundary_device_fail");
    for (i = 0; i < LEN(ae_b_ecdsa_devfail); i++) {
        const ae_devfail *f = &ae_b_ecdsa_devfail[i];
        unsigned char sk[32], rho[32], hc[32];
        secp256k1_ecdsa_s2c_opening op;
        secp256k1_ecdsa_signature sig;
        int c, g;
        char msg[80];
        ae_unhex(f->sk, sk, 32);
        ae_unhex(f->rho, rho, 32);
        ae_unhex(f->hc, hc, 32);
        c = secp256k1_ecdsa_anti_exfil_signer_commit(ctx, &op, f->m, sk, hc);
        g = secp256k1_anti_exfil_sign(ctx, &sig, f->m, sk, rho);
        sprintf(msg, "sign returned %d (must be 0)", g);
        ae_check(f->id, !g, msg);
        if (c) {
            ae_note("DIFF", f->id, "signer_commit returned %d on an invalid key: it does not check seckey32 (spec: the device fails)", c);
        }
    }

    for (i = 0; i < NF; i++) {
        ae_note("SKIP", ae_ecdsa_forced[i].id, "forced-hash case, needs a hash override; expected %s", ae_ecdsa_forced[i].expected);
    }
    secp256k1_context_destroy(ctx);
    return ae_finish();
}
