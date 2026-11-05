/* Shared code of the three test programs: hex decoding, tuples built from the
 * tables, case reporting and the control hooks. C89, no heap. */
#ifndef AE_COMMON_H
#define AE_COMMON_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "anti_exfil_vectors.h"

#define AE_MAXF 80
#define AE_MAXM 1100

/* One host-side tuple as bytes. Lengths are kept because the tables hold
 * wrong-length values on purpose. */
typedef struct {
    unsigned char pk[AE_MAXF], rho[AE_MAXF], r0[AE_MAXF], sig[AE_MAXF], m[AE_MAXM];
    size_t pklen, rholen, r0len, siglen, mlen;
} ae_tuple;

/* ---- reporting ---- */

static const char *ae_prog = "";
static char ae_sec[96] = "";
static unsigned long ae_pass = 0, ae_fail = 0, ae_na = 0;
static unsigned long ae_spass = 0, ae_sfail = 0, ae_sna = 0;

static void ae_end_section(void) {
    if (ae_sec[0] != '\0') {
        printf("TALLY %s %s pass=%lu fail=%lu na=%lu\n", ae_prog, ae_sec, ae_spass, ae_sfail, ae_sna);
    }
    ae_sec[0] = '\0';
    ae_spass = ae_sfail = ae_sna = 0;
}

static void ae_section(const char *name) {
    ae_end_section();
    strcpy(ae_sec, name);
}

/* Section name with a prefix ("boundary_" for the boundary tables, "" for the main ones). */
static void ae_sectionp(const char *pfx, const char *name) {
    char buf[96];
    sprintf(buf, "%s%s", pfx, name);
    ae_section(buf);
}

static void ae_check(const char *id, int ok, const char *detail) {
    if (ok) {
        ae_pass++; ae_spass++;
        printf("PASS %s %s %s\n", ae_prog, ae_sec, id);
    } else {
        ae_fail++; ae_sfail++;
        printf("FAIL %s %s %s%s%s\n", ae_prog, ae_sec, id, detail[0] ? ": " : "", detail);
    }
}

static void ae_not_run(const char *id, const char *why) {
    ae_na++; ae_sna++;
    printf("NA %s %s %s: %s\n", ae_prog, ae_sec, id, why);
}

/* Something seen that is neither a pass nor a failure of a table case. */
static void ae_note(const char *kind, const char *id, const char *fmt, ...) {
    va_list ap;
    printf("%s %s %s: ", kind, ae_prog, id);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static void ae_start(const char *prog) {
    ae_prog = prog;
    printf("PROGRAM %s vectors_sha256=%s boundary_sha256=%s\n", prog, AE_VECTORS_SHA256, AE_BOUNDARY_SHA256);
#ifdef AE_CONTROL
    printf("CONTROL build: one honest tuple and one rejection tuple are altered, two FAIL lines are expected\n");
#endif
}

static int ae_finish(void) {
    ae_end_section();
    printf("RESULT %s pass=%lu fail=%lu na=%lu\n", ae_prog, ae_pass, ae_fail, ae_na);
    return ae_fail ? 1 : 0;
}

/* ---- bytes ---- */

static int ae_hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Decodes a table string. The tables are generated, so bad hex is a bug here. */
static size_t ae_unhex(const char *s, unsigned char *out, size_t max) {
    size_t n = strlen(s), i;
    if (n % 2 != 0 || n / 2 > max) { fprintf(stderr, "bad table hex\n"); exit(2); }
    for (i = 0; i < n / 2; i++) {
        int hi = ae_hexval(s[2 * i]), lo = ae_hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) { fprintf(stderr, "bad table hex\n"); exit(2); }
        out[i] = (unsigned char)(hi * 16 + lo);
    }
    return n / 2;
}

static void ae_tohex(const unsigned char *b, size_t n, char *out) {
    static const char d[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) { out[2 * i] = d[b[i] >> 4]; out[2 * i + 1] = d[b[i] & 15]; }
    out[2 * n] = '\0';
}

static void ae_from_valid(ae_tuple *t, const ae_valid *v) {
    t->pklen = ae_unhex(v->pk, t->pk, AE_MAXF);
    t->rholen = ae_unhex(v->rho, t->rho, AE_MAXF);
    t->r0len = ae_unhex(v->r0, t->r0, AE_MAXF);
    t->siglen = ae_unhex(v->sig, t->sig, AE_MAXF);
    if (v->mlen > AE_MAXM) { fprintf(stderr, "message too long\n"); exit(2); }
    memcpy(t->m, v->m, v->mlen);
    t->mlen = v->mlen;
}

static void ae_from_reject(ae_tuple *t, const ae_reject *r) {
    t->pklen = ae_unhex(r->pk, t->pk, AE_MAXF);
    t->rholen = ae_unhex(r->rho, t->rho, AE_MAXF);
    t->r0len = ae_unhex(r->r0, t->r0, AE_MAXF);
    t->siglen = ae_unhex(r->sig, t->sig, AE_MAXF);
    if (r->mlen > AE_MAXM) { fprintf(stderr, "message too long\n"); exit(2); }
    memcpy(t->m, r->m, r->mlen);
    t->mlen = r->mlen;
}

/* Index of the valid case with this id, or -1. */
static int ae_find(const ae_valid *tab, size_t n, const char *id) {
    size_t i;
    for (i = 0; i < n; i++) {
        if (strcmp(tab[i].id, id) == 0) return (int)i;
    }
    return -1;
}

/* Why a library with fixed-size arguments cannot be given this tuple, or NULL.
 * pklen is 32 for BIP340 and 33 for ECDSA; the message must be 32 bytes for ECDSA only. */
static const char *ae_fixed_size_reason(const ae_tuple *t, size_t pklen, int msg32) {
    if (t->pklen != pklen) return "public key length is fixed by the API";
    if (t->rholen != 32) return "rho is a fixed 32-byte argument";
    if (t->r0len != 33) return "R0 is a fixed 33-byte argument";
    if (t->siglen != 64) return "signature is a fixed 64-byte argument";
    if (msg32 && t->mlen != 32) return "message hash is a fixed 32-byte argument";
    return NULL;
}

/* Copies into dst, for each field of equal length, the bytes at which the
 * rejection tuple differs from its source tuple. Used to put the same change
 * onto a signature made by the library's own derivation. Returns 0 if a
 * field has another length. */
static int ae_apply_delta(ae_tuple *dst, const ae_tuple *src, const ae_tuple *rej) {
    size_t i, h;
    if (src->pklen != rej->pklen || src->rholen != rej->rholen || src->r0len != rej->r0len ||
        src->siglen != rej->siglen || src->mlen != rej->mlen) return 0;
    for (i = 0; i < rej->pklen; i++) if (rej->pk[i] != src->pk[i]) dst->pk[i] = rej->pk[i];
    for (i = 0; i < rej->rholen; i++) if (rej->rho[i] != src->rho[i]) dst->rho[i] = rej->rho[i];
    for (i = 0; i < rej->r0len; i++) if (rej->r0[i] != src->r0[i]) dst->r0[i] = rej->r0[i];
    /* A signature half that differs in 8 bytes or more is a replaced value (a range case): take it whole. */
    for (h = 0; h + 32 <= rej->siglen; h += 32) {
        size_t nd = 0;
        for (i = h; i < h + 32; i++) if (rej->sig[i] != src->sig[i]) nd++;
        if (nd >= 8) memcpy(dst->sig + h, rej->sig + h, 32);
        else for (i = h; i < h + 32; i++) if (rej->sig[i] != src->sig[i]) dst->sig[i] = rej->sig[i];
    }
    for (i = 0; i < rej->mlen; i++) if (rej->m[i] != src->m[i]) dst->m[i] = rej->m[i];
    return 1;
}

/* ---- control hooks ----
 * Built with -DAE_CONTROL, the first honest tuple loses one bit of its
 * signature, and the rejection tuple named below gets its one changed byte
 * put back, which makes it a valid tuple. A test that can fail reports both. */
#define AE_CONTROL_SCHNORR_ID "bip340-reject-s-changed-a"
#define AE_CONTROL_ECDSA_ID "ecdsa-reject-s-changed-a"

#ifdef AE_CONTROL
static void ae_control_accept(size_t i, ae_tuple *t) {
    if (i == 0) {
        t->sig[0] ^= 1;
        printf("CONTROL %s: first honest tuple, signature byte 0 xor 1\n", ae_prog);
    }
}
static void ae_control_reject(const ae_reject *r, const ae_valid *tab, size_t n, ae_tuple *t, const char *id) {
    if (strcmp(r->id, id) == 0) {
        int k = ae_find(tab, n, r->from);
        ae_tuple s;
        if (k < 0) { fprintf(stderr, "control source missing\n"); exit(2); }
        ae_from_valid(&s, &tab[k]);
        t->sig[63] = s.sig[63];
        printf("CONTROL %s: %s, signature byte 63 put back\n", ae_prog, id);
    }
}
#else
#define ae_control_accept(i, t) ((void)0)
#define ae_control_reject(r, tab, n, t, id) ((void)0)
#endif

#endif
