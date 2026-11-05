/* Shared helpers for the ctime and memscan drivers. Inputs use this line format:
 *   S <id> <sk32-hex> <rho32-hex> <msg-hex-or--> (Schnorr)
 *   E <id> <sk32-hex> <msg32-hex> <rho32-hex>    (ECDSA)
 * Valid inputs only. */
#ifndef SECRETS_COMMON_H
#define SECRETS_COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char id[40];
    unsigned char sk[32], rho[32], msg[1024];
    size_t msglen;
} secrets_case;

static int secrets_unhex(unsigned char *out, size_t n, const char *in) {
    size_t i;
    if (strlen(in) != n * 2) return 0;
    for (i = 0; i < n; ++i) {
        unsigned int b;
        if (sscanf(in + 2 * i, "%2x", &b) != 1) return 0;
        out[i] = (unsigned char)b;
    }
    return 1;
}

static void secrets_hex(FILE *f, const unsigned char *p, size_t n) {
    size_t i;
    for (i = 0; i < n; ++i) fprintf(f, "%02x", p[i]);
}

/* Returns 1 on a parsed case, 0 on end of input, -1 on a malformed line. */
static int secrets_read_case(FILE *in, secrets_case *c) {
    char line[4096], kind, id[40], a[65], b[65], m[2049];
    if (fgets(line, sizeof(line), in) == NULL) return 0;
#ifdef SECRETS_SCHNORR
    if (sscanf(line, "%c %39s %64s %64s %2048s", &kind, id, a, b, m) != 5 || kind != 'S') return -1;
    if (!secrets_unhex(c->sk, 32, a) || !secrets_unhex(c->rho, 32, b)) return -1;
    if (strcmp(m, "-") == 0) c->msglen = 0;
    else {
        size_t chars = strlen(m);
        if ((chars & 1) || chars / 2 > sizeof(c->msg)) return -1;
        c->msglen = chars / 2;
        if (!secrets_unhex(c->msg, c->msglen, m)) return -1;
    }
#else
    if (sscanf(line, "%c %39s %64s %64s %64s", &kind, id, a, m, b) != 5 || kind != 'E') return -1;
    if (!secrets_unhex(c->sk, 32, a) || !secrets_unhex(c->msg, 32, m) || !secrets_unhex(c->rho, 32, b)) return -1;
    c->msglen = 32;
#endif
    strcpy(c->id, id);
    return 1;
}
#endif
