/* Line driver for the module, used by check_vectors.py. Reads lines of
 * hex on stdin ("-" is the empty string), prints one line per input.
 *   VB id sk rho m             BIP340: derive pk hc R0 sig through the public API
 *   VE id sk rho m             ECDSA: the same
 *   HB id pk m rho R0 sig      BIP340 host check; ACCEPT, REJECT <where> or NA <why>
 *   HE id pk m rho R0 sig      ECDSA host check
 * Valid and well-formed inputs and tampered tuples only. No randomness. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_anti_exfil.h>

#define MAXB 4096

static size_t unhex(const char *s, unsigned char *out, size_t max) {
    size_t n, i;
    if (strcmp(s, "-") == 0) return 0;
    n = strlen(s);
    if (n % 2 || n / 2 > max) { fprintf(stderr, "bad hex\n"); exit(2); }
    for (i = 0; i < n / 2; i++) { unsigned v; if (sscanf(s + 2 * i, "%2x", &v) != 1) exit(2); out[i] = (unsigned char)v; }
    return n / 2;
}
static void phex(const unsigned char *b, size_t n) {
    size_t i;
    if (n == 0) { printf(" -"); return; }
    printf(" ");
    for (i = 0; i < n; i++) printf("%02x", b[i]);
}

int main(void) {
    static char line[2 * MAXB + 512];
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (ctx == NULL) return 2;
    while (fgets(line, sizeof(line), stdin)) {
        char *tok[8]; int nt = 0; char *p = strtok(line, " \t\r\n");
        static unsigned char a[MAXB], b[MAXB], c[MAXB], d[MAXB], e[MAXB];
        size_t la, lb, lc, ld, le;
        while (p && nt < 8) { tok[nt++] = p; p = strtok(NULL, " \t\r\n"); }
        if (nt == 0) continue;
        if ((strcmp(tok[0], "VB") == 0 || strcmp(tok[0], "VE") == 0) && nt == 5) {
            unsigned char pk[33], hc[32], r0[33], sig[64];
            size_t pklen = 32, lm;
            int ok = 1;
            la = unhex(tok[2], a, 32); lb = unhex(tok[3], b, 32); lm = unhex(tok[4], c, MAXB);
            if (la != 32 || lb != 32) { printf("%s %s NA bad sk/rho length\n", tok[0], tok[1]); continue; }
            if (tok[0][1] == 'B') {
                secp256k1_keypair kp; secp256k1_xonly_pubkey xpk;
                ok &= secp256k1_keypair_create(ctx, &kp, a);
                ok &= secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp);
                ok &= secp256k1_xonly_pubkey_serialize(ctx, pk, &xpk);
                ok &= secp256k1_anti_exfil_schnorr_host_commit(ctx, hc, b);
                ok &= secp256k1_anti_exfil_schnorr_signer_commit(ctx, r0, lm ? c : NULL, lm, &kp, hc);
                ok &= secp256k1_anti_exfil_schnorr_sign(ctx, sig, lm ? c : NULL, lm, &kp, b);
            } else {
                secp256k1_pubkey pub; secp256k1_ecdsa_signature es;
                pklen = 33;
                if (lm != 32) { printf("VE %s NA msg must be 32 bytes\n", tok[1]); continue; }
                ok &= secp256k1_ec_pubkey_create(ctx, &pub, a);
                ok &= secp256k1_ec_pubkey_serialize(ctx, pk, &pklen, &pub, SECP256K1_EC_COMPRESSED);
                ok &= secp256k1_anti_exfil_ecdsa_host_commit(ctx, hc, b);
                ok &= secp256k1_anti_exfil_ecdsa_signer_commit(ctx, r0, c, a, hc);
                ok &= secp256k1_anti_exfil_ecdsa_sign(ctx, &es, c, a, b);
                ok &= secp256k1_ecdsa_signature_serialize_compact(ctx, sig, &es);
            }
            printf("%s %s ok=%d", tok[0], tok[1], ok); phex(pk, pklen); phex(hc, 32); phex(r0, 33); phex(sig, 64); printf("\n");
        } else if ((strcmp(tok[0], "HB") == 0 || strcmp(tok[0], "HE") == 0) && nt == 7) {
            int hv;
            la = unhex(tok[2], a, MAXB);  /* pk */
            lb = unhex(tok[3], b, MAXB);  /* m */
            lc = unhex(tok[4], c, MAXB);  /* rho */
            ld = unhex(tok[5], d, MAXB);  /* R0 */
            le = unhex(tok[6], e, MAXB);  /* sig */
            if (lc != 32) { printf("%s %s NA fixed-size rho argument\n", tok[0], tok[1]); continue; }
            if (ld != 33) { printf("%s %s NA fixed-size R0 argument\n", tok[0], tok[1]); continue; }
            if (le != 64) { printf("%s %s NA fixed-size sig argument\n", tok[0], tok[1]); continue; }
            if (tok[0][1] == 'B') {
                secp256k1_xonly_pubkey xpk;
                if (la != 32) { printf("HB %s NA x-only pk parse takes a fixed 32 bytes\n", tok[1]); continue; }
                if (!secp256k1_xonly_pubkey_parse(ctx, &xpk, a)) { printf("HB %s REJECT parse_pk\n", tok[1]); continue; }
                hv = secp256k1_anti_exfil_schnorr_host_verify(ctx, e, lb ? b : NULL, lb, &xpk, c, d);
            } else {
                secp256k1_pubkey pub; secp256k1_ecdsa_signature es;
                if (lb != 32) { printf("HE %s NA fixed-size msg32 argument\n", tok[1]); continue; }
                if (la != 33 || !secp256k1_ec_pubkey_parse(ctx, &pub, a, la)) { printf("HE %s REJECT parse_pk\n", tok[1]); continue; }
                if (!secp256k1_ecdsa_signature_parse_compact(ctx, &es, e)) { printf("HE %s REJECT parse_sig\n", tok[1]); continue; }
                hv = secp256k1_anti_exfil_ecdsa_host_verify(ctx, &es, b, &pub, c, d);
            }
            printf("%s %s %s\n", tok[0], tok[1], hv ? "ACCEPT" : "REJECT host_verify");
        } else { fprintf(stderr, "bad command\n"); return 2; }
        fflush(stdout);
    }
    secp256k1_context_destroy(ctx);
    return 0;
}
