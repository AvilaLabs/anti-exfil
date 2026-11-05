/* base_unchanged: signs a fixed sample with the base's own schnorrsig_sign32, schnorrsig_sign_custom (BIP340 with a
 * message of any length) and ecdsa_sign, and prints the bytes. Linked once against the pristine base and once
 * against the base with the module; the outputs must be identical. Keys, messages and aux randomness are
 * SHA-256-style counters, no randomness. */
#include <stdio.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

static void fill(unsigned char *b, size_t n, unsigned i, unsigned salt) {
    size_t j; unsigned x = i * 2654435761u + salt * 40503u + 12345u;
    for (j = 0; j < n; j++) { x = x * 1664525u + 1013904223u; b[j] = (unsigned char)(x >> 24); }
}
int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    unsigned i;
    for (i = 0; i < 200; i++) {
        unsigned char sk[32], m[100], aux[32], sig[64], c[64];
        secp256k1_keypair kp; secp256k1_ecdsa_signature es; size_t j, ml = (i * 7) % 100;
        secp256k1_schnorrsig_extraparams ep = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
        fill(sk, 32, i, 1); fill(m, 100, i, 2); fill(aux, 32, i, 3);
        if (!secp256k1_keypair_create(ctx, &kp, sk)) { sk[0] = 0; sk[31] = 1; if (!secp256k1_keypair_create(ctx, &kp, sk)) return 1; }
        if (!secp256k1_schnorrsig_sign32(ctx, sig, m, &kp, aux)) return 1;
        for (j = 0; j < 64; j++) printf("%02x", sig[j]);
        ep.ndata = aux;
        if (!secp256k1_schnorrsig_sign_custom(ctx, sig, ml ? m : NULL, ml, &kp, &ep)) return 1;
        for (j = 0; j < 64; j++) printf("%02x", sig[j]);
        if (!secp256k1_ecdsa_sign(ctx, &es, m, sk, NULL, NULL)) return 1;
        secp256k1_ecdsa_signature_serialize_compact(ctx, c, &es);
        for (j = 0; j < 64; j++) printf("%02x", c[j]);
        printf("\n");
    }
    secp256k1_context_destroy(ctx);
    return 0;
}
