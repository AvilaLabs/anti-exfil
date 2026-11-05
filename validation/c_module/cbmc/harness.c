/* static CBMC harnesses for the anti-exfil module. The library is included in one translation unit
 * without the module (ENABLE_MODULE_ANTI_EXFIL is not defined for secp256k1.c), then the heavy arithmetic
 * the module calls is replaced by stubs with nondeterministic results (macros that rename the callee at
 * the module's call sites), and then the module's main_impl.h is included. The module code itself is
 * the real code; SHA-256 compression, group and scalar multiplication, inversion, point decompression,
 * keypair loading and the base library's verify are abstracted. Each harness is run alone, see run_cbmc.sh. */
#include "secp256k1.c"

#ifndef MSGLEN
# define MSGLEN 5
#endif
#ifndef TAGV
# define TAGV 0
#endif
int nondet_int(void);
unsigned char nondet_uchar(void);
size_t nondet_size(void);

/* Stubs: outputs are left as they are (nondeterministic if uninitialised), results are nondeterministic. */
static void cbmc_sha256_transform(uint32_t *state, const unsigned char *blocks64, size_t n_blocks) { (void)state; (void)blocks64; (void)n_blocks; }
static int cbmc_ge_set_xo_var(secp256k1_ge *r, const secp256k1_fe *x, int odd) { (void)r; (void)x; (void)odd; return nondet_int(); }
static void cbmc_gej_add_ge(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b) { (void)r; (void)a; (void)b; }
static void cbmc_ge_set_gej(secp256k1_ge *r, secp256k1_gej *a) { (void)r; (void)a; }
static void cbmc_mulgen(const secp256k1_ecmult_gen_context *c, secp256k1_gej *r, const secp256k1_scalar *k) { (void)c; (void)r; (void)k; }
static int cbmc_schnorrsig_verify(const secp256k1_context *ctx, const unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_xonly_pubkey *pk) { (void)ctx; (void)sig64; (void)msg; (void)msglen; (void)pk; return nondet_int(); }
static void cbmc_scalar_inverse(secp256k1_scalar *r, const secp256k1_scalar *x) { (void)r; (void)x; }
static void cbmc_scalar_mul(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) { (void)r; (void)a; (void)b; }
static int cbmc_scalar_add(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) { (void)r; (void)a; (void)b; return nondet_int(); }
static void cbmc_ecmult(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_scalar *na, const secp256k1_scalar *ng) { (void)r; (void)a; (void)na; (void)ng; }
static int cbmc_ecdsa_sig_sign(const secp256k1_ecmult_gen_context *c, secp256k1_scalar *r, secp256k1_scalar *s, const secp256k1_scalar *sk, const secp256k1_scalar *m, const secp256k1_scalar *n, int *recid) { (void)c; (void)r; (void)s; (void)sk; (void)m; (void)n; (void)recid; return nondet_int(); }
static int cbmc_keypair_load(const secp256k1_context *ctx, secp256k1_scalar *sk, secp256k1_ge *pk, const secp256k1_keypair *kp) { (void)ctx; (void)sk; (void)pk; (void)kp; return nondet_int(); }
static int cbmc_keypair_xonly_pub(const secp256k1_context *ctx, secp256k1_xonly_pubkey *pk, int *parity, const secp256k1_keypair *kp) { (void)ctx; (void)pk; (void)parity; (void)kp; return nondet_int(); }

#ifdef SECP256K1_ANTI_EXFIL_ECMULT_GEN_PLAIN
# define secp256k1_ecmult_gen cbmc_mulgen
#else
# define secp256k1_ecmult_gen_gej cbmc_mulgen
#endif
#define secp256k1_ge_set_xo_var cbmc_ge_set_xo_var
#define secp256k1_gej_add_ge cbmc_gej_add_ge
#define secp256k1_ge_set_gej cbmc_ge_set_gej
#define secp256k1_schnorrsig_verify cbmc_schnorrsig_verify
#define secp256k1_scalar_inverse cbmc_scalar_inverse
#define secp256k1_scalar_mul cbmc_scalar_mul
#define secp256k1_scalar_add cbmc_scalar_add
#define secp256k1_ecmult cbmc_ecmult
#define secp256k1_ecdsa_sig_sign cbmc_ecdsa_sig_sign
#define secp256k1_keypair_load cbmc_keypair_load
#define secp256k1_keypair_xonly_pub cbmc_keypair_xonly_pub
#include "modules/anti_exfil/main_impl.h"
#undef secp256k1_ge_set_xo_var
#undef secp256k1_gej_add_ge
#undef secp256k1_ge_set_gej
#undef secp256k1_scalar_inverse
#undef secp256k1_scalar_mul
#undef secp256k1_scalar_add
#undef secp256k1_ecmult
#undef secp256k1_ecdsa_sig_sign
#undef secp256k1_keypair_load
#undef secp256k1_keypair_xonly_pub
#undef secp256k1_schnorrsig_verify

static int ill_count;
static void ill_cb(const char *text, void *data) { (void)text; (void)data; ill_count++; }
static void err_cb(const char *text, void *data) { (void)text; (void)data; __CPROVER_assert(0, "error callback reached"); }

int nondet_int(void);
unsigned char nondet_uchar(void);
size_t nondet_size(void);

static void setup(secp256k1_context *ctx) {
    ctx->ecmult_gen_ctx.built = 1;
    ctx->hash_ctx.fn_sha256_compression = cbmc_sha256_transform;
    ctx->illegal_callback.fn = ill_cb; ctx->illegal_callback.data = 0;
    ctx->error_callback.fn = err_cb; ctx->error_callback.data = 0;
    ctx->declassify = 0;
    ill_count = 0;
}
#define ALL_ZERO(p, n) __CPROVER_forall { int zi; (zi < 0 || zi >= (int)(n)) || ((p)[zi] == 0) }

/* parse33 reads exactly 33 bytes and returns 0 whenever the prefix is not 0x02 or 0x03. ge_set_xo_var abstracted. */
void h_parse33(void) {
    unsigned char in[33]; secp256k1_ge r; int ret; size_t i;
    ret = secp256k1_anti_exfil_parse33(&r, in);
    if (in[0] != 0x02 && in[0] != 0x03) __CPROVER_assert(!ret, "bad prefix rejected");
}

/* ser33 writes exactly 33 bytes (the array is 33 long) and the prefix byte is 0x02 or 0x03. Real field code. */
void h_ser33(void) {
    unsigned char xb[32], yb[32], out[33]; secp256k1_ge g; size_t i;
    secp256k1_fe_set_b32_mod(&g.x, xb); secp256k1_fe_set_b32_mod(&g.y, yb); g.infinity = 0;
    secp256k1_anti_exfil_ser33(out, &g);
    __CPROVER_assert(out[0] == 0x02 || out[0] == 0x03, "ser33 prefix");
}

/* hash_final clears the hash state after a 33 byte write (the largest tagged write the module makes besides
 * the 129 byte ECDSA nonce hash, whose clearing is the same code). One run per tag (TAGV): a symbolic tag made the
 * strlen/memcpy encoding run out of 2 GB. Compression abstracted. */
void h_hash_final(void) {
    secp256k1_context ctx; secp256k1_sha256 sha; unsigned char data[65], out[32]; int tag = TAGV; size_t n = 33;
    setup(&ctx);
    secp256k1_anti_exfil_hash_init(&ctx.hash_ctx, &sha, tag);
    secp256k1_sha256_write(&ctx.hash_ctx, &sha, data, n);
    secp256k1_anti_exfil_hash_final(&ctx.hash_ctx, &sha, out, tag);
    __CPROVER_assert(ALL_ZERO((const unsigned char *)&sha.s, sizeof(sha.s)) && ALL_ZERO(sha.buf, 64) && sha.bytes == 0, "hash state cleared");
}

/* tweak and host_commit read 32/33 byte inputs and write a 32 byte output within bounds. */
void h_commit_tweak_bounds(void) {
    secp256k1_context ctx; unsigned char rho[32], r0[33], hc[32]; secp256k1_scalar t; size_t i; int tag = TAGV; int ret;
    setup(&ctx);
    secp256k1_anti_exfil_host_commit_internal(&ctx.hash_ctx, hc, rho, tag);
    ret = secp256k1_anti_exfil_tweak(&ctx.hash_ctx, &t, r0, rho, tag);
    (void)ret;
}

/* Public host_verify (Schnorr): every NULL argument is rejected through the illegal callback exactly once,
 * with return 0 and before any other use of the pointers. */
void h_schnorr_verify_args(void) {
    secp256k1_context ctx; unsigned char sig[64], msg[8], rho[32], r0[33]; secp256k1_xonly_pubkey pk; size_t msglen = nondet_size();
    const unsigned char *psig = nondet_int() ? sig : NULL, *pmsg = nondet_int() ? msg : NULL, *prho = nondet_int() ? rho : NULL, *pr0 = nondet_int() ? r0 : NULL;
    const secp256k1_xonly_pubkey *ppk = nondet_int() ? &pk : NULL; int ret, bad;
    __CPROVER_assume(msglen <= 8);
    setup(&ctx);
    bad = psig == NULL || (pmsg == NULL && msglen != 0) || ppk == NULL || prho == NULL || pr0 == NULL;
    __CPROVER_assume(bad);
    ret = secp256k1_anti_exfil_schnorr_host_verify(&ctx, psig, pmsg, msglen, ppk, prho, pr0);
    __CPROVER_assert(ret == 0 && ill_count == 1, "NULL argument rejected once");
}

/* Same for the ECDSA host_verify, including a context whose ecmult_gen is not built. */
void h_ecdsa_verify_args(void) {
    secp256k1_context ctx; secp256k1_ecdsa_signature sig; unsigned char msg[32], rho[32], r0[33]; secp256k1_pubkey pk;
    const secp256k1_ecdsa_signature *psig = nondet_int() ? &sig : NULL; const unsigned char *pmsg = nondet_int() ? msg : NULL, *prho = nondet_int() ? rho : NULL, *pr0 = nondet_int() ? r0 : NULL;
    const secp256k1_pubkey *ppk = nondet_int() ? &pk : NULL; int ret, bad;
    setup(&ctx);
    ctx.ecmult_gen_ctx.built = nondet_int() ? 1 : 0;
    bad = !ctx.ecmult_gen_ctx.built || psig == NULL || pmsg == NULL || ppk == NULL || prho == NULL || pr0 == NULL;
    __CPROVER_assume(bad);
    ret = secp256k1_anti_exfil_ecdsa_host_verify(&ctx, psig, pmsg, ppk, prho, pr0);
    __CPROVER_assert(ret == 0 && ill_count == 1, "bad argument rejected once");
}

/* Schnorr host_verify_internal: a bad prefix of R0 returns 0 immediately (parse33), with a valid-pointer
 * call otherwise bounded: sig 64, msg up to 8, rho 32, R0 33. Arithmetic abstracted. */
void h_schnorr_verify_internal(void) {
    secp256k1_context ctx; unsigned char sig[64], msg[8], rho[32], r0[33]; secp256k1_xonly_pubkey pk; size_t msglen = nondet_size(), i; int ret;
    __CPROVER_assume(msglen <= 8);
    setup(&ctx);
    ret = secp256k1_anti_exfil_schnorr_host_verify_internal(&ctx, sig, msg, msglen, &pk, rho, r0);
    if (r0[0] != 0x02 && r0[0] != 0x03) __CPROVER_assert(!ret, "bad R0 prefix rejected");
}

/* ECDSA host_verify_internal with abstracted arithmetic: no out-of-bounds access, bad R0 prefix rejected. */
void h_ecdsa_verify_internal(void) {
    secp256k1_context ctx; secp256k1_scalar r, s; secp256k1_ge p; unsigned char msg[32], rho[32], r0[33]; size_t i; int ret;
    setup(&ctx);
    ret = secp256k1_anti_exfil_ecdsa_host_verify_internal(&ctx, &r, &s, msg, &p, rho, r0);
    if (r0[0] != 0x02 && r0[0] != 0x03) __CPROVER_assert(!ret, "bad R0 prefix rejected");
}

/* signer_commit outputs are zeroed whenever the call fails. The base derivation is replaced by a
 * nondeterministic result, so this covers the memczero use and the argument handling, not the derivation. */
void h_schnorr_commit_zero(void) {
    secp256k1_context ctx; unsigned char r0[33], hc[32], msg[8]; secp256k1_keypair kp; size_t msglen = MSGLEN; int ret;
    setup(&ctx);
    ret = secp256k1_anti_exfil_schnorr_signer_commit(&ctx, r0, msg, msglen, &kp, hc);
    if (!ret) __CPROVER_assert(ALL_ZERO(r0, 33), "R0 zeroed on failure");
}
void h_ecdsa_commit_zero(void) {
    secp256k1_context ctx; unsigned char r0[33], hc[32], msg[32], sk[32]; int ret;
    setup(&ctx);
    ret = secp256k1_anti_exfil_ecdsa_signer_commit(&ctx, r0, msg, sk, hc);
    if (!ret) __CPROVER_assert(ALL_ZERO(r0, 33), "R0 zeroed on failure");
}
/* sign outputs are zeroed on failure (Schnorr 64 bytes; ECDSA r and s). Base derivation, tweak, host checks and
 * the scalar/group arithmetic are abstracted; memczero and cmov are real. */
void h_schnorr_sign_zero(void) {
    secp256k1_context ctx; unsigned char sig[64], rho[32], msg[8]; secp256k1_keypair kp; size_t msglen = MSGLEN; int ret;
    setup(&ctx);
    ret = secp256k1_anti_exfil_schnorr_sign(&ctx, sig, msg, msglen, &kp, rho);
    if (!ret) __CPROVER_assert(ALL_ZERO(sig, 64), "signature zeroed on failure");
}
void h_ecdsa_sign_zero(void) {
    secp256k1_context ctx; secp256k1_ecdsa_signature sig; unsigned char rho[32], msg[32], sk[32]; int ret;
    setup(&ctx);
    ret = secp256k1_anti_exfil_ecdsa_sign(&ctx, &sig, msg, sk, rho);
    if (!ret) __CPROVER_assert(ALL_ZERO((const unsigned char *)sig.data, 64), "signature zeroed on failure");
}

/* Control: a false claim, "parse33 rejects the prefix 0x02". CBMC must report FAILED. */
void h_control_false_claim(void) {
    unsigned char in[33]; secp256k1_ge r; int ret; size_t i;
    ret = secp256k1_anti_exfil_parse33(&r, in);
    if (in[0] == 0x02) __CPROVER_assert(!ret, "FALSE CLAIM: prefix 0x02 rejected");
}
