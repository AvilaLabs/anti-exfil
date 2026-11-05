/* constant_time: ctime-style Valgrind memcheck driver, in the manner of
 * secp256k1's ctime_tests. Secret inputs (sk, keypair, rho) are marked
 * undefined with VALGRIND_MAKE_MEM_UNDEFINED; declassified outputs (hc, R0,
 * sig, opening, accept/reject results) are marked defined. Memcheck then
 * reports any branch or memory index that depends on a secret. Stage markers
 * go to stderr so the checker can attribute each report to a stage.
 * Build with -DP56_SCHNORR (benma lib) or -DP56_ECDSA (Jade zkp lib). */
#include <valgrind/memcheck.h>
#include <secp256k1.h>
#include "secrets_common.h"
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_anti_exfil.h>

#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))

static void stage(const char *name, const char *id) {
    fprintf(stderr, "@@STAGE %s %s\n", name, id);
    fflush(stderr);
}

/* Controls: deliberately secret-dependent code, which memcheck must flag. */
static volatile int secrets_sink;
static volatile unsigned char secrets_table[256];
__attribute__((noinline)) static void ctl_a(void) { secrets_sink += 1; __asm__ __volatile__("" ::: "memory"); }
__attribute__((noinline)) static void ctl_b(void) { secrets_sink += 2; __asm__ __volatile__("" ::: "memory"); }
__attribute__((noinline)) static void control_branch(const unsigned char *secret) {
    volatile unsigned char s = secret[0];
    if (s & 1) ctl_a(); else ctl_b();   /* CONTROL-BRANCH */
}
__attribute__((noinline)) static void control_index(const unsigned char *secret) {
    volatile unsigned char s = secret[1];
    secrets_sink += secrets_table[s];           /* CONTROL-INDEX */
}

static int expect(int ok, const char *what, const char *id) {
    if (!ok) { fprintf(stderr, "@@DRIVER-ERROR %s %s\n", what, id); return 1; }
    return 0;
}

int main(int argc, char **argv) {
    secp256k1_context *ctx;
    secrets_case c;
    int rc, bad = 0, ncases = 0;
    unsigned char control_secret[32];
    int control_only = argc > 1 && strcmp(argv[1], "--control-only") == 0;

    if (!RUNNING_ON_VALGRIND) { fprintf(stderr, "must run under valgrind memcheck\n"); return 2; }
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE | SECP256K1_CONTEXT_DECLASSIFY);
    if (ctx == NULL) return 2;

    while (!control_only && (rc = secrets_read_case(stdin, &c)) > 0) {
        unsigned char hc[32], bad_rho[32], bad_msg[1024], r0[33];
        unsigned char rho[32], sk[32];
        const unsigned char *mp;
        int ok, hv, hv_bad_rho, hv_bad_msg;
        ++ncases;
        memcpy(rho, c.rho, 32); memcpy(sk, c.sk, 32);
        mp = c.msglen ? c.msg : NULL;
#ifdef SECRETS_SCHNORR
        {
            secp256k1_keypair kp;
            secp256k1_xonly_pubkey pk;
            unsigned char sig[64];
            stage("setup", c.id);
            if (expect(secp256k1_keypair_create(ctx, &kp, sk), "keypair_create", c.id)) return 3;
            if (expect(secp256k1_keypair_xonly_pub(ctx, &pk, NULL, &kp), "xonly_pub", c.id)) return 3;
            SECRET(&kp, sizeof(kp)); SECRET(sk, 32); SECRET(rho, 32);

            stage("host_commit", c.id);
            ok = secp256k1_anti_exfil_schnorr_host_commit(ctx, hc, rho);
            PUBLIC(&ok, sizeof(ok)); PUBLIC(hc, 32);
            bad |= expect(ok, "host_commit", c.id);

            stage("signer_commit", c.id);
            ok = secp256k1_anti_exfil_schnorr_signer_commit(ctx, r0, mp, c.msglen, &kp, hc);
            PUBLIC(&ok, sizeof(ok)); PUBLIC(r0, 33);
            bad |= expect(ok, "signer_commit", c.id);

            stage("signer_sign", c.id);
            ok = secp256k1_anti_exfil_schnorr_sign(ctx, sig, mp, c.msglen, &kp, rho);
            PUBLIC(&ok, sizeof(ok)); PUBLIC(sig, 64);
            bad |= expect(ok, "sign", c.id);

            stage("host_verify", c.id);
            hv = secp256k1_anti_exfil_schnorr_host_verify(ctx, sig, mp, c.msglen, &pk, rho, r0);
            PUBLIC(&hv, sizeof(hv));
            bad |= expect(hv == 1, "host_verify accepts valid", c.id);

            stage("host_verify_wrong_rho", c.id);
            memcpy(bad_rho, c.rho, 32); bad_rho[0] ^= 1; SECRET(bad_rho, 32);
            hv_bad_rho = secp256k1_anti_exfil_schnorr_host_verify(ctx, sig, mp, c.msglen, &pk, bad_rho, r0);
            PUBLIC(&hv_bad_rho, sizeof(hv_bad_rho));
            bad |= expect(hv_bad_rho == 0, "host_verify rejects wrong rho", c.id);

            stage("host_verify_wrong_msg", c.id);
            memcpy(bad_msg, c.msg, c.msglen);
            if (c.msglen == 0) bad_msg[0] = 0; else bad_msg[c.msglen - 1] ^= 1;
            hv_bad_msg = secp256k1_anti_exfil_schnorr_host_verify(ctx, sig, bad_msg, c.msglen ? c.msglen : 1, &pk, rho, r0);
            PUBLIC(&hv_bad_msg, sizeof(hv_bad_msg));
            bad |= expect(hv_bad_msg == 0, "host_verify rejects wrong msg", c.id);
        }
#else
        {
            secp256k1_pubkey pub;
            secp256k1_ecdsa_signature sig;
            stage("setup", c.id);
            if (expect(secp256k1_ec_pubkey_create(ctx, &pub, sk), "pubkey_create", c.id)) return 3;
            SECRET(sk, 32); SECRET(rho, 32);

            stage("host_commit", c.id);
            ok = secp256k1_anti_exfil_ecdsa_host_commit(ctx, hc, rho);
            PUBLIC(&ok, sizeof(ok)); PUBLIC(hc, 32);
            bad |= expect(ok, "host_commit", c.id);

            stage("signer_commit", c.id);
            ok = secp256k1_anti_exfil_ecdsa_signer_commit(ctx, r0, c.msg, sk, hc);
            PUBLIC(&ok, sizeof(ok)); PUBLIC(r0, 33);
            bad |= expect(ok, "signer_commit", c.id);

            stage("signer_sign", c.id);
            ok = secp256k1_anti_exfil_ecdsa_sign(ctx, &sig, c.msg, sk, rho);
            PUBLIC(&ok, sizeof(ok)); PUBLIC(&sig, sizeof(sig));
            bad |= expect(ok, "sign", c.id);

            stage("host_verify", c.id);
            hv = secp256k1_anti_exfil_ecdsa_host_verify(ctx, &sig, c.msg, &pub, rho, r0);
            PUBLIC(&hv, sizeof(hv));
            bad |= expect(hv == 1, "host_verify accepts valid", c.id);

            stage("host_verify_wrong_rho", c.id);
            memcpy(bad_rho, c.rho, 32); bad_rho[0] ^= 1; SECRET(bad_rho, 32);
            hv_bad_rho = secp256k1_anti_exfil_ecdsa_host_verify(ctx, &sig, c.msg, &pub, bad_rho, r0);
            PUBLIC(&hv_bad_rho, sizeof(hv_bad_rho));
            bad |= expect(hv_bad_rho == 0, "host_verify rejects wrong rho", c.id);

            stage("host_verify_wrong_msg", c.id);
            memcpy(bad_msg, c.msg, 32); bad_msg[31] ^= 1;
            hv_bad_msg = secp256k1_anti_exfil_ecdsa_host_verify(ctx, &sig, bad_msg, &pub, rho, r0);
            PUBLIC(&hv_bad_msg, sizeof(hv_bad_msg));
            bad |= expect(hv_bad_msg == 0, "host_verify rejects wrong msg", c.id);
        }
#endif
    }
    if (rc < 0) { fprintf(stderr, "@@DRIVER-ERROR malformed input line\n"); return 2; }

    /* Controls, run once after the cases. */
    memset(control_secret, 0x5a, sizeof(control_secret));
    SECRET(control_secret, sizeof(control_secret));
    stage("control_branch", "ctl");
    control_branch(control_secret);
    stage("control_index", "ctl");
    control_index(control_secret);
    PUBLIC(control_secret, sizeof(control_secret));
    stage("control_declassified", "ctl");
    control_branch(control_secret);
    control_index(control_secret);
    stage("done", "ctl");
    fprintf(stderr, "@@CASES %d\n", ncases);
    secp256k1_context_destroy(ctx);
    return bad ? 4 : 0;
}
