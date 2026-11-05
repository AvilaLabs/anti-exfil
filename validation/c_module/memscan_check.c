/* residue: memory-scan harness. Runs each new function on a fresh,
 * zero-filled alternate stack (ucontext), and at exit from the function scans
 * the whole alternate stack (live frames are gone, so this is the dead-stack
 * residue) and the process heap for known secret byte patterns. The inputs
 * (sk, keypair, rho, ...) live in .bss and are not scanned; the pattern table
 * is static for the same reason. Not run under valgrind.
 *
 * usage: memscan_secrets <patterns-file> < case-line
 * patterns-file lines: <name> <minrun> <hex>
 * Controls: "baseline" (empty function: must find nothing) and "plant"
 * (leaves sk in a local on purpose: must be found) are emitted as rows.
 * Output: one JSON object per (function, pattern, region).
 * Build with -DP56_SCHNORR or -DP56_ECDSA. */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <ucontext.h>
#include <secp256k1.h>
#include "secrets_common.h"
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_anti_exfil.h>

#define STACK_SIZE (256 * 1024)
#define MAXPAT 64

static struct { char name[48]; size_t len, minrun; unsigned char b[64]; } pats[MAXPAT];
static int npats;
static secrets_case c;
static secp256k1_context *ctx;
static unsigned char hc[32];
static const unsigned char *mp;
#ifdef SECRETS_SCHNORR
static secp256k1_keypair kp;
static secp256k1_xonly_pubkey pk;
static unsigned char r0[33];
static unsigned char sig[64];
#else
static secp256k1_pubkey pub;
static unsigned char r0[33];
static secp256k1_ecdsa_signature sig;
#endif
static int fn_ret;
static ucontext_t main_uc, fn_uc;
static void (*cur_fn)(void);

static void tramp(void) { cur_fn(); }

/* Runs fn on a fresh zero-filled stack; returns the stack base for scanning. */
static unsigned char *run_on_fresh_stack(void (*fn)(void)) {
    unsigned char *stk = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stk == MAP_FAILED) { perror("mmap"); exit(2); }
    cur_fn = fn;
    getcontext(&fn_uc);
    fn_uc.uc_stack.ss_sp = stk;
    fn_uc.uc_stack.ss_size = STACK_SIZE;
    fn_uc.uc_link = &main_uc;
    makecontext(&fn_uc, tramp, 0);
    swapcontext(&main_uc, &fn_uc);
    return stk;
}

/* ---- functions under test (each sets fn_ret) ---- */
static void f_noop(void) { fn_ret = 1; }
static void f_plant(void) {
    volatile unsigned char leak[32];
    size_t i;
    for (i = 0; i < 32; i++) leak[i] = c.sk[i];
    fn_ret = 1;
}
#ifdef SECRETS_SCHNORR
static void f_setup(void) {
    unsigned char tmp_sk[32];
    memcpy(tmp_sk, c.sk, 32);
    fn_ret = secp256k1_keypair_create(ctx, &kp, tmp_sk) && secp256k1_keypair_xonly_pub(ctx, &pk, NULL, &kp)
        && secp256k1_anti_exfil_schnorr_host_commit(ctx, hc, c.rho)
        && secp256k1_anti_exfil_schnorr_signer_commit(ctx, r0, mp, c.msglen, &kp, hc)
        && secp256k1_anti_exfil_schnorr_sign(ctx, sig, mp, c.msglen, &kp, c.rho);
}
static void f_host_commit(void) { fn_ret = secp256k1_anti_exfil_schnorr_host_commit(ctx, hc, c.rho); }
static void f_signer_commit(void) { fn_ret = secp256k1_anti_exfil_schnorr_signer_commit(ctx, r0, mp, c.msglen, &kp, hc); }
static void f_sign(void) { fn_ret = secp256k1_anti_exfil_schnorr_sign(ctx, sig, mp, c.msglen, &kp, c.rho); }
static void f_host_verify(void) { fn_ret = secp256k1_anti_exfil_schnorr_host_verify(ctx, sig, mp, c.msglen, &pk, c.rho, r0); }
#else
static void f_setup(void) {
    fn_ret = secp256k1_ec_pubkey_create(ctx, &pub, c.sk)
        && secp256k1_anti_exfil_ecdsa_host_commit(ctx, hc, c.rho)
        && secp256k1_anti_exfil_ecdsa_signer_commit(ctx, r0, c.msg, c.sk, hc)
        && secp256k1_anti_exfil_ecdsa_sign(ctx, &sig, c.msg, c.sk, c.rho);
}
static void f_host_commit(void) { fn_ret = secp256k1_anti_exfil_ecdsa_host_commit(ctx, hc, c.rho); }
static void f_signer_commit(void) { fn_ret = secp256k1_anti_exfil_ecdsa_signer_commit(ctx, r0, c.msg, c.sk, hc); }
static void f_sign(void) { fn_ret = secp256k1_anti_exfil_ecdsa_sign(ctx, &sig, c.msg, c.sk, c.rho); }
static void f_host_verify(void) { fn_ret = secp256k1_anti_exfil_ecdsa_host_verify(ctx, &sig, c.msg, &pub, c.rho, r0); }
#endif

/* ---- scanning ---- */
static void scan(const char *fn, const char *region, const unsigned char *buf, size_t len) {
    int p;
    for (p = 0; p < npats; p++) {
        size_t full = 0, frags = 0, maxfrag = 0, i, j, L = pats[p].len, mr = pats[p].minrun;
        for (i = 0; i + mr <= len; i++) {
            for (j = 0; j + mr <= L; j++) {
                size_t k;
                if (buf[i] != pats[p].b[j]) continue;
                /* only start a run where it cannot be extended backwards */
                if (i > 0 && j > 0 && buf[i - 1] == pats[p].b[j - 1]) continue;
                for (k = 0; i + k < len && j + k < L && buf[i + k] == pats[p].b[j + k]; k++) {}
                if (k < mr) continue;
                if (k == L) full++;
                else { frags++; if (k > maxfrag) maxfrag = k; }
            }
        }
        printf("{\"fn\":\"%s\",\"region\":\"%s\",\"pattern\":\"%s\",\"full\":%zu,\"fragments\":%zu,\"max_fragment\":%zu}\n",
               fn, region, pats[p].name, full, frags, maxfrag);
    }
}

static void scan_heap(const char *fn) {
    FILE *m = fopen("/proc/self/maps", "r");
    char line[512];
    static unsigned char copy[8 * 1024 * 1024];
    if (!m) return;
    while (fgets(line, sizeof(line), m)) {
        unsigned long lo, hi;
        if (strstr(line, "[heap]") && sscanf(line, "%lx-%lx", &lo, &hi) == 2) {
            size_t n = hi - lo;
            if (n > sizeof(copy)) n = sizeof(copy);
            memcpy(copy, (void *)lo, n);
            scan(fn, "heap", copy, n);
        }
    }
    fclose(m);
}

static void run_one(const char *name, void (*fn)(void)) {
    unsigned char *stk;
    fn_ret = 0;
    stk = run_on_fresh_stack(fn);
    printf("{\"fn\":\"%s\",\"region\":\"return\",\"pattern\":\"-\",\"ret\":%d}\n", name, fn_ret);
    scan(name, "stack", stk, STACK_SIZE);
    scan_heap(name);
    munmap(stk, STACK_SIZE);
}

int main(int argc, char **argv) {
    FILE *pf;
    char line[512], hex[200];
    unsigned char *s;
    int emit = argc == 2 && strcmp(argv[1], "--emit") == 0;
    if (argc != 2) return 2;
    pf = emit ? NULL : fopen(argv[1], "r");
    if (!pf && !emit) return 2;
    while (!emit && npats < MAXPAT && fgets(line, sizeof(line), pf)) {
        unsigned int mr;
        if (sscanf(line, "%47s %u %199s", pats[npats].name, &mr, hex) != 3) return 2;
        pats[npats].len = strlen(hex) / 2; pats[npats].minrun = mr;
        if (pats[npats].len > 64 || !secrets_unhex(pats[npats].b, pats[npats].len, hex)) return 2;
        npats++;
    }
    if (pf) fclose(pf);
    if (secrets_read_case(stdin, &c) != 1) return 2;
    mp = c.msglen ? c.msg : NULL;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    s = run_on_fresh_stack(f_setup);       /* residue of setup is not reported */
    munmap(s, STACK_SIZE);
    if (!fn_ret) { fprintf(stderr, "setup failed\n"); return 3; }
    if (emit) {  /* public values the checker needs to derive the secret patterns */
        unsigned char o[33];
        size_t ol = sizeof(o);
        printf("{\"hc\":\""); secrets_hex(stdout, hc, 32);
#ifdef SECRETS_SCHNORR
        secp256k1_xonly_pubkey_serialize(ctx, o, &pk);
        printf("\",\"pk\":\""); secrets_hex(stdout, o, 32);
        printf("\",\"R0\":\""); secrets_hex(stdout, r0, 33);
        printf("\",\"sig\":\""); secrets_hex(stdout, sig, 64);
#else
        secp256k1_ec_pubkey_serialize(ctx, o, &ol, &pub, SECP256K1_EC_COMPRESSED);
        printf("\",\"pk\":\""); secrets_hex(stdout, o, 33);
        printf("\",\"R0\":\""); secrets_hex(stdout, r0, 33);
        { unsigned char s64[64]; secp256k1_ecdsa_signature_serialize_compact(ctx, s64, &sig);
          printf("\",\"sig\":\""); secrets_hex(stdout, s64, 64); }
#endif
        (void)ol;
        printf("\"}\n");
        return 0;
    }
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    run_one("control_baseline", f_noop);
    run_one("control_plant", f_plant);
    run_one("host_commit", f_host_commit);
    run_one("signer_commit", f_signer_commit);
    run_one("signer_sign", f_sign);
    run_one("host_verify", f_host_verify);
    fflush(stdout);
    return 0;
}
