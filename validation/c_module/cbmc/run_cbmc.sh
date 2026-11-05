#!/usr/bin/env bash
# static: CBMC runs on the anti-exfil module, one harness at a time. Usage: run_cbmc.sh BASE (benma|zkp)
# Library in one TU, no asm, 64-bit-limb-free portable arithmetic (USE_FORCE_WIDEMUL_INT64), no __int128.
# Env: UNW (unwind, default 24), HARNESSES and TAGS (lists; set but empty means none), C_OUT (log folder, default .work/c_module).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd); cd "$ROOT"
# AE_TOOLS_ENV: optional shell file that puts the analysis tools (clang-21, valgrind, cbmc, mull-runner-21, qemu-user,
# cross compilers) on PATH
[[ -z ${AE_TOOLS_ENV:-} ]] || . "$AE_TOOLS_ENV"
BASE=$1; T=$ROOT/.work/c/$BASE
if [[ $BASE == benma ]]; then DEF=; else DEF=-DSECP256K1_ANTI_EXFIL_ECMULT_GEN_PLAIN; fi
# ENABLE_MODULE_ANTI_EXFIL is deliberately not defined: harness.c includes the module itself after the stubs.
COMMON="-DUSE_FORCE_WIDEMUL_INT64 -DECMULT_WINDOW_SIZE=15 -DCOMB_BLOCKS=43 -DCOMB_TEETH=6 -I$T -I$T/include -I$T/src -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 $DEF"
HARN=$ROOT/validation/c_module/cbmc/harness.c
UNW=${UNW:-24}
rc_all=0
run() { # name, extra cbmc flags, log suffix
    local h=$1 extra=$2 sfx=$3 start rc=0 log
    log=${C_OUT:-$ROOT/.work/c_module}/cbmc_${BASE}_${h}${sfx}.log
    start=$(date +%s)
    nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 -p RuntimeMaxSec=900 -- \
        cbmc $COMMON $extra --function $h --bounds-check --pointer-check --signed-overflow-check --div-by-zero-check \
        --unwind $UNW --unwinding-assertions --object-bits 10 "$HARN" > "$log" 2>&1 || rc=$?
    echo "$BASE $h$sfx rc=$rc $(grep -E '^VERIFICATION' "$log" | head -1) $(( $(date +%s) - start ))s"
    if [[ $h == h_control_false_claim ]]; then [[ $rc -eq 10 ]] || rc_all=1; else [[ $rc -eq 0 ]] || rc_all=1; fi
}
for h in ${HARNESSES-h_parse33 h_ser33 h_schnorr_verify_args h_ecdsa_verify_args h_schnorr_verify_internal h_ecdsa_verify_internal h_schnorr_commit_zero h_ecdsa_commit_zero h_schnorr_sign_zero h_ecdsa_sign_zero h_control_false_claim}; do
    run $h "" ""
done
for t in ${TAGS-0 1 2 3 4 5 6 7 8}; do
    run h_hash_final "-DTAGV=$t" "_tag$t"
    run h_commit_tweak_bounds "-DTAGV=$t" "_tag$t"
done
exit $rc_all
