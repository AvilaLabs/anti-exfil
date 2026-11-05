#!/usr/bin/env bash
# Static tools other than CBMC: GCC -fanalyzer, Clang analyzer (scan-build) and cppcheck on one base's
# generated tree (.work/c/BASE, which includes the module), and a control per tool on the planted use-after-free
# in validation/c_module/tool_controls/uaf.c. # Usage: run_static.sh BASE OUTDIR        analysis of one base
#        run_static.sh control OUTDIR     the three controls (they must fire: finding text in the output)
# Output files in OUTDIR: module_in_tu_BASE.txt, fanalyzer_BASE.txt, scanbuild_BASE.txt, cppcheck_BASE.txt,
# control_fanalyzer.txt, control_scanbuild.txt, control_cppcheck.txt. Exit status is 0 unless a tool itself failed to run;
# findings are read by check.py, not here.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd); cd "$ROOT"
# AE_TOOLS_ENV: optional shell file that puts the analysis tools (clang-21, valgrind, cbmc, mull-runner-21, qemu-user,
# cross compilers) on PATH
[[ -z ${AE_TOOLS_ENV:-} ]] || . "$AE_TOOLS_ENV"
MODE=$1; OUTD=$2; mkdir -p "$OUTD"; OUTD=$(cd "$OUTD" && pwd)
SCOPE="nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 -p RuntimeMaxSec=1200"
if [[ $MODE == control ]]; then
    UAF=$ROOT/validation/c_module/tool_controls/uaf.c
    $SCOPE gcc -fanalyzer -O0 -c "$UAF" -o /dev/null > "$OUTD/control_fanalyzer.txt" 2>&1
    $SCOPE scan-build --use-analyzer="$(command -v clang-21)" -o "$OUTD/sb_control" clang-21 -c "$UAF" -o /dev/null > "$OUTD/control_scanbuild.txt" 2>&1
    $SCOPE cppcheck --enable=warning -q "$UAF" > "$OUTD/control_cppcheck.txt" 2>&1
    exit 0
fi
BASE=$MODE
T=$ROOT/.work/c/$BASE
DEF=; [[ $BASE == zkp ]] && DEF="-DENABLE_MODULE_ECDSA_S2C=1 -DSECP256K1_ANTI_EXFIL_ECMULT_GEN_PLAIN"
INC="-I$T -I$T/include -I$T/src"
DEFS="-DCOMB_BLOCKS=43 -DCOMB_TEETH=6 -DECMULT_WINDOW_SIZE=15 -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_ANTI_EXFIL=1 $DEF"
# the module must be in the translation unit the tools see (a count of zero means the tools looked at something else)
gcc -E -std=c89 $INC $DEFS "$T/src/secp256k1.c" 2>/dev/null | grep -c 'secp256k1_anti_exfil_schnorr_sign(' > "$OUTD/module_in_tu_$BASE.txt" || true
$SCOPE gcc -fanalyzer -O0 -std=c89 $INC $DEFS -c "$T/src/secp256k1.c" -o /dev/null > "$OUTD/fanalyzer_$BASE.txt" 2>&1
echo "exit=$?" >> "$OUTD/fanalyzer_$BASE.txt"
rm -rf "$OUTD/sb_$BASE"
$SCOPE scan-build --use-analyzer="$(command -v clang-21)" -enable-checker security.ArrayBound -enable-checker deadcode.DeadStores \
    -enable-checker security.insecureAPI.DeprecatedOrUnsafeBufferHandling -o "$OUTD/sb_$BASE" \
    clang-21 -O0 -std=c89 -w $INC $DEFS -c "$T/src/secp256k1.c" -o /dev/null > "$OUTD/scanbuild_$BASE.txt" 2>&1
echo "exit=$?" >> "$OUTD/scanbuild_$BASE.txt"
$SCOPE cppcheck --enable=warning,style,performance,portability --inline-suppr --suppress=missingIncludeSystem -q \
    --template='{file}:{line}:{severity}:{id}:{message}' $INC $DEFS "$T/src/secp256k1.c" > "$OUTD/cppcheck_$BASE.txt" 2>&1
echo "exit=$?" >> "$OUTD/cppcheck_$BASE.txt"
