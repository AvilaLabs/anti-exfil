#!/usr/bin/env bash
# Build the module on one base with explicit gcc, no cmake.
# Usage: build.sh BASE TARGET [OUTNAME]
#   BASE    benma | zkp (the tree made by apply_to_base.py under .work/c/BASE)
#   TARGET  lib        libsecp256k1.a with the module (normal build)
#           tests      the base's tests.c with the module tests (normal build)
#           tests-seam tests.c with SECP256K1_ANTI_EXFIL_TEST_SEAM
#           exh13|exh199  tests_exhaustive.c with the seam, EXHAUSTIVE_TEST_ORDER 13 or 199
#           base-tests tests.c of the pristine export, no module (base_unchanged baseline)
#           base-lib   libsecp256k1.a of the pristine export (base_unchanged sign-bytes comparison)
#           driver     vector driver linked to the normal lib
#           ctime      lib with -DVALGRIND plus the constant-time drivers (ctime_check, both schemes)
#           memscan    lib plus the memory-scan drivers (memscan_check, both schemes)
# Env: VALGRIND_ROOT (prefix with usr/include/valgrind, default: the system), OPT (default -O2), STDFLAGS (default -std=c89 -pedantic), EXTRA (more flags),
#      CC (default gcc), OUT (default .work/c/build/BASE-TARGET-OPT),
#      TREE (source tree, default .work/c/BASE; the zeroization sensitivity runs build a patched copy)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
BASE=${1:?base}; TARGET=${2:?target}
OPT=${OPT:--O2}; CC=${CC:-gcc}; EXTRA=${EXTRA:-}
STDFLAGS=${STDFLAGS:--std=c89 -pedantic}
SRC=$ROOT/.work/c/$BASE
[[ $TARGET == base-tests || $TARGET == base-lib ]] && SRC=$ROOT/.work/c/$BASE.pristine
[[ -n ${TREE:-} ]] && SRC=$TREE   # build a patched copy of the tree
[[ -d $SRC ]] || { echo "no tree $SRC; run apply_to_base.py $BASE" >&2; exit 1; }
OUT=${OUT:-$ROOT/.work/c/build/$BASE-$TARGET${OPT//-/}}
mkdir -p "$OUT"
export TMPDIR=$ROOT/.work/c/tmp; mkdir -p "$TMPDIR"

if [[ ${IN_SCOPE:-0} != 1 ]]; then
    if [[ ${AE_NO_SCOPE:-0} != 1 ]] && command -v systemd-run >/dev/null 2>&1 && systemd-run --user --scope -q true >/dev/null 2>&1; then
        exec nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 \
            -p RuntimeMaxSec=1800 --setenv=IN_SCOPE=1 -- "$0" "$@"
    fi
    IN_SCOPE=1 exec nice -n 15 "$0" "$@"
fi

DEFS="-DCOMB_BLOCKS=43 -DCOMB_TEETH=6 -DECMULT_WINDOW_SIZE=15 -DUSE_ASM_X86_64=1"
MODS="-DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1"
if [[ $BASE == benma ]]; then
    MODS="-DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 $MODS -DENABLE_MODULE_MUSIG=1 -DENABLE_MODULE_ELLSWIFT=1 -DENABLE_MODULE_SILENTPAYMENTS=1"
else
    MODS="-DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 $MODS -DENABLE_MODULE_MUSIG=1 -DENABLE_MODULE_ELLSWIFT=1 -DENABLE_MODULE_ECDSA_S2C=1 -DENABLE_MODULE_SCHNORRSIG_HALFAGG=1"
fi
[[ $TARGET == base-tests || $TARGET == base-lib ]] || MODS="$MODS -DENABLE_MODULE_ANTI_EXFIL=1"
WARN=${WARN:--Wall -Wextra -Wno-long-long -Werror}
CF="$OPT -g $STDFLAGS $WARN -Wno-unused-function -I$SRC -I$SRC/include -I$SRC/src $DEFS $MODS $EXTRA"
case $TARGET in
    ctime) CF="$CF -DVALGRIND -I${VALGRIND_ROOT:-}/usr/include" ;;
esac
case $TARGET in
    tests-seam) CF="$CF -DSECP256K1_ANTI_EXFIL_TEST_SEAM=1" ;;
    exh13) CF="$CF -DSECP256K1_ANTI_EXFIL_TEST_SEAM=1 -DEXHAUSTIVE_TEST_ORDER=13" ;;
    exh199) CF="$CF -DSECP256K1_ANTI_EXFIL_TEST_SEAM=1 -DEXHAUSTIVE_TEST_ORDER=199" ;;
esac
echo "CC=$CC flags: $CF" > "$OUT/flags.txt"

pre() { # precomputed tables are not part of the std=c89 check
    for f in precomputed_ecmult precomputed_ecmult_gen; do
        $CC $OPT -g -I"$SRC" -I"$SRC/include" -I"$SRC/src" $DEFS -c "$SRC/src/$f.c" -o "$OUT/$f.o"
    done
}
case $TARGET in
    lib|base-lib|driver|ctime|memscan)
        $CC $CF -c "$SRC/src/secp256k1.c" -o "$OUT/secp256k1.o"; pre
        ar rcs "$OUT/libsecp256k1.a" "$OUT"/secp256k1.o "$OUT"/precomputed_ecmult.o "$OUT"/precomputed_ecmult_gen.o
        if [[ $TARGET == ctime ]]; then
            VG=${VALGRIND_ROOT:-}/usr/include
            for K in SCHNORR ECDSA; do
                $CC -O0 -g -std=gnu99 -Wall -Wextra -Wno-unused-function -DP56_$K -I"$SRC/include" -I"$ROOT/validation/c_module" -I"$VG" \
                    "$ROOT/validation/c_module/ctime_check.c" "$OUT/libsecp256k1.a" -o "$OUT/ctime_check_$K"
            done
        fi
        if [[ $TARGET == memscan ]]; then
            for K in SCHNORR ECDSA; do
                $CC -O0 -g -std=gnu99 -Wall -Wextra -Wno-unused-function -DP56_$K -I"$SRC/include" -I"$ROOT/validation/c_module" \
                    "$ROOT/validation/c_module/memscan_check.c" "$OUT/libsecp256k1.a" -o "$OUT/memscan_check_$K"
            done
        fi
        if [[ $TARGET == driver ]]; then
            $CC -O2 -std=c99 -Wall -Wextra -Werror $EXTRA -I"$SRC/include" "$HERE/vector_driver.c" "$OUT/libsecp256k1.a" -o "$OUT/vector_driver"
        fi ;;
    tests|tests-seam|base-tests)
        pre
        $CC $CF "$SRC/src/tests.c" "$OUT/precomputed_ecmult.o" "$OUT/precomputed_ecmult_gen.o" -o "$OUT/tests" ;;
    exh13|exh199)
        pre
        $CC $CF "$SRC/src/tests_exhaustive.c" -o "$OUT/tests_exhaustive" ;;
    *) echo "unknown target" >&2; exit 1 ;;
esac
echo "built $OUT"
