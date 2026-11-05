#!/usr/bin/env bash
# Cross-architecture: cross-compiles the module tests (seam on) and the vector driver as static binaries for
# s390x (big-endian), ARM32 and ppc64le and runs them under qemu-user. Usage: run_cross_arch.sh [BASE...]
# Writes $C_OUT/cross_arch_log.txt (default .work/c_module). Build output under $C_BUILD/BASE-TARGET-{tests,driver}
# (default .work/c/build); build and run logs go to $C_OUT/logs (default .work/c).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd); cd "$ROOT"
# AE_TOOLS_ENV: optional shell file that puts the analysis tools (clang-21, valgrind, cbmc, mull-runner-21, qemu-user,
# cross compilers) on PATH
[[ -z ${AE_TOOLS_ENV:-} ]] || . "$AE_TOOLS_ENV"
BASES=${*:-benma zkp}
OUTD=${C_OUT:-.work/c_module}; LG=${C_OUT:+$C_OUT/logs}; LG=${LG:-.work/c}; mkdir -p "$OUTD" "$LG"
BR=${C_BUILD:-$ROOT/.work/c/build}
L=$OUTD/cross_arch_log.txt; : >> "$L"
declare -A GCC=([s390x]=s390x-linux-gnu-gcc [arm]=arm-linux-gnueabihf-gcc [ppc64le]=powerpc64le-linux-gnu-gcc)
declare -A QEMU=([s390x]=qemu-s390x [arm]=qemu-arm [ppc64le]=qemu-ppc64le)
fail=0
for base in $BASES; do for t in s390x arm ppc64le; do
    for k in tests-seam driver; do
        d=tests; [[ $k == driver ]] && d=driver
        CC=${GCC[$t]} WARN="-Wall -Wextra -Wno-long-long" EXTRA="-static -UUSE_ASM_X86_64" OPT=-O2 OUT=$BR/$base-$t-$d \
            c/build.sh "$base" "$k" > "$LG/cross_arch_build_${base}_${t}_$k.log" 2>&1 || { echo "$base $t $k: BUILD FAILED" | tee -a "$L"; fail=1; continue; }
    done
    file "$BR/$base-$t-driver/vector_driver" | cut -d, -f1-2 | tee -a "$L"
    if C_RUNNER=${QEMU[$t]} nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 python3 -B -I c/check_vectors.py --bases "$base" --san "$t" > "$LG/cross_arch_${base}_${t}.out" 2>&1; then
        echo "$base $t (qemu): $(tail -1 $LG/cross_arch_${base}_${t}.out)" | tee -a "$L"
    else echo "$base $t (qemu): FAILED" | tee -a "$L"; tail -15 "$LG/cross_arch_${base}_${t}.out" | tee -a "$L"; fail=1; fi
done; done
exit $fail
