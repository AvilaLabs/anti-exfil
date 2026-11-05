#!/usr/bin/env bash
# Sanitizers: controls, then module tests (seam on) and the vector driver under ASan, UBSan and MSan.
# Needs c/san_build.sh BASE SAN for each base and sanitizer. Writes $C_OUT/sanitizers_log.txt (default .work/c_module).
# C_BUILD: build root (default .work/c/build).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd); cd "$ROOT"
# AE_TOOLS_ENV: optional shell file that puts the analysis tools (clang-21, valgrind, cbmc, mull-runner-21, qemu-user,
# cross compilers) on PATH
[[ -z ${AE_TOOLS_ENV:-} ]] || . "$AE_TOOLS_ENV"
BR=${C_BUILD:-.work/c/build}; OUTD=${C_OUT:-.work/c_module}
B=$BR/c7ctl; mkdir -p "$B" "$OUTD"
L=$OUTD/sanitizers_log.txt; : > "$L"
declare -A FLAG=([asan]="-fsanitize=address" [ubsan]="-fsanitize=undefined -fno-sanitize-recover=all" [msan]="-fsanitize=memory")
declare -A DEF=([asan]=CTL_ASAN [ubsan]=CTL_UBSAN [msan]=CTL_MSAN)
declare -A NEED=([asan]="heap-buffer-overflow" [ubsan]="signed integer overflow" [msan]="use-of-uninitialized-value")
fail=0
for s in asan ubsan msan; do
    clang-21 -O1 -g ${FLAG[$s]} -D${DEF[$s]} validation/c_module/san_controls.c -o $B/ctl_$s
    clang-21 -O1 -g ${FLAG[$s]} validation/c_module/san_controls.c -o $B/clean_$s
    if $B/ctl_$s >$B/ctl_$s.out 2>&1; then echo "CONTROL $s: NOT REPORTED" | tee -a "$L"; fail=1
    elif grep -q "${NEED[$s]}" $B/ctl_$s.out; then echo "CONTROL $s: fires (${NEED[$s]})" | tee -a "$L"
    else echo "CONTROL $s: failed with a different message" | tee -a "$L"; fail=1; fi
    if $B/clean_$s >/dev/null 2>&1; then echo "CLEAN $s: quiet" | tee -a "$L"; else echo "CLEAN $s: REPORTED" | tee -a "$L"; fail=1; fi
done
for base in benma zkp; do for s in asan ubsan msan; do
    T=$BR/$base-$s-tests/tests
    # the module's own tests: all anti_exfil tests, 256 iterations
    if nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 $T -t=anti_exfil -i=256 >$B/$base-$s-tests.out 2>&1; then
        echo "$base $s module tests: clean ($(tail -1 $B/$base-$s-tests.out))" | tee -a "$L"
    else echo "$base $s module tests: REPORT/FAIL" | tee -a "$L"; tail -20 $B/$base-$s-tests.out | tee -a "$L"; fail=1; fi
    if nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 python3 -B -I c/check_vectors.py --bases $base --san $s >$B/$base-$s-vec.out 2>&1; then
        echo "$base $s vector driver + seam tests: $(tail -1 $B/$base-$s-vec.out)" | tee -a "$L"
    else echo "$base $s vector driver: REPORT/FAIL" | tee -a "$L"; tail -20 $B/$base-$s-vec.out | tee -a "$L"; fail=1; fi
done; done
exit $fail
