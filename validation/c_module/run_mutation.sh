#!/usr/bin/env bash
# Mutation: Mull 0.37.0 (LLVM 21) on the module's tests, one base at a time. Usage: run_mutation.sh BASE...
# Mutations are limited to src/modules/anti_exfil/main_impl.h (mull.yml includePaths). The tests are the library's
# own tests.c with the module tests and the test seam, run as `tests -t=anti_exfil -i=16`. "No mutants" is a failure.
# Logs go to $C_OUT (default .work/c_module). MULL_IR_FRONTEND: the mull-ir-frontend-21 plugin (default: next to mull-runner-21).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd); cd "$ROOT"
# AE_TOOLS_ENV: optional shell file that puts the analysis tools (clang-21, valgrind, cbmc, mull-runner-21, qemu-user,
# cross compilers) on PATH
[[ -z ${AE_TOOLS_ENV:-} ]] || . "$AE_TOOLS_ENV"
W=$ROOT/.work/c/mull; mkdir -p "$W"; cp validation/c_module/mull.yml "$W/mull.yml"
OUTD=${C_OUT:-.work/c_module}; mkdir -p "$OUTD"
for base in "$@"; do
    ( cd "$W" && CC=clang-21 WARN="-Wno-everything" OPT=-O0 EXTRA="-grecord-command-line -fpass-plugin=${MULL_IR_FRONTEND:-$(dirname "$(command -v mull-runner-21)")/../lib/mull-ir-frontend-21}" \
        OUT="$W/$base-tests" "$ROOT/c/build.sh" "$base" tests-seam > "build_$base.log" 2>&1 )
    ( cd "$W" && nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 -p RuntimeMaxSec=1500 \
        mull-runner-21 --workers 2 --include-not-covered --reporters IDE --ide-reporter-show-killed --no-output "./$base-tests/tests" -t=anti_exfil -i=16 > "run_$base.log" 2>&1 ) || true
    sed 's/\r/\n/g' "$W/run_$base.log" | grep -vE '^\s*\[[#-]*\]' > "$OUTD/mutation_${base}_mull.log"
    n=$(grep -c "warning: \(Killed\|Survived\)" "$OUTD/mutation_${base}_mull.log" || true)
    if [[ ${n:-0} -eq 0 ]]; then echo "$base: NO MUTANTS (counts as FAILURE)"; fi
    grep -E "Mutation score|Surviving mutants" "$OUTD/mutation_${base}_mull.log" | sed "s/^/$base /"
done
