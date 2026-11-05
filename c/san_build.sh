#!/usr/bin/env bash
# sanitizers helper: builds the module tests (seam on) and the vector driver with clang-21 and one sanitizer.
# Usage: san_build.sh BASE SAN   (SAN = asan | ubsan | msan)  Output .work/c/build/BASE-SAN-{tests,driver}
# Inline asm is off (-UUSE_ASM_X86_64) because the sanitizers cannot see through it; this changes the field code, so
# the sanitizer runs are on the portable C field arithmetic. Tests and driver run with ASAN_OPTIONS etc. set by the caller.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/.." && pwd)
BASE=$1; SAN=$2
case $SAN in
    asan) FL="-fsanitize=address -fno-omit-frame-pointer" ;;
    ubsan) FL="-fsanitize=undefined -fno-sanitize-recover=all" ;;
    msan) FL="-fsanitize=memory -fsanitize-memory-track-origins=1 -fno-omit-frame-pointer" ;;
esac
# AE_TOOLS_ENV: optional shell file that puts clang-21 (with the sanitizer runtimes) on PATH
[[ -z ${AE_TOOLS_ENV:-} ]] || . "$AE_TOOLS_ENV"
export CC=clang-21
export WARN="-Wall -Wextra -Wno-long-long -Wno-unknown-warning-option"
export STDFLAGS="-std=c89 -pedantic"
O=${C_BUILD:-$ROOT/.work/c/build}
OPT=-O1 EXTRA="$FL -UUSE_ASM_X86_64" OUT=$O/$BASE-$SAN-tests "$HERE/build.sh" "$BASE" tests-seam
OPT=-O1 EXTRA="$FL -UUSE_ASM_X86_64" OUT=$O/$BASE-$SAN-driver "$HERE/build.sh" "$BASE" driver
