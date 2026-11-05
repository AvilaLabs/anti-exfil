#!/usr/bin/env bash
# usage: native_cfg.sh BUILD_DIR  (configure libjade, native)
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# libjade builds against the mbedtls and http_parser of an ESP-IDF v5.5 checkout
export IDF_PATH=${IDF_PATH:?set IDF_PATH to an ESP-IDF v5.5 checkout}
export TMPDIR=$ROOT/.work/tmp
shift 0
B=${1:?}; shift
cmake -S $ROOT/.work/jade/libjade -B "$B" -G 'Unix Makefiles' \
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_MAKE_PROGRAM=/usr/bin/make -DCI=ON -DSELFCHECK= -DLOG=OFF -DCOVERAGE=OFF -DCAMERA=OFF -DJADE_DISPLAY=v2 "$@"
