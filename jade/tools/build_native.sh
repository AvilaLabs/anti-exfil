#!/usr/bin/env bash
# usage: build_native.sh BUILD_DIR [logfile]  -- build libjade under the memory cap
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# libjade builds against the mbedtls and http_parser of an ESP-IDF v5.5 checkout
export IDF_PATH=${IDF_PATH:?set IDF_PATH to an ESP-IDF v5.5 checkout}
export TMPDIR=$ROOT/.work/tmp
B=$1
nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 make -j3 -C "$B" jade
