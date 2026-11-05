#!/usr/bin/env bash
# usage: fw_build.sh NAME [target]  -- build a configured firmware dir under the memory cap (no flashing)
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
NAME=$1; shift
B=$ROOT/.work/builds/fw-$NAME
# ESP-IDF v5.5 checkout, its Python environment, and the Espressif tools folder (xtensa-esp-elf 14.2.0, cmake 3.30.2)
SDK=${IDF_PATH:?set IDF_PATH to an ESP-IDF v5.5 checkout}
PYENV=${IDF_PYTHON_ENV_PATH:?set IDF_PYTHON_ENV_PATH to the Python environment of that ESP-IDF}
TOOLS=${IDF_TOOLS_PATH:?set IDF_TOOLS_PATH to the Espressif tools folder}
CC=$TOOLS/tools/xtensa-esp-elf/esp-14.2.0_20260121/xtensa-esp-elf/bin
export IDF_PATH=$SDK IDF_TOOLS_PATH=$TOOLS IDF_PYTHON_ENV_PATH=$PYENV
export IDF_COMPONENT_CHECK_NEW_VERSION=0 IDF_COMPONENT_CACHE_PATH=$ROOT/.work/component-cache
export PYTHONDONTWRITEBYTECODE=1 TMPDIR=$ROOT/.work/tmp XDG_CACHE_HOME=$ROOT/.work/xdg-cache
export PATH=$PYENV/bin:$TOOLS/tools/cmake/3.30.2/bin:$CC:/usr/bin:/bin
unset CI
nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 make -j3 -C "$B" "$@"
