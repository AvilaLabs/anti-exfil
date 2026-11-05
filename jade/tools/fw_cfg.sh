#!/usr/bin/env bash
# usage: fw_cfg.sh NAME y|n [extra sdkconfig line...]   -- configure a T-Display firmware build (no flashing)
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TREE=$ROOT/.work/jade
NAME=$1; AM=$2; shift 2
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
mkdir -p "$B" $XDG_CACHE_HOME
cp $TREE/configs/sdkconfig_display_ttgo_tdisplay.defaults $B/sdkconfig.defaults.used
sed -i '/^CONFIG_DEBUG_MODE=/d; /^CONFIG_DEBUG_UNATTENDED_CI=/d; /^CONFIG_AMALGAMATED_BUILD=/d' $B/sdkconfig.defaults.used
printf '\nCONFIG_DEBUG_MODE=n\nCONFIG_DEBUG_UNATTENDED_CI=n\nCONFIG_AMALGAMATED_BUILD=%s\n' $AM >> $B/sdkconfig.defaults.used
for l in "$@"; do echo "$l" >> $B/sdkconfig.defaults.used; done
python -B $SDK/tools/idf.py -C $TREE -B $B -G 'Unix Makefiles' -DIDF_TARGET=esp32 -DCMAKE_C_FLAGS=-fstack-usage \
  -DSDKCONFIG=$B/sdkconfig.resolved -DSDKCONFIG_DEFAULTS=$B/sdkconfig.defaults.used --no-ccache reconfigure
