#!/usr/bin/env bash
# usage: fw_cfg_qemu.sh NAME  -- configure the QEMU (esp32, psram, ci, stack test) firmware build; no flashing
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TREE=$ROOT/.work/jade
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
mkdir -p "$B"
D=$B/sdkconfig.defaults.used
cp $TREE/configs/sdkconfig_qemu.defaults $D
# the same changes as tools/switch_to.sh qemu --dev --ci --psram
sed -i '/^CONFIG_ESP_WIFI_STATIC_TX_BUFFER=/d; /^CONFIG_ESP_WIFI_STATIC_TX_BUFFER_NUM=/d' $D
cat >> $D <<EOT
CONFIG_SPIRAM=y
CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY=y
CONFIG_SPIRAM_BANKSWITCH_ENABLE=n
CONFIG_SPIRAM_MEMTEST=n
CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=256
CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL=65536
CONFIG_NVS_ALLOCATE_CACHE_IN_SPIRAM=y
CONFIG_AE_STACK_TEST=y
EOT
python -B $SDK/tools/idf.py -C $TREE -B $B -G 'Unix Makefiles' -DIDF_TARGET=esp32 -DCMAKE_C_FLAGS=-fstack-usage \
  -DSDKCONFIG=$B/sdkconfig.resolved -DSDKCONFIG_DEFAULTS=$D --no-ccache reconfigure
