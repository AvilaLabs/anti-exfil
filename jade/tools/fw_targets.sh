#!/usr/bin/env bash
# Build the series for each Jade hardware target with its development configuration. No flashing. One at a time, under the cap.
set -u
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TREE=$ROOT/.work/jade
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
OUT=$ROOT/.work/fw_targets.txt
: > "$OUT"
git -C "$TREE" checkout -q series-only && git -C "$TREE" submodule update -q --init --recursive || exit 1
for name in dev_jade dev_jade_v1_1 dev_jade_v2 dev_jade_v2c; do
    B=$ROOT/.work/builds/fw-$name
    rm -rf "$B"; mkdir -p "$B"
    t0=$SECONDS
    cp "$TREE/configs/sdkconfig_$name.defaults" "$B/sdkconfig.defaults.used"
    target=$(sed -n 's/^CONFIG_IDF_TARGET="\(.*\)"/\1/p' "$B/sdkconfig.defaults.used"); target=${target:-esp32}
    if ! python -B "$SDK/tools/idf.py" -C "$TREE" -B "$B" -G 'Unix Makefiles' -DIDF_TARGET="$target" \
        -DSDKCONFIG="$B/sdkconfig.resolved" -DSDKCONFIG_DEFAULTS="$B/sdkconfig.defaults.used" --no-ccache reconfigure > "$ROOT/.work/fw-$name-cfg.log" 2>&1; then
        echo "$name target=$target configure FAILED seconds=$((SECONDS-t0))" >> "$OUT"; continue
    fi
    if flock "$ROOT/.work/build.lock" nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 make -j3 -C "$B" > "$ROOT/.work/fw-$name.log" 2>&1; then
        ota=$(python -B "$SDK/components/partition_table/gen_esp32part.py" "$B/partition_table/partition-table.bin" 2>/dev/null | awk -F, '$1=="ota_0"{print $5}')
        echo "$name target=$target ok seconds=$((SECONDS-t0)) size=$(stat -c %s "$B/jade.bin") ota_0=$ota warnings_new=$(grep -c 'warning:.*\(anti_exfil\|sign_psbt_ae\)' "$ROOT/.work/fw-$name.log") sha256=$(sha256sum "$B/jade.bin" | cut -d' ' -f1)" >> "$OUT"
    else
        echo "$name target=$target build FAILED seconds=$((SECONDS-t0))" >> "$OUT"
    fi
done
git -C "$TREE" checkout -q anti-exfil-psbt && git -C "$TREE" submodule update -q --init --recursive
cat "$OUT"
