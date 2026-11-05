#!/usr/bin/env bash
# Clean-build T-Display firmware from the series branch twice and once from its upstream base, and compare. No flashing.
# This differs from Jade's REPRODUCIBLE.md in that it does not use docker. Same tree path, same toolchain, build folder removed between builds.
set -u
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TREE=$ROOT/.work/jade
T=$ROOT/jade/tools
OUT=$ROOT/.work/fw_repro.txt
: > "$OUT"
one() {  # name ref
    local name=$1 ref=$2 B=$ROOT/.work/builds/fw-$1
    git -C "$TREE" checkout -q "$ref" && git -C "$TREE" submodule update -q --init --recursive || { echo "$name checkout failed" >> "$OUT"; return 1; }
    rm -rf "$B"
    local t0=$SECONDS
    bash "$T/fw_cfg.sh" "$name" y > "$ROOT/.work/fw-$name-cfg.log" 2>&1 || { echo "$name configure failed" >> "$OUT"; return 1; }
    flock "$ROOT/.work/build.lock" bash "$T/fw_build.sh" "$name" > "$ROOT/.work/fw-$name.log" 2>&1 || { echo "$name build failed" >> "$OUT"; return 1; }
    local bin=$B/jade.bin
    echo "$name ref=$(git -C "$TREE" rev-parse --short HEAD) seconds=$((SECONDS-t0)) size=$(stat -c %s "$bin") sha256=$(sha256sum "$bin" | cut -d' ' -f1)" >> "$OUT"
}
one series-a series-only
one series-b series-only
one base a59d14c2
git -C "$TREE" checkout -q anti-exfil-psbt && git -C "$TREE" submodule update -q --init --recursive
cat "$OUT"
cmp "$ROOT/.work/builds/fw-series-a/jade.bin" "$ROOT/.work/builds/fw-series-b/jade.bin" && echo "series builds identical"
