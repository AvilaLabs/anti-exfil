#!/usr/bin/env bash
# residue sensitivity: the clear calls cannot be seen by the functional tests, so each clear in LIST is
# removed in turn from a COPY of the generated benma tree, the residue residue scan (O0) is rebuilt and rerun, and its count
# of full-length secrets left in dead memory is read. The unmutated build (BASELINE) must give 0. Pinned sources and
# .work/c/benma are never edited; the copy lives under $C_BUILD/sensitivity (default .work/c/build/sensitivity).
# Usage: run_residue_sensitivity.sh LIST OUTDIR [FROM TO]
#   LIST    residue_clears.txt (tab-separated: line, column, function, statement; # lines are comments)
#   OUTDIR  gets residue_sensitivity.tsv (one row per clear, plus BASELINE first unless NOBASE=1) and clear_L<line>/ per clear
#   FROM TO 1-based inclusive range of the clears in LIST (default all); used to split the run into phases
# TSV columns: line, column, function, statement, build_rc, scan_rc, control_failures, full_length_entries, max_fragment_bytes, reported
# "reported" is yes when the scan found at least one full-length secret in dead memory that the baseline does not have.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd); cd "$ROOT"
LIST=$1; OUTD=$2; FROM=${3:-1}; TO=${4:-100000}
SCOPE="nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0"
W=${C_BUILD:-$ROOT/.work/c/build}/sensitivity
rm -rf "$W"; mkdir -p "$W/build" "$OUTD"
cp -r .work/c/benma "$W/tree"
F=$W/tree/src/modules/anti_exfil/main_impl.h
cp "$F" "$W/main_impl.clean.h"
TSV=$OUTD/residue_sensitivity.tsv; : > "$TSV"

row() { # line col function statement   (line 0 = baseline, no edit)
    local line=$1 col=$2 fn=$3 st=$4 brc=0 src=0 d=$OUTD/clear_L$1
    cp "$W/main_impl.clean.h" "$F"
    if [[ $line != 0 ]]; then
        python3 - "$F" "$line" "$st" <<'PY'
import sys
f, line, st = sys.argv[1], int(sys.argv[2]), sys.argv[3]
L = open(f).read().split("\n")
assert L[line - 1].strip() == st, "line %d is %r, not %r" % (line, L[line - 1].strip(), st)
L[line - 1] = L[line - 1].replace(st, ";", 1)
open(f, "w").write("\n".join(L))
PY
        diff "$W/main_impl.clean.h" "$F" > "$OUTD/edit_L$line.diff" || true
        [[ $(grep -c '^[<>]' "$OUTD/edit_L$line.diff") -eq 2 ]] || { echo "edit of line $line changed more than one line" >&2; exit 2; }
    fi
    rm -rf "$W/build/benma-memscanO0"
    TREE=$W/tree OUT=$W/build/benma-memscanO0 OPT=-O0 WARN="-Wall -Wextra -Wno-long-long" c/build.sh benma memscan > "$OUTD/build_L$line.log" 2>&1 || brc=$?
    mkdir -p "$d"
    if [[ $brc -eq 0 ]]; then
        C_BUILD=$W/build $SCOPE python3 -B -I validation/c_module/check_secrets.py --bases benma --opts O0 --skip-constant_time --tag sensitivity --out "$d" > "$d.log" 2>&1 || src=$?
    fi
    python3 - "$line" "$col" "$fn" "$st" "$brc" "$src" "$d" >> "$TSV" <<'PY'
import sys, json, os
line, col, fn, st, brc, src, d = sys.argv[1:]
cf, nfull, frag = "NA", "NA", "NA"
p = os.path.join(d, "secrets_results.json")
if int(brc) == 0 and os.path.exists(p):
    r = json.load(open(p))
    cf = r["residue_control_failures"]; nfull = len(r.get("residue_full_length_found", []))
    frag = max([x.get("max_fragment", 0) for e in r["residue"] for x in e["rows"] if x.get("fn") in ("host_commit", "signer_commit", "signer_sign", "host_verify")] + [0])
rep = "NA" if nfull == "NA" else ("yes" if nfull > 0 else "no")
print("\t".join(str(x) for x in (line, col, fn, st, brc, src, cf, nfull, frag, rep)))
PY
    echo "L$line $fn: $(tail -1 "$TSV" | cut -f5-)"
}

[[ ${NOBASE:-0} == 1 ]] || row 0 0 BASELINE ""
n=0
while IFS=$'\t' read -r line col fn st; do
    [[ -z ${line:-} || $line == \#* ]] && continue
    n=$((n + 1))
    [[ $n -lt $FROM || $n -gt $TO ]] && continue
    row "$line" "$col" "$fn" "$st"
done < "$LIST"
