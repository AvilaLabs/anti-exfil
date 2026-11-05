#!/usr/bin/env bash
# Coverage: gcov branch coverage of src/modules/anti_exfil/main_impl.h from the module tests (seam on, -i=64, -O0).
# The order-13 exhaustive binary is not merged: it is built at -O1 and its branch numbering differs. Usage: run_coverage.sh BASE. Writes $C_OUT/coverage_BASE_branches.txt (default .work/c_module). C_BUILD: build root.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd); cd "$ROOT"
BASE=$1; B=${C_BUILD:-$ROOT/.work/c/build}; export C_OUTD=${C_OUT:-$ROOT/.work/c_module}; mkdir -p "$C_OUTD"
if [[ ${SKIP_RUN:-0} != 1 ]]; then
OPT=-O0 EXTRA="--coverage" OUT=$B/$BASE-cov-tests c/build.sh "$BASE" tests-seam > /dev/null
rm -f "$B/$BASE-cov-tests"/*.gcda
nice -n 15 systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 "$B/$BASE-cov-tests/tests" -t=anti_exfil -i=64 > "$B/$BASE-cov-tests/run.log" 2>&1
fi
for d in tests; do
    ( cd "$B/$BASE-cov-$d" && rm -f *.gcov && { gcov -b -c -p -o . *.gcda > /dev/null 2>&1 || true; } )
done
python3 - "$BASE" <<'PY'
import sys, glob, re, os
base = sys.argv[1]; root = os.getcwd(); B = os.environ.get("C_BUILD", root + "/.work/c/build") + "/"; OD = os.environ["C_OUTD"]
taken, src, never_line = {}, {}, {}
for d in ("tests",):  # the exhaustive binary is built at -O1, its branch numbering differs, so it is not merged
    for f in glob.glob(B + base + "-cov-" + d + "/*anti_exfil#main_impl.h.gcov"):
        ln = None
        for line in open(f, errors="replace"):
            m = re.match(r"\s*([\d#=\-\*]+)\*?:\s*(\d+):(.*)", line)
            if m:
                ln = int(m.group(2)); src[ln] = m.group(3).strip()
                if m.group(1).strip("*") in ("#####", "====="): never_line.setdefault(ln, True)
                elif m.group(1).strip("*") not in ("-",): never_line[ln] = False
                bi = 0
                continue
            m = re.match(r"branch\s+(\d+)\s+(taken (\d+)|never executed)", line)
            if m and ln is not None:
                k = (ln, int(m.group(1)))
                t = int(m.group(3)) if m.group(3) else 0
                taken[k] = taken.get(k, 0) + t
total = len(taken); hit = sum(1 for v in taken.values() if v)
out = open(OD + "/coverage_%s_branches.txt" % base, "w")
out.write("%s: %d of %d branches taken (module main_impl.h, module tests with the seam at -O0, -i=64)\n" % (base, hit, total))
for (ln, bi), v in sorted(taken.items()):
    if not v: out.write("NOT TAKEN line %d branch %d: %s\n" % (ln, bi, src.get(ln, "")))
out.close()
print(open(OD + "/coverage_%s_branches.txt" % base).read())
PY
