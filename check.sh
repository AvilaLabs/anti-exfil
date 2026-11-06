#!/usr/bin/env bash
# Checks of the anti-exfil standard. Run from the root of this tree; nothing outside the tree is written
# (work files go to .work/).
#
#   ./check.sh                 default tier, no arguments:
#                                1. the vector generators in --check mode, and the independent recomputation of the vectors
#                                2. the PSBT reference suite (without the Bitcoin Core regtest tests)
#                                3. the C module on the two pinned bases: tests, vector driver, vector replay
#                                4. secp1140/run.sh: the module against PR 1140 and secp256k1-zkp
#                              Every step is followed by its control: the same check run on something it must refuse.
#   ./check.sh --regtest       the default tier plus the Bitcoin Core regtest tests. Needs BITCOIN_BIN=<folder with
#                              bitcoind and bitcoin-cli of Bitcoin Core 31.1>.
#   ./check.sh --jade          the default tier plus the Jade native build and the replay of the fixed seed vectors
#                              (vectors/bip-anti-exfil-psbt-seed.json) against it. Needs JADE_SRC=<a Blockstream/Jade
#                              checkout, submodules initialised, managed_components present, containing commit
#                              a59d14c2b39715060e6721a309a7d49bedd3ee5b>, IDF_PATH=<ESP-IDF v5.5 checkout>, cmake, and a
#                              Python (JADE_PYTHON, default python3) with wallycore, cbor2 and pyserial installed.
#   ./check.sh --long --yes    the default tier plus the long runs: the shortcut run and its mutants, the
#                              requirement mutants, the host lifecycle check, the C module run. Prints the time
#                              estimate first and does nothing without --yes. Needs the analysis tools (clang-21,
#                              valgrind, cbmc, mull-runner-21, qemu-user, cross compilers; Fil-C through FILC_HOME);
#                              AE_TOOLS_ENV=<shell file that puts them on PATH> if they are not already there.
#                              MULL_IR_FRONTEND=<the mull-ir-frontend-21 plugin> if it is not next to mull-runner-21.
#   --no-default               skip the default tier (use with the options above)
#   --groups "vectors psbt"    run only these groups of the default tier (vectors, psbt, cmodule, secp1140)
#   --verbose                  show each command's output instead of keeping it in .work/check/logs/
#
# The exit status is non-zero if any step or any control fails. Without systemd-run the jobs run under nice only;
# AE_NO_SCOPE=1 turns the 2 GB memory scope off.
set -u
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"
mkdir -p .work/check/logs
LOGS=$ROOT/.work/check/logs

TIER_DEFAULT=1; TIER_REGTEST=0; TIER_JADE=0; TIER_LONG=0; YES=0; VERBOSE=0
GROUPS_WANTED="vectors psbt cmodule secp1140"
while [[ $# -gt 0 ]]; do
    a=$1; shift
    case $a in
        --groups) GROUPS_WANTED=${1:?--groups needs a list}; shift ;;
        --regtest) TIER_REGTEST=1 ;;
        --jade) TIER_JADE=1 ;;
        --long) TIER_LONG=1 ;;
        --yes) YES=1 ;;
        --no-default) TIER_DEFAULT=0 ;;
        --verbose) VERBOSE=1 ;;
        -h|--help) sed -n '2,/^set -u/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $a (see ./check.sh --help)" >&2; exit 2 ;;
    esac
done

# ------------------------------------------------------------------------------------------ tools needed
MISSING=0
need() {   # need COMMAND "what it is for"
    command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1 ($2)" >&2; MISSING=1; }
}
need_env_dir() {   # need_env_dir VARIABLE "what it must point to"
    local v=${!1:-}
    [[ -n $v && -d $v ]] || { echo "missing setting: $1 must be set to $2" >&2; MISSING=1; }
}
need python3 "runs every script"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null || { echo "python3 is older than 3.9" >&2; MISSING=1; }
need git "fetches the two pinned libraries"
need gcc "builds the C module"
need make "builds the libraries"
need ar "builds the C module (binutils)"
need flock "serialises builds (util-linux)"
need nice "lowers the priority of the jobs (coreutils)"
need tar "unpacks the pinned library sources"
if [[ $TIER_REGTEST == 1 ]]; then
    need_env_dir BITCOIN_BIN "the folder with bitcoind and bitcoin-cli of Bitcoin Core 31.1"
    [[ -x ${BITCOIN_BIN:-/nonexistent}/bitcoind ]] || { echo "missing tool: \$BITCOIN_BIN/bitcoind" >&2; MISSING=1; }
fi
if [[ $TIER_JADE == 1 ]]; then
    need_env_dir JADE_SRC "a Blockstream/Jade checkout at (or containing) commit a59d14c2b39715060e6721a309a7d49bedd3ee5b, with submodules and managed_components"
    need_env_dir IDF_PATH "an ESP-IDF v5.5 checkout (libjade builds against its mbedtls and http_parser)"
    need cmake "configures libjade"
    JADE_PYTHON=${JADE_PYTHON:-python3}
    "$JADE_PYTHON" -c 'import wallycore, cbor2, serial' 2>/dev/null || { echo "missing: $JADE_PYTHON cannot import wallycore, cbor2 and serial (pip install wallycore cbor2 pyserial; set JADE_PYTHON to that Python)" >&2; MISSING=1; }
fi
if [[ $TIER_LONG == 1 ]]; then
    [[ -z ${AE_TOOLS_ENV:-} ]] || . "$AE_TOOLS_ENV"
    for t in clang-21 valgrind cbmc mull-runner-21 qemu-s390x cppcheck scan-build gcov s390x-linux-gnu-gcc; do
        need "$t" "analysis tool of the C module run (set AE_TOOLS_ENV to a shell file that puts it on PATH)"
    done
    [[ -x ${FILC_HOME:-/nonexistent}/build/bin/clang ]] || { echo "missing tool: Fil-C clang (set FILC_HOME so that \$FILC_HOME/build/bin/clang exists)" >&2; MISSING=1; }
fi
if [[ $MISSING == 1 ]]; then echo "check.sh: install or set the above and run it again" >&2; exit 2; fi

# ---------------------------------------------------------------------------------------------- running
SCOPE=()
if [[ ${AE_NO_SCOPE:-0} != 1 ]] && command -v systemd-run >/dev/null 2>&1 && systemd-run --user --scope -q true >/dev/null 2>&1; then
    SCOPE=(systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0)
fi
heavy() { nice -n 15 "${SCOPE[@]}" "$@"; }       # a job under the memory scope and nice
PY=(python3 -B -I)

NSTEP=0; FAILS=0
SUMMARY=()
record() { SUMMARY+=("$(printf '%-6s %-62s %-5s %5ss' "$1" "$2" "$3" "$4")"); }

# step ID "description" command...   expects exit 0
# control ID "description" command...  expects a non-zero exit (the check refuses what it must refuse)
run_logged() {   # run_logged LOG command...
    local log=$1; shift
    if [[ $VERBOSE == 1 ]]; then ( "$@" ) 2>&1 | tee "$log"; return "${PIPESTATUS[0]}"; fi
    ( "$@" ) >"$log" 2>&1
}
step() {
    local id=$1 desc=$2; shift 2
    NSTEP=$((NSTEP + 1)); local log=$LOGS/$(printf '%02d' $NSTEP)-$id.log
    printf '%s  %s\n' "$id" "$desc"; local t0=$SECONDS
    run_logged "$log" "$@"; local rc=$?; local dt=$((SECONDS - t0))
    if [[ $rc == 0 ]]; then printf '      PASS (%ss)\n' "$dt"; record "$id" "$desc" PASS "$dt"
    else printf '      FAIL (exit %s, %ss), last lines of %s\n' "$rc" "$dt" "${log#$ROOT/}"; tail -n 12 "$log" | sed 's/^/        /'; record "$id" "$desc" FAIL "$dt"; FAILS=$((FAILS + 1)); fi
    return $rc
}
control() {
    local id=$1 desc=$2; shift 2
    NSTEP=$((NSTEP + 1)); local log=$LOGS/$(printf '%02d' $NSTEP)-$id.log
    printf '%s  control: %s\n' "$id" "$desc"; local t0=$SECONDS
    run_logged "$log" "$@"; local rc=$?; local dt=$((SECONDS - t0))
    if [[ $rc != 0 && $rc != 126 && $rc != 127 ]]; then
        printf '      control OK: the check refuses it (exit %s, %ss). Its message: %s\n' "$rc" "$dt" "$(grep -v '^\s*$' "$log" | tail -n 1 | cut -c1-150)"
        record "$id" "control: $desc" PASS "$dt"
    else printf '      CONTROL FAILED: the check accepted what it must refuse (exit %s, %ss)\n' "$rc" "$dt"; record "$id" "control: $desc" FAIL "$dt"; FAILS=$((FAILS + 1)); fi
}

# a copy of the pieces the vector checks need, under .work/control/NAME, with one hex digit of a long hex value
# (after the key KEY) in vectors/FILE changed; the checks locate their files from their own path
flipped_root() {   # flipped_root NAME FILE KEY
    local r=$ROOT/.work/control/$1
    rm -rf "$r"; mkdir -p "$r/vectors" "$r/validation/second_implementations"
    cp -r scripts reference psbt c "$r"/
    cp -r validation/second_implementations/python "$r/validation/second_implementations/"
    cp vectors/* "$r/vectors/"
    rm -rf "$r/psbt/.work" "$r/c/module/.work"
    "${PY[@]}" - "$r/vectors/$2" "$3" <<'PYEOF' || return 1
import re, sys
path, key = sys.argv[1], sys.argv[2]
s = open(path, encoding="utf-8").read()
m = re.search(r'"%s": "([0-9a-f])' % re.escape(key), s)
if not m:
    sys.exit("control: no %r value to change in %s" % (key, path))
new = "0" if m.group(1) != "0" else "1"
open(path, "w", encoding="utf-8").write(s[:m.start(1)] + new + s[m.end(1):])
print("changed one digit of the first %r value in %s" % (key, path), file=sys.stderr)
PYEOF
    echo "$r"
}

# ---------------------------------------------------------------------------------------------- tier: default
step_vectors() {
    local r
    step vec-bip "vector generator: vectors/bip-anti-exfil.json is what gen_bip_vectors.py writes" heavy "${PY[@]}" scripts/gen_bip_vectors.py --check
    r=$(flipped_root ctl-bip bip-anti-exfil.json sig) && control vec-bip "gen_bip_vectors.py --check on a vector file with one digit changed" heavy "${PY[@]}" "$r/scripts/gen_bip_vectors.py" --check
    step vec-boundary "boundary vectors: vectors/bip-anti-exfil-boundary.json is what gen_boundary_vectors.py writes" heavy "${PY[@]}" scripts/gen_boundary_vectors.py --check
    r=$(flipped_root ctl-boundary bip-anti-exfil-boundary.json sig) && control vec-boundary "gen_boundary_vectors.py --check on a changed file" heavy "${PY[@]}" "$r/scripts/gen_boundary_vectors.py" --check
    step vec-psbt "PSBT vectors and seed vectors: the files are what gen_psbt_vectors.py writes (replays every vector through psbt/)" heavy "${PY[@]}" scripts/gen_psbt_vectors.py --check
    r=$(flipped_root ctl-psbt bip-anti-exfil-psbt.json signature_key) && control vec-psbt "gen_psbt_vectors.py --check on a changed file" heavy "${PY[@]}" "$r/scripts/gen_psbt_vectors.py" --check
    step vec-indep "independent recomputation of every BIP vector (own curve code, all rejection and forced-hash cases)" heavy "${PY[@]}" scripts/check_bip_vectors.py
    r=$(flipped_root ctl-indep bip-anti-exfil.json sig) && control vec-indep "check_bip_vectors.py on a vector file with one digit changed" heavy "${PY[@]}" scripts/check_bip_vectors.py --json "$r/vectors/bip-anti-exfil.json"
}

step_psbt() {
    local r
    step psbt-suite "PSBT reference host and signer: unit tests, lifecycle and known-answer tests (no regtest)" heavy "${PY[@]}" psbt/tests/run_tests.py --no-regtest
    r=$(flipped_root ctl-known bip-anti-exfil-psbt.json protocol_pk) && control psbt-suite "test_known_answers on a PSBT vector file with one digit changed" heavy "${PY[@]}" "$r/psbt/tests/test_known_answers.py"
}

c_bases() {
    set -e
    AE_FETCH_ONLY=1 secp1140/run.sh
    for b in benma zkp; do
        "${PY[@]}" c/apply_to_base.py "$b" --replace
        flock .work/build.lock c/build.sh "$b" driver
        flock .work/build.lock c/build.sh "$b" tests-seam
    done
}
step_cmodule() {
    local r
    step c-build "C module: pinned bases fetched, module applied, vector driver and module tests built (benma, zkp)" c_bases
    step c-vectors "C module: vector driver reproduces every valid vector, rejects every rejection case, module tests pass" heavy "${PY[@]}" c/check_vectors.py
    # the control: a vector file with one signature digit changed, and the test header regenerated from it
    export C_BUILD=$ROOT/.work/c/build
    r=$(flipped_root ctl-c bip-anti-exfil.json sig) && "${PY[@]}" "$r/c/gen_test_vectors.py" >/dev/null &&
        control c-vectors "c/check_vectors.py on a vector file with one signature digit changed" heavy "${PY[@]}" "$r/c/check_vectors.py"
    # the control: the driver's last result row dropped
    C_RUNNER='sh -c '\''"$0" "$@" | head -n -1'\''' \
        control c-vectors "c/check_vectors.py when the driver's last result row is missing" heavy "${PY[@]}" c/check_vectors.py
    unset C_BUILD
}

step_secp1140() {
    rm -f .work/secp1140/results.json
    step secp1140 "module against PR 1140 and secp256k1-zkp: three test programs, vector tables up to date, cross-check" secp1140/run.sh
    # run.sh builds a control copy of each test program with a flipped tuple and fails unless the control reports failure
    if [[ -f .work/secp1140/results.json ]]; then
        "${PY[@]}" - <<'PYEOF'
import json
r = json.load(open(".work/secp1140/results.json"))
c = r["control"]
print("control built by run.sh:", {k: ("reports failure" if v["reported_failure_as_expected"] else "DID NOT") for k, v in c.items()})
raise SystemExit(0 if r["control_reports_failure"] else 1)
PYEOF
        local rc=$?
        NSTEP=$((NSTEP + 1))
        if [[ $rc == 0 ]]; then record secp1140 "control: flipped honest and rejection tuple make each test program fail" PASS 0
        else record secp1140 "control: flipped honest and rejection tuple make each test program fail" FAIL 0; FAILS=$((FAILS + 1)); fi
    fi
}

if [[ $TIER_DEFAULT == 1 ]]; then
    echo "== default tier =="
    for g in $GROUPS_WANTED; do
        case $g in
            vectors) step_vectors ;;
            psbt) step_psbt ;;
            cmodule) step_cmodule ;;
            secp1140) step_secp1140 ;;
            *) echo "unknown group: $g" >&2; FAILS=$((FAILS + 1)) ;;
        esac
    done
fi

# ---------------------------------------------------------------------------------------------- tier: regtest
regtest_run() {   # regtest_run BITCOIN_BIN: run the regtest module, fail unless it ran without skipping a test
    local out rc
    out=$(BITCOIN_BIN=$1 heavy "${PY[@]}" -c 'import sys, unittest; sys.path.insert(0, "psbt/tests"); unittest.main(module="test_regtest", argv=["x", "-v"])' 2>&1); rc=$?
    printf '%s\n' "$out"
    [[ $rc == 0 ]] && ! grep -qi 'skipped' <<<"$out" && grep -q '^OK' <<<"$out"
}
if [[ $TIER_REGTEST == 1 ]]; then
    echo "== regtest tier (Bitcoin Core at $BITCOIN_BIN) =="
    step regtest "PSBT reference host and signer spend every form on a regtest node (versions 0 and 2); no test may be skipped" regtest_run "$BITCOIN_BIN"
    control regtest "the same tests with BITCOIN_BIN pointing nowhere (they skip, and the check treats a skip as a failure)" regtest_run /nonexistent-bitcoin-bin
fi

# ------------------------------------------------------------------------------------------------ tier: jade
jade_prepare() {
    set -e
    local pin=a59d14c2b39715060e6721a309a7d49bedd3ee5b
    rm -rf .work/jade; mkdir -p .work
    cp -a "$JADE_SRC" .work/jade
    git -C .work/jade checkout -q --detach "$pin"
    git -C .work/jade submodule update -q --init --recursive
    [[ $(git -C .work/jade rev-parse HEAD) == "$pin" ]]
    git -C .work/jade -c user.name=check -c user.email=check@localhost am -q "$ROOT"/jade/patches/test-build-only/*.patch "$ROOT"/jade/patches/series/*.patch
}
jade_build() {
    set -e
    rm -rf .work/jade-build
    flock .work/build.lock jade/tools/native_cfg.sh "$ROOT/.work/jade-build"
    flock .work/build.lock jade/tools/build_native.sh "$ROOT/.work/jade-build"
    find .work/jade-build -name libjade.so | grep -q .
}
jade_replay() {
    local lib; lib=$(dirname "$(find "$ROOT/.work/jade-build" -name libjade.so | head -n 1)")
    LD_LIBRARY_PATH=$lib heavy "$JADE_PYTHON" -B jade/check_seed_vectors.py --report .work/check/jade_seed_report.json
}
if [[ $TIER_JADE == 1 ]]; then
    echo "== jade tier (Jade from $JADE_SRC) =="
    step jade-tree "Jade checkout copied to .work/jade at the pinned commit, patch series applied" jade_prepare
    step jade-build "libjade built natively from the patched tree" jade_build
    step jade-replay "fixed seed vectors replayed against libjade (the check also flips a byte of an expected value as its control)" jade_replay
fi

# ------------------------------------------------------------------------------------------------ tier: long
HEAVY_STR="nice -n 15 ${SCOPE[*]}"
long_commands() {   # id | estimate in minutes | command
    cat <<EOF
bases|1|AE_FETCH_ONLY=1 secp1140/run.sh
shortcuts|45|$HEAVY_STR ${PY[*]} validation/shortcuts/check.py --run --out .work/long/shortcuts.json --workers 3
shortcut-mutants|60|$HEAVY_STR ${PY[*]} validation/shortcuts/check_mutants.py --base .work/long/shortcuts.json --out .work/long/shortcuts_mutants.json --workers 3
requirements|20|$HEAVY_STR ${PY[*]} validation/requirements/check.py --run --workers 3 --out .work/long/requirements.json
lifecycle|35|$HEAVY_STR ${PY[*]} validation/host_lifecycle/check.py --adapter host_adapter:factory
c-module-a|20|${PY[*]} validation/c_module/run.py a
c-module-b|25|${PY[*]} validation/c_module/run.py b
c-module-c|10|${PY[*]} validation/c_module/run.py c
c-module-d|40|${PY[*]} validation/c_module/run.py d
c-module-e|45|${PY[*]} validation/c_module/run.py e
c-module-f|15|${PY[*]} validation/c_module/run.py f
c-module-g1|20|${PY[*]} validation/c_module/run.py g1
c-module-g2|20|${PY[*]} validation/c_module/run.py g2
c-module-h|15|${PY[*]} validation/c_module/run.py h
EOF
}
if [[ $TIER_LONG == 1 ]]; then
    echo "== long tier =="
    total=0
    while IFS='|' read -r id est cmd; do total=$((total + est)); printf '  %-14s about %3s min   %s\n' "$id" "$est" "$cmd"; done < <(long_commands)
    printf '  estimated wall time about %d minutes (%d.%d hours), at most 3 workers, 2 GB memory scope per job;\n' "$total" $((total / 60)) $((total % 60 / 6))
    echo "  the figures are measured times and vary with the machine. The C module run writes to .work/c_module/,"
    echo "  the others to .work/long/ and .work/. Run it with --yes to start."
    if [[ $YES != 1 ]]; then echo "  not started: --yes is required"; FAILS=$((FAILS + 1)); record long "long tier not started (--yes missing)" FAIL 0
    else
        mkdir -p .work/long
        while IFS='|' read -r id est cmd; do
            step "$id" "long run $id (about $est min)" bash -c "cd '$ROOT' && $cmd"
        done < <(long_commands)
        # the verdict of the C module run
        step c-module-check "C module run: verdict over all phases" "${PY[@]}" validation/c_module/check.py .work/c_module --classes validation/c_module/classes.tsv
    fi
fi

# ---------------------------------------------------------------------------------------------- summary
echo
echo "== summary =="
printf '%-6s %-62s %-5s %6s\n' step what result time
for l in "${SUMMARY[@]}"; do echo "$l"; done
if [[ $FAILS == 0 ]]; then echo "RESULT: all steps and controls passed"; exit 0; fi
echo "RESULT: $FAILS step(s) or control(s) failed (logs in .work/check/logs/)"
exit 1
