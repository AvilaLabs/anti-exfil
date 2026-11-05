#!/usr/bin/env bash
# One command: builds PR 1140, secp256k1-zkp and the module tree out of tree under
# .work/, runs the three test programs and a control build, prints a summary and
# writes results.json into the work directory.
#
# Env: PR1140_SRC, ZKP_SRC  use existing git checkouts at the pinned commits
#                           instead of fetching into .work/secp1140/
#      WORK                 build directory (default <repo>/.work/secp1140)
#      AE_RESULTS           where results.json is written (default $WORK/results.json)
#      AE_FETCH_ONLY=1      only fetch and check the two pinned checkouts, then stop
#      AE_NO_SCOPE=1        do not use a systemd-run memory scope (it is used when systemd-run works)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=${WORK:-$ROOT/.work/secp1140}

PR_URL=https://github.com/benma/secp256k1.git
PR_SHA=b4d2b22e39832d4332ce889aac40812ff1c4cbad
ZKP_URL=https://github.com/BlockstreamResearch/secp256k1-zkp.git
ZKP_SHA=45f6f0f158c5ae80a2c8a53398ea4adbf19af6dc

if [[ ${AE_IN_SCOPE:-0} != 1 ]]; then
    mkdir -p "$ROOT/.work"
    if [[ ${AE_NO_SCOPE:-0} != 1 ]] && command -v systemd-run >/dev/null 2>&1 && systemd-run --user --scope -q true >/dev/null 2>&1; then
        exec flock "$ROOT/.work/build.lock" nice -n 15 systemd-run --user --scope -q \
            -p MemoryMax=2G -p MemorySwapMax=0 -p RuntimeMaxSec=1800 --setenv=AE_IN_SCOPE=1 -- "$0" "$@"
    fi
    AE_IN_SCOPE=1 exec flock "$ROOT/.work/build.lock" nice -n 15 "$0" "$@"
fi

die() { echo "run.sh: $*" >&2; exit 2; }

# ensure_clone DIR URL SHA: a checkout of exactly SHA, fetched if absent.
ensure_clone() {
    local dir=$1 url=$2 sha=$3
    if [[ ! -d $dir/.git ]]; then
        mkdir -p "$dir"
        git init -q "$dir"
        git -C "$dir" remote add origin "$url"
        git -C "$dir" fetch -q --depth 1 origin "$sha" || die "cannot fetch $sha from $url"
        git -C "$dir" checkout -q --detach FETCH_HEAD
    fi
    [[ $(git -C "$dir" rev-parse HEAD) == "$sha" ]] || die "$dir is at $(git -C "$dir" rev-parse HEAD), want $sha"
    [[ -z $(git -C "$dir" status --porcelain) ]] || die "$dir has local changes"
}

mkdir -p "$WORK"
PR=${PR1140_SRC:-$WORK/pr1140}
ZKP=${ZKP_SRC:-$WORK/zkp}
ensure_clone "$PR" "$PR_URL" "$PR_SHA"
ensure_clone "$ZKP" "$ZKP_URL" "$ZKP_SHA"
echo "sources: PR 1140 at $PR_SHA, secp256k1-zkp at $ZKP_SHA"
[[ ${AE_FETCH_ONLY:-0} != 1 ]] || exit 0

python3 -B -I "$ROOT/scripts/gen_boundary_vectors.py" --check || die "vectors/bip-anti-exfil-boundary.json is stale; run scripts/gen_boundary_vectors.py"
python3 -B -I "$HERE/gen_tables.py" --check || die "regenerate the tables with gen_tables.py"
set +e; python3 -B -I "$ROOT/scripts/gen_boundary_vectors.py" --crosscheck > "$WORK/crosscheck.log" 2>&1; XRC=$?; set -e
echo "cross-check of the ECDSA message cases with the second implementation's arithmetic: exit $XRC"

MOD=$WORK/module-benma
python3 -B -I "$ROOT/c/apply_to_base.py" benma --src "$PR" --out "$MOD" --replace > "$WORK/apply_module.log" \
    || { cat "$WORK/apply_module.log"; die "could not apply the module to the PR 1140 tree"; }

BUILD=$WORK/build
rm -rf "$BUILD"; mkdir -p "$BUILD/control" "$WORK/logs"
make -j"${AE_JOBS:-2}" -s -f "$HERE/Makefile" BUILD="$BUILD" PR="$PR" ZKP="$ZKP" MOD="$MOD" all > "$WORK/logs/make.log" 2>&1 \
    || { tail -30 "$WORK/logs/make.log"; die "build failed (log: $WORK/logs/make.log)"; }
echo "built into $BUILD"

rcs=""
for p in pr1140 zkp module; do
    set +e; "$BUILD/test_$p" > "$WORK/logs/$p.log" 2>&1; rc=$?; set -e
    rcs="$rcs $p=$rc"
    set +e; "$BUILD/control/test_$p" > "$WORK/logs/control_$p.log" 2>&1; crc=$?; set -e
    rcs="$rcs control_$p=$crc"
done

AE_RCS="$rcs" AE_WORK="$WORK" AE_OUT="${AE_RESULTS:-$WORK/results.json}" AE_PR_SHA=$PR_SHA AE_ZKP_SHA=$ZKP_SHA \
AE_PR_URL=$PR_URL AE_ZKP_URL=$ZKP_URL AE_VEC="$ROOT/vectors/bip-anti-exfil.json" AE_CC="$(gcc --version | head -1)" \
AE_XRC=$XRC AE_BVEC="$ROOT/vectors/bip-anti-exfil-boundary.json" AE_REPO_HEAD="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)" \
python3 -B -I - <<'PY'
import collections, hashlib, json, os, re, sys

work = os.environ["AE_WORK"]
rcs = dict(x.split("=") for x in os.environ["AE_RCS"].split())
vec = hashlib.sha256(open(os.environ["AE_VEC"], "rb").read()).hexdigest()
bvec = hashlib.sha256(open(os.environ["AE_BVEC"], "rb").read()).hexdigest()


def parse(path):
    r = {"sections": collections.OrderedDict(), "failures": [], "differences": [], "not_run": [], "forced_hash_not_run": 0, "notes": 0}
    for line in open(path):
        f = line.rstrip("\n").split(" ", 3)
        if f[0] == "TALLY":
            m = re.match(r"pass=(\d+) fail=(\d+) na=(\d+)", line.split(" ", 3)[3])
            r["sections"][f[2]] = {"pass": int(m[1]), "fail": int(m[2]), "na": int(m[3])}
        elif f[0] == "FAIL":
            r["failures"].append(line[5:].rstrip("\n"))
        elif f[0] == "DIFF":
            r["differences"].append(line[5:].rstrip("\n"))
        elif f[0] == "NA":
            r["not_run"].append(line[3:].rstrip("\n"))
        elif f[0] == "SKIP":
            r["forced_hash_not_run"] += 1
        elif f[0] == "NOTE":
            r["notes"] += 1
    r["pass"] = sum(s["pass"] for s in r["sections"].values())
    r["fail"] = sum(s["fail"] for s in r["sections"].values())
    r["na"] = sum(s["na"] for s in r["sections"].values())
    return r


res = {
    "pins": {
        "pr1140": {"repo": os.environ["AE_PR_URL"], "commit": os.environ["AE_PR_SHA"]},
        "secp256k1_zkp": {"repo": os.environ["AE_ZKP_URL"], "commit": os.environ["AE_ZKP_SHA"]},
    },
    "vector_file": "vectors/bip-anti-exfil.json",
    "vector_file_sha256": vec,
    "boundary_vector_file": "vectors/bip-anti-exfil-boundary.json",
    "boundary_vector_file_sha256": bvec,
    "cross_check_second_implementation": {
        "what": "ECDSA message cases recomputed with the arithmetic of validation/second_implementations/python/secp.py (plain functions only)",
        "exit_code": int(os.environ["AE_XRC"]),
        "lines": open(work + "/crosscheck.log").read().strip().split("\n"),
    },
    "compiler": os.environ["AE_CC"],
    "repository_head_at_run": os.environ["AE_REPO_HEAD"],
    "programs": {},
    "control": {},
}
ok = int(os.environ["AE_XRC"]) == 0
expect = {"pr1140": 2, "zkp": 2, "module": 4}
for p in ("pr1140", "zkp", "module"):
    r = parse("%s/logs/%s.log" % (work, p))
    r["exit_code"] = int(rcs[p])
    res["programs"][p] = r
    if r["exit_code"] != 0 or r["fail"] != 0:
        ok = False
    c = parse("%s/logs/control_%s.log" % (work, p))
    acc = sum(s["fail"] for n, s in c["sections"].items() if n.endswith("verify_accept"))
    rej = sum(s["fail"] for n, s in c["sections"].items() if n.endswith("verify_reject"))
    good = int(rcs["control_" + p]) != 0 and c["fail"] == expect[p] + r["fail"] and acc == expect[p] // 2 and rej == expect[p] // 2
    res["control"][p] = {"exit_code": int(rcs["control_" + p]), "failures": c["failures"], "honest_tuple_refused": acc,
                         "rejection_tuple_accepted": rej, "reported_failure_as_expected": good}
    if not good:
        ok = False
res["all_programs_passed"] = all(r["exit_code"] == 0 and r["fail"] == 0 for r in res["programs"].values())
res["control_reports_failure"] = all(c["reported_failure_as_expected"] for c in res["control"].values())
open(os.environ["AE_OUT"], "w").write(json.dumps(res, indent=2) + "\n")

print()
print("== summary ==")
print("vector file sha256 %s" % vec)
print("boundary vector file sha256 %s" % bvec)
print("second-implementation cross-check of the ECDSA message cases: %s" % ("agrees" if int(os.environ["AE_XRC"]) == 0 else "DISAGREES"))
for p, label in (("pr1140", "PR 1140 (BIP340)"), ("zkp", "secp256k1-zkp (ECDSA)"), ("module", "this repository's module")):
    r = res["programs"][p]
    print("%-26s pass %3d  fail %d  not expressible %2d  exit %d" % (label, r["pass"], r["fail"], r["na"], r["exit_code"]))
    for s, t in r["sections"].items():
        print("    %-30s pass %3d  fail %d  na %2d" % (s, t["pass"], t["fail"], t["na"]))
    for x in r["failures"]:
        print("    FAIL " + x)
    for x in r["differences"]:
        print("    DIFF " + x)
print("control (a flipped byte in one honest and one rejection tuple must fail):")
for p, c in res["control"].items():
    print("    %-8s exit %d, honest tuple refused %d, rejection tuple accepted %d -> %s" % (
        p, c["exit_code"], c["honest_tuple_refused"], c["rejection_tuple_accepted"], "reports failure" if c["reported_failure_as_expected"] else "DID NOT REPORT AS EXPECTED"))
print("forced-hash cases are not run by any program (they need a hash override).")
print("RESULT: %s" % ("all tables passed, control reports failure" if ok else "FAILED, see above"))
print("wrote %s" % os.environ["AE_OUT"])
sys.exit(0 if ok else 1)
PY
