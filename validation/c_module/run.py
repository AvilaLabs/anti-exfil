#!/usr/bin/env python3
"""Driver of the C module acceptance runs. Runs one phase and writes
.work/c_module/<phase>/ with the raw outputs and phase.json.

usage: run.py PHASE [--dry-run] [--overwrite]

| Phase | Checks | What it does |
|---|---|---|
| a | vectors, base_unchanged, source_rules | the module reproduces the vectors on both bases, the base libraries are unchanged by the module, source rules |
| b | differential | 10,000 inputs per scheme, module against the Python reference |
| c | constant_time, residue | Valgrind constant-time runs and the secret-residue scan |
| d | sanitizers | ASan, UBSan, MSan and Fil-C |
| e | coverage, exhaustive, static | branch coverage, exhaustive group tests, static analysis and CBMC |
| f | mutation | Mull mutation tests and the review of each survivor |
| g1, g2 | residue (sensitivity) | removes each of the 54 zeroization calls in turn; g1 takes clears 1-27, g2 takes 28-54 |
| h | cross_arch | s390x, ARM32 and ppc64le under qemu-user |

`g` (all 54 clears in one phase) is refused on its estimate; use g1 and g2.

Each phase prints its estimate first (with the source of each figure) and stops without running if the estimate is
over 55 minutes. Before and after the phase it hashes c/module, both pinned bases (git HEAD, clean state, the
generated trees and the pristine exports) and the scripts and inputs the phase uses; a change inside the phase, or
against the other phases, is an ERROR (check.py compares). The existing scripts are run as they are; they are given
$C_BUILD (a build folder under .work/c/run_build/<phase>) and $C_OUT (the phase folder).
Heavy commands run under nice and a 2G systemd scope; build.sh and the run_*.sh scripts set the scope themselves."""
import argparse, datetime, difflib, fnmatch, gzip, hashlib, importlib.util, json, os, pathlib, re, shlex, shutil, signal, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = ROOT / "validation/c_module"
REV = ROOT / "c"
WORK = ROOT / ".work/c"
BASES = ("benma", "zkp")
LIMIT_MIN = 55.0
SCOPE = ["nice", "-n", "15", "systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=2G", "-p", "MemorySwapMax=0"]
SEED = "00112233445566778899aabbccddeeff"
FILC_WARN = "-Wall -Wextra -Wno-long-long -Wno-unknown-warning-option"

# ---------------------------------------------------------------------------------------------- estimates
# (label, seconds, source). Build figures are the measured time from flags.txt to the last file of each build folder.
EST = {
    "a": [
        ("builds, benma: lib 22, base-lib 22, driver 21, tests-seam 80, base-tests 36, tests 77", 258, "measured build times"),
        ("builds, zkp: lib 14, base-lib 14, driver 14, tests-seam 60, base-tests 28, tests 62", 192, "measured build times"),
        ("base and module suites, both bases (-i=16)", 250, "measured: 69.6+70.9+53.3+56.6 s"),
        ("vectors (driver runs, seam tests -i=64)", 60, "not timed alone; the 12 sanitizer vector and test runs took 75 s"),
        ("seam_compare, 2 bases (2 object compiles each)", 72, "lib build times above, not timed separately"),
        ("base_sample (4 compiles and runs), glue, pin, vendor and source_rules checks, hashing", 40, "assumed"),
    ],
    "b": [
        ("driver builds (benma 21, zkp 14)", 35, "measured build times"),
        ("differential: 10,000 inputs x 2 schemes, C 13.9+16.2 s, Python reference 412.9+481.0 s", 924, "measured"),
    ],
    "c": [
        ("ctime builds O0/O2/Os (benma 5+20+9, zkp 5+14+9)", 62, "measured build times"),
        ("memscan builds O0/O2/Os (benma 5+21+9, zkp 5+13+9)", 62, "measured build times"),
        ("constant_time Valgrind runs, 12 configurations", 64, "measured: sum of the run times"),
        ("residue scan, 36 case/base/opt runs", 120, "measured"),
    ],
    "d": [
        ("sanitizer builds, benma: asan 56+24, ubsan 45+21, msan 106+45", 297, "measured build times"),
        ("sanitizer builds, zkp: asan 51+20, ubsan 31+11, msan 98+40", 251, "measured build times"),
        ("run_sanitizers.sh: 3 controls and 12 test and vector runs", 75, "measured"),
        ("Fil-C builds: benma tests 520 + driver 101, zkp tests 438 + driver 47", 1106, "measured build times; tests.c takes 6 to 7 minutes"),
        ("Fil-C runs and control", 30, "measured: module tests 1.4 s and 0.9 s; the rest assumed"),
    ],
    "e": [
        ("coverage builds (benma 25, zkp 24)", 49, "measured build times"),
        ("coverage runs, -i=64 at -O0 with coverage, and gcov, 2 bases", 140, "assumed: 60 s run + 10 s gcov per base"),
        ("exhaustive builds, order 13 (benma 15, zkp 9)", 24, "measured build times"),
        ("exhaustive order 13 runs, 2 x 419.5 s", 839, "measured for benma (6m59.5s); zkp taken as equal"),
        ("static: GCC -fanalyzer, 2 bases", 110, "measured: 55 s per base"),
        ("static: scan-build, 2 bases", 336, "measured: 136 s for benma, 200 s for zkp"),
        ("static: cppcheck 2 bases and 3 tool controls", 35, "measured: 7.2 s per base; controls assumed 15 s"),
        ("static: CBMC, both bases: 25 runs at about 15 s and the 4 zero harnesses at about 260 s each base", 1268, "measured"),
    ],
    "f": [
        ("Mull, benma then zkp (build about 80 s + run, 4m27s measured for zkp)", 700, "measured: 'Total execution time: 4m27.1s' for zkp"),
        ("run_mutation_pairs.sh: 4 builds of tests-seam (80 s) and 4 test runs (about 20 s)", 400, "build time measured; run time assumed"),
        ("mutation_review.py", 5, "assumed"),
    ],
    "g1": [("baseline and 27 clears, 90 s each: copy-tree rebuild of memscan -O0 plus the residue scan", 28 * 90, "measured: about 96 s per clear with the constant_time runs included, which are now skipped; 90 s kept")],
    "g2": [("baseline and 27 clears, 90 s each", 28 * 90, "as g1")],
    "g": [("baseline and 54 clears, 90 s each", 55 * 90, "as g1; refused, use g1 and g2")],
    "h": [("run_cross_arch.sh, both bases: 3 cross builds of tests-seam and driver, 3 qemu runs each", 912, "measured: about 7.5 minutes for benma and 8 for zkp")],
}

ITEMS = {"a": "vectors base_unchanged source_rules", "b": "differential", "c": "constant_time residue", "d": "sanitizers", "e": "coverage exhaustive static", "f": "mutation", "g1": "residue sensitivity (clears 1-27)",
         "g2": "residue sensitivity (clears 28-54)", "g": "residue sensitivity (all 54)", "h": "cross_arch"}
PHASES = ["a", "b", "c", "d", "e", "f", "g", "g1", "g2", "h"]
LIST_FILE = HERE / "residue_clears.txt"

# ---------------------------------------------------------------------------------------------- hashing
def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_hash(root):
    """sha256 over the sorted (relative path, file sha256) pairs below root; symlinks by target."""
    root = pathlib.Path(root)
    h = hashlib.sha256()
    n = 0
    for dp, dn, fn in os.walk(root):
        dn.sort()
        for f in sorted(fn):
            p = pathlib.Path(dp) / f
            rel = p.relative_to(root).as_posix()
            d = ("link:" + os.readlink(p)) if p.is_symlink() else sha_file(p)
            h.update(rel.encode() + b"\0" + d.encode() + b"\n")
            n += 1
    return {"sha256": h.hexdigest(), "files": n}


def load_apply_to_base():
    sp = importlib.util.spec_from_file_location("apply_to_base", REV / "apply_to_base.py")
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def git(src, *args):
    return subprocess.run(["git", "-C", str(src)] + list(args), capture_output=True, text=True)


def base_hash(b, atb):
    cfg = atb.BASES[b]
    src = pathlib.Path(os.environ.get("AE_%s_SOURCE" % b.upper(), cfg["src"]))
    head = git(src, "rev-parse", "HEAD").stdout.strip()
    dirty = git(src, "status", "--porcelain", "--untracked-files=no").stdout.strip().splitlines()
    return {"pin": cfg["pin"], "source": str(src), "head": head, "head_is_pin": head == cfg["pin"], "dirty": dirty,
            "generated_tree": tree_hash(WORK / b), "pristine_tree": tree_hash(WORK / (b + ".pristine"))}


COMMON = ["validation/c_module/run.py", "c/build.sh", "c/apply_to_base.py",
          "jade/patches/series/0001-libwally-core-vendor-the-anti-exfil-secp256k1-module.patch"]
PHASE_FILES = {
    "a": ["c/check_vectors.py", "c/seam_compare.py", "c/vector_driver.c", "c/gen_test_vectors.py", "validation/c_module/base_sample.c",
          "vectors/bip-anti-exfil.json"],
    "b": ["validation/c_module/check_differential.py", "c/vector_driver.c", "vectors/bip-anti-exfil.json",
          "reference/anti_exfil.py"],
    "c": ["validation/c_module/check_secrets.py", "validation/c_module/secrets_scan.py", "validation/c_module/secrets_common.h",
          "validation/c_module/ctime_check.c", "validation/c_module/memscan_check.c", "validation/c_module/secrets_common.h"],
    "d": ["validation/c_module/run_sanitizers.sh", "c/san_build.sh", "validation/c_module/san_controls.c", "c/check_vectors.py",
          "c/vector_driver.c", "validation/c_module/tool_controls/farptr.c"],
    "e": ["validation/c_module/run_coverage.sh", "validation/c_module/cbmc/run_cbmc.sh", "validation/c_module/cbmc/harness.c",
          "validation/c_module/run_static.sh", "validation/c_module/tool_controls/uaf.c"],
    "f": ["validation/c_module/run_mutation.sh", "validation/c_module/mull.yml", "validation/c_module/mutation_review.py",
          "validation/c_module/run_mutation_pairs.sh"],
    "g": ["validation/c_module/run_residue_sensitivity.sh", "validation/c_module/residue_clears.txt", "validation/c_module/check_secrets.py",
          "validation/c_module/secrets_scan.py", "validation/c_module/secrets_common.h", "validation/c_module/memscan_check.c", "validation/c_module/secrets_common.h"],
    "h": ["validation/c_module/run_cross_arch.sh", "c/check_vectors.py", "c/vector_driver.c"],
}
PHASE_FILES["g1"] = PHASE_FILES["g2"] = PHASE_FILES["g"]


def input_hashes(phase, atb):
    files = {}
    for rel in COMMON + PHASE_FILES[phase]:
        p = ROOT / rel
        files[rel] = sha_file(p) if p.exists() else "MISSING"
    return {"module": tree_hash(REV / "module"), "benma": base_hash("benma", atb), "zkp": base_hash("zkp", atb), "files": files}


def hashes_equal(a, b):
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ---------------------------------------------------------------------------------------------- environment
def load_env():
    # AE_TOOLS_ENV: optional shell file that puts the analysis tools (clang-21, valgrind, cbmc, mull-runner-21, qemu-user,
    # cross compilers, Fil-C through FILC_HOME) on PATH
    env_sh = pathlib.Path(os.environ["AE_TOOLS_ENV"]) if os.environ.get("AE_TOOLS_ENV") else None
    env = dict(os.environ)
    if env_sh and env_sh.exists():
        out = subprocess.run(["bash", "-c", '. "%s" && env -0' % env_sh], capture_output=True).stdout.decode(errors="replace")
        env = dict(kv.split("=", 1) for kv in out.split("\0") if "=" in kv)
    return env


def first_line(argv, env):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60)
        return ((p.stdout or p.stderr).strip().splitlines() or ["(no output)"])[0]
    except Exception as e:  # noqa: BLE001 (any failure is recorded as text)
        return "unavailable: %s" % e


def tool_versions(phase, env):
    fil = env.get("FILC_HOME", "") + "/build/bin/clang"
    vg_root = pathlib.Path(env.get("VALGRIND_ROOT", "/"))        # prefix of a valgrind install (default: the system)
    vg_env = dict(env, VALGRIND_LIB=str(vg_root / "usr/libexec/valgrind"), PATH=str(vg_root / "usr/bin") + ":" + env.get("PATH", ""))
    want = {"python3": ["python3", "--version"], "gcc": ["gcc", "--version"], "git": ["git", "--version"]}
    if phase == "c" or phase.startswith("g"):
        want["valgrind"] = ["valgrind", "--version"]
    if phase == "d":
        want.update({"clang-21": ["clang-21", "--version"], "filc-clang": [fil, "--version"]})
    if phase == "e":
        want.update({"gcov": ["gcov", "--version"], "clang-21": ["clang-21", "--version"], "scan-build": ["scan-build", "--help"], "cppcheck": ["cppcheck", "--version"], "cbmc": ["cbmc", "--version"]})
    if phase == "f":
        want.update({"clang-21": ["clang-21", "--version"], "mull-runner-21": ["mull-runner-21", "--version"]})
    if phase == "h":
        want.update({"s390x-gcc": ["s390x-linux-gnu-gcc", "--version"], "arm-gcc": ["arm-linux-gnueabihf-gcc", "--version"], "ppc64le-gcc": ["powerpc64le-linux-gnu-gcc", "--version"],
                     "qemu-s390x": ["qemu-s390x", "--version"], "qemu-arm": ["qemu-arm", "--version"], "qemu-ppc64le": ["qemu-ppc64le", "--version"]})
    return {k: first_line(v, vg_env if k == "valgrind" else env) for k, v in want.items()}


# ---------------------------------------------------------------------------------------------- the phase object
class Stopped(Exception):
    pass


def _term(signum, frame):
    raise Stopped("signal %d" % signum)


class Phase:
    def __init__(self, name, dry, env):
        self.name, self.dry = name, dry
        self.out = ROOT / ".work" / "c_module" / name
        self.build = WORK / "run_build" / name
        self.cmds, self.notes, self.proc = [], [], None
        self.env = dict(env, C_BUILD=str(self.build), C_OUT=str(self.out))

    def say(self, s):
        print(s, flush=True)

    def step(self, label, argv, wrap=True, ok=(0,), env=None, timeout=None, log=None):
        argv = [str(a) for a in argv]
        full = (SCOPE + argv) if wrap else argv
        if self.dry:
            extra = " ".join("%s=%s" % (k, shlex.quote(v)) for k, v in (env or {}).items())
            self.say("  [%s] %s%s" % (label, (extra + " ") if extra else "", shlex.join(full)))
            return 0
        rec = {"label": label, "argv": argv, "wrapped": wrap, "env": env or {}, "ok_rc": list(ok), "log": (log or label + ".log")}
        envx = dict(self.env)
        envx.update(env or {})
        t0 = time.time()
        with open(self.out / rec["log"], "wb") as f:
            self.proc = subprocess.Popen(full, stdout=f, stderr=subprocess.STDOUT, cwd=str(ROOT), env=envx, start_new_session=True)
            try:
                rc = self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait()
                rc = -9
                rec["timeout"] = True
            except BaseException:  # stopped by a signal: take the running command down with the phase
                try:
                    os.killpg(self.proc.pid, signal.SIGTERM)
                    self.proc.wait(timeout=30)
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                self.proc = None
        rec.update(rc=rc, seconds=round(time.time() - t0, 1), ok=rc in ok)
        self.cmds.append(rec)
        self.say("  [%s] rc=%s %.0fs%s" % (label, rc, rec["seconds"], "" if rec["ok"] else "  UNEXPECTED"))
        return rc

    def build_step(self, base, target, name, opt="-O2", env=None, ok=(0,)):
        e = {"OPT": opt, "OUT": str(self.build / name)}
        e.update(env or {})
        rc = self.step("build_" + name, [REV / "build.sh", base, target], wrap=False, env=e, ok=ok)
        if not self.dry:
            fl = self.build / name / "flags.txt"
            if fl.exists():
                (self.out / "flags").mkdir(exist_ok=True)
                shutil.copy(fl, self.out / "flags" / (name + ".txt"))
        return rc

    def write_json(self, name, obj):
        if self.dry:
            self.say("  would write %s" % name)
            return
        (self.out / name).write_text(json.dumps(obj, indent=1, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------------------------- in-process checks (phase a)
def jade_vendor_check(P):
    """The module as Jade vendors it: patch 0001 of jade/patches/series creates two of the module's files verbatim
    (include/secp256k1_anti_exfil.h and src/modules/anti_exfil/main_impl.h) under components/libwally-core/anti_exfil/.
    Their added lines, with the leading '+' removed, are compared byte for byte with c/module. The patch also
    adds forwarding headers and a wrapper (combined_ae.c), which are Jade glue and not module files; tests_impl.h,
    tests_vectors.h and tests_exhaustive_impl.h are not vendored. No comparison with .work/jade is needed."""
    patch = ROOT / "jade/patches/series/0001-libwally-core-vendor-the-anti-exfil-secp256k1-module.patch"
    P.say("  jade vendor check against %s" % patch.name)
    if P.dry:
        return
    lines = patch.read_bytes().split(b"\n")
    want = {"include/secp256k1_anti_exfil.h": b"components/libwally-core/anti_exfil/include/secp256k1_anti_exfil.h",
            "src/modules/anti_exfil/main_impl.h": b"components/libwally-core/anti_exfil/src/modules/anti_exfil/main_impl.h"}
    res = {"patch": patch.name, "patch_sha256": sha_file(patch), "method": "added lines of the new-file hunks in patch 0001 compared with c/module", "files": {}}
    for rel, tail in want.items():
        got, i, found = [], 0, False
        while i < len(lines):
            if lines[i].startswith(b"diff --git") and lines[i].endswith(b"b/" + tail):
                found = True
                i += 1
                while not lines[i].startswith(b"@@"):
                    i += 1
                i += 1
                while i < len(lines) and not lines[i].startswith(b"diff --git") and not lines[i].startswith(b"-- "):
                    if lines[i].startswith(b"+"):
                        got.append(lines[i][1:])
                    i += 1
                break
            i += 1
        mod = (REV / "module" / rel).read_bytes()
        data = b"\n".join(got) + b"\n"
        res["files"][rel] = {"found_in_patch": found, "equal": found and data == mod, "module_sha256": hashlib.sha256(mod).hexdigest(),
                             "vendored_sha256": hashlib.sha256(data).hexdigest()}
    res["all_equal"] = all(v["equal"] for v in res["files"].values())
    P.write_json("jade_vendor.json", res)
    P.say("    equal: %s" % res["all_equal"])


def pin_check(P, b, atb):
    """The pristine export is the pinned commit: every file's git blob id equals the one in `git ls-tree -r HEAD`, no extras."""
    P.say("  pin check %s" % b)
    if P.dry:
        return
    cfg = atb.BASES[b]
    src = pathlib.Path(os.environ.get("AE_%s_SOURCE" % b.upper(), cfg["src"]))
    head = git(src, "rev-parse", "HEAD").stdout.strip()
    tree = {}
    for l in git(src, "ls-tree", "-r", "HEAD").stdout.splitlines():
        meta, path = l.split("\t", 1)
        mode, typ, sha = meta.split()
        if typ == "blob" and mode != "120000":
            tree[path] = sha
    pr = WORK / (b + ".pristine")
    present = sorted(p.relative_to(pr).as_posix() for p in pr.rglob("*") if p.is_file() and not p.is_symlink())
    bad = []
    ph = subprocess.run(["git", "hash-object", "--stdin-paths"], input="\n".join(str(pr / x) for x in present) + "\n", capture_output=True, text=True, cwd=str(pr))
    got = dict(zip(present, ph.stdout.split()))
    for path, sha in tree.items():
        if got.get(path) != sha:
            bad.append(path)
    extra = [x for x in present if x not in tree]
    P.write_json("pin_check_%s.json" % b, {"base": b, "pin": cfg["pin"], "head": head, "head_is_pin": head == cfg["pin"], "tracked_files": len(tree),
                                            "mismatched": bad[:50], "mismatched_count": len(bad), "extra_in_pristine": extra[:50], "ok": head == cfg["pin"] and not bad and not extra})


ALLOWED_GLUE = [r"^$", r"^#ifdef ENABLE_MODULE_ANTI_EXFIL$", r"^#endif$", r'^# ?include "modules/anti_exfil/(main|tests|tests_exhaustive)_impl\.h"$',
                r"^# define SECP256K1_ANTI_EXFIL_ECMULT_GEN_PLAIN 1$", r"^\s+MAKE_TEST_MODULE\(anti_exfil\),$", r"^\s+test_exhaustive_anti_exfil\(ctx, group\);$"]


def glue_check(P, b):
    """base_unchanged: the generated tree differs from the pristine export only by the three glue files, only by added include/registration
    lines, and the five overlay files are byte-equal to c/module."""
    P.say("  base_unchanged glue check %s" % b)
    if P.dry:
        return
    tree, pr = WORK / b, WORK / (b + ".pristine")
    def files(r):
        return {p.relative_to(r).as_posix() for p in r.rglob("*") if p.is_file() and p.name not in ("GLUE.diff", "GLUE.txt")}
    a, c = files(tree), files(pr)
    overlay = ["include/secp256k1_anti_exfil.h", "src/modules/anti_exfil/main_impl.h", "src/modules/anti_exfil/tests_impl.h",
               "src/modules/anti_exfil/tests_vectors.h", "src/modules/anti_exfil/tests_exhaustive_impl.h"]
    new = sorted(a - c)
    removed = sorted(c - a)
    changed = sorted(x for x in a & c if (tree / x).read_bytes() != (pr / x).read_bytes())
    added, viol, diffs = [], [], []
    for x in changed:
        d = list(difflib.unified_diff((pr / x).read_text().splitlines(), (tree / x).read_text().splitlines(), "a/" + x, "b/" + x, lineterm=""))
        diffs += d
        for l in d:
            if l.startswith("+++") or l.startswith("---") or l.startswith("@@"):
                continue
            if l.startswith("-"):
                viol.append("%s: removed line %r" % (x, l[1:]))
            elif l.startswith("+"):
                added.append("%s: %s" % (x, l[1:]))
                if not any(re.match(r, l[1:]) for r in ALLOWED_GLUE):
                    viol.append("%s: added line not build glue or an include: %r" % (x, l[1:]))
    overlay_eq = {x: (tree / x).read_bytes() == (REV / "module" / x).read_bytes() for x in overlay}
    res = {"base": b, "changed_existing_files": changed, "expected_changed": ["src/secp256k1.c", "src/tests.c", "src/tests_exhaustive.c"],
           "new_files": new, "expected_new": sorted(overlay), "removed_files": removed, "added_lines": added, "violations": viol, "overlay_equals_module": overlay_eq}
    res["ok"] = (changed == res["expected_changed"] and new == res["expected_new"] and not removed and not viol and all(overlay_eq.values()))
    P.write_json("glue_%s.json" % b, res)
    (P.out / ("glue_%s.diff" % b)).write_text("\n".join(diffs) + "\n")
    P.say("    ok: %s (%d changed existing files, %d added lines)" % (res["ok"], len(changed), len(added)))


def strip_c(src):
    """Blank out comments and string/char literals, keeping the newlines, so token searches see code only."""
    def blank(m):
        return re.sub(r"[^\n]", " ", m.group(0))
    return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', blank, src, flags=re.S)


def find_banned(text):
    code = strip_c(text)
    return [{"token": m.group(1), "line": code.count("\n", 0, m.start()) + 1}
            for m in re.finditer(r"\b(malloc|calloc|realloc|free|alloca|__builtin_alloca|aligned_alloc|posix_memalign|strdup)\b", code)]


def find_unchecked(text, names):
    """(number of calls of the named functions, the calls whose result is not used: a call that starts a statement,
    follows `)` as in `(void)f()` or `if (c) f()`, or follows else/do)."""
    code = strip_c(text)
    lines = text.split("\n")
    bad, n = [], 0
    for m in re.finditer(r"\b(" + "|".join(names) + r")\s*\(", code):
        n += 1
        k = m.start() - 1
        while k >= 0 and code[k] in " \t\r\n":
            k -= 1
        prev = code[k] if k >= 0 else ";"
        word = re.search(r"(\w+)$", code[:k + 1])
        bare = prev in ";{}" or prev == ")" or (word and word.group(1) in ("else", "do"))
        if bare and not re.match(r"^\s*(int|static|SECP)", code[code.rfind("\n", 0, m.start()) + 1:m.start()]):
            ln = code.count("\n", 0, m.start()) + 1
            bad.append({"function": m.group(1), "line": ln, "text": lines[ln - 1].strip()})
    return n, bad


def source_rules_check(P):
    """source_rules source half: no malloc family, and every call of the new API in the module's tests and the vector driver has its result used.
    (The new API functions are SECP256K1_WARN_UNUSED_RESULT, so -Wall -Werror in the tests build also rejects an ignored result;
    this is the second check. VLAs are rejected by -std=c89 -pedantic -Werror, and the lib build adds -Wvla.)"""
    P.say("  source_rules source checks")
    if P.dry:
        return
    hdr = (REV / "module/include/secp256k1_anti_exfil.h").read_text()
    names = sorted(set(re.findall(r"SECP256K1_API[^;]*?\b(secp256k1_anti_exfil_\w+)\s*\(", hdr, flags=re.S)))
    mod = REV / "module"
    all_files = [mod / "include/secp256k1_anti_exfil.h"] + sorted((mod / "src/modules/anti_exfil").glob("*.h"))
    test_files = [mod / "src/modules/anti_exfil/tests_impl.h", mod / "src/modules/anti_exfil/tests_exhaustive_impl.h", REV / "vector_driver.c"]
    banned, unchecked, ncalls = [], [], 0
    for f in all_files + [REV / "vector_driver.c"]:
        banned += [dict(x, file=f.name) for x in find_banned(f.read_text())]
    for f in test_files:
        n, bad = find_unchecked(f.read_text(), names)
        ncalls += n
        unchecked += [dict(x, file=f.name) for x in bad]
    P.write_json("source_rules.json", {"api_functions": names, "calls_in_tests": ncalls, "banned_tokens": banned, "unchecked_results": unchecked,
                             "files_checked": [str(x.relative_to(ROOT)) for x in all_files + test_files]})
    P.say("    %d API calls in tests, %d banned tokens, %d unchecked" % (ncalls, len(banned), len(unchecked)))


# ---------------------------------------------------------------------------------------------- phases
def phase_a(P):
    jade_vendor_check(P)
    atb = load_apply_to_base()
    for b in BASES:
        pin_check(P, b, atb)
        glue_check(P, b)
    source_rules_check(P)
    sample = {}
    for b in BASES:
        for nm, target in (("lib", "lib"), ("base-lib", "base-lib")):
            P.build_step(b, target, "%s-%sO2" % (b, nm), env={"EXTRA": "-Wvla"})
        for tag, name in (("module", "%s-libO2" % b), ("base", "%s-base-libO2" % b)):
            tree = WORK / (b if tag == "module" else b + ".pristine")
            exe = P.build / ("base_sample_%s_%s" % (b, tag))
            P.step("base_sample_build_%s_%s" % (b, tag), ["gcc", "-O2", "-std=gnu99", "-I%s/include" % tree, HERE / "base_sample.c", P.build / name / "libsecp256k1.a", "-o", exe], wrap=False)
            P.step("base_sample_run_%s_%s" % (b, tag), [exe], wrap=False, log="base_sample_%s_%s.out" % (b, tag))
        P.build_step(b, "driver", "%s-driverO2" % b)
        P.build_step(b, "tests-seam", "%s-tests-seamO2" % b)
    P.step("check_vectors", ["python3", "-B", "-I", REV / "check_vectors.py", "--bases", "benma", "zkp", "--opt", "O2", "--out", P.out / "vectors.json"], ok=(0, 1), timeout=3000)
    for b in BASES:
        P.step("seam_compare_%s" % b, ["python3", "-B", "-I", REV / "seam_compare.py", b], ok=(0, 1), timeout=3000)
    for b in BASES:
        P.build_step(b, "base-tests", "%s-base-testsO2" % b)
        P.build_step(b, "tests", "%s-testsO2" % b)
        for tag, name in (("base", "%s-base-testsO2" % b), ("module", "%s-testsO2" % b)):
            P.step("base_suite_%s_%s" % (b, tag), [P.build / name / "tests", "-i=16", "-seed=" + SEED], ok=(0,), timeout=3000)
    if not P.dry:
        for b in BASES:
            r = {}
            for tag in ("base", "module"):
                f = P.out / ("base_sample_%s_%s.out" % (b, tag))
                r[tag] = {"sha256": sha_file(f) if f.exists() else None, "lines": len(f.read_text().splitlines()) if f.exists() else 0}
            sample[b] = dict(r, equal=r["base"]["sha256"] is not None and r["base"]["sha256"] == r["module"]["sha256"])
        P.write_json("base_sample.json", sample)


def phase_b(P):
    for b in BASES:
        P.build_step(b, "driver", "%s-driverO2" % b)
    P.step("differential", ["python3", "-B", "-I", HERE / "check_differential.py", "--n", "10000", "--out", P.out / "differential.json", "--label", "run"], ok=(0, 1), timeout=3300)


def phase_c(P):
    for b in BASES:
        for O in ("O0", "O2", "Os"):
            P.build_step(b, "ctime", "%s-ctime%s" % (b, O), opt="-" + O)
            P.build_step(b, "memscan", "%s-memscan%s" % (b, O), opt="-" + O)
    P.step("constant_time_c6", ["python3", "-B", "-I", HERE / "check_secrets.py", "--out", P.out, "--tag", "run"], ok=(0, 1), timeout=3300)


def phase_d(P):
    for b in BASES:
        for s in ("asan", "ubsan", "msan"):
            P.step("san_build_%s_%s" % (b, s), [REV / "san_build.sh", b, s], wrap=False)
    P.step("sanitizers", [HERE / "run_sanitizers.sh"], wrap=False, ok=(0, 1), timeout=3000)
    filc = P.env.get("FILC_HOME", "") + "/build/bin/clang"
    for b in BASES:
        e = {"CC": filc, "WARN": FILC_WARN, "EXTRA": "-UUSE_ASM_X86_64"}
        r1 = P.build_step(b, "tests-seam", "%s-filc-tests" % b, opt="-O1", env=e, ok=(0, 1))
        r2 = P.build_step(b, "driver", "%s-filc-driver" % b, opt="-O1", env=e, ok=(0, 1))
        if not P.dry and (r1 or r2):
            P.notes.append("Fil-C build failed for %s (tests rc %s, driver rc %s); reported, not a FAIL" % (b, r1, r2))
        elif not P.dry:
            P.step("filc_vectors_%s" % b, ["python3", "-B", "-I", REV / "check_vectors.py", "--bases", b, "--san", "filc", "--out", P.out / ("filc_vectors_%s.json" % b)], ok=(0, 1), timeout=3000)
    # the Fil-C control: the far out-of-bounds read in validation/c_module/tool_controls/farptr.c must be caught
    ctl = P.build / "filc_control"
    P.step("filc_control_build", [filc, "-O0", "-g", ROOT / "validation/c_module/tool_controls/farptr.c", "-o", ctl], wrap=False, ok=(0, 1))
    P.step("filc_control_run", [ctl], wrap=False, ok=(0, 1, 2, 134, 139), log="filc_control.out")
    if not P.dry:
        built = {b: all((P.build / ("%s-filc-%s" % (b, k)) / n).exists() for k, n in (("tests", "tests"), ("driver", "vector_driver"))) for b in BASES}
        out = (P.out / "filc_control.out").read_text(errors="replace") if (P.out / "filc_control.out").exists() else ""
        P.write_json("filc.json", {"filc_clang": filc, "built": built, "control_fired": "filc safety error" in out, "control_output_head": out[:400],
                                   "vectors_json": {b: (P.out / ("filc_vectors_%s.json" % b)).exists() for b in BASES}})


CBMC_GROUPS = [  # (name, unwind, harnesses, tags)
    ("std", "24", "h_parse33 h_ser33 h_schnorr_verify_args h_ecdsa_verify_args h_schnorr_verify_internal h_ecdsa_verify_internal h_control_false_claim", "0 1 2 3 4 5 6 7 8"),
    ("zero40", "40", "h_schnorr_commit_zero h_ecdsa_commit_zero h_ecdsa_sign_zero", ""),
    ("zero70", "70", "h_schnorr_sign_zero", ""),
]


def phase_e(P):
    for b in BASES:
        P.step("coverage_%s" % b, [HERE / "run_coverage.sh", b], wrap=False, ok=(0, 1), timeout=3000)
        if not P.dry:
            g = P.build / ("%s-cov-tests" % b)
            for f in g.glob("*anti_exfil#main_impl.h.gcov"):
                shutil.copy(f, P.out / ("coverage_%s_main_impl.h.gcov" % b))
    for b in BASES:
        P.build_step(b, "exh13", "%s-exh13O1" % b, opt="-O1")
        P.step("exhaustive_exh13_%s" % b, [P.build / ("%s-exh13O1" % b) / "tests_exhaustive"], ok=(0,), timeout=3300)
    P.step("static_control", [HERE / "run_static.sh", "control", P.out], wrap=False)
    for b in BASES:
        P.step("static_static_%s" % b, [HERE / "run_static.sh", b, P.out], wrap=False)
    for b in BASES:
        for name, unw, hs, tags in CBMC_GROUPS:
            P.step("cbmc_%s_%s" % (b, name), [HERE / "cbmc/run_cbmc.sh", b], wrap=False, ok=(0, 1), timeout=3300,
                   env={"UNW": unw, "HARNESSES": hs, "TAGS": tags}, log="cbmc_%s_%s_summary.txt" % (b, name))
            if not P.dry:  # the logs are about 1 MB each; keep them compressed
                for f in P.out.glob("cbmc_%s_*.log" % b):
                    with open(f, "rb") as fi, gzip.open(str(f) + ".gz", "wb") as fo:
                        shutil.copyfileobj(fi, fo)
                    f.unlink()
    if not P.dry:
        (P.out / "cbmc_scope.txt").write_text(
            "CBMC (version in phase.json). The library is included in one translation unit with USE_FORCE_WIDEMUL_INT64 (no asm, no __int128); the module code is the real code;\n"
            "SHA-256 compression, group and scalar multiplication, inversion, point decompression, keypair loading and the base library's Schnorr verify are replaced by stubs\n"
            "with nondeterministic results (cbmc/harness.c). It says nothing about the arithmetic. Checks: --bounds-check --pointer-check --signed-overflow-check\n"
            "--div-by-zero-check --unwinding-assertions --object-bits 10. Unwind 24 (parse, serialise, verify, hash_final, commit_tweak harnesses), 40 (schnorr and ecdsa\n"
            "commit_zero, ecdsa sign_zero), 70 (schnorr sign_zero). BIP340 message length 5 bytes (verify harnesses: up to 8). hash_final and commit_tweak_bounds for all nine tags, on both bases.\n"
            "h_control_false_claim is a planted false claim and must fail (exit 10).\n")


def phase_f(P):
    P.step("mutation_mull", [HERE / "run_mutation.sh", "benma", "zkp"], wrap=False, ok=(0,), timeout=3300)
    P.step("mutation_review", ["python3", "-B", "-I", HERE / "mutation_review.py"], ok=(0,))
    P.step("mutation_pairs", [HERE / "run_mutation_pairs.sh"], wrap=False, ok=(0,), timeout=3000, log="mutation_pairs.txt")


def phase_g(P, lo, hi):
    P.step("residue_sensitivity", [HERE / "run_residue_sensitivity.sh", LIST_FILE, P.out / "sens", lo, hi], wrap=False, ok=(0,), timeout=3300)


def phase_h(P):
    P.step("cross_arch", [HERE / "run_cross_arch.sh", "benma", "zkp"], wrap=False, ok=(0, 1), timeout=3300)


def plan_g(P):
    n = len([l for l in LIST_FILE.read_text().splitlines() if l.strip() and not l.startswith("#")])
    return n


# ---------------------------------------------------------------------------------------------- main
def estimate(phase):
    items = EST[phase]
    return items, sum(s for _, s, _ in items) / 60.0


def write_phase_json(P, doc):
    if P.dry:
        return
    P.out.mkdir(parents=True, exist_ok=True)
    (P.out / "phase.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("phase", choices=PHASES)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--overwrite", action="store_true", help="replace an existing phase folder")
    a = ap.parse_args()
    name = a.phase
    items, minutes = estimate(name)
    print("phase %s (%s)%s" % (name, ITEMS[name], "  [dry run]" if a.dry_run else ""))
    print("estimate:")
    for l, s, src in items:
        print("  %6.0f s  %s   <- %s" % (s, l, src))
    print("  total %.1f min (limit %.0f min)" % (minutes, LIMIT_MIN))
    env = load_env()
    P = Phase(name, a.dry_run, env)
    if minutes > LIMIT_MIN:
        msg = "STOPPED: estimate %.1f min is over %.0f min. Split the phase%s." % (minutes, LIMIT_MIN, " into g1 (clears 1-27) and g2 (clears 28-54)" if name == "g" else "")
        print(msg)
        if not a.dry_run:
            P.out.mkdir(parents=True, exist_ok=True)
            write_phase_json(P, {"schema": 1, "phase": name, "status": "stopped", "reason": msg, "estimate_minutes": round(minutes, 1)})
        return 3
    if name.startswith("g"):
        n = plan_g(P)
        print("clears in %s: %d" % (LIST_FILE.name, n))
        if n != 54:
            print("STOPPED: the list has %d clears, not 54" % n)
            return 3
    if not a.dry_run:
        if P.out.exists() and any(P.out.iterdir()):
            if not a.overwrite:
                print("STOPPED: %s already has output; a phase is not rerun over its output (use --overwrite to replace it)" % P.out)
                return 3
            shutil.rmtree(P.out)
        P.out.mkdir(parents=True)
        P.build.parent.mkdir(parents=True, exist_ok=True)
        if P.build.exists():
            shutil.rmtree(P.build)
        P.build.mkdir(parents=True)
    atb = load_apply_to_base()
    t_start = time.time()
    before = input_hashes(name, atb)
    head = git(ROOT, "rev-parse", "HEAD").stdout.strip()
    dirty = git(ROOT, "status", "--porcelain", "--", "c", "validation/c_module", "jade").stdout.strip().splitlines()
    print("module %s  benma %s (pin %s)  zkp %s (pin %s)" % (before["module"]["sha256"][:16], before["benma"]["generated_tree"]["sha256"][:16],
          "ok" if before["benma"]["head_is_pin"] else "WRONG", before["zkp"]["generated_tree"]["sha256"][:16], "ok" if before["zkp"]["head_is_pin"] else "WRONG"))
    bad = [b for b in BASES if not before[b]["head_is_pin"] or before[b]["dirty"]]
    if bad and not a.dry_run:
        print("STOPPED: a pinned base is not at its pin or is not clean: %s" % bad)
        write_phase_json(P, {"schema": 1, "phase": name, "status": "error", "reason": "pinned base not at pin or dirty: %s" % bad})
        return 4
    if missing := [k for k, v in before["files"].items() if v == "MISSING"]:
        print("STOPPED: input files missing: %s" % missing)
        return 4
    status, reason = "complete", ""
    load0 = os.getloadavg()
    signal.signal(signal.SIGTERM, _term)
    write_phase_json(P, {"schema": 1, "phase": name, "status": "running", "git_head": head,
                         "hashes_before": before, "started": datetime.datetime.fromtimestamp(t_start).isoformat(timespec="seconds"),
                         "load_average_at_start": load0})
    try:
        if name == "a":
            phase_a(P)
        elif name == "b":
            phase_b(P)
        elif name == "c":
            phase_c(P)
        elif name == "d":
            phase_d(P)
        elif name == "e":
            phase_e(P)
        elif name == "f":
            phase_f(P)
        elif name == "g1":
            phase_g(P, 1, 27)
        elif name == "g2":
            phase_g(P, 28, 54)
        elif name == "h":
            phase_h(P)
    except (Stopped, KeyboardInterrupt) as e:
        status, reason = "stopped", "interrupted: %s" % e
        if P.proc:
            P.proc.terminate()
    except Exception as e:  # noqa: BLE001 (recorded; the output stays)
        status, reason = "failed", "%s: %s" % (type(e).__name__, e)
    if a.dry_run:
        print("dry run: nothing written")
        return 0
    bad_steps = [c["label"] for c in P.cmds if not c["ok"]]
    if status == "complete" and bad_steps:
        status, reason = "failed", "steps with unexpected exit status: %s" % ", ".join(bad_steps)
    after = input_hashes(name, atb)
    same = hashes_equal(before, after)
    if not same:
        status, reason = "error", "inputs changed during the phase (module, a pinned base or a script hash differs before and after)"
    doc = {"schema": 1, "phase": name, "items": ITEMS[name], "status": status, "reason": reason,
           "git_head": head, "git_dirty_paths": dirty, "started": datetime.datetime.fromtimestamp(t_start).isoformat(timespec="seconds"),
           "wall_seconds": round(time.time() - t_start, 1), "estimate_minutes": round(minutes, 1), "hashes_before": before, "hashes_after": after,
           "hashes_equal": same, "load_average_at_start": load0, "load_average_at_end": os.getloadavg(), "tool_versions": tool_versions(name, env), "commands": P.cmds, "notes": P.notes, "build_folder": str(P.build)}
    write_phase_json(P, doc)
    print("phase %s: %s%s  (%.1f min; estimate %.1f)" % (name, status, (" - " + reason) if reason else "", (time.time() - t_start) / 60, minutes))
    return 0 if status == "complete" else (4 if status == "error" else 1)


if __name__ == "__main__":
    sys.exit(main())
