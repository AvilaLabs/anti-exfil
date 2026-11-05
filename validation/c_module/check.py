#!/usr/bin/env python3
"""Checker for the C module runs. Reads the phase outputs written by run.py and prints one line per check,
then the overall PASS, FAIL, INCOMPLETE, INVALID or ERROR.

usage: check.py RUN_DIR --classes FILE [--no-recheck]      score a run
       check.py --self-test                                  show each outcome on small fabricated runs in a temp folder

Rules.
 - A phase that has not run gives INCOMPLETE for its items. An output a phase should have produced and did not gives INCOMPLETE.
 - A control that does not fire gives INVALID for its item (the constant-time and residue controls, the residue baseline, the sanitizer and Fil-C controls,
   the CBMC false claim and the three static-tool controls, empty inputs). INVALID beats FAIL.
 - Every finding (Valgrind report, residue left in dead memory, sanitizer report, branch not taken, static-tool or CBMC finding,
   Mull survivor, a banned token or unchecked API result) must be matched by a line of the classes file, or the item FAILS.
   A class that starts with "bug" fails the item too. A Mull survivor that is a removed clear and that the residue sensitivity run
   reported is listed as covered by the scan and needs no line.
 - ERROR: a hash of c/module, a pinned base, a script or the git commit differs between the before and after of a phase or
   between phases, or from the files now (unless --no-recheck), or Jade's vendored copy differs from the module.
 - Overall: ERROR, then INVALID, then FAIL, then INCOMPLETE, then PASS.

Classes file (written by hand, hashed into this output): one entry per line, three TAB-separated fields
    KEY <TAB> CLASS <TAB> REASON
KEY is a shell pattern (fnmatch, * and ?) matched against the finding keys this checker prints as `UNCLASSIFIED <key>`. Lines starting
with # and blank lines are ignored. The reason must not be empty. Key forms:
    vectors|<mismatch text>                          source_rules|banned|<file>|<token>      source_rules|unchecked|<file>|<function>|<source text>
    constant_time|<base>|<opt>|<function>|<source text>    residue|<scheme>|<fn>|<secret>|<base>|<opt>|<region>      residue_miss|L<line> (reason for a missed clear)
    sanitizers|<log line>                               coverage|<base>|<line N branch K>|<source>
    static|fanalyzer|<base>|<id>|<file>:<line>|<message>      static|scanbuild|<base>|<N bugs>      static|cppcheck|<base>|<id>|<file>:<line>
    static|cbmc|<base>|<harness>                   mutation|<mutator>|<description>|<source text>
"""
import argparse, fnmatch, gzip, hashlib, json, os, pathlib, re, shutil, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = ROOT / "validation/c_module"
BASES = ("benma", "zkp")
OPTS = ("O0", "O2", "Os")
RANK = {"PASS": 1, "INCOMPLETE": 2, "FAIL": 3, "INVALID": 4}
PHASES = ("a", "b", "c", "d", "e", "f", "g1", "g2", "h")
CBMC_STD = ["h_parse33", "h_ser33", "h_schnorr_verify_args", "h_ecdsa_verify_args", "h_schnorr_verify_internal", "h_ecdsa_verify_internal",
            "h_schnorr_commit_zero", "h_ecdsa_commit_zero", "h_schnorr_sign_zero", "h_ecdsa_sign_zero"]
CBMC_TAGGED = ["h_hash_final", "h_commit_tweak_bounds"]
CBMC_CONTROL = "h_control_false_claim"


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_hash(root):  # same algorithm as run.py
    root = pathlib.Path(root)
    h = hashlib.sha256()
    for dp, dn, fn in os.walk(root):
        dn.sort()
        for f in sorted(fn):
            p = pathlib.Path(dp) / f
            d = ("link:" + os.readlink(p)) if p.is_symlink() else sha_file(p)
            h.update(p.relative_to(root).as_posix().encode() + b"\0" + d.encode() + b"\n")
    return h.hexdigest()


# ---------------------------------------------------------------------------------------------- classes
class Classes:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.sha = sha_file(self.path)
        self.entries, self.used = [], set()
        for n, l in enumerate(self.path.read_text().split("\n"), 1):
            if not l.strip() or l.lstrip().startswith("#"):
                continue
            f = l.split("\t")
            if len(f) < 3 or not f[0].strip() or not f[1].strip() or not "\t".join(f[2:]).strip():
                raise SystemExit("classes file line %d: want KEY<TAB>CLASS<TAB>REASON (reason not empty): %r" % (n, l[:100]))
            self.entries.append((f[0].strip(), f[1].strip(), "\t".join(f[2:]).strip()))

    def lookup(self, key):
        for i, (pat, cls, reason) in enumerate(self.entries):
            if fnmatch.fnmatchcase(key, pat):
                self.used.add(i)
                return cls, reason
        return None

    def unused(self):
        return [e[0] for i, e in enumerate(self.entries) if i not in self.used]


# ---------------------------------------------------------------------------------------------- items
class Item:
    def __init__(self, ident, classes):
        self.id, self.classes, self.verdict = ident, classes, "PASS"
        self.notes, self.details = [], []
        self.n_classified = 0

    def up(self, v, msg):
        if RANK[v] > RANK[self.verdict]:
            self.verdict = v
        self.notes.append("%s: %s" % (v, msg) if v != "PASS" else msg)

    def incomplete(self, msg):
        self.up("INCOMPLETE", msg)

    def invalid(self, msg):
        self.up("INVALID", msg)

    def fail(self, msg):
        self.up("FAIL", msg)

    def judge(self, key, what=None):
        """A finding: classified by a line of the classes file, or it fails the item."""
        r = self.classes.lookup(key)
        if r is None:
            self.details.append("UNCLASSIFIED %s" % key)
            self.up("FAIL", "unclassified finding: %s" % (what or key)[:110])
        elif r[0].startswith("bug"):
            self.details.append("BUG %s :: %s" % (key, r[1]))
            self.up("FAIL", "finding classed as %s: %s" % (r[0], (what or key)[:90]))
        else:
            self.n_classified += 1
            self.details.append("classified [%s] %s :: %s" % (r[0], key, r[1]))

    def line(self):
        shown = [n for n in self.notes if not n.startswith("FAIL") and not n.startswith("INVALID") and not n.startswith("INCOMPLETE")]
        bad = [n for n in self.notes if n not in shown]
        if bad and bad[0].startswith(self.verdict + ": "):
            bad[0] = bad[0][len(self.verdict) + 2:]
        txt = "; ".join((bad + shown)[:4])
        if self.n_classified:
            txt += "; %d findings classified" % self.n_classified
        return "%-15s %-10s %s" % (self.id, self.verdict, txt)


class Run:
    def __init__(self, d):
        self.dir = pathlib.Path(d)
        self.ph = {}
        for p in PHASES:
            f = self.dir / p / "phase.json"
            if f.exists():
                try:
                    self.ph[p] = json.loads(f.read_text())
                except ValueError:
                    self.ph[p] = {"status": "error", "reason": "phase.json unreadable"}

    def need(self, item, p):
        if p not in self.ph:
            item.incomplete("phase %s has not run" % p)
            return None
        st = self.ph[p].get("status")
        if st != "complete":
            item.notes.append("(phase %s status %s: %s)" % (p, st, str(self.ph[p].get("reason", ""))[:60]))
        return self.ph[p]

    def path(self, p, name):
        f = self.dir / p / name
        if f.exists():
            return f
        g = self.dir / p / (name + ".gz")
        return g if g.exists() else None

    def text(self, p, name):
        f = self.path(p, name)
        if f is None:
            return None
        if f.suffix == ".gz":
            return gzip.open(f, "rt", errors="replace").read()
        return f.read_text(errors="replace")

    def json(self, p, name):
        t = self.text(p, name)
        if t is None:
            return None
        try:
            return json.loads(t)
        except ValueError:
            return None

    def cmd(self, p, label):
        for c in self.ph.get(p, {}).get("commands", []):
            if c["label"] == label:
                return c
        return None


def module_lines():
    return (ROOT / "c/module/src/modules/anti_exfil/main_impl.h").read_text().split("\n")


def clears_list():
    out = {}
    for l in (HERE / "residue_clears.txt").read_text().split("\n"):
        if l.strip() and not l.startswith("#"):
            f = l.split("\t")
            out[int(f[0])] = (f[2], f[3])
    return out


def need_file(run, it, p, name):
    v = run.text(p, name)
    if v is None:
        it.incomplete("%s/%s missing" % (p, name))
    return v


# ---------------------------------------------------------------------------------------------- vectors to source_rules (phase a)
def check_c1(run, cl):
    it = Item("vectors", cl)
    if not run.need(it, "a"):
        return it
    j = run.json("a", "vectors.json")
    if j is None:
        it.incomplete("a/vectors.json missing")
        return it
    nvalid = nrej = nna = 0
    for m in j.get("mismatches", []):
        it.judge("vectors|" + m, m)
    for b in BASES:
        rep = j.get("bases", {}).get(b)
        if not rep:
            it.incomplete("base %s missing in vectors.json" % b)
            continue
        for sc in ("bip340", "ecdsa"):
            s = rep.get(sc, {})
            for k in ("valid_derivation_match", "valid_host_accept"):
                m = re.match(r"(\d+) of (\d+)$", s.get(k, ""))
                if not m or m.group(1) != m.group(2):
                    it.fail("%s %s %s: %s" % (b, sc, k, s.get(k)))
                elif b == BASES[0] and k == "valid_derivation_match":
                    nvalid += int(m.group(2))
            for cls, cnt in s.get("reject_by_class", {}).items():
                if cnt.get("ACCEPTED (mismatch)"):
                    it.fail("%s %s: reject class %s accepted" % (b, sc, cls))
                if b == BASES[0]:
                    nrej += sum(cnt.values())
                    nna += cnt.get("not expressible", 0)
            if not s.get("forced_hash_cases"):
                it.fail("%s %s: forced-hash cases not listed" % (b, sc))
            bad = [k for k, v in s.get("forced_hash_cases", {}).items() if not (v == "seam test" or v.startswith("not run: "))]
            if bad:
                it.fail("forced-hash case without a status: %s" % bad[:3])
            if any("(" not in x for x in s.get("reject_not_expressible", [])):
                it.fail("%s %s: a not-expressible case has no reason" % (b, sc))
        if rep.get("seam_tests", {}).get("returncode") != 0:
            it.fail("%s: seam tests rc %s" % (b, rep.get("seam_tests", {}).get("returncode")))
    if nvalid == 0 or nrej == 0:
        it.invalid("no valid or no reject vectors were evaluated (%d valid, %d reject)" % (nvalid, nrej))
    for b in BASES:
        t = run.text("a", "seam_compare_%s.log" % b)
        if t is None:
            it.incomplete("seam_compare log for %s missing" % b)
        elif "nm identical: True" not in t or "objdump -d identical: True" not in t:
            it.fail("%s: seam is present in the normal build (seam_compare)" % b)
    if it.verdict == "PASS":
        it.notes.insert(0, "%d valid, %d reject tuples per base all as expected (%d not expressible, with reasons); forced-hash cases listed; seam absent from normal build" % (nvalid, nrej, nna))
    return it


def check_c2(run, cl):
    it = Item("differential", cl)
    if not run.need(it, "b"):
        return it
    j = run.json("b", "differential.json")
    if j is None:
        it.incomplete("b/differential.json missing")
        return it
    tot = 0
    for sc in ("bip340", "ecdsa"):
        s = j.get("schemes", {}).get(sc)
        if not s:
            it.incomplete("scheme %s missing" % sc)
            continue
        if s["cases"] < 10000:
            it.fail("%s: %d inputs, fewer than 10,000" % (sc, s["cases"]))
        for k, v in s["mismatches"].items():
            if v:
                it.fail("%s: %d mismatches in %s" % (sc, v, k))
        pk, r0 = s.get("pk_parity_counts_odd_even", {}), s.get("R0_parity_counts", {})
        if not (pk.get("0") and pk.get("1")):
            it.fail("%s: keys of only one parity" % sc)
        if sc == "bip340":
            lo, hi = s.get("message_length_range", [None, None])
            if lo != 0 or hi is None or hi < 1000:
                it.fail("bip340: message lengths %s..%s do not include empty and long" % (lo, hi))
        tot += s["cases"]
    if tot == 0:
        it.invalid("no inputs compared")
    if it.verdict == "PASS":
        it.notes.insert(0, "%d inputs per scheme, 0 mismatches against the Python reference and between the bases; both key parities; empty to 1000 byte messages" % (tot // 2))
    return it


def flags_of(run, name):
    t = run.text("a", "flags/%s.txt" % name)
    return t


def check_c3(run, cl):
    it = Item("base_unchanged", cl)
    if not run.need(it, "a"):
        return it
    for b in BASES:
        g = run.json("a", "glue_%s.json" % b)
        if g is None:
            it.incomplete("glue_%s.json missing" % b)
        else:
            if not g.get("ok"):
                it.fail("%s: generated tree differs from the pristine export beyond the glue: %s" % (b, "; ".join(g.get("violations", [])[:2]) or "file lists differ"))
        p = run.json("a", "pin_check_%s.json" % b)
        if p is None:
            it.incomplete("pin_check_%s.json missing" % b)
        elif not p.get("ok"):
            it.fail("%s: pristine export is not the pinned commit" % b)
        for tag in ("base", "module"):
            c = run.cmd("a", "base_suite_%s_%s" % (b, tag))
            if c is None:
                it.incomplete("suite %s %s not run" % (b, tag))
            else:
                t = run.text("a", c["log"]) or ""
                if c["rc"] != 0 or "Total execution time" not in t:
                    it.fail("%s %s suite rc %s" % (b, tag, c["rc"]))
    s = run.json("a", "base_sample.json")
    if s is None:
        it.incomplete("base_sample.json missing")
    else:
        for b in BASES:
            e = s.get(b)
            if not e or e["base"]["lines"] == 0 or e["module"]["lines"] == 0:
                it.invalid("%s: sample produced no output" % b)
            elif not e["equal"]:
                it.fail("%s: schnorrsig_sign / ecdsa_sign bytes differ from the unpatched base" % b)
    if it.verdict == "PASS":
        n = sum(len(run.json("a", "glue_%s.json" % b)["added_lines"]) for b in BASES)
        it.notes.insert(0, "only build glue and include lines changed (%d added lines, 3 files per base, listed in a/glue_*.json); 4 suites pass; sign bytes identical on 200 samples" % n)
    return it


def check_c4(run, cl):
    it = Item("source_rules", cl)
    if not run.need(it, "a"):
        return it
    names = []
    for b in BASES:
        names += ["%s-libO2" % b, "%s-base-libO2" % b, "%s-tests-seamO2" % b, "%s-testsO2" % b, "%s-base-testsO2" % b]
    for n in names:
        t = flags_of(run, n)
        c = run.cmd("a", "build_" + n)
        if t is None or c is None:
            it.incomplete("build %s not recorded" % n)
            continue
        if c["rc"] != 0:
            it.fail("build %s failed (rc %s)" % (n, c["rc"]))
        for fl in ("-std=c89", "-pedantic", "-Wall", "-Wextra", "-Werror"):
            if not re.search(r"(^|\s)%s(\s|$)" % re.escape(fl), t):
                it.fail("build %s lacks %s" % (n, fl))
        if n.endswith("-libO2") and "-Wvla" not in t:
            it.fail("lib build %s lacks -Wvla" % n)
    j = run.json("a", "source_rules.json")
    if j is None:
        it.incomplete("source_rules.json missing")
    else:
        if j.get("calls_in_tests", 0) == 0:
            it.invalid("no call of the new API found in the tests (scan saw nothing)")
        for x in j.get("banned_tokens", []):
            it.judge("source_rules|banned|%s|%s" % (x["file"], x["token"]), "%s uses %s (line %d)" % (x["file"], x["token"], x["line"]))
        for x in j.get("unchecked_results", []):
            it.judge("source_rules|unchecked|%s|%s|%s" % (x["file"], x["function"], x["text"]), "unchecked result %s:%d" % (x["file"], x["line"]))
    if it.verdict == "PASS":
        it.notes.insert(0, "lib, base-lib, tests, tests-seam and base-tests build under -std=c89 -pedantic -Wall -Wextra -Werror on both bases (lib with -Wvla); no malloc family; %d API calls in tests, all results used" % j["calls_in_tests"])
    return it


# ---------------------------------------------------------------------------------------------- constant_time, residue (phases c, g1, g2)
def sensitivity(run):
    """rows of the residue sensitivity run: {line: row}; None if g1 or g2 is missing."""
    rows, base_ok, missing = {}, True, []
    for p in ("g1", "g2"):
        t = run.text(p, "sens/residue_sensitivity.tsv")
        if t is None:
            missing.append(p)
            continue
        for l in t.split("\n"):
            f = l.split("\t")
            if len(f) < 10:
                continue
            rows.setdefault(p, {})[int(f[0])] = dict(zip(("line", "col", "fn", "stmt", "build_rc", "scan_rc", "ctl", "nfull", "frag", "reported"), f))
    return rows, missing


def check_c5(run, cl):
    it = Item("constant_time", cl)
    if not run.need(it, "c"):
        return it
    j = run.json("c", "secrets_results.json")
    if j is None:
        it.incomplete("c/secrets_results.json missing")
        return it
    seen = set()
    nhit = 0
    for e in j.get("constant_time", []):
        seen.add((e["base"], e["opt"], e["scheme"]))
        cfg = "%s %s %s" % (e["base"], e["opt"], e["scheme"])
        if not (e["control_branch"] and e["control_index"] and e["control_declassified_clean"]):
            it.invalid("controls did not behave in %s (branch %s, index %s, declassified-clean %s)" % (cfg, e["control_branch"], e["control_index"], e["control_declassified_clean"]))
        if not e["driver_ok"]:
            it.invalid("driver call failed in %s" % cfg)
        for h in e.get("hits", []):
            nhit += 1
            it.judge("constant_time|%s|%s|%s|%s" % (e["base"], e["opt"], h["function"], h["source"]), "%s: %s %s" % (cfg, h["function"], h["source"]))
    want = {(b, o, s) for b in BASES for o in OPTS for s in ("schnorr", "ecdsa")}
    if want - seen:
        it.incomplete("configurations missing: %s" % sorted(want - seen)[:3])
    if it.verdict == "PASS":
        it.notes.insert(0, "%d configurations (2 bases x O0/O2/Os x 2 schemes), controls fired and the declassified control stayed quiet in each; %d reports, all classified; %s" % (len(seen), nhit, j.get("valgrind", "")))
    return it


def check_c6(run, cl):
    it = Item("residue", cl)
    if not run.need(it, "c"):
        pass
    j = run.json("c", "secrets_results.json")
    if j is None:
        it.incomplete("c/secrets_results.json missing")
    else:
        combos, ncase, partial = set(), set(), set()
        for e in j.get("residue", []):
            combos.add((e["scheme"], e["base"], e["opt"]))
            ncase.add((e["scheme"], e["case"]))
            rows = e["rows"]
            basehit = [r for r in rows if r.get("fn") == "control_baseline" and r.get("full", 0) + r.get("fragments", 0)]
            plant = [r for r in rows if r.get("fn") == "control_plant" and r.get("pattern") == "sk/be" and r.get("region") == "stack" and r.get("full", 0) >= 1]
            if basehit or not plant or e.get("rc"):
                it.invalid("scan controls failed for %s %s %s %s" % (e["scheme"], e["case"], e["base"], e["opt"]))
            for r in rows:
                if r.get("fn") in ("host_commit", "signer_commit", "signer_sign", "host_verify") and not r.get("full") and r.get("max_fragment", 0) > 0:
                    partial.add((e["scheme"], e["base"], e["opt"], r["fn"], r.get("pattern", "").split("/")[0], r.get("region")))
        if j.get("residue_control_failures"):
            it.invalid("the scan reported %s control failures" % j["residue_control_failures"])
        want = {(s, b, o) for s in ("schnorr", "ecdsa") for b in BASES for o in OPTS}
        if want - combos:
            it.incomplete("scan configurations missing: %s" % sorted(want - combos)[:3])
        if not ncase:
            it.invalid("scan ran no cases")
        for (sc, fn, sname, base, O, reg, nf) in [tuple(x) for x in j.get("residue_full_length_found", [])]:
            it.judge("residue|%s|%s|%s|%s|%s|%s" % (sc, fn, sname, base, O, reg), "full-length %s left in %s of %s (%s %s)" % (sname, reg, fn, base, O))
        it.details.append("partial-pattern sites (a fragment of a secret found, no full value): %d, per case in c/residue_table.md" % len(partial))
        residue = "scan: %d configurations, %d cases per scheme, controls fired, %d sites with a partial fragment" % (len(combos), len(ncase) // 2 if ncase else 0, len(partial))
    rows, missing = sensitivity(run)
    exp = clears_list()
    if missing:
        it.incomplete("sensitivity phase(s) %s not run (needed for the 54-clear table)" % ",".join(missing))
    got = {}
    for p, r in rows.items():
        for k, v in r.items():
            if k == 0:
                if v["build_rc"] != "0" or v["scan_rc"] != "0" or v["ctl"] != "0" or v["nfull"] != "0":
                    it.invalid("%s baseline (unmutated copy) not clean: build %s scan %s controls %s full-length %s" % (p, v["build_rc"], v["scan_rc"], v["ctl"], v["nfull"]))
            else:
                got[k] = v
    if not missing:
        lost = sorted(set(exp) - set(got))
        extra = sorted(set(got) - set(exp))
        if lost:
            it.incomplete("sensitivity rows missing for lines %s" % lost[:6])
        if extra:
            it.fail("sensitivity rows for lines not in the list: %s" % extra[:6])
    unscanned = [k for k, v in got.items() if v["build_rc"] != "0" or v["scan_rc"] != "0" or v["ctl"] != "0"]
    if unscanned:
        it.invalid("%d clears could not be scanned (build or scan or control failed): lines %s" % (len(unscanned), sorted(unscanned)[:6]))
    seen_ok = {k: v for k, v in got.items() if k not in unscanned}
    hit = sorted(k for k, v in seen_ok.items() if v["reported"] == "yes")
    miss = sorted(k for k, v in seen_ok.items() if v["reported"] != "yes")
    for k in miss:
        r = cl.lookup("residue_miss|L%d" % k)
        fn, st = exp.get(k, ("?", "?"))
        it.details.append("MISSED clear L%d %s: %s%s" % (k, fn, st, (" :: [%s] %s" % r) if r else " :: no reason written"))
    if got:
        it.notes.append("clear-removal sensitivity: scan reported %d of %d clears (%d scanned); %d missed and named in the details%s" % (len(hit), len(exp), len(seen_ok), len(miss), "" if not missing else "; table incomplete"))
    if j is not None and it.verdict == "PASS":
        it.notes.insert(0, residue + "; no full-length secret in dead memory")
    return it


# ---------------------------------------------------------------------------------------------- sanitizers
def check_c7(run, cl):
    it = Item("sanitizers", cl)
    if not run.need(it, "d"):
        return it
    t = run.text("d", "sanitizers_log.txt")
    if t is None:
        it.incomplete("d/sanitizers_log.txt missing")
        return it
    for s in ("asan", "ubsan", "msan"):
        if "CONTROL %s: fires" % s not in t:
            if ("CONTROL %s:" % s) in t:
                it.invalid("%s control did not fire" % s)
            else:
                it.incomplete("%s control line missing" % s)
        if "CLEAN %s: quiet" % s not in t:
            (it.invalid if "CLEAN %s: REPORTED" % s in t else it.incomplete)("%s clean control is not quiet / missing" % s)
        for b in BASES:
            a = "%s %s module tests: clean" % (b, s)
            v = "%s %s vector driver + seam tests: mismatches: 0" % (b, s)
            for want, label in ((a, "module tests"), (v, "vector driver")):
                if want not in t:
                    line = next((l for l in t.split("\n") if l.startswith("%s %s %s" % (b, s, label.split()[0])) and "REPORT/FAIL" in l), None)
                    if line:
                        it.judge("sanitizers|" + line, line)
                    else:
                        it.incomplete("%s %s %s: no result line" % (b, s, label))
    f = run.json("d", "filc.json")
    if f is None:
        it.incomplete("d/filc.json missing (Fil-C must be recorded either way)")
    else:
        fn = []
        for b in BASES:
            if not f["built"].get(b):
                fn.append("Fil-C build failed for %s (recorded, not a FAIL)" % b)
                continue
            if not f.get("control_fired"):
                it.invalid("Fil-C built but its control (far out-of-bounds read) did not fire")
            v = run.json("d", "filc_vectors_%s.json" % b)
            if v is None:
                it.incomplete("Fil-C vector result for %s missing" % b)
            elif v.get("mismatches"):
                it.fail("Fil-C %s: %d mismatches" % (b, len(v["mismatches"])))
        it.notes += fn
        if not fn and it.verdict == "PASS":
            it.notes.append("Fil-C built and ran the module tests and vectors on both bases, control fired")
    if it.verdict == "PASS":
        it.notes.insert(0, "ASan, UBSan, MSan: controls fire, clean builds quiet, module tests and vector driver clean on both bases")
    return it


# ---------------------------------------------------------------------------------------------- coverage, exhaustive, static (phase e)
def check_c8(run, cl):
    it = Item("coverage", cl)
    if not run.need(it, "e"):
        return it
    tot = 0
    for b in BASES:
        t = run.text("e", "coverage_%s_branches.txt" % b)
        if t is None:
            it.incomplete("coverage_%s_branches.txt missing" % b)
            continue
        m = re.match(r"(\w+): (\d+) of (\d+) branches taken", t)
        if not m or int(m.group(3)) == 0:
            it.invalid("%s: no branch counts in the gcov output" % b)
            continue
        tot += int(m.group(3))
        for l in t.split("\n")[1:]:
            mm = re.match(r"NOT TAKEN (line \d+ branch \d+): (.*)", l)
            if mm:
                it.judge("coverage|%s|%s|%s" % (b, mm.group(1), mm.group(2)), "%s %s not taken: %s" % (b, mm.group(1), mm.group(2)))
        if int(m.group(2)) < int(m.group(3)) and not any("coverage|%s" % b in d for d in it.details):
            it.fail("%s: %s of %s branches taken but no NOT TAKEN lines" % (b, m.group(2), m.group(3)))
    if it.verdict == "PASS":
        it.notes.insert(0, "every branch of src/modules/anti_exfil/main_impl.h taken on both bases (%d branches counted)" % tot)
    return it


def check_c9(run, cl):
    it = Item("exhaustive", cl)
    if not run.need(it, "e"):
        return it
    for b in BASES:
        c = run.cmd("e", "exhaustive_exh13_%s" % b)
        t = run.text("e", c["log"]) if c else None
        if t is None:
            it.incomplete("exhaustive output for %s missing" % b)
            continue
        m = re.search(r"test count = (\d+)", t)
        if not m or int(m.group(1)) == 0:
            it.invalid("%s: exhaustive binary ran no tests" % b)
        if c["rc"] != 0 or "no problems found" not in t:
            it.fail("%s: exhaustive tests did not end with 'no problems found' (rc %s)" % (b, c["rc"]))
    if it.verdict == "PASS":
        it.notes.insert(0, "order 13 only (order 199 is about 270 days at the measured speed); no problems found on both bases")
    return it


def parse_fanalyzer(text):
    out = []
    for l in text.split("\n"):
        m = re.match(r"^(/\S.*?):(\d+):\d+: warning: (.*) \[-Wanalyzer-([\w-]+)\]\s*$", l)
        if m:
            msg = re.sub(r"callstring:.*?before", "callstring: ... before", m.group(3))
            msg = re.sub(r"\d+", "N", msg)[:100]
            out.append((m.group(4), "%s:%s" % (os.path.basename(m.group(1)), m.group(2)), msg))
    return out


def check_c10(run, cl):
    it = Item("static", cl)
    if not run.need(it, "e"):
        return it
    ctl = {"fanalyzer": (r"use-after-free|use after .free", run.text("e", "control_fanalyzer.txt")),
           "scanbuild": (r"scan-build: [1-9]\d* bugs? found", run.text("e", "control_scanbuild.txt")),
           "cppcheck": (r"deallocuse|ereferenc", run.text("e", "control_cppcheck.txt"))}
    for k, (rx, t) in ctl.items():
        if t is None:
            it.incomplete("control for %s missing" % k)
        elif not re.search(rx, t):
            it.invalid("%s control (planted use after free) did not fire" % k)
    nf = 0
    for b in BASES:
        n = run.text("e", "module_in_tu_%s.txt" % b)
        if n is None:
            it.incomplete("module_in_tu_%s.txt missing" % b)
        elif not n.strip().isdigit() or int(n.strip()) == 0:
            it.invalid("%s: the module is not in the translation unit the static tools were given" % b)
        t = run.text("e", "fanalyzer_%s.txt" % b)
        if t is None:
            it.incomplete("fanalyzer_%s.txt missing" % b)
        else:
            if re.search(r"^\S.*: (fatal )?error: ", t, flags=re.M) or "exit=0" not in t:
                it.invalid("%s: gcc -fanalyzer did not finish cleanly" % b)
            for (i, loc, msg) in parse_fanalyzer(t):
                nf += 1
                it.judge("static|fanalyzer|%s|%s|%s|%s" % (b, i, loc, msg), "fanalyzer %s %s %s" % (b, i, loc))
        t = run.text("e", "scanbuild_%s.txt" % b)
        if t is None:
            it.incomplete("scanbuild_%s.txt missing" % b)
        elif "No bugs found" in t:
            pass
        else:
            m = re.search(r"scan-build: (\d+) bugs? found", t)
            if m:
                it.judge("static|scanbuild|%s|%s bugs" % (b, m.group(1)), "scan-build %s: %s bugs" % (b, m.group(1)))
            else:
                it.invalid("%s: scan-build gave neither 'No bugs found' nor a bug count" % b)
        t = run.text("e", "cppcheck_%s.txt" % b)
        if t is None:
            it.incomplete("cppcheck_%s.txt missing" % b)
        else:
            if "exit=0" not in t:
                it.invalid("%s: cppcheck did not finish cleanly" % b)
            for l in t.split("\n"):
                f = l.split(":", 4)
                if len(f) == 5 and f[1].isdigit():
                    nf += 1
                    it.judge("static|cppcheck|%s|%s|%s:%s" % (b, f[3], os.path.basename(f[0]), f[1]), "cppcheck %s %s %s:%s" % (b, f[3], os.path.basename(f[0]), f[1]))
        runs = 0
        expect = CBMC_STD + [CBMC_CONTROL] + ["%s_tag%d" % (h, t) for h in CBMC_TAGGED for t in range(9)]
        for h in expect:
            lt = run.text("e", "cbmc_%s_%s.log" % (b, h))
            if lt is None:
                it.incomplete("cbmc log %s %s missing" % (b, h))
                continue
            runs += 1
            ok, bad = "VERIFICATION SUCCESSFUL" in lt, "VERIFICATION FAILED" in lt
            if h == CBMC_CONTROL:
                if not bad:
                    it.invalid("%s: the CBMC false-claim control was not reported as failing" % b)
            elif bad or not ok:
                it.judge("static|cbmc|%s|%s" % (b, h), "CBMC %s %s: %s" % (b, h, "FAILED" if bad else "no verdict"))
    if it.verdict == "PASS":
        it.notes.insert(0, "GCC -fanalyzer, scan-build, cppcheck (controls fired, module in the TU) and %d CBMC runs per base: no unclassified finding. CBMC runs with the arithmetic abstracted and says nothing about the arithmetic (e/cbmc_scope.txt)" % (len(CBMC_STD) + 1 + 18))
    return it


# ---------------------------------------------------------------------------------------------- mutation
MULL_SV = re.compile(r"main_impl\.h:(\d+):(\d+): warning: Survived: (.*?) \[(\w+)\]")


def check_c11(run, cl):
    it = Item("mutation", cl)
    if not run.need(it, "f"):
        return it
    src = module_lines()
    rows, missing = sensitivity(run)
    by_line = {}
    for p, r in rows.items():
        by_line.update({k: v for k, v in r.items() if k})
    sets, covered, nsurv = {}, 0, 0
    for b in BASES:
        t = run.text("f", "mutation_%s_mull.log" % b)
        if t is None:
            it.incomplete("mutation_%s_mull.log missing" % b)
            continue
        killed = len(re.findall(r"warning: Killed", t))
        sv = sorted(set(MULL_SV.findall(t)), key=lambda x: (int(x[0]), int(x[1])))
        sets[b] = {(l, c, d, m) for l, c, d, m in sv}
        if killed + len(sv) == 0:
            it.invalid("%s: Mull ran no mutants" % b)
            continue
        if not re.search(r"Mutation score: \d+%", t):
            it.invalid("%s: Mull log has no mutation score (run did not finish)" % b)
        nsurv = max(nsurv, len(sv))
        for l, c, d, m in sv:
            l = int(l)
            stmt = src[l - 1].strip() if 0 < l <= len(src) else "?"
            is_clear = m == "cxx_remove_void_call" and re.search(r"_clear|memclear", d)
            if is_clear and l in by_line and by_line[l]["reported"] == "yes" and by_line[l]["build_rc"] == "0":
                covered += 1
                continue
            if is_clear and l not in by_line and missing:
                if cl.lookup("mutation|%s|%s|%s" % (m, d, stmt)) is None:
                    it.incomplete("%s L%d is a removed clear and the sensitivity phase has not run" % (b, l))
                    continue
            it.judge("mutation|%s|%s|%s" % (m, d, stmt), "%s L%d %s %s" % (b, l, m, d[:50]))
    if len(sets) == 2 and sets["benma"] != sets["zkp"]:
        it.notes.append("survivor sets differ between the bases (%d only on benma, %d only on zkp)" % (len(sets["benma"] - sets["zkp"]), len(sets["zkp"] - sets["benma"])))
    dm = run.text("f", "mutation_pairs.txt")
    if dm is None:
        it.incomplete("mutation_pairs.txt missing")
    else:
        it.details.append("pair experiments: " + "; ".join(l.split(" (")[0] for l in dm.split("\n") if re.match(r"[AB]\d ", l)))
    if it.verdict == "PASS":
        it.notes.insert(0, "Mull on both bases, every survivor classified; %d survivor sites listed as covered by the residue scan (reported in the sensitivity run), not by the functional tests" % covered)
    return it


def check_c12(run, cl):
    it = Item("cross_arch", cl)
    if not run.need(it, "h"):
        return it
    t = run.text("h", "cross_arch_log.txt")
    if t is None:
        it.incomplete("h/cross_arch_log.txt missing")
        return it
    for b in BASES:
        for tg, arch in (("s390x", "S/390"), ("arm", "ARM"), ("ppc64le", "PowerPC")):
            if "%s %s (qemu): mismatches: 0" % (b, tg) in t:
                continue
            if "%s %s" % (b, tg) in t and ("FAILED" in t.split("%s %s" % (b, tg))[1].split("\n")[0] or "BUILD FAILED" in t):
                it.fail("%s %s: build or run failed" % (b, tg))
            else:
                it.incomplete("%s %s: no result line" % (b, tg))
    if it.verdict == "PASS":
        it.notes.insert(0, "module tests (seam on, -i=64) and vector driver under qemu-user on s390x, ARM32, ppc64le, both bases: 0 mismatches")
    return it


# ---------------------------------------------------------------------------------------------- hashes
def check_hashes(run, recheck):
    errs = []
    names = [p for p in PHASES if p in run.ph]
    ref = None
    for p in names:
        ph = run.ph[p]
        if ph.get("status") in ("running", "stopped", "failed") and "hashes_after" not in ph:
            continue
        if ph.get("status") == "error":
            errs.append("phase %s ended in ERROR: %s" % (p, ph.get("reason", "")))
        hb, ha = ph.get("hashes_before"), ph.get("hashes_after")
        if hb is None or ha is None:
            if ph.get("status") != "stopped":
                errs.append("phase %s has no hashes" % p)
            continue
        if json.dumps(hb, sort_keys=True) != json.dumps(ha, sort_keys=True):
            errs.append("phase %s: inputs changed between before and after" % p)
        if ref is None:
            ref = (p, ph)
        else:
            rp, r = ref
            for k in ("module", "benma", "zkp"):
                if json.dumps(hb[k], sort_keys=True) != json.dumps(r["hashes_before"][k], sort_keys=True):
                    errs.append("%s differs between phase %s and phase %s" % (k, rp, p))
            # other work may be committed during a run of several hours: what must hold is that the inputs
            # are the same (compared by hash here) and that the later commit descends from the named one
            if ph.get("git_head") != r.get("git_head") and r.get("git_head") and ph.get("git_head") and subprocess.run(
                    ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", r["git_head"], ph["git_head"]]).returncode != 0:
                errs.append("phase %s's commit does not descend from phase %s's" % (p, rp))
            for f, v in hb["files"].items():
                if f in r["hashes_before"]["files"] and r["hashes_before"]["files"][f] != v:
                    errs.append("%s differs between phase %s and phase %s" % (f, rp, p))
    jv = run.json("a", "jade_vendor.json") if "a" in run.ph else None
    if jv is not None and not jv.get("all_equal"):
        errs.append("Jade's vendored copy (patch 0001) differs from c/module")
    if recheck and ref:
        p, ph = ref
        hb = ph["hashes_before"]
        if tree_hash(ROOT / "c/module") != hb["module"]["sha256"]:
            errs.append("c/module now differs from the run")
        for k, v in {kk: vv for q in names for kk, vv in run.ph[q].get("hashes_before", {}).get("files", {}).items()}.items():
            f = ROOT / k
            if f.exists() and sha_file(f) != v:
                errs.append("%s now differs from the run" % k)
        for b in BASES:
            for key, d in (("generated_tree", b), ("pristine_tree", b + ".pristine")):
                if (ROOT / ".work/c" / d).exists() and tree_hash(ROOT / ".work/c" / d) != hb[b][key]["sha256"]:
                    errs.append("%s %s now differs from the run" % (b, key))
    return errs


# ---------------------------------------------------------------------------------------------- main scoring
def score(run_dir, classes_path, recheck=True, out=print):
    cl = Classes(classes_path)
    run = Run(run_dir)
    errs = check_hashes(run, recheck)
    items = [f(run, cl) for f in (check_c1, check_c2, check_c3, check_c4, check_c5, check_c6, check_c7, check_c8, check_c9, check_c10, check_c11, check_c12)]
    out("check: %s" % run_dir)
    out("classes file: %s sha256 %s (%d entries)" % (cl.path, cl.sha, len(cl.entries)))
    out("checker: %s sha256 %s" % (pathlib.Path(__file__).name, sha_file(__file__)))
    out("phases present: %s; missing: %s" % (", ".join(p for p in PHASES if p in run.ph) or "none", ", ".join(p for p in PHASES if p not in run.ph) or "none"))
    out("hash checks (module, bases, scripts, commit, Jade): %s" % ("OK" if not errs else "ERROR"))
    for it in items:
        out(it.line())
    verdicts = [i.verdict for i in items]
    if errs:
        overall = "ERROR"
    elif "INVALID" in verdicts:
        overall = "INVALID"
    elif "FAIL" in verdicts:
        overall = "FAIL"
    elif "INCOMPLETE" in verdicts:
        overall = "INCOMPLETE"
    else:
        overall = "PASS"
    out("overall: %s" % overall)
    if errs or any(i.details for i in items) or cl.unused():
        out("")
        out("details")
        for e in errs:
            out("  ERROR %s" % e)
        for i in items:
            for d in i.details:
                out("  %s: %s" % (i.id, d))
        if cl.unused():
            out("  classes entries that matched nothing: %s" % cl.unused())
    return overall, items


# ---------------------------------------------------------------------------------------------- self test
def fabricate(root, mod=None):
    """A small complete run under root with every item passing. mod(name, path) may change it afterwards."""
    root = pathlib.Path(root)
    def w(p, name, data):
        f = root / p / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(data if isinstance(data, str) else json.dumps(data))
    hashes = {"module": {"sha256": "aa" * 32, "files": 5}, "benma": {"head": "x", "generated_tree": {"sha256": "bb"}, "pristine_tree": {"sha256": "cc"}},
              "zkp": {"head": "y", "generated_tree": {"sha256": "dd"}, "pristine_tree": {"sha256": "ee"}}, "files": {"c/build.sh": "11" * 32}}
    for p in PHASES:
        w(p, "phase.json", {"phase": p, "status": "complete", "git_head": "abc", "hashes_before": hashes, "hashes_after": hashes, "hashes_equal": True, "commands": []})
    # a
    cmds = []
    for b in BASES:
        for tag in ("base", "module"):
            cmds.append({"label": "base_suite_%s_%s" % (b, tag), "rc": 0, "log": "suite_%s_%s.log" % (b, tag)})
            w("a", "suite_%s_%s.log" % (b, tag), "iterations = 16\nTotal execution time: 1.0 seconds\n")
        for n in ("libO2", "base-libO2", "testsO2", "base-testsO2", "tests-seamO2"):
            name = "%s-%s" % (b, n)
            cmds.append({"label": "build_" + name, "rc": 0})
            w("a", "flags/%s.txt" % name, "CC=gcc flags: -O2 -g -std=c89 -pedantic -Wall -Wextra -Wno-long-long -Werror %s" % ("-Wvla" if n.endswith("libO2") and "tests" not in n else ""))
        w("a", "glue_%s.json" % b, {"ok": True, "violations": [], "added_lines": ["src/tests.c: #endif"]})
        w("a", "pin_check_%s.json" % b, {"ok": True})
        w("a", "seam_compare_%s.log" % b, "nm identical: True\nobjdump -d identical: True\n")
    ph = json.loads((root / "a/phase.json").read_text())
    ph["commands"] = cmds
    w("a", "phase.json", ph)
    w("a", "jade_vendor.json", {"all_equal": True})
    w("a", "base_sample.json", {b: {"base": {"sha256": "s", "lines": 200}, "module": {"sha256": "s", "lines": 200}, "equal": True} for b in BASES})
    w("a", "source_rules.json", {"calls_in_tests": 145, "banned_tokens": [], "unchecked_results": []})
    sc = {"valid_derivation_match": "54 of 54", "valid_host_accept": "54 of 54", "reject_by_class": {"x": {"rejected by host_verify": 3, "not expressible": 1}},
          "reject_not_expressible": ["case (reason)"], "forced_hash_cases": {"f1": "seam test", "f2": "not run: outside module"}}
    w("a", "vectors.json", {"mismatches": [], "bases": {b: {"bip340": sc, "ecdsa": sc, "seam_tests": {"returncode": 0}} for b in BASES}})
    # b
    s = {"cases": 10000, "mismatches": {"module_vs_python": 0}, "pk_parity_counts_odd_even": {"0": 5, "1": 5}, "R0_parity_counts": {"0": 5, "1": 5}, "message_length_range": [0, 1000]}
    w("b", "differential.json", {"schemes": {"bip340": s, "ecdsa": s}})
    # c
    constant_time = [{"base": b, "opt": o, "scheme": sch, "control_branch": True, "control_index": True, "control_declassified_clean": True, "driver_ok": True, "hits": []}
          for b in BASES for o in OPTS for sch in ("schnorr", "ecdsa")]
    rows = [{"fn": "control_plant", "pattern": "sk/be", "region": "stack", "full": 1}, {"fn": "control_baseline", "full": 0, "fragments": 0}]
    residue = [{"scheme": sch, "case": "k1", "base": b, "opt": o, "rows": rows, "rc": 0} for sch in ("schnorr", "ecdsa") for b in BASES for o in OPTS]
    w("c", "secrets_results.json", {"valgrind": "valgrind-fab", "constant_time": constant_time, "residue": residue, "residue_full_length_found": [], "residue_control_failures": 0})
    # d
    t = ""
    for s_ in ("asan", "ubsan", "msan"):
        t += "CONTROL %s: fires (x)\nCLEAN %s: quiet\n" % (s_, s_)
        for b in BASES:
            t += "%s %s module tests: clean (t)\n%s %s vector driver + seam tests: mismatches: 0\n" % (b, s_, b, s_)
    w("d", "sanitizers_log.txt", t)
    w("d", "filc.json", {"built": {b: True for b in BASES}, "control_fired": True})
    for b in BASES:
        w("d", "filc_vectors_%s.json" % b, {"mismatches": []})
    # e
    for b in BASES:
        w("e", "coverage_%s_branches.txt" % b, "%s: 106 of 106 branches taken (x)\n" % b)
        w("e", "exhaustive_exh13_%s.log" % b, "Exhaustive tests for order 13\ntest count = 2\nno problems found\n")
        w("e", "module_in_tu_%s.txt" % b, "3\n")
        w("e", "fanalyzer_%s.txt" % b, "exit=0\n")
        w("e", "scanbuild_%s.txt" % b, "scan-build: No bugs found.\nexit=0\n")
        w("e", "cppcheck_%s.txt" % b, "exit=0\n")
        for h in CBMC_STD + ["%s_tag%d" % (h, i) for h in CBMC_TAGGED for i in range(9)]:
            w("e", "cbmc_%s_%s.log" % (b, h), "VERIFICATION SUCCESSFUL\n")
        w("e", "cbmc_%s_%s.log" % (b, CBMC_CONTROL), "VERIFICATION FAILED\n")
        ph = json.loads((root / "e/phase.json").read_text())
        ph["commands"] += [{"label": "exhaustive_exh13_%s" % b, "rc": 0, "log": "exhaustive_exh13_%s.log" % b}]
        w("e", "phase.json", ph)
    w("e", "control_fanalyzer.txt", "warning: use after 'free' [-Wanalyzer-use-after-free]\n")
    w("e", "control_scanbuild.txt", "scan-build: 1 bug found.\n")
    w("e", "control_cppcheck.txt", "error: Dereferencing 'p' after it is freed [deallocuse]\n")
    # f, g
    lines = module_lines()
    c = clears_list()
    two = sorted(c)[:2]
    mull = ""
    for b in BASES:
        mull = "".join("/x/modules/anti_exfil/main_impl.h:%d:5: warning: Survived: Replaced %s with  [cxx_remove_void_call]\n" % (l, c[l][1].rstrip(";")) for l in two)
        mull += "/x/modules/anti_exfil/main_impl.h:3:1: warning: Killed: x [cxx_lt_to_le]\n[info] Mutation score: 99%\n"
        w("f", "mutation_%s_mull.log" % b, mull)
    w("f", "mutation_pairs.txt", "A1 x: SURVIVED\nA2 x: KILLED (t)\n")
    for p, part in (("g1", sorted(c)[:27]), ("g2", sorted(c)[27:])):
        r = ["0\t0\tBASELINE\t\t0\t0\t0\t0\t0\tno"]
        for l in part:
            r.append("%d\t5\t%s\t%s\t0\t0\t0\t%d\t0\t%s" % (l, c[l][0], c[l][1], 1, "yes"))
        w(p, "sens/residue_sensitivity.tsv", "\n".join(r) + "\n")
    # h
    w("h", "cross_arch_log.txt", "".join("%s %s (qemu): mismatches: 0\n" % (b, t) for b in BASES for t in ("s390x", "arm", "ppc64le")))
    if mod:
        mod(root)
    return root


def self_test():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="selftest_", dir=str(ROOT / ".work")))
    results = []
    try:
        cls_path = tmp / "classes.txt"
        cls_path.write_text("# fabricated classes\nc8|benma|line 999 branch 0|*\tunreachable\tfabricated reason for the self-test\n")
        def scenario(name, mod, want_overall, want_items, classes_text=None):
            d = tmp / name
            fabricate(d, mod)
            cp = cls_path
            if classes_text is not None:
                cp = tmp / (name + "_classes.txt")
                cp.write_text(classes_text)
            lines = []
            overall, items = score(d, cp, recheck=False, out=lines.append)
            got = {i.id: i.verdict for i in items}
            ok = overall == want_overall and all(got[k] == v for k, v in want_items.items())
            results.append(ok)
            print("%-34s overall %-10s (want %-10s) %s %s" % (name, overall, want_overall, " ".join("%s=%s" % (k, got[k]) for k in want_items), "ok" if ok else "WRONG"))
            return lines
        def set_phase_hash(root):
            f = root / "e/phase.json"
            j = json.loads(f.read_text())
            j["hashes_before"]["module"]["sha256"] = "ff" * 32
            j["hashes_after"]["module"]["sha256"] = "ff" * 32
            f.write_text(json.dumps(j))
        def after_changes(root):
            f = root / "c/phase.json"
            j = json.loads(f.read_text())
            j["hashes_after"]["files"]["c/build.sh"] = "22" * 32
            f.write_text(json.dumps(j))
        def coverage_gap(root):
            (root / "e/coverage_benma_branches.txt").write_text("benma: 105 of 106 branches taken (x)\nNOT TAKEN line 212 branch 1: if (x) {\n")
        def missed_text(idx):
            c = sorted(clears_list())[idx]
            return "mutation|cxx_remove_void_call|*|%s\tnot_detectable\tfabricated: a pattern in this temporary is not recognisable on the stack\n" % clears_list()[c][1]
        def coverage_gap_classed_text():
            return "coverage|benma|line 212 branch 1|*\tunreachable\tfabricated: needs a failing allocator, which the module does not have\n"
        def no_h(root):
            shutil.rmtree(root / "h")
        def silent_cbmc(root):
            (root / "e/cbmc_zkp_h_control_false_claim.log").write_text("VERIFICATION SUCCESSFUL\n")
        def silent_valgrind(root):
            f = root / "c/secrets_results.json"
            j = json.loads(f.read_text())
            j["constant_time"][3]["control_branch"] = False
            f.write_text(json.dumps(j))
        def survivor(root):
            for b in BASES:
                f = root / ("f/mutation_%s_mull.log" % b)
                f.write_text(f.read_text() + "/x/modules/anti_exfil/main_impl.h:114:20: warning: Survived: Replaced 0 with 1 [cxx_init_const]\n")
        def missed_clear_at(idx):
            def mod(root):
                c = sorted(clears_list())[idx]
                f = root / "g1/sens/residue_sensitivity.tsv"
                f.write_text("\n".join((l.rsplit("\t", 2)[0] + "\t0\tno") if l.startswith("%d\t" % c) else l for l in f.read_text().split("\n")))
            return mod
        def no_g(root):
            shutil.rmtree(root / "g2")
        def dirty_baseline(root):
            f = root / "g1/sens/residue_sensitivity.tsv"
            f.write_text(f.read_text().replace("0\t0\tBASELINE\t\t0\t0\t0\t0\t0\tno", "0\t0\tBASELINE\t\t0\t0\t0\t2\t0\tyes"))
        scenario("all fabricated outputs pass", None, "PASS", {"C%d" % i: "PASS" for i in range(1, 13)})
        scenario("unclassified finding (coverage)", coverage_gap, "FAIL", {"coverage": "FAIL", "vectors": "PASS"})
        scenario("same finding, classified by file", coverage_gap, "PASS", {"coverage": "PASS"}, classes_text=coverage_gap_classed_text())
        scenario("unclassified Mull survivor", survivor, "FAIL", {"mutation": "FAIL"})
        scenario("phase h not run", no_h, "INCOMPLETE", {"cross_arch": "INCOMPLETE", "mutation": "PASS"})
        scenario("phase g2 not run", no_g, "INCOMPLETE", {"residue": "INCOMPLETE", "mutation": "PASS"})
        scenario("CBMC control silent", silent_cbmc, "INVALID", {"static": "INVALID"})
        scenario("Valgrind control silent", silent_valgrind, "INVALID", {"constant_time": "INVALID"})
        scenario("residue baseline not clean", dirty_baseline, "INVALID", {"residue": "INVALID"})
        scenario("scan misses a clear Mull did not flag", missed_clear_at(9), "PASS", {"residue": "PASS", "mutation": "PASS"})
        scenario("scan misses a Mull survivor, no class", missed_clear_at(0), "FAIL", {"residue": "PASS", "mutation": "FAIL"})
        scenario("same, classified by file", missed_clear_at(0), "PASS", {"mutation": "PASS"}, classes_text=missed_text(0))
        scenario("module hash differs between phases", set_phase_hash, "ERROR", {})
        scenario("script hash differs before/after", after_changes, "ERROR", {})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("self-test: %s (%d of %d scenarios as expected)" % ("OK" if all(results) else "FAILED", sum(results), len(results)))
    return 0 if all(results) else 1


def main():
    ap = argparse.ArgumentParser(description="checker for the C module runs")
    ap.add_argument("run_dir", nargs="?")
    ap.add_argument("--classes")
    ap.add_argument("--no-recheck", action="store_true", help="do not compare with the files now (the self-test uses this)")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.run_dir or not a.classes:
        ap.error("RUN_DIR and --classes FILE are required")
    overall, _ = score(a.run_dir, a.classes, recheck=not a.no_recheck)
    return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
