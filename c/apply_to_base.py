#!/usr/bin/env python3
"""Copy a pinned base library to .work/c/<base>/ and add the
anti-exfil module and the minimum build glue.

Usage: apply_to_base.py benma|zkp [--src DIR] [--out DIR] [--replace]

The base is exported with `git archive` from a git checkout at its pin, so
nothing in the source checkout is written. The module files are copied from
c/module/ unchanged. The glue is exact text replacement in four existing
files, each block asserted to occur exactly once. The edits are listed in
.work/c/<base>/GLUE.txt, and the result is also written as GLUE.diff
against the pristine export (kept in <out>.pristine for the comparison).
"""
import argparse
import difflib
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "c/module"

BASES = {
    "benma": {
        "pin": "b4d2b22e39832d4332ce889aac40812ff1c4cbad",
        "src": ROOT / ".work/secp1140/pr1140",    # the checkout secp1140/run.sh makes
        "define": "",
    },
    "zkp": {
        "pin": "45f6f0f158c5ae80a2c8a53398ea4adbf19af6dc",
        "src": ROOT / ".work/secp1140/zkp",       # the checkout secp1140/run.sh makes
        "define": "# define SECP256K1_ANTI_EXFIL_ECMULT_GEN_PLAIN 1\n",
    },
}

OVERLAY = [
    "include/secp256k1_anti_exfil.h",
    "src/modules/anti_exfil/main_impl.h",
    "src/modules/anti_exfil/tests_impl.h",
    "src/modules/anti_exfil/tests_vectors.h",
    "src/modules/anti_exfil/tests_exhaustive_impl.h",
]


def replace_once(path, old, new, log):
    s = path.read_text()
    n = s.count(old)
    if n != 1:
        sys.exit("glue anchor occurs %d times (want 1) in %s:\n%s" % (n, path, old))
    path.write_text(s.replace(old, new))
    log.append("%s: after anchor %r" % (path.name, old.strip().splitlines()[0]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base", choices=sorted(BASES))
    ap.add_argument("--src")
    ap.add_argument("--out")
    ap.add_argument("--replace", action="store_true", help="remove an earlier output tree first")
    a = ap.parse_args()
    cfg = BASES[a.base]
    src = pathlib.Path(a.src or os.environ.get("AE_%s_SOURCE" % a.base.upper(), cfg["src"]))
    out = pathlib.Path(a.out or ROOT / ".work/c" / a.base)
    pristine = out.with_name(out.name + ".pristine")
    got = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if got != cfg["pin"]:
        sys.exit("pin mismatch for %s: want %s, got %s" % (a.base, cfg["pin"], got))
    for d in (out, pristine):
        if d.exists():
            if not a.replace:
                sys.exit("%s exists; use --replace" % d)
            shutil.rmtree(d)
        d.mkdir(parents=True)
    # git archive reads the repository and writes only to the pipe.
    for d in (pristine, out):
        p = subprocess.Popen(["git", "-C", str(src), "archive", "--format=tar", "HEAD"], stdout=subprocess.PIPE)
        subprocess.run(["tar", "-xf", "-", "-C", str(d)], stdin=p.stdout, check=True)
        if p.wait():
            sys.exit("git archive failed")

    for rel in OVERLAY:
        dst = out / rel
        if dst.exists():
            sys.exit("overlay file already in base: %s" % rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(MODULE / rel, dst)

    log = []
    s = out / "src"
    replace_once(s / "secp256k1.c",
                 '#ifdef ENABLE_MODULE_ELLSWIFT\n# include "modules/ellswift/main_impl.h"\n#endif\n',
                 '#ifdef ENABLE_MODULE_ELLSWIFT\n# include "modules/ellswift/main_impl.h"\n#endif\n\n'
                 '#ifdef ENABLE_MODULE_ANTI_EXFIL\n' + cfg["define"] + '# include "modules/anti_exfil/main_impl.h"\n#endif\n', log)
    replace_once(s / "tests.c",
                 '#ifdef ENABLE_MODULE_ELLSWIFT\n# include "modules/ellswift/tests_impl.h"\n#endif\n',
                 '#ifdef ENABLE_MODULE_ELLSWIFT\n# include "modules/ellswift/tests_impl.h"\n#endif\n\n'
                 '#ifdef ENABLE_MODULE_ANTI_EXFIL\n# include "modules/anti_exfil/tests_impl.h"\n#endif\n', log)
    replace_once(s / "tests.c",
                 '#ifdef ENABLE_MODULE_ELLSWIFT\n    MAKE_TEST_MODULE(ellswift),\n#endif\n',
                 '#ifdef ENABLE_MODULE_ELLSWIFT\n    MAKE_TEST_MODULE(ellswift),\n#endif\n'
                 '#ifdef ENABLE_MODULE_ANTI_EXFIL\n    MAKE_TEST_MODULE(anti_exfil),\n#endif\n', log)
    replace_once(s / "tests_exhaustive.c",
                 '#ifdef ENABLE_MODULE_ELLSWIFT\n#include "modules/ellswift/tests_exhaustive_impl.h"\n#endif\n',
                 '#ifdef ENABLE_MODULE_ELLSWIFT\n#include "modules/ellswift/tests_exhaustive_impl.h"\n#endif\n\n'
                 '#ifdef ENABLE_MODULE_ANTI_EXFIL\n#include "modules/anti_exfil/tests_exhaustive_impl.h"\n#endif\n', log)
    replace_once(s / "tests_exhaustive.c",
                 '#ifdef ENABLE_MODULE_SCHNORRSIG\n        test_exhaustive_schnorrsig(ctx);\n#endif\n',
                 '#ifdef ENABLE_MODULE_SCHNORRSIG\n        test_exhaustive_schnorrsig(ctx);\n#endif\n'
                 '#ifdef ENABLE_MODULE_ANTI_EXFIL\n        test_exhaustive_anti_exfil(ctx, group);\n#endif\n', log)

    # Diff against the pristine export: only the four glue files may differ,
    # and the overlay files are new.
    changed = []
    for dp, _, fs in os.walk(out):
        for f in fs:
            p = pathlib.Path(dp) / f
            rel = p.relative_to(out).as_posix()
            q = pristine / rel
            if not q.exists():
                if rel not in OVERLAY:
                    sys.exit("unexpected new file " + rel)
                continue
            if p.read_bytes() != q.read_bytes():
                changed.append(rel)
    assert sorted(changed) == ["src/secp256k1.c", "src/tests.c", "src/tests_exhaustive.c"], changed
    diff = []
    for rel in sorted(changed):
        diff += difflib.unified_diff((pristine / rel).read_text().splitlines(True),
                                     (out / rel).read_text().splitlines(True), "a/" + rel, "b/" + rel)
    (out / "GLUE.diff").write_text("".join(diff))
    (out / "GLUE.txt").write_text("base %s at %s\nexisting files changed: %s\nnew files: %s\nedits:\n  %s\n" % (
        a.base, cfg["pin"], ", ".join(sorted(changed)), ", ".join(OVERLAY), "\n  ".join(log)))
    print("applied the module to", out)
    print((out / "GLUE.txt").read_text())


if __name__ == "__main__":
    main()
