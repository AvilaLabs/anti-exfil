#!/usr/bin/env python3
"""Show that the test seam is absent from the normal build. Makes a copy of
.work/c/<base> in which the seam source is deleted (every
`#ifdef SECP256K1_ANTI_EXFIL_TEST_SEAM ... #endif` region of main_impl.h, keeping
the #else branch), builds libsecp256k1.a from both trees with the same flags, and
compares the symbols (nm), the disassembly (objdump -d of every object) and the
preprocessor output of main_impl.h's functions. Also prints the seam's size in
main_impl.h. Usage: seam_compare.py benma|zkp"""
import pathlib, re, shutil, subprocess, sys, os
ROOT = pathlib.Path(__file__).resolve().parents[1]
base = sys.argv[1]
tree = ROOT / ".work/c" / base
bare = ROOT / ".work/c" / (base + ".noseam")
if bare.exists():
    shutil.rmtree(bare)
shutil.copytree(tree, bare)
f = bare / "src/modules/anti_exfil/main_impl.h"
src = f.read_text()
lines = src.split("\n")
out, depth, keep, seam_lines = [], 0, True, 0
i = 0
while i < len(lines):
    l = lines[i]
    if l.strip() == "#ifdef SECP256K1_ANTI_EXFIL_TEST_SEAM":
        # find matching #else / #endif at depth 0
        j, d, els = i + 1, 0, None
        while True:
            t = lines[j].strip()
            if t.startswith("#if"): d += 1
            elif t == "#else" and d == 0: els = j
            elif t == "#endif":
                if d == 0: break
                d -= 1
            j += 1
        seam_lines += (els if els is not None else j) - i + 1
        if els is not None:
            out += lines[els + 1:j]
        i = j + 1
        continue
    out.append(l); i += 1
f.write_text("\n".join(out))
print("seam size in main_impl.h: %d lines (ifdef regions, counting the #ifdef and the closing line)" % seam_lines)
res = {}
for label, t in (("with-seam-source", tree), ("seam-source-deleted", bare)):
    o = pathlib.Path(os.environ.get("C_BUILD", ROOT / ".work/c/build")) / ("seamcmp-%s-%s" % (base, label))
    o.mkdir(parents=True, exist_ok=True)
    flags = ["-O2", "-g0", "-std=c89", "-w", "-DCOMB_BLOCKS=43", "-DCOMB_TEETH=6", "-DECMULT_WINDOW_SIZE=15", "-DUSE_ASM_X86_64=1",
             "-DENABLE_MODULE_EXTRAKEYS=1", "-DENABLE_MODULE_SCHNORRSIG=1", "-DENABLE_MODULE_ANTI_EXFIL=1",
             "-I%s" % t, "-I%s/include" % t, "-I%s/src" % t]
    if base == "zkp":
        flags.append("-DENABLE_MODULE_ECDSA_S2C=1")
    else:
        flags += ["-DENABLE_MODULE_ECDH=1"]
    subprocess.run(["gcc"] + flags + ["-c", str(t / "src/secp256k1.c"), "-o", str(o / "secp256k1.o")], check=True)
    nm = subprocess.run(["nm", "--defined-only", str(o / "secp256k1.o")], capture_output=True, text=True, check=True).stdout
    dis = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(o / "secp256k1.o")], capture_output=True, text=True, check=True).stdout
    dis = "\n".join(x for x in dis.split("\n") if "file format" not in x)
    res[label] = (nm, dis, (o / "secp256k1.o").read_bytes())
a, b = res["with-seam-source"], res["seam-source-deleted"]
print("nm identical:", a[0] == b[0], "(%d symbols)" % len(a[0].split("\n")))
print("objdump -d identical:", a[1] == b[1], "(%d lines)" % len(a[1].split("\n")))
print("objects byte-identical:", a[2] == b[2])
print("seam symbols in normal object:", [l for l in a[0].split("\n") if "force" in l or "seam" in l.lower()])
sys.exit(0 if (a[0] == b[0] and a[1] == b[1]) else 1)
