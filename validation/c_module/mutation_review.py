#!/usr/bin/env python3
"""Reads the Mull logs of both bases and writes mutation_review.md with every survivor classified by hand
(rules below, one written reason per class). Survivor sets are compared between the bases."""
import os, re, collections, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[2]
OUTD = pathlib.Path(os.environ.get("C_OUT", ROOT / ".work/c_module"))
src = (ROOT / ".work/c/benma/src/modules/anti_exfil/main_impl.h").read_text().split("\n")
def load(b):
    t = (OUTD / ("mutation_%s_mull.log" % b)).read_text()
    sv = set(re.findall(r"main_impl\.h:(\d+):(\d+): warning: Survived: (.*?) \[(\w+)\]", t))
    kl = len(re.findall(r"warning: Killed", t))
    sc = re.search(r"Mutation score: (\d+)%", t).group(1)
    return sv, kl, sc
A = {
 "A": ("zeroization removed", "MATTERS (confidentiality). Not observable from a functional test: the output is the same with or without the clear. Covered by the residue residue scan, whose sensitivity to each removal is shown in residue_sensitivity.txt (each is reported as a full-length secret in dead memory; the unmutated build gives none). The other removals are not individually sampled."),
 "B": ("declassify removed", "Equivalent in a normal build: secp256k1_declassify is a no-op unless the build defines VALGRIND. It is what constant_time observes: with VALGRIND defined, a missing declassify on a public output gives a Valgrind report (seen while writing the module), and constant_time passes with them present."),
 "C": ("fallback cmov (value forced to 1 when the call has already failed)", "Equivalent on outputs. When the flag is already 0 the output is zeroed or the call rejected anyway; the cmov only keeps zero and infinity out of the later arithmetic. For the k' one (Schnorr, ECDSA) it is also a second barrier: see the pair experiments in mutation_pairs.txt."),
 "D": ("zero / infinity predicate replaced by 0", "MATTERS (decides acceptance), redundant by design. x = 0 is not the x coordinate of any curve point (checked: 7 is a non-residue), so an infinity result, which becomes (0, 0), can never equal a genuine r or x(W): the W-infinity and V-infinity checks are backed by the later x comparisons and by the base's BIP340 verify, and the s = 0 check by V = infinity. k' = 0 gives W = infinity at the host, so the k' check is backed by the self-check. r = 0 is backed by x(W) mod n = r plus V = +/-W; a case where it alone decides needs a point with x = n (x = n is on the curve) and the discrete log of that point, which no test can build. The vectors' forced W-infinity, k'-zero and isolated cases reject, but through these backups. Removing both members of a pair was not tried for the verify-side ones."),
 "E": ("&= replaced by |= on a failure-propagation line", "MATTERS (decides whether a failed call returns a signature), redundant by construction: the k' fallback cmov makes the signature inconsistent with the host's own t, so the self-check still rejects. The pair (|= plus the cmov removed) is killed, mutation_pairs.txt A2 and B2."),
 "F": ("ret = 0 -> ret = 1 when sig r >= p", "Equivalent: the base's schnorrsig_verify, called two lines later, rejects r >= p."),
 "G": ("dead initialiser (int overflow = 0 -> 1)", "Equivalent: scalar_set_b32 assigns overflow before it is read."),
 "H": ("loop bound i < 32 -> i <= 32 on the xor mask", "Not killable by a functional test (one stray byte on the stack). It is a different program with a one-byte overrun; the ASan and UBSan runs (sanitizers) exercise the real loops and report nothing."),
 "S": ("test seam code", "Test-only code (SECP256K1_ANTI_EXFIL_TEST_SEAM), absent from the normal build (seam_compare.py)."),
}
def cat(l, m, d):
    line = src[int(l) - 1]
    if m == "cxx_remove_void_call":
        if re.search(r"_clear|memclear", d): return "A"
        if "declassify" in d: return "B"
        if "cmov" in d: return "C"
    if m == "cxx_replace_scalar_call_zr": return "D"
    if m == "cxx_and_assign_to_or_assign": return "E"
    if m == "cxx_assign_const": return "F"
    if m == "cxx_init_const": return "G"
    if m == "cxx_lt_to_le" and "i < 32" in line: return "H"
    if m in ("cxx_lt_to_le", "cxx_gt_to_ge") and int(l) < 100: return "S"
    return "?"
out = ["# Mull review of the anti-exfil module", "",
       "Tool: Mull 0.37.0 (LLVM 21.1.8), mutators cxx_all, mutations limited to src/modules/anti_exfil/main_impl.h. Tests: the library's tests.c with the module tests and the test seam, `-t=anti_exfil -i=16`. Not-covered mutants included.", ""]
sets = {}
for b in ("benma", "zkp"):
    sv, kl, sc = load(b); sets[b] = sv
    out.append("- %s: %d mutants, %d killed, %d survived, score %s%%" % (b, kl + len(sv), kl, len(sv), sc))
out.append("- survivor sets identical between the bases: %s" % (sets["benma"] == sets["zkp"]))
out.append("")
sv = sorted(sets["benma"], key=lambda x: (int(x[0]), int(x[1])))
cnt = collections.Counter(cat(l, m, d) for l, c, d, m in sv)
out.append("| class | count | what | verdict |"); out.append("|---|---|---|---|")
for k in "ABCDEFGHS":
    out.append("| %s | %d | %s | %s |" % (k, cnt.get(k, 0), A[k][0], A[k][1]))
if cnt.get("?"): out.append("| ? | %d | UNCLASSIFIED | fails |" % cnt["?"])
out += ["", "## Every survivor (benma line numbers; the zkp set is identical)", "", "| line | mutator | change | class | source |", "|---|---|---|---|---|"]
for l, c, d, m in sv:
    out.append("| %s | %s | %s | %s | `%s` |" % (l, m, d.replace("|", "\\|")[:70], cat(l, m, d), src[int(l) - 1].strip().replace("|", "\\|")[:80]))
(OUTD / "mutation_review.md").write_text("\n".join(out) + "\n")
print("\n".join(out[:20]))
