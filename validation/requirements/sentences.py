"""Sentence splitting and normative-word detection shared by the checker and the builder of the requirements file."""
import re

# Words that make a sentence normative. TIER1 is the protocol's list; TIER2 is stricter.
TIER1 = re.compile(r"\b(MUST NOT|MUST|SHOULD NOT|SHOULD|MAY)\b|\bfail if\b|\bfails\b", re.I)
TIER1_CASE = re.compile(r"\b(MUST NOT|MUST|SHOULD NOT|SHOULD|MAY)\b")
TIER2 = re.compile(r"\bfail\b|\bfailed\b|\bmust\b|\bshall\b|\bnever\b|\brefus\w*\b", re.I)
_END = re.compile(r"(?<=[.!?:])\s+(?=[A-Z`*(<\-])")


def sentences(line):
    """Yield (start, end, text) spans of the sentences of one source line."""
    out, pos = [], 0
    if line.lstrip().startswith("|") or line.lstrip().startswith("```"):
        return [(0, len(line), line)] if line.strip() else []
    for m in _END.finditer(line):
        out.append((pos, m.start(), line[pos:m.start()]))
        pos = m.end()
    if pos < len(line):
        out.append((pos, len(line), line[pos:]))
    return [s for s in out if s[2].strip()]


def tier(text):
    t = re.sub(r"<!--.*?-->", "", text)
    if TIER1_CASE.search(t) or re.search(r"\bfail if\b|\bfails\b", t, re.I):
        return 1
    if TIER2.search(t):
        return 2
    return 0
