#!/usr/bin/env python3
"""Targeted mutants: textual patches applied to temporary copies of psbt/.

Two sources. REUSED are the 108 disabled-check mutants of psbt/tests/mutation_check.py (imported
read-only; their patches are applied unchanged), each mapped here to the requirement rows it violates.
NEW are written for the requirement rows. Each mutant is {id, reqs, file, patches, tests, desc, source}; a patch is
(old, new) or (old, new, count) and the old text must occur exactly `count` times (default 1) or the
mutant is stale. Pinned sources are never edited: apply() takes source text and returns mutated text.

`tests` are the tests the mutant is expected to turn red (reused: the ones mutation_check names; new: the
coverage of the rows it violates, filled in by check.py from requirements.json).
"""
import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MUTATION_CHECK = ROOT / "psbt/tests/mutation_check.py"

# ---- requirement rows violated by each reused mutant -------------------------------------
REUSED_REQS = {
    "Y1-link-exception": ["P-038"], "Y2-recover-own-device": ["P-045"], "Y3-count-after-recovery": ["P-043"],
    "Y4-keep-count": ["P-046"], "Y5-erase-req2": ["P-027"], "Y6-duplicate-leaf": ["B-005"], "Y8-modifiable-parse": ["B-096"],
    "Y9-optional-direct": ["B-019"],
    "H01-core-tx": ["B-083", "B-084"], "H02-commitment-missing": ["B-068", "B-070", "B-085", "B-116"],
    "H03-signature-missing": ["B-085"], "H04-hc-echo": ["B-086"], "H05-r0-changed": ["P-050", "B-086"],
    "H06-r0-from-rejected": ["P-050"], "H07-second-pass-ae": ["B-087"], "H08-rho-first-pass": ["B-088"],
    "H09-unrequested-pair": ["B-088"], "H10-sig-removed": ["B-089"], "H10b-removal-always-allowed": ["B-089"],
    "H10c-removal-never-allowed": ["B-089"], "H10d-witness-only": ["B-089"], "H10e-scriptsig-only": ["B-089"],
    "H11-sig-changed": ["B-089"], "H12-sig-added": ["B-089", "B-068", "P-069"], "H13-sig-added-unrequested-allowed": ["B-089"],
    "V01-der": ["B-076"], "V02-ecdsa-sighash": ["B-041", "B-077"], "V03-tap-length": ["B-041", "B-077"],
    "V04-tap-sighash": ["B-041", "B-077"], "V05-ecdsa-verify": ["P-015", "P-016", "P-022", "B-075"],
    "V06-bip340-verify": ["P-015", "B-075"], "V08-reject-all": ["P-016", "P-034", "B-078"],
    "R01-copy-response": ["P-016", "P-072", "B-006", "B-071", "B-079", "B-082", "B-091"], "R02-v2-flags": ["B-080"],
    "R03-step3-tx": ["P-006", "B-073", "B-074"], "R04-step3-pairs": ["P-006", "B-073", "B-074"],
    "PA01-preexisting-ae": ["B-063"], "PA02-no-pairs": ["B-066"], "PA03-skip-signed": ["B-059"],
    "PA04-keypath-precedence": ["B-058"], "PA05-cb1-duplicate-pairs": ["B-054"], "PA06b-hybrid": ["B-028"],
    "PA06c-no-leaf-note": ["B-061"], "PA06-uncompressed": ["B-027", "B-028"], "PA07-notify": ["B-067"],
    "L01-record-before-hc": ["P-032"], "L03-count-once": ["P-043"], "L04-recover": ["P-045"], "L05-recover-double": ["P-045"],
    "L06-warn": ["P-055", "P-057", "P-062"], "L07-ack-scope": ["P-057", "P-058"], "L08-unreadable-all": ["P-046"],
    "L09-unreadable-device": ["P-046"], "L10-retry-bound": ["P-049", "P-054"], "L11-same-rho": ["P-051"],
    "L12-abandon-charged": ["P-035"], "L13-cancel": ["P-038"], "L14-unsolicited": ["P-038", "P-039"],
    "L15-decline-always": ["P-063", "P-037"], "L15b-decline-related": ["P-064"], "L21-stop-after-rho": ["P-036"], "L22-rho-flag": ["P-036"],
    "L23-same-tx": ["P-060", "P-061"], "L24-user-choice": ["P-060", "P-061"], "L25-recovered-failed-mark": ["P-060"],
    "L26-completed-clears": ["P-060"], "L27-decline-after-counted": ["P-063"], "L28-discard-outside": ["P-039"],
    "L29-poll-counts": ["P-039"], "L30-ack-not-consumed": ["P-058"], "L31-reset-keeps-warned": ["P-059"],
    "L32-unreadable-two": ["P-046"], "L33-step2-budget": ["P-050", "P-053"], "L33b-step2-own-budget": ["P-050", "P-053"], "L16-fsync": ["P-043"],
    "L18-reset-no-confirm": ["P-048"], "L19-failure-limit": ["P-065"], "L20-secrets": ["P-023", "P-024"],
    "S01-hc": ["P-012", "P-019", "B-104", "B-106"], "S02-r0": ["P-012", "P-019", "B-104", "B-106"], "S03-already-signed": ["B-097"],
    "S04-both-paths": ["B-100"], "S05-mixed": ["B-102"], "S06-nonce-only": ["B-110"], "S07-approval": ["P-029"],
    "S08-key-ownership": ["B-099"], "S09-strip": ["B-109"],
    "C40-nonminimal-key-type": ["B-002"], "S40-multisig-key-valid": ["B-016"], "G40-purpose-check": ["B-092"],
    "X01-finalized": ["B-042"], "X02-nw-txid": ["B-047"], "X03-nw-index": ["B-047"], "X04-utxo-disagree": ["B-046"],
    "X05-missing-utxo": ["B-043"], "X06-redeem": ["B-043"], "X07-witness-script": ["B-043"], "X08-output-key": ["B-043"],
    "X30-internal-key": ["B-099"], "X31b-hybrid-record": ["B-028"], "X31-uncompressed-record": ["B-028"],
    "X09-control-block": ["B-023", "B-043"], "X10-depth": ["B-023"], "X11-leaf-ambiguous": ["B-022"], "X12-leaf-missing": ["B-022"],
    "X13-leaf-version": ["B-023"], "X14-op-success": ["B-025"], "X15-codesep": ["B-026"], "X16-mapping": ["B-024"],
    "X17-sighash-unsupported": ["B-034", "B-037"], "X18-zero-ecdsa": ["B-037"], "X19-sighash-length": ["B-035"],
    "X20-single-legacy": ["P-007", "B-037"], "X21-musig-participant": ["B-029"], "X22-musig-aggregate": ["B-030"],
    "X24-legacy-nonwitness": ["B-044"], "X26-optional": ["B-019", "B-020"], "X27-multisig-ambiguous": ["B-018", "B-064"],
    "X28-fee-verified": ["B-112"], "X29-fee-nw": ["B-112", "B-113"],
}


def _load_reused():
    spec = importlib.util.spec_from_file_location("mutation_check_import", str(MUTATION_CHECK))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = []
    for mid, file, pairs, tests, desc in mod.M:
        out.append({"id": mid, "reqs": REUSED_REQS.get(mid, []), "file": file, "patches": [tuple(p) for p in pairs],
                    "tests": list(tests), "desc": desc, "source": "mutation_check.py"})
    return out


NEW = []


def N(mid, reqs, file, desc, *patches):
    NEW.append({"id": mid, "reqs": list(reqs), "file": file, "patches": [tuple(p) for p in patches],
                "tests": None, "desc": desc, "source": "new"})


# control: a no-op that must survive
N("N00-noop", [], "host.py", "no-op: a comment on the first import line (must survive)", ("import copy\n", "import copy  # no-op\n"))

# ----------------------------------------------------------------------------- signer.py
N("N01-field-length", ["P-003", "B-004"], "signer.py", "signer: field value lengths unchecked",
  ('                if len(val) != {C.AE_HC: 32, C.AE_R0: 33, C.AE_RHO: 32}[typ]:\n', "                if False:\n"))
N("N02-keyid-length", ["P-003", "B-004", "B-027"], "signer.py", "signer: key identifier length unchecked in the table loop",
  ("                if len(keyid) not in (33, 32, 64):\n", "                if False:\n"))
N("N03-approval-removed", ["P-029"], "signer.py", "signer: the approval callback is never called",
  ('        if self._approve(self._describe(p, pairs, fee, fee_ok, unverified)) is not True:\n            raise SignerFail("not_approved", "the user did not approve")\n', ""))
N("N04-approval-no-leaf", ["P-030"], "signer.py", "signer: approval omits the leaf",
  ('"leaf_hash": pr.leaf.hex() if pr.leaf else None,', '"leaf_hash": None,'))
N("N05-approval-no-sighash", ["P-030"], "signer.py", "signer: approval hides the sighash type",
  ('"sighash": sighash_name(pr.sighash), "sighash_type": pr.sighash,', '"sighash": "ALL", "sighash_type": 1,'))
N("N06-approval-first-pass", ["P-031", "B-105"], "signer.py", "signer: the first pass demands approval",
  ("        out = p.clone()\n        if not second:\n", '        out = p.clone()\n        if not second and self._approve({}) is not True:\n            raise SignerFail("not_approved", "x")\n        if not second:\n'))
N("N07-approval-per-pair", ["B-107"], "signer.py", "signer: one approval per pair instead of one for the PSBT",
  ("        for k, pr in pairs.items():\n            rho = table[k][C.AE_RHO]\n",
   "        for k, pr in pairs.items():\n            self._approve(self._describe(p, pairs, fee, fee_ok, unverified))\n            rho = table[k][C.AE_RHO]\n"))
N("N08-approval-early", ["B-096"], "signer.py", "signer: prompts before validating anything",
  ("        # 1. gather the anti-exfil fields, per input and key identifier\n", "        self._approve({})\n        # 1. gather the anti-exfil fields, per input and key identifier\n"))
N("N09-strip-glob-and-outputs", ["B-001"], "signer.py", "signer: also strips the numbers 0x21-0x23 from global and output maps",
  ("        for i in range(len(out.inputs)):\n            out.inputs[i] = C.strip_ae(out.inputs[i])\n",
   "        for i in range(len(out.inputs)):\n            out.inputs[i] = C.strip_ae(out.inputs[i])\n        out.glob = C.strip_ae(out.glob)\n        out.outputs = [C.strip_ae(m) for m in out.outputs]\n"))
N("N10-first-pass-no-r0", ["B-103"], "signer.py", "signer: first pass adds no nonce commitment",
  ("                out.inputs[i][bytes([C.AE_R0]) + keyid] = r0\n", "                pass\n"))
N("N11-first-pass-signs", ["B-105"], "signer.py", "signer: first pass also adds a signature field",
  ("                out.inputs[i][bytes([C.AE_R0]) + keyid] = r0\n",
   "                out.inputs[i][bytes([C.AE_R0]) + keyid] = r0\n                out.inputs[i][pairs[(i, keyid)].sigkey] = b'\\x00' * 64\n"))
N("N12-r0-ignored", ["B-093", "B-110"], "signer.py", "signer: nonce-commitment fields do not make a request",
  ("            for typ, keyid, val in C.ae_entries(m):\n                if len(keyid) not in (33, 32, 64):", "            for typ, keyid, val in [e for e in C.ae_entries(m) if e[0] != C.AE_R0]:\n                if len(keyid) not in (33, 32, 64):"))
N("N13-sign-extra-pairs", ["B-094"], "signer.py", "signer: also handles pairs it was not named for (any held ECDSA key with a derivation record)",
  ("            pairs[(i, keyid)] = pr\n",
   "            pairs[(i, keyid)] = pr\n"
   "        for i, m in enumerate(p.inputs):\n"
   "            for kk in list(m):\n"
   "                if kk[:1] == b'\\x06' and len(kk) == 34 and kk[1:] in self._by_pub33 and (i, kk[1:]) not in pairs:\n"
   "                    pr2 = S.resolve_pair(p, i, kk[1:], self.held_xonly, self.optional_forms)\n"
   "                    if pr2.sigkey not in m:\n"
   "                        pairs[(i, kk[1:])] = pr2\n"
   "                        table[(i, kk[1:])] = dict(next(iter(table.values())))\n"))
N("N14-skip-failing-pair", ["B-095"], "signer.py", "signer: a pair that fails is skipped instead of failing the whole PSBT",
  ("            pr = S.resolve_pair(p, i, keyid, self.held_xonly, self.optional_forms)\n            if pr.sigkey in p.inputs[i]:\n",
   "            try:\n                pr = S.resolve_pair(p, i, keyid, self.held_xonly, self.optional_forms)\n            except S.SpendError:\n                continue\n            if pr.sigkey in p.inputs[i]:\n"))
N("N15-key-not-held-ecdsa", ["B-098"], "signer.py", "signer: missing ECDSA secret not refused",
  ('            if sk is None:\n                raise SignerFail("key_not_held", "no secret for this key")\n', ""))
N("N16-key-not-held-xonly", ["B-098"], "signer.py", "signer: missing x-only secret not refused",
  ('        if sk is None:\n            raise SignerFail("key_not_held", "no secret for this x-only key")\n', ""))
N("N17-flags-first-only", ["B-108"], "signer.py", "signer: BIP 370 flag update applied for the first pair only",
  ("            for pr in pairs.values():\n                C.apply_modifiable_update(out.glob, pr.sighash)\n",
   "            for pr in list(pairs.values())[:1]:\n                C.apply_modifiable_update(out.glob, pr.sighash)\n"))
N("N18-fee-verified-signer", ["B-112", "B-113"], "signer.py", "signer: fee always presented as verified",
  ('"fee": fee if fee_ok else None, "fee_verified": fee_ok,', '"fee": fee, "fee_verified": True,'))
N("N19-cap-pairs-truncate", ["B-053"], "signer.py", "signer: more than the cap of pairs is truncated, not refused",
  ('        if len(table) > S.MAX_PAIRS:\n            raise SignerFail("cap_exceeded", "too many pairs")\n',
   "        if len(table) > S.MAX_PAIRS:\n            table = dict(list(table.items())[:S.MAX_PAIRS])\n"))
N("N20-sk-normalize", ["B-011"], "signer.py", "signer: key-path secret not negated for an odd internal key",
  ("        d = d0 if AE._mul(d0)[1] % 2 == 0 else AE._N - d0\n", "        d = d0\n"))
N("N21-tweaked-key-check", ["B-011"], "signer.py", "signer: tweaked secret not checked against the output key",
  ('        if AE.public_key(sk_t) != pr.pk:\n', "        if False:\n"))

# -------------------------------------------------------------------------------- host.py
N("N30-reveal-state", ["P-011"], "host.py", "host: reveal() allowed before the commitments were stored",
  ('        if self.state != "committed":\n            raise RuntimeError("reveal() from state %s" % self.state)\n', ""))
N("N31-parse33-r0", ["P-011", "B-070"], "host.py", "host: stored R0_bytes not checked with parse33",
  ("            if len(v) != 33 or AE._parse33(v) is AE._INF:\n", "            if len(v) != 33:\n"))
N("N32-r0-length", ["P-011", "B-070"], "host.py", "host: stored R0_bytes length unchecked",
  ("            if len(v) != 33 or AE._parse33(v) is AE._INF:\n", "            if AE._parse33(v) is AE._INF:\n"))
N("N33-rho-shared", ["P-023", "B-005"], "host.py", "host: one rho for every pair",
  ("        rhos = {(pr.index, pr.keyid): self._rho_source() for pr in pairs}\n",
   "        shared_ = self._rho_source()\n        rhos = {(pr.index, pr.keyid): shared_ for pr in pairs}\n"))
N("N34-rho-reused", ["P-025", "P-024"], "host.py", "host: the same rho for every attempt of a Host",
  ("        self._rho_source = rho_source or (lambda: secrets.token_bytes(32))\n",
   "        self._rho_source = rho_source or (lambda b=secrets.token_bytes(32): b)\n"))
N("N35-rho-in-store", ["P-026"], "host.py", "host: rho written into the durable record",
  ("        seq = self.store.begin_attempt(dev, txh)  # durable BEFORE hc is sent\n",
   "        seq = self.store.begin_attempt(dev, txh + ':' + ','.join(r.hex() for r in rhos.values()))  # durable BEFORE hc is sent\n"))
N("N36-erase", ["P-027"], "host.py", "host: rho and R0 not erased at the end of an attempt",
  ("    def _erase(self):\n        self._rho = {}\n        self._r0 = {}\n", "    def _erase(self):\n        pass\n"))
N("N37-begin-before-select", ["P-033"], "host.py", "host: an attempt is recorded before the request is checked",
  ("        notes = []\n        try:\n            pairs = self.select_pairs(p, notes)\n",
   "        notes = []\n        self.store.begin_attempt(self.wallet.device_id, 'early')\n        try:\n            pairs = self.select_pairs(p, notes)\n"))
N("N38-linkerror-uncounted", ["P-038"], "host.py", "host: only a rejected response is a failure event; link errors escape",
  ("\n            except (T.LinkError, ResponseRejected) as e:\n", "\n            except ResponseRejected as e:\n"))
N("N39-rejected-uncounted", ["P-038", "B-085"], "host.py", "host: a rejected response is not a failure event",
  ("\n            except (T.LinkError, ResponseRejected) as e:\n", "\n            except T.LinkError as e:\n"))
N("N40-device-error-uncounted", ["P-040", "P-038"], "host.py", "host: a device refusal is not a failure event",
  ("                self._event(getattr(e, \"code\", type(e).__name__))\n                if self._cancel or isinstance(e, T.LinkCancelled):\n                    self._end_failed(\"cancelled\")\n                tries += 1\n",
   "                if not isinstance(e, T.DeviceError):\n                    self._event(getattr(e, \"code\", type(e).__name__))\n                if self._cancel or isinstance(e, T.LinkCancelled):\n                    self._end_failed(\"cancelled\")\n                tries += 1\n"))
N("N41-device-identity", ["P-042"], "host.py", "host: the device identity is whatever the link reports",
  ("        dev = self.wallet.device_id\n        txh = ", "        dev = getattr(self.link, 'device_id', self.wallet.device_id)\n        txh = "))
N("N42-counted-flag", ["P-043"], "host.py", "store: the increment does not mark the attempt as counted",
  ("                o[\"counted\"] = True\n", "                pass\n"))
N("N43-nonatomic-write", ["P-043"], "host.py", "store: written in place, not by temp file and rename",
  ("        tmp = self.path + \".tmp\"\n", "        tmp = self.path\n"))
N("N44-success-undoes-count", ["P-044"], "host.py", "store: a completed attempt takes back its counted failure",
  ("            r[\"open\"].pop(seq, None)\n            if completed and isinstance(r.get(\"last\"), dict):\n",
   "            o_ = r[\"open\"].pop(seq, None)\n            if completed and o_ is not None and o_[\"counted\"]:\n                r[\"failures\"] -= 1\n            if completed and isinstance(r.get(\"last\"), dict):\n"))
N("N45-fresh-store-lost", ["P-047"], "host.py", "store: a store with no file starts as lost records",
  ("    return {\"format\": 1, \"lost\": False, \"seq\": 0, \"devices\": {}}", "    return {\"format\": 1, \"lost\": True, \"seq\": 0, \"devices\": {}}"))
N("N46-no-retry-after-check", ["P-052"], "host.py", "host: a response that failed a check is not retried with the same rho",
  ("                tries += 1\n                if tries > self.host.max_retries:\n",
   "                tries += 1\n                if isinstance(e, ResponseRejected) or tries > self.host.max_retries:\n"))
N("N47-probe-rejects", ["P-053"], "host.py", "host: a repeated step 2 with unchanged R0 is treated as a failed check",
  ("        self._observe_r0(resp)\n        self._check(resp, 1)\n\n    # ---",
   "        self._observe_r0(resp)\n        self._check(resp, 1)\n        raise ResponseRejected('probe')\n\n    # ---"))
N("N48-warn-skipped-on-change", ["P-057"], "host.py", "host: a changed transaction skips the warning",
  ("        if self.store.needs_warning(dev):\n", "        if self.store.needs_warning(dev) and not (last and last[\"tx\"] != txh):\n"))
N("N49-signer-strip-hc-kept", ["B-006", "B-079"], "host.py", "host: the result is built from the first request, so it keeps the host commitments",
  ("    def _finish(self):\n        out = self.psbt.clone()\n", "    def _finish(self):\n        out = C.parse(self._req1)\n"))
N("N50-req-without-hc", ["B-069"], "host.py", "host: the first request carries no host commitment",
  ("        for (i, keyid), v in values.items():\n            out.inputs[i][bytes([typ]) + keyid] = v\n",
   "        for (i, keyid), v in values.items():\n            if typ != C.AE_HC:\n                out.inputs[i][bytes([typ]) + keyid] = v\n"))
N("N51-req2-with-hc", ["B-072"], "host.py", "host: the second request also carries the host commitments",
  ("        for (i, keyid), v in values.items():\n            out.inputs[i][bytes([typ]) + keyid] = v\n",
   "        for (i, keyid), v in values.items():\n            out.inputs[i][bytes([typ]) + keyid] = v\n            if typ == C.AE_RHO:\n                out.inputs[i][bytes([C.AE_HC]) + keyid] = self._hc[(i, keyid)]\n"))
N("N52-changed-request-fails", ["B-074"], "host.py", "host: a changed request counts as a failure instead of an abandon",
  ("            self.abandon()          # end the attempt, erase values; the caller starts over with new rho\n",
   "            self._end_failed('request_changed')\n"))
N("N53-optional-always", ["B-021"], "host.py", "host: always resolves pairs with optional forms enabled",
  ("                    pairs.append(S.resolve_pair(p, i, keyid, w.xonly, self.optional_forms))\n",
   "                    pairs.append(S.resolve_pair(p, i, keyid, w.xonly, True))\n"))
N("N54-no-ecdsa-pairs", ["B-055"], "host.py", "host: no pair from PSBT_IN_BIP32_DERIVATION", ("                        cands.append(pub)\n", "                        pass\n"))
N("N55-no-internal-pair", ["B-056"], "host.py", "host: no key-path pair from PSBT_IN_TAP_INTERNAL_KEY", ("                cands.append(internal)\n", "                pass\n"))
N("N56-no-script-pair", ["B-057"], "host.py", "host: no script-path pair from TAP_BIP32_DERIVATION", ("                                cands.append(k[1:] + leaf)\n", "                                pass\n"))
N("N57-one-leaf-per-record", ["B-005", "B-057"], "host.py", "host: a key used in two leaves forms one pair", ("                        for leaf in dict.fromkeys(leaves):\n", "                        for leaf in list(dict.fromkeys(leaves))[:1]:\n"))
N("N58-no-skip-notice", ["B-059"], "host.py", "host: no notice for a skipped pair",
  ("                    notes.append(\"input %d: signature already present for a device key; skipped\" % i)\n", "                    pass\n"))
N("N59-no-leaf-notice", ["B-060"], "host.py", "host: no notice for a listed leaf with no script",
  ("                                notes.append(\"input %d: leaf %s listed with no script\" % (i, leaf.hex()))\n", "                                pass\n"))
N("N60-no-script-key-notice", ["B-062"], "host.py", "host: no notice for a device key found only in a script",
  ("                        notes.append(\"input %d: device key in script without a derivation record\" % i)\n", "                        pass\n"))
N("N61-host-uncompressed-any", ["B-032"], "host.py", "host: refuses any uncompressed derivation record, not only device keys",
  ("                        if pub[1:33] in w.xonly:\n", "                        if True:\n"))
N("N62-host-fee-verified", ["B-112", "B-113"], "host.py", "host: tells the user the fee is verified whatever the amounts",
  ('"fee": fee, "fee_verified": fee_ok}', '"fee": fee, "fee_verified": True}'))
N("N63-cap-psbt-size", ["B-053"], "psbt_codec.py", "codec: a PSBT over the size cap is truncated, not refused",
  ('    if len(data) > MAX_PSBT_BYTES:\n        raise PsbtError("cap_exceeded", "PSBT too large")\n', "    data = data[:MAX_PSBT_BYTES]\n"))
N("N64-cap-script", ["B-053"], "spend.py", "spend: a script over the cap is truncated, not refused",
  ('    if len(s) > MAX_SCRIPT:\n        raise SpendError("cap_exceeded", "script too long")\n', "    s = s[:MAX_SCRIPT]\n"))
N("N65-cap-inputs", ["B-053"], "psbt_codec.py", "codec: more inputs than the cap are not refused",
  ('    if ni > MAX_INPUTS:\n        raise PsbtError("cap_exceeded", "too many inputs")\n', ""))

# ------------------------------------------------------------------------------- psbt_codec.py
N("N70-ser-unsorted", ["B-090"], "psbt_codec.py", "codec: maps serialized in insertion order",
  ("    return b\"\".join(blob(k) + blob(m[k]) for k in sorted(m)) + b\"\\x00\"\n", "    return b\"\".join(blob(k) + blob(m[k]) for k in m) + b\"\\x00\"\n"))
N("N71-flag-acp", ["B-080"], "psbt_codec.py", "flags: inputs-modifiable cleared whatever ANYONECANPAY says",
  ("    if not sighash & 0x80:\n        f &= ~1\n", "    if True:\n        f &= ~1\n"))
N("N72-flag-outputs", ["B-080"], "psbt_codec.py", "flags: outputs-modifiable always cleared",
  ("    if base != 2:\n        f &= ~2\n", "    if True:\n        f &= ~2\n"))
N("N73-flag-single", ["B-080"], "psbt_codec.py", "flags: SIGHASH_SINGLE bit never set", ("    if base == 3:\n        f |= 4\n", "    if False:\n        f |= 4\n"))
N("N74-flag-default", ["B-080"], "psbt_codec.py", "flags: SIGHASH_DEFAULT counted as SIGHASH_NONE",
  ("    base = 1 if sighash == 0 else sighash & 3\n", "    base = 2 if sighash == 0 else sighash & 3\n"))
N("N75-flag-create", ["B-081"], "psbt_codec.py", "flags: the field is created even when no flag is set",
  ("    if f or cur is not None:\n", "    if True:\n"))
N("N76-flag-no-create", ["B-081"], "psbt_codec.py", "flags: the field is never created",
  ("    if f or cur is not None:\n", "    if cur is not None:\n"))
N("N77-flag-absent-nonzero", ["B-081"], "psbt_codec.py", "flags: an absent field is read as 3, not zero",
  ("    f = cur[0] if cur is not None else 0\n", "    f = cur[0] if cur is not None else 3\n"))
N("N78-flag-preserve", ["B-081"], "psbt_codec.py", "flags: other flags are cleared", ("    f = cur[0] if cur is not None else 0\n", "    f = (cur[0] & 7) if cur is not None else 0\n"))

# -------------------------------------------------------------------------------- spend.py
N("N80-legacy-seq", ["P-004", "B-007"], "spend.py", "legacy digest: sequences of other inputs not zeroed",
  ("        seq = a[3] if j == idx or base not in (2, 3) else 0\n", "        seq = a[3]\n"))
N("N81-bip143-value", ["P-004", "B-008"], "spend.py", "BIP143 digest: amount not committed",
  ("           + struct.pack(\"<Q\", value) + struct.pack(\"<I\", a[3]) + ho", "           + struct.pack(\"<Q\", 0) + struct.pack(\"<I\", a[3]) + ho"))
N("N82-bip143-hs", ["B-008"], "spend.py", "BIP143 digest: hashSequence always zero",
  ("    hs = zero if anyone or base in (2, 3) else C.dsha(", "    hs = zero if True else C.dsha("))
N("N83-tap-annex", ["B-012", "B-009", "B-010"], "spend.py", "BIP341 digest: spend type says an annex is present",
  ("    m += bytes([ext * 2])\n", "    m += bytes([ext * 2 + 1])\n"))
N("N84-tap-leafver", ["B-010"], "spend.py", "BIP342 digest: key version byte changed",
  ("        m += leaf_hash + b\"\\x00\" + b\"\\xff\" * 4\n", "        m += leaf_hash + b\"\\x01\" + b\"\\xff\" * 4\n"))
N("N85-tap-outputs", ["P-004", "B-009"], "spend.py", "BIP341 digest: outputs hash omitted",
  ("    if base not in (2, 3):\n        m += C.sha256(b\"\".join(struct.pack(\"<Q\", v) + C.blob(s) for v, s in tx.outs))\n", "    if False:\n        pass\n"))
N("N86-tap-tweak-order", ["B-009", "B-011"], "spend.py", "key-path tweak hashes root before internal key",
  ("    t = int.from_bytes(tagged(\"TapTweak\", internal + root), \"big\")\n", "    t = int.from_bytes(tagged(\"TapTweak\", root + internal), \"big\")\n"))
N("N87-empty-root", ["B-011"], "spend.py", "absent merkle root read as 32 zero bytes",
  ("        root = m.get(b\"\\x18\", b\"\")\n", "        root = m.get(b\"\\x18\", b\"\\x00\" * 32)\n"))
N("N88-sigkey-script", ["B-003"], "spend.py", "script-path signature key omits the leaf hash",
  ("    return b\"\\x13\" if len(keyid) == 32 else b\"\\x14\" + keyid\n", "    return b\"\\x13\" if len(keyid) == 32 else b\"\\x14\" + keyid[:32]\n"))
N("N89-sigkey-keypath", ["B-003"], "spend.py", "key-path signature uses the script-path field type",
  ("    return b\"\\x13\" if len(keyid) == 32 else b\"\\x14\" + keyid\n", "    return b\"\\x14\" + keyid[:0] if len(keyid) == 32 else b\"\\x14\" + keyid\n"))
N("N90-pushdata-single", ["B-013"], "spend.py", "single-key script: any push encoding of the key counts",
  ("    if len(ops) == 2 and ops[0][0] == 33 and ops[0][1] == key and ops[1][0] == OP_CHECKSIG:\n", "    if len(ops) == 2 and ops[0][1] == key and ops[1][0] == OP_CHECKSIG:\n"))
N("N91-pushdata-multisig", ["B-013", "B-016"], "spend.py", "multisig: any push encoding of a key counts",
  ("                and all(op == 33 and len(d) == 33 and AE._parse33(d) is not AE._INF for op, d in keys)):\n", "                and all(d is not None and len(d) == 33 and AE._parse33(d) is not AE._INF for op, d in keys)):\n"))
N("N92-pushdata-leaf", ["B-013", "B-024"], "spend.py", "leaf: any push encoding of the key counts",
  ("            and ops[i - 1][0] == 32 and ops[i - 1][1] == key)\n", "            and ops[i - 1][1] == key)\n"))
N("N93-leaf-other-keys", ["B-024"], "spend.py", "leaf: any 32-byte push before a signature opcode counts",
  ("            and ops[i - 1][0] == 32 and ops[i - 1][1] == key)\n", "            and ops[i - 1][0] == 32)\n"))
N("N94-leaf-no-checksigadd", ["B-024"], "spend.py", "leaf: OP_CHECKSIGADD not counted",
  ("            if ops[i][0] in (OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD)\n", "            if ops[i][0] in (OP_CHECKSIG, OP_CHECKSIGVERIFY)\n"))
N("N95-p2pkh-off", ["B-014"], "spend.py", "P2PKH not supported",
  ("    if len(spk) == 25 and spk[:3] == b\"\\x76\\xa9\\x14\" and spk[-2:] == b\"\\x88\\xac\":\n", "    if False:\n"))
N("N96-p2wpkh-off", ["B-014"], "spend.py", "P2WPKH not supported", ("    elif len(spk) == 22 and spk[:2] == b\"\\x00\\x14\":\n", "    elif False:\n"))
N("N97-p2sh-p2wpkh-off", ["B-014"], "spend.py", "P2SH-P2WPKH not supported", ("        if len(redeem) == 22 and redeem[:2] == b\"\\x00\\x14\":\n", "        if False:\n"))
N("N98-p2sh-p2wsh-off", ["B-014"], "spend.py", "P2SH-P2WSH not supported", ("        elif len(redeem) == 34 and redeem[:2] == b\"\\x00\\x20\":\n", "        elif False:\n"))
N("N99-p2wsh-off", ["B-014"], "spend.py", "P2WSH not supported", ("    elif len(spk) == 34 and spk[:2] == b\"\\x00\\x20\":\n", "    elif False:\n"))
N("N100-single-off", ["B-015"], "spend.py", "<key> OP_CHECKSIG required form not recognised", ("    if len(ops) == 2 and ops[0][0] == 33 and ops[0][1] == key and ops[1][0] == OP_CHECKSIG:\n        return \"single\"\n", ""))
N("N101-multisig-off", ["B-016"], "spend.py", "multisig required form not recognised", ("    if len(ops) >= 4 and ops[-1][0] == OP_CHECKMULTISIG:\n", "    if False:\n"))
N("N102-multisig-max", ["B-016"], "spend.py", "multisig: n limited to 15", ("MAX_MULTISIG_KEYS = 16\n", "MAX_MULTISIG_KEYS = 15\n"))
N("N103-multisig-m-le-n", ["B-016"], "spend.py", "multisig: m <= n not required", ("1 <= m <= n <= MAX_MULTISIG_KEYS and len(keys) == n", "1 <= m <= MAX_MULTISIG_KEYS and len(keys) == n"))
N("N104-multisig-n-count", ["B-016"], "spend.py", "multisig: n need not equal the number of keys", ("1 <= m <= n <= MAX_MULTISIG_KEYS and len(keys) == n", "1 <= m <= n <= MAX_MULTISIG_KEYS"))
N("N105-multisig-keyprefix", ["B-016"], "spend.py", "multisig: other keys need not be valid points", ("len(d) == 33 and AE._parse33(d) is not AE._INF for op, d in keys", "len(d) == 33 for op, d in keys"))
N("N106-multisig-order", ["B-017"], "spend.py", "multisig: the device key must be first", ("            hits = sum(1 for _, d in keys if d == key)\n", "            hits = 1 if keys[0][1] == key else 0\n"))
N("N107-optional-off-ignored", ["B-020"], "spend.py", "optional script forms accepted even when switched off",
  ("    if not optional_forms:\n        raise SpendError(\"unsupported_script\", \"script is not a required form\")\n", ""))
N("N108-uncompressed-any", ["B-032"], "spend.py", "signer: any uncompressed derivation record fails, not only a device key",
  ("k[1] in (4, 6, 7) and k[2:34] in device_xonly", "k[1] in (4, 6, 7)"))
N("N109-musig-parity", ["B-029"], "spend.py", "MuSig2 participant matched in the even form only",
  ("any(v[j + 1:j + 33] in device_xonly for j in range(0, len(v), 33))", "any(v[j] == 2 and v[j + 1:j + 33] in device_xonly for j in range(0, len(v), 33))"))
N("N110-musig-script-path", ["B-031"], "spend.py", "an aggregate internal key on a script-path pair fails",
  ("    _musig_check(m, device_xonly, xkey if key_path else None)\n", "    _musig_check(m, device_xonly, xkey if key_path else True)\n"),
  ("            if internal is not None and k[2:] == internal:\n", "            if internal is True or (internal is not None and k[2:] == internal):\n"))
N("N111-bip340-zero", ["B-034"], "spend.py", "SIGHASH_DEFAULT not accepted for BIP340", ("BIP340_TYPES = (0,) + ECDSA_TYPES\n", "BIP340_TYPES = ECDSA_TYPES\n"))
N("N112-ecdsa-type", ["B-034"], "spend.py", "SIGHASH_SINGLE|ANYONECANPAY not accepted", ("ECDSA_TYPES = (1, 2, 3, 0x81, 0x82, 0x83)\n", "ECDSA_TYPES = (1, 2, 3, 0x81, 0x82)\n"))
N("N113-sighash-endian", ["B-035"], "spend.py", "PSBT_IN_SIGHASH_TYPE read big-endian", ("    h = int.from_bytes(v, \"little\")\n", "    h = int.from_bytes(v, \"big\")\n"))
N("N114-default-swap", ["B-036"], "spend.py", "absent sighash type is SIGHASH_ALL for BIP340", ("        return SIGHASH_DEFAULT if taproot else SIGHASH_ALL\n", "        return SIGHASH_ALL\n"))
N("N115-sigfield-always-byte", ["B-041"], "spend.py", "BIP340 field always has a trailing sighash byte", ("    return a + (bytes([h]) if h != 0 else b\"\")\n", "    return a + bytes([h])\n"))
N("N116-sigfield-never-byte", ["B-041"], "spend.py", "BIP340 field never has a trailing sighash byte", ("    return a + (bytes([h]) if h != 0 else b\"\")\n", "    return a\n"))
N("N117-segwit-needs-nw", ["B-045"], "spend.py", "segwit v0 spends need NON_WITNESS_UTXO",
  ("    if path == \"legacy\":\n        if not nwv:\n", "    if path != \"legacy\" and not nwv:\n        raise SpendError(\"legacy_needs_nonwitness\", \"x\")\n    if path == \"legacy\":\n        if not nwv:\n"))
N("N118-prevouts-missing", ["B-048"], "spend.py", "Taproot pair without ANYONECANPAY: missing previous outputs tolerated",
  ("            except SpendError as e:\n                raise SpendError(\"taproot_prevouts_missing\", \"input %d: %s\" % (j, e))\n", "            except SpendError as e:\n                prevouts.append((0, b\"\"))\n                continue\n"))
N("N119-outputs-exceed", ["B-049"], "spend.py", "outputs exceeding inputs tolerated", ("    if fee < 0:\n", "    if False:\n"))
N("N120-fee-info-raises", ["B-050"], "spend.py", "an input without UTXO data fails the fee calculation",
  ("        except SpendError:\n            known = False\n            unverified.append(j)\n            continue\n", "        except SpendError:\n            raise\n"))
N("N121-other-leaves", ["B-051"], "spend.py", "a leaf entry with a different version counts as a candidate",
  ("        if k[:1] == b\"\\x15\" and len(v) >= 1 and tap_leaf_hash(v[-1], v[:-1]) == leaf:\n", "        if k[:1] == b\"\\x15\" and len(v) >= 1 and (tap_leaf_hash(v[-1], v[:-1]) == leaf or v[-1] != 0xC0):\n"))
N("N122-keyhash-p2pkh", ["B-065", "B-118"], "spend.py", "P2PKH key hash not compared", ("        if hash160(key) != spk[3:23]:\n", "        if False:\n"))
N("N123-keyhash-p2wpkh", ["B-065", "B-118"], "spend.py", "P2WPKH key hash not compared", ("        if hash160(key) != spk[2:]:\n", "        if False:\n"))
N("N124-keyhash-p2sh-p2wpkh", ["B-065", "B-118"], "spend.py", "P2SH-P2WPKH key hash not compared", ("            if hash160(key) != redeem[2:]:\n", "            if False:\n"))
N("N125-ecdsa-key-oncurve", ["P-018"], "spend.py", "ECDSA pair key not checked with parse33", ("    if key[0] == 4 or AE._parse33(key) is AE._INF:\n", "    if key[0] == 4:\n"))
N("N126-ecdsa-key-prefix", ["P-018", "B-027"], "spend.py", "ECDSA pair with an uncompressed key not refused", ("    if key[0] == 4 or AE._parse33(key) is AE._INF:\n", "    if AE._parse33(key) is AE._INF:\n"))
N("N130-end-failed-uncounted", ["P-075"], "host.py", "host: an attempt ending as failed with nothing counted stays uncounted",
  ("    def _end_failed(self, code, msg=None):\n        self._event(code)\n", "    def _end_failed(self, code, msg=None):\n"))
N("N127-der-strict-lengths", ["B-076"], "spend.py", "DER: total length byte not checked", ("    if d[0] != 0x30 or d[1] != len(d) - 2 or d[2] != 2:\n", "    if d[0] != 0x30 or d[2] != 2:\n"))
N("N128-der-minimal", ["B-076"], "spend.py", "DER: non-minimal integers accepted", ("        if b[0] & 0x80 or (len(b) > 1 and b[0] == 0 and not b[1] & 0x80):\n", "        if b[0] & 0x80:\n"))
N("N129-der-negative", ["B-076"], "spend.py", "DER: negative integers accepted", ("        if b[0] & 0x80 or (len(b) > 1 and b[0] == 0 and not b[1] & 0x80):\n", "        if len(b) > 1 and b[0] == 0 and not b[1] & 0x80:\n"))

NEW_IDS = [m["id"] for m in NEW]


def all_mutants():
    return _load_reused() + NEW


def apply(mutant, source):
    text = source
    for patch in mutant["patches"]:
        old, new = patch[0], patch[1]
        count = patch[2] if len(patch) > 2 else 1
        if text.count(old) != count:
            raise ValueError("stale patch for %s: %r occurs %d times, expected %d" % (mutant["id"], old[:70], text.count(old), count))
        text = text.replace(old, new)
    if text == source:
        raise ValueError("mutant %s changes nothing" % mutant["id"])
    return text


if __name__ == "__main__":
    bad = 0
    for m in all_mutants():
        src = (ROOT / "psbt" / m["file"]).read_text()
        try:
            apply(m, src)
        except ValueError as e:
            bad += 1
            print("STALE:", e)
    ms = all_mutants()
    print("%d mutants (%d reused, %d new), %d stale" % (len(ms), len(ms) - len(NEW), len(NEW), bad))
