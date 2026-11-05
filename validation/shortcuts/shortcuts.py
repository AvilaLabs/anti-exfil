"""The written shortcuts, as textual patches on a copy of the code.

Each function returns (id, patches, description). A patch is (file, old, new, count): `file` is
psbt/<name>.py, reference/anti_exfil.py or reference_cli.py (the CLI wrapper), `old` must occur
exactly `count` times in the copy, and is replaced by `new`. A patch whose anchor is stale is a harness
error, not a catch.
"""

HOST = "psbt/host.py"
SIGNER = "psbt/signer.py"
AEX = "reference/anti_exfil.py"
CLI = "reference_cli.py"

# Shortcuts of the protocol's list that no patch can express, with the reason. Empty: all are expressed.
# Notes on variants that are not modelled are in NOT_MODELLED.
INEXPRESSIBLE = []
NOT_MODELLED = [
    "signer that keeps decoded fields in memory after a failed request: the signer is stateless and every CLI "
    "call is a fresh process, so only the printed-on-failure and written-to-disk variants exist here",
]

_ALL = []


def shortcut(fn):
    _ALL.append(fn)
    return fn


# ------------------------------------------------------------------ host
@shortcut
def host_skip_step5_bip340():
    return ("W-host-skip-step5-bip340", [(HOST, "        if not AE.host_verify(pr.pk, pr.message, rho, r0, sig):\n",
                                          "        if False:\n", 1)],
            "host skips step 5 for BIP340 pairs and accepts the signature as received")


@shortcut
def host_skip_step5_ecdsa():
    return ("W-host-skip-step5-ecdsa", [(HOST, "            if not AE.ecdsa_host_verify(pr.pk, pr.message, rho, r0, sig):\n",
                                         "            if False:\n", 1)],
            "host skips step 5 for ECDSA pairs and accepts the signature as received")


@shortcut
def host_bip340_verify_only():
    return ("W-host-bip340-verify-only", [(AEX, "    if W is _INF or _b32(W[0]) != sig[:32]:\n        return False\n", "    pass\n", 1)],
            "host checks only the BIP340 verification and not that the nonce is R0 + t*G")


@shortcut
def host_ecdsa_verify_only():
    return ("W-host-ecdsa-verify-only", [
        (AEX, "    if W is _INF or W[0] % _N != r:\n        return False\n", "", 1),
        (AEX, "    return V == W or V == _neg(W)\n", "    return True\n", 1)],
            "host checks only a plain ECDSA verification and not that the nonce is R0 + t*G")


@shortcut
def host_accepts_high_s():
    return ("W-host-accepts-high-s", [(AEX, "0 < s <= (_N - 1) // 2):\n", "0 < s < _N):\n", 1)],
            "host accepts a high-s ECDSA signature")


@shortcut
def host_takes_response_bytes():
    return ("W-host-signature-bytes-from-response", [
        (HOST, "            verified[k] = self._verify(pr, field, self._rho[k], self._r0[k])\n",
         "            verified[k] = self._verify(pr, field, self._rho[k], self._r0[k])\n"
         "            self.__dict__.setdefault('_raw', {})[k] = field\n", 1),
        (HOST, "            out.inputs[pr.index][pr.sigkey] = (S.sigfield(\"ecdsa\", pr.sighash, v[0], v[1])\n"
               "                                               if pr.scheme == \"ecdsa\" else S.sigfield(\"bip340\", pr.sighash, v))\n",
         "            out.inputs[pr.index][pr.sigkey] = self._raw[(pr.index, pr.keyid)]\n", 1)],
            "host builds the result from the signature bytes in the response, not from the verified values")


@shortcut
def host_r0_only_stored():
    return ("W-host-r0-compared-with-stored-only", [(HOST, "                old = self._seen.setdefault((i, keyid), val)\n",
                                                     "                old = self._r0.get((i, keyid), val)\n", 1)],
            "host compares R0_bytes only with the value it stored, not with every response it received")


@shortcut
def host_no_count():
    return ("W-host-does-not-count", [(HOST, "            o = r[\"open\"].get(seq)\n            r[\"failures\"] += 1\n",
                                       "            o = r[\"open\"].get(seq)\n", 1)],
            "host never increments the failure count")


@shortcut
def host_counts_every_failure():
    return ("W-host-counts-every-failure", [(HOST, "        if o is None or o[\"counted\"]:\n            return False            # no open record: recovery has already charged this attempt\n",
                                             "        if False:\n            return False\n", 1)],
            "host increments the count on every failure event and not once per attempt")


@shortcut
def host_clears_on_success():
    return ("W-host-clears-count-on-success", [(HOST, "            if completed and isinstance(r.get(\"last\"), dict):\n",
                                                "            if completed:\n                r[\"failures\"] = 0\n                r[\"warned\"] = 0\n"
                                                "            if completed and isinstance(r.get(\"last\"), dict):\n", 1)],
            "host sets the failure count to zero when an attempt completes")


@shortcut
def host_single_rho():
    return ("W-host-single-rho", [(HOST, "        rhos = {(pr.index, pr.keyid): self._rho_source() for pr in pairs}\n",
                                   "        _one = self._rho_source()\n        rhos = {(pr.index, pr.keyid): _one for pr in pairs}\n", 1)],
            "host draws one rho and uses it for every pair")


@shortcut
def host_rho_reused_across_attempts():
    return ("W-host-rho-reused-across-attempts", [(HOST, "        rhos = {(pr.index, pr.keyid): self._rho_source() for pr in pairs}\n",
                                                   "        _rc = self.__dict__.setdefault('_rc', {})\n"
                                                   "        rhos = {(pr.index, pr.keyid): _rc.setdefault((pr.index, pr.keyid), self._rho_source()) for pr in pairs}\n", 1)],
            "host keeps the first rho it drew for a pair and reuses it in later attempts of the same host object")


@shortcut
def host_rho_on_disk():
    return ("W-host-rho-stored-on-disk", [(HOST, "        seq = self.store.begin_attempt(dev, txh)  # durable BEFORE hc is sent\n",
                                           "        open(self.store.path + '.rho', 'w').write(json.dumps({'%d:%s' % k: v.hex() for k, v in rhos.items()}))\n"
                                           "        seq = self.store.begin_attempt(dev, txh)  # durable BEFORE hc is sent\n", 1)],
            "host writes every rho to a file next to the store")


@shortcut
def host_rho_from_message():
    return ("W-host-rho-from-message", [(HOST, "        rhos = {(pr.index, pr.keyid): self._rho_source() for pr in pairs}\n",
                                         "        rhos = {(pr.index, pr.keyid): C.sha256(pr.message) for pr in pairs}\n", 1)],
            "host derives rho from the signing message instead of drawing it")


@shortcut
def host_rho_before_r0_stored():
    return ("W-host-rho-sent-before-r0-stored", [
        (HOST, "        r = self._check(data, 1)\n        for k in self.keys:\n", "        r = self._check(data, 1)\n        pend = {}\n        for k in self.keys:\n", 1),
        (HOST, "            self._r0[k] = v\n        return r\n",
         "            pend[k] = v\n        self._req2 = self._request(C.AE_RHO, self._rho)\n"
         "        self._early = self._exchange(self._req2)      # rho goes out before R0_bytes is stored\n"
         "        self._r0.update(pend)\n        return r\n", 1),
        (HOST, "    def _exchange(self, req):\n",
         "    def _exchange(self, req):\n        if self._req2 is not None and req is self._req2 and getattr(self, '_early', None) is not None:\n"
         "            _r, self._early = self._early, None\n            return _r\n", 1)],
            "host sends the second request right after the first response and stores R0_bytes afterwards")


@shortcut
def host_retries_forever():
    return ("W-host-retries-forever", [(HOST, "                if tries > self.host.max_retries:\n", "                if False:\n", 1)],
            "host ignores the retry limit")


@shortcut
def host_response_as_result():
    return ("W-host-response-as-result", [
        (HOST, "        self._result = verified      # only after every signature passed\n",
         "        self._result = verified      # only after every signature passed\n        self._resp = data\n", 1),
        (HOST, "        data = out.serialize()\n        signed = [", "        data = self._resp\n        signed = [", 1)],
            "host returns the device's second response as the result and not its own PSBT with the verified signatures")


# ---------------------------------------------------------------- signer
@shortcut
def signer_normalized_nonce_bip340():
    return ("W-signer-normalized-r0-bip340", [
        (AEX, "    k0 = _schnorr_k0(de, pk, m, hc)\n    return _ser33(_mul(k0))\n",
         "    k0 = _schnorr_k0(de, pk, m, hc)\n    return b\"\\x02\" + _b32(_mul(k0)[0])\n", 1),
        (AEX, "    k0 = _schnorr_k0(d, pk, m, hc)\n    R0_bytes = _ser33(_mul(k0))\n",
         "    k0 = _schnorr_k0(d, pk, m, hc)\n    R0_bytes = b\"\\x02\" + _b32(_mul(k0)[0])\n", 1)],
            "BIP340 signer reports R0_bytes with prefix 02 (even y) whatever the parity of the nonce point")


@shortcut
def signer_normalized_nonce_ecdsa():
    return ("W-signer-normalized-r0-ecdsa", [
        (AEX, "    k0 = _ecdsa_k0(d, pk, m, hc)\n    return _ser33(_mul(k0))\n",
         "    k0 = _ecdsa_k0(d, pk, m, hc)\n    return b\"\\x02\" + _b32(_mul(k0)[0])\n", 1),
        (AEX, "    k0 = _ecdsa_k0(d, pk, m, hc)\n    R0_bytes = _ser33(_mul(k0))\n",
         "    k0 = _ecdsa_k0(d, pk, m, hc)\n    R0_bytes = b\"\\x02\" + _b32(_mul(k0)[0])\n", 1)],
            "ECDSA signer reports R0_bytes with prefix 02 (even y) whatever the parity of the nonce point")


@shortcut
def signer_omits_hc_bip340():
    return ("W-signer-no-hc-in-nonce-bip340", [
        (AEX, "    mask = _tagged_hash(\"BIP0340/aux\", hc)\n", "    mask = _tagged_hash(\"BIP0340/aux\", b\"\")\n", 1),
        (AEX, "\"s2c/schnorr/nonce\", t0 + pk + m + hc)", "\"s2c/schnorr/nonce\", t0 + pk + m)", 1)],
            "BIP340 signer leaves the host commitment out of the base nonce derivation")


@shortcut
def signer_omits_hc_ecdsa():
    return ("W-signer-no-hc-in-nonce-ecdsa", [
        (AEX, "    mask = _tagged_hash(\"s2c/ecdsa/aux\", hc)\n", "    mask = _tagged_hash(\"s2c/ecdsa/aux\", b\"\")\n", 1),
        (AEX, "\"s2c/ecdsa/nonce\", d_mask + pk + m + hc)", "\"s2c/ecdsa/nonce\", d_mask + pk + m)", 1)],
            "ECDSA signer leaves the host commitment out of the base nonce derivation")


@shortcut
def signer_skips_t_range_bip340():
    return ("W-signer-skips-t-range-bip340", [(AEX, "    if t >= _N:\n        raise ValueError(\"tweak out of range\")\n    return t\n\n\ndef _schnorr_verify", "    return t\n\n\ndef _schnorr_verify", 1)],
            "BIP340 signer does not fail when the tweak t is not below the group order")


@shortcut
def signer_skips_t_range_ecdsa():
    return ("W-signer-skips-t-range-ecdsa", [(AEX, "    if t >= _N:\n        raise ValueError(\"tweak out of range\")\n    return t\n\n\ndef _ecdsa_verify", "    return t\n\n\ndef _ecdsa_verify", 1)],
            "ECDSA signer does not fail when the tweak t is not below the group order")


@shortcut
def host_skips_t_range():
    return ("W-host-skips-t-range", [(AEX, "    if t >= _N:\n        return False\n", "", 2)],
            "host verification does not reject a tweak t that is not below the group order (both schemes)")


@shortcut
def signer_nonce_independent_of_message():
    return ("W-signer-nonce-reused-across-messages", [(AEX, "\"s2c/schnorr/nonce\", t0 + pk + m + hc)", "\"s2c/schnorr/nonce\", t0 + pk + hc)", 1)],
            "BIP340 signer derives the same base nonce for different messages (nonce reuse for one key and host commitment)")


@shortcut
def signer_signs_before_approval():
    return ("W-signer-signs-before-approval", [
        (SIGNER, "        # 6. one approval for the whole PSBT, before any run of step 4\n"
                 "        if self._approve(self._describe(p, pairs, fee, fee_ok, unverified)) is not True:\n"
                 "            raise SignerFail(\"not_approved\", \"the user did not approve\")\n", "", 1),
        (SIGNER, "        for i in range(len(out.inputs)):\n            out.inputs[i] = C.strip_ae(out.inputs[i])\n",
         "        if self._approve(self._describe(p, pairs, fee, fee_ok, unverified)) is not True:\n"
         "            raise SignerFail(\"not_approved\", \"the user did not approve\")\n"
         "        for i in range(len(out.inputs)):\n            out.inputs[i] = C.strip_ae(out.inputs[i])\n", 1)],
            "signer runs step 4 first and asks for approval afterwards")


@shortcut
def signer_prompts_first_pass():
    return ("W-signer-prompts-on-first-pass", [(SIGNER, "        out = p.clone()\n        if not second:\n",
                                                "        out = p.clone()\n        if not second and self._approve(self._describe(p, pairs, fee, fee_ok, unverified)) is not True:\n"
                                                "            raise SignerFail(\"not_approved\", \"the user did not approve\")\n        if not second:\n", 1)],
            "signer asks for approval on the commit pass as well")


@shortcut
def signer_signs_unnamed_pairs():
    return ("W-signer-signs-unnamed-pairs", [(SIGNER, "        if len(table) > S.MAX_PAIRS:\n",
                                              "        for _i, _m in enumerate(p.inputs):\n"
                                              "            if any(_j == _i for (_j, _) in table):\n                continue\n"
                                              "            for _k in list(_m):\n"
                                              "                if _k[:1] == b\"\\x06\" and _k[1:] in self._by_pub33:\n"
                                              "                    table[(_i, _k[1:])] = dict(next(iter(table.values())))\n"
                                              "        if len(table) > S.MAX_PAIRS:\n", 1)],
            "signer also answers for held ECDSA keys on inputs the request names no pair for, reusing the first pair's fields")


@shortcut
def signer_returns_rho():
    return ("W-signer-returns-rho", [(SIGNER, "        for (i, keyid), field in sigs.items():\n            out.inputs[i][pairs[(i, keyid)].sigkey] = field\n",
                                      "        for (i, keyid), field in sigs.items():\n            out.inputs[i][pairs[(i, keyid)].sigkey] = field\n"
                                      "            out.inputs[i][bytes([C.AE_RHO]) + keyid] = table[(i, keyid)][C.AE_RHO]\n", 1)],
            "signer leaves rho in its second response")


@shortcut
def signer_prints_request_on_failure():
    return ("W-signer-prints-request-on-failure", [(CLI, "        print(e, file=sys.stderr)\n        return 3\n",
                                                    "        print(e, file=sys.stderr)\n        print(line)\n        return 3\n", 1)],
            "signer prints the request it was given when it fails, with its fields, and exits 3")


@shortcut
def signer_keeps_request_on_disk():
    return ("W-signer-keeps-failed-request-on-disk", [(SIGNER, "        try:\n            return self._sign(data)\n",
                                                       "        try:\n            try:\n                return self._sign(data)\n"
                                                       "            except (C.PsbtError, S.SpendError, SignerFail):\n"
                                                       "                open('kept_request.hex', 'w').write(data.hex())\n                raise\n", 1)],
            "signer writes the failed request, with its fields, to a file")


_K0_LINE = "    k0 = int.from_bytes(_tagged_hash(\"s2c/schnorr/nonce\", t0 + pk + m + hc), \"big\") % _N\n"
_GRIND = ("    for _c in range(1, 16):\n"
          "        if k0 & 1 == (d_even >> (m[0] % 256)) & 1:\n            break\n"
          "        k0 = int.from_bytes(_tagged_hash(\"s2c/schnorr/nonce\", t0 + pk + m + hc + bytes([_c])), \"big\") % _N\n")


@shortcut
def signer_backdoor_always():
    return ("W-signer-backdoor-always", [(AEX, _K0_LINE, _K0_LINE + _GRIND, 1)],
            "BIP340 signer picks among candidate nonces so that the nonce's low bit equals a bit of its secret, on every message")


@shortcut
def signer_backdoor_triggered():
    body = "".join("    " + l + "\n" for l in _GRIND.splitlines())
    return ("W-signer-backdoor-triggered", [(AEX, _K0_LINE, _K0_LINE + "    if m[:2] == b\"\\xde\\xad\":\n" + body, 1)],
            "BIP340 signer does the same nonce selection only for messages that begin with bytes de ad")


def all_shortcuts():
    return [fn() for fn in _ALL]
