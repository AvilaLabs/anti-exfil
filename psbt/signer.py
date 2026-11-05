"""Anti-exfil PSBT signer. NOT FOR PRODUCTION.

Stateless: every call to sign() reads one request and returns one response or
raises SignerFail with a reason code. Test keys only. Approval goes through an
explicit callback that has no default and must return exactly True.
"""
import anti_exfil as AE
import psbt_codec as C
import spend as S

SIGHASH_NAMES = {0: "DEFAULT", 1: "ALL", 2: "NONE", 3: "SINGLE"}


class SignerFail(Exception):
    """The signer fails the whole PSBT and returns nothing. `code` names the rule."""

    def __init__(self, code, msg=None):
        super().__init__("%s: %s" % (code, msg or code))
        self.code = code


def sighash_name(h):
    return SIGHASH_NAMES[0 if h == 0 else h & 3] + ("|ANYONECANPAY" if h & 0x80 else "")


class Signer:
    def __init__(self, secret_keys, approve, optional_forms=True):
        if approve is None or not callable(approve):
            raise ValueError("an approval callback is required; there is no default")
        self._approve = approve
        self.optional_forms = optional_forms
        self._by_pub33, self._by_x = {}, {}
        for sk in secret_keys:
            pub = AE.ecdsa_public_key(sk)
            self._by_pub33[pub] = sk
            self._by_x[pub[1:]] = sk

    @property
    def held_xonly(self):
        return set(self._by_x)

    def sign(self, data):
        try:
            return self._sign(data)
        except (C.PsbtError, S.SpendError) as e:
            raise SignerFail(e.code, str(e))

    # ------------------------------------------------------------------
    def _sign(self, data):
        p = C.parse(data)
        # 1. gather the anti-exfil fields, per input and key identifier
        table = {}
        for i, m in enumerate(p.inputs):
            for typ, keyid, val in C.ae_entries(m):
                if len(keyid) not in (33, 32, 64):
                    raise SignerFail("bad_keyid_length", "key identifier length %d" % len(keyid))
                if len(val) != {C.AE_HC: 32, C.AE_R0: 33, C.AE_RHO: 32}[typ]:
                    raise SignerFail("bad_field_length", "field %#x has length %d" % (typ, len(val)))
                table.setdefault((i, keyid), {})[typ] = val
        if not table:
            raise SignerFail("not_a_request", "no anti-exfil fields; no ordinary signing path")
        if len(table) > S.MAX_PAIRS:
            raise SignerFail("cap_exceeded", "too many pairs")
        # 2. one phase per request
        second = [t for t in table.values() if C.AE_RHO in t]
        if second and len(second) != len(table):
            raise SignerFail("mixed_phases", "some pairs hold rho and some do not")
        if not second and any(C.AE_HC not in t for t in table.values()):
            raise SignerFail("nonce_only", "a pair holds a nonce commitment without a host commitment")
        # 3. one spend path per input
        for i in range(len(p.inputs)):
            lens = {len(k) for (j, k) in table if j == i}
            if 32 in lens and 64 in lens:
                raise SignerFail("both_paths", "input %d has a key-path and a script-path pair" % i)
        # 4. resolve every pair; check ownership and existing signatures
        pairs = {}
        for (i, keyid) in sorted(table):
            pr = S.resolve_pair(p, i, keyid, self.held_xonly, self.optional_forms)
            if pr.sigkey in p.inputs[i]:
                raise SignerFail("already_signed", "input %d already holds a signature for this pair" % i)
            pairs[(i, keyid)] = pr
        # 5. secrets, and the values step 2 or step 4 recompute
        for pr in pairs.values():
            self._check_purpose(p, pr)
        secrets_ = {k: self._secret_for(pr) for k, pr in pairs.items()}
        commits = {}
        for k, pr in pairs.items():
            t = table[k]
            if second:
                hc = (AE.ecdsa_host_commit if pr.scheme == "ecdsa" else AE.host_commit)(t[C.AE_RHO])
            else:
                hc = t[C.AE_HC]
            if second and C.AE_HC in t and t[C.AE_HC] != hc:
                raise SignerFail("hc_mismatch", "host commitment differs from the one rho gives")
            r0 = self._commit(pr, secrets_[k], hc)
            if C.AE_R0 in t and t[C.AE_R0] != r0:
                raise SignerFail("r0_mismatch", "nonce commitment differs from the computed value")
            commits[k] = r0
        fee, fee_ok, unverified = S.fee_info(p, list(pairs.values()))
        out = p.clone()
        if not second:
            for (i, keyid), r0 in commits.items():
                out.inputs[i][bytes([C.AE_R0]) + keyid] = r0
            return out.serialize()
        # 6. one approval for the whole PSBT, before any run of step 4
        if self._approve(self._describe(p, pairs, fee, fee_ok, unverified)) is not True:
            raise SignerFail("not_approved", "the user did not approve")
        sigs = {}
        for k, pr in pairs.items():
            rho = table[k][C.AE_RHO]
            try:
                if pr.scheme == "ecdsa":
                    sig = AE.ecdsa_device_sign(secrets_[k], pr.message, rho)
                    field = S.sigfield("ecdsa", pr.sighash, int.from_bytes(sig[:32], "big"),
                                       int.from_bytes(sig[32:], "big"))
                else:
                    field = S.sigfield("bip340", pr.sighash, AE.device_sign(secrets_[k], pr.message, rho))
            except ValueError as e:
                raise SignerFail("step4_failed", str(e))
            sigs[k] = field
        for i in range(len(out.inputs)):
            out.inputs[i] = C.strip_ae(out.inputs[i])
        for (i, keyid), field in sigs.items():
            out.inputs[i][pairs[(i, keyid)].sigkey] = field
        if p.version == 2:
            for pr in pairs.values():
                C.apply_modifiable_update(out.glob, pr.sighash)
        return out.serialize()

    # ------------------------------------------------------------------
    @staticmethod
    def _check_purpose(p, pr):
        """SHOULD keep each key to one scheme: fail on a path purpose that names the other scheme."""
        m = p.inputs[pr.index]
        try:
            if pr.scheme == "ecdsa":
                rec, off, wrong = m.get(b"\x06" + pr.keyid), 4, (86,)
            else:
                rec, wrong = m.get(b"\x16" + pr.keyid[:32]), (44, 49, 84)
                if rec is None:
                    return
                n, off = C.read_compact(rec, 0)
                off += 32 * n + 4
        except C.PsbtError:
            return                  # cannot tell
        if rec is None or len(rec) < off + 4:
            return
        first = int.from_bytes(rec[off:off + 4], "little")
        if first & 0x80000000 and first & 0x7FFFFFFF in wrong:
            raise SignerFail("scheme_purpose_mismatch", "derivation path purpose names the other scheme")

    def _secret_for(self, pr):
        """The secret scalar bytes the protocol functions take for this pair."""
        if pr.scheme == "ecdsa":
            sk = self._by_pub33.get(pr.keyid)
            if sk is None:
                raise SignerFail("key_not_held", "no secret for this key")
            if AE.ecdsa_public_key(sk) != pr.keyid:
                raise SignerFail("key_mismatch", "held secret does not match the key")
            return sk
        x = pr.keyid[:32]
        sk = self._by_x.get(x)
        if sk is None:
            raise SignerFail("key_not_held", "no secret for this x-only key")
        if AE.public_key(sk) != x:
            raise SignerFail("key_mismatch", "held secret does not match the declared key")
        if pr.path == "script":
            return sk
        # key path: the secret must belong to the internal key, then tweak it as BIP341
        d0 = int.from_bytes(sk, "big")
        d = d0 if AE._mul(d0)[1] % 2 == 0 else AE._N - d0
        sk_t = AE._b32((d + pr.tweak) % AE._N)
        if AE.public_key(sk_t) != pr.pk:
            raise SignerFail("tweaked_key_mismatch", "tweaked secret does not give the output key")
        return sk_t

    @staticmethod
    def _commit(pr, sk, hc):
        try:
            if pr.scheme == "ecdsa":
                return AE.ecdsa_device_commit(sk, pr.message, hc)
            return AE.device_commit(sk, pr.message, hc)
        except ValueError as e:
            raise SignerFail("step2_failed", str(e))

    @staticmethod
    def _describe(p, pairs, fee, fee_ok, unverified):
        tx = C.core_tx(p)
        return {
            "version": tx.version, "locktime": tx.locktime,
            "inputs": [{"txid": h[::-1].hex(), "vout": i, "sequence": q} for h, i, _, q in tx.ins],
            "outputs": [{"value": v, "script": s.hex()} for v, s in tx.outs],
            "fee": fee if fee_ok else None, "fee_verified": fee_ok,
            "unverified_inputs": unverified,
            "signatures": [{
                "input": pr.index, "scheme": pr.scheme, "key": pr.keyid.hex(),
                "spend_path": {"legacy": "legacy", "segwit": "segwit v0", "key": "taproot key path",
                               "script": "taproot script path"}[pr.path],
                "leaf_hash": pr.leaf.hex() if pr.leaf else None,
                "leaf_script": pr.script.hex() if pr.leaf else None,
                "sighash": sighash_name(pr.sighash), "sighash_type": pr.sighash,
                "amount": pr.value,
            } for _, pr in sorted(pairs.items())],
        }
