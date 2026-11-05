# Test vectors for the anti-exfil BIP

`bip-anti-exfil.json` holds the test vectors for the protocol in
`spec/bip-anti-exfil.md`. They are available under CC0-1.0 or MIT, at your
option.

**The keys are artificial.** Every secret key, `rho` and message is the SHA-256
of a fixed text string, so anyone can recompute it. They protect nothing and
must never be used with real funds.

## File layout

The top level has the fields `title`, `specification_revision`, `license`,
`keys_are_artificial`, `encoding`, `derivation` and `classes`, then one section
for each scheme, `bip340` and `ecdsa`. Each scheme section has three lists:
`valid`, `reject` and `forced_hash`. All byte strings are lowercase hex. An
empty message is the empty string.

## Valid cases (`valid`)

These are complete honest runs. Each case has these fields.

- `id`, `comment`: a name and a plain-sentence description.
- `seed`: the text the inputs were derived from. `sk` is SHA-256 of the seed
  followed by `/sk`, `rho` is SHA-256 of the seed followed by `/rho`, and a
  32-byte `m` is SHA-256 of the seed followed by `/m`. The 1024-byte message
  in the long BIP340 case is the 32 hashes of the seed followed by `/m/0`
  through `/m/31`, joined together.
- `sk`: the 32-byte secret key. `m`: the message (any length for BIP340,
  exactly 32 bytes for ECDSA). `rho`: the host's 32 bytes.
- `pk`: the public key (32-byte x-only for BIP340, 33-byte compressed for
  ECDSA). `hc`: the host commitment computed from `rho`. `R0_bytes`: the
  33-byte device commitment, with its real y parity. `sig`: the 64-byte
  signature.
- `R0_parity`, `P_parity`, `W_parity`: the y parity of `R0`, of the public key
  point `P = d' * G`, and of the final nonce point `W`. For ECDSA, `s_negated`
  says whether low-s normalization replaced `s` with `n - s`. `m_length` is
  the byte length of `m`.

To use them, give a device implementation `sk`, `m` and `rho` and check that it
produces exactly `pk`, `hc`, `R0_bytes` and `sig`. Give a host implementation
`(pk, m, rho, R0_bytes, sig)` and check that it accepts.

Coverage: for each scheme, all eight combinations of odd and even `R0`, `P`
and `W`. For BIP340, also an empty, a 32-byte and a 1024-byte message. For
ECDSA, one case where low-s normalization negates `s` and one where it does
not.

## Rejection cases (`reject`)

Each is a tuple `pk`, `m`, `rho`, `R0_bytes`, `sig` that a host must reject.
Every tuple is a valid case from the same file with exactly one value changed;
`derived_from` names that case, `defect` names the kind of change and
`comment` states the reason. There is no secret key. `expected` is always
`reject`.

The defects are: wrong `rho`, wrong `R0_bytes`, wrong `m`, wrong `pk`, changed
`r`, changed `s`, high-s ECDSA, `R0_bytes` prefix `06`, `07`, `00` or `04` (and the same for the ECDSA `pk`), an
x coordinate that is not below `p` (in `R0_bytes`, in `pk`, and in the BIP340
`r`), a value outside the allowed range for `r` or `s`, an x coordinate with no
curve point, each field one byte too short and one byte too long, and a valid
signature from the right key made with a nonce that is not `W`
(`nonce_not_W`: one with an unrelated nonce and one with the base nonce `k0`
alone). The last class verifies as an ordinary signature; the host must reject
it because `r` is not `x(W)`.

To use them, give a host implementation each tuple and check that it rejects.
A host that is a library with fixed-size arguments may be unable to receive a
wrong-length value. In that case it satisfies the case by construction.

## Forced-hash cases (`forced_hash`)

These need a hash override, so a test harness must be able to replace one
tagged hash output. Each case has `requires_hash_override: true` and a
`forced_hash` object. In it, `tag` names the tagged hash, `output` is the
32 bytes that call returns, and `why` says what that does. During the case,
every call to `tagged_hash` with that tag returns `output` and every other
hash is computed normally.

`operations` lists what to run: `device_commit` and `device_sign` for failures
in the device, `host_verify` for host rejections. Device cases give `sk`, `m`,
`rho` and `hc` and expect the operation to fail (`expected` is `device_fails`).
Host cases give a tuple and expect rejection (`expected` is `reject`). Without
the override the same inputs succeed.

The cases are: `k0` equal to 0 (BIP340 also with the output `n`, which reduces
to 0), ECDSA `k0` equal to `n` and to `2^256-1` (no reduction and no retry),
`t >= n` in the device and in the host, `k' = 0` (the forced `t` is `n - k0`),
and `W` at infinity in the host (the same forced `t`).

## Isolated cases

Some rejection cases fail for more than one reason: a tuple with a bad `pk` or a bad
`R0_bytes` also has a signature that does not match, so an implementation that skips the check
named in `defect` still rejects it. The cases with `isolated` in their id fail only on the check
they name. Each has an `isolates` field that states the check, and a `comment` that says why every
other check passes. They are in the same `reject` and `forced_hash` lists.
Each isolated case was confirmed against a mutant of the reference that drops the named
check (the mutant accepts, the reference does not); the record is
`validation/mutants/isolated_vector_confirm.json`.

Fields in the isolated cases: `isolates`, `fails_at_step` (the step of the host procedure
where the reference refuses it, 1 to 5; a reject case that fails there and nowhere earlier),
`plain_signature_valid` (true when the signature is an ordinary valid signature of the key) and
`seed` (the text that `sk`, `rho` and `m` derive from, as in the valid cases; absent where no key
is needed).

Without a hash override (`reject`, same procedure as above):

- `*-reject-isolated-pk-off-curve`: `pk` is not a curve point (BIP340: an x with no point;
  ECDSA: `02` plus such an x), `R0_bytes` is valid, and the signature is the one that satisfies the
  verification equation when the `pk` term is dropped. Only the failed lift or parse of `pk` refuses it.
- `*-reject-isolated-R0-prefix-04`, `-R0-x-off-curve`, `-R0-x-not-below-p`: `R0_bytes` does not
  parse. The signature is an ordinary valid signature of the key made with nonce `t = tagged_hash(point
  tag, R0_bytes || rho)`, so `x(W)` matches `r` if `R0` is dropped. Only the failed parse of
  `R0_bytes` refuses it.

With a hash override (`forced_hash`). Besides the `forced_hash` object, a case may carry
`additional_forced_hashes`, a list of further `{tag, output, why}` objects applied together.
Two new `expected` values appear. `accept`: the host must accept the tuple under the override
(the case checks that a valid tuple is not refused). `device_produces`: the device must return exactly
`R0_bytes` from `device_commit` and `sig` from `device_sign` under the override.

- `*-forced-isolated-W-doubling` (`accept`): `t` is forced to 5 and `R0 = 5G`, so `W = R0 + t*G` is
  the doubling case of point addition. The signature is valid with nonce 10.
- `*-forced-isolated-W-infinity-from-negated-R0` (`reject`, step 3): `t` is forced to 5 and
  `R0 = -5G`, so `W` is infinity. The signature is valid with nonce `n - 10`, so only the infinity
  check refuses it.
- `bip340-forced-isolated-s-equals-n` (`reject`, step 5): `t` forced to 0 and the BIP340 challenge
  forced to `e`, with `R0 = -e*P` and `s = n`. Reduced, `s` would be 0 and satisfy the equation;
  only the range check `s < n` refuses it.
- `ecdsa-forced-isolated-s-one-device` and `-s-one-host`: `k0` forced to 11 and `t` to 13 and `m`
  chosen so the raw `s` is 1. The device produces that signature and the host accepts it. (`-host`
  forces only `t`.)
- `ecdsa-forced-isolated-s-low-limit-device` and `-host`: the same with the raw `s` equal to
  `(n-1)/2`, the largest accepted value. The device must not negate it and the host must accept it.

Not in this file: the r = 0 and r = 1 ECDSA cases (mutants of the reference that change the `r == 0` check or the range check on `r`) need a small group order to build, because they need a nonce point
whose x coordinate is `n` or 1 and so a known discrete log. They are covered by the tests in
`validation/mutants/reference_math_mutant_tests.py`, not by the public vectors:

- `api:toy-ecdsa-r-zero-sign-message`: the signer must refuse when `r = x(W) mod n` is 0.
- `api:toy-ecdsa-r-one-accepted`: the signer must return, and the host must accept, a signature
  with `r = 1`.

Two further seam cases (the signer refusing `s = 0`, and the reasons for `k0` out of range) differ
between a correct implementation and a faulty one only in the failure message, which this file
does not specify, so they have no vector here.

## Regenerating and checking

`scripts/gen_bip_vectors.py` writes the file from the reference
implementation, and its `--check` option confirms the file on disk is what it
would write. `scripts/check_bip_vectors.py` recomputes every case with a
separate implementation written from the specification.

