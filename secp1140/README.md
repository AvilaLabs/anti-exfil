# Anti-exfil host-check tests for libsecp256k1 PR 1140

Test tables for the anti-exfil protocol in `spec/bip-anti-exfil.md` (`vectors/bip-anti-exfil.json` plus the
boundary file `vectors/bip-anti-exfil-boundary.json`: ECDSA messages at or above n, keys 1, n-1 and out of
range, out-of-range signature halves), run against the unmodified
API of two libraries and against this repository's own module. Test data only; all keys are artificial.

    secp1140/run.sh

Needs gcc, make, git, python3, flock and systemd-run. The first run fetches the two pinned commits
(about 20 MB) into `.work/secp1140/`, builds out of tree with `make -j2` (`AE_JOBS` changes it), takes about a minute, prints
a summary and writes `.work/secp1140/results.json` (`AE_RESULTS` names another file). Exit code 0 means every table passed and the control failed as it should.

## What runs

- **BIP340 on PR 1140** (benma/secp256k1 `b4d2b22e`, `test_pr1140.c`): `anti_exfil_host_commit` exact
  bytes; `anti_exfil_host_verify` on tuples made under the spec's derivation (honest ones accepted,
  every rejection tuple refused under both values of the negation flag); PR 1140's own `signer_commit`,
  `sign_custom` and `host_verify`, with the same rejection cases applied to its own signature.
- **ECDSA on secp256k1-zkp** (`45f6f0f1`, `test_zkp.c`): the same with its API.
- **This repository's module** (`test_module.c`, built on the PR 1140 tree): the same tables, plus the
  signer known answers, which must match byte for byte.
- **Control**: the tests are rebuilt with `-DAE_CONTROL`, which flips one signature bit in one honest
  tuple and puts back the one changed byte of a rejection tuple. Each program must then report both.
- Not run: forced-hash cases (they need a hash override) and wrong-length values (the APIs take
  fixed-size arguments). Both are listed as skipped or not expressible, with the case id.

The boundary cases run in every program as `boundary_*` sections. `scripts/gen_boundary_vectors.py --crosscheck`
also recomputes the ECDSA message cases with the arithmetic of a second implementation in this repository.

`gen_tables.py` writes `anti_exfil_vectors.h` from both vector files; `--check` fails if it is stale.

## What does not match PR 1140

- **Nonce derivation.** The spec derives `k0` from `tagged_hash("s2c/schnorr/nonce", ...)` with the key
  masked by the host commitment (ECDSA: `s2c/ecdsa/nonce`, not RFC 6979). PR 1140 uses `BIP0340/nonce`
  with the commitment as auxiliary data, and zkp uses RFC 6979. Signer output therefore differs from
  the tables, by design, and is never compared with them; the run prints both R0 values.
  The host commitment, the `point` tag, the wire bytes and the host checks are the same.
- **Opening.** PR 1140 passes R0 as a pubkey plus an `s2c_opening` with a `nonce_is_negated` flag; the spec
  sends the 33 bytes of R0. The tests convert with PR 1140's own parser: the commitment is
  `ec_pubkey_parse(R0_bytes)`, and the opening is `s2c_opening_parse` of R0_bytes with bit 2 of the first
  byte set when `W = R0 + t*G` has odd y, `t = tagged_hash("s2c/schnorr/point", R0_bytes || rho)`.
  The host derives the flag itself; the opposite flag is refused for all 11 honest tuples.
- **Prefix 06 and 07.** `s2c_opening_parse` reads them as 02 and 03 plus the flag. The spec's `parse33`
  refuses them. `bip340-reject-R0-prefix-06` and `-07` are refused only because the commitment is parsed
  from `R0_bytes`; a caller that takes the commitment from the opening accepts the 6 honest tuples whose
  W is odd with R0 starting 06 or 07 (printed as `DIFF`).
- **zkp key range.** `secp256k1_ecdsa_anti_exfil_signer_commit` does not check the secret key: it returns 1 for
  sk = 0, sk = n and sk = 2^256 - 1 (`ecdsa-boundary-sk-zero`, `-sk-n`, `-sk-max`), while
  `secp256k1_anti_exfil_sign` returns 0 for them. The spec requires the device to fail at that step.
- PR 1140 takes a keypair, so an out-of-range key is refused by `secp256k1_keypair_create`, before the signer functions.
- Apart from the key range, zkp showed no difference from the spec in these tables.
