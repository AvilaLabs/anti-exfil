# Anti-exfil PSBT test vectors

`bip-anti-exfil-psbt.json` holds the vectors for `bip-anti-exfil-psbt.md`. License: CC0-1.0 or MIT, at your option. All keys are artificial, derived from
labelled seeds, and have no value. `scripts/gen_psbt_vectors.py` writes both files; `--check` compares them with the disk.

## Contents

- `exchanges` (86): for each spend form and PSBT version 0 and 2, the host's PSBT, both requests, both responses, the
  host's result and the finalized transaction. Further exchanges cover every accepted sighash type for a segwit v0 key and a
  Taproot key path, and a transaction with all thirteen forms.
- `signer_refusals` (79): requests a signer must fail, each with the rule it tests.
- `host_refusals` (40): exchanges in which a response breaks a rule under "Handling a response" or fails step 5.
- `host_accepts` (4): responses that differ from the request in an allowed way, which the host must accept.
- `request_refusals` (26): host PSBTs the host must refuse before it records an attempt.
- `lifecycle_scenarios` (18): host runs against one store in order (restart after a kill, an unreadable store, an unsolicited
  line, answers to the decline questions, a reset, a user stop before `rho`, after `rho` and with a response outstanding), each with
  scripted responses and the expected outcome and count.
- `user_facts` (11): what the user is told, as facts a log can show: the host's notice before its first request, and a fee that is not
  presented as verified when the text forbids it.

A second file, `bip-anti-exfil-psbt-seed.json` (20 exchanges), holds the required spend forms in PSBT versions 0 and 2 with keys derived
from the BIP39 test mnemonic of BIP84 and BIP86 (`abandon ... about`, empty passphrase) along the standard path of each script type, for a
device that holds a mnemonic. It uses the schema of `exchanges`, and
`--check` covers it. The keys are public test data and have no value.

## How to use

Parse each PSBT as a map set keyed by key bytes. Order of maps and of fields inside a map does not matter, so compare parsed
maps. For an exchange, give a signer `first_request` and expect `first_response`, then `second_request` and expect
`second_response`. Give a host `host_psbt`, the listed device keys and the listed `rho` values (a real host draws them
from a secure random source; vectors fix them), and expect it to send the stated requests and to produce `host_result`.
Signatures are deterministic given `rho`, so the bytes are reproducible.

`reason_code` values name the rule in the reference code. They are labels; a conforming implementation needs only to fail.

## Spend forms

p2pkh, p2wpkh, p2sh-p2wpkh, p2tr-key (no merkle root), p2tr-key-root (with a merkle root), p2wsh-single and p2sh-p2wsh-single
(`<K> OP_CHECKSIG`), p2wsh-2of3 and p2sh-p2wsh-2of3 (two device keys of three), and the optional forms p2sh-single and p2sh-2of3
(legacy P2SH), p2tr-script (one device key in a leaf, with a sibling leaf) and p2tr-multi_a (a `multi_a`-style leaf, two device keys).

## Rules the vectors pin down

Signature hashes use no annex. A key-path pair fails if `PSBT_IN_TAP_INTERNAL_KEY` is present and differs from the identifier. A
derivation record with the uncompressed form of a device key fails, for the host before it records an attempt and for the signer.
Attempt records, counts and warnings are pinned by `lifecycle_scenarios`, which needs a harness that can kill the host process, write to its
input and reuse its store; the SHOULD rules of that section (a limit on the count, the same transaction after a failure, the same `rho` on a
retry) are not tested, because a conforming host may do otherwise. `psbt/tests/test_lifecycle.py` holds the rest. A scenario or
fact marked `requires_contract` 2 or 3 needs the reset command, the decline answers, the user stop or the log of the harness's command
line contract (`validation/shortcuts/CLI_CONTRACT.md`). A signer refusal marked `conditional` (`signer-no-ae-fields`) applies only to an
implementation with no ordinary signing path. A case marked `optional_form` needs a form the text makes optional (the Taproot script path), so a
signer that does not support it fails it for that reason. `user_changes_transaction` on a lifecycle step is the user's choice to change the
transaction after a failure. `host-accepts-uncompressed-record-of-a-key-that-is-not-a-device-key` tests the host only, because a signer that holds a seed
MAY fail on any uncompressed derivation record. The host's `host_result`
for PSBT version 2 includes `PSBT_GLOBAL_TX_MODIFIABLE`; compare it. One exchange (`p2wpkh-signer-holds-key-of-unrequested-input-v0`) leaves an
input unsigned on purpose and has null `final_transaction` and `final_txid`.

## Checks on these vectors

Every vector is replayed through the reference host and signer in `psbt/` while the file is generated, and the run stops if the
code disagrees. Every `final_transaction` for a non-optional and optional form was accepted by Bitcoin Core 31.1 on regtest
(`psbt/tests/test_regtest.py`). Core 31.1 could not read PSBT version 2, so for version 2 the final transaction was built
by the test suite's own finalizer from the host's result.

Some exchanges (required locktimes, no fallback locktime, 1-of-2 multisig, a NON_WITNESS_UTXO with witness data, two Taproot
inputs with explicit SIGHASH_ALL) ran through the reference and were not mined.

The vectors do not repeat the lists of invalid PSBTs in BIP 174, BIP 370 and BIP 371. An implementation should pass those too; the
reference does, in `psbt/tests/test_bip_psbt_cases.py`.
