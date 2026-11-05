# Evidence

What was tested, what failed and what wasn't tested. None of this shows the protocol is secure. No cryptographer has reviewed it, and it has had no outside audit. Unless a row says otherwise, you can rerun it with `./check.sh` and the options in the README.

## What was tested

| Check | Result | What it doesn't show |
|---|---|---|
| Protocol vectors, recomputed by separate curve code | 768 checks, 0 failures | Generator and checker share an author |
| Reference suite | 262 tests pass, including the invalid and valid PSBT lists in BIP 174, 370 and 371, BIP 341's wallet vectors, BIP 143's examples and Core's `sighash.json` | Core rows with hash types the reference refuses are left out |
| Each required and optional form spent on Bitcoin Core 31.1 regtest | Accepted and mined | Core 31.1 can't read PSBT version 2, so those transactions come from our own finalizer. Some exchanges, such as required locktimes and 1-of-2 multisig, ran through the reference and weren't mined |
| Vector strength: 272 shortcuts planted in a command-line implementation | 207 caught. The other 65 are listed with reasons as beyond the vectors, equivalent or not required. None is an open vector gap | Only shortcuts we thought of. The full set ran before the last refusal vector was added, and the two cases that vector affects were rerun on the final file |
| Requirements: mutants for each testable rule in the reference, 238 in all | 232 killed. The other 6 read by hand as equivalent, with the reasons in the classes file | The reference only |
| Mechanical mutants: three fixed samples of 200 from 2,351 | 160, 172 and 187 killed, each a different draw. All 80 survivors read by hand: 33 equivalent, 47 test gaps, each now tested. One mutant failed at import and counts as neither | A sample isn't a score of the whole. The full sweep wasn't run, and the arithmetic file wasn't sampled |
| Two more implementations, Python and Rust, written by an AI model from the text alone, with no feedback | Python 38 of 39 and Rust 39 of 39 on signer refusals, all else full marks. Live exchanges between them and the reference pass 54 of 54 on every pairing | The same kind of model helped write the text, so they can share a misreading, and no separate team has implemented it. Not run on the final vector file. Two Taproot script exchanges differ by design, because a rule was narrowed after they were written |
| btclib's host on our protocol vectors | BIP340: 11 of 11 honest, 38 of 38 rejections. ECDSA: 10 of 10 honest, 47 of 49 rejections. The other two are high-s signatures, which the spec refuses and its host leaves to the caller | btclib's host only |
| secp256k1 PR 1140 and secp256k1-zkp, unmodified, on the host tables | PR 1140: 156 pass, 0 fail, 20 not applicable. secp256k1-zkp: 138 pass, 0 fail, 25 not applicable. A flipped byte makes each report failure | Host checks only. The nonce derivation differs on purpose |
| C module: 12 checks on two bases, including 10,000 differential inputs per scheme, valgrind on 12 configurations, sanitizers and Fil-C, every branch taken, CBMC, Mull, three other CPU families under emulation | All pass, after hand classification of 299 raw findings | See the limits below |
| Host lifecycle model driven through the real reference host | Search exhausted at depth 26, 2,637 states, no violation | Read against our reading of the text, in `validation/host_lifecycle/`. Not rerun since the parser's field checks were added, which this path doesn't use |
| Jade port on the native build | 378 tests pass, 245 of them Jade's existing tests, unchanged. 1,088 checks through the reference host and against the reference signer, 0 failures: commitments and signatures byte-equal, 36 transactions mined. Of the vector exchanges, 44 ran inside Jade's limits and 42 were refused outside them. Of 79 signer refusals, 69 were refused by Jade, up to 35 of them only because the whole category is refused | Native build, not a device |
| Jade firmware | Five targets build. The T-Display image rebuilds byte-identical, and every secret wipe is present in its Xtensa code | Nothing was flashed. Later changes touched only test data and test formatting, so the images weren't rebuilt |
| Proof | Written proof for isolated keys, with hops checked exactly on small groups, CryptoVerif on three hops, ProVerif on message order and replay | The proof as a whole isn't machine-checked. Related keys rest on a stated assumption and a candidate proof |

## What failed

- **The reference parser accepted 31 PSBTs that BIP 174, 370 and 371 list as invalid.** It checked what it used and ignored the rest, so it would have gone on to sign them. It now refuses them, and the lists are in the suite.
- **The mutant samples found 47 test gaps.** Several were vector gaps: required locktimes in PSBT version 2, no fallback locktime, 1-of-n multisig, witness-serialized UTXOs, a P2SH-P2WSH script without the key, and explicit `SIGHASH_ALL` on multi-input Taproot. None was wrong behaviour, only nothing holding it right.
- **A text defect.** The PSBT document didn't require a signer to check a non-Taproot key against the script. The reference did, and a signer following the text might not have. The text now requires it.
- **Three vector defects.** Two refusal vectors failed on more than the check they named. Repairing one of them let a signer that ignores the rule that exactly one Taproot leaf entry may match refuse for the wrong reason, and pass. Planted shortcuts found that, and another vector closes it.
- **Implementations of an earlier draft, written with no feedback, scored 0 of 35 and 0 of 36.** The text was rewritten after that, and the scores above come from it.
- **The reference host failed early lifecycle runs.** A crash could lose a count, and a failed repeat of step 2 used up the wrong retry budget. Both are corrected.
- **A generator check fails by its own rule.** Regenerating the exchanges from the two extra implementations reproduces all but `p2tr-script-aggregate-internal-v0` and `-v2`, for the reason in the table. So that rule rests on the reference and our own judgment.
- **C module.** Valgrind reported one base function at `-O0`, and static tools raised 169 findings, all in base library files. Mull left 82 of 285 mutants alive per base, and the classes are hand-written.

## What wasn't tested

- **No hardware.** Nothing has run on a device, and there are no timing or power measurements. Constant-time evidence is valgrind on x86 builds, and Xtensa was only read for wipes.
- **Seven refusal vectors weren't run on Jade.** They hold malformed encodings, which the reference and the C module refuse.
- **Secret wipes in C.** The dead-memory scan noticed only 17 of 54 wipes when they were removed. Two it missed hold secret nonce data (`buf` in `schnorr_base` and `ecdsa_base`), so those rest on reading the source and on the Xtensa check.
- **The exhaustive group test** ran at order 13 only. Order 199 would take about 270 days.
- **Plain vectors can't reach some checks:** `t >= n`, `W` at infinity, ECDSA `V = ±W` with `x(V) mod n = r`, `V` at infinity, and the `x(W) >= n` double lift. Only seam tests in the C module cover them.
- **Beyond the vectors.** Some shortcuts can't be seen through a vector, such as a crash mid-write or `rho` reused across attempts. They're listed in `validation/shortcuts/not_caught*.json` with the reasons.
- **Jade can't take two valid requests.** libwally won't parse a `PSBT_GLOBAL_TX_MODIFIABLE` with bits outside 0 to 2, so that exchange wasn't sent. Jade refuses an input with no UTXO data, even one it doesn't sign. Refusing is safe. It also leaves out Taproot script paths and some sighash types, listed in `jade/README.md`.
- **The total leakage has no bound** without a limit on failed attempts. A malicious device still gets a bounded number of bits per failed attempt, and `spec/security-argument.md` gives that bound.
- **The long checks** ran piece by piece on the development tree, not as one `--long` run from a clean checkout.
