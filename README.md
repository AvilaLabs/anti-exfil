# Anti-exfil signing

A proposed standard that stops a signing device from leaking its keys through the nonces of its signatures. The host contributes randomness to each nonce and checks the result, so the device can't choose the nonce on its own. It covers BIP340 and ECDSA, and adds PSBT fields so wallets and devices can use it without a private extension.

**[Read the handbook](https://anti-exfil.avilalabs.org)** for a guide to the attack, the protocol, the PSBT fields and the checks.

From Avila Labs. Draft, with no BIP number. No cryptographer has reviewed it and it has had no outside audit. **The Python code here is for reading and test generation only: it uses variable-time arithmetic and must not be used with real keys.**

## What's here

| Folder | Contents |
|---|---|
| `spec/` | The protocol BIP, the PSBT BIP, the security argument and the transport analysis |
| `vectors/` | Test vectors for the protocol and PSBT fields, and fixed-seed vectors a device can replay |
| `reference/`, `psbt/` | Reference arithmetic, then the host and signer, in Python, with their tests |
| `scripts/` | The vector generators, and a separate recomputation of the vectors |
| `c/` | A C module for libsecp256k1, on two pinned bases |
| `jade/` | A patch series adding this to Jade's `sign_psbt`, and the checks for it |
| `secp1140/` | The host-check tables, run against secp256k1 pull request 1140 and secp256k1-zkp with one command |
| `proof/` | The proof documents and their small-model and machine checks |
| `validation/` | Python and Rust implementations written from the text, shortcut and mutation checks, lifecycle model, C module checks |

Start with [`spec/bip-anti-exfil.md`](spec/bip-anti-exfil.md). [`EVIDENCE.md`](EVIDENCE.md) lists what was tested, what failed and what wasn't tested.

## Run the checks

    ./check.sh

This regenerates the vectors and compares them, recomputes them with separate curve code, runs the reference suite, builds the C module on both pinned bases and runs it, and runs `secp1140/run.sh`. Each step is followed by a control: the same check on something it must refuse. It takes about 15 minutes and needs Python 3, a C compiler, autotools and network access for the pinned bases.

| Option | Adds | Needs |
|---|---|---|
| `--regtest` | Spends of every form on a Bitcoin Core regtest node | `BITCOIN_BIN`, Core 31.1 |
| `--jade` | Jade native build, and the fixed seed vectors replayed against it | `JADE_SRC`, `IDF_PATH`, `cmake`, see the top of `check.sh` |
| `--long --yes` | The long mutation, lifecycle and C module runs | About 6 hours, and the analysis tools listed in `check.sh` |

## License

MIT. See [`LICENSE`](LICENSE). The test vectors are also available under CC0-1.0.
