# Running the checks

One script reruns most of the checks:

    git clone https://github.com/AvilaLabs/anti-exfil
    cd anti-exfil
    ./check.sh

It needs Python 3, a C compiler, autotools and network access to fetch the pinned libsecp256k1 bases. It takes about 15 minutes.

## What it runs

| Step | What it checks |
|---|---|
| `vec-bip`, `vec-boundary`, `vec-psbt` | Each vector file is exactly what its generator writes. The PSBT step replays every vector through the reference host and signer |
| `vec-indep` | Every protocol vector, recomputed with separate curve code |
| `psbt-suite` | Unit, lifecycle and known-answer tests for the reference host and signer |
| `c-build`, `c-vectors` | The C module built on both pinned bases, reproducing every valid vector and rejecting every rejection case |
| `secp1140` | The host checks run against secp256k1 pull request 1140 and secp256k1-zkp, unmodified |

Each step is followed by a control, which runs the same check on something it must refuse, such as a vector file with one digit changed. If the check accepts it, the check isn't testing anything, and the script reports the control as failed. The last line reads `RESULT: all steps and controls passed` when everything passed.

## Options

| Option | Adds | Needs |
|---|---|---|
| `--regtest` | Spends of every form on a Bitcoin Core regtest node | `BITCOIN_BIN` set to a folder with Bitcoin Core 31.1 |
| `--jade` | The Jade native build, and the seed vectors replayed against it | `JADE_SRC`, `IDF_PATH`, `cmake` and a Python with `wallycore`, `cbor2` and `pyserial`. The top of `check.sh` has the details |
| `--long --yes` | The long mutation, lifecycle and C module runs | About 6 hours, and the analysis tools listed in `check.sh` |

## The results

[`EVIDENCE.md`](https://github.com/AvilaLabs/anti-exfil/blob/main/EVIDENCE.md) lists every check with its result and what it doesn't show, what failed during development and how it was fixed, and what wasn't tested.
