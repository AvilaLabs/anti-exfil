# Command line contract

How the harness runs the executable under test, a signer and a host in one program. What the program does comes from the two specification documents; this file fixes only the command line, the lines read and written, and the exit codes. The contract of the second implementations, [`validation/second_implementations/CLI_CONTRACT.md`](../second_implementations/CLI_CONTRACT.md), is level 1 of this one.

Records of `vectors/bip-anti-exfil-psbt.json` carry `"requires_contract"` with the level they need.

| Level | Contents |
|---|---|
| 1 | The `signer` and `host` commands, with the options not marked below |
| 2 | The `reset` command, the two decline answers, and lines that arrive when no response is owed |
| 3 | The host's `--stop` and `--change-transaction` options, and a `--log` option for both roles |

A program that lacks a level still passes every record that does not need it, except the scenarios that need unsolicited lines or a kill, which need no option.

The program is one executable. All byte strings are lowercase hex. A PSBT on a command line or a line of input is its serialized bytes in hex.

## Signer

    <program> signer --secret-key <hex32> [--secret-key <hex32> ...] [--decline] [--log <path>]

The signer reads one line from standard input, a request PSBT. Each run is a new process with no memory of earlier requests.

- It handles requests under this protocol only. Anything else is a failure.
- `--decline` means the user declines any approval prompt on the device. Without it, the user approves every prompt.
- On success it prints the response PSBT on one line and exits 0.
- On failure it prints nothing on standard output and exits 3. Diagnostics may go to standard error.

## Host

    <program> host --device-key <hex33> [--device-key <hex33> ...] --store <path> --max-retries <n> --psbt <hex> --rho <input>:<key identifier hex>:<rho hex> [--rho ...] [--ack-warning] [--declined] [--decline-unrelated] [--change-transaction] [--stop <point>] [--log <path>]

The host runs one signing of the given PSBT against a device reached through standard input and output. The keys given are the wallet's keys for one device. `--psbt` is the host's own PSBT.

For each request the host would send to the device:

- It prints `REQUEST <hex>` on one line and flushes.
- It reads one line. The line is a response PSBT, or the word `ERROR`, which means the device reported a failure or refusal.

`--store` is a file the program owns, for whatever the host must keep durably. It may not exist yet. The same path is used across runs for the same device. The format is the program's own.

`--rho` gives the random value for each pair, where `<input>` is the input index in decimal and the identifier is the pair's key identifier. The host uses these values instead of drawing random ones. If a pair has no `--rho`, the host prints `MISSING_RHO` and exits 9.

`--max-retries` is the number of retries per step. With 0 the host never retries.

`--ack-warning` means the user acknowledges any warning the host has to show before starting. Without it, the user does not acknowledge.

`--declined` and `--decline-unrelated` are the user's answers to the two questions the host asks after a second-pass refusal: did the user decline on the device, and was that decline unrelated to what the device showed. Without a flag the answer is no. (Level 2.)

**Lines when no response is owed.** A line the harness writes to the host's input while no response is outstanding is an unsolicited message, not a response: before the host's first `REQUEST`, or in the same write as a response, or straight after it. The host handles it as the text says. The harness may also end the host process at any `REQUEST`, and may write junk to the `--store` file before a run. (Level 2. These need no option.)

Before exiting, the host prints `COUNT <n>`, the failure count for this device, and then one of these:

| Last line | Exit | Meaning |
|---|---|---|
| `RESULT <hex>` | 0 | Signing completed, and this is the host's result PSBT |
| `FAILED` | 3 | An attempt ended as failed |
| `REFUSED` | 4 | The host refused before recording an attempt, and sent nothing |
| `NOT_ACKNOWLEDGED` | 5 | A warning was owed and was not acknowledged, and nothing was sent |
| `ABANDONED` | 6 | An attempt ended as abandoned |

(`MISSING_RHO` exits 9. The `reset` command exits 0 or 7 as below.)

## Reset (level 2)

    <program> reset --device-key <hex33> [--device-key <hex33> ...] --store <path> [--confirm]

Clears the failure count for the device. `--confirm` means the user confirms the clearing; without it the user does not. The program prints `COUNT <n>`, the count after the call, then `RESET` and exits 0 if it cleared the count, or `NOT_RESET` and exits 7 if it did not.

## User stop, transaction change and log (level 3)

These are test scaffolding. They are not part of the standard.

    <program> host ... --stop <point>

`--stop` makes the user stop the host at one named point, in whatever way the implementation handles a user stop or cancel. `<point>` is one of:

- `before_rho`: the first pass is done, `rho` has not been sent, and no response is outstanding.
- `after_rho`: `rho` has been sent, and the response to it has come back and has not been handled yet, so nothing is outstanding.
- `outstanding:<n>`: the response to the n-th request the host sends is outstanding (`outstanding:1` is the first pass, `outstanding:2` the one that carries `rho`). The harness writes the response; the host does not use it.

After the stop the host ends the run as the text says that attempt ends: it prints `COUNT <n>` and then `ABANDONED` (exit 6) if the attempt ended as abandoned, or `FAILED` (exit 3) if it ended as failed, without sending a further request. The stop does not erase the record the way a completed attempt would; the next run on the same store behaves as after any ended attempt.

    <program> host ... --change-transaction

`--change-transaction` is the user's choice, after a failed attempt, to change the transaction the host signs. Without it the user does not choose, and a host that insists on the same transaction after a failure refuses a different one (`REFUSED`, exit 4). With it the host goes on to the checks that follow, such as the warning.

    <program> host ... --log <path>
    <program> signer ... --log <path>

`--log` appends JSON lines of facts, one object per line, to the file, flushing each at once. The harness reads facts and never wording. The events:

| Event | Role | Fields | When |
|---|---|---|---|
| `notice` | host | `anti_exfil` (true) | when the user is told the host is requesting anti-exfil signing; this comes before the first `request` event |
| `request` | host | `n` | just before the n-th `REQUEST` line is printed |
| `fee` | host | `party` ("host"), `verified` (bool) | whether the host presents the fee to the user as verified |
| `approval` | signer | `party` ("signer"), `verified` (bool), `pairs` | whether the signer's approval description presents the fee as verified, and the signatures it covers: `pairs` is a list with one object per signature, holding `input`, `sighash_type` (the type the signature commits to, an integer) and `leaf_hash` (lowercase hex, `null` if the pair has no leaf). One event for each second pass, and no more |

The harness requires only what the text requires: a party that must not present a fee as verified never logs `verified: true` for it, and says it is unverified (`verified: false`). A party may log `false` for a fee it could have verified.

## Build

A file named `RUN` in the top of the implementation's folder holds the command that runs the program, as one line, relative to that folder. For example `python3 -B main.py`, or `target/release/aexf`. The harness adds the arguments.
