# Command line contract

How the harness runs the executable under test, a signer and a host in one program. What the program does comes from the two specification documents; this file fixes only the command line, the lines read and written, and the exit codes. This is level 1 of the contract in [`validation/shortcuts/CLI_CONTRACT.md`](../shortcuts/CLI_CONTRACT.md), which adds the `reset` command, the decline answers, unsolicited lines, a user stop and a log.

The program is one executable. All byte strings are lowercase hex. A PSBT on a command line or a line of input is its serialized bytes in hex.

## Signer

    <program> signer --secret-key <hex32> [--secret-key <hex32> ...] [--decline]

The signer reads one line from standard input, a request PSBT. Each run is a new process with no memory of earlier requests.

- It handles requests under this protocol only. Anything else is a failure.
- `--decline` means the user declines any approval prompt on the device. Without it, the user approves every prompt.
- On success it prints the response PSBT on one line and exits 0.
- On failure it prints nothing on standard output and exits 3. Diagnostics may go to standard error.

## Host

    <program> host --device-key <hex33> [--device-key <hex33> ...] --store <path> --max-retries <n> --psbt <hex> --rho <input>:<key identifier hex>:<rho hex> [--rho ...] [--ack-warning]

The host runs one signing of the given PSBT against a device reached through standard input and output. The keys given are the wallet's keys for one device. `--psbt` is the host's own PSBT.

For each request the host would send to the device:

- It prints `REQUEST <hex>` on one line and flushes.
- It reads one line. The line is a response PSBT, or the word `ERROR`, which means the device reported a failure or refusal.

`--store` is a file the program owns, for whatever the host must keep durably. It may not exist yet. The same path is used across runs for the same device. The format is the program's own.

`--rho` gives the random value for each pair, where `<input>` is the input index in decimal and the identifier is the pair's key identifier. The host uses these values instead of drawing random ones. If a pair has no `--rho`, the host prints `MISSING_RHO` and exits 9.

`--max-retries` is the number of retries per step. With 0 the host never retries.

`--ack-warning` means the user acknowledges any warning the host has to show before starting. Without it, the user does not acknowledge.

Before exiting, the host prints `COUNT <n>`, the failure count for this device, and then one of these:

| Last line | Exit | Meaning |
|---|---|---|
| `RESULT <hex>` | 0 | Signing completed, and this is the host's result PSBT |
| `FAILED` | 3 | An attempt ended as failed |
| `REFUSED` | 4 | The host refused before recording an attempt, and sent nothing |
| `NOT_ACKNOWLEDGED` | 5 | A warning was owed and was not acknowledged, and nothing was sent |
| `ABANDONED` | 6 | An attempt ended as abandoned |

## Build

A file named `RUN` in the top of the implementation's folder holds the command that runs the program, as one line, relative to that folder. For example `python3 -B main.py`, or `target/release/aexf`. The harness adds the arguments.
