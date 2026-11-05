# Test vectors

All vector files are in `vectors/`, and each has a README with its exact layout. They are available under CC0-1.0 or MIT. Every key in them is artificial and must never hold funds.

## Protocol vectors

`bip-anti-exfil.json` covers both schemes.

- **`valid`**: complete honest runs. Give a device `sk`, `m` and `rho` and check that it produces exactly `pk`, `hc`, `R0_bytes` and `sig`. Give a host `pk`, `m`, `rho`, `R0_bytes` and `sig` and check that it accepts. The cases cover every combination of odd and even `R0`, `P` and `W`.
- **`reject`**: tuples a host must refuse. Each is a valid case with exactly one value changed, and it names the change.
- **`forced_hash`**: failures that real hashes can't reach, such as `k0 = 0`. Each states the hash output a test has to substitute.

`bip-anti-exfil-boundary.json` adds boundary cases in the same format: device runs that must fail, host rejections that each name the check that refuses them, and tuples a host must accept.

## PSBT vectors

`bip-anti-exfil-psbt.json` has:

| Section | Count | What it holds |
|---|---|---|
| `exchanges` | 86 | Full exchanges for each spend form and PSBT version: both requests, both responses, the host's result and the finalized transaction |
| `signer_refusals` | 79 | Requests a signer must fail, each with the rule it tests |
| `host_refusals` | 40 | Responses a host must reject |
| `host_accepts` | 4 | Responses that differ from the request in an allowed way |
| `request_refusals` | 26 | Host PSBTs the host must refuse before starting |
| `lifecycle_scenarios` | 18 | Runs against one store, with restarts, stops and resets, and the expected outcome and count |
| `user_facts` | 11 | What the user must be told |

Compare PSBTs as parsed maps, because the order of maps and fields doesn't matter. The vectors fix `rho` so the bytes are reproducible. A real host draws it at random.

`bip-anti-exfil-psbt-seed.json` holds the required spend forms with keys from the BIP39 test mnemonic (`abandon ... about`), for a device that holds a mnemonic.

The vectors don't repeat the invalid PSBT lists in BIPs 174, 370 and 371. An implementation should pass those too.

## Regenerating them

The generators are in `scripts/`. `gen_bip_vectors.py --check`, `gen_boundary_vectors.py --check` and `gen_psbt_vectors.py --check` each regenerate their file and compare it with the one on disk. `check_bip_vectors.py` recomputes every protocol vector with separate curve code.
