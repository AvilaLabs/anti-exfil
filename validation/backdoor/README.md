# Harness: backdoored-signer leakage

Purpose: measure what simulated backdoored signers leak against the unmodified public
`host_verify` / `ecdsa_host_verify` of `reference/anti_exfil.py`, as predicted
by the numeric windows coded in `check.py`. Verdicts are computed by the checker from those windows.

Files
- `signers.py`: loads the reference after checking SHA-256 `39d9c6c350133cef4b56110abc4d6a0e713eca2f8faac66493fadc36f68631ce`, then
  defines the simulated devices, observers, a seeded SHA-256 DRBG and a secret test
  stream. Only `G`-multiplication is replaced by a table version (compared with the
  reference at load and in `selftest()`); grinding walks R0 or W by adding G.
- `check.py`: part 1 (C1, C2, A1 to A13, 15 cases x 2 schemes). Flag `--smoke` uses small samples.
  Writes `.work/backdoor/result.json`, or `.work/backdoor/smoke_result.json` with `--smoke`. The flag `--seed N`
  (default 1) is part of the seed label. `results/output.txt` is the output of a full run.

Run: `systemd-run --user --scope -q -p MemoryMax=2G -p MemorySwapMax=0 python3 -B -I validation/backdoor/check.py`

Sample sizes (protocol-fixed numbers S=64, 200 trials, L in 0/1/3/8, b in 1/2/4, 4 inputs
are not changed). N is per scheme (BIP340 and ECDSA each):

| Case | N |
|---|---|
| C1 | 100 signatures |
| C2 | 20 trials of 32 signatures (256 bits each) |
| A1 | 1280 signatures |
| A2 | 1280 signatures |
| A3 | 100 signatures per variant (3 variants, plus high-s for ECDSA, plus an honest control) |
| A4 | the A1 and A2 low bytes (1280 each), 256 bins |
| A5 | 500 accepted signatures per b |
| A6 | 100 exchanges |
| A7 | 200 trials per L (fixed); every accepted signature of the first 100 trials per L goes through host_verify, the other 100 are not host-checked |
| A8 | 400 accepted messages |
| A9 | 300 accepted 4-input requests |
| A10, A11 | 100 signatures |
| A12, A13 | 100 signatures (A12 builds the 65536-entry rho table per scheme) |

A full run takes about 15 minutes on one core (859 s measured).

Decisions and limits
- Windows: bit accuracy 0.5 +/- 4 SE with SE = sqrt(0.25/n). Mean counts: predicted +/- 4 SE with
  SE = sample sd / sqrt(N). A7 needs mean excess in [L/2 - 4 SE, L] for L > 0 and |excess| <= 4 SE
  for L = 0 (read literally from the protocol; `in_window_around_L_over_2` is also recorded).
- A1 observer: the published observer does not know hc, so it assumes hc = 32 zero bytes; an
  oracle-strengthened observer given the true hc is also run. Both must recover 0 keys.
- A10 and A11 use different backdoor nonces: A10 uses A1's k0 = H(K, m, hc); A11 uses k0 = H(K, m)
  because an observer who knows only t cannot compute hc.
- A6 tests determinism, plus the retained-R0 rule of the spec's Failure handling, which is host
  policy and not part of `host_verify`. The harness models it as a byte comparison.
- A8 refuses at step 2. A5, A7, A9 refuse at step 4. A9 draws a fresh rho for every input of every attempt.
- The host-acceptance of honest-math signatures is also required where a case says the host accepts.
- Nothing here shows a device is secure or that the spec leaks no more than measured. Test keys only.
