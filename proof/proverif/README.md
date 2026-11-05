# Symbolic model of message order and replay
Result: `result.json`. The raw ProVerif output of each model is not kept, only its verdict and queries.

## What was checked

A ProVerif 2.05 model of the five protocol steps in `spec/bip-anti-exfil.md` with an
honest host, in two setups. Setup A: honest device, attacker controls the channel.
Setup B: the attacker holds the device key and answers every device message.

- Q1 (B, temporal): an accepted R0 was received before rho was released.
- Q2 (B): the accepted nonce point is add(R0, tweak(R0, rho)) for the stored R0 and the
  rho drawn in that attempt.
- Q3 (A): a host accepts (m, rho) only if the device approved that (m, rho).
- Q4 (A and B): with replicated attempts, one rho or one nonce point is accepted in at
  most one attempt; in A, an accepted R0 is the one the device recomputed for that hc.
- Q5 (A): rho is secret on a private link, before and after; not secret on a public one.
- Q6 (A): replayed passes get identical answers (correspondence on output terms).
- Q7 (A): no signature is released without approval for that (m, rho).

Seven controls (M1 to M6 and K1) are mutated models in which a named query must come
back false. If one does not, the checker reports INVALID.

## What the model leaves out

Free constructors only. Not modelled: the curve, hash strength, nonce bias and
grinding, signature malleability, parse33 and range failures, multi-key and related
keys, PSBT parsing, the user (approval is an abstract device event), the failure
counter, retries and the changed-R0 rule. Q1 and Q7 are partly true by the sequencing
of the code; their controls show they can fail. Q6 describes the device definition, not
a real device. A true result is about this abstraction only.

## Rerun

From the repository root:

    python3 -I proof/proverif/check.py

Each model runs one at a time under a 2 GB cap and a 600 s timeout. The checker prints
PASS, FINDING or INVALID and writes `result.json`.
