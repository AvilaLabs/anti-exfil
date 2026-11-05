# What isn't proved or tested

## The proof

[`spec/security-argument.md`](https://github.com/AvilaLabs/anti-exfil/blob/main/spec/security-argument.md) gives a game-based reduction in the random oracle model, for one honestly generated key used only through this protocol. It covers a malicious host: a forgery on a message the user didn't approve yields a forgery against plain BIP340 or ECDSA, losing a factor of `q_s + 1` plus small statistical terms.

No cryptographer has reviewed it, and the proof isn't machine-checked as a whole. Parts of it are checked: some steps exactly on small groups, three steps in CryptoVerif, and message order and replay in ProVerif.

It doesn't cover:

- the malicious-device goal, which has a shorter, less reviewed argument of its own
- the concrete SHA-256 function
- the same key used with ordinary signing, or with both schemes
- related keys, such as a Taproot output key and its internal key, or non-hardened BIP32 children. A candidate extension covers these, but it rests on an assumption that hasn't been proved.

It also assumes plain ECDSA is unforgeable.

## The protocol's limits

- A device can still leak through refusals. The host makes them visible, but there is no overall bound unless it also caps failed attempts.
- `rho` must stay secret. QR codes and files don't keep it secret, and no transport for them is defined.
- Only single signers are covered, so MuSig2 and FROST are out of scope.
- Key generation, physical attacks, and timing or radio channels are out of scope.
- A signature made outside the protocol has no protection, so one ordinary signature under a key can leak that key.

## Testing

- **No hardware.** Nothing has run on a device, and there are no timing or power measurements.
- **Jade on the native build only.** The patch series passes Jade's own tests and the interoperability checks there, and the firmware builds for five targets, but none of it has been flashed.
- **Text-only implementations.** Two implementations were written from the text alone by an AI model, as a test that it can be followed. They could share a misreading with the text, and no separate team has implemented it.
- **Sampled mutation testing.** The mutation runs on the reference used samples, not the full set.

[`EVIDENCE.md`](https://github.com/AvilaLabs/anti-exfil/blob/main/EVIDENCE.md) has the full list, including what failed during development.
