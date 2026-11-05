# Anti-exfil signing over QR, SD card and file transports

This analysis, for version 0.16, is on paper, with some attack arithmetic checked in Python using test keys. Nothing here has run on a device or a camera, and nobody else has reviewed it.

## Summary

- **QR: no obstacle found on paper, but nothing tested in practice.** The protocol's messages need no change, and a stateless device suits the flow. QR would still need its own profile, because the direct-link documents exclude it. The profile would rest on one assumption: nobody who can pass `rho` to the holder of a device's backdoor sees the QR code carrying it, whole or nearly whole, at the time or from a kept copy.
- **What that assumption gives.** Against a backdoored device, plain QR signing today loses the key to the backdoor holder from public signatures alone. With two rounds over QR, that holder also needs a view of the QR code. This rests on the less reviewed malicious-device argument in `spec/security-argument.md`.
- **SD card and file transports do not work as they stand.** `rho` would be written to storage, which the specification forbids. Encrypting it does not fix this, as explained below.
- **One round does not avoid the problem.** It saves two displays, but exposes an equivalent value and leaves grinding open.
- **Usability is the main unknown.** Four displays per transaction instead of two, and the frame counts may be too high for small screens.

## Why `rho` matters

A backdoored device can compute `k0` from a secret its maker holds. Anyone with that secret and `rho` computes `t`, then the final nonce, then the key from one published signature.

A partial view is enough if it leaves few bits unknown. With most of `rho`, an attacker can try the remainder offline and test each guess against the public key. A profile cannot treat a partly captured QR code as safe.

## Who sees what

Every row assumes a backdoored device and an attacker holding its backdoor secret. If host and device collude, no transport helps.

| The attacker also has | Plain QR signing today | Two rounds over QR | Two rounds over USB |
|---|---|---|---|
| Nothing but published signatures | Key lost. One signature suffices with a known nonce, and Dark Skippy leaks a seed in two | Nonce channel closed under the argument's assumptions. Refusals, timing and failure reactions remain | Same as QR |
| A view of the host's `rho` frames, live or from a kept copy | Key lost anyway | Key lost from one signature | No frames exist. The equivalent is a cable tap |
| Malware reading the host's memory or logs | Key lost anyway | Key lost | Key lost |
| A view of the device's screen, live or recorded | Key lost anyway. The device can show it directly | Key lost anyway | Key lost anyway |

Two notes on the table.

**The device's screen.** `R0_bytes` is device-chosen and visible on QR. It can carry data in that point, but this matters little here, because a malicious device with a screen can display data in any QR code on any protocol. Two rounds neither add nor remove that risk, so an attacker viewing the device's screen is out of scope for every option.

**Air-gapped users.** They often choose QR because they distrust their host. The protocol's guarantee needs one of the two parties to be honest, so a host that does not collude with the device is still required, on QR and on USB alike. An air gap limits what a compromised host can do during signing. It does not replace this requirement.

For the other direction: a malicious host alone is the subject of Part 1 of the security argument, and the transport does not change that analysis.

## Per transport

**QR.** Screens are not durable, so the no-storage rule can hold if the wallet keeps no frames. A profile would require the host to show `rho` frames only while the user scans and clear them afterwards, with no screenshots or logs, and to tell the user about the viewing assumption. Phone hosts need care with camera and display capture. Whether common wallets can meet this is unknown.

**SD card and file.** The host would write `rho` to removable or synced storage, which breaks "MUST NOT be written to durable storage". Deleting a file does not reliably remove it, and backups and sync copy it. The card is also shared with the device, so a malicious device can write what it likes there for anyone who later reads the card.

## Encrypting `rho`

A key supplied by the device does not help, since a malicious device can choose one its maker can read. A key the host generates at setup and shows once in private helps only against someone who sees the host's QR frames and nothing else. It does nothing against host malware, and it does not rescue SD card or file, because a backdoored device can write the key to the same card. It has no forward secrecy, and it needs a new wire format and a stored secret on the device.

## Comparison with one round

The one-round form is Wuille's Scheme 2, and the Delving "level 2" proposal is its ECDSA version.

| | Two rounds | One round |
|---|---|---|
| QR displays per transaction | 4 | 2 |
| Secret on screen | `rho` | `t` or `n`, with the same role |
| Attacker with chain only, device never refuses | Nothing through the nonce, under the argument's assumptions | Grinding: the device sees the host's value before it commits |
| Detection | Refusals show as failures | Not as failures. Delving discusses timing checks and factory or user tests, which limit a device that grinds noticeably. There is no host-side check that bounds it |

One round does not avoid exposing a secret on screen, so its advantage is fewer displays. In the Delving thread, Wuille pointed out that a 4-bit grind leaks a secret in 64 signatures, and wrote that where interaction is not possible, a scheme like this is "probably the best possible". Wuille's 2020 overview says Scheme 2 "could be used", with grinding protection "reduced to spot checking". Two rounds appear possible on QR, subject to the open questions below.

## Cost

Two rounds means four displays, with the host holding `rho` in memory while the user carries messages. A restart ends the attempt.

Field overhead per pair is small: 68 bytes for `hc` or `rho` and 69 for `R0_bytes` on ECDSA, and 99 to 100 on a Taproot script path. The larger cost is the transaction itself. As specified, the whole PSBT crosses four times, so both directions roughly double compared with plain signing.

A profile could shorten responses to bare commitments and signatures, since the host discards the rest. Then only the host-to-device direction would double. We have not built or tested this.

As a rough scale only, offline encoder measurements on an earlier revision gave a median of 80 frames at QR version 12 and 758 at version 4, summed across all four messages for small transactions, using Jade's fountain redundancy. These are not scan counts and have no two-message baseline. On Jade's 240 by 135 screen, version 12 is 2 pixels per module, so the lowest frame count is also the hardest to scan. No camera, renderer or heap measurement stands behind this.

## Open questions

These need answers before a QR profile:

1. **Failure accounting.** The specification does not separate transport faults from refusals, because a device can present one as the other. On QR, a person carries messages and scans fail routinely, so counting every failed scan would train users to ignore warnings. A profile needs a rule that holds to the same reasoning. For example, waiting is not a failure, while a decoded bad response or a user-reported refusal is. Phone app restarts count as restarts.
2. **BC-UR (the fountain-coded QR format) and parsers.** Whether existing signers and wallets preserve the unknown key types `0x21` to `0x23` through their QR path.
3. **Display and memory limits.** Frame counts, multi-input growth and heap on real devices.
4. **Real use.** Whether four displays are acceptable.
5. **Host behaviour.** Whether common wallets can avoid keeping frames.
