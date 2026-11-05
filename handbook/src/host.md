# Host rules

The host does most of the work. A device can be dishonest, so every rule that matters for the protection is enforced by the host. These are the main ones. The full rules are in the protocol BIP, under Host randomness, Attempts and failures, and step 5.

## `rho`

- Draw a new `rho` for every attempt, and for every message and key within it, from a secure random source. Never derive it from something else.
- Never log it, publish it, share it or write it to durable storage, during or after signing. Erase it when the attempt ends.
- Keep `R0_bytes` in memory with `rho`. A restart ends the attempt.
- Use a link that keeps `rho` from third parties. Anyone who learns `rho` can recover the key from a backdoored device's signature. QR codes and files don't meet this on their own, and the drafts don't define a transport that does.

## The checks

Before sending `rho`, check that `R0_bytes` is a valid point and store it. After step 4, check, using only your own values and the stored `R0_bytes`:

1. `R0_bytes` parses as a point.
2. `t = hash(R0_bytes, rho)` is below `n`.
3. `W = R0 + t * G` is not the point at infinity.
4. The signature's `r` matches `W`.
5. The signature verifies for your own `pk` and `m`.

For ECDSA, also require low `s`, and check that the verification point equals `W` or `-W`. Use nothing the device sent other than the signature. Don't forward `R0_bytes`.

## Attempts

An **attempt** is one run of the protocol with one set of `rho` values. Before sending `hc`, record durably that an attempt is open for that device. That way a crash can't hide a failure.

An attempt ends as completed, abandoned or failed. It is abandoned only if the user stops or changes the request before `rho` is sent, for a reason that has nothing to do with the device. Anything else that ends it unsuccessfully is a failure.

## Counting failures

Timeouts, errors, refusals, malformed responses, a changed `R0_bytes`, failed checks and host restarts all count as failure events. Don't try to tell a transport fault from a refusal, because a device can make one look like the other.

- Keep a durable failure count per device. Identify the device by the keys in your own wallet data, never by an identifier the device reports.
- Add one at the first failure event in an attempt, and at most once per attempt, in the same atomic write as the attempt's state. A later success doesn't undo it.
- An attempt still open at startup counts as failed.
- Reset the count only when the user asks, with a clear statement of what is being cleared.

## Retries

Within an attempt you can retry a few times. Three retries each for steps 2 and 4 is the suggested default.

- You can repeat step 2 with the same `hc`. If `R0_bytes` comes back different, the attempt fails, because a second value is a second choice of nonce.
- After a failure past step 2, repeat steps 3 and 4 with the same `rho`, rather than starting a new attempt. A new attempt gives the device a fresh choice.

## Warnings

If the count has gone up since the user last acknowledged a warning, warn the user before starting another attempt with that device. Say that an attempt failed and that repeated failures can mean a malicious device. Changing the message, reconnecting or restarting doesn't clear this.

Don't start a new attempt silently after a failure, and don't change the fee or coins by yourself because of one, because an observer can see a changed transaction. If a device can't do anti-exfil signing, don't fall back to ordinary signing unless the user decides to, knowing they lose the protection.
