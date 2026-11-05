# The protocol

The protocol has five steps across two round trips. The **host** holds no secret key and checks the result. The **device** holds the key and signs.

```text
Host                                          Device

1. draw rho, compute hc
            ---- m, hc ---------------------->
                                              2. derive k0 from the key, m and hc
            <--- R0_bytes --------------------    send R0_bytes = k0 * G
   store R0_bytes
3.          ---- m, rho --------------------->
                                              4. user approves
                                                 recompute hc and k0 from rho
                                                 t = hash(R0_bytes, rho)
            <--- sig -------------------------    sign with nonce k0 + t
5. check that sig uses R0 + t * G
   and verifies
```

The device needs no state between the two round trips. It recomputes everything in step 4.

## The steps, for BIP340

Values are as in BIP340. `tagged_hash` is BIP340's tagged hash, and `ser33` is a 33-byte compressed point that keeps its real y parity.

**1. Host commits.** The host draws `rho`, 32 random bytes from a secure source, and sends `m` and

    hc = tagged_hash("s2c/schnorr/data", rho)

**2. Device commits.** The device derives a base nonce from its key, the message and `hc`, and sends the point:

    t0 = bytes32(d) xor tagged_hash("BIP0340/aux", hc)
    k0 = int(tagged_hash("s2c/schnorr/nonce", t0 || pk || m || hc)) mod n
    R0_bytes = ser33(k0 * G)

Because `k0` depends on `hc`, a host can't get two signatures from one base nonce. Step 2 gives out no signature, so it doesn't need the user's approval.

**3. Host reveals.** Only after it has received `R0_bytes`, checked it's a valid point and stored it, the host sends `rho` and `m` again.

**4. Device signs.** After the user approves, the device recomputes `hc`, `k0` and `R0_bytes` itself. It never takes them from the host. Then:

    t = int(tagged_hash("s2c/schnorr/point", R0_bytes || rho))
    k' = (k0 + t) mod n

and it signs with `k'` as in BIP340.

**5. Host verifies.** The host uses its own `pk`, `m`, `rho` and the `R0_bytes` it stored, and takes only `sig` from the device. It checks that `W = R0 + t * G` has the x coordinate in the signature, and that the signature verifies. It never forwards `R0_bytes` or anything else the device sent.

## ECDSA

ECDSA follows the same five steps with its own tags (`s2c/ecdsa/...`). `pk` is a 33-byte compressed key and `m` is exactly 32 bytes. Three things differ:

- `k0` fails if the hash is 0 or at least `n`, rather than being reduced.
- The device normalizes to low `s`, and the host refuses a high `s`, because otherwise the choice of `s` or `n - s` would give the device one free bit per signature.
- The host checks that the verification point equals `W` or `-W`, not only that the x coordinates match.

## Design choices

These are covered in full in the BIP's Rationale section.

- **Two round trips.** With one, the device sees the host's value before it chooses its nonce, and can try nonces until the signature carries the bits it wants.
- **A hashed tweak.** The nonce is `k0 + hash(R0_bytes, rho)` and not `k0 + rho`. This ties the tweak to the device's commitment and matches the sign-to-contract form that existing libraries implement. Wuille's 2020 overview calls this a variant of its Scheme 6.
- **A nonce derivation of its own.** The tags are used only by this protocol, so the same inputs can't reach an ordinary signing path.
- **A deterministic `k0`.** A device can then be stateless, and the host can retry step 4 with the same `rho` and get the same nonce.

## What's left to the device

A malicious device can still refuse. If it only finishes when the signature happens to carry the bits it wants, each refusal leaks a little. The security argument puts this at about 1.44 bits per expected failed attempt after the reveal. That's why the host has to count failures and tell the user (see [Host rules](host.md)). There is no overall bound unless the host also caps the number of failed attempts.
