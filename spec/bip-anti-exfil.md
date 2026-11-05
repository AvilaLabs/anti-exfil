```
BIP: ?
Layer: Applications
Title: Anti-Exfil Signing for BIP340 and ECDSA
Authors: Connor Avila <Connoravila@gmail.com>
Status: Draft
Type: Specification
Assigned: ?
License: MIT
Version: 0.16.0
Requires: 340
```

## Abstract

A signing device chooses the nonce in every signature it makes, so a compromised device can hide secret data in valid signatures. This document specifies a two-round protocol in which a host contributes randomness to the nonce and then checks that the device used it. It covers BIP340 and ECDSA. A second BIP specifies how to carry the protocol in PSBT.

## Motivation

A device that controls its nonce can reveal its key to anyone who knows how it chooses nonces. The output looks like any other valid signature, and neither the owner nor a verifier can tell. Dark Skippy showed that a seed can leak in two signatures. Without help from the host, a device can always grind: Pieter Wuille noted in the Delving thread listed under References that `2^b` grinding steps per signature leak `b` bits per signature.

Wuille's 2020 overview describes several schemes, and this document follows its Scheme 6, with a sign-to-contract tweak. Devices already deploy versions of it, and bitcoin-core/secp256k1 pull request 1140 proposes library support. There is no agreed specification. [Sjors Provoost's draft](https://github.com/Sjors/bips/pull/2) of October 2026 covers two-round signing for a single Taproot key path, with proprietary PSBT fields and a plain added tweak, so it does not interoperate with this document. Each implementer has to decide its own byte formats, failure rules and host checks, and several of those decisions affect what is protected, such as whether the host compares a repeated `R0_bytes` or counts a failed attempt.

## Specification

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are as in RFC 2119.

### Parties and goals

The **device** holds the secret key and signs. The **host** talks to the device, holds no secret key, and checks results.

1. **Malicious host, honest device:** the host cannot recover the key or obtain a signature on a message the user did not approve.
2. **Malicious device, honest host:** an accepted signature carries nothing the device chose, apart from what it can convey by refusing, as long as `rho` stays secret from every third party.

If both parties are malicious, the protocol offers nothing.

### Notation

`n`, `p` and `G` are the secp256k1 group order, field size and generator.

- `||` is byte concatenation, and `xor` is bytewise exclusive or.
- `tagged_hash(tag, x)` is `SHA256(SHA256(tag) || SHA256(tag) || x)`, with `tag` as ASCII bytes.
- `int(b)` reads bytes as a big-endian integer without reduction. `bytes32(i)` is its 32-byte inverse.
- `ser33(P)` is one byte, `0x02` if `y(P)` is even and `0x03` if odd, followed by `bytes32(x(P))`.
- `parse33(b)` is the inverse of `ser33`. It fails unless `b` is 33 bytes, its first byte is `0x02` or `0x03`, the remaining bytes as an integer are below `p`, and that integer is the x coordinate of a curve point.

**Fail** means the party stops the attempt and outputs no commitment or signature. How a failure is reported, including which one when several apply, is left to implementations. Values have fixed lengths: `rho`, `hc` and `sk` are 32 bytes, `R0_bytes` is 33 and `sig` is 64. `pk` and `m` are given per scheme. A party fails on any other length.

### The message

The device MUST compute `m` itself from data the user approves, either as a consensus signature hash or as a hash under a message-signing scheme shown to the user. It MUST NOT offer an entry point that signs a value supplied by a host, because approval means nothing for a value the user cannot read. Where the steps below say the host sends `m`, the host sends the data the device computes `m` from. The host computes `m` independently. It MUST send the same data in steps 1 and 3. If the data differs, the device derives a different nonce and the host's check in step 5 fails, so no separate check is needed.

A device MUST refuse `SIGHASH_SINGLE` with no matching output. Under the legacy signature hash such a signature commits to a constant and not to the transaction, and BIP341 makes it invalid.

### BIP340 protocol

`m` is a byte string of any length. `pk` is the 32-byte x-only public key.

**Step 1: host commits.** The host draws `rho`, 32 uniformly random bytes with full entropy from a cryptographically secure source, and sends `(m, hc)` to the device:

    hc = tagged_hash("s2c/schnorr/data", rho)

**Step 2: device commits.** The device fails unless `0 < int(sk) < n`, then computes:

    d' = int(sk)
    P = d' * G
    d = d' if y(P) is even, otherwise n - d'
    pk = bytes32(x(P))
    t0 = bytes32(d) xor tagged_hash("BIP0340/aux", hc)
    k0 = int(tagged_hash("s2c/schnorr/nonce", t0 || pk || m || hc)) mod n
    fail if k0 = 0
    R0_bytes = ser33(k0 * G)

`R0_bytes` records the actual parity of `k0 * G`. The device MUST NOT negate `k0` at this step, because the host hashes the actual point and both sides must agree on the bytes. It sends `R0_bytes` and need not keep any state.

**Step 3: host reveals.** The host MUST NOT send `rho` until it has received `R0_bytes`, checked that `parse33` accepts it, and stored it. It then sends `rho` and `m`.

**Step 4: device signs.** After user approval, the device MUST recompute `hc` from `rho`, and `d`, `pk`, `k0` and `R0_bytes` as in step 2. It MUST NOT use a stored value or accept any of these values from the host, because a host that could supply them could get two signatures on one base nonce and solve for the key. A failure named in step 2 is also a failure here. It then computes:

    t = int(tagged_hash("s2c/schnorr/point", R0_bytes || rho))
    fail if t >= n
    k' = (k0 + t) mod n
    fail if k' = 0
    W = k' * G
    k = k' if y(W) is even, otherwise n - k'
    r = bytes32(x(W))
    e = int(tagged_hash("BIP0340/challenge", r || pk || m)) mod n
    sig = r || bytes32((k + e * d) mod n)

The device SHOULD run the checks in step 5 on `sig` with its own values, and fail if any does not pass. This guards against faults only.

**Step 5: host verifies.** The host uses its own `pk`, `m` and `rho` and the `R0_bytes` it stored. The only other value it takes from the device is `sig`. It fails unless all of these hold:

1. `R0 = parse33(R0_bytes)` succeeds.
2. `t = int(tagged_hash("s2c/schnorr/point", R0_bytes || rho))` is below `n`.
3. `W = R0 + t * G` is not the point at infinity.
4. `bytes32(x(W))` equals the first 32 bytes of `sig`.
5. BIP340 Verify accepts `sig` for `pk` and `m`.

The host MUST NOT use a signature that fails these checks, and MUST NOT forward anything else the device produced, because that is device-chosen data.

### ECDSA protocol

The ECDSA protocol has the same five steps, with these differences.

`d = int(sk)` with no negation, and the device fails unless `0 < d < n`. `pk = ser33(d * G)` is 33 bytes. `m` is exactly 32 bytes, and `z = int(m) mod n`.

**Step 1.** The host fails if `parse33(pk)` fails, before sending anything. `hc = tagged_hash("s2c/ecdsa/data", rho)`.

**Step 2.**

    pk = ser33(d * G)
    d_mask = bytes32(d) xor tagged_hash("s2c/ecdsa/aux", hc)
    k0 = int(tagged_hash("s2c/ecdsa/nonce", d_mask || pk || m || hc))
    fail if k0 = 0 or k0 >= n
    R0_bytes = ser33(k0 * G)

The hash input is exactly 129 bytes, and `m` is not reduced. This is not RFC 6979, and a range failure does not retry with another output.

**Step 4.** After user approval, the device MUST recompute these values from `rho` under the same rule as the BIP340 protocol, then:

    t = int(tagged_hash("s2c/ecdsa/point", R0_bytes || rho))
    fail if t >= n
    k' = (k0 + t) mod n
    fail if k' = 0
    W = k' * G
    r = x(W) mod n
    s = (k')^-1 * (z + r * d) mod n
    fail if r = 0 or s = 0
    if s > (n - 1) / 2: s = n - s
    sig = bytes32(r) || bytes32(s)

**Step 5.** The inputs are as in the BIP340 protocol. The host fails unless all of these hold, where `r` and `s` are the two halves of `sig`:

1. `R0 = parse33(R0_bytes)` succeeds.
2. `t = int(tagged_hash("s2c/ecdsa/point", R0_bytes || rho))` is below `n`.
3. `W = R0 + t * G` is not the point at infinity.
4. `0 < r < n`, `0 < s <= (n - 1) / 2`, and `x(W) mod n` equals `r`.
5. With `P = parse33(pk)`, `u1 = z * s^-1 mod n` and `u2 = r * s^-1 mod n`, the point `V = u1 * G + u2 * P` is not infinity, `x(V) mod n` equals `r`, and `V` equals `W` or `-W`.

### Host randomness

The host MUST draw a new `rho` for every attempt and for every message and key within it. `rho` MUST NOT be derived deterministically, because its secrecy would then rest on whatever it was derived from. A `rho` the device has seen MUST NOT be used in a later attempt, because the device could then grind against it. Drawing it fresh from a secure random source meets this, and the host need not keep a record of past values.

`rho` MUST NOT be logged, published or shared with anyone but the device, during or after signing, and MUST NOT be written to durable storage. The host SHOULD erase it when the attempt ends. `R0_bytes` is kept in memory with `rho`, so a restart ends the attempt.

The link between host and device MUST keep `rho` from third parties. A third party who learns `rho` can recover the key from a signature made with a nonce it can predict. A QR or file transport does not meet this requirement without further measures, and this document does not define one that does.

### User approval

The device MUST obtain the user's approval before every run of step 4. Approval MUST cover everything the signature commits to, including a non-default sighash type and, for a Taproot script path, the leaf being satisfied. Step 2 releases no signature and needs no approval. Approval given around step 2 MUST NOT be relied on for step 4, because a stateless device cannot tell that the two steps concern the same message.

### Attempts and failures

A device that refuses selectively leaks through its refusals: accepting 1 attempt in `2^b` conveys about `b` bits. The host cannot close this channel, but it can make it visible to the user. The rules below are the only mitigation.

An **attempt** is one run of the protocol with one set of `rho` values. The host MUST durably record the attempt as open for that device before sending `hc`, so that a crash cannot hide a failure. A host that cannot write the record does not start the attempt. A request the host refuses before making that record is not an attempt. An attempt ends in one of three ways:

- **Completed:** every requested signature passed step 5.
- **Abandoned:** before `rho` was sent, the user stopped or changed the request for a reason independent of the device, with no response outstanding and no failure recorded. A decline that is not counted, under the rule below, also ends this way.
- **Failed:** anything else that ends it.

A **failure event** during an attempt is a timeout, a device error or refusal, a cancellation on either side while a response is outstanding, a malformed or missing response, a changed `R0_bytes`, a failed host check, a message the host did not request, or a host restart. A message the host did not request is a failure event but does not end the attempt. Outside any attempt the host discards it. The host does not try to separate transport faults from refusals, because a device can present one as the other. A timeout on a step that waits for the user SHOULD leave time to read the device and decide, because each one counts as a failure.

The host keeps a durable failure count per device. A device is identified by the keys or fingerprint in the host's own wallet data, never by an identifier the device reports. The host MUST add one, durably and in one atomic write with the attempt's state, at the first failure event in an attempt, and at most once per attempt, so that a crash can neither lose the count nor add it twice. A later success on that attempt does not undo it. An attempt that ends as failed with no failure event yet counted is counted as it ends. At startup, an attempt still recorded as open counts as failed. A host that cannot read its records for a device MUST treat that device as having a count of at least one. A host with no records at all cannot tell a new device from deleted records, and treats the device as new. The count resets only by an explicit user action that states what is being cleared.

Within an attempt, the host MAY retry a bounded number of times. Three retries for each of steps 2 and 4 is a reasonable default. It MAY repeat step 2 with the same `(m, hc)`, and MUST end the attempt as failed if `R0_bytes` differs from any value received for that attempt, whatever its form, including one in a response it rejected, because a second value is a second choice of nonce. A response the host cannot parse holds no value to compare, and nothing from it is used. After a failure event past step 2, it SHOULD repeat steps 3 and 4 with the same `rho` rather than start a new attempt, because a new attempt gives the device a fresh choice. This covers every failure event past step 2 other than a changed `R0_bytes`, including a response that failed a check. It MAY do so after a repeated step 2 returns an unchanged `R0_bytes`. When retries run out, the attempt has failed.

If the failure count has risen since the user last acknowledged a warning, the host MUST warn the user before starting another attempt with that device. The warning says that the attempt failed and that repeated failures can mean a malicious device. Changing the message, coins or fee, reconnecting and restarting do not clear this requirement.

An acknowledgement covers exactly one new attempt and is used up in the same durable write that records it, so it does not survive into another attempt after a restart. A reset clears any pending warning.

Until an attempt completes, a new attempt after a failure SHOULD carry the same core transaction unless the user chooses to change it, and a host MUST NOT change the fee or coins on its own because of a failure, since a published change tells an observer a failure happened. The host MUST NOT start a new attempt silently in response to a failure.

After a refusal at step 4, a host MAY ask the user whether they declined on the device, and need not count a decline the user confirms was unrelated to what the device showed, since a device cannot produce that answer. A decline because the device showed something unexpected counts, because a device can induce it. It SHOULD refuse further attempts past a small limit on the count. This document establishes no limit that bounds the total leakage, and counts held by separate hosts do not combine.

### Key separation

An implementation MUST NOT expose the nonce functions in this document through an ordinary signing interface, and a device MUST NOT use them for any signature outside this protocol, because a second signature on one base nonce can reveal the key. An ordinary signing interface under the same key MUST NOT let a host choose inputs that make it produce the base nonce `k0`.

## Rationale

**Why two rounds.** With one round, the device sees the host's contribution before choosing its nonce and can grind for a signature carrying chosen bits. Non-interactive schemes accept this limit, which is why they suit air-gapped use despite the grinding channel. This protocol uses the extra round to remove it, leaving only the choice to refuse.

**Why a commitment to `rho`.** If `k0` did not depend on the host's contribution, a host could get two signatures with one base nonce and two tweaks, and solve for the key. Deriving `k0` from `hc` ties the base nonce to `rho` before `rho` is revealed.

**Why a hashed tweak and not simple addition.** Hashing `R0_bytes` with `rho` binds the tweak to the device's commitment and matches sign-to-contract, which existing libraries implement. It does not protect a predictable `rho`.

**Why a derivation of its own.** A nonce function reserved for this protocol means the same inputs cannot reach an ordinary signing path, and it lets the security argument treat these nonces as their own domain. The cost is that device test vectors differ from older implementations; the protocol on the wire does not change.

**Why BIP340 reduces and ECDSA range-fails.** BIP340 signing already reduces its nonce hash, and this keeps that form. ECDSA has no such form to follow here, and range failure gives a uniform `k0`. The security argument accounts for both, with a bias term for the BIP340 reduction.

**Why `R0` keeps its parity.** Implementations must agree, because the choice changes the signature. Actual parity needs no flag and matches existing commitment formats.

**Why `k0` is deterministic.** Same-`rho` retries and a stateless device need the same `k0` each time. This rules out mixing device randomness into `k0`, which can help against physical side channels. A stateful variant is out of scope.

**Why V = W or -W.** Ordinary verification plus `x(W) mod n = r` also accepts a point whose x coordinate is `r + n`. Comparing points closes that case.

**Why low-s is required at the host.** ECDSA accepts both `(r, s)` and `(r, n - s)`, so allowing both gives a device one free bit per signature.

**Why failures count even when a retry succeeds.** A device can present a refusal as a disconnect. Counting by event costs an occasional warning after a real connection fault, and the warning says only that repeated failures can mean a malicious device.

**Why not deterministic signatures alone.** BIP 461 standardizes deterministic ECDSA so that two signers loaded with the same key can be compared. It detects deviation only on messages signed by both, and it covers ECDSA only. A signature made under this document includes host randomness, so it differs from a BIP 461 signature on the same message by design.

## Backward compatibility

This document adds a protocol and changes nothing for existing signers. A device that does not implement it fails or returns no commitment. The host MUST NOT fall back to ordinary signing without a separate user decision that discloses the loss of protection.

The messages have the same layout as the commitment form in bitcoin-core/secp256k1 pull request 1140 and in secp256k1-zkp as used by Blockstream Jade. The nonce derivation differs, so their nonce and signature bytes differ from this document's test vectors, and a host running the step 5 checks accepts their signatures.

A host cannot see which derivation a device uses, so it cannot enforce this document's derivation. That derivation is the one specified and the only one the proof covers. A device that keeps an older derivation MUST ensure that no ordinary signing interface lets a host supply `hc` as auxiliary or additional nonce data under the same key, because equal inputs can produce an equal base nonce.

## Reference implementation

Protocol arithmetic is in `reference/anti_exfil.py`. It is for reading and test generation, uses variable-time arithmetic and MUST NOT be used with real funds. C changes against the pinned libraries are in `c/`.

## Test vectors

`vectors/bip-anti-exfil.json` gives `sk`, `m`, `rho`, `pk`, `hc`, `R0_bytes` and `sig` for both schemes: odd and even `R0`, `P` and `W`, empty and long BIP340 messages, and tuples a host must reject. Failure cases such as `k0 = 0` cannot be reached with real hashes, so their vectors state the hash output a test must substitute.

## Security considerations

**What is proved.** `spec/security-argument.md` gives a game-based reduction in the random oracle model for one honestly generated key used only through this protocol, against a malicious host: a forgery on an unapproved message yields a forgery against plain BIP340 or ECDSA, with a loss factor of `q_s + 1` plus small statistical terms. No cryptographer has reviewed it and it has no whole-proof machine check, so it is a candidate and not an established result.

**What is not proved.** The proof does not cover goal 2, the concrete SHA-256 function, use of the same key with ordinary signing, either scheme under one key, or related keys such as a Taproot output key and its known-offset internal key or non-hardened BIP32 children. The reduction assumes plain ECDSA is unforgeable. The security argument has a candidate extension to related keys, which assumes unforgeability under related keys, for BIP340 and ECDSA, and that assumption is unproved.

**Against a malicious device.** The host checks the nonce point, not its derivation. A device can still choose `k0` freely, including from a backdoor secret, and that is why `rho` must stay secret: anyone who learns `rho` and `k0` can compute the key from a signature. With `rho` secret, Part 2 of the security argument, which is shorter and less reviewed, argues that published signatures depend on what the device holds only through which attempts it refuses, at most about 1.44 bits per expected failed attempt past the reveal. This excludes the user's reaction to failure, timing, and whether a signature is published at all. Counts held by separate hosts add, and a count limit only helps if it stays well below the length of the secret. `R0_bytes` is itself device-controlled output that the host sees, and it MUST NOT be forwarded. Refusals remain a channel, as described under Attempts and failures.

**Out of scope.** This protocol does not address key generation, physical attacks, timing or radio channels, or data a host forwards from the device. It covers single-signer signing only. Multi-party schemes such as MuSig2 and FROST are not covered. A signature made outside this protocol has no protection, so a single ordinary signature under a key can leak that key.

**Implementation.** `t`, `k0`, `k'`, the masked secret and intermediate hash states MUST NOT be logged or disclosed and SHOULD be erased after use. Parties SHOULD process `rho` and values derived from it in constant time. A signing library can leave such values on the stack, and a device concerned with memory readout has to clear them.

## Acknowledgements

The protocol follows the sign-to-contract variant of Scheme 6 in Pieter Wuille's 2020 overview of anti-covert-channel signing, which credits earlier work by Stepan Snigirev and Andrew Poelstra among others. Prior art includes True2F's firewalled ECDSA. Marko Bencun and Jonas Nick wrote the library implementation in pull request 1140.

## References

- Wuille, "Overview of anti-covert-channel signing techniques", bitcoin-dev, 2020-03-03: <https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-March/017667.html>
- Dark Skippy disclosure: <https://darkskippy.com/>
- BIP 461, Deterministic ECDSA Signatures: <https://github.com/bitcoin/bips/blob/master/bip-0461.md>
- "Non-interactive anti-exfil (airgap compatible)", Delving Bitcoin, 2024: <https://delvingbitcoin.org/t/non-interactive-anti-exfil-airgap-compatible/1081>
- bitcoin-core/secp256k1 pull request 1140: <https://github.com/bitcoin-core/secp256k1/pull/1140>
- Dauterman et al., "True2F: Backdoor-resistant authentication tokens", IEEE S&P 2019, section 4.4 of the full version: <https://arxiv.org/abs/1810.04660v4>
- BIP340, Schnorr Signatures for secp256k1: <https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>

## Copyright

This document is licensed under the MIT license. Its test vectors are available under CC0-1.0 or MIT, at your option.
