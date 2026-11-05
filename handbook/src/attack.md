# How a device can leak its key

## Nonces

A Schnorr or ECDSA signature uses a secret number, the nonce, that the signer picks. Anyone who knows the nonce of one signature can compute the secret key from it. Two signatures whose nonces have a known relation give the key away in the same way.

So the signer has to keep its nonces secret. The trouble is that only the signer knows how it chose them.

## The attack

Suppose a device's firmware has been changed, at the factory, in the supply chain or by an update. Instead of random or properly derived nonces, it picks nonces the attacker can predict, or nonces that encode bits of the seed.

Every signature it makes is still valid. The transaction pays the right addresses and the wallet accepts it. Once it's on the chain, the attacker reads the signature and recovers the key. Nobody else can tell anything happened, and that includes the owner.

[Dark Skippy](https://darkskippy.com/) showed that a seed can leak in as few as two signatures this way.

## Checking signatures doesn't help

The wallet can check that a signature is valid, but a valid signature with a bad nonce looks the same as one with a good nonce. Deterministic nonces, such as RFC 6979 or [BIP 461](https://github.com/bitcoin/bips/blob/master/bip-0461.md), make a device checkable if you hold the same key somewhere else and sign the same message there. A watch-only wallet can't do that.

## What the host can do

The host, which is the wallet software the device talks to, can contribute randomness to the nonce:

1. The host commits to a random value without revealing it.
2. The device commits to its own nonce.
3. The host reveals its value, and the device signs with a nonce made from both.
4. The host checks that the final nonce really came from both.

The device chose its part before it saw the host's value, and it can't change it afterwards. So it can't steer the final nonce. The one thing left to it is refusing to finish, and the protocol makes refusals visible to the user. [The protocol](protocol.md) gives the exact steps.

This protects against a malicious device with an honest host. It doesn't help if the host is also compromised, and it doesn't cover physical attacks, timing or radio channels, or key generation.
