# Security argument for anti-exfil signing

For `spec/bip-anti-exfil.md` and `spec/bip-anti-exfil-psbt.md`, version 0.16.

**Status.** No cryptographer has read this, and it has no whole-proof machine check. Treat every statement here as a candidate until a cryptographer has checked it. Nothing in this document says the protocol is secure.

## What this document claims

| Direction | Claim | Form | Largest gap |
|---|---|---|---|
| Malicious host | Forging on an unapproved message implies forging against plain BIP340 or ECDSA or extracting the key, losing a factor of `q_s + 1` plus small statistical terms | Game-based reduction, Part 1 | Part 1 covers isolated keys. Part 1b extends it to related keys under an assumption nobody has proved in this form. Ordinary signing under the same key is not covered |
| Malicious device | With `rho` secret, published signatures depend on what the device holds only through which attempts it refuses, at most about 1.44 bits per expected failed attempt past the reveal | Short argument, Part 2 | Only for someone who sees published signatures. Assumes the host follows the rules, `rho` never leaks, and what gets published does not change because of failures |

Part 1b is a candidate extension to related keys. Part 3 lists what none of these parts cover. Part 4 lists the supporting evidence and what each piece does not show.

## Part 1. Malicious host

`O1` is step 2 of the protocol and `O2` is step 4.

Section 4 of the proof covers batches on one key. That is the case a PSBT request with several pairs creates when those keys are independent. In practice, they usually are not. See Part 1b and Part 3.

### 1. Game

Fix one honestly generated key: `d` for ECDSA, normalized `d` for BIP340. `B = 2^256`.
Independent random oracles: `H_data`, `H_point`, `H_mask`, `H_nonce`, and `H_chal` for
BIP340 or `H_msg` for ECDSA. Each maps to 32 bytes. Modeling the ECDSA signing digest as `H_msg(M)` is
an assumption of this game. It is not a statement about Bitcoin sighashes.

A context is `c = (m, hc)`, with `m = M` for BIP340 and `m = H_msg(M)` for ECDSA.
`Base(c)` computes the nonce hash at the context's hidden input
`mask_input(d, hc) || pk || m || hc`. BIP340: `k0 = int(X) mod n`, fail if zero. ECDSA:
`k0 = int(X)`, fail if `k0 = 0` or `k0 >= n`.

- `O1(M, hc)`: return `ser33(k0 G)`, or failure.
- `O2(M, rho)`: `hc = H_data(rho)`, `R0 = k0 G`, `u_full = int(H_point(ser33(R0) || rho))`.
  Fail if base failed or `u_full >= n`. `k' = k0 + u_full`, fail if zero. `W = k' G`. Then
  BIP340 signs with `k = +-k'` so that `kG` has even y, and `e = H_chal(r || pk || m) mod n`.
  ECDSA computes `r = x(W) mod n` and `s = k'^-1 (z + r d)`, fails if `r = 0` or `s = 0`,
  and normalizes to low s.

Both oracles are deterministic functions of the key and tables. The device keeps no state,
so concurrency adds nothing: any interleaving is a sequence of these calls.

`F` makes at most `q_s` oracle calls and at most `T` queries to `H_point`. It wins by
outputting a valid `(M*, sig*)` such that no `O2` on `M*` returned a signature.

Fixed budgets, not random counts: `N` bounds distinct contexts, with `N <= q_s`. `D` bounds distinct inputs
evaluated under `H_data`, including evaluations inside `O2`. `T` bounds queries by `F` to `H_point`. `q_H` bounds all of `F`'s hash queries.

Comparison game: `B_adv` gets `pk`, the shared `H_chal` or `H_msg` table, and `Sign_Rand`,
which draws a fresh nonce on every call, including repeats. BIP340: uniform nonzero nonce,
even-y normalization. ECDSA: uniform in `K_good(M, d) = {k in 1..n-1 : r(k) != 0, s(k) != 0}`,
low-s normalized. `B_adv` wins with a valid signature on a byte message it never sent to
`Sign_Rand`. `Adv` is its winning probability.

### 2. Theorem

For every `F` there is a `B_adv` making at most `q_s + 1` signing queries, with expected run time
that of `F` plus simulation work and `O(q_H)` group operations for the extraction test, such that

    Pr[F wins] <= (q_s + 1) Adv(B_adv) + Delta

    Delta_BIP340 = D(D-1)/2^257 + N D/2^256 + N (T + N)/(n - 1) + N beta
    Delta_ECDSA  = D(D-1)/2^257 + N D/2^256 + N (T + N)/(n - 1) + 8 N / n

with `g = B - n` and `beta = (g-1)(n-g) / ((B-2)(n-1))`.

### 3. Proof

#### G0 to G1: hidden nonce table

G1 answers `Base` from a separate table for hidden inputs. The nonce payload encodes `(m, hc)`
injectively for a fixed key: the last 32 bytes are `hc`, which fixes the mask, and the fixed-width prefix
then leaves `m` (also checked in `proof/nonce_encoding.lean`). `bad1` is set if `F` ever queries
`H_nonce` on a payload whose first 32 bytes, xored with `H_mask` of its last 32 bytes, give a scalar `K`
with `K G = P`, or for BIP340 with `x(K G)` equal to `pk`, either sign root. Every hidden-input query sets `bad1`, whichever came first, query or context.
G0 and G1 are identical until `bad1`, so `Pr[win in G0] <= Pr[win or bad1 in G1]`. This is an
exact inequality with no probability term: `bad1` stays inside the event carried forward.

#### G1 to G2: base law (BIP340 only)

Keep the exact failure probability `2/B`. Given nonzero, replace the reduced hash with uniform
`Z_n*`. Values below `g` have two preimages and the rest one, which gives total variation
`beta` per context. Cost `N beta`. For ECDSA the valid-range output is already uniform on `Z_n*`.

#### G2 to G3: fresh sampling with flags

G3 evaluates each context atomically at its first touch.

A preimage of `hc` is *known* when `H_data` has been evaluated on an input giving `hc`, by `F` or inside `O2`.

- `bad2`: a new `H_data` output equals an earlier one for a different input.
- If `hc` has no known preimage at the touch, which only `O1` can do, the context is
  *unresolved*: sample the base outcome and return `R0`. `bad3`: a later `H_data` evaluation
  outputs an unresolved `hc`.
- Otherwise the context has a preimage `rho` and is *resolved*: sample the base
  outcome and `u_full` from fresh randomness, compute `R0`, and write `u_full` to the
  `H_point` address `ser33(R0) || rho`. `bad4`: that address was already defined. G3 still uses
  the fresh `u_full` internally.

After any flag is set, G3 continues with fresh randomness and no further constraint: after `bad2` the
first preimage stays the context's `rho`, and after `bad3` the context stays unresolved and any `O2` on it
uses fresh values. What it does then doesn't matter for the win event, since these hops only count runs
without a flag, but it must keep drawing fresh independent values so the bounds below stay valid in G3.
Without a flag, `O2` never reaches an unresolved context, because `O2` evaluates `H_data(rho)` first and a
match with an unresolved `hc` sets `bad3`.

From here on, let `E` be the event "win or `bad1`, and no flag among `bad2`, `bad3`, `bad4`". The fundamental
lemma gives `Pr[win or bad1 in G2] <= Pr[E in G3] + Pr[flag in G3]`. The later equalities are stated for `E`.
After a flag, `B_adv` stops and gives up, since it can't answer an `O2` on an unresolved context without `d`,
and those runs are already paid for by the flag terms.

G2 and G3 are identical until `bad2`, `bad3` or `bad4` (fundamental lemma of game playing).
In G3 every context's `(k0, u_full)` is independent of the whole history by construction, so
nothing below needs a conditional law over adaptive histories.

- `Pr[bad2] <= D(D-1)/2^257` by the birthday bound.
- `Pr[bad3] <= N D / 2^256`: each of `D` fresh outputs hits one of at most `N` values.
- `Pr[bad4] <= N (T + N)/(n - 1)`: `R0` is uniform on the `n - 1` non-infinity points and
  independent of the defined addresses, of which there are at most `T + N`.

#### G3 to G4: exact resampling, no cost

Replace the resolved-context sampling order by the following.

1. Base failure with its exact probability. If it fails, cache that.
2. With probability `(B - n)/B`: `u_full` uniform in `[n, B)`, `k0` uniform in `Z_n*`. `O2` fails.
3. Otherwise `k'` uniform in `Z_n`, then `u` uniform in `Z_n \ {k'}`, `k0 = k' - u`.

The map `(k0, u) -> (k0 + u, u)` is a bijection from `Z_n* x Z_n` onto `{(x, u) : u != x}`,
and both sides are uniform, so the law is unchanged. `k'` is uniform on `Z_n`, and the value
`k' = 0`, with probability `1/n`, is the exact failure branch, with `R0 = -uG` and `u != 0`.

#### G4 to G4' (ECDSA only): remove failures that need the key

Given `k' != 0`, replace uniform on `1..n-1` by uniform on `K_good(M, d)`, for every context.
At most 8 scalars are excluded: for a fixed residue `r`, an affine x is `r` or `r + n` when below
`p`, each x has at most two y values, and distinct nonce scalars give distinct points, so at most 4
scalars have that `r`. `r(k) = 0` is one residue. `s(k) = 0` means `r = -z/d mod n`, one residue. (On
secp256k1 x = 0 is not on the curve and x = n is, so the true count is at most 6, but 8 suffices.) The
total variation is `Pr[k' != 0]` times at most `8/(n-1)`, so at most `8/n` per context. Cost `8 N / n`. After this hop the only `O2` failure branches are base failure,
`u_full >= n` and `k' = 0`, each decided by a coin the simulator holds. Sampling from `K_good`
without `d` is possible: draw `k`, reject when `r(k) = 0` or when `zG + r(k)P` is infinity.

#### G4 to G5: signatures from the comparison signer, no cost

For a resolved context in branch 3 with `k' != 0`, on a non-reserved message, call
`Sign_Rand(M)` once per context and cache the result.

- BIP340: the signature determines the even-y nonce point `V`. A fair sign `b` gives `W = +-V`.
  `(V, b)` is uniform on all non-infinity points, the same law as `k' G`.
- ECDSA: `V = s^-1 (zG + rP)` with the low-s `s`. `K_good` is closed under negation, since
  `r(-k) = r(k)` and `s(-k) = -s(k)`, and low-s normalization picks one element of each pair. So
  `V` is uniform over one representative per pair, and a fair sign `b` gives `W = +-V` uniform
  on `K_good G`.

Draw `u` uniform in `Z_n` and redraw while `uG = W`, which is uniform on `Z_n` minus the unique
excluded scalar, without knowing that scalar. Set `R0 = W - uG` and program `u`. `O2` returns the
cached signature, which is the signature the real device computes for that `W` and `M`, since
each is unique for its scheme given `W`, the key and the message under the deterministic
signing rule. No `d` is used.

#### Reserved message and the reduction

`B_adv` guesses uniform `rho_g` in `1..q_s + 1`. For `rho_g <= q_s` it reserves the
`rho_g`-th distinct byte message in a protocol call. `rho_g = q_s + 1` reserves none. If fewer
distinct messages occur, nothing is reserved, so unused slots behave like the last slot.

Contexts on the reserved message and unresolved contexts stay concrete: `B_adv` holds `k0`, and for a
resolved reserved context also `u`, using the G4 or G4' sampling. Their failure branches are coins it holds. `O2` on a reserved
message aborts only if it would return a signature.

ECDSA aliases: contexts are keyed by the digest, and verification uses only `z`, so another byte message
could force a reserved context to sign. To stop that, `B_adv` stores `z` for every protocol message and
every `H_msg` query from the start, and checks them when it reserves and on every new evaluation. If a
byte message `M2 != M*` has the same `z` as the reserved `M*`, whichever appeared first, `B_adv` calls
`Sign_Rand(M2)`, or reuses a cached result, and outputs that signature on `M*`, which is valid and fresh.
This covers the same digest under two byte messages. It adds at most one signing query, and it ends the
run with a win. If the forgery message was in no protocol call, the same check applies at the forgery.

Extraction: `B_adv` tests each `H_nonce` query with the `bad1` test. On a match it holds `d`,
picks a byte message outside its signing queries, of which at most `q_s + 1` exist, signs it, and wins.

Independence of the guess: answer reserved `O2` calls with a helper that holds `d`. Reserved and
non-reserved contexts then give `F` exactly the same law, since each is an exact form of G4 or
G4'. So `F`'s complete view, including whether it wins, does not depend on `rho_g`. Every view with `bad1` or a win has at least one good value of `rho_g`:

- `F` wins: take `rho_g` naming `M*`, or the last slot if `M*` was in no protocol call. No reserved
  `O2` returned a signature, because a returned signature on `M*` would disqualify `F`. So no
  abort occurs, and `sig*` is a forgery for `B_adv` because `M*` never reached `Sign_Rand`.
- `bad1` without a win: take the last slot. Nothing is reserved, no abort can occur, and extraction wins.

Therefore `Pr[B_adv wins] >= Pr[E in G5] / (q_s + 1)`.

Signing queries: with a reserved message there are at most `q_s - 1` non-reserved contexts, plus at most one
alias query. With none reserved there are at most `q_s` contexts, plus at most one alias query. That gives at
most `q_s + 1`. The alias step relies on standard ECDSA verification reading the message only through `z`.

Combining the hops gives the theorem.

### 4. Corollary: batches on one key

A request with several pairs under one key, with whole-request failure, needs no new argument, provided
`q_s`, `N` and the slots count pairs, not requests. Failure is decided by coins fixed at first touch
without using a signature, so `B_adv` first checks every pair and then either returns all signatures or
none. A failed batch marks no message signed, so freshness is preserved.

For `K` independently generated keys, `B_adv` guesses which key `F` forges under, embeds its challenge key
there, generates the other keys itself and answers their oracles directly with them. `bad1` and the extraction
test apply to the challenge key only, and flags apply to all contexts. A forgery under any key is then bounded by
`K` times the single-key advantage, with `N`, `D` and `T` taken as totals over all keys because `H_data` and
`H_point` are shared.
Related keys are not covered.

### 5. Remark on Wagner and ROS style attacks

Those attacks get several signatures on one nonce against adversarially combined challenges. A host here
has real freedom: unlimited fresh `(m, rho)` trials on the first pass, knowledge of `W` before asking for
the second pass, and the choice of which contexts to open. That freedom doesn't give it the needed
structure, because `k0` is fixed by `(m, hc)` and `rho` by `hc` except under `bad2`, so each context has
one tweak, one `W` and one challenge. This remark carries no weight in the proof, which instead simulates
each context exactly from its own independent `Sign_Rand` call. The theorem is what rules these attacks
out, under its assumptions.

### 6. What this does not prove

- Concrete SHA-256. Tagged hashes are modeled as independent random oracles.
- Same-key use with ordinary signing, or earlier signatures under the same key. `Sign_Rand` cannot
  simulate deterministic signers.
- Related keys: Taproot tweaks, BIP32 children, or cross-scheme use.
- Plain ECDSA. Its randomized UF-CMA is an assumption here, not a derived result.
- Anything about the malicious-device direction, approval, or sighash semantics.

The factor `q_s + 1` is real. It comes from the unapproved first pass, which gives `F` a nonce point
on a message with no signature, so a concrete bound must account for it. `B_adv`'s redraws of `u` and of `K_good` scalars have
expected constant cost and fail with probability about `1/n` per draw, so its run time is an expected one.

## Part 1b. Related keys: candidate extension

Part 1 covers independently generated keys. Real wallets use one secret with many public offsets, through non-hardened BIP32 and Taproot. This part moves that gap to a stated assumption and does not remove it. Its proof steps are in `proof/related_key/related_key_theorem.md`. Its definitions needed correcting more than once, including two errors that made a comparison game trivially winnable, so more may remain.

**Statement.** Replace the comparison game by `RK-UF-CMA`: plain signing with fresh nonces under any allowed derivation, with a win being a valid signature on a pair of key and message never sent to the signing oracle. Then

    Pr[F wins] <= (q_s + 1) Adv_RK(B_adv) + Delta

with `Delta` as in Part 1, using totals over all keys. `q_s` counts every oracle call, including first passes, which need no approval.

**Which derivations.** The rule decides whether the game can be hard at all.

- BIP340: any public offset, named at any time, including negation. A key and its negation are one key under x-only encoding.
- ECDSA: non-negated offsets only, either in a set fixed before the first oracle call, or hash-derived through a random oracle. In multi-level BIP32 each edge is a random oracle on the parent key and index, and the public chain code is not modeled. Over PSBT a host can name a path but not an offset, so the hash-derived rule is the relevant one for what a device will sign, and the fixed rule describes an attacker aiming at keys already funded. Free offsets named after a signature or a first pass are excluded, because then `(r, s)` on `z` is valid on any `z2` under `P + a G` with `a = (z - z2) / r`, which takes one division and no secret.

Hardened children are not in the family. They are independent keys only where the HMAC is modeled as a random oracle.

**What the assumption rests on.** For BIP340, close results exist with key-prefixed challenges (Morita et al., 2015/1135; Bacho et al., 2026/2128), though neither models x-only keys or even-y normalization, and using the second for one signer is our reading. For plain ECDSA, the only result we found is Groth and Shoup (2021/1330), in the elliptic-curve generic group model. Nothing we found derives tweaked-key security from plain ECDSA unforgeability for Bitcoin's sighashes. Only some of these proofs were read in full.

**A real cost.** The first pass needs no approval and the host knows `rho`, so it learns `r` before anyone approves. For ECDSA this makes a cross-key attack cheaper than against plain signing. With `g` first passes and `K` fixed offsets, one hash tests `g K` targets `z - r_i a_j`, for about `n / (g K)` hashes against `n / (q K)` with `q` approved plain signatures. At `g = 2^40` and `K = 2^32` this leaves about `2^184` hashes, and total work is never below about `2^129`. The protocol keeps the first pass unapproved. BIP340 has no such transfer, and toy searches showed no such gain.

**Checks.** Exact small-group enumeration of the extension's algebra passes, and the free-win case above is demonstrated on secp256k1. Attempts at concrete attacks by a malicious host found none at real key sizes. Those attempts assume the hashes behave as random oracles. None of this establishes the assumption.

## Part 2. Malicious device

This part concerns an observer who sees published signatures and public transaction data, and who may know every secret the device holds, such as a backdoor key. That observer does not see the link between host and device. The argument is short and has had less review than Part 1.

**Assumptions.** The host follows the protocol. It draws each `rho` uniformly and independently, and keeps it from everyone but the device, including after signing. It computes `m` itself. It publishes only fields it rebuilds from `(r, s)` or `sig` and the expected sighash type, and it never forwards `R0_bytes`. What gets published, in what order and when does not depend on failures, which often will not hold, as the conditions below say. The device does not choose the message or the key. The tagged hashes are independent random oracles, and the device makes at most `q` queries to them.

### Claim A: one attempt

Fix everything the device holds, and let it choose `R0` however it likes, knowing `hc` but not `rho`.

1. Except with probability `q / 2^256` per pair, the device has not queried `H_data` on `rho` or `H_point` on `R0_bytes || rho` when it commits to `R0`.
2. In that case `H_point(R0_bytes || rho)` is a fresh uniform value at the moment `R0` is fixed. Given that it is below `n`, `t` is uniform on `Z_n`, so `W = R0 + t * G` is uniform on the group whatever `R0` was. The device learns `t` after the reveal, but by then `W` is fixed.
3. `W`, `pk` and `m` determine the only signature the host accepts:
   - BIP340: `r = x(W)`, and the verification equation fixes `s`.
   - ECDSA: `V = W` or `V = -W`, with `x(W) mod n = r`, and these give `s` and `n - s`. Low-s keeps one of them.
4. The host rebuilds the published fields from that signature, so encoding choices, extra fields and sighash bytes reach nobody.

So each attempt's `W` is uniform and independent of everything the device held when it fixed `R0`. The device learns `W` at the reveal and may then complete or refuse, and that choice may depend on `rho`, `R0`, its secrets and history. The published signature is a function of `W` and public data. All dependence on the device's secrets enters through which attempts it refuses, which is Claim B. The exceptions are item 1, summed over all attempts and pairs, and the branches where `t >= n` or `W` is infinity, with probabilities about `2^-128` and `1/n`, which end the attempt.

This is the reason for several rules in the specification: the two rounds (item 1), the `V = ±W` and low-s checks (item 3), and the rebuild rule (item 4). Removing any one of them reopens a channel.

### Claim B: refusals

A device cannot change a signature, but it can decide which attempts succeed. For each request, it can look at each candidate after the reveal and either complete or fail the attempt, which draws again with new `rho` values. Its choice can depend on its secret `S`, on earlier signatures, on candidates it rejected and on the candidate itself. A request with several pairs is one step here: `W_t` is the tuple of its nonce points, because a failure redraws them together, and a signature-by-signature count would miss information held between the pairs.

**Bound.** Let `f_t` be the number of failed attempts past the reveal before request `t` completes, and let `F` be their total. Let `P_S` be the law of the published sequence given `S`, and `U` the uniform law. Under the conditions listed below,

    I(S; published) <= average over S of D(P_S || U)
    D(P_S || U) = sum over t of E[ D(law of W_t given past and S || uniform) ]
                <= sum over t of E[ log2(1 + E[f_t | past, S]) ]
                <= E[F | S] / ln 2
    I(S; published) <= E[F] / ln 2

The third line holds because a device that accepts `W` with probability `p(W)` publishes `W` with density `p(W) / mean(p)` relative to uniform. That density is at most `1 / mean(p)`, and `1 / mean(p) = 1 + E[f_t]`. With hidden state, such as rejected candidates, the density at any `W` is still at most the expected number of attempts. The last line uses `log2(1 + x) <= x / ln 2`.

**What this says.**

- A device that never fails conveys nothing through signatures.
- The total is at most about `1.44` bits per expected failed attempt past the reveal, for requests that publish a signature. That limit is attained: with many possible secrets, each rejecting its own small set of candidates, the ratio approaches `1/ln 2`.
- A host that stops a request after `L` failures and publishes nothing adds one more outcome, and the per-failure rate above does not apply to it. A device can then exceed that rate. The outcome is one of `L + 1` candidates or nothing, so the leak for that request is at most `log2(L + 2)` bits, whatever the expected number of failures. A user who retries after that starts a new request, and its failures count too. This fits the known rejection-sampling figure: accepting one attempt in `2^b` takes about `2^b` tries and conveys `b` bits.
- The rate of `1` bit per failure at `f = 1` is not the worst case. A device that fails rarely does better per failure, because which signatures it chooses to fail also carries information. `proof/refusal_bound/` checks this exactly on small sets.

**Conditions.**

- **Counts held by separate hosts add.** The bound is over all failures everywhere. One host sees only its own, and a reset clears a number but not what has already leaked.
- **Failures must not change what gets published.** This is the most important condition. If a wallet bumps the fee on every retry, a device with `2^20` transactions can fail once, at a position it chooses, and an observer reads 20 bits from the fee rates. The same applies when a user changes coins or amounts because of a failure. The specification says a new attempt should carry the same transaction unless the user chooses otherwise, but it cannot stop users from reacting.
- **It is a bound on expected failures.** A particular run can be luckier for the device than its expected count. The bound limits information on average, which is how leakage is usually measured, but it does not say a given key is safe after a given number of failures.
- **Attempts count however they ended.** Same-`rho` retries give the same `W`, so they add nothing. An attempt abandoned before the reveal adds nothing, since the device has not seen `rho`. A completed attempt the user discards and repeats adds a candidate, and a device has some influence over that through its screen and its timing.
- **A decline can be induced.** A device can show a wrong screen so that the user declines. The specification therefore lets a host leave a decline uncounted only when the user says it had nothing to do with what the device showed. If users answer wrongly, those failures go uncounted.
- **Stalling and timing are separate.** A device can refuse a transaction entirely, or take longer to answer without failing at all. Whether and when something is published conveys information that this bound does not cover. A user may see a refusal, and is unlikely to notice a delay.
- **Secrets are short.** A 128-bit seed takes about 89 expected failures at the best rate. A count limit only helps if it stays well below that. A device that knows when large amounts are at stake can save its failures for those signatures.

### What breaks this part

- **`rho` leaks.** Anyone who learns `rho` and `k0` for one signature computes `k'` and then the key. A backdoored device can make `k0` known to its maker, so one leaked `rho` can reveal the key. This is why the specification forbids logging or storing `rho`, and why transports need separate analysis.
- **The host forwards `R0_bytes` or copies from a response.** Both are device-chosen data.
- **The device chose the key.** Nothing here addresses malicious key generation.
- **Any signature made outside this protocol.** It has no protection, and one is enough to leak a key.

## Part 3. What neither part covers

- **Related keys, in part.** Part 1b reduces related keys to `RK-UF-CMA` for the plain scheme and does not prove that assumption, for BIP340 with x-only keys or for ECDSA. It applies only to devices whose key use stays inside its rules. Taproot merkle roots supplied by a host fit the BIP340 rule. One key used under both schemes is not covered, and the PSBT document asks signers to avoid it: Pieter Wuille wrote to the bitcoin-dev list in February 2021 that no attacks across the two schemes are known, that there is probably no proof, and that creating one may be tricky. Most real PSBT signing relies on this part, so it remains the largest gap between the argument and practice.
- **Ordinary signing under the same key.** The comparison signer in the proof draws fresh randomness, so it cannot simulate deterministic signing. Earlier public signatures under the same key are also outside the game.
- **Concrete SHA-256.** Tagged hashes are modeled as independent random oracles.
- **Plain ECDSA.** Its unforgeability under randomized signing is assumed here. It is not derived from anything.
- **Sighash semantics and approval.** The game concerns signed bytes. It does not show that a user approved what they thought they approved, or that two transactions have different signature hashes.
- **Implementations.** Timing, power, faults, memory residue and physical attacks. The C checks on secrets ran on native builds, and they cover branches and dead memory. They are not timing or power measurements, and none ran on a device.
- **The channels Part 2 sets aside.** A user's or wallet's reaction to failures, whether a signature is published at all, and timing. Part 2's bound also holds only on average, not for a particular run.
- **Failure policy as enforced by real hosts.** The protocol rules can be modeled, but no test can show that users read warnings.

## Part 4. Supporting evidence

| Evidence | Where | Does not show |
|---|---|---|
| Exact checks of proof hops on small groups, with broken simulators detected | `proof/isolated_key/checks/` | Anything at full group size, or the adaptive argument as a whole |
| Nonce encoding injectivity in Lean, and finite results | `proof/` | The reduction. These are small lemmas |
| CryptoVerif run with three correspondences proved, and ProVerif symbolic traces | `proof/cryptoverif/results/`, `proof/proverif/results.txt` | Discrete-log hardness, probability or secp256k1 arithmetic. The models use ideal constructors |
| CryptoVerif: the nonce subgame, G0 to G1 as an equivalence, and the G2 to G3 flags, with bounds that confirm the written `n - 1` terms and reach the written `2^256` terms within a factor of 2. Broken controls fail to prove | `proof/cryptoverif/` | The theorem as a whole. G1 to G2, G3 to G4, G4 to G5, the reduction and the union bound stay by hand. CryptoVerif has no one-time pad for an additive group, so the signature simulation could not be expressed. The models use structured constructors, with no SHA-256, curve or signature equations |
| ProVerif: message order, replay across attempts and `rho` secrecy, with an honest device and with an attacker holding the device key. Broken models detected | `proof/proverif/` | The curve, hash strength, nonce bias, parsing, the user or the failure counter. Two of the order queries hold partly by the sequence of the code |
| Exact checks of the refusal bound on small finite sets, including hidden state, shared attempts and attaining the limit | `proof/refusal_bound/` | That the model describes the protocol. The bound is elementary, so passing is weak evidence |
| Backdoored signers against a conforming host, each limited as the argument predicts | `validation/backdoor/` | Only the strategies we thought of. Part 2 is the general statement, and it has less review |
| Exact small-group checks of the related-key extension, with broken models detected, and a free-win check on secp256k1 | `proof/related_key/` | The assumption in Part 1b, or security at real key sizes |
| Test vectors, checked by a second implementation, including cases that fail on only the check they name | `vectors/bip-anti-exfil.json` | Security. Generator and checker share an author |
