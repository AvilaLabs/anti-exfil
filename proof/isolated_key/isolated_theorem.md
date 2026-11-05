# Isolated-key theorem for the malicious-host goal: candidate full proof

Status: written proof attempt for one narrow game.
Not checked by any cryptographer and not machine-checked as a whole.

Method: bad events are flags in identical-until-bad game hops, so no conditional law over adaptive
histories is needed, and each context's values are sampled exactly in an order that needs no key.

## 1. Game

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

## 2. Theorem

For every `F` there is a `B_adv` making at most `q_s + 1` signing queries, with expected run time
that of `F` plus simulation work and `O(q_H)` group operations for the extraction test, such that

    Pr[F wins] <= (q_s + 1) Adv(B_adv) + Delta

    Delta_BIP340 = D(D-1)/2^257 + N D/2^256 + N (T + N)/(n - 1) + N beta
    Delta_ECDSA  = D(D-1)/2^257 + N D/2^256 + N (T + N)/(n - 1) + 8 N / n

with `g = B - n` and `beta = (g-1)(n-g) / ((B-2)(n-1))`.

## 3. Proof

### G0 to G1: hidden nonce table

G1 answers `Base` from a separate table for hidden inputs. The nonce payload encodes `(m, hc)`
injectively for a fixed key: the last 32 bytes are `hc`, which fixes the mask, and the fixed-width prefix
then leaves `m` (also checked in `proof/nonce_encoding.lean`). `bad1` is set if `F` ever queries
`H_nonce` on a payload whose first 32 bytes, xored with `H_mask` of its last 32 bytes, give a scalar `K`
with `K G = P`, or for BIP340 with `x(K G)` equal to `pk`, either sign root. Every hidden-input query sets `bad1`, whichever came first, query or context.
G0 and G1 are identical until `bad1`, so `Pr[win in G0] <= Pr[win or bad1 in G1]`. This is an
exact inequality with no probability term: `bad1` stays inside the event carried forward.

### G1 to G2: base law (BIP340 only)

Keep the exact failure probability `2/B`. Given nonzero, replace the reduced hash with uniform
`Z_n*`. Values below `g` have two preimages and the rest one, which gives total variation
`beta` per context. Cost `N beta`. For ECDSA the valid-range output is already uniform on `Z_n*`.

### G2 to G3: fresh sampling with flags

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

### G3 to G4: exact resampling, no cost

Replace the resolved-context sampling order by the following.

1. Base failure with its exact probability. If it fails, cache that.
2. With probability `(B - n)/B`: `u_full` uniform in `[n, B)`, `k0` uniform in `Z_n*`. `O2` fails.
3. Otherwise `k'` uniform in `Z_n`, then `u` uniform in `Z_n \ {k'}`, `k0 = k' - u`.

The map `(k0, u) -> (k0 + u, u)` is a bijection from `Z_n* x Z_n` onto `{(x, u) : u != x}`,
and both sides are uniform, so the law is unchanged. `k'` is uniform on `Z_n`, and the value
`k' = 0`, with probability `1/n`, is the exact failure branch, with `R0 = -uG` and `u != 0`.

### G4 to G4' (ECDSA only): remove failures that need the key

Given `k' != 0`, replace uniform on `1..n-1` by uniform on `K_good(M, d)`, for every context.
At most 8 scalars are excluded: for a fixed residue `r`, an affine x is `r` or `r + n` when below
`p`, each x has at most two y values, and distinct nonce scalars give distinct points, so at most 4
scalars have that `r`. `r(k) = 0` is one residue. `s(k) = 0` means `r = -z/d mod n`, one residue. (On
secp256k1 x = 0 is not on the curve and x = n is, so the true count is at most 6, but 8 suffices.) The
total variation is `Pr[k' != 0]` times at most `8/(n-1)`, so at most `8/n` per context. Cost `8 N / n`. After this hop the only `O2` failure branches are base failure,
`u_full >= n` and `k' = 0`, each decided by a coin the simulator holds. Sampling from `K_good`
without `d` is possible: draw `k`, reject when `r(k) = 0` or when `zG + r(k)P` is infinity.

### G4 to G5: signatures from the comparison signer, no cost

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

### Reserved message and the reduction

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

## 4. Corollary: batches on one key

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

## 5. Remark on Wagner and ROS style attacks

Those attacks get several signatures on one nonce against adversarially combined challenges. A host here
has real freedom: unlimited fresh `(m, rho)` trials on the first pass, knowledge of `W` before asking for
the second pass, and the choice of which contexts to open. That freedom doesn't give it the needed
structure, because `k0` is fixed by `(m, hc)` and `rho` by `hc` except under `bad2`, so each context has
one tweak, one `W` and one challenge. This remark carries no weight in the proof, which instead simulates
each context exactly from its own independent `Sign_Rand` call. The theorem is what rules these attacks
out, under its assumptions.

## 6. What this does not prove

- Concrete SHA-256. Tagged hashes are modeled as independent random oracles.
- Same-key use with ordinary signing, or earlier signatures under the same key. `Sign_Rand` cannot
  simulate deterministic signers.
- Related keys: Taproot tweaks, BIP32 children, or cross-scheme use.
- Plain ECDSA. Its randomized UF-CMA is an assumption here, not a derived result.
- Anything about the malicious-device direction, approval, or sighash semantics.

The factor `q_s + 1` is real. It comes from the unapproved first pass, which gives `F` a nonce point
on a message with no signature, so a concrete bound must account for it. `B_adv`'s redraws of `u` and of `K_good` scalars have
expected constant cost and fail with probability about `1/n` per draw, so its run time is an expected one.
