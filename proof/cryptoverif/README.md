# CryptoVerif 2.13 check of hops in the isolated-key proof

Result: `result.json` (verdict `OK`, 13 prover runs, 30 s).
Rerun everything, one prover at a time under the memory cap: `python3 -I proof/cryptoverif/check.py rerun.json`
(from the repo root; the argument names the output file, default `result.json`).

Reading the table: a proved model covers the model's abstractions only. The theorem is not machine checked as a whole.

| Theorem step | Status | Model and result |
|---|---|---|
| G0 to G1 hidden nonce table | machine checked in this model | `gb_bip340`, `gb_ecdsa`: G0 and G1 indistinguishable, no probability term, same as the theorem's exact inequality |
| Extraction (hit on a hidden input gives the key) | machine checked in this model | `ga_*`: 6 of 6 goals proved exactly (extraction soundness and completeness, shared-table agreement, repeats) |
| G1 to G2 base law, `beta`, `2/B` | by hand only | not expressible. `check.py` verifies the `beta` formula and `2/B` by exact enumeration on two toy moduli, not in CryptoVerif |
| G2 to G3 flags bad2, bad3, bad4 | partial | `gc_*`: each flag event proved improbable, with bounds in `result.json`. The identical-until-bad step itself is by hand |
| G3 to G4 exact resampling | by hand only | finite bijection |
| G4 to G4' ECDSA `K_good` | by hand only | counting argument, no model |
| G4 to G5 signature simulation | by hand only | `gd_*` fail, see below |
| Reserved message, `q_s + 1`, alias step, batches, multi-key | by hand only | no model |

CryptoVerif bounds (`D = qD + qO2`, `N = qO1 + qO2`; `|hc| = 2^256`, `|point|` stands for `n - 1`):
- bad2: `(2.5 qO2^2 + 1.5 qD^2 + 2 qO2 qD + qO1 qO2)/|hc| + (qT qO1 + qO2 qO1 + qT qO2 + qO2^2)/|point|`
- bad3: `(qD^2 + 2 qD qO2 + 3 qO2^2 + qO1 qD + qO1 qO2)/|hc| + the same |point| term`
- bad4: `(qD^2 + qD qO2 + 2 qO2^2 + qO1 qO2)/|hc| + the same |point| term`
- O2 never reaches an unresolved context (`gc_o2unres`): proved up to a similar bound.
Each CryptoVerif bound includes the collision terms it spends on the way, so it does not split like the theorem's. The `|hc|`
part dominates the theorem's `D(D-1)/2^257 + N D/2^256` coefficient by coefficient (the quadratic terms are about twice as large).
The `|point|` part is `N (T + qO2)/|point|`; the theorem has `N (T + N)/(n - 1)`. The extra `N qO1` counts addresses that G3
programs for O1 contexts, which the G2 table game does not contain.

How to read that comparison: CryptoVerif gives upper bounds, so it can confirm a written term only where its bound is no larger. It confirms the `|point|` part, and the cross terms of the `|hc|` part. It does not confirm the written constants on `qD^2` and `qO2^2`, where its bound is up to twice the theorem's; those remain a hand count of the birthday bound. A smaller CryptoVerif term would not have been an error either. The check requires only that each bound is proved. The comparison with the theorem's terms above was made by hand.

The `ga_*` models have no context cache. A model with one proves repeats only up to a spurious probability and does not prove
the hidden-versus-adversary agreement, because CryptoVerif cannot relate the cache to the table. The cache is redundant.

G4 to G5 (`gd_coupling`, `gd_xor_toy`, both not proved). CryptoVerif's DH macros give `exp(g, mult(a,b))` and have no
addition of exponents and no product of group elements. A builtin `commut_group` for both sides plus a homomorphism equation is
accepted, but there is no one-time-pad equivalence for an additive group (only `Xor`, exponent 2), so `(k0, u) -> (k0 + u, u)`
cannot be derived. Left by hand: the bijection on `Z_n*` x `Z_n` with `u != k'`, the sign draw `W = +-V`, `u` redrawn until
`uG != W`, the point-programming `H_point(ser33(W - uG) || rho) = u`, the low-s and even-y cases, infinity and `u_full >= n`.

`results/` holds CryptoVerif output for a related model with a direct-tagged nonce. That model is not in this tree.

Controls, all failed to prove as required: M1 (`m1_ga_nomask`, `m1_gb_nomask`, mask omitted) and M2 (`m2_gc_o2unres`, `hc` from the caller).

Assumptions: A1 `pubbytes` injective and `norm(tobytes(s)) = tobytes(s)` (BIP340 either-root test);
A2 `nin` injective constructor, `aux` and `hdata` opaque, `canonical(tobytes(s)) = true`, `xor(xor(x,y),y) = x`; A3 (G-D only)
`mulg` homomorphism; A4 on a key-test hit both G-B games return `leak(guess)` without touching a table (the `bad1` branch).
Left out of every model: concrete encodings and SHA-256, tag independence, full-digest and range rejection, infinity,
`u_full >= n`, ECDSA equations, low-s, even-y, `Sign_Rand`, the reduction. `R0` is a uniform element of an abstract type.
