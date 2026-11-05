# Related keys for the malicious-host goal: candidate extension

Status: candidate. Three reviews each found a problem in its definitions, so more may remain. Nobody with cryptography credentials has read it. It extends `proof/isolated_key/isolated_theorem.md`, cited here as the isolated-key proof, and it should be read next to that text.

Idea in one line: the anti-exfil layer needs no new kind of assumption, so what remains is the related-key security of the plain scheme, which BIP32 and Taproot already rely on. It still has a cost, because unapproved first passes count as signing queries, and for ECDSA that cost is concrete. See section 5.

## 1. Key family

`d` is one honestly generated secret with public key `P`. A **derivation** is a public affine map `phi = (sigma, tau)` with `sigma` in `{+1, -1}` and `tau` in `Z_n`, and `d_phi = sigma d + tau`, `P_phi = sigma P + tau G`. For BIP340 the signing secret is `d_phi` normalized to even y and the key is `x(P_phi)`. This covers non-hardened BIP32 children, including several levels, and Taproot output keys, where `sigma` comes from the public parity of the internal key.

**BIP340 key classes.** `(sigma, tau)` and `(-sigma, -tau)` give points `Q` and `-Q`, so the same x-only key and the same normalized secret, for every `d`. They are one signing key, not two. For BIP340, a key is the class of these two maps, identified by its x-only key, and contexts and freshness are indexed by class. Without this the comparison game is trivially won: one signature under `(1, 0)` verifies under `(-1, 0)`. ECDSA is unaffected, since its 33-byte keys for `Q` and `-Q` differ, and there each map is its own key.

Which derivations the adversary may use depends on the scheme, because the rule decides whether the comparison game can be hard at all. `K` is the number of distinct keys used.

- **BIP340, free rule.** Any `(sigma, tau)`, named at any time after seeing `P`. Real tweaks hash the public key and wallets derive children as they go, and the key prefix in the challenge is what makes free tweaks reasonable here.
- **ECDSA, fixed rule.** `F` outputs a set `Phi` of derivations after seeing `P` and before its first call to `O1` or `O2`, with `|Phi| = K`, and `B_adv` likewise before its first `Sign_Rand`. Every call and the forgery must use `phi` in `Phi`. A first pass counts here, because it shows the host `r` just as a signature would: naming an offset after a first pass allows the same free forgery as below. This models keys that matter to the attacker, such as addresses already funded.
- **ECDSA, hashed rule.** The adversary names identifiers at any time, and `tau` is the output of an independent random oracle on the identifier, shared by `F` and `B_adv`, as BIP32 does. In multi-level BIP32, `tau` is a sum of edge outputs, each a random oracle on the parent key and index, and the public chain code is not modeled. The attack costs below are unchanged, with the parent key as base. Over PSBT a host can name a path but not an offset, so this is the rule for what a device will sign. Freshness is on (key, message). Two identifiers with one `tau` are one key, which adds at most `q^2 / n` to `Delta`, for `q` queries to that oracle.
- **ECDSA uses `sigma = +1` only.** BIP32 never negates an ECDSA key. Negation is a BIP340 normalization. `Q` and `-Q` are distinct 33-byte keys but not independent: a signature on `z` under `Q` is valid on `-z` under `-Q`, with no dependence on `r`. A family holding both can be won by finding `M`, `M'` with `H(M) + H(M') = 0`, about `2^128` hashes, needing one signature and no first-pass advantage. Excluding them matches practice and keeps the costs below accurate.
- **ECDSA with free tweaks named after signing is excluded.** Given `(r, s)` on `z` under `P`, any digest `z2` and `a = (z - z2) / r` make `(r, s)` valid on `z2` under `P + a G`. One division gives a forgery on a message nobody signed, using no secret (`check_real_curve.py`). Under that rule `Adv_RK` is 1 and the theorem says nothing. The key `P + a G` is useless to an attacker unless someone funds it, but a game that counts it cannot express security.

Hardened children are not in `Phi`. Their tweak depends on the secret, so they are not public maps of `d`. Nor are keys from separate seeds, which the isolated-key proof's corollary covers.

**Coincidences and zero keys.** Suppose a new derivation gives a key equal to an earlier one's, where the two are not the same key as defined above. Then `sigma1 d + tau1 = ± (sigma2 d + tau2)` with the `d` coefficient equal to `±2`, since a zero coefficient forces the same map or the same class. So `d` is determined. Likewise `sigma P + tau G` at infinity gives `d = -sigma tau`. `B_adv` tests each named derivation against a table of keys so far, and either event goes to extraction. From now on, distinct keys have distinct key bytes and all `d_phi` are nonzero.

## 2. Games

**Protocol game.** As in the isolated-key proof, with each oracle also taking a derivation `phi` named by `F`: `O1(phi, M, hc)` and `O2(phi, M, rho)` run on `d_phi`, `pk_phi`. `F` may query the random oracles before naming any given derivation. A context is `c = (key of phi, m, hc)`. `Base(c)` computes the nonce hash at `mask_input(d_phi, hc) || pk_phi || m || hc`. `F` wins by outputting `(phi*, M*, sig*)` with `sig*` valid under `pk_phi*`, and no `O2` on `(key of phi*, M*)` having returned a signature. Freshness is per message and key, the stronger form.

**Comparison game `RK-UF-CMA`.** `B_adv` gets `P` and the shared `H_chal` or `H_msg` table, works under the same derivation rule as `F`, and has `Sign_Rand(phi, M)` for any `phi` that rule allows, with a fresh nonce on every call under `d_phi`, with the same law as in the isolated-key proof (uniform nonzero with even-y normalization for BIP340; uniform in `K_good(M, d_phi)`, low-s normalized, for ECDSA). It wins with a valid signature on `(phi*, M*)`, with that pair of key and message never sent to `Sign_Rand`. Write its winning probability as `Adv_RK`. This notion is an assumption here. Section 5 says what is known about it.

## 3. Theorem

For every `F` there is a `B_adv` making at most `q_s + 1` signing queries, with run time that of `F` plus simulation work, a table of keys for the coincidence test, and `O(q_H)` group operations for the extraction test, such that

    Pr[F wins] <= (q_s + 1) Adv_RK(B_adv) + Delta

with `Delta` exactly as in the isolated-key proof, where `N`, `D` and `T` are totals over all keys. `K` does not appear in `Delta` or in the factor in front. It appears in the run time and inside `Adv_RK`, which may itself degrade with `K`. As in the isolated-key proof, `q_s` counts all oracle calls, including first passes, which need no approval. `B_adv` spends a `Sign_Rand` query on each resolved first pass, so `q_s` must not be read as the number of signatures a user approved. Section 5 gives a concrete case.

## 4. Proof: what changes at each step of the isolated-key proof

**G0 to G1, hidden nonce table.** Payloads are injective in `(phi, m, hc)`: the last 32 bytes give `hc`, which fixes the mask, and the fixed-width `pk_phi` gives the key by the coincidence step, leaving `m`. `bad1` is set if `F` queries `H_nonce` on a payload whose key field is some `pk_phi` and whose first 32 bytes, xored with `H_mask` of its last 32 bytes, give a scalar `K'` with `K' G = P_phi` for that same `phi`, or for BIP340 with `x(K' G) = pk_phi`, either root. `B_adv` stores all `H_nonce` queries by key field and tests a stored query when its key is first named, since `F` may query before naming. A payload pairing one key's masked secret with another key's public key is not a hidden input for any context, so it is an ordinary query and cannot differ between the games. The rest is unchanged. It is exact, with no probability term, since `bad1` stays in the event carried forward.

**G1 to G2.** Per context, unchanged. Cost `N beta`, with `N` over all keys.

**G2 to G3.** `H_data` and `H_point` are shared across keys. `bad2` and `bad3` concern only `H_data` and `hc`, so they do not see `phi`. For `bad4`, the address is `ser33(R0) || rho`. Two contexts under different keys can share `rho`, but then each has its own uniform `R0`, and a match of addresses is a collision of uniform points, already counted by the bound `N (T + N) / (n - 1)` over all `N`. So the bounds carry over with totals. Each context's `(k0, u_full)` is independent of history by construction, as in the isolated-key proof.

**G3 to G4, resampling.** Per context, no key used. Unchanged.

**G4 to G4' (ECDSA).** Replace uniform on `1..n-1` by `K_good(M, d_phi)` for that context's key. The count of 8 excluded scalars holds for any fixed nonzero key: the residue `r = -z / d_phi` plays the same role. Cost `8 N / n`. Sampling needs only `P_phi`: reject when `r(k) = 0` or `z G + r(k) P_phi` is infinity.

**G4 to G5.** For a resolved context in branch 3 with `k' != 0`, on a non-reserved pair, call `Sign_Rand(phi, M)` once and cache it. The derivation of `V` is the isolated-key proof's, with `P_phi` in place of `P`, and the law matches since each context draws independently. Program `u` at `ser33(R0) || rho`, as in the isolated-key proof. No secret is used.

**Reserved pair and reduction.** `B_adv` guesses `rho_g` in `1..q_s + 1` and reserves the `rho_g`-th distinct pair `(phi, M)` in a protocol call, keyed by pair. Reserved contexts stay concrete.

**ECDSA aliases.** Contexts are keyed by `(phi, z)`. `B_adv` records `z` for every protocol message and every `H_msg` query, by byte message, as in the isolated-key proof. If a byte message `M2 != M*` has the same `z` as reserved `M*`, then `Sign_Rand(phi*, M2)` gives a valid signature on `(phi*, M*)`, which wins. This adds at most one query.

**The cross-key ECDSA relation.** An `(r, s)` on `z` under `P_phi` is valid on `z - r a` under `P_phi + a G`. This needs no special step here. `B_adv` never needs to detect it: if `F` uses it to forge, that forgery is a win against `RK-UF-CMA`, and the cost lands in `Adv_RK`. It does mean `Adv_RK` for ECDSA is not close to plain ECDSA without more assumptions on the hash. See section 5.

**Extraction.** On a `bad1` match, `B_adv` holds `d_phi` and computes `d = sigma (d_phi - tau)`, up to the BIP340 sign, which `P` settles. It signs a pair outside its queries and wins.

**Independence of the guess, signing query count, combining.** As in the isolated-key proof, with pairs in place of messages.

**Batches.** A request with several pairs, possibly under different keys, fails whole. the isolated-key proof's corollary carries over: `q_s`, `N` and slots count pairs.

## 5. What the assumption rests on

An AI agent checked the theorem statements below against each paper's text, using Wayback copies of the eprint versions and the Eurocrypt version of Groth and Shoup. I have not read the proofs myself. Bacho et al. (2026/2128) was read only as an eprint, so its published form, if any, should be rechecked, and parts of its proofs were not read line by line.

**BIP340.** No result I know of covers exactly this. Closest: Morita et al. (2015/1135) Theorem 3 and Corollary 1, Schnorr whose challenge hashes `(m, r, psi)`, with `psi` recomputed from the possibly tampered signing key, secure against affine tampering in the ROM under DL, with a square-root forking loss, and Bacho et al. (2026/2128) Theorem 1, Schnorr whose challenge hashes (derived key, R, message), with adversary-chosen tweaks in `Z_p` for signing and for the forgery, (derived key, message) freshness and fresh nonces, in the ROM and AGM under `l`-AOMDL with `l = 2 Q_MS + 1`. Neither is stated for x-only keys, even-y normalization or tagged hashes. Bacho's Theorem 1 is stated for the joint Schnorr and MuSig2 game and has no single-signer corollary. Taking `Q_MS = 0` gives `l = 1`, which is plain DL, so a single-signer reading looks straightforward, but it is our reading and it still needs the algebraic adversary. Morita's game verifies the forgery under the original key, so it is a related game and not this one. BIP340 states the related-key defense informally and cites 2015/1135 for it, and a footnote there sketches moving proofs to x-only keys by reencoding keys and negating the hash when the challenge key has odd y. BIP341 has no related-key statement. Wuille wrote in February 2021 of a belief that Schnorr-only related keys are secure because challenges commit to the key, and that a formal proof would be "still trivial to construct". I expect a reduction to go through. Neither he nor I have written one that I can cite. The review found no cross-key transfer other than the class in section 1: `(R, s)` to `(R, s + a e)` needs equal challenge hashes under different keys.

**ECDSA.** Weaker. Groth and Shoup (2021/1330) Theorem 2 is the only result found for plain ECDSA. Same shape: per-query tweak, fresh nonce, (message, tweak) freshness, forging tweak in a set fixed before the game. It is in the EC-GGM under hash assumptions, with a loss of `|E|`, and it warns of an attack when `|E|` nears `q^(1/2)`. Das et al. (2021/1287) Theorem 3.3 reduces to one-per-message UF-CMA of ECDSA, not plain UF-CMA, for a key-prefixed variant, with honestly random tweaks, one signature per (derived key, message), programmable random oracles, and a loss factor equal to the number of tweaks. Their introduction says plain UF-CMA of ECDSA "remains only a conjecture" in the plain random oracle model. Nothing found derives tweaked-key security from plain ECDSA UF-CMA for Bitcoin's sighashes. Our derivations may depend on `P` and are named during the game, and their Theorem 2 fixes its set in advance. For tweaks derived by hashing an identifier, their Section 6.1 drops the fixed set: freshness is on (message, identifier), the `|E|` factors become a 2sum term, at most `Q Q' / q` in the ROM, and collision resistance of the tweak hash is added. Their Appendix D shows the non-hardened BIP32 derivation, which hashes the master public key, is a public-use random oracle for a fixed master key. Their 2sum game has no key argument, so a tweak depending on a key chosen during the game is not covered. Fitting our derivations to this is our reading, not their result, and I have not done it. `Adv_RK` for ECDSA also has a concrete attack, and anti-exfil makes it cheaper than it is against plain signing. The first pass needs no approval and shows `R0`, and the host chose `rho`, so the host knows each `r_i` before the user approves anything. With `g` first passes and `K` fixed offsets, one hash of a message variant tests `g K` targets `z - r_i a_j`. On a hit, the host asks for the single approval it needs, on an innocuous `z`, and transfers that signature. Expected work is about `n / (g K)` hashes, `g` device calls and `g K` multiplications to build the targets, against `n / (q K)` hashes for plain signing with `q` approved signatures. These are costs for given `g` and `K`. Total work `g K + n / (g K)` is never below about `2^129`. On a 20-bit toy curve this took about 14 hashes with `g = 4096`, `K = 16` and one approval, against about 5000 for plain signing with `q = 16`, `K = 16` (12 runs each).

At secp256k1 size this is not close to a break: `g = 2^40` and `K = 2^32` leave about `2^184` hashes, and `g` is limited by device speed and `K` by funded addresses. Under the hashed rule the identifier is a second offline search, which is Groth and Shoup's 2sum term: about `2^128 / sqrt(g)` message hashes at best, but `2^128 sqrt(g)` multiplications to build the targets, so again at least about `2^129` total. That key is useful only if someone funds it, so the funded-address figure is the one that matters to a real attacker.

Results mean something only for `K` well below `2^128`. A set given implicitly, such as an arithmetic progression, needs no target table and costs about `n / K` tests of a first pass and hash pair.

BIP340 has no such map. `(R, s)` to `(R, s + a e)` needs an equal challenge hash under a different key, and each trial tests one target. The toy runs showed no `1 / (q K)` gain.

## 6. Remark: tweak timing

Bacho et al. report a polynomial ROS-type attack on two-round signing when a tweak is chosen after round 1. Here the host may call `O1` under one derivation and `O2` under another, but those are two unrelated contexts: `O2` recomputes the nonce from the derivation it is given, so its `k0` is that context's own, and its signature fails step 5 against the `R0` the host got earlier. Each context has one key, one `W` and one challenge.

A concrete combination of signatures across keys fails. It needs `sum lambda_i sigma_i e_i = sigma* e*`, where each `e_i` hashes its own `W_i`, each `rho_i` is committed before `R0_i` exists, and `e*` hashes a point that depends on the `lambda_i`. Related-key offsets only shift a public constant. It would work only if `W` or `pk` were left out of the challenge hash. That key prefix belongs to the base scheme, not to anti-exfil. The separation of nonces across keys comes from the whole nonce payload, including the masked secret, so the proof doesn't depend on `pk` in the nonce hash.

This needs one thing from the specification: the device must select `(d_phi, pk_phi)` from the request at both passes. The signing text has one `sk`, and the PSBT companion supplies the selection: its signer "looks up keys by identifier", and each pass handles the pairs named in that request.

## 7. What this does not prove

- That the comparison notion holds for BIP340 with x-only keys under the free rule, or for ECDSA with Bitcoin sighashes under the fixed or hashed rule.
- ECDSA children derived after signing, with tweaks an attacker does not control, sit between the two ECDSA rules. The hashed rule is the closer model, and it assumes the hash is a random oracle.
- Any bound on how `Adv_RK` falls with `K`.
- Use of one family under both schemes. Wuille wrote in February 2021 that no attacks are known across the two schemes, that there is probably no proof, and that creating one may be tricky.
- Hardened derivation, except as independent keys in a model where the HMAC is a random oracle.
- Ordinary signing under any key in the family, or earlier signatures under one.
- Concrete SHA-256, the malicious-device direction, approval and sighash semantics.
- Aggregated keys, which the specification refuses.
