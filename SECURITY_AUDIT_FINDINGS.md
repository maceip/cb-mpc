# Security Audit Findings — cb-mpc Protocol and ZK Layers

## Finding 1: ECDSA-MP Missing Zero-Check on `r` Before Division

**File:** `src/cbmpc/protocol/ecdsa_mp.cpp`, lines 392-393, 444-445
**Severity:** Medium

### Description
In the multi-party ECDSA signing protocol, the signature's `r` component is derived as `R.get_x() % q` (line 393). Neither `r` nor `sum_rho_k` is checked for zero before being used in a modular division on line 445: `MODULO(q) s = sum_beta / sum_rho_k;`.

If `sum_rho_k == 0 mod q`, the modular inverse is undefined and OpenSSL's `BN_mod_inverse` may fail silently or produce incorrect results. Similarly, if `r == 0`, the resulting signature `(0, s)` is trivially forgeable since any `s` value would satisfy verification for any message.

### Attack Path
1. A malicious coalition of parties can manipulate their `rho_k` shares so that `sum_rho_k ≡ 0 mod q`.
2. The division `sum_beta / sum_rho_k` becomes undefined, leading to either a crash or an unpredictable `s` value.
3. Even without active manipulation, a negligible-but-nonzero probability natural occurrence would cause undefined behavior rather than a clean abort.

### Why Existing Mitigations Don't Prevent It
The ElGamal commitment proofs verify consistency of shares but do not enforce that the aggregate `rho * k` product is non-zero. The final `pub.verify(msg, sig)` check would catch an invalid signature but only for the sig_receiver; the protocol has already leaked intermediate values by that point.

---

## Finding 2: ECDSA-2P Missing Zero-Check on `r` Component

**File:** `src/cbmpc/protocol/ecdsa_2p.cpp`, lines 300, 337
**Severity:** Medium

### Description
In 2-party ECDSA signing, `r[i] = R[i].get_x() % q` is computed but never checked for `r == 0`. While astronomically unlikely with honest parties, a valid ECDSA signature requires `r != 0` and `s != 0`. If `r == 0`, the signature is invalid per the ECDSA specification and could leak information about the signing nonce.

### Attack Path
1. P2 computes `R[i] = k2[i] * R1[i]` and `r[i] = R[i].get_x() % q`.
2. If `r[i] == 0` (which can theoretically happen for curves where the x-coordinate of some point is a multiple of `q`), the Paillier ciphertext computation `c_key_tag * (k2_inv * r[i])` zeroes out the x_share contribution.
3. The resulting ciphertext `c[i]` sent to P1 would then encrypt only `k2_inv * m[i] + rho * q`, leaking no x_share info, but producing an invalid/trivially forgeable signature.

### Why Existing Mitigations Don't Prevent It
The final signature verification on P1's side (`ecc_verification_key.verify`) would catch this and return an error, but the protocol should abort cleanly before leaking the malformed ciphertext `c[i]` to P1.

---

## Finding 3: ECDSA-MP No Validation of `v_theta` from OT Receiver

**File:** `src/cbmpc/protocol/ecdsa_mp.cpp`, lines 247-260
**Severity:** Medium

### Description
In the OT-based multiplication protocol within ECDSA-MP signing, the OT receiver sends `v_theta._ij` and `seed._ij` to the OT sender (line 250-251). The sender uses `v_theta._j` directly at line 260 without any validation. A malicious receiver can send arbitrary `v_theta` values unrelated to the actual OT computation.

### Attack Path
1. A malicious OT receiver party `j` crafts `v_theta._ij` values that are unrelated to the actual inner product computation done with OT.
2. The sender `i` uses these directly to compute `s[ot_sender][j][t]`, which feeds into the multiplication products `rho_k_i` and `rho_x_i` (lines 276-288).
3. This introduces an additive error into the multiplication output, which propagates to the `beta` values and ultimately corrupts the signature.
4. While the final signature verification would catch this, it means a single malicious party can force repeated signing failures without being identified—a liveness denial-of-service.

### Why Existing Mitigations Don't Prevent It
The protocol includes ElGamal commitment proofs for `eRHO_K` and `eRHO_X` shares, and the `W_eRHO_K == Z_eRHO_K.R` check (line 398), which would detect inconsistency. However, these checks only apply to the aggregate shares and don't provide per-party attribution of the error to the malicious receiver. The protocol lacks identifiable abort for OT misbehavior.

---

## Finding 4: ECDSA-2P Refresh — P1 `x_share` Not Reduced Modulo `q`

**File:** `src/cbmpc/protocol/ecdsa_2p.cpp`, line 212
**Severity:** Medium

### Description
In the ECDSA-2P key refresh function, P1's new x_share is computed as `new_key.x_share = key.x_share + rho` (line 212) without a `MODULO(q)` operation, while P2's share IS computed with `MODULO(q)` (line 214). Over multiple refresh operations, P1's x_share can grow unboundedly as an integer.

### Attack Path
1. After multiple refresh operations, P1's x_share grows beyond `q` as an integer, even though it represents an element of Z_q.
2. This creates an inconsistency: The Paillier ciphertext `c_key` encrypts the unreduced integer, but the signing protocol's ZK proofs and range checks are designed for values in the range `[0, q)`.
3. Specifically, in the integer commitment ZK proof (`zk_ecdsa_sign_2pc_integer_commit_t`), the range checks on `w1_tag_tag` and `w2_tag_tag` (lines 537-538) bound values relative to `q`. If P1's x_share exceeds `q`, the prover cannot satisfy these range bounds, causing signing to fail.
4. A malicious P2 could intentionally trigger many refreshes to eventually cause P1's share to overflow the ZK range, making signing impossible—a targeted denial-of-service.

### Why Existing Mitigations Don't Prevent It
The Paillier `add_scalar` operates over integers mod N^2, not mod q, so the ciphertext update is mathematically correct at the Paillier level. But the higher-level protocol assumes x_share is in `[0, q)` for the ZK proofs. The absence of `MODULO(q)` on P1's side is intentional for Paillier consistency but creates a subtle range issue after repeated refreshes.

---

## Finding 5: Schnorr-2P Signing — P2 Sends Partial Signature `s2` in the Clear

**File:** `src/cbmpc/protocol/schnorr_2p.cpp`, lines 96-102
**Severity:** Medium

### Description
In 2-party Schnorr signing, P2 computes `s2[i] = e[i] * key.x_share + k2[i]` (line 98) and sends it to P1 in the clear (line 102: `job.p2_to_p1(s2)`). This partial signature contains P2's secret key share `x_share` blinded only by the nonce `k2[i]`.

If P1 is malicious and can observe P2's nonce commitment `R2[i]`, compute `k2[i]` (which it cannot since it only knows `R2[i] = k2[i] * G`), it could extract `x_share`. However, there is a more subtle issue: P1 learns `s2[i] = e[i] * x2 + k2[i]` for every signing operation. If P1 can orchestrate two signings with the same `k2` (nonce reuse), then `s2 - s2' = (e - e') * x2`, allowing P1 to compute `x2`.

### Attack Path
1. P1 attempts to force P2 to reuse a nonce. The protocol uses `bn_t::rand(q)` which should be resistant, but if the PRNG is weak or if P2's entropy source is compromised, nonce reuse becomes possible.
2. Given two partial signatures `s2 = e * x2 + k2` and `s2' = e' * x2 + k2` (same k2), P1 computes `x2 = (s2 - s2') / (e - e')`.
3. Combined with P1's own `x_share`, P1 now has the full secret key.

### Why Existing Mitigations Don't Prevent It
The commitment scheme ensures P1 commits to R1 before seeing R2, preventing P1 from adaptively choosing R1. But the protocol does not use any verifiable randomness to ensure P2's nonces are fresh across sessions. The security relies entirely on P2's local PRNG quality.

---

## Finding 6: HD ECDSA-2P Key Derivation — Paillier `c_key` Not Updated for Derived Keys

**File:** `src/cbmpc/protocol/hd_keyset_ecdsa_2p.cpp`, lines 162-174
**Severity:** High

### Description
In the HD ECDSA 2-party key derivation (`derive_keys`), the Paillier ciphertext `c_key` is copied directly from the root key (line 166: `derived_keys[i].c_key = bn_t(key.c_key)`). Since `c_key` encrypts P1's `x_share` under Paillier, and P1's `x_share` does NOT change for derived keys (line 173: `derived_keys[i].x_share = x_share`), while P2's share absorbs the derivation delta (line 171), this appears correct in the standard signing flow.

However, the derived key's `c_key` still encrypts the ROOT `x_share`, not a value specific to the derivation path. If the signing protocol ever validates that `c_key` encrypts a value consistent with the derived key's public key `Q_derived`, this check would fail. More critically, P2's signing ciphertext computation at `ecdsa_2p.cpp:317-318` computes `c_key_tag = key.paillier.elem(key.c_key) + (q << SEC_P_STAT)` and then `pai_c = (c_key_tag * (k2_inv * r[i])) + c_tag`. The `c_key` here encrypts x1_root, but the secret being signed with requires `x1_root + x2_derived = x_total_derived`. P2 accounts for the delta in its own share, so `c_tag` includes `k2_inv * x2_derived * r[i]` while the Paillier multiplication provides `k2_inv * x1_root * r[i]`. Together they yield `k2_inv * r[i] * (x1_root + x2_derived) = k2_inv * r[i] * x_derived`. So the signing protocol IS correct.

The real issue is that ALL derived keys for ALL derivation paths share the SAME `c_key` encrypting the same root P1 share. If the `c_key` value is ever exposed or compromised for one derived key, it immediately compromises ALL derived keys, violating the key isolation property expected from HD key derivation.

### Attack Path
1. An attacker compromises the encrypted backup or obtains the `c_key` ciphertext for any one derived key path.
2. Since all derived keys share the identical `c_key`, the attacker now has the root Paillier ciphertext.
3. Combined with a Paillier key compromise (which is a separate assumption), the attacker can decrypt to obtain `x1_root` and use it across all derivation paths.

### Why Existing Mitigations Don't Prevent It
The `c_key` sharing is not detected by the DKG verification because the value is functionally correct for signing. There is no per-derivation-path freshness or binding of the Paillier ciphertext.

---

## Finding 7: ECDSA-MP Signing — No Check That `K` Is Not the Point at Infinity

**File:** `src/cbmpc/protocol/ecdsa_mp.cpp`, line 391
**Severity:** Medium

### Description
After computing `K = SUM(K_i._js)` (the aggregate nonce point), the protocol computes `r = K.get_x() % q` (lines 392-393) without verifying that `K` is not the point at infinity. While individual `K_i` values are verified through `pi_K` proofs (line 388) to be well-formed, the aggregate sum could still theoretically be the point at infinity if a malicious party contributes a `K_i` that cancels others.

### Attack Path
1. A malicious party observes other parties' committed `K_j` values (after the commitment opening).
2. The party computes its own `K_i = -SUM(K_j for j != i)` to make the aggregate `K` the point at infinity.
3. However, the `pi_K` proof (elgamal_com_pub_share_equ_t) proves consistency between `K_i` and the ElGamal commitment `eK_i`, which was committed before seeing others' values. The commitment scheme prevents this adaptive choice.
4. Nonetheless, the lack of an explicit infinity check after aggregation means any implementation error in the commitment scheme could lead to `get_x()` returning undefined behavior on the identity point.

### Why Existing Mitigations Don't Prevent It
The commitment scheme and ZK proofs make this practically infeasible for a computationally bounded attacker. But defense-in-depth principles suggest an explicit check is warranted, especially since `ecc_point_t::get_x()` behavior on infinity is implementation-defined.

---

## Finding 8: `weak_agree_random` Functions Allow Adversarial Bias

**File:** `src/cbmpc/protocol/agree_random.cpp`, lines 39-75
**Severity:** Medium

### Description
Both `weak_agree_random_p1_first` and `weak_agree_random_p2_first` use a simple send-then-send pattern without commitments. The first sender transmits their random value in the clear, and the second sender can observe it before choosing their own value.

### Attack Path
1. In `weak_agree_random_p1_first`, P1 sends `rnd1` first (line 44).
2. P2 receives `rnd1` and can choose `rnd2` adversarially to bias the output `hash(rnd1, rnd2)`.
3. While the hash function provides some mixing, P2 can evaluate `hash(rnd1, rnd2)` for many candidate `rnd2` values and select one that produces a biased output.
4. This is used in `generate_sid_fixed_2p` (sid.h:14-16) to generate session IDs. A biased SID could weaken the security of protocols that rely on SID freshness.

### Why Existing Mitigations Don't Prevent It
The "weak" prefix acknowledges this limitation, and the hash output provides computational mixing. However, when used for SID generation via `generate_sid_fixed_2p`, this bias could allow an adversary to precompute proofs for predicted SIDs, reducing the effective security of Fischlin-transform-based ZK proofs that include the SID.

---

## Finding 9: DKG-MP Threshold Refresh — Missing ZK Proof Verification for Own Party Index

**File:** `src/cbmpc/protocol/ec_dkg.cpp`, lines 226-230
**Severity:** Low

### Description
In the key refresh protocol `key_share_mp_t::refresh`, when verifying ZK proofs for random values, the code at line 228 skips proof verification when `l == j` (`if (l == j) continue;`), meaning each party `j` doesn't prove knowledge of the discrete log of `R._j[j]` (the random value it generated for its own index). Only the discrete log consistency check at line 230 (`r._ji * G != R._j[i]`) validates `R._j[i]` for `i` being the current party.

### Attack Path
1. A malicious party `j` could provide a `R._j[j]` that is not a valid DL commitment. While the refresh protocol doesn't directly use `R._j[j]` in updating party `j`'s own share (since `delta_x` is computed for `j != i`), the value `R._j[j]` IS used in updating `Qis[j]` (line 247-252) for all parties, creating an inconsistency in the public share records.
2. After refresh, `new_key.Qis[j]` would contain an incorrect value, which could cause downstream verification failures in subsequent protocols.

### Why Existing Mitigations Don't Prevent It
The check at line 255 (`new_key.Qis[i] != new_key.x_share * G`) only validates the current party's own consistency. Cross-party consistency is checked at line 257 (`SUM(new_key.Qis) != current_key.Q`), which would catch an error in the total sum but not isolate which party caused it.

---

## Finding 10: PVE-AC Verify — Missing Curve Subgroup Checks on `Q` Points

**File:** `src/cbmpc/protocol/pve_ac.cpp`, lines 138-148
**Severity:** Low

### Description
In `ec_pve_ac_t::verify`, the Q points are checked for equality with stored values (lines 146-151) but individual `curve.check(Q[i])` is not performed. The code at lines 147-149 checks element-wise equality, and then checks `Q != this->Q` again at line 151 (redundant). However, there is no subgroup membership check on the input `Q` points. If the stored `this->Q` points were originally set by a malicious encryptor without validation, the verify function would accept them.

### Attack Path
This is a defense-in-depth issue. If `this->Q` was set from untrusted input during encryption without subgroup validation, subsequent verification would also accept non-subgroup points. However, the `encrypt` function does compute `Q[i] = x[i] * G` from scalars, so points set through normal encryption are always on the curve.

### Why Existing Mitigations Don't Prevent It
The encrypt function generates Q points from scalar multiplication, guaranteeing subgroup membership. But the verify function doesn't independently validate this, relying on the integrity of the stored data.
