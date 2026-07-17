# Security Audit Findings — cb-mpc Cryptographic Library

**Date:** 2026-07-17
**Scope:** Targeted audit of specific source files for NEW cryptographic implementation vulnerabilities.

---

## Finding 1: Paillier `encrypt()` with private key skips coprimality check on randomness

**File:** `src/cbmpc/crypto/base_paillier.cpp`, lines 181–192
**Severity:** HIGH

### Description
In `paillier_t::encrypt(const bn_t& src, const bn_t& rand)`, when the caller has the private key (`has_private == true`), the code uses CRT-based exponentiation but **never validates** that `rand` is coprime to `N`. In contrast, when `has_private == false` (public-key-only path), `coprime(rand, N)` is checked via `cb_assert`.

```cpp
bn_t paillier_t::encrypt(const bn_t& src, const bn_t& rand) const {
  bn_t rn;
  if (has_private) {
    rn = crt_enc.compute_power(rand, NN);   // NO coprimality check
  } else {
    cb_assert(mod_t::coprime(rand, N) && "paillier_t::encrypt: rand and N are not coprime");
    MODULO(NN) rn = rand.pow(N);
  }
  // ...
}
```

### Attack Path
If an attacker can control or influence the `rand` parameter (e.g., through a fault injection, a compromised DRBG, or a protocol-level choice), they can pass a value that shares a factor with `N`. Since `N = p * q`, any `rand` that is a multiple of `p` or `q` will produce a ciphertext whose randomness component reveals the factorization of `N`. Specifically, `gcd(r^N mod N^2, N)` would reveal `p` or `q`, breaking the Paillier key entirely.

The same issue exists in `paillier_t::rerand()` at line 208–219: the private-key path skips the coprimality check.

### Why Existing Mitigations Don't Prevent It
The `cb_assert` only fires in the public-key path. The private-key CRT path relies on `bn_t::rand(N)` from `encrypt(const bn_t& src)` (line 164), but the two-argument `encrypt()` is a public API that can be called with arbitrary `rand`.

---

## Finding 2: `ossl_ecdsa_verify` and `ossl_ecdsa_sign` use hardcoded 65-byte buffer, crashes for P-384/P-521

**File:** `src/cbmpc/crypto/base_ecc.cpp`, lines 90–119 (verify) and 121–148 (sign)
**Severity:** HIGH

### Description
The `ossl_ecdsa_verify` function uses a fixed 65-byte buffer for the uncompressed point encoding:

```cpp
error_t ossl_ecdsa_verify(const EC_GROUP* group, EC_POINT* point, mem_t hash, mem_t signature) {
  uint8_t oct[65];
  cb_assert(EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, oct, 65, ...) > 0);
  // ...
  cb_assert(OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", oct, 65) > 0);
```

65 bytes is only correct for 256-bit curves (1 + 32 + 32 = 65). For P-384, the uncompressed point requires 97 bytes (1 + 48 + 48). For P-521, it requires 133 bytes (1 + 66 + 66).

Similarly, `crypto_ec_group_2_name` (line 79–88) only handles `NID_X9_62_prime256v1` and `NID_secp256k1`, returning `nullptr` for P-384 and P-521, which would cause `OSSL_PARAM_BLD_push_utf8_string` to receive a null pointer.

### Attack Path
If any code path calls `verify()` or `sign()` on an `ecurve_ossl_t` instance for P-384 or P-521, the 65-byte buffer overflows during `EC_POINT_point2oct`, writing past the stack buffer. This is a stack buffer overflow that can lead to code execution. Even without exploitation, the `cb_assert` would fire and crash the process, causing denial of service.

Note: This is distinct from the already-known "P-384/P-521 crash in base_ecc.cpp" which refers to a different issue. This finding specifically identifies a **stack buffer overflow** via the hardcoded 65-byte array in `ossl_ecdsa_verify`/`ossl_ecdsa_sign`.

### Why Existing Mitigations Don't Prevent It
There is no size check before calling `EC_POINT_point2oct`. The curve-dispatch mechanism does route P-384/P-521 through this code path (`ecurve_ossl_t::verify` calls `ossl_ecdsa_verify` directly at line 350).

---

## Finding 3: `hash_numbers_t::l` member is uninitialized — causes undefined behavior in `mod()`

**File:** `src/cbmpc/crypto/ro.h`, line 115; `src/cbmpc/crypto/ro.cpp`, lines 77–91
**Severity:** HIGH

### Description
The `hash_numbers_t` class has a private member `int l;` that is never initialized in the constructor. The constructor only calls `encode_and_update(args...)`:

```cpp
class hash_numbers_t : public hmac_state_t {
 public:
  template <typename... ARGS>
  hash_numbers_t(const ARGS&... args) {
    encode_and_update(args...);
  }
  hash_numbers_t& count(int l) {
    this->l = l;
    return *this;
  }
  // ...
 private:
  int l;  // UNINITIALIZED
};
```

If `mod()` is called without first calling `count()`, the uninitialized `l` is used in:

```cpp
std::vector<bn_t> hash_numbers_t::mod(const mod_t& p) {
  // ...
  buf_t t = drbg_sample_string(h, bytes_to_bits(bytes_per_value) * l);  // l is garbage
  std::vector<bn_t> r(l);  // l is garbage — unbounded allocation
  for (int i = 0; i < l; i++) { ... }
  // ...
}
```

### Attack Path
An uninitialized `l` can be any value. If negative, the `std::vector<bn_t> r(l)` constructor will throw (or wrap to a huge value). If a large positive value, this causes massive memory allocation and potential denial of service. In either case, the `drbg_sample_string` call with `bytes_to_bits(bytes_per_value) * l` using uninitialized `l` produces unpredictable DRBG output length, which could yield incorrect cryptographic results (e.g., truncated or wrong random oracle outputs) that silently compromise protocol security.

### Why Existing Mitigations Don't Prevent It
There is no default initializer on `l`, and the C++ standard does not zero-initialize non-static members of class type. The `count()` call is a fluent-API setter that callers can easily forget.

---

## Finding 4: `bn_cmp_ct` leaks `top` (number length) via loop bound — timing side channel

**File:** `src/cbmpc/crypto/base_bn.cpp`, lines 638–655
**Severity:** MEDIUM

### Description
The constant-time comparison function `bn_cmp_ct` computes `len = std::max(a.top, b.top)` and iterates from `len - 1` down to 0. While the loop body is constant-time, the **number of iterations** depends on the `top` fields of the operands, which encode the number of significant BN_ULONG words.

```cpp
static int bn_cmp_ct(const BIGNUM& a, const BIGNUM& b) {
  int len = std::max(a.top, b.top);  // Leaks max(a.top, b.top) via timing
  // ...
  for (int i = len - 1; i >= 0; i--) {
    xa = (i < a.top) ? a.d[i] : 0;  // Branch on a.top
    xb = (i < b.top) ? b.d[i] : 0;  // Branch on b.top
    // ...
  }
}
```

Additionally, the conditional expressions `(i < a.top) ? a.d[i] : 0` introduce data-dependent branches within the loop that reveal individual `top` values.

### Attack Path
An attacker performing timing measurements can determine the bit-length of secret values compared via `bn_cmp_ct`. Since `bn_t::compare()` (line 666–668) uses this function, all comparisons including range checks (`check_open_range`, `check_closed_range`, etc.) leak the approximate magnitude of secret operands. In protocols where secret shares or nonces are compared against bounds, this leaks partial information about those secrets.

### Why Existing Mitigations Don't Prevent It
The function is named `bn_cmp_ct` (constant-time) and is explicitly intended to avoid timing leaks, but the variable loop count and conditional memory access patterns undermine this goal. The `consttime_gt` helper function within the loop body is constant-time, but it cannot compensate for the variable-length iteration.

---

## Finding 5: Paillier `create_prv` does not validate that `N == p * q` or that p, q are prime

**File:** `src/cbmpc/crypto/base_paillier.cpp`, lines 99–105
**Severity:** MEDIUM

### Description
The `create_prv` method accepts externally-supplied `N`, `p`, and `q` without any validation:

```cpp
void paillier_t::create_prv(const bn_t& theN, const bn_t& theP, const bn_t& theQ) {
  N = mod_t(theN, /* multiplicative_dense */ true);
  p = theP;
  q = theQ;
  has_private = true;
  update_private();
}
```

There is no check that:
- `theN == theP * theQ`
- `theP` and `theQ` are prime
- `theP != theQ`
- `theP` and `theQ` have appropriate bit lengths

### Attack Path
In a protocol scenario where a party receives Paillier key components from a counterparty (e.g., during key resharing or threshold key generation), a malicious party can supply inconsistent values. If `N != p * q`, then `phi_N = (p-1)*(q-1)` is incorrect, and `inv_phi_N = N.inv(phi_N)` will produce a wrong value. Decryption then silently produces incorrect plaintexts. In an MPC protocol, this leads to corrupted computation outputs that pass syntactic checks but are semantically wrong, potentially allowing an adversary to manipulate protocol outcomes.

### Why Existing Mitigations Don't Prevent It
The `update_private()` function (lines 47–97) performs mathematical setup based on `p` and `q` but never validates them against `N`. The function trusts its inputs completely.

---

## Finding 6: Paillier `encrypt` with private key doesn't validate plaintext range

**File:** `src/cbmpc/crypto/base_paillier.cpp`, lines 181–192
**Severity:** MEDIUM

### Description
The `encrypt` function computes `src * N + 1` modulo `N^2`. For Paillier encryption to be correct, the plaintext `src` must be in the range `[0, N)`. However, there is no validation of `src` in either the public or private key paths:

```cpp
bn_t paillier_t::encrypt(const bn_t& src, const bn_t& rand) const {
  // ...
  MODULO(NN) rn *= src * N + 1;  // If src >= N, this wraps and produces invalid ciphertext
  return rn;
}
```

### Attack Path
If `src >= N` or `src < 0`, the encryption produces a ciphertext that does not correspond to the intended plaintext. Decryption will yield `src mod N`, not `src`. In MPC protocols that rely on Paillier for secret sharing or oblivious transfer, an attacker who can manipulate the plaintext input can cause silent truncation of values, leading to incorrect protocol outputs. This is particularly dangerous in two-party ECDSA signing where Paillier-encrypted values are used in share conversion.

### Why Existing Mitigations Don't Prevent It
Neither `encrypt()` overload checks the plaintext range. The caller is implicitly expected to ensure `0 <= src < N`, but this is not enforced.

---

## Finding 7: TDH2 `combine_additive` allows duplicate PIDs — double-counting partial decryptions

**File:** `src/cbmpc/crypto/tdh2.cpp`, lines 126–152
**Severity:** MEDIUM

### Description
In the `combine_additive` function, partial decryptions are iterated and their `Xi` values are summed into `V`. The PID is checked for range (`pid < 1 || pid > n`) but there is no check for duplicate PIDs:

```cpp
for (int i = 0; i < n; i++) {
    const partial_decryption_t& partial_decryption = partial_decryptions[i];
    int pid = partial_decryption.pid;
    if (pid < 1 || pid > n) return coinbase::error(E_CRYPTO);
    // No check: is pid already seen?
    if (rv = partial_decryption.check_partial_decryption_helper(Qi[pid - 1], ciphertext, curve)) return rv;
    V += partial_decryption.Xi;
}
```

### Attack Path
A malicious party can submit multiple partial decryptions with the same PID. Each will pass `check_partial_decryption_helper` (since it validates the ZK proof against the same public share `Qi[pid-1]`), and each `Xi` will be accumulated into `V`. With `n` identical partial decryptions from the same party (for PID `j`), `V = n * x_j * R1` instead of `sum(x_i * R1)`. The final decryption will fail (AES-GCM tag mismatch), causing denial of service. More subtly, if the attacker controls `n-1` slots and duplicates their own PID, they can force decryption failure even when holding a valid share, selectively blocking decryption.

### Why Existing Mitigations Don't Prevent It
The `check_partial_decryption_helper` validates each partial decryption individually (ZK proof of correct decryption share), but does not track which PIDs have already been processed. The only check is `pid < 1 || pid > n`, which allows repeated use of the same valid PID.

---

## Finding 8: DRBG uses only AES-128 (128-bit key), insufficient for 256-bit security targets

**File:** `src/cbmpc/crypto/drbg.cpp`, lines 5–10, 14–21
**Severity:** MEDIUM

### Description
The DRBG initialization uses a 16-byte (128-bit) AES key:

```cpp
void drbg_aes_ctr_t::init() {
  byte_t k[16] = {0};  // 128-bit key
  byte_t iv[16] = {0};
  ctr.init(mem_t(k, 16), iv);
}

void drbg_aes_ctr_t::init(mem_t s) {
  if (s.size == 32) {
    ctr.init(s.take(16), s.data + 16);  // Only first 16 bytes used as key
  } else {
    init();
    seed(s);
  }
}
```

Even when a 32-byte seed is provided, only the first 16 bytes become the AES key (the remaining 16 bytes are used as the IV). This means the DRBG provides at most 128 bits of security, regardless of the seed entropy.

### Attack Path
For curves and protocols targeting 256-bit security (e.g., operations involving P-521), the DRBG's 128-bit key limits the actual security to 128 bits. An attacker with ~2^128 computational resources could enumerate all possible DRBG states, predicting all "random" values generated by the DRBG. This affects all protocol randomness derived from the DRBG: nonces, shares, blinding factors, and commitments. The `seed()` method (line 23–27) also splits its 256-bit SHA-256 output as 128-bit key + 128-bit IV.

### Why Existing Mitigations Don't Prevent It
The `aes_ctr_t::init` method accepts `mem_t key` and dispatches to `cipher_aes_ctr(key.size)`, which would use AES-256 for a 32-byte key. But `drbg_aes_ctr_t` always passes exactly 16 bytes as the key, hardcoding AES-128.

---

## Finding 9: `lagrange_basis` (int-PID overload) has unchecked `BN_mod_inverse` — silent failure on zero denominator

**File:** `src/cbmpc/crypto/lagrange.cpp`, lines 53–65
**Severity:** MEDIUM

### Description
The `lagrange_basis` function with `std::vector<int>` PIDs calls `BN_mod_inverse` without checking its return value:

```cpp
bn_t lagrange_basis(const bn_t& x, const std::vector<int>& pids, int current, const mod_t& q) {
  bn_t numerator, denominator;
  lagrange_basis(x, pids, current, q, numerator, denominator);

  auto bn_ctx = bn_t::thread_local_storage_bn_ctx();
  const bn_t& mod = q.value();
  BN_mod_inverse(denominator, denominator, mod,
                 bn_ctx);  // Return value NOT checked!

  BN_mod_mul(numerator, numerator, denominator, mod,
             bn_ctx);  // Also unchecked
  return numerator;
}
```

Note: This is distinct from the already-known "Lagrange BN_mod_inverse unchecked in lagrange.cpp" which refers to a **different overload** (the `bn_t` PID version). This finding is about the `int` PID overload at lines 53–65, which has the same class of bug.

### Attack Path
If duplicate PIDs exist in the `pids` vector (which is not validated in this function), the denominator product becomes zero mod `q`. `BN_mod_inverse` returns NULL on failure (no inverse exists), and the `denominator` BIGNUM is left in an undefined state. The subsequent `BN_mod_mul` then operates on this corrupt value, producing an incorrect Lagrange coefficient. In a secret sharing reconstruction, this silently yields a wrong reconstructed secret, which in MPC protocols could allow an adversary to extract or manipulate private key shares.

### Why Existing Mitigations Don't Prevent It
There is a `cb_assert(pids[j] > 0)` in the helper function (line 29), but no check for duplicate PIDs. The `BN_mod_inverse` return value is discarded.

---

## Finding 10: `ecc_point_t::operator==` returns wrong result when only one pointer is null

**File:** `src/cbmpc/crypto/base_ecc.cpp`, lines 869–875
**Severity:** MEDIUM

### Description
The equality operator has a logic error in its null-pointer handling:

```cpp
bool ecc_point_t::operator==(const ecc_point_t& val) const {
  if (!ptr) return val.ptr == nullptr;   // If this->ptr is null, check if val.ptr is also null — CORRECT
  if (!val.ptr) return ptr != nullptr;   // If val.ptr is null but this->ptr is not null, returns TRUE — BUG
  // ...
}
```

On line 871: when `this->ptr` is non-null and `val.ptr` is null, the expression `ptr != nullptr` evaluates to `true`. This means a valid point compares equal to a null/uninitialized point.

### Attack Path
If any protocol code compares a received point against an expected point, and the received point was improperly deserialized (resulting in a null `ptr`), the comparison would incorrectly return `true`. In signature verification, public key validation, or commitment opening, this allows an attacker to pass a null/invalid point that is accepted as matching a valid expected point. For example, in TDH2's `check_partial_decryption_helper`, if `Xi` or `Qi` failed to deserialize properly, the equality comparisons used in proof verification could yield incorrect results.

### Why Existing Mitigations Don't Prevent It
The `curve.check()` function validates that a point is on the curve and non-infinity, which would catch null points in many code paths. However, the equality operator itself is broken and could be used in contexts where `curve.check()` is not called first.

---

## Summary

| # | File | Severity | Issue |
|---|------|----------|-------|
| 1 | base_paillier.cpp:183 | HIGH | Paillier encrypt with private key skips coprimality check on randomness |
| 2 | base_ecc.cpp:91 | HIGH | Hardcoded 65-byte buffer in ECDSA verify/sign overflows for P-384/P-521 |
| 3 | ro.h:115 | HIGH | `hash_numbers_t::l` uninitialized — UB in `mod()` |
| 4 | base_bn.cpp:638 | MEDIUM | `bn_cmp_ct` leaks operand length via variable loop count |
| 5 | base_paillier.cpp:99 | MEDIUM | `create_prv` doesn't validate N == p*q or primality |
| 6 | base_paillier.cpp:181 | MEDIUM | Paillier `encrypt` doesn't validate plaintext range |
| 7 | tdh2.cpp:140 | MEDIUM | `combine_additive` allows duplicate PIDs |
| 8 | drbg.cpp:5 | MEDIUM | DRBG hardcodes AES-128 (128-bit key), insufficient for 256-bit security |
| 9 | lagrange.cpp:59 | MEDIUM | `lagrange_basis` (int-PID overload) unchecked `BN_mod_inverse` |
| 10 | base_ecc.cpp:871 | MEDIUM | `operator==` returns true when comparing valid point with null point |
