# SHA Module — Crypto Library

This folder contains all SHA-based cryptographic hash functions implemented in the library, including SHA-1, SHA-2, SHA-3, SHAKE, and Raw Keccak functions.  

The SHA module is designed to be **lightweight, self-contained, and portable**, providing both one-shot and incremental (streaming) APIs for flexibility in hashing data of any size. It also includes utilities for safe hash comparison and bit-level operations when using SHAKE or Raw Keccak.  

## Key Features

- **SHA-1/2 variants**: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256  
- **SHA-3 variants**: SHA3-224, SHA3-256, SHA3-384, SHA3-512  
- **SHAKE / XOF variants**: SHAKE128, SHAKE256  
- **Raw Keccak / Raw SHAKE** — always used internally by SHA-3 and SHAKE functions, but also available for direct use  
- Incremental (streaming) API: `Init`, `Absorb/Update`, `Final`, `Squeeze` (all return `bool`)  
- One-shot wrapper functions for convenience  
- **Safe hash comparison** with `CompareOrder` inline helpers  
- Automatic endianness handling  
- Lightweight and fast — suitable for embedded or performance-sensitive environments  

---

## Internal Dependencies

The headers handle internal dependencies automatically:

- SHA-224 → uses SHA-256 internally  
- SHA-384 → uses SHA-512 internally  
- SHA-512/224 and SHA-512/256 → use SHA-512 internally  
- SHA-3 and SHAKE variants → all use the internal Keccak permutation functions for processing  

---

## Organization

- `sha1.h/c`    — SHA-1 functions and context  
- `sha2.h/c`     — SHA-2 functions (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256)  
- `sha3.h/c`     — SHA-3 functions (224–512)  
- `shake.h/c`    — SHAKE128, SHAKE256, and Raw Keccak functions  
- `keccak.h/c`   — low-level Keccak permutation functions used internally by SHA-3, SHAKE, and Raw Keccak  
- `sha_common.h` — shared definitions and utilities  

This folder provides all building blocks needed for cryptographic hashing, whether for secure message digests, digital signatures, or low-level bitwise operations with Keccak.

---

## Usage Examples

### Wrapper / Single-Shot API

```c
#include <stdio.h>
#include "tiny_sha.h"

int main() {
    const char *msg = "Hello, Tiny SHA!";
    uint8_t hash[SHA256_DIGEST_SIZE];

    if (SHA256((const uint8_t*)msg, strlen(msg), hash)) {
        printf("SHA-256: ");
        for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    } else {
        printf("SHA-256 computation failed!\n");
    }

    return 0;
}
```

### Incremental / Streaming API

```c
#include <stdio.h>
#include "tiny_sha.h"

int main() {
    const char *msg = "Hello, Tiny SHA!";
    uint8_t hash[SHA256_DIGEST_SIZE];
    SHA256_CTX ctx;

    if (sha256_init(&ctx) &&
        sha256_update(&ctx, (const uint8_t*)msg, strlen(msg)) &&
        sha256_final(&ctx, hash)) {

        printf("SHA-256: ");
        for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    } else {
        printf("SHA-256 computation failed!\n");
    }

    return 0;
}
```

### Comparing Hash Digests

```c
uint8_t hash1[SHA256_DIGEST_SIZE];
uint8_t hash2[SHA256_DIGEST_SIZE];

// Compute hash1 and hash2...

int cmp = SHA256CompareOrder(hash1, hash2);
if (cmp == 0) {
    printf("Hashes are equal\n");
} else if (cmp < 0) {
    printf("hash1 < hash2\n");
} else {
    printf("hash1 > hash2\n");
}
```

---

## Output Sizes

| Algorithm      | Digest Size |
|----------------|-------------|
| SHA-1          | 20 bytes    |
| SHA-224        | 28 bytes    |
| SHA-256        | 32 bytes    |
| SHA-384        | 48 bytes    |
| SHA-512        | 64 bytes    |
| SHA-512/224    | 28 bytes    |
| SHA-512/256    | 32 bytes    |
| SHA3-224       | 28 bytes    |
| SHA3-256       | 32 bytes    |
| SHA3-384       | 48 bytes    |
| SHA3-512       | 64 bytes    |
| SHAKE128       | variable    |
| SHAKE256       | variable    |
| RawSHAKE128    | variable    |
| RawSHAKE256    | variable    |

---

## Notes

- SHA-3 functions correspond to SHA-2 operations:
  - `Init` (SHA-2) → `Init` (SHA-3)  
  - `Update` (SHA-2) → `Absorb` (SHA-3)  
  - `Final` (SHA-2) → `Final` / `Squeeze` (SHA-3)  
- One-shot wrapper functions follow the same style across all algorithms, ensuring a consistent API.  
- SHAKE and RawSHAKE functions support variable-length output for flexible bit-level operations.  
- The Raw Keccak API underlies all SHA-3 and SHAKE variants. While you normally use the SHA-3 or SHAKE wrappers, the Raw Keccak functions are available for advanced or bit-level use.
- Optional bit-level helpers (enabled with `ENABLE_SHAKE128`, `ENABLE_SHAKE256`, `ENABLE_RAWSHAKE128` or `ENABLE_RAWSHAKE256`):
  - `Trunc_s(X, Xlen, s, out)` — truncates a byte array `X` to the first `s` bits, storing the result in `out`.
  - `concat_bits(X, x_bits, Y, y_bits, out)` — concatenates `x_bits` from `X` and `y_bits` from `Y` into `out`.

---

## Sources

- [RFC 6234 – US Secure Hash Algorithms (SHA and SHA‑based HMAC and HKDF), May 2011](https://datatracker.ietf.org/doc/html/rfc6234)
- [FIPS PUB 202 – SHA‑3 Standard: Permutation-Based Hash and Extendable-Output Functions, August 2015](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

---

## License

This project is released under the **MIT License**. See `LICENSE` for full text.