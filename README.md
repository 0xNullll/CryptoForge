# TinyCryptLib

A **modular, lightweight C crypto library** including SHA variants, HMAC, KMAC, and Keccak.  
Designed with **layered APIs** similar to OpenSSL, but smaller scale, where each API layer has its own prefix.

---

## Project Goals / TODO

### 1. Hashing
Hash functions provide integrity and form the basis for MACs, KDFs, and RNGs.

- [x] **MD5** – legacy, fast but insecure.  
- [x] **SHA-1** – legacy, weak against collisions.  
- [x] **SHA-2** – SHA-224 / 256 / 384 / 512 / 512-224 / 512-256, widely used and secure.  
- [x] **SHA-3** – SHA3-224 / 256 / 384 / 512, sponge-based, resistant to length-extension.  
- [x] **SHAKE / rawSHAKE** – 128 / 256, extendable-output, flexible length.  
- [x] **cSHAKE** – 128 / 256, customizable for keyed or domain-specific hashing.

**Notes:** 
- Hashes are required for HMACs, KMACs, and some DRBG constructions.
---

### 2. MACS
Message Authentication Codes ensure **data integrity and authenticity**.

- [x] **HMAC-SHA1** – simple MAC using SHA-1 (legacy).
- [x] **HMAC-SHA2** – widely used, secure.
- [x] **HMAC-SHA3** – newer design, resistant to length-extension attacks.
- [x] **KMAC** – SHA-3 based MAC, flexible key and output size.
- [x] **KMAC-XOF** – SHA-3 based MAC with extendable output, flexible key and output size.
- [ ] **CMAC** - block-cipher based MAC, widely used with AES.

**Notes:** MACs are building blocks for authenticated encryption and secure RNGs.

---

### 3. Pre-Cipher Utilities
Utilities for encoding and decoding data to facilitate testing and real-world usage.

- [ ] **Hex encode/decode** – common format for test vectors.
- [ ] **Base64 encode/decode** – widely used in networking and data transfer.
- [ ] **Base32 encode/decode** – optional, used in protocols like TOTP.

**Notes:** Implement these before ciphers to simplify testing with RFC/NIST vectors.

---

### 4. Symmetric Ciphers
Provide **confidentiality** via block and stream ciphers.

- [ ] **AES (CBC / CTR / GCM / XTS)** – block cipher with multiple modes.
- [ ] **ChaCha20 (+ Poly1305)** – stream cipher, software-friendly, AEAD support with Poly1305.

**Notes:** Start with simple modes (CBC/CTR), then implement authenticated encryption (GCM/Poly1305).

---

### 5. RNG / DRBG
Random number generation for keys, nonces, and salts.

- [ ] **Fast PRNG (Xorshift128+, PCG)** – software-efficient, non-crypto use.
- [ ] **SHA-based DRBG** – cryptographically secure deterministic RNG.
- [ ] **Seed from user/system entropy** – ensure unpredictable input.

**Notes:** RNGs feed salts, nonces, and cryptographic keys. Secure seeding is critical.

---

### 6. Salts / Nonces
Stretch and derive keys securely. Turn passwords or shared secrets into cryptographically strong keys.

- [ ] **Salt generator (RNG)** – for hashing, KDFs, and MACs.
- [ ] **Nonce generator (RNG)** – for ciphers like AES-GCM or ChaCha20.

---

### 7. Key Derivation Functions (KDFs)
Stretch and derive keys securely.

- [ ] **scrypt** – memory-hard KDF designed to derive strong keys from low-entropy inputs
- [ ] **PBKDF2** – password-based key derivation using iterative hashing.
- [ ] **HKDF** – modern extract+expand key derivation using HMAC.

---

### 8. Padding Utilities
Required for block ciphers to handle plaintext not aligned to block size.

- [ ] **PKCS#7 padding** – standard padding scheme.
- [ ] **Zero padding** – simple, less recommended for variable-length messages.

---

### 9. Optional / Future Enhancements
- Additional AES modes (CFB, OFB, CCM) and ChaCha variants.
- TRNGs (jitter, thermal noise, hardware-based) for high-quality entropy.
- Unit tests using RFC/NIST test vectors.
- Integrated authenticated encryption pipelines combining MACs and ciphers.
---

## Directory Structure

```c
/TinyCryptLib
├─ /config
│   ├─ crypto_config.h      <-- DLL/export, PREFIX_T, compile flags
│   └─ demo_config.h
├─ /crypto
│   ├─ /hash
│   │   ├─ hash_common.h     <-- padding, endian helpers, round macros
│   │   ├─ /sha
│   │   │   ├─ sha1.{c,h}
│   │   │   ├─ sha256.{c,h}
│   │   │   ├─ sha512.{c,h}
│   │   │   └─ /keccak
│   │   │       ├─ sha3.{c,h}
│   │   │       ├─ keccak_core.{c,h}
│   │   │       └─ shake.{c,h}
│   │   ├─ /md
│   │   │   └─ md5.{c,h}
│   ├─ /mac
│   │   ├─ hmac.{c,h}
│   │   └─ kmac.{c,h}
│   └─ /evp
│       ├─ evp_defs.h
│       ├─ evp_flags.h
│       ├─ evp_hash.{c,h}
│       └─ evp_mac.{c,h}
├─ /utils
│   ├─ mem.h            <-- secure memory helpers
│   ├─ misc_utils.h     <-- force_inline, generic macros
│   └─ tclib_status.h
└─ /demo
    ├─ demo_hash.c
    ├─ demo_mac.c
    └─ run_all_demos.c
```

---

## Layered API Design

1. **Low-level:** raw implementations → internal use  
2. **EVP layer:** dispatcher by enum/macro, supports streaming/piping and user-facing APIs

---

## Sources / References

- [RFC 6234 – US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF), May 2011](https://datatracker.ietf.org/doc/html/rfc6234)
- [FIPS 202 – SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions, August 2015](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [RFC 2104 – HMAC: Keyed-Hashing for Message Authentication, February 1997](https://www.rfc-editor.org/rfc/rfc2104)
- [SP800-185 – SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, ParallelHash, August 2015](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)


---

## License

This project is released under the **MIT License**. See `LICENSE` for full text.