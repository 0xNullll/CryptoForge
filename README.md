# TinyCryptLib

A **modular, lightweight C crypto library** including SHA variants, HMAC, KMAC, and Keccak.  
Designed with **layered APIs** similar to OpenSSL, but smaller scale, where each API layer has its own prefix.

---

## Project Goals / TODO

### 1. Hashing
- [X] SHA-1  
- [X] SHA-224 / SHA-256 / SHA-512  
- [X] SHA3-224 / SHA3-256 / SHA3-512  
- [X] Keccak (optional raw)

### 2. HMAC / KMAC
- [ ] HMAC-SHA1  
- [ ] HMAC-SHA2  
- [ ] HMAC-SHA3  

- [ ] KMAC
### 3. RNG / DRBG
- [ ] Fast PRNG (Xorshift128+, PCG)  
- [ ] SHA-based DRBG (crypto-secure)  
- [ ] Optional: seed from user/system  

### 4. Encoding / Decoding
- [ ] Hex encode/decode  
- [ ] Base64 encode/decode  
- [ ] Optional: Base32  

### 5. Salts / Nonces
- [ ] Salt generator (RNG)  
- [ ] Nonce generator (RNG)  

### 6. Optional / Future
- [ ] AES (CBC / CTR)  
- [ ] ChaCha20  
- [ ] PBKDF2 / HKDF  
- [ ] Padding utils (PKCS#7 / Zero)

---

## Directory Structure

```c
/TinyCryptLib
├─ /config
│   ├─ crypto_config.h    <-- library-level flags, DLL macros, PREFIX_T
│   └─ demo_config.h      <-- demo/test settings
├─ /crypto                  <-- implementation folder
│   ├─ /hash                <-- low-level hash algorithms   
│   │   ├─ hash_commons.h   <-- shared macros (padding, endian conversions)
│   │   ├─ /sha             <-- SHA family
│   │   │   ├─ sha1.c / sha1.h
│   │   │   ├─ sha256.c / sha256.h
│   │   │   ├─ sha512.c / sha512.h
│   │   │   └─ /keccak
│   │   │       ├─ sha3.c / sha3.h
│   │   │       ├─ keccak.c / keccak.h
│   │   │       └─ shake.c / shake.h
│   │   ├─ /md             <-- MD family
│   │   │   └─ md5.c / md5.h
│   ├─ /mac                <-- HMAC / KMAC implementations
│   │   ├─ hmac.c / hmac.h
│   │   └─ kmac.c / kmac.h
│   └─ /evp                <-- dispatcher / high-level wrappers
│       ├─ evp_defs.h
│       ├─ evp_flags.h
│       ├─ evp_status.h
│       ├─ evp_hash.c / evp_hash.h
│       └─ evp_mac.c / evp_mac.h
├─ /utils                  <-- helper functions
│   ├─ utils.c / utils.h
└─ /demo                   <-- demo/test programs
    ├─ demo_hash.c
    ├─ demo_mac.c
    └─ run_all_demos.c
```

---

## Layered API Design

1. **Low-level:** raw hash/HMAC/KMAC implementations → no prefix, internal use  
2. **EVP layer:** dispatcher by enum/macro, supports streaming/piping and user-facing APIs

---

## Sources / References

- [RFC 6234 – US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF), May 2011](https://datatracker.ietf.org/doc/html/rfc6234)  
- [FIPS PUB 202 – SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions, August 2015](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)  
- [RFC 2104 – HMAC: Keyed-Hashing for Message Authentication, February 1997](https://www.rfc-editor.org/rfc/rfc2104)

---

## License

This project is released under the **MIT License**. See `LICENSE` for full text.