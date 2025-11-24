# TinyCryptLib

A **modular, lightweight C crypto library** including SHA variants, HMAC, KMAC, and Keccak.  
Designed with **layered APIs** similar to OpenSSL, but smaller scale, where each API layer has its own prefix.

---

## Project Goals / TODO

### 1. Hashing
- [X] SHA-1  
- [X] SHA-224 / SHA-256 / SHA-512  
- [X] SHA3-224 / SHA3-256 / SHA3-512  
- [x] SHAKE / rawSHAKE  
- [ ] cSHAKE    
### 2. HMAC / KMAC
- [x] HMAC-SHA1  
- [x] HMAC-SHA2  
- [x] HMAC-SHA3  
- [ ] KMAC  

### 3. RNG / DRBG
- [ ] Fast PRNG (Xorshift128+, PCG)  
- [ ] SHA-based DRBG (crypto-secure)  
- [ ] seed from user/system  

### 4. Encoding / Decoding
- [ ] Hex encode/decode  
- [ ] Base64 encode/decode  
- [ ] Base32 encode/decode

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

1. **Low-level:** raw hash/HMAC/KMAC implementations → internal use  
2. **EVP layer:** dispatcher by enum/macro, supports streaming/piping and user-facing APIs

---

## Sources / References

- [RFC 6234 – US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF), May 2011](https://datatracker.ietf.org/doc/html/rfc6234)  
- [FIPS PUB 202 – SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions, August 2015](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)  
- [RFC 2104 – HMAC: Keyed-Hashing for Message Authentication, February 1997](https://www.rfc-editor.org/rfc/rfc2104)

---

## License

This project is released under the **MIT License**. See `LICENSE` for full text.