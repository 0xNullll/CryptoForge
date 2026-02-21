# CryptoForge

**CryptoForge** is a **modular, lightweight C cryptographic library** implementing SHA variants, HMAC, KMAC, Keccak, AES, ChaCha, AEAD constructions, KDFs, MACs, and encoding utilities.  

It is designed with **layered APIs**, separating low-level primitives (`ll_*`) from user-facing functions (`CF_*`), while remaining lightweight and portable.

CryptoForge is intended for **educational, experimental**. It has **not undergone formal audits**.  

---

## Directory Structure

```text
/CryptoForge
├─ /src
│   ├─ /crypto
│   │   ├─ /aead
│   │   │   ├─ /aes           <-- AES-GCM
│   │   │   └─ /chacha        <-- ChaCha20-Poly1305 and XChaCha20-Poly1305
│   │   ├─ /cf_api            <-- Public API implementations
│   │   ├─ /enc               <-- Base16/32/58/64/85 encoders
│   │   ├─ /hash
│   │   │   ├─ /md            <-- Legacy hashes (MD5)
│   │   │   └─ /sha
│   │   │       └─ /keccak    <-- SHA3 / Keccak / SHAKE
│   │   ├─ /kdf               <-- PBKDF2, HKDF
│   │   ├─ /mac               <-- HMAC, CMAC, GMAC, KMAC, Poly1305
│   │   └─ /cipher
│   │       ├─ /aes           <-- AES core + standard modes (ECB, CBC, CFB, OFB, CTR)
│   │       └─ /chacha        <-- ChaCha/XChaCha core + stream implementations
│   ├─ /include
│   │   ├─ /cf_api            <-- Public API headers (cf_*)
│   │   ├─ /crypto            <-- Internal crypto headers
│   │   ├─ /config            <-- Build/runtime configuration headers
│   │   └─ /utils             <-- Utility headers
│   ├─ /utils                 <-- Utility implementations (memory, misc helpers)
├─ /demo                      <-- Test programs and demos
├─ /vectors                   <-- Auto-generated test vector headers for cryptography validation
│   ├─ /NIST
│   │   └─ /KAT               <-- NIST Known Answer Tests (AES, SHA, etc.)
│   └─ /wycheproof            <-- Wycheproof tests for edge cases and subtle bugsand cross-verification
└─ LICENSE, README.md
```

---

## Layered API Design

1. **Low-Level / Context Layer (`ll_*`)**
   - Implements atomic primitives: AES, ChaCha, SHA family, SHAKE, HMAC, KMAC, PBKDF2, etc.  
   - Maintains deterministic state and supports streaming operations.  
   - Minimal internal helpers; some `ll_*` call other `ll_*` primitives.  
   - No user-facing checks or policy enforcement.  

2. **Facade / User-Facing Layer (`cf_*`)**
   - Dispatcher layer by enum/macro for algorithm selection.  
   - Supports streaming, pipelining, and memory-safe APIs.  
   - Enforces key sizes and nonce rules for AEAD.  
   - Handles zeroization, error codes, and resource management.  

---

## Main Features

### Symmetric Ciphers
- **AES:** ECB, CBC, CFB8, CFB128, OFB, CTR modes  
- **ChaCha / XChaCha:**  ChaCha8, ChaCha12, ChaCha20, XChaCha8 XChaCha12, XChaCha20  
- **AEAD Constructions:** AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305  

### Hash Functions
- **SHA family:** SHA-1, SHA-224, SHA-256, SHA-384, SHA-512  
- **SHA3 / Keccak:** SHA3-224/256/384/512, Keccak, rawSHAKE128/256, SHAKE128/256
- **cSHAKE** cSHAKE128/256
- **Legacy:** MD5

### Message Authentication Codes (MACs)
- HMAC, CMAC, GMAC, KMAC, KMAC-XOF, Poly1305  

### Key Derivation Functions (KDFs)
- PBKDF2, HKDF, KMAC-XOF

### Encoding / Decoding Utilities
- Base16, Base32, Base58, Base64, Base85

### Miscellaneous
- Modular, layered API for flexibility  
- Portable and lightweight, suitable for embedded targets  
- Configurable memory footprint via compile-time options  

---

## Security Disclaimer

CryptoForge prioritizes **clarity, correctness, and simplicity of implementation** over performance tuning or platform‑specific optimizations.

- The library is **purely software-based** and does **not** include hardware acceleration
 (e.g., AES-NI, NEON, AVX, or other CPU-specific optimizations).
- Implementations aim to be **as close as possible to their reference specifications**, favoring readability and auditability over aggressive micro-optimizations.
- Memory handling is designed to be **explicit and defensive**, using OS-provided memory helpers where appropriate, secure zeroization, and **constant-time comparisons** for sensitive operations.
- The API is intentionally designed to be **easy to use correctly**, with layered abstractions to reduce common misuse patterns.

However, **CryptoForge is not production-ready** at this stage:

- The library is intended for **educational and experimental use**.
- It has **not undergone formal security audits, third-party reviews, or certification** by recognized cryptographic authorities.
- Correctness and edge cases are currently verified using a combination of:
  - **Wycheproof test vectors**
  - **NIST KATs (Known Answer Tests)**
  - **NIST MCTs (Monte Carlo tests)**
  - Other internal or synthetic test suites  
  These cover different usage patterns, boundary conditions, and input scenarios.
- Side-channel resistance beyond basic constant-time logic  
  (e.g., cache, power, or microarchitectural attacks) has **not been formally evaluated**.
- The API surface and internal behavior may change as the project evolves.

**Do not use CryptoForge to protect sensitive, high-value, or real-world secrets** without  
independent review and additional hardening.

CryptoForge is best suited for:

- Learning cryptographic internals
- Studying algorithm behavior and design tradeoffs
- Experimentation, prototyping, and embedded research
- Security education and reverse-engineering practice

---

## Sources / References

### RFCs
- [RFC 32: The Z85 (ZeroMQ Base85) Data Encoding, March 2010](https://rfc.zeromq.org/spec/32/)
- [RFC 2104: HMAC: Keyed-Hashing for Message Authentication, February 1997](https://www.rfc-editor.org/rfc/rfc2104)
- [RFC 3548: Base16, Base32, and Base64 Data Encodings, July 2003](https://datatracker.ietf.org/doc/html/rfc3548)
- [RFC 4648: The Base16, Base32, and Base64 Data Encodings, October 2006](https://datatracker.ietf.org/doc/html/rfc4648)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF), May 2010](https://datatracker.ietf.org/doc/html/rfc5869)
- [RFC 6234: US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF), May 2011](https://datatracker.ietf.org/doc/html/rfc6234)
- [RFC 7539: ChaCha20 and Poly1305 for IETF Protocols, May 2015](https://datatracker.ietf.org/doc/html/rfc7539)
- [draft-arciszewski-xchacha-03: XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305, December 18, 2018](https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03)

### NIST
- [FIPS 197: Advanced Encryption Standard (AES), November 2001](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [FIPS 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions, August 2015](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [SP 800-38A: Recommendation for Block Cipher Modes of Operation: Methods and Techniques, December 2001](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
- [SP 800-38B: Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication, May 2005](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf)
- [SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM), November 2007](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [SP 800-185: SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, ParallelHash, August 2015](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)

### RSA Laboratories
- [PKCS #5: Password-Based Cryptography Specification Version 2.0, September 2000](https://datatracker.ietf.org/doc/html/rfc2898)

### Other / Misc
- [Ascii85: ASCII/Base85 Binary‑to‑Text Encoding (btoa/Adobe/PDF/PostScript), circa 1990s](https://en.wikipedia.org/wiki/Ascii85)

---

## License

This project is released under the **Apache-2.0 license**. See '[LICENSE](LICENSE)' for full text.