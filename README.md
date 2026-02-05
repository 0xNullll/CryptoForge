# CryptoForge

A **modular, lightweight C crypto library** including SHA variants, HMAC, KMAC, and Keccak.  
Designed with **layered APIs** similar to OpenSSL, but smaller scale, where each API layer has its own prefix.

---

## Directory Structure

```c
/CryptoForge
├─ /include
│   ├─ /cf_api              <-- top-level API headers (includes the umbrella header file too)
│   ├─ /utils               <-- utility headers (mem, status, misc)
│   ├─ /config              <-- config headers (crypto_config, demo_config)
│   └─ /crypto              <-- all low-level crypto headers
├─ /crypto
│   ├─ /cf_api
│   ├─ /cipher
│   │   ├─ /aes
│   │   └─ /chacha
│   ├─ /hash
│   │   ├─ /sha
│   │   │   └─ /keccak
│   │   └─ /md
│   ├─ /mac
│   ├─ /kdf
│   └─ /enc
├─ /utils
├─ /config
└─ /demo
```

---

## Layered API Design

1. **Low-level & Hybrid / Context Layer**
   - Implements atomic algorithms (SHAKE, AES, etc.) and builds higher-level contexts
   - Minimal internal helpers while also maintaining algorithm contexts (e.g., `ll_HMAC_CTX`, `ll_KMAC_CTX`)
   - Mixes multiple primitives safely and handles internal state and streaming
   - Fully deterministic, no user-facing key checks or policy enforcement
   - Some `ll_*` may call other lower-level `ll_*` functions

2. **Facade Layer / User-Facing Layer (`cf_*`)**
   - Dispatcher by enum/macro for algorithm selection
   - Supports streaming, piping, and user-facing APIs
   - Enforces security policies (e.g., minimum key lengths)
   - Handles memory management and zeroization

---

## Security Disclaimer

This library is intended for educational, experimental, and embedded use.
It has not undergone formal verification or professional security audits.
Do not use for protecting high‑value secrets without independent review.

---

## Sources / References
- [RFC 2898 - PKCS #5: Password-Based Cryptography Specification Version 2.0, September 2000](https://datatracker.ietf.org/doc/html/rfc2898)
- [SP 800-38D – Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM), November 2007](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [SP 800-38B - Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication, May 2005](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf)
- [SP 800-38A – Recommendation for Block Cipher Modes of Operation: Methods and Techniques, December 2001](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
- [FIPS 197 – Advanced Encryption Standard (AES), November 2001](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [RFC 6234 – US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF), May 2011](https://datatracker.ietf.org/doc/html/rfc6234)
- [FIPS 202 – SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions, August 2015](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [RFC 2104 – HMAC: Keyed-Hashing for Message Authentication, February 1997](https://www.rfc-editor.org/rfc/rfc2104)
- [SP 800-185 – SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, ParallelHash, August 2015](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)
- [RFC 5869 – HMAC-based Extract-and-Expand Key Derivation Function (HKDF), May 2010](https://datatracker.ietf.org/doc/html/rfc5869)
- [RFC 4648 – The Base16, Base32, and Base64 Data Encodings, October 2006](https://datatracker.ietf.org/doc/html/rfc4648)
- [RFC 3548 – Base16, Base32, and Base64 Data Encodings, July 2003](https://datatracker.ietf.org/doc/html/rfc3548)
- [Ascii85 – ASCII/Base85 Binary‑to‑Text Encoding (btoa/Adobe/PDF/PostScript), circa 1990s](https://en.wikipedia.org/wiki/Ascii85)
- [RFC 32 – The Z85 (ZeroMQ Base85) Data Encoding, March 2010](https://rfc.zeromq.org/spec/32/)

---

## License

This project is released under the **MIT License**. See '[LICENSE](LICENSE)' for full text.