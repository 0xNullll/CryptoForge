# tiny-crypto Library

A modular, lightweight C crypto library including SHA variants, HMAC, and Keccak.

---

## Project Structure

Below is the directory layout of the project:

```c
tiny-crypto/
├─ include/ # Public headers
│  ├─ libs.h          # central include for standard C libraries and basic utilities
│  ├─ crypto_config.h # Configuration flags to enable/disable algorithms
│  ├─ demo_config.h   # Configuration for demo/testing files
│  ├─ sha_commons.h   # Shared SHA functions (padding, endian conversions, etc.)
│  ├─ sha1.h
│  ├─ sha2.h
│  ├─ sha3.h
│  ├─ keccak.h
│  └─ hmac.h
│
├─ src/ # Source files
│  └─ sha/ # SHA family implementation folder
│     ├─ sha1.c     
│     ├─ sha2.c
│     ├─ sha3.c
│     ├─ keccak.c
│     └─ README_SHA.md # Overview of SHA implementations
│  └─ hmac.c
│
├─ tests/ # Demo and test files
│  ├─ demo_sha.c      # Demo/test SHA-1/2/3 & Keccak
│  ├─ demo_hmac.c     # Demo/test HMAC using any SHA
│  └─ run_all_demos.c # Aggregate test runner for all demos
│
├─ LICENSE
├─ README.md
├─ .gitattributes
└─ .gitignore
```

---

## Sources

- [RFC 6234 – US Secure Hash Algorithms (SHA and SHA‑based HMAC and HKDF), May 2011](https://datatracker.ietf.org/doc/html/rfc6234)
- [FIPS PUB 202 – SHA‑3 Standard: Permutation-Based Hash and Extendable-Output Functions, August 2015](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

---

## License

This project is released under the **MIT License**. See `LICENSE` for full text.