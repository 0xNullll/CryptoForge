# tiny-crypto Repository Layout

A modular, lightweight C crypto library including SHA variants, HMAC, and Keccak.

---

## Project Structure

Below is the directory layout of the project:

```c
tiny-crypto/
├─ include/ # Public headers
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
│     └─ keccak.c
│  └─ hmac.c
│
├─ tests/ # Demo and test files
│  ├─ demo_sha.c      # Demo/test SHA-1/2/3 & Keccak
│  ├─ demo_hmac.c     # Demo/test HMAC using any SHA
│  └─ run_all_demos.c # Aggregate test runner for all demos
│
├─ LICENSE
├─ README.md
└─ .gitignore
```

---

### Notes

- `include/` contains all **public headers** that your users or other projects would include.  
- `src/` contains **all implementation files**; the SHA family is grouped in its own subfolder.  
- `tests/` keeps your demos and testing separate from production code.  
- The `crypto_config.h` file centralizes **all feature flags** (enable/disable SHA variants, HMAC, Keccak core).  
- The `demo_config.h` file centralizes **all demo/testing flags**, allowing you to enable or disable specific demo files or test modules modifying the source.  
- The structure allows you to **easily extend** with new crypto algorithms or utilities in the future.
