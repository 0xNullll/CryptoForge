# tiny-crypto

```c
tiny-crypto/
├─ include/             # Public headers
│   ├─ crypto_config.h  # Config flags for enabling/disabling algorithms
│   ├─ demo_config.h
│   ├─ sha_commons.h    # (shared functions like padding, endian conversion)
│   ├─ sha1.h
│   ├─ sha2.h
│   ├─ sha3.h
│   ├─ keccak.h         # Raw Keccak functions
│   └─ hmac.h           # HMAC wrapper (can use any SHA)
│
├─ src/                 # Source files
│   └─ sha/             # SHA family folder
│       ├─ sha1.c
│       ├─ sha2.c
│       ├─ sha3.c
│       └─ keccak.c
│   └─ hmac.c           # HMAC implementation
│
├─ tests/
│   ├─ demo_sha.c       # Tests SHA1/2/3/Keccak
│   ├─ demo_hmac.c      # Tests HMAC using any SHA
│   └─ run_all_demos.c
├─ LICENSE
├─ README.md
└─ .gitignore
```