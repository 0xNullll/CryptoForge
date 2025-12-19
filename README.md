# CryptoForge

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

**Notes:** Hashes are required for HMACs, KMACs, and some DRBG constructions.

---

### 2. MACS
Message Authentication Codes ensure **data integrity and authenticity**.

- [x] **HMAC-SHA1** – simple MAC using SHA-1 (legacy).
- [x] **HMAC-SHA2** – widely used, secure.
- [x] **HMAC-SHA3** – newer design, resistant to length-extension attacks.
- [x] **KMAC** – SHA-3 based MAC, flexible key and output size.
- [x] **KMAC-XOF** – SHA-3 based MAC with extendable output, flexible key and output size.
- [ ] **CMAC** - block-cipher based MAC, widely used with AES.
- [ ] **GMAC** – Galois/Counter Mode based MAC for authenticated encryption.
- [ ] **Poly1305** - fast, one-time-key MAC, good for stream-like usage.
- [ ] **PBMAC1 (optional-advanced)** – password-based MAC: PBKDF2 + HMAC.

**Notes:** MACs are building blocks for authenticated encryption and secure RNGs.

---

### 3. Encoders/Decoders
Utilities for encoding and decoding data to facilitate testing and real-world usage.

- [x] **base16 UppererCase encode/decode** – standard RFC 3548 base16, common format for test vectors.
- [x] **base16 LowerCase encode/decode** – optional but common format for test vectors.
- [x] **Base32 encode/decode** – commonly used in applications such as TOTP for encoding binary data.
- [x] **Base32 no-padding encode/decode** – optional variant, often employed in TOTP and other systems where padding characters are omitted.
- [x] **Base64 encode/decode** (standard) – widely used in networking and data transfer.
- [x] **Base64 URL-safe encode/decode** – safe for URLs and filenames; optional padding.
- [x] **Base64 URL-safe no-padding encode/decode** – used in JWTs and query parameters.
- [x] **Base58 encode/decode** - Optional but recommended for “completeness”; crypto addresses, blockchain
- [x] **Base85 Ascii85 compact ASCII-safe encode/decode** – classic variant used in PostScript/PDF; supports 'z' shortcut for zero blocks.
- [x] **Base85 Z85 compact ASCII-safe encode/decodes** – modern variant used in ZeroMQ; fixed mapping, no padding, clean and safe for binary data.

---

### 4. Symmetric Ciphers
Provide **confidentiality** via block and stream ciphers.

#### Block Ciphers
- [x] **AES Core** – block cipher implementation (AES-128 / AES-192 / AES-256)
- [x] **AES-ECB** – basic block mode (testing only; insecure for real use)
- [x] **AES-CBC** – Cipher Block Chaining mode with padding support
- [ ] **AES-GCM** – Galois/Counter Mode, AEAD with authentication tag
- [ ] **AES-CCM** – Counter with CBC-MAC, AEAD mode for embedded systems
- [ ] **AES-XTS** – disk/sector encryption with tweak support
- [ ] **AES-KW (RFC 3394 / SP 800-38F)** – AES Key Wrap, fixed-length key wrapping
- [ ] **AES-KWP (RFC 5649 / SP 800-38F)** – AES Key Wrap with padding, arbitrary key lengths
- [ ] **AES-FF1** – Format-Preserving Encryption with Feistel network
- [ ] **AES-FF3 / FF3-1** – Optional FPE variant, faster and lighter
- [ ] **Blowfish** – classic 64-bit block cipher, symmetric key

#### Stream Ciphers
- [x] **AES-CTR** – Counter mode, stream-like, encryption = decryption
- [x] **AES-CFB8 & AES-CFB128** – Cipher Feedback mode (optional / legacy)
- [x] **AES-OFB8 & AES-OFB128** – Output Feedback mode (optional / legacy)
- [ ] **ChaCha20 (+ Poly1305)** – stream cipher with AEAD support
- [ ] **PBES2 (optional-advanced)** – PBKDF2 + AES encryption scheme for password-based encryption

---

### 5. Asymmetric Ciphers
Provide **key exchange, digital signatures, and encryption** using public/private key pairs.

- [ ] **RSA** – widely used for encryption and signatures; security depends on factoring large integers.
- [ ] **Elliptic Curve Cryptography (ECC / ECDSA / ECDH)** – smaller keys, efficient; used for signatures (ECDSA) and key exchange (ECDH).
- [ ] **EdDSA (Ed25519)** – modern signature scheme, fast and secure.
- [ ] **Diffie-Hellman (DH)** – key exchange protocol, establishes shared secret over insecure channels.

**Notes:** RSA and ECC more standard and most practical implementations. Using DH or ECDH for secure session key establishment.

---

### 6. Padding Utilities
Handle **block alignment** for block ciphers. Padding is a structural operation, not cryptography.

- [ ] **PKCS#7 Padding** – standard block padding used with AES-CBC and PBES2; appends `N` bytes of value `N`.
- [ ] **ISO/IEC 7816-4 Padding** – `0x80` followed by zero bytes; unambiguous and byte-oriented.
- [ ] **ANSI X9.23 Padding** – zero-filled padding ending with a length byte (legacy).
- [ ] **Zero Padding** – fills with `0x00`; unsafe when plaintext may end in zero bytes.
- [ ] **No Padding (Block-aligned)** – caller guarantees input length is a multiple of block size.

**Notes:**
- Padding is required only for block modes (ECB, CBC).
- Stream modes and AEAD modes do not use padding.
- PKCS#7 is the recommended default for general-purpose use.

---

### 7. RNG / DRBG
Random number generation for keys, nonces, and salts.

- [ ] **Fast PRNG (Xorshift128+, PCG)** – software-efficient, non-crypto use.
- [ ] **SHA-based DRBG** – cryptographically secure deterministic RNG.
- [ ] **Seed from user/system entropy** – ensure unpredictable input.

**Notes:** RNGs feed salts, nonces, and cryptographic keys. Secure seeding is critical.

---

### 8. Salts / Nonces
Stretch and derive keys securely. Turn passwords or shared secrets into cryptographically strong keys.

- [ ] **Salt generator (RNG)** – for hashing, KDFs, and MACs.
- [ ] **Nonce generator (RNG)** – for ciphers like AES-GCM or ChaCha20.

---

### 9. Key Derivation Functions (KDFs)
Stretch and derive keys securely.

- [ ] **scrypt** – memory-hard KDF designed to derive strong keys from low-entropy inputs
- [ ] **PBKDF2** – password-based key derivation using iterative hashing.
- [x] **HKDF** – modern extract+expand key derivation using HMAC.

---

### 10. Optional / Future Enhancements
- TRNGs (jitter, thermal noise, hardware-based) for high-quality entropy.
- Integrated authenticated encryption pipelines combining MACs and ciphers.
- EVP stack-only mode (optional/advanced) – alternate init and struct versions for fully stack-based operation without malloc or OS dependencies

---

### 11. Utilities / Helper Functions
Small, reusable helpers that make your library more **robust, convenient, and developer-friendly**.

- [ ] **Input normalization** – trim whitespace, remove null bytes, convert line endings.
- [ ] **Length calculation helpers** – compute required buffer size for encodings or cipher output.
- [ ] **Safe memory operations** – secure zeroing, constant-time comparison, copy helpers.
- [ ] **Validation helpers** – check input sizes, valid character ranges, or padding correctness.
- [ ] **Flexible padding helpers** – add/remove PKCS#7, zero padding, or custom padding schemes.
- [x] **Extended Base85 flags** – optional whitespace ignoring, ‘y’ extension, or fixed-length padding.
- [ ] **Debug / hex dump functions** – for printing binary data safely and clearly.
- [ ] **File I/O helpers** – load/save buffers safely for test vectors or demo purposes.
- [ ] **Vector testing utilities** – compare output against test vectors automatically.
- [ ] **Big-endian testing** – verify all algorithms produce correct outputs, simulate if hardware is little-endian

**Notes:** Utilities don’t add new crypto primitives but make the library **polished, safe, and easier to use** for demos, testing, or practical applications.

---

## Directory Structure

```c
/CryptoForge
├─ /config
│   ├─ crypto_config.h      <-- DLL/export, PREFIX_T, compile flags
│   └─ demo_config.h
├─ /crypto
│   ├─ /cipher
│   │   ├─ /aes
│   │   │   ├─ aes_core.{c,h}
│   │   │   ├─ ecb_mode.{c,h}
│   │   │   ├─ cbc_mode.{c,h}
│   │   │   ├─ cfb_mode.{c,h}
│   │   │   ├─ ofb_mode.{c,h}
│   │   │   └─ ctr_mode.{c,h}
│   │   └─ /chacha
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
│   ├─ /kdf
│   │   └─ hkdf.{c,h}
│   ├─ /enc
│   │   ├─ base16.{c,h}
│   │   ├─ base32.{c,h}
│   │   ├─ base64.{c,h}
│   │   ├─ base58.{c,h}
│   │   ├─ base64.{c,h}
│   │   └─ base85.{c,h}
│   └─ /evp
│       ├─ evp_defs.h
│       ├─ evp_flags.h
│       ├─ evp_hash.{c,h}
│       ├─ evp_mac.{c,h}
│       ├─ evp_kdf.{c,h}
│       └─ evp_enc.{c,h}
├─ /utils
│   ├─ mem.{c,h}        <-- secure memory helpers
│   ├─ misc_utils.h     <-- force_inline, generic macros
│   └─ cf_status.h
└─ /demo
    ├─ demo_hash.c
    ├─ demo_mac.c
    ├─ demo_kdf.c
    ├─ demo_enc.c
    └─ run_all_demos.c
```

---

## Layered API Design

1. **Low-level & Hybrid / Context Layer**
   - Implements atomic algorithms (SHAKE, AES, etc.) and builds higher-level contexts
   - Minimal internal helpers while also maintaining algorithm contexts (e.g., `ll_HMAC_CTX`, `ll_KMAC_CTX`)
   - Mixes multiple primitives safely and handles internal state and streaming
   - Fully deterministic, no user-facing key checks or policy enforcement
   - Some `ll_*` may call other lower-level `ll_*` functions

2. **Envelope Layer / User-Facing Layer (`evp_*`)**
   - Dispatcher by enum/macro for algorithm selection
   - Supports streaming, piping, and user-facing APIs
   - Enforces security policies (e.g., minimum key lengths)
   - Handles memory management and zeroization

---

## Sources / References
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

This project is released under the **GPL-3.0 License**. See '[LICENSE](LICENSE)' for full text.