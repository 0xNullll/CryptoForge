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
- [x] **CMAC** - block-cipher based MAC, widely used with AES.
- [x] **GMAC** – Galois/Counter Mode based MAC for authenticated encryption.
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
- [x] **AES-GCM** – Galois/Counter Mode, AEAD with authentication tag
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
- [ ] **ChaCha20** – standard 256-bit key stream cipher with 20 rounds; fast and secure
- [ ] **ChaCha12** – reduced-round variant (12 rounds) for faster performance with slightly lower security
- [ ] **ChaCha8** – reduced-round variant (8 rounds); very fast but minimal security
- [ ] **XChaCha20** – extended-nonce (192-bit) variant of ChaCha20; prevents nonce reuse in long-lived streams
- [ ] **ChaCha20-Poly1305** – AEAD construction combining ChaCha20 stream cipher with Poly1305 MAC for authenticated encryption
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

### 10. Utilities / Helper Functions
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

### 11. Advanced Security & Hardening Features

These features go beyond initial correctness to protect the library against real-world misuse, adversarial inputs, and advanced attack scenarios.

- **Integrated AE Pipelines**
  - High-level authenticated encryption workflows
  - Combine cipher + MAC correctly (e.g. Encrypt-then-MAC)
  - Reduce API misuse by providing safe defaults
  - Optional: user-controlled low-level primitives remain exposed

- **EVP Stack-Only & Explicit Memory Ownership (Advanced)**
  - High-level API supports fully stack-based operation with caller-provided memory, avoiding any hidden malloc or OS dependencies
  - Suitable for bare-metal or highly constrained embedded systems where deterministic memory usage is required
  - Contexts require explicit memory ownership, enabling safe stack allocation and full zeroization
  - Alternate init paths and structs ensure auditable lifetimes and consistent behavior across embedded and standard environments

- **Runtime Legacy / Optional Feature Control**
  - Centralized configuration module tracks which algorithms or features are enabled at runtime
  - Weak or legacy algorithms (DES, MD5, etc.) are disabled by default and must be explicitly enabled
  - High-level API functions check this central configuration before executing
  - Supports safe opt-in for backward compatibility without compromising default security
  - Can be extended to track padding schemes, experimental primitives, or debugging hooks

- **Context Lifetime & Auto-Zeroing Policy**
  - Finalization functions securely wipe and invalidate cryptographic contexts by default
  - Advanced users may opt into “keep-state” APIs or per-context flags to disable automatic wiping
  - When keep-state is used, the caller is responsible for explicit context cleanup via provided free/wipe functions


- **Optional Debug / Audit Hooks**
  - Hooks can provide trace or memory audit features for development
  - Disabled in production builds to avoid exposing sensitive data
  - Supports testing and static analysis without compromising runtime security

- **Unified XOR Utility (Advanced)**
  - Provides a single function to XOR two buffers of arbitrary length
  - Handles alignment and architecture differences safely (e.g., 8-bit, 32-bit, 64-bit, or vectorized)
  - Enables optimized block operations (AES, CMAC, Poly1305, etc.) without duplicating code
  - Reduces risk of mistakes from manual loops or repeated byte-wise XORs
  - Can optionally include safe fallbacks for unaligned or small buffers

---

### 12. Fuzzing & Robustness Testing (Advanced)

Stress-test the library against malformed, adversarial, and unexpected inputs.

- **Coverage-guided fuzzing**
  - Target encoders/decoders, padding, MAC verification, AEAD APIs
  - Validate graceful failure (no crashes, no UB, no leaks)

- **Boundary & Limit Testing**
  - Extremely large inputs
  - Zero-length and near-limit buffers
  - Invalid IV, nonce, tag, and key sizes

- **Error-path fuzzing**
  - Ensure all error conditions are handled deterministically
  - No memory leaks or partial state exposure on failure

---

### 13. Reverse Engineering & Binary Analysis (Advanced)

Use the compiled library itself as a reverse-engineering target.

- **Self-RE practice**
  - Analyze compiled binaries to verify assumptions made in C
  - Ensure constant-time logic survives compiler optimizations
  - Inspect memory layout, call flow, and symbol boundaries

- **Compiler behavior validation**
  - Confirm secure zeroing is not optimized away
  - Validate constant-time comparisons at assembly level
  - Identify unexpected instruction patterns or data-dependent branches

---

### 14. Sandbox & Isolation Testing (Advanced)

Evaluate behavior under hostile or constrained execution environments.

- **VM-based testing**
  - Run under different OS versions and configurations
  - Simulate low-memory and restricted execution environments

- **Sandbox execution**
  - Test behavior under debuggers, emulators, and monitoring tools
  - Observe memory access patterns and failure modes

- **Crash containment**
  - Ensure failures do not corrupt external memory
  - Validate clean teardown and state reset after errors

---

## Directory Structure

```c
/CryptoForge
├─ /include
│   ├─ cf.h                 <-- umbrella header
│   ├─ cf_api/              <-- top-level API headers
│   ├─ utils/               <-- utility headers (mem, status, misc)
│   ├─ config/              <-- config headers (crypto_config, demo_config)
│   └─ crypto/              <-- all low-level crypto headers
├─ /crypto
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

2. **Facade  Layer / User-Facing Layer (`cf_*`)**
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