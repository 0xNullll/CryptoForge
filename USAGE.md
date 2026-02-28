# CryptoForge Usage Guide

This document shows **minimal examples** and explains how to use the CryptoForge API in C programs.

> **Note:** This guide provides minimal examples for getting started. For **detailed information** about return codes, error handling, optional parameters, and full API documentation, see the header files in:
> `src/CryptoForge/include/cf_api/`
> Each header contains a **detailed description** for all public functions.

---

## Table of Contents

- [Symbols and Conventions](#symbols-and-conventions)
- [Main API Headers](#main-api-headers)
- [Encoders](#encoders)
- [Hash Functions](#hash-functions)
- [Message Authentication Codes (MACs)](#message-authentication-codes-macs)
- [Key Derivation Functions (KDFs)](#key-derivation-functions-kdfs)
- [Symmetric Ciphers](#symmetric-ciphers)
- [AEAD Constructions](#aead-constructions)
- [Utilities](#utilities)
- [Compilation and Linking](#compilation-and-linking)
- [Runtime Notes](#runtime-notes)

---

## Symbols and Conventions

To make examples clear, here is the following symbols and notation:

| Symbol | Meaning |
|--------|---------|
| `$` | Shell prompt / command line input (do **not** type `$`) |
| `[]` | Optional argument or flag |
| `{}` | Mandatory choice; select **one** of the options separated by `|` |
| `< >` | Placeholder for a value (e.g., `<file>`, `<directory>`) |
| `//` | Inline comment in C code |
| `CF_*` | Public CryptoForge API functions |

---

**Example:**

```c
#include <include/cf_hash.h>

int main(void) {
    CF_HASH_CTX ctx;
    const CF_HASH *hash = CF_Hash_GetByFlag(CF_SHA256);

    // Initialize hashing context
    CF_Hash_Init(&ctx, hash, NULL);

    // Hash some data
    const unsigned char data[] = "Hello, CryptoForge!";
    CF_Hash_Update(&ctx, data, sizeof(data) - 1);

    // Finalize and get digest
    unsigned char digest[CF_SHA256_DIGEST_SIZE];
    CF_Hash_Finish(&ctx, digest);

    return 0;
}
```

---

## Main API Headers

The CryptoForge library organizes its headers to provide a clean and modular API. Here's the overview of the main headers:

### 1. Umbrella Header

- **`cf.h`** – The main header. Including this automatically pulls in all high-level API headers (`cf_hash.h`, `cf_mac.h`, `cf_kdf.h`, `cf_cipher.h`, `cf_aead.h`, `cf_enc.h`, etc.) for convenience.

  ```c
  #include <cf.h>
  ```

### 2. Flags and Status Codes

- **`cf_flags.h`** – Contains all flags, enums, and constants used across the library.
- **`cf_status.h`** – Defines `CF_STATUS` return codes for all API functions.

  ```c
  #include <cf_flags.h>
  #include <cf_status.h>
  ```

> **Note:** Unlike normal API headers in `include/cf_api`, `cf_status.h` is in `include/utils` and handles status codes rather than API-specific flags.

### 3. Hash Functions

- **`cf_hash.h`** – Provides the `CF_HASH` API for SHA, SHA3, XOF, and cSHAKE variants.

  ```c
  #include <cf_hash.h>
  ```

### 4. Message Authentication Codes (MACs)

- **`cf_mac.h`** – Provides the `CF_MAC` API for HMAC, KMAC, AES-CMAC, AES-GMAC, and Poly1305.

  ```c
  #include <cf_mac.h>
  ```

### 5. Key Derivation Functions (KDFs)

- **`cf_kdf.h`** – Provides the `CF_KDF` API for HKDF, PBKDF2, and KMAC-XOF based derivation.

  ```c
  #include <cf_kdf.h>
  ```

### 6. Symmetric Ciphers

- **`cf_cipher.h`** – Provides the `CF_Cipher` API for AES, ChaCha, and XChaCha in block and stream modes.

  ```c
  #include <cf_cipher.h>
  ```

### 7. AEAD Constructions

- **`cf_aead.h`** – Provides the `CF_AEAD` API for authenticated encryption modes like AES-GCM and ChaCha20-Poly1305.

  ```c
  #include <cf_aead.h>
  ```

### 8. Encoders / Decoders

- **`cf_enc.h`** – Provides the `CF_ENCODER` API for Base16, Base32, Base58, Base64, Base85, Z85, and ASCII85 encoding/decoding.

  ```c
  #include <cf_enc.h>
  ```

### 9. Utilities

- **`cf_util.h`** – Provides helper functions and utilities used across modules.

  ```c
  #include <cf_util.h>
  ```

> **Tip:** For detailed usage examples, context structures, and optional parameters, refer to each header in the `include/cf_api/` directory.

---

## Encoders

This section provides a comprehensive reference for using the `CF_ENCODER` API. It focuses on practical usage, context management, encoding/decoding operations, and flag definitions, which are all defined in the [cf_enc.h](src/CryptoForge/include/cf_api/cf_enc.h) file.

---

### 1. Context Initialization

#### Stack Allocation (One-Shot Use)
```c
CF_ENCODER_CTX ctx;
CF_STATUS status = CF_Enc_Init(&ctx, CF_BASE64_STD_ENC, CF_BASE64_STD_DEC);
if (status != CF_SUCCESS) {
    // handle error
}
```

#### Heap Allocation (Reusable)
```c
CF_STATUS status;
CF_ENCODER_CTX *ctx = CF_Enc_InitAlloc(CF_BASE32_ENC | CF_BASE32_ENC_NOPAD, CF_BASE32_DEC, &status);
if (!ctx || status != CF_SUCCESS) {
    // handle allocation/init error
}
```

---

### 2. Encoding

#### One-Shot Encoding into Pre-Allocated Buffer
```c
uint8_t data[] = {0x01, 0x02, 0x03};
char out[16];
size_t out_len = sizeof(out);

CF_STATUS status = CF_Enc_Encode(&ctx, data, sizeof(data), out, &out_len);
if (status != CF_SUCCESS) {
    // handle error
}
```

#### Heap-Allocated Output
```c
size_t out_len;
CF_STATUS status;
char *encoded = CF_Enc_EncodeAlloc(&ctx, data, sizeof(data), &out_len, &status);
if (!encoded || status != CF_SUCCESS) {
    // handle error
}
free(encoded); // free when done
```

- `CF_Enc_EncodeRaw` and `CF_Enc_EncodeAllocRaw` accept `void*` input.

---

### 3. Decoding

#### Pre-Allocated Output
```c
char encoded[] = "AQID";
uint8_t decoded[3];
size_t decoded_len = sizeof(decoded);

CF_STATUS status = CF_Enc_Decode(&ctx, encoded, strlen(encoded), decoded, &decoded_len);
if (status != CF_SUCCESS) {
    // handle error
}
```

#### Heap-Allocated Output
```c
size_t decoded_len;
CF_STATUS status;
uint8_t *decoded = CF_Enc_DecodeAlloc(&ctx, encoded, strlen(encoded), &decoded_len, &status);
if (!decoded || status != CF_SUCCESS) {
    // handle error
}
free(decoded);
```

- Raw variants accept `void*` input buffers.

---

### 4. Context Management

- **Reset a context:**
```c
CF_Enc_Reset(&ctx);
```

- **Free heap-allocated context:**
```c
CF_Enc_Free(&ctx_ptr); // ctx_ptr is CF_ENCODER_CTX*
```

- **Clone context:**
```c
CF_ENCODER_CTX clone;
CF_Enc_CloneCtx(&clone, &ctx);

CF_ENCODER_CTX *clone_heap = CF_Enc_CloneCtxAlloc(&ctx, &status);
```

- **Validate context integrity:**
```c
CF_STATUS status = CF_Enc_ValidateCtx(&ctx);
```

---

### 5. Utility Functions

- **Get encoder name:**
```c
const char *name = CF_Enc_GetName(&ctx);
printf("Using encoder: %s\n", name);
```

- **Compute required buffer sizes:**
```c
size_t enc_len = CF_Enc_RequiredEncLen(CF_BASE64_STD_ENC, data_len);
size_t dec_len = CF_Enc_RequiredDecLen(CF_BASE64_STD_DEC, strlen(encoded));
```

- **Minimum block sizes:**
```c
size_t min_input  = CF_Enc_MinInput(&ctx);
size_t min_output = CF_Enc_MinOutput(&ctx);
```

- **Input validation (pre-decode check):**
```c
bool valid = CF_Enc_IsValidInput(CF_BASE64_STD_DEC, encoded, strlen(encoded));
```

---

### 6. Encoding/Decoding Flags

#### Base16 / Hex
| Variant | Flag | Notes |
|---------|------|-------|
| Uppercase Hex Encode | `CF_BASE16_UPPER` | `0-9, A-F` |
| Lowercase Hex Encode | `CF_BASE16_LOWER` | `0-9, a-f` |
| Decimal Only | `CF_BASE16_DEC` | Only `0-9` |

#### Base32
| Variant | Flag | Notes |
|---------|------|-------|
| Encode | `CF_BASE32_ENC` | Standard Base32 |
| Decode | `CF_BASE32_DEC` | Standard Base32 decoding |
| Encode No-Pad | `CF_BASE32_ENC_NOPAD` | Omits padding |
| Decode No-Pad | `CF_BASE32_DEC_NOPAD` | Accepts unpadded input |

#### Base58
| Variant | Flag | Notes |
|---------|------|-------|
| Encode | `CF_BASE58_ENC` | Bitcoin-style alphabet |
| Decode | `CF_BASE58_DEC` | Decodes Base58 strings |

#### Base64
| Variant | Flag | Notes |
|---------|------|-------|
| Std Encode | `CF_BASE64_STD_ENC` | `A-Z a-z 0-9 + /` |
| Std Decode | `CF_BASE64_STD_DEC` | Accepts standard Base64 |
| URL Encode | `CF_BASE64_URL_ENC` | `A-Z a-z 0-9 - _` |
| URL Decode | `CF_BASE64_URL_DEC` | Accepts URL-safe Base64 |
| Std Encode No-Pad | `CF_BASE64_NOPAD_ENC` | Omits `=` |
| Std Decode No-Pad | `CF_BASE64_NOPAD_DEC` | Accepts unpadded input |

#### Base85 / ASCII85 / Z85
| Variant | Flag | Notes |
|---------|------|-------|
| Std ASCII85 Encode | `CF_BASE85_STD_ENC` | Supports `'z'` compression |
| Std ASCII85 Decode | `CF_BASE85_STD_DEC` | Decodes `'z'` sequences |
| Extended ASCII85 Encode | `CF_BASE85_EXT_ENC` | Optional `'y'` compression |
| Extended ASCII85 Decode | `CF_BASE85_EXT_DEC` | Decodes `'y'` sequences |
| Z85 Encode | `CF_BASE85_Z85_ENC` | Z85 variant (no `z`/`y`) |
| Z85 Decode | `CF_BASE85_Z85_DEC` | Decodes Z85 input |
| Ignore Whitespace | `CF_BASE85_IGNORE_WS` | Skip spaces/newlines when decoding |

> **Note:** All encoding/decoding flags shown above are defined in the [cf_flags.h](src/CryptoForge/include/cf_api/cf_flags.h) file (`CF_ENCODING_FLAGS`).

---

### 7. Example Full Flow
```c
CF_STATUS status;
CF_ENCODER_CTX *ctx = CF_Enc_InitAlloc(CF_BASE64_STD_ENC, CF_BASE64_STD_DEC, &status);

uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
size_t out_len;
char *encoded = CF_Enc_EncodeAlloc(ctx, data, sizeof(data), &out_len, &status);

if (encoded && status == CF_SUCCESS) {
    printf("Encoded: %.*s\n", (int)out_len, encoded);

    size_t decoded_len;
    uint8_t *decoded = CF_Enc_DecodeAlloc(ctx, encoded, out_len, &decoded_len, &status);

    if (decoded && status == CF_SUCCESS) {
        // decoded contains original bytes
        free(decoded);
    }

    free(encoded);
}

CF_Enc_Free(&ctx);
```

---

## Hash Functions
This section provides a practical guide for using the `CF_HASH` API, including context initialization, one-shot and streaming operations, and optional XOF/cSHAKE customization, which are all defined in the [cf_hash.h](src/CryptoForge/include/cf_api/cf_hash.h) file.

---

### 1. Context Initialization

#### Stack Allocation (One-Shot / Streaming)
```c
CF_HASH_CTX ctx;
CF_STATUS status = CF_Hash_Init(&ctx, CF_Hash_GetByFlag(CF_SHA256), NULL);
if (status != CF_SUCCESS) {
    // handle error
}
```

#### Heap Allocation (Reusable / Cloneable)
```c
CF_STATUS status;
CF_HASH_CTX *ctx = CF_Hash_InitAlloc(CF_Hash_GetByFlag(CF_SHA3_512), NULL, &status);
if (!ctx || status != CF_SUCCESS) {
    // handle allocation/init error
}
```

---

### 2. Updating / Feeding Data

#### Incremental Updates
```c
uint8_t data_chunk[] = {0x01, 0x02, 0x03};
CF_STATUS status = CF_Hash_Update(&ctx, data_chunk, sizeof(data_chunk));
if (status != CF_SUCCESS) {
    // handle error
}
```

- Can be called multiple times before finalizing.
- Not allowed after `CF_Hash_Final` unless context is reset.

---

### 3. Finalization

#### Fixed / Default Output Digest
```c
uint8_t digest[CF_SHA256_DIGEST_SIZE];
CF_STATUS status = CF_Hash_Final(&ctx, digest, sizeof(digest));
if (status != CF_SUCCESS) {
    // handle error
}
```

- For XOFs (SHAKE/rawSHAKE/cSHAKE), `digest_len` can specify a custom output length.
- After finalization, the context is marked finalized.

---

### 4. One-Shot Hashing

#### Full Computation
```c
uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
uint8_t digest[CF_SHA256_DIGEST_SIZE];

CF_STATUS status = CF_Hash_Compute(
    CF_Hash_GetByFlag(CF_SHA256),
    data, sizeof(data),
    digest, sizeof(digest),
    NULL // optional CF_HASH_OPTS
);
```

#### Fixed-Output Convenience
```c
CF_Hash_ComputeFixed(CF_Hash_GetByFlag(CF_SHA256), data, sizeof(data), digest);
```

---

### 5. Context Management

- **Reset context:**
```c
CF_Hash_Reset(&ctx);
```

- **Free heap-allocated context:**
```c
CF_Hash_Free(&ctx_ptr); // ctx_ptr is CF_HASH_CTX*
```

- **Clone context (stack or heap):**
```c
CF_HASH_CTX clone;
CF_Hash_CloneCtx(&clone, &ctx);

CF_HASH_CTX *clone_heap = CF_Hash_CloneCtxAlloc(&ctx, &status);
```

- **Validate context:**
```c
CF_Hash_ValidateCtx(&ctx);
```

---

### 6. Optional Hash Parameters (SHAKE/rawSHAKE/cSHAKE)

- **Initialize stack options:**
```c
CF_HASH_OPTS opts;
CF_HashOpts_Init(&opts, N_bytes, N_len, S_bytes, S_len);
```

- **Heap-allocated options:**
```c
CF_HASH_OPTS *opts = CF_HashOpts_InitAlloc(N_bytes, N_len, S_bytes, S_len, &status);
```

- **Reset / Free / Clone:**
```c
CF_HashOpts_Reset(&opts);
CF_HashOpts_Free(&opts_ptr);
CF_HashOpts_Clone(&dst, &src);;
CF_HASH_OPTS *clone_heap = CF_HashOpts_CloneCtxAlloc(&src, &status);
```

---

### 7. Hash Utility Functions
```c
size_t digest_size = CF_Hash_GetDigestSize(CF_Hash_GetByFlag(CF_SHA256));
size_t block_size  = CF_Hash_GetBlockSize(CF_Hash_GetByFlag(CF_SHA256));
const char *name   = CF_Hash_GetName(CF_Hash_GetByFlag(CF_SHA256));
```

---

### 8. Hash Algorithm Flags

| Algorithm        | Flag             | Digest Size | Block Size |
|------------------|------------------|-------------|------------|
| MD5              | `CF_MD5`         | 16          | 64         |
| SHA-1            | `CF_SHA1`        | 20          | 64         |
| SHA-224          | `CF_SHA224`      | 28          | 64         |
| SHA-256          | `CF_SHA256`      | 32          | 64         |
| SHA-384          | `CF_SHA384`      | 48          | 128        |
| SHA-512          | `CF_SHA512`      | 64          | 128        |
| SHA3-224         | `CF_SHA3_224`    | 28          | 144        |
| SHA3-256         | `CF_SHA3_256`    | 32          | 136        |
| SHA3-384         | `CF_SHA3_384`    | 48          | 104        |
| SHA3-512         | `CF_SHA3_512`    | 64          | 72         |
| SHAKE128         | `CF_SHAKE128`    | 32*         | 168        |
| SHAKE256         | `CF_SHAKE256`    | 64*         | 136        |
| rawSHAKE128      | `CF_RAWSHAKE128` | 32*         | 168        |
| rawSHAKE256      | `CF_RAWSHAKE256` | 64*         | 136        |
| cSHAKE128        | `CF_CSHAKE128`   | 32*         | 168        |
| cSHAKE256        | `CF_CSHAKE256`   | 64*         | 136        |

\* Default digest size for XOFs; can be overridden in `CF_Hash_Final` or `CF_Hash_Compute`.

> **Note:** For a complete reference of hash algorithm flags, digest sizes, and block sizes, see the [cf_flags.h](src/CryptoForge/include/cf_api/cf_flags.h) file.
> Digest sizes are defined in `CF_DIGEST_SIZE` (or `CF_DIGEST_DEFAULT_SIZE` for XOFs), and block sizes are defined in `CF_HASH_BLOCK_SIZE`.

---

### 9. Example Full Flow

```c
CF_STATUS status;
CF_HASH_CTX *hash_ctx = CF_Hash_InitAlloc(CF_SHA256, &status);

uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
uint8_t digest[CF_SHA256_DIGEST_SIZE]; // 32 bytes for SHA-256

if (hash_ctx && status == CF_SUCCESS) {
    status = CF_Hash_Update(hash_ctx, data, sizeof(data));

    if (status == CF_SUCCESS) {
        status = CF_Hash_Final(hash_ctx, digest, sizeof(digest));

        if (status == CF_SUCCESS) {
            printf("SHA-256 Digest: ");
            for (size_t i = 0; i < sizeof(digest); i++) {
                printf("%02X", digest[i]);
            }
            printf("\n");
        }
    }

    CF_Hash_Free(&hash_ctx);
}
```

---

## Message Authentication Codes (MACs)

This section provides a comprehensive reference for using the `CF_MAC` API, including context initialization, one-shot and streaming operations, optional parameters, and flag definitions, as defined in the [cf_mac.h](src/CryptoForge/include/cf_api/cf_mac.h) file.

---

### 1. Context Initialization

#### Stack Allocation (One-Shot / Streaming)
```c
CF_MAC_CTX ctx;
CF_STATUS status = CF_MAC_Init(&ctx, CF_MAC_GetByFlag(CF_HMAC), NULL, key, key_len, CF_MD5);
if (status != CF_SUCCESS) {
    // handle error
}
```

#### Heap Allocation (Reusable)
```c
CF_STATUS status;
CF_MAC_CTX *ctx = CF_MAC_InitAlloc(CF_MAC_GetByFlag(CF_KMAC_STD), NULL, key, key_len, CF_KMAC128, &status);
if (!ctx || status != CF_SUCCESS) {
    // handle allocation/init error
}
```

---

### 2. Updating / Feeding Data
```c
uint8_t data[] = {0x01, 0x02, 0x03};
CF_STATUS status = CF_MAC_Update(&ctx, data, sizeof(data));
if (status != CF_SUCCESS) {
    // handle error
}
```

- Can be called multiple times before `CF_MAC_Final`.

---

### 3. Finalization
```c
uint8_t tag[32]; // desired tag length
CF_STATUS status = CF_MAC_Final(&ctx, tag, sizeof(tag));
```

---

### 4. One-Shot MAC Computation
```c
uint8_t tag[CF_SHA256_DIGEST_SIZE]; // 32 bytes for SHA-256
CF_STATUS status = CF_MAC_Compute(CF_MAC_GetByFlag(CF_HMAC), key, key_len, data, sizeof(data), tag, sizeof(tag), NULL, CF_SHA256);
```

---

### 5. Context Management

- **Reset context:**
```c
CF_MAC_Reset(&ctx);
```

- **Free heap-allocated context:**
```c
CF_MAC_Free(&ctx_ptr); // ctx_ptr is CF_MAC_CTX*
```

- **Clone context (stack or heap):**
```c
CF_MAC_CTX clone;
CF_MAC_CloneCtx(&clone, &ctx);

CF_MAC_CTX *clone_heap = CF_MAC_CloneCtxAlloc(&ctx, &status);
```

- **Validate context:**
```c
CF_MAC_ValidateCtx(&ctx);
```

---

### 6. MAC Algorithm Flags

#### 1. Algorithm Flags
| Algorithm | Flag         |
|-----------|--------------|
| HMAC      | CF_HMAC      |
| KMAC      | CF_KMAC_STD  |
| AES-CMAC  | CF_AES_CMAC  |
| AES-GMAC  | CF_AES_GMAC  |
| Poly1305  | CF_POLY1305  |

> **Note:** HMAC variants are selected via the `subflags` parameter using hash algorithm flags (`CF_HASH_FLAGS`). Any non-XOF hash can be used.  
> KMAC variants are selected via the `subflags` parameter using `CF_KMAC_TYPE_FLAGS`. Overall MAC algorithm flags are defined in `CF_MAC_FLAGS`.

---

#### 2. KMAC Type Subflags
| Type        | Flag           |
|-------------|----------------|
| KMAC128     | CF_KMAC128     |
| KMAC256     | CF_KMAC256     |
| KMAC_XOF128 | CF_KMAC_XOF128 |
| KMAC_XOF256 | CF_KMAC_XOF256 |

> **Note:** KMAC variants are chosen via the `subflags` parameter. Any type, including XOF variants, is allowed. These subflags are defined in `CF_KMAC_TYPE_FLAGS`.

---

### 8. MAC Utility Functions

- **Get MAC name:**
```c
const char *name = CF_MAC_GetName(mac);
```

- **Get full descriptive name:**
```c
const char *full = CF_MAC_GetFullName(ctx);
```

- **Validate key/tag length:**
```c
bool valid_key = CF_MAC_IsValidKeyLength(mac, key_len);
bool valid_tag = CF_MAC_IsValidTagLength(mac, tag_len);
```

- **Get valid key/tag sizes:**
```c
size_t key_count = 0;
size_t tag_count = 0;
CF_MAC_GetValidKeySizes(mac, &key_count);
CF_MAC_GetValidTagSizes(mac, &tag_count);
```

---

### 9. MAC Options

- **Stack initialization:**
```c
CF_MAC_OPTS opts;
CF_MACOpts_Init(&opts, iv, iv_len, custom, custom_len);
```

- **Heap initialization:**
```c
CF_MAC_OPTS *opts = CF_MACOpts_InitAlloc(iv, iv_len, custom, custom_len, &status);
```

- **Reset / Free / Clone:**
```c
CF_MACOpts_Reset(&opts);
CF_MACOpts_Free(&opts_ptr);
CF_MACOpts_CloneCtx(&dst, &src);
CF_MAC_OPTS *clone_heap = CF_MACOpts_CloneCtxAlloc(&src, &status);
```

### 10. Example Full Flow

```c
CF_STATUS status;
uint8_t key[CF_KEY_128_SIZE] = {0x00};     // example 16-byte key
uint8_t iv[12]  = {0x00};                  // example 96-bit IV
uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
uint8_t tag[CF_TAG_128_SIZE];              // GMAC tag (AES block size)

CF_MAC_CTX *ctx = CF_MAC_InitAlloc(
    CF_MAC_GetByFlag(CF_GMAC), NULL,
    key, sizeof(key),
    CF_AES_128, iv, sizeof(iv),
    &status
);

if (ctx && status == CF_SUCCESS) {
    status = CF_MAC_Update(ctx, data, sizeof(data));

    if (status == CF_SUCCESS) {
        status = CF_MAC_Final(ctx, tag, sizeof(tag));

        if (status == CF_SUCCESS) {
            printf("GMAC Tag: ");
            for (size_t i = 0; i < sizeof(tag); i++) {
                printf("%02X", tag[i]);
            }
            printf("\n");
        }
    }

    CF_MAC_Free(&ctx);
}
```

---

## Key Derivation Functions (KDFs)

This section provides a comprehensive guide for using the `CF_KDF` API, including context initialization, one-shot and streaming operations, optional parameters, and flag definitions. All functions and structures are defined in the [cf_kdf.h](src/CryptoForge/include/cf_api/cf_kdf.h) file.

---

### 1. Context Initialization

#### Stack Allocation (One-Shot / Streaming)
```c
CF_KDF_CTX ctx;
CF_STATUS status = CF_KDF_Init(
    &ctx,
    CF_KDF_GetByFlag(CF_HKDF),
    NULL,                // optional CF_KDF_OPTSS
    ikm, ikm_len,        // input keying material
    CF_SHA256            // subflags (hash variant)
);
if (status != CF_SUCCESS) {
    // handle error
}
```

#### Heap Allocation (Reusable)
```c
CF_STATUS status;
CF_KDF_CTX *ctx = CF_KDF_InitAlloc(
    CF_KDF_GetByFlag(CF_PBKDF2),
    opts,                // optional CF_KDF_OPTSS
    ikm, ikm_len,
    CF_SHA512,           // subflags
    &status
);
if (!ctx || status != CF_SUCCESS) {
    // handle allocation/init error
}
```

---

### 2. Extract / Expand Operations

#### Extract Phase (Optional)
```c
CF_STATUS status = CF_KDF_Extract(ctx, salt, salt_len);
if (status != CF_SUCCESS) {
    // handle error
}
```

#### Expand Phase
```c
uint8_t derived_key[32];
CF_STATUS status = CF_KDF_Expand(ctx, derived_key, sizeof(derived_key));
if (status != CF_SUCCESS) {
    // handle error
}
```

---

### 3. One-Shot KDF Computation
```c
uint8_t derived_key[32];
CF_STATUS status = CF_KDF_Compute(
    CF_KDF_GetByFlag(CF_HKDF),
    ikm, ikm_len,
    salt, salt_len,
    derived_key, sizeof(derived_key),
    opts, CF_SHA256
);
if (status == CF_SUCCESS) {
    // derived_key now contains the key material
}
```

---

### 4. Context Management

- **Reset context:**
```c
CF_KDF_Reset(&ctx);
```

- **Free heap-allocated context:**
```c
CF_KDF_Free(&ctx_ptr); // ctx_ptr is CF_KDF_CTX*
```

- **Clone context:**
```c
CF_KDF_CTX clone;
CF_KDF_CloneCtx(&clone, &ctx);

CF_KDF_CTX *clone_heap = CF_KDF_CloneCtxAlloc(&ctx, &status);
```

- **Validate context:**
```c
CF_KDF_ValidateCtx(&ctx);
```

---

### 5. KDF Utility Functions

- **Get short name of KDF type:**
```c
const char *name = CF_KDF_GetName(CF_KDF_GetByFlag(CF_HKDF));
printf("KDF Type: %s\n", name);
```

- **Get full descriptive name of KDF context:**
```c
const char *full_name = CF_KDF_GetFullName(&ctx);
printf("Full KDF Context: %s\n", full_name);
```

---

### 6. KDF Options

- **Stack initialization:**
```c
CF_KDF_OPTS opts;
CF_KDFOpts_Init(&opts, info, info_len, custom, custom_len, iterations);
```

- **Heap initialization:**
```c
CF_KDF_OPTS *opts = CF_KDFOpts_InitAlloc(info, info_len, custom, custom_len, iterations, &status);
```

- **Set new info in KDF options:**
```c
CF_STATUS status = CF_KDFOpts_SetNewInfo(opts, new_info, new_info_len);
```

- **Reset / Free / Clone:**
```c
CF_KDFOpts_Reset(&opts);
CF_KDFOpts_Free(&opts_ptr);
CF_KDFOpts_CloneCtx(&dst, &src);
CF_KDF_OPTS *clone_heap = CF_MACOpts_CloneCtxAlloc(&src, &status);
```


### 6. KDF Algorithm Flags

#### 1. Algorithm Flags
| Algorithm   | Flag           |
|-------------|----------------|
| HKDF       | CF_HKDF        |
| PBKDF2     | CF_PBKDF2      |
| KMAC XOF   | CF_KMAC_XOF    |

> **Note:** KDF variants are selected via the `subflags` parameter. Hash-based variants (like HKDF or PBKDF2) use `CF_HASH_FLAGS` for the underlying hash selection.
> KMAC-XOF variants use `CF_KMAC_TYPE_FLAGS` for the subflags. Overall KDF algorithm flags are defined in `CF_KDF_FLAGS`.

---

#### 2. KMAC-XOF Type Subflags
| Type        | Flag           |
|-------------|----------------|
| KMAC_XOF128 | CF_KMAC_XOF128 |
| KMAC_XOF256 | CF_KMAC_XOF256 |

> **Note:** KMAC-XOF variants are chosen via the `subflags` parameter, using `CF_KMAC_TYPE_FLAGS`.

---

### 7. Example Full Flow

```c
CF_STATUS status;
uint8_t ikm[] = {0x01, 0x02, 0x03, 0x04};
uint8_t salt[] = {0x0A, 0x0B, 0x0C};
uint8_t derived_key[32];

CF_KDF_CTX *ctx = CF_KDF_InitAlloc(
    CF_KDF_GetByFlag(CF_HKDF),
    NULL,      // optional opts
    ikm, sizeof(ikm),
    CF_SHA256, // subflags
    &status
);

if (ctx && status == CF_SUCCESS) {
    status = CF_KDF_Extract(ctx, salt, sizeof(salt));
    if (status == CF_SUCCESS) {
        status = CF_KDF_Expand(ctx, derived_key, sizeof(derived_key));
        if (status == CF_SUCCESS) {
            printf("Derived Key: ");
            for (size_t i = 0; i < sizeof(derived_key); i++) {
                printf("%02X", derived_key[i]);
            }
            printf("\n");
        }
    }
    CF_KDF_Free(&ctx);
}
```

---

## Symmetric Ciphers

This section provides a comprehensive guide for using the `CF_Cipher` API, including context initialization, one-shot and streaming operations, optional parameters, flag definitions, and block/stream cipher behavior. All functions and structures are defined in the [cf_cipher.h](src/CryptoForge/include/cf_api/cf_cipher.h) file.

---

### 1. Cipher Context Initialization

#### Stack Allocation (One-Shot / Streaming)
```c
CF_CIPHER_CTX ctx;
CF_STATUS status = CF_Cipher_Init(
    &ctx,
    CF_Cipher_GetByFlag(CF_AES_CBC),
    opts,                // optional CF_CIPHER_OPTS
    key, key_len,        // encryption/decryption key
    CF_OP_ENCRYPT        // operation mode
);
if (status != CF_SUCCESS) {
    // handle error
}
```

#### Heap Allocation (Reusable)
```c
CF_STATUS status;
CF_CIPHER_CTX *ctx = CF_Cipher_InitAlloc(
    CF_Cipher_GetByFlag(CF_CHACHA20),
    opts,                // optional CF_CIPHER_OPTS
    key, key_len,
    CF_OP_DECRYPT,       // operation mode
    &status
);
if (!ctx || status != CF_SUCCESS) {
    // handle allocation/init error
}
```

---

### 2. Data Processing

#### Encrypt / Decrypt Operations
```c
uint8_t out_buf[256];
size_t out_len;
CF_STATUS status = CF_Cipher_Process(&ctx, input, input_len, out_buf, &out_len);
if (status != CF_SUCCESS) {
    // handle error
}
```

> **Note:** For AES-ECB and AES-CBC (with or without PKCS7 padding), input length must be a multiple of 16 bytes (or padded). Modes that behave like stream ciphers — AES-OFB, AES-CFB, AES-CTR, ChaCha, and XChaCha — support arbitrary input lengths.

---

### 3. One-Shot Encryption / Decryption
```c
uint8_t ciphertext[256];
size_t ct_len;
CF_STATUS status = CF_Cipher_Encrypt(
    CF_Cipher_GetByFlag(CF_AES_ECB),
    key, key_len,
    plaintext, pt_len,
    ciphertext, &ct_len,
    opts
);

uint8_t plaintext_out[256];
size_t pt_out_len;
status = CF_Cipher_Decrypt(
    CF_Cipher_GetByFlag(CF_AES_ECB),
    key, key_len,
    ciphertext, ct_len,
    plaintext_out, &pt_out_len,
    opts
);
```

---

### 4. Context Management

- **Reset context:**
```c
CF_Cipher_Reset(&ctx);
```

- **Free heap-allocated context:**
```c
CF_Cipher_Free(&ctx_ptr); // ctx_ptr is CF_CIPHER_CTX*
```

- **Clone context:**
```c
CF_CIPHER_CTX clone;
CF_Cipher_CloneCtx(&clone, &ctx);

CF_CIPHER_CTX *clone_heap = CF_Cipher_CloneCtxAlloc(&ctx, &status);
```

- **Validate context:**
```c
CF_Cipher_ValidateCtx(&ctx);
```

---

### 5. Cipher Utility Functions

- **Get short name of cipher:**
```c
const char *name = CF_Cipher_GetName(CF_Cipher_GetByFlag(CF_AES_CBC));
printf("Cipher: %s\n", name);
```

- **Get full name including key size:**
```c
const char *full_name = CF_Cipher_GetFullName(&ctx);
printf("Full Cipher: %s\n", full_name);
```

- **Check key length validity:**
```c
bool valid = CF_Cipher_IsValidKeyLength(CF_Cipher_GetByFlag(CF_AES_ECB), 32);
```

- **Get valid key sizes:**
```c
size_t count;
const size_t *sizes = CF_Cipher_GetValidKeySizes(CF_Cipher_GetByFlag(CF_AES_CBC), &count);
```

- **Get block size / output length:**
```c
size_t block_size = CF_Cipher_GetBlockSize(&ctx);
size_t out_len = CF_Cipher_GetOutputLength(&ctx, input_len);
```

---

### 6. Cipher Options

- **Stack initialization:**
```c
CF_CipherOpts_Init(&opts, iv, iv_len, ctr_block, chacha_counter);
```

- **Heap initialization:**
```c
CF_CIPHER_OPTS *opts = CF_CipherOpts_InitAlloc(iv, iv_len, ctr_block, chacha_counter, &status);
```

- **Reset / Free / Clone:**
```c
CF_CipherOpts_Reset(&opts);
CF_CipherOpts_Free(&opts_ptr);
CF_CipherOpts_CloneCtx(&dst, &src);
CF_CIPHER_OPTS *clone_heap = CF_CipherOpts_CloneCtxAlloc(&src, &status);
```

---

### 7. Cipher Flags / Block, Key & IV sizes

| Cipher | Flag | Block Size (bytes) | IV Required | IV Length (bytes) | CTR Counter | ChaCha Counter | Type | Supported Key Sizes (bytes) |
|--------|-------|-------------------|-------------|-------------------|-------------|----------------|------|-----------------------------|
| AES-ECB           | `CF_AES_ECB`       | 16         | No          | 0         | No  | No  | Block  | 16, 24, 32 |
| AES-CBC           | `CF_AES_CBC`       | 16         | Yes         | 16        | No  | No  | Block  | 16, 24, 32 |
| AES-CBC-PKCS7     | `CF_AES_CBC_PKCS7` | 16         | Yes         | 16        | No  | No  | Block  | 16, 24, 32 |
| AES-OFB           | `CF_AES_OFB`       | 16         | Yes         | 16        | No  | No  | Stream | 16, 24, 32 |
| AES-CFB8          | `CF_AES_CFB8`      | 16         | Yes         | 16        | No  | No  | Stream | 16, 24, 32 |
| AES-CFB128        | `CF_AES_CFB128`    | 16         | Yes         | 16        | No  | No  | Stream | 16, 24, 32 |
| AES-CTR           | `CF_AES_CTR`       | 16         | Yes         | 16        | Yes | No  | Stream | 16, 24, 32 |
| ChaCha8           | `CF_CHACHA8`       | 0          | No          | 0         | No  | Yes | Stream | 32 |
| ChaCha12          | `CF_CHACHA12`      | 0          | No          | 0         | No  | Yes | Stream | 32 |
| ChaCha20          | `CF_CHACHA20`      | 0          | No          | 0         | No  | Yes | Stream | 32 |
| XChaCha8          | `CF_XCHACHA8`      | 0          | Yes         | 24        | No  | Yes | Stream | 32 |
| XChaCha12         | `CF_XCHACHA12`     | 0          | Yes         | 24        | No  | Yes | Stream | 32 |
| XChaCha20         | `CF_XCHACHA20`     | 0          | Yes         | 24        | No  | Yes | Stream | 32 |

> **Note:** For a complete reference of cipher flags, block sizes, IV requirements, and counter usage, see the [cf_flags.h](src/CryptoForge/include/cf_api/cf_flags.h) file.
> Key sizes are defined in the `CF_KEY_SIZE` enum, while cipher mode flags can be found in the `CF_AES_MODE_FLAGS` and `CF_CHACHA_MODE_FLAGS` enums.

---

### 8. Example Full Flow
```c
CF_STATUS status;
uint8_t key[CF_KEY_256_SIZE] = {0};
uint8_t iv[16] = {0};
uint8_t plaintext[64] = {0};
uint8_t ciphertext[64];
size_t ct_len;

CF_CIPHER_OPTS opts;
CF_CipherOpts_Init(&opts, iv, sizeof(iv), NULL, 0);

CF_CIPHER_CTX *ctx = CF_Cipher_InitAlloc(
    CF_Cipher_GetByFlag(CF_AES_CBC),
    &opts,
    key, sizeof(key),
    CF_OP_ENCRYPT,
    &status
);

if (ctx && status == CF_SUCCESS) {
    status = CF_Cipher_Process(ctx, plaintext, sizeof(plaintext), ciphertext, &ct_len);
    if (status == CF_SUCCESS) {
        printf("Ciphertext length: %zu\n", ct_len);
    }
    CF_Cipher_Free(&ctx);
}
```

---

## AEAD Constructions

This section provides a comprehensive guide for using the `CF_AEAD` API, including context initialization, one-shot and streaming operations, optional parameters, flag definitions, tag/key behavior, and AEAD-specific utilities. All functions and structures are defined in the [cf_aead.h](src/CryptoForge/include/cf_api/cf_aead.h) file.

---

### 1. AEAD Context Initialization

#### Stack Allocation (One-Shot / Streaming)
```c
CF_AEAD_CTX ctx;
CF_STATUS status = CF_AEAD_Init(
    &ctx,
    CF_AEAD_GetByFlag(CF_AES_GCM),
    key, key_len,
    iv, iv_len,
    aad, aad_len,
    CF_OP_ENCRYPT
);
if (status != CF_SUCCESS) {
    // handle error
}
```

#### Heap Allocation (Reusable)
```c
CF_STATUS status;
CF_AEAD_CTX *ctx = CF_AEAD_InitAlloc(
    CF_AEAD_GetByFlag(CF_CHACHA20_POLY1305),
    key, key_len,
    iv, iv_len,
    aad, aad_len,
    CF_OP_DECRYPT,
    &status
);
if (!ctx || status != CF_SUCCESS) {
    // handle allocation/init error
}
```

---

### 2. Data Processing

#### Encrypt / Decrypt Operations
```c
uint8_t out_buf[256];
size_t out_len;
CF_STATUS status = CF_AEAD_Update(&ctx, input, input_len, out_buf, &out_len);
if (status != CF_SUCCESS) {
    // handle error
}
```

#### Finalizing AEAD
```c
uint8_t tag[CF_AEAD_TAG_128_SIZE]; // 16-Bytes tag
status = CF_AEAD_Final(&ctx, tag, sizeof(tag));
if (status != CF_SUCCESS) {
    // handle error
}
```

> **Note:** AEAD modes support arbitrary input lengths and require a valid authentication tag length when finalizing.

---

### 3. One-Shot Encryption / Decryption

#### Standard Encrypt / Decrypt

```c
uint8_t ciphertext[256];
size_t ct_len;
uint8_t tag[CF_AEAD_TAG_128_SIZE]; // 16-Bytes tag size
CF_STATUS status = CF_AEAD_Encrypt(
    CF_AEAD_GetByFlag(CF_AES_GCM),
    key, key_len,
    iv, iv_len,
    aad, aad_len,
    plaintext, pt_len,
    ciphertext, &ct_len,
    tag, sizeof(tag)
);

uint8_t plaintext_out[256];
size_t pt_out_len;
status = CF_AEAD_Decrypt(
    CF_AEAD_GetByFlag(CF_AES_GCM),
    key, key_len,
    iv, iv_len,
    aad, aad_len,
    ciphertext, ct_len,
    plaintext_out, &pt_out_len,
    tag, sizeof(tag)
);
```

#### Encrypt / Decrypt With Appended Tag

```c
uint8_t out_combined[272]; // ciphertext + tag
size_t out_len;
status = CF_AEAD_EncryptAppendTag(
    CF_AEAD_GetByFlag(CF_AES_GCM),
    key, key_len,
    iv, iv_len,
    aad, aad_len,
    plaintext, pt_len,
    out_combined, &out_len
);

uint8_t plaintext_out[256];
size_t pt_out_len;
status = CF_AEAD_DecryptAppendTag(
    CF_AEAD_GetByFlag(CF_AES_GCM),
    key, key_len,
    iv, iv_len,
    aad, aad_len,
    out_combined, out_len,
    plaintext_out, &pt_out_len
);
```

> **Note:** These functions internally allocate a temporary stack AEAD context and combine the authentication tag with the ciphertext. They always use the maximum tag size supported by the AEAD construction.

---

### 4. Context Management

- **Reset context:**
```c
CF_AEAD_Reset(&ctx);
```

- **Free heap-allocated context:**
```c
CF_AEAD_Free(&ctx_ptr); // ctx_ptr is CF_AEAD_CTX*
```

- **Clone context:**
```c
CF_AEAD_CTX clone;
CF_AEAD_CloneCtx(&clone, &ctx);

CF_AEAD_CTX *clone_heap = CF_AEAD_CloneCtxAlloc(&ctx, &status);
```

- **Validate context:**
```c
CF_AEAD_ValidateCtx(&ctx);
```

---

### 5. AEAD Utility Functions

- **Get short name of AEAD:**
```c
const char *name = CF_AEAD_GetName(CF_AEAD_GetByFlag(CF_AES_GCM));
printf("AEAD: %s\n", name);
```

- **Get full name including key size:**
```c
const char *full_name = CF_AEAD_GetFullName(&ctx);
printf("Full AEAD: %s\n", full_name);
```

- **Check key length validity:**
```c
bool valid = CF_AEAD_IsValidKeyLength(CF_AEAD_GetByFlag(CF_AES_GCM), 32);
```

- **Check tag length validity:**
```c
bool valid_tag = CF_AEAD_IsValidTagLength(CF_AEAD_GetByFlag(CF_AES_GCM), 16);
```

- **Get valid key sizes:**
```c
size_t count;
const size_t *sizes = CF_AEAD_GetValidKeySizes(CF_AEAD_GetByFlag(CF_AES_GCM), &count);
```

- **Get valid tag sizes / max tag size:**
```c
const size_t *tag_sizes = CF_AEAD_GetValidTagSizes(CF_AEAD_GetByFlag(CF_AES_GCM), &count);
size_t max_tag = CF_AEAD_GetMaxTagSize(CF_AEAD_GetByFlag(CF_AES_GCM));
```

---

### 6. AEAD Flags / IV & Key Sizes

| AEAD                  | Flag                     | IV Sizes (bytes) | Tag Sizes (bytes) | Key Sizes (bytes) |
|-----------------------|-------------------------|-----------------|-----------------|-----------------|
| AES-GCM               | `CF_AES_GCM`            | 12              | 4, 8, 12, 16    | 16, 24, 32      |
| ChaCha20-Poly1305     | `CF_CHACHA20_POLY1305`  | 12              | 4, 8, 12, 16    | 32              |
| XChaCha20-Poly1305    | `CF_XCHACHA20_POLY1305` | 24              | 4, 8, 12, 16    | 32              |

> **Note:** For a complete reference of AEAD constructions, supported IVs, and counter usage, see the [cf_flags.h](src/CryptoForge/include/cf_api/cf_flags.h) file.  
> Key sizes are defined in the `CF_KEY_SIZE` enum, AEAD-specific flags are in the `CF_AEAD_MODE_FLAGS` enum, and tag sizes are defined in the `CF_AEAD_TAG_SIZE` enum.

---

### 7. Example Full Flow
```c
CF_STATUS status;
uint8_t key[CF_KEY_256_SIZE] = {0};
uint8_t iv[12] = {0};
uint8_t aad[16] = {0};
uint8_t plaintext[64] = {0};
uint8_t ciphertext[64];
uint8_t tag[CF_AEAD_TAG_128_SIZE]; // 16-Bytes tag size
size_t ct_len;

CF_AEAD_CTX *ctx = CF_AEAD_InitAlloc(
    CF_AEAD_GetByFlag(CF_AES_GCM),
    key, sizeof(key),
    iv, sizeof(iv),
    aad, sizeof(aad),
    CF_OP_ENCRYPT,
    &status
);

if (ctx && status == CF_SUCCESS) {
    status = CF_AEAD_Update(ctx, plaintext, sizeof(plaintext), ciphertext, &ct_len);
    if (status == CF_SUCCESS) {
        CF_AEAD_Final(ctx, tag, sizeof(tag));
        printf("Ciphertext length: %zu, Tag length: %zu\n", ct_len, sizeof(tag));
    }
    CF_AEAD_Free(&ctx);
}
```

---

## Utilities

This section provides a detailed guide for using the `CF_UTILS` API, including constant-time comparisons, lexicographical operations, entropy generation, and other utility functions. All functions are declared in the [cf_utils.h](src/CryptoForge/include/cf_api/cf_utils.h) file.

---

### 1. Constant-Time Buffer Comparison

#### Compare Two Buffers

```c
uint8_t buf1[32] = {0};
uint8_t buf2[32] = {0};

int cmp = CF_Compare(buf1, buf2, sizeof(buf1));
if (cmp == 1) {
    printf("Buffers are equal\n");
} else if (cmp == 0) {
    printf("Buffers differ\n");
} else {
    printf("Error occurred: %d\n", cmp);
}
```

> **Note:** `CF_Compare` ensures a constant-time comparison to mitigate timing attacks. Returns `1` for equality, `0` for inequality, and negative values for errors.

---

### 2. Lexicographical Comparison

#### Compare Buffers Lexicographically

```c
uint8_t a[16] = {0x01, 0x02};
uint8_t b[16] = {0x01, 0x03};

int lex_cmp = CF_CompareLex(a, b, sizeof(a));
if (lex_cmp < 0) {
    printf("a < b\n");
} else if (lex_cmp == 0) {
    printf("a == b\n");
} else {
    printf("a > b\n");
}
```

> **Note:** `CF_CompareLex` performs a constant-time lexicographical comparison. Returns `-1` if `a < b`, `0` if equal, `1` if `a > b`, and negative values for errors.

---

### 3. Entropy Generation from the OS

#### Fill a Buffer with Cryptographic Entropy

```c
uint8_t entropy[64];
CF_STATUS status = CF_EntropyFromOS(entropy, sizeof(entropy));
if (status != CF_SUCCESS) {
    printf("Failed to generate entropy: %d\n", status);
} else {
    printf("Entropy generated successfully\n");
}
```

> **Note:**
> - On Linux: uses `getrandom()` if available, falling back to `/dev/urandom`.
> - On Windows: uses `BCryptGenRandom` on MSVC, and falls back to the older CryptoAPI (`CryptGenRandom`) on other compilers.
> - Returns `CF_SUCCESS` on success, or error codes such as `CF_ERR_NULL_PTR` or `CF_ERR_OS_FAIL`.

---

### 4. Example Full Flow

```c
CF_STATUS status;
uint8_t buf1[32] = {0};
uint8_t buf2[32] = {0};
uint8_t entropy[32];

// Generate entropy
status = CF_EntropyFromOS(entropy, sizeof(entropy));
if (status != CF_SUCCESS) {
    // handle error
}

// Compare buffers
int cmp = CF_Compare(buf1, buf2, sizeof(buf1));
if (cmp == 1) {
    printf("Buffers match\n");
} else if (cmp == 0) {
    printf("Buffers differ\n");
}

// Lexicographical comparison
int lex_cmp = CF_CompareLex(buf1, buf2, sizeof(buf1));
printf("Lexicographical comparison result: %d\n", lex_cmp);
```

---

### 5. Error Codes

| Function             | Error Codes                 | Description                                            |
|----------------------|-----------------------------|--------------------------------------------------------|
| `CF_Compare`         | `<0`                        | General error (CF_ERR_* code)                          |
| `CF_CompareLex`      | `<0`                        | General error (CF_ERR_* code)                          |
| `CF_EntropyFromOS`   | `CF_ERR_NULL_PTR`           | Buffer pointer is NULL or length is zero               |
|                      | `CF_ERR_OS_FAIL`            | OS entropy source failed                               |

> **Note:** All CryptoForge utility functions are designed for safety, timing-attack resistance, and cross-platform compatibility.

---

## Compilation and Linking

This guide covers compiling and linking programs with CryptoForge on various platforms and compilers, including dynamic linking examples.

---

### GCC (Windows or Linux)
```bash
gcc main.c -IC:/path/to/CryptoForge/include -L/path/to/lib -lcryptoforge -o main.exe
```

---

### MSVC (Windows)
```cmd
cl main.c /I C:\path\to\CryptoForge\include /link /LIBPATH:C:\path\to\lib cryptoforge.lib /OUT:main.exe
```

---

### Clang (Windows)
```bash
clang main.c -IC:/path/to/CryptoForge/include -LC:/path/to/lib -lcryptoforge -o main.exe
```

---

### Recommendations
- When building the library, define an output binary location to make linking easier.
- If your text editor doesn't properly show or locate headers, coding and referencing becomes harder. Recommended approaches:
  - Keep this guide open side by side while coding.
  - Or copy the headers into your project folder to simplify access.

---

## Runtime Notes

### Endian Safety
- All algorithms are fully endian-safe. Both little- and big-endian platforms are supported transparently.

### Memory Management
- Functions with the `*Alloc` prefix return heap-allocated buffers; the caller is responsible for freeing them.
- Functions without `*Alloc` (e.g., initialization, cloning) use user-provided memory; the library does not free these buffers.

### Thread Safety
- Descriptor contexts (`CF_HASH`, `CF_ENCODER`, `CF_MAC`, `CF_KDF`, `CF_CIPHER`, `CF_AEAD`) are **always thread-safe**.
- Cloned contexts are safe for concurrent use across threads.
- Original contexts that are not cloned are **not safe** for simultaneous access.

### Context Initialization & Reset
- All contexts are automatically reset during initialization, even if the user did not manually reset them.
- Internal state is securely zeroed and managed automatically before context destruction.

### Magic Value Verification
- Each `CF_*_CTX` contains a magic value for integrity verification.
- For `CF_NAME_CTX`, the magic is XORed with the associated descriptor; functions will reject tampered contexts.
- For `CF_NAME_OPTS`, the magic value is used directly for verification.

### Context Lifecycle Rules
- Contexts cannot be reused after finalization functions (`Finish`, `Finalize`, `EncryptFinal`, etc.).
- Functions meant to run once cannot be executed twice on the same context.
- **Exceptions:** XOF-based hashes, MACs, and KDFs can be “expanded” or squeezed multiple times after finalization.

### Internal Security
- All sensitive buffers and internal contexts are zeroed automatically.
- Function pointers and internal descriptors are validated via the magic value before use, preventing tampered contexts from executing.