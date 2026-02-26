/*
 * CryptoForge - cf_aead.h / High-level AEAD cipher context and utility definitions
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CF_AEAD_H
#define CF_AEAD_H

#include "../config/crypto_config.h"
#include "../config/libs.h"

#include "../utils/misc.h"
#include "../utils/mem.h"
#include "../utils/cf_status.h"

#include "cf_defs.h"
#include "cf_flags.h"

#include "../crypto/aes_core.h"
#include "../crypto/aes_gcm.h"
#include "../crypto/chacha20_poly1305.h"
#include "../crypto/xchacha20_poly1305.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// AEAD Algorithm Descriptor
// ============================
// Describes an AEAD (Authenticated Encryption with Associated Data) implementation.
// Each CF_AEAD instance is static, immutable, and shared across contexts.
typedef struct _CF_AEAD {

    // Unique AEAD identifier / flag.
    uint32_t id;

    // --- Size metadata ---

    // Size of the low-level AEAD context (for allocation/stack usage).
    size_t ctx_size;

    // Size of the expanded key context (e.g., AES key schedule).
    size_t key_ctx_size;

    // --- Low-level entry points ---
    // Implement algorithm-specific logic; invoked by high-level API.

    // Initializes the low-level AEAD context.
    // Must be called before encryption or decryption.
    bool (*aead_init_fn)(const CF_AEAD_CTX *ctx);

    // Processes input data (encrypt or decrypt depending on context).
    // Can be called repeatedly for streaming input.
    // Writes output to `out` buffer.
    bool (*aead_update_fn)(
        const CF_AEAD_CTX *ctx,
        const uint8_t *in, size_t in_len,
        uint8_t *out
    );

    // Finalizes AEAD operation and writes authentication tag.
    bool (*aead_final_fn)(
        const CF_AEAD_CTX *ctx,
        uint8_t *tag, size_t tag_len
    );

} CF_AEAD;

// ============================
// High-level AEAD Context
// ============================
// Holds runtime state for a single AEAD encryption or decryption operation.
// By default, not thread-safe; concurrent usage requires independent contexts.
typedef struct _CF_AEAD_CTX {

    // Integrity guard: CF_CTX_MAGIC ^ (uintptr_t)aead
    uint64_t magic;

    // --- Algorithm binding (library-owned) ---
    // Descriptor is static and immutable.
    const CF_AEAD *aead;

    // Pointer to low-level AEAD state (algorithm-specific context).
    void *aead_ctx;

    // Pointer to expanded key material.
    // May be NULL for AEADs that do not require separate key expansion.
    void *key_ctx;

    // --- Key material ---
    // Raw user-supplied key (borrowed).
    // The library does not assume ownership unless explicitly documented.
    const uint8_t *key;
    size_t key_len;

    // --- Initialization Vector / Nonce ---
    // Raw user-supplied IV / nonce (borrowed).
    const uint8_t *iv;
    size_t iv_len;

    // --- Additional Authenticated Data (optional) ---
    const uint8_t *aad;
    size_t aad_len;

    // Total length of processed input data.
    uint64_t total_data_len;

    // Operation mode (encrypt or decrypt).
    CF_OPERATION operation;

    // Indicates whether this structure was heap allocated.
    // If set, it must be released via the appropriate free routine.
    int isHeapAlloc;

} CF_AEAD_CTX;

/*
 * CF_AEAD_GetByFlag
 *
 * Retrieves a pointer to a CF_AEAD descriptor based on an algorithm flag.
 * Iterates the internal cf_aead_table and invokes the associated getter function.
 *
 * Returns:
 *   pointer to CF_AEAD - if flag matches a supported AEAD algorithm
 *   NULL               - if flag is invalid or unsupported
 *
 * Parameters:
 *   algo_flag - algorithm identifier flag (e.g., CF_AES_GCM, CF_CHACHA20_POLY1305)
 */
CF_API const CF_AEAD *CF_AEAD_GetByFlag(uint32_t algo_flag);

/*
 * CF_AEAD_Init
 *
 * Initializes a stack-allocated AEAD context for encryption or decryption.
 * Validates parameters, sets up internal key and AEAD context memory, and
 * prepares the context for one-shot or streaming operations.
 *
 * Returns:
 *   CF_SUCCESS                    - initialization succeeded
 *   CF_ERR_NULL_PTR               - if ctx, aead, key, or IV is NULL
 *   CF_ERR_UNSUPPORTED            - if AEAD type is not recognized
 *   CF_ERR_CTX_CORRUPT            - if internal allocation or setup fails
 *   CF_ERR_CTX_UNINITIALIZED      - if heap allocation flag is invalid
 *   CF_ERR_INVALID_PARAM          - if operation mode or IV length is invalid
 *   CF_ERR_CIPHER_INVALID_KEY_LEN - if key length is invalid for AEAD
 *   CF_ERR_AEAD_INVALID_IV        - IV length invalid for selected AEAD
 *   CF_ERR_AEAD_INVALID_AAD       - AAD length invalid for selected AEAD
 *   CF_ERR_ALLOC_FAILED           - memory allocation for key or AEAD context failed
 *   CF_ERR_CIPHER_KEY_SETUP       - AES key schedule setup failed
 *
 * Parameters:
 *   ctx      - pointer to stack-allocated CF_AEAD_CTX
 *   aead     - pointer to CF_AEAD descriptor
 *   key      - pointer to encryption/decryption key
 *   key_len  - length of key in bytes
 *   iv       - pointer to initialization vector / nonce
 *   iv_len   - length of IV in bytes
 *   aad      - pointer to additional authenticated data (optional, can be NULL)
 *   aad_len  - length of AAD in bytes
 *   op       - operation mode (CF_OP_ENCRYPT or CF_OP_DECRYPT)
 */
CF_API CF_STATUS CF_AEAD_Init(
    CF_AEAD_CTX *ctx, const CF_AEAD *aead,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    CF_OPERATION op
);

/*
 * CF_AEAD_InitAlloc
 *
 * Allocates a new CF_AEAD_CTX on the heap and initializes it for encryption
 * or decryption with the specified AEAD algorithm. Marks the context as
 * heap-allocated for proper cleanup via CF_AEAD_Free.
 *
 * Returns:
 *   pointer to allocated CF_AEAD_CTX - on success
 *   NULL                             - on failure, with *status set
 *
 * Parameters:
 *   aead     - pointer to CF_AEAD descriptor
 *   key      - pointer to encryption/decryption key
 *   key_len  - length of key in bytes
 *   iv       - pointer to initialization vector / nonce
 *   iv_len   - length of IV in bytes
 *   aad      - pointer to additional authenticated data (optional)
 *   aad_len  - length of AAD in bytes
 *   op       - operation mode (CF_OP_ENCRYPT or CF_OP_DECRYPT)
 *   status   - pointer to receive CF_STATUS result
 */
CF_API CF_AEAD_CTX* CF_AEAD_InitAlloc(
    const CF_AEAD *aead,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    CF_OPERATION op, CF_STATUS *status
);

/*
 * CF_AEAD_Update
 *
 * Feeds input data into an initialized AEAD context. Can be called
 * repeatedly to process streaming input before calling CF_AEAD_Final.
 *
 * Returns:
 *   CF_SUCCESS               - update succeeded
 *   CF_ERR_NULL_PTR          - if ctx, input, or output is NULL
 *   CF_ERR_CTX_UNINITIALIZED - context or low-level AEAD not initialized
 *   CF_ERR_CTX_CORRUPT       - context integrity check failed (magic mismatch)
 *   CF_ERR_LIMIT_EXCEEDED    - input exceeds maximum allowed data length
 *
 * Parameters:
 *   ctx      - pointer to initialized CF_AEAD_CTX
 *   in       - pointer to input data bytes
 *   in_len   - length of input data in bytes
 *   out      - output buffer to receive ciphertext/plaintext
 *   out_len  - pointer to size_t to receive number of bytes written (optional)
 */
CF_API CF_STATUS CF_AEAD_Update(
    CF_AEAD_CTX *ctx,
    const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len
);

/*
 * CF_AEAD_Final
 *
 * Finalizes an AEAD operation and writes the authentication tag to the
 * provided buffer. After finalization, the context should not be updated
 * further without resetting.
 *
 * Returns:
 *   CF_SUCCESS                 - finalization succeeded
 *   CF_ERR_NULL_PTR            - if ctx or tag buffer is NULL
 *   CF_ERR_CTX_UNINITIALIZED   - context or low-level AEAD not initialized
 *   CF_ERR_CTX_CORRUPT         - context integrity check failed (magic mismatch)
 *   CF_ERR_MAC_INVALID_TAG_LEN - provided tag length is invalid for the AEAD
 *
 * Parameters:
 *   ctx      - pointer to initialized CF_AEAD_CTX
 *   tag      - pointer to buffer to receive authentication tag
 *   tag_len  - length of tag buffer in bytes
 */
CF_API CF_STATUS CF_AEAD_Final(
    CF_AEAD_CTX *ctx,
    uint8_t *tag, size_t tag_len
);

/*
 * CF_AEAD_Reset
 *
 * Resets an AEAD context to its initial, empty state. Frees any
 * internal low-level AEAD or key context memory and clears all fields
 * to prevent accidental reuse or leakage of sensitive data.
 *
 * Returns:
 *   CF_SUCCESS               - reset completed successfully
 *   CF_ERR_NULL_PTR          - if ctx is NULL
 *   CF_ERR_CTX_UNINITIALIZED - if ctx->aead is NULL
 *   CF_ERR_CTX_CORRUPT       - if internal sizes or pointers are inconsistent
 *
 * Parameters:
 *   ctx - pointer to CF_AEAD_CTX to reset
 */
CF_API CF_STATUS CF_AEAD_Reset(CF_AEAD_CTX *ctx);

/*
 * CF_AEAD_Free
 *
 * Frees a heap-allocated AEAD context, including all internal state,
 * and securely clears the structure. Sets the caller pointer to NULL.
 * For stack-allocated contexts, only resets internal state without
 * freeing memory.
 *
 * Returns:
 *   CF_SUCCESS      - free/reset completed successfully
 *   CF_ERR_NULL_PTR - if p_ctx or *p_ctx is NULL
 *
 * Parameters:
 *   p_ctx - pointer to pointer of CF_AEAD_CTX to free/reset
 */
CF_API CF_STATUS CF_AEAD_Free(CF_AEAD_CTX **p_ctx);

/*
 * CF_AEAD_Encrypt
 *
 * Performs a one-shot AEAD encryption operation using the specified AEAD,
 * key, IV, optional AAD, and input data. Allocates a temporary stack
 * AEAD context internally, initializes it, processes the input, and
 * finalizes the tag.
 *
 * Returns:
 *   CF_SUCCESS         - encryption successful
 *   CF_ERR_NULL_PTR    - if aead, key, or tag buffer is NULL
 *   other CF_ERR_*     - from CF_AEAD_Init, CF_AEAD_Update, or CF_AEAD_Final
 *
 * Parameters:
 *   aead     - pointer to CF_AEAD descriptor
 *   key      - pointer to encryption key
 *   key_len  - length of key in bytes
 *   iv       - pointer to initialization vector
 *   iv_len   - length of IV in bytes
 *   aad      - pointer to additional authenticated data
 *   aad_len  - length of AAD in bytes
 *   in       - input buffer to encrypt
 *   in_len   - length of input buffer in bytes
 *   out      - output buffer to receive ciphertext
 *   out_len  - pointer to size_t to receive ciphertext length
 *   tag      - output buffer to receive authentication tag
 *   tag_len  - length of tag in bytes
 */
CF_API CF_STATUS CF_AEAD_Encrypt(
    const CF_AEAD *aead,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len,
    uint8_t *tag, size_t tag_len
);

/*
 * CF_AEAD_Decrypt
 *
 * Performs a one-shot AEAD decryption operation using the specified AEAD,
 * key, IV, optional AAD, ciphertext, and authentication tag. Allocates
 * a temporary stack AEAD context internally, initializes it, processes
 * the input, and verifies the tag.
 *
 * Returns:
 *   CF_SUCCESS         - decryption successful and tag valid
 *   CF_ERR_NULL_PTR    - if aead, key, or tag buffer is NULL
 *   CF_ERR_AUTH_FAILED - if authentication tag verification fails
 *   other CF_ERR_*     - from CF_AEAD_Init, CF_AEAD_Update, or CF_AEAD_Final
 *
 * Parameters:
 *   aead     - pointer to CF_AEAD descriptor
 *   key      - pointer to decryption key
 *   key_len  - length of key in bytes
 *   iv       - pointer to initialization vector
 *   iv_len   - length of IV in bytes
 *   aad      - pointer to additional authenticated data
 *   aad_len  - length of AAD in bytes
 *   in       - input buffer containing ciphertext
 *   in_len   - length of input buffer in bytes
 *   out      - output buffer to receive plaintext
 *   out_len  - pointer to size_t to receive plaintext length
 *   tag      - pointer to authentication tag
 *   tag_len  - length of tag in bytes
 */
CF_API CF_STATUS CF_AEAD_Decrypt(
    const CF_AEAD *aead,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len,
    uint8_t *tag, size_t tag_len
);

/*
 * CF_AEAD_EncryptAppendTag
 *
 * Performs a one-shot AEAD encryption where the ciphertext and
 * authentication tag are combined into a single output buffer.
 * Internally allocates a temporary stack AEAD context and appends
 * the fixed-length tag to the ciphertext.
 *
 * Returns:
 *   CF_SUCCESS         - encryption successful
 *   CF_ERR_NULL_PTR    - if aead, key, or IV is NULL
 *   other CF_ERR_*     - from CF_AEAD_EncDec
 *
 * Parameters:
 *   aead     - pointer to CF_AEAD descriptor
 *   key      - pointer to encryption key
 *   key_len  - length of key in bytes
 *   iv       - pointer to initialization vector
 *   iv_len   - length of IV in bytes
 *   aad      - pointer to additional authenticated data
 *   aad_len  - length of AAD in bytes
 *   in       - input buffer to encrypt
 *   in_len   - length of input buffer in bytes
 *   out      - output buffer to receive ciphertext + tag
 *   out_len  - pointer to size_t to receive total output length
 */
CF_API CF_STATUS CF_AEAD_EncryptAppendTag(
    const CF_AEAD *aead,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len
);

/*
 * CF_AEAD_DecryptAppendTag
 *
 * Performs a one-shot AEAD decryption where the input buffer contains
 * ciphertext followed by a fixed-length authentication tag. Splits the
 * tag internally and verifies it.
 *
 * Returns:
 *   CF_SUCCESS         - decryption successful and tag valid
 *   CF_ERR_NULL_PTR    - if aead, key, or IV is NULL
 *   CF_ERR_INVALID_LEN - if input length is smaller than tag length
 *   CF_ERR_AUTH_FAILED - if authentication tag verification fails
 *   other CF_ERR_*     - from CF_AEAD_EncDec
 *
 * Parameters:
 *   aead     - pointer to CF_AEAD descriptor
 *   key      - pointer to decryption key
 *   key_len  - length of key in bytes
 *   iv       - pointer to initialization vector
 *   iv_len   - length of IV in bytes
 *   aad      - pointer to additional authenticated data
 *   aad_len  - length of AAD in bytes
 *   in       - input buffer containing ciphertext + tag
 *   in_len   - total input length (ciphertext + tag)
 *   out      - output buffer to receive plaintext
 *   out_len  - pointer to size_t to receive plaintext length
 */
CF_API CF_STATUS CF_AEAD_DecryptAppendTag(
    const CF_AEAD *aead,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len
);

/*
 * CF_AEAD_CloneCtx
 *
 * Copies a CF_AEAD_CTX structure from src to dst.
 * Performs a deep copy of low-level key and AEAD contexts, and
 * a shallow copy of metadata. dst must be pre-allocated.
 *
 * Returns:
 *   CF_SUCCESS               - context successfully cloned
 *   CF_ERR_NULL_PTR          - if dst or src is NULL
 *   CF_ERR_CTX_UNINITIALIZED - if src->aead is NULL
 *   CF_ERR_CTX_CORRUPT       - if src context appears corrupted
 *   CF_ERR_ALLOC_FAILED      - if memory allocation for key_ctx or aead_ctx fails
 *
 * Parameters:
 *   dst - destination CF_AEAD_CTX
 *   src - source CF_AEAD_CTX
 *
 * Notes:
 *   Cloning allows safe concurrent use of the AEAD context across threads.
 */
CF_API CF_STATUS CF_AEAD_CloneCtx(CF_AEAD_CTX *dst, const CF_AEAD_CTX *src);

/*
 * CF_AEAD_CloneCtxAlloc
 *
 * Allocates a new CF_AEAD_CTX on the heap and clones the source context.
 * Performs a deep copy of low-level key and AEAD contexts and metadata.
 *
 * Returns:
 *   pointer to cloned CF_AEAD_CTX on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   src    - source CF_AEAD_CTX to clone
 *   status - pointer to receive CF_STATUS result
 *
 * Notes:
 *   The cloned context is heap-allocated and can be safely used concurrently
 *   with the source context in different threads.
 */
CF_API CF_AEAD_CTX* CF_AEAD_CloneCtxAlloc(const CF_AEAD_CTX *src, CF_STATUS *status);

/*
 * CF_AEAD_ValidateCtx
 *
 * Validates a CF_AEAD_CTX structure by checking its bound magic value.
 * Detects accidental corruption or misuse of the AEAD context.
 *
 * Returns:
 *   CF_SUCCESS         - if the context is valid
 *   CF_ERR_NULL_PTR    - if ctx is NULL
 *   CF_ERR_CTX_CORRUPT - if the context appears tampered or invalid
 *
 * Parameters:
 *   ctx - pointer to CF_AEAD_CTX to validate
 */
CF_API CF_STATUS CF_AEAD_ValidateCtx(const CF_AEAD_CTX *ctx);

/*
 * CF_AEAD_GetName
 *
 * Returns a short human-readable name describing the AEAD algorithm.
 *
 * Examples:
 *   "AES-GCM"
 *   "ChaCha20-Poly1305"
 *
 * Returns:
 *   name string if AEAD is recognized
 *   "UNKNOWN-AEAD" if AEAD is unrecognized
 *   "NULL" if AEAD pointer is NULL
 *
 * Parameters:
 *   aead - pointer to CF_AEAD
 */
CF_API const char* CF_AEAD_GetName(const CF_AEAD *aead);

/*
 * CF_AEAD_GetFullName
 *
 * Returns a full human-readable name describing the AEAD algorithm and
 * key size associated with the provided context.
 *
 * Examples:
 *   "AES-256-GCM"
 *   "ChaCha20-Poly1305"
 *
 * Returns:
 *   full name string if context and AEAD are valid
 *   "UNKNOWN-AEAD" if unrecognized
 *   "NULL" if ctx or ctx->aead is NULL
 *
 * Parameters:
 *   ctx - pointer to CF_AEAD_CTX
 */
CF_API const char* CF_AEAD_GetFullName(const CF_AEAD_CTX *ctx);

/*
 * CF_AEAD_IsValidKeyLength
 *
 * Validates whether the provided key length is valid for the specified AEAD.
 *
 * Returns:
 *   true  - if key_len is valid for the AEAD
 *   false - otherwise
 *
 * Parameters:
 *   aead    - pointer to CF_AEAD
 *   key_len - length of key in bytes
 */
CF_API bool CF_AEAD_IsValidKeyLength(const CF_AEAD *aead, size_t key_len);

/*
 * CF_AEAD_IsValidTagLength
 *
 * Validates whether the provided authentication tag length is valid for the AEAD.
 *
 * Returns:
 *   true  - if tag_len is valid for the AEAD
 *   false - otherwise
 *
 * Parameters:
 *   aead    - pointer to CF_AEAD
 *   tag_len - length of tag in bytes
 */
CF_API bool CF_AEAD_IsValidTagLength(const CF_AEAD *aead, size_t tag_len);

/*
 * CF_AEAD_GetValidKeySizes
 *
 * Returns an array of valid key sizes (in bytes) for the specified AEAD.
 *
 * Returns:
 *   pointer to static array of key sizes on success
 *   NULL if aead is NULL or unrecognized
 *   *count is set to the number of valid key sizes
 *
 * Parameters:
 *   aead  - pointer to CF_AEAD
 *   count - pointer to size_t to receive number of key sizes
 */
CF_API const size_t* CF_AEAD_GetValidKeySizes(const CF_AEAD *aead, size_t *count);

/*
 * CF_AEAD_GetValidTagSizes
 *
 * Returns an array of valid authentication tag sizes (in bytes) for the AEAD.
 *
 * Returns:
 *   pointer to static array of tag sizes on success
 *   NULL if aead is NULL or unrecognized
 *   *count is set to the number of valid tag sizes
 *
 * Parameters:
 *   aead  - pointer to CF_AEAD
 *   count - pointer to size_t to receive number of tag sizes
 */
CF_API const size_t* CF_AEAD_GetValidTagSizes(const CF_AEAD *aead, size_t *count);

/*
 * CF_AEAD_GetMaxTagSize
 *
 * Returns the maximum supported authentication tag size (in bytes) for the AEAD.
 *
 * Returns:
 *   max tag size if AEAD is recognized
 *   0 if aead is NULL or unrecognized
 *
 * Parameters:
 *   aead - pointer to CF_AEAD
 */
CF_API size_t CF_AEAD_GetMaxTagSize(const CF_AEAD *aead);

#ifdef __cplusplus
}
#endif

#endif // CF_AEAD_H