/*
 * CryptoForge - cf_cipher.h / High-level cipher context and utility definitions
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

#ifndef CF_CIPHER_H
#define CF_CIPHER_H

#include <CryptoForge/cf_flags.h>
#include <CryptoForge/cf_defs.h>
#include <CryptoForge/cf_status.h>
#include <CryptoForge/cf_exports.h>

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// Cipher Algorithm Descriptor
// ============================
// Describes a block or stream cipher implementation.
// Each CF_CIPHER instance is static, immutable, and shared across contexts.
typedef struct _CF_CIPHER {

    // Unique cipher identifier / flag.
    uint32_t id;

    // Size of the low-level cipher context (for allocation/stack usage).
    size_t ctx_size;

    // Size of the expanded key context.
    // For stream ciphers this may be equal to ctx_size or zero.
    size_t key_ctx_size;

    // Block size in bytes.
    // * Non-zero for block ciphers (e.g., AES-ECB = 16)
    // * Zero for stream ciphers (e.g., ChaCha20)
    size_t block_size;

    // --- Low-level entry points ---
    // Implement algorithm-specific logic; invoked by high-level API.

    // Initializes the low-level cipher context and prepares
    // expanded key material or internal state.
    // Must be called before encryption or decryption.
    bool (*cipher_init_fn)(CF_CIPHER_CTX *ctx, CF_CIPHER_OPTS *opts);

    // Encrypts input data.
    // May be called once or multiple times depending on mode.
    // Writes ciphertext to `out` and sets `out_len`.
    bool (*cipher_enc_fn)(
        const CF_CIPHER_CTX *ctx,
        const uint8_t *in,
        size_t in_len,
        uint8_t *out,
        size_t *out_len,
        uint8_t *ctr_block,
        const CF_CIPHER_OPTS *opts
    );

    // Decrypts input data.
    // Writes plaintext to `out` and sets `out_len`.
    // Behavior is mode-dependent (stream vs block).
    bool (*cipher_dec_fn)(
        const CF_CIPHER_CTX *ctx,
        const uint8_t *in,
        size_t in_len,
        uint8_t *out,
        size_t *out_len,
        uint8_t *ctr_block,
        const CF_CIPHER_OPTS *opts
    );

} CF_CIPHER;

// ============================
// Optional Cipher Parameters
// ============================
// Parameters that modify cipher behavior (IVs, nonces, counters, mode state).
// All pointer fields are borrowed and must remain valid for the duration
// of the cipher operation.
typedef struct _CF_CIPHER_OPTS {

    // Integrity guard (CF_CTX_MAGIC).
    // Verified by public API entry points.
    uint32_t magic;

    // --- IV / Nonce ---
    // Initialization vector or nonce.
    // Size and meaning depend on the selected cipher/mode.
    uint8_t iv[CF_MAX_CIPHER_IV_SIZE];
    size_t iv_len;

    // --- AES-CTR specific ---
    // 16-byte counter/IV block used internally for AES-CTR mode.
    // Maintained across block operations.
    uint8_t ctr_block[CF_AES_BLOCK_SIZE];

    // --- ChaCha / XChaCha specific ---
    // 32-bit initial block counter.
    // Used for stream position control.
    uint32_t chacha_counter;

    // Indicates whether this structure was heap allocated.
    // If set, it must be released via the appropriate free routine.
    int isHeapAlloc;

} CF_CIPHER_OPTS;

// ============================
// Cipher Context
// ============================
// Holds runtime state for a single encryption or decryption operation.
// By default, not thread-safe; concurrent usage requires independent contexts.
typedef struct _CF_CIPHER_CTX {

    // Integrity guard: CF_CTX_MAGIC ^ (uintptr_t)cipher.
    uint64_t magic;

    // Descriptor is static and immutable.
    const CF_CIPHER *cipher;

    // Optional user-supplied parameters (borrowed or owned depending on allocation).
    CF_CIPHER_OPTS *opts;

    // Pointer to low-level cipher state (algorithm-specific context).
    void *cipher_ctx;

    // Pointer to expanded key material.
    // May be NULL for ciphers that do not require separate expansion.
    void *key_ctx;

    // Raw user-supplied key (borrowed).
    // The library does not assume ownership unless explicitly documented.
    const uint8_t *key;
    size_t key_len;

    // Operation mode (encrypt or decrypt).
    // Set during initialization and enforced by public API.
    CF_OPERATION operation;

    // Indicates whether this structure was heap allocated.
    // If set, it must be released via the appropriate free routine.
    int isHeapAlloc;

} CF_CIPHER_CTX;

/*
 * CF_Cipher_GetByFlag
 *
 * Retrieves a pointer to a CF_CIPHER descriptor based on a cipher flag.
 * Iterates the internal cf_Cipher_table and invokes the associated getter function.
 *
 * Returns:
 *   pointer to CF_CIPHER - if flag matches a supported cipher
 *   NULL                 - if flag is invalid or unsupported
 *
 * Parameters:
 *   cipher_flag - algorithm identifier flag (e.g., CF_AES_ECB, CF_CHACHA20)
 */
CF_API const CF_CIPHER *CF_Cipher_GetByFlag(uint32_t cipher_flag);

/*
 * CF_Cipher_Init
 *
 * Initializes a stack-allocated cipher context for encryption or decryption.
 * Validates parameters, sets up internal key and cipher memory, and prepares
 * the context for one-shot or streaming operations.
 *
 * Returns:
 *   CF_SUCCESS                  - initialization succeeded
 *   CF_ERR_NULL_PTR             - if ctx, cipher, or key is NULL
 *   CF_ERR_UNSUPPORTED          - if cipher type is invalid or not recognized
 *   CF_ERR_CTX_CORRUPT          - if options or low-level initialization fails
 *   CF_ERR_CTX_UNINITIALIZED    - if heap allocation flag is invalid
 *   CF_ERR_INVALID_PARAM        - if operation mode or IV length is invalid
 *   CF_ERR_CTX_OPTS_UNINITIALIZED - if required opts (e.g., IV) are missing
 *   CF_ERR_CIPHER_INVALID_KEY_LEN - if key length is invalid for cipher
 *   CF_ERR_ALLOC_FAILED         - memory allocation for key or cipher context failed
 *   CF_ERR_CIPHER_KEY_SETUP     - AES key schedule setup failed
 *
 * Parameters:
 *   ctx     - pointer to stack-allocated CF_CIPHER_CTX
 *   cipher  - pointer to CF_CIPHER descriptor
 *   opts    - optional cipher options (may be NULL)
 *   key     - pointer to encryption/decryption key
 *   key_len - length of key in bytes
 *   op      - operation mode (CF_OP_ENCRYPT or CF_OP_DECRYPT)
 */
CF_API CF_STATUS CF_Cipher_Init(
    CF_CIPHER_CTX *ctx, const CF_CIPHER *cipher, CF_CIPHER_OPTS *opts,
    const uint8_t *key, size_t key_len, CF_OPERATION op
);

/*
 * CF_Cipher_InitAlloc
 *
 * Allocates a new CF_CIPHER_CTX on the heap and initializes it for encryption
 * or decryption with the specified cipher and options. Marks the context as
 * heap-allocated for proper cleanup via CF_Cipher_Free.
 *
 * Returns:
 *   pointer to allocated CF_CIPHER_CTX - on success
 *   NULL                               - on failure, with *status set
 *
 * Parameters:
 *   cipher - pointer to CF_CIPHER descriptor
 *   opts   - optional cipher options (may be NULL)
 *   key    - pointer to encryption/decryption key
 *   key_len - length of key in bytes
 *   op     - operation mode (CF_OP_ENCRYPT or CF_OP_DECRYPT)
 *   status - pointer to receive CF_STATUS result
 */
CF_API CF_CIPHER_CTX* CF_Cipher_InitAlloc(
    const CF_CIPHER *cipher, CF_CIPHER_OPTS *opts,
    const uint8_t *key, size_t key_len, 
    CF_OPERATION op, CF_STATUS *status
);

/*
 * CF_Cipher_Process
 *
 * Processes input data through an initialized cipher context. Performs
 * encryption or decryption depending on ctx->operation. Supports both
 * stream and block ciphers. For block ciphers, input length must be a
 * multiple of the block size.
 *
 * Returns:
 *   CF_SUCCESS               - processing succeeded
 *   CF_ERR_NULL_PTR          - if ctx, in, or out is NULL
 *   CF_ERR_CTX_UNINITIALIZED - if cipher or key context not initialized
 *   CF_ERR_CTX_CORRUPT       - context integrity check failed (magic mismatch)
 *   CF_ERR_INVALID_PARAM     - input length not multiple of block size (block cipher)
 *   CF_ERR_CIPHER_ENCRYPT    - internal encryption failed
 *   CF_ERR_CIPHER_DECRYPT    - internal decryption failed
 *
 * Parameters:
 *   ctx      - pointer to initialized CF_CIPHER_CTX
 *   in       - input buffer to encrypt/decrypt
 *   in_len   - length of input buffer in bytes
 *   out      - output buffer to receive processed data
 *   out_len  - pointer to receive number of bytes written
 */
CF_API CF_STATUS CF_Cipher_Process(
    CF_CIPHER_CTX *ctx,
    const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len
);

/*
 * CF_Cipher_Reset
 *
 * Resets a cipher context to an empty state, freeing any low-level
 * key or cipher memory. Clears all fields to prevent accidental reuse
 * or leakage of sensitive data.
 *
 * Returns:
 *   CF_SUCCESS               - reset completed successfully
 *   CF_ERR_NULL_PTR          - if ctx is NULL
 *   CF_ERR_CTX_UNINITIALIZED - if ctx->cipher is NULL
 *   CF_ERR_CTX_CORRUPT       - if internal sizes or pointers are inconsistent
 *
 * Parameters:
 *   ctx - pointer to CF_CIPHER_CTX to reset
 */
CF_API CF_STATUS CF_Cipher_Reset(CF_CIPHER_CTX *ctx);

/*
 * CF_Cipher_Free
 *
 * Frees a heap-allocated cipher context, including all internal state,
 * and securely clears the structure. Sets the caller pointer to NULL.
 * For stack-allocated contexts, only resets internal state without freeing.
 *
 * Returns:
 *   CF_SUCCESS      - free/reset completed successfully
 *   CF_ERR_NULL_PTR - if p_ctx or *p_ctx is NULL
 *
 * Parameters:
 *   p_ctx - pointer to pointer of CF_CIPHER_CTX to free/reset
 */
CF_API CF_STATUS CF_Cipher_Free(CF_CIPHER_CTX **p_ctx);

/*
 * CF_Cipher_Encrypt
 *
 * Performs a one-shot encryption operation using the specified cipher,
 * key, and optional cipher options. Internally allocates a temporary
 * stack cipher context, initializes it, processes the input, and resets
 * the context securely.
 *
 * Returns:
 *   CF_SUCCESS         - encryption successful
 *   CF_ERR_NULL_PTR    - if cipher, key, or output buffer is NULL
 *   other CF_ERR_*     - from CF_Cipher_Init or CF_Cipher_Process
 *
 * Parameters:
 *   cipher   - pointer to CF_CIPHER descriptor
 *   key      - pointer to encryption key
 *   key_len  - length of key in bytes
 *   in       - input buffer to encrypt
 *   in_len   - length of input buffer in bytes
 *   out      - output buffer to receive ciphertext
 *   out_len  - pointer to size_t to receive output length
 *   opts     - optional CF_CIPHER_OPTS (can be NULL)
 */
CF_API CF_STATUS CF_Cipher_Encrypt(
    const CF_CIPHER *cipher,
    const uint8_t *key, size_t key_len,
    const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len,
    CF_CIPHER_OPTS *opts
);

/*
 * CF_Cipher_Decrypt
 *
 * Performs a one-shot decryption operation using the specified cipher,
 * key, and optional cipher options. Internally allocates a temporary
 * stack cipher context, initializes it, processes the input, and resets
 * the context securely.
 *
 * Returns:
 *   CF_SUCCESS         - decryption successful
 *   CF_ERR_NULL_PTR    - if cipher, key, or output buffer is NULL
 *   other CF_ERR_*     - from CF_Cipher_Init or CF_Cipher_Process
 *
 * Parameters:
 *   cipher   - pointer to CF_CIPHER descriptor
 *   key      - pointer to decryption key
 *   key_len  - length of key in bytes
 *   in       - input buffer to decrypt
 *   in_len   - length of input buffer in bytes
 *   out      - output buffer to receive plaintext
 *   out_len  - pointer to size_t to receive output length
 *   opts     - optional CF_CIPHER_OPTS (can be NULL)
 */
CF_API CF_STATUS CF_Cipher_Decrypt(
    const CF_CIPHER *cipher,
    const uint8_t *key, size_t key_len,
    const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len,
    CF_CIPHER_OPTS *opts
);

/*
 * CF_Cipher_CloneCtx
 *
 * Copies a CF_CIPHER_CTX structure from src to dst.
 * Performs a deep copy of the low-level key and cipher contexts, and
 * a shallow copy of metadata and options. dst must be pre-allocated.
 *
 * Returns:
 *   CF_SUCCESS               - context successfully cloned
 *   CF_ERR_NULL_PTR          - if dst or src is NULL
 *   CF_ERR_CTX_UNINITIALIZED - if src->cipher is NULL
 *   CF_ERR_CTX_CORRUPT       - if src context appears corrupted (magic mismatch)
 *   CF_ERR_ALLOC_FAILED      - if memory allocation for key_ctx or cipher_ctx fails
 *
 * Parameters:
 *   dst - destination CF_CIPHER_CTX
 *   src - source CF_CIPHER_CTX
 *
 * Notes:
 *   Cloning allows safe concurrent use of the cipher context across threads.
 */
CF_API CF_STATUS CF_Cipher_CloneCtx(CF_CIPHER_CTX *dst, const CF_CIPHER_CTX *src);

/*
 * CF_Cipher_CloneCtxAlloc
 *
 * Allocates a new CF_CIPHER_CTX on the heap and clones the source context.
 * Performs a deep copy of low-level key and cipher contexts and metadata.
 *
 * Returns:
 *   pointer to cloned CF_CIPHER_CTX on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   src    - source CF_CIPHER_CTX to clone
 *   status - pointer to receive CF_STATUS result
 *
 * Notes:
 *   The cloned context is heap-allocated and can be safely used concurrently
 *   with the source context in different threads.
 */
CF_API CF_CIPHER_CTX* CF_Cipher_CloneCtxAlloc(const CF_CIPHER_CTX *src, CF_STATUS *status);

/*
 * CF_Cipher_ValidateCtx
 *
 * Validates a CF_CIPHER_CTX structure by checking its bound magic value.
 * Detects accidental corruption or misuse of the cipher context.
 *
 * Returns:
 *   CF_SUCCESS         - if the context is valid
 *   CF_ERR_NULL_PTR    - if ctx is NULL
 *   CF_ERR_CTX_CORRUPT - if the context appears tampered or invalid
 *
 * Parameters:
 *   ctx - pointer to CF_CIPHER_CTX to validate
 */
CF_API CF_STATUS CF_Cipher_ValidateCtx(const CF_CIPHER_CTX *ctx);

/*
 * CF_Cipher_GetName
 *
 * Returns a short human-readable name describing the cipher.
 *
 * Examples:
 *   "AES-ECB"
 *   "ChaCha20"
 *
 * Returns:
 *   name string if cipher is recognized
 *   "UNKNOWN-CIPHER" if cipher is unrecognized
 *   "NULL" if cipher pointer is NULL
 *
 * Parameters:
 *   cipher - pointer to CF_CIPHER
 */
CF_API const char* CF_Cipher_GetName(const CF_CIPHER *cipher);

/*
 * CF_Cipher_GetFullName
 *
 * Returns a full human-readable name describing the cipher and key size
 * associated with the provided context.
 *
 * Examples:
 *   "AES-256-CBC"
 *   "ChaCha20-256"
 *
 * Returns:
 *   full name string if context and cipher are valid
 *   "UNKNOWN-CIPHER" if unrecognized
 *   "NULL" if ctx or ctx->cipher is NULL
 *
 * Parameters:
 *   ctx - pointer to CF_CIPHER_CTX
 */
CF_API const char* CF_Cipher_GetFullName(const CF_CIPHER_CTX *ctx);

/*
 * CF_Cipher_IsValidKeyLength
 *
 * Validates whether the provided key length is valid for the specified cipher.
 *
 * Returns:
 *   true  - if key_len is valid for the cipher
 *   false - otherwise
 *
 * Parameters:
 *   cipher  - pointer to CF_CIPHER
 *   key_len - length of key in bytes
 */
CF_API bool CF_Cipher_IsValidKeyLength(const CF_CIPHER *cipher, size_t key_len);

/*
 * CF_Cipher_GetValidKeySizes
 *
 * Returns an array of valid key sizes (in bytes) for the specified cipher.
 *
 * Returns:
 *   pointer to static array of key sizes on success
 *   NULL if cipher is NULL or unrecognized
 *   *count is set to the number of valid key sizes
 *
 * Parameters:
 *   cipher - pointer to CF_CIPHER
 *   count  - pointer to size_t to receive number of key sizes
 */
CF_API const size_t* CF_Cipher_GetValidKeySizes(const CF_CIPHER *cipher, size_t *count);

/*
 * CF_Cipher_GetBlockSize
 *
 * Returns the block size (in bytes) of the cipher bound to the context.
 * Returns 0 for stream ciphers or invalid contexts.
 *
 * Parameters:
 *   ctx - pointer to CF_CIPHER_CTX
 */
CF_API size_t CF_Cipher_GetBlockSize(const CF_CIPHER_CTX *ctx);

/*
 * CF_Cipher_GetOutputLength
 *
 * Computes the expected output length (in bytes) for a given input length,
 * accounting for block alignment for block ciphers.
 *
 * Returns:
 *   padded length if block cipher
 *   in_len if stream cipher
 *   0 if ctx, ctx->cipher, or in_len is invalid
 *
 * Parameters:
 *   ctx    - pointer to CF_CIPHER_CTX
 *   in_len - input length in bytes
 */
CF_API size_t CF_Cipher_GetOutputLength(const CF_CIPHER_CTX *ctx, size_t in_len);

/*
 * CF_CipherOpts_Init
 *
 * Initializes a CF_CIPHER_OPTS context with optional IV, AES counter block, and ChaCha counter.
 * Performs a deep copy of IV and AES counter block, shallow copy of ChaCha counter.
 *
 * Returns:
 *   CF_SUCCESS         - on success
 *   CF_ERR_NULL_PTR    - if opts is NULL
 *   CF_ERR_INVALID_LEN - if iv_len exceeds CF_MAX_CIPHER_IV_SIZE
 *
 * Parameters:
 *   opts           - pointer to a CF_CIPHER_OPTS struct to initialize
 *   iv             - optional initialization vector (can be NULL)
 *   iv_len         - length of IV in bytes
 *   ctr_block      - optional AES counter block (can be NULL)
 *   chacha_counter - optional ChaCha counter, pass 0 for default
 */
CF_API CF_STATUS CF_CipherOpts_Init(
    CF_CIPHER_OPTS *opts,
    const uint8_t *iv, size_t iv_len,
    const uint8_t ctr_block[CF_AES_BLOCK_SIZE],
    uint32_t chacha_counter
);

/*
 * CF_CipherOpts_InitAlloc
 *
 * Allocates a new CF_CIPHER_OPTS struct on the heap and initializes it.
 * Performs deep copy of IV and AES counter block, shallow copy of ChaCha counter.
 *
 * Returns:
 *   pointer to allocated CF_CIPHER_OPTS on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   iv             - optional initialization vector (can be NULL)
 *   iv_len         - length of IV in bytes
 *   ctr_block      - optional AES counter block (can be NULL)
 *   chacha_counter - optional ChaCha counter, pass 0 for default
 *   status         - pointer to receive CF_STATUS result
 */
CF_API CF_CIPHER_OPTS* CF_CipherOpts_InitAlloc(
    const uint8_t *iv, size_t iv_len,
    const uint8_t ctr_block[CF_AES_BLOCK_SIZE],
    uint32_t chacha_counter,
    CF_STATUS *status
);

/*
 * CF_CipherOpts_Reset
 *
 * Resets a CF_CIPHER_OPTS context to zeroed state.
 * Clears IV, AES counter, ChaCha counter, and magic field.
 *
 * Returns:
 *   CF_SUCCESS      - on success
 *   CF_ERR_NULL_PTR - if opts is NULL
 *
 * Parameters:
 *   opts - pointer to CF_CIPHER_OPTS to reset
 */
CF_API CF_STATUS CF_CipherOpts_Reset(CF_CIPHER_OPTS *opts);

/*
 * CF_CipherOpts_Free
 *
 * Frees a CF_CIPHER_OPTS struct if heap-allocated.
 * Resets the context and sets caller's pointer to NULL.
 *
 * Returns:
 *   CF_SUCCESS      - on success
 *   CF_ERR_NULL_PTR - if p_opts or *p_opts is NULL
 *
 * Parameters:
 *   p_opts - pointer to the pointer of CF_CIPHER_OPTS
 */
CF_API CF_STATUS CF_CipherOpts_Free(CF_CIPHER_OPTS **p_opts);

/*
 * CF_CipherOpts_CloneCtx
 *
 * Copies a CF_CIPHER_OPTS context from src to dst.
 * Performs deep copy of IV and AES counter, shallow copy of ChaCha counter.
 * dst must be pre-allocated.
 *
 * Returns:
 *   CF_SUCCESS         - on success
 *   CF_ERR_NULL_PTR    - if dst or src is NULL
 *   CF_ERR_CTX_CORRUPT - if src magic value is invalid
 *
 * Parameters:
 *   dst - destination CF_CIPHER_OPTS struct
 *   src - source CF_CIPHER_OPTS struct
 */
CF_API CF_STATUS CF_CipherOpts_CloneCtx(CF_CIPHER_OPTS *dst, const CF_CIPHER_OPTS *src);

/*
 * CF_CipherOpts_CloneCtxAlloc
 *
 * Allocates a new CF_CIPHER_OPTS on the heap and clones the source context.
 * Performs deep copy of IV and AES counter, shallow copy of ChaCha counter.
 *
 * Returns:
 *   pointer to cloned CF_CIPHER_OPTS on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   src    - source CF_CIPHER_OPTS to clone
 *   status - pointer to receive CF_STATUS result
 */
CF_API CF_CIPHER_OPTS* CF_CipherOpts_CloneCtxAlloc(const CF_CIPHER_OPTS *src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // CF_CIPHER_H