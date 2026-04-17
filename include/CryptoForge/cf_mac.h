/*
 * CryptoForge - cf_mac.h / High-level MAC context and utility definitions
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

#ifndef CF_MAC_H
#define CF_MAC_H

#include <CryptoForge/cf_flags.h>
#include <CryptoForge/cf_defs.h>
#include <CryptoForge/cf_status.h>
#include <CryptoForge/cf_exports.h>

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// MAC Algorithm Descriptor
// ============================
// Describes a MAC algorithm implementation.
// Each CF_MAC instance is static, immutable, and shared across contexts.
typedef struct _CF_MAC {

    // Unique algorithm identifier / flag.
    uint32_t id;

    // Size (in bytes) required for the internal MAC state.
    size_t ctx_size;

    // Size (in bytes) required for optional key-specific state (AES-CMAC/GMAC).
    size_t key_ctx_size;

    // Default authentication tag length (in bytes).
    size_t default_tag_len;

    // --- Low-level entry points ---
    // Implement algorithm-specific logic; invoked by high-level API.

    // Initializes the context and binds key material.
    // Must be called before any update/final operations.
    CF_STATUS (*mac_init_fn)(
        struct _CF_MAC_CTX *ctx,
        const struct _CF_MAC_OPTS *opts);

    // Processes input data.
    // Can be called multiple times after initialization.
    CF_STATUS (*mac_update_fn)(
        struct _CF_MAC_CTX *ctx,
        const uint8_t *data,
        size_t data_len);

    // Finalizes computation and writes the authentication tag.
    // Transition: context moves to "finalized" state; further updates require reset.
    CF_STATUS (*mac_final_fn)(
        struct _CF_MAC_CTX *ctx,
        uint8_t *tag,
        size_t tag_len);

    // Resets the context to its initial state.
    // Allows reuse with the same key or new key material.
    CF_STATUS (*mac_reset_fn)(
        struct _CF_MAC_CTX *ctx);

    // Convenience routine: processes data and verifies tag.
    // Must be implemented in constant time to prevent timing attacks.
    CF_STATUS (*mac_verify_fn)(
        struct _CF_MAC_CTX *ctx,
        const uint8_t *data,
        size_t data_len,
        const uint8_t *expected_tag,
        size_t expected_tag_len,
        const struct _CF_MAC_OPTS *opts);

    // Clones internal state from src to dest.
    // Useful for checkpointing or branching computation.
    CF_STATUS (*mac_clone_ctx_fn)(
        struct _CF_MAC_CTX *ctx_dest,
        const struct _CF_MAC_CTX *ctx_src);

} CF_MAC;

// ============================
// Optional MAC Parameters
// ============================
// Parameters that modify MAC behavior.
// All pointer fields are borrowed and must remain valid for the duration
// of the MAC operation.
typedef struct _CF_MAC_OPTS {

    // Integrity guard (CF_CTX_MAGIC).
    // Verified by public API entry points.
    uint32_t magic;

    // Optional initialization vector (CMAC/GMAC).
    // Only the first iv_len bytes are used.
    uint8_t iv[CF_AES_BLOCK_SIZE];
    size_t iv_len;

    // Optional customization string (KMAC).
    const uint8_t *S;
    size_t S_len;

    // Indicates whether this structure was heap allocated.
    // If set, it must be released via the appropriate free routine.
    int isHeapAlloc;

} CF_MAC_OPTS;

// ============================
// MAC Context
// ============================
// Holds runtime state for a single MAC computation.
// By default, not thread-safe; concurrent usage requires cloning via the library-provided clone function.
typedef struct _CF_MAC_CTX {

    // Integrity guard: CF_CTX_MAGIC ^ (uintptr_t)mac.
    uint64_t magic;

    // --- Algorithm binding (library-owned) ---
    const CF_MAC *mac;       // Descriptor is static and immutable
    const CF_HASH *hash;     // Optional hash descriptor (HMAC)
    const CF_MAC_OPTS *opts; // Optional user-supplied parameters (borrowed)

    // --- Internal state (library-managed) ---
    void *mac_ctx;           // Low-level MAC state
    void *key_ctx;           // Optional key-specific state (AES-CMAC/GMAC)

    // --- User inputs (borrowed) ---
    const uint8_t *key;      // Key material; must remain valid until init completes
    size_t key_len;

    // Requested tag length or the default tag length
    size_t tag_len;

    // Algorithm-specific flags
    uint32_t subflags;

    // True if mac_final_fn has been called
    int isFinalized;

    // Indicates whether this structure was heap allocated.
    // If set, it must be released via the appropriate free routine.
    int isHeapAlloc;

} CF_MAC_CTX;

/*
 * CF_MAC_GetByFlag
 *
 * Retrieves a pointer to a CF_MAC descriptor based on a MAC algorithm flag.
 * Iterates the internal cf_mac_table and calls the associated getter function.
 *
 * Returns:
 *   pointer to CF_MAC  - if flag matches a supported MAC
 *   NULL               - if flag is invalid or unsupported
 *
 * Parameters:
 *   algo_flag - algorithm identifier flag (e.g., CF_HMAC, CF_KMAC_STD)
 */
CF_API const CF_MAC *CF_MAC_GetByFlag(uint32_t mac_flag);

/*
 * CF_MAC_Init
 *
 * Initializes a stack-allocated MAC context for one-shot or streaming
 * operations. Validates parameters, sets up internal state, allocates
 * MAC-specific buffers, and prepares the context for updates and finalization.
 *
 * Returns:
 *   CF_SUCCESS                    - initialization succeeded
 *   CF_ERR_NULL_PTR               - if ctx, mac, or key is NULL
 *   CF_ERR_UNSUPPORTED            - unsupported MAC type or hash
 *   CF_ERR_INVALID_PARAM          - invalid subflags or key/IV for MAC
 *   CF_ERR_CIPHER_INVALID_KEY_LEN - invalid AES key length
 *   CF_ERR_ALLOC_FAILED           - memory allocation failed
 *   CF_ERR_CIPHER_KEY_SETUP       - AES key expansion failed
 *   CF_ERR_CTX_CORRUPT            - inconsistent context sizes
 *
 * Parameters:
 *   ctx      - pointer to stack-allocated CF_MAC_CTX
 *   mac      - pointer to CF_MAC descriptor
 *   opts     - optional MAC options (can be NULL)
 *   key      - pointer to key bytes
 *   key_len  - length of key in bytes
 *   subflags - MAC-specific flags (hash type, KMAC variant, etc.)
 */
CF_API CF_STATUS CF_MAC_Init(CF_MAC_CTX *ctx, const CF_MAC *mac, const CF_MAC_OPTS *opts,
                             const uint8_t *key, size_t key_len, uint32_t subflags);

/*
 * CF_MAC_InitAlloc
 *
 * Allocates and initializes a heap-allocated MAC context. Equivalent to
 * CF_MAC_Init but allocates memory on the heap and marks the context as
 * heap-owned for automatic cleanup via CF_MAC_Free.
 *
 * Returns:
 *   pointer to CF_MAC_CTX         - on success
 *   NULL                          - on failure (status set accordingly)
 *
 * Parameters:
 *   mac      - pointer to CF_MAC descriptor
 *   opts     - optional MAC options (can be NULL)
 *   key      - pointer to key bytes
 *   key_len  - length of key in bytes
 *   subflags - MAC-specific flags
 *   status   - optional pointer to receive CF_STATUS result
 */
CF_API CF_MAC_CTX* CF_MAC_InitAlloc(const CF_MAC *mac, const CF_MAC_OPTS *opts,
                                    const uint8_t *key, size_t key_len, uint32_t subflags,
                                    CF_STATUS *status);

/*
 * CF_MAC_Update
 *
 * Feeds input data into an initialized MAC context. Can be called
 * repeatedly for streaming input before calling CF_MAC_Final.
 *
 * Returns:
 *   CF_SUCCESS               - update succeeded
 *   CF_ERR_NULL_PTR          - ctx is NULL
 *   CF_ERR_CTX_UNINITIALIZED - context not initialized
 *   CF_ERR_CTX_CORRUPT       - context integrity check failed
 *   CF_ERR_MAC_FINALIZED     - context already finalized
 *
 * Parameters:
 *   ctx      - pointer to initialized CF_MAC_CTX
 *   data     - pointer to input data bytes
 *   data_len - length of input data in bytes
 */
CF_API CF_STATUS CF_MAC_Update(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len);

/*
 * CF_MAC_Final
 *
 * Finalizes a MAC computation and writes the authentication tag to the
 * provided buffer. After finalization, the context is marked as finalized
 * and cannot be updated further without reinitialization.
 *
 * Returns:
 *   CF_SUCCESS                  - finalization succeeded
 *   CF_ERR_NULL_PTR             - ctx or tag is NULL
 *   CF_ERR_CTX_UNINITIALIZED    - context or MAC not initialized
 *   CF_ERR_CTX_CORRUPT          - context integrity check failed
 *   CF_ERR_INVALID_LEN          - invalid tag length
 *   CF_ERR_MAC_INVALID_TAG_LEN  - tag length not supported by MAC type
 *
 * Parameters:
 *   ctx      - pointer to initialized CF_MAC_CTX
 *   tag      - pointer to buffer to receive computed MAC
 *   tag_len  - length of tag buffer in bytes
 */
CF_API CF_STATUS CF_MAC_Final(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len);

/*
 * CF_MAC_Reset
 *
 * Resets a MAC context to its initial, empty state. Frees any internal
 * key or MAC-specific context memory, and clears all fields to prevent
 * accidental reuse or leakage of sensitive data.
 *
 * Returns:
 *   CF_SUCCESS               - reset completed successfully
 *   CF_ERR_NULL_PTR          - if ctx is NULL
 *   CF_ERR_CTX_UNINITIALIZED - if ctx->mac is NULL
 *   CF_ERR_UNSUPPORTED       - if the MAC type is invalid
 *   CF_ERR_CTX_CORRUPT       - if internal sizes are inconsistent
 *
 * Parameters:
 *   ctx - pointer to CF_MAC_CTX to reset
 */
CF_API CF_STATUS CF_MAC_Reset(CF_MAC_CTX *ctx);

/*
 * CF_MAC_Free
 *
 * Frees a heap-allocated MAC context, including all internal state,
 * and securely clears the structure. Sets the caller pointer to NULL.
 * For stack-allocated contexts, only resets internal state without
 * freeing memory.
 *
 * Returns:
 *   CF_SUCCESS      - free/reset completed successfully
 *   CF_ERR_NULL_PTR - if p_ctx or *p_ctx is NULL
 *
 * Parameters:
 *   p_ctx - pointer to pointer of CF_MAC_CTX to free/reset
 */
CF_API CF_STATUS CF_MAC_Free(CF_MAC_CTX **p_ctx);

/*
 * CF_MAC_Verify
 *
 * Verifies that a computed MAC matches the expected value. Performs a
 * one-shot computation using the specified key, MAC algorithm, options,
 * and subflags, then compares the result with expected_mac.
 *
 * Returns:
 *   CF_SUCCESS        - verification succeeded, tags match
 *   CF_ERR_NULL_PTR   - if any pointer (mac, key, data, expected_mac) is NULL
 *   CF_ERR_CTX_CORRUPT or other CF_ERR_* from underlying MAC functions
 *
 * Parameters:
 *   mac               - pointer to CF_MAC descriptor
 *   key               - pointer to key bytes
 *   key_len           - length of the key in bytes
 *   data              - pointer to data to verify
 *   data_len          - length of data in bytes
 *   expected_mac      - pointer to the expected MAC tag
 *   expected_mac_len  - length of expected MAC tag
 *   opts              - optional MAC options (can be NULL)
 *   subflags          - algorithm-specific subflags (e.g., hash variant)
 */
CF_API CF_STATUS CF_MAC_Verify(const CF_MAC *mac,
                               const uint8_t *key, size_t key_len,
                               const uint8_t *data, size_t data_len,
                               const uint8_t *expected_mac, size_t expected_mac_len,
                               const CF_MAC_OPTS *opts, uint32_t subflags);

/*
 * CF_MAC_Compute
 *
 * Performs a one-shot MAC computation on the input data using the specified MAC algorithm,
 * key, options, and subflags. The function internally creates a temporary MAC context on the stack,
 * initializes it, updates it with the data, and finalizes it to produce the authentication tag.
 *
 * Returns:
 *   CF_SUCCESS         - MAC successfully computed
 *   CF_ERR_NULL_PTR    - if mac, key, or tag pointer is NULL
 *   CF_ERR_CTX_CORRUPT - if context integrity fails during computation
 *   CF_ERR_INVALID_LEN - if tag_len is invalid for the chosen MAC
 *   other CF_ERR_*     - from underlying CF_MAC_Init, CF_MAC_Update, or CF_MAC_Final
 *
 * Parameters:
 *   mac       - pointer to the CF_MAC descriptor describing the algorithm
 *   key       - pointer to the key bytes
 *   key_len   - length of the key in bytes
 *   data      - pointer to the input data to authenticate
 *   data_len  - length of the input data in bytes
 *   tag       - pointer to buffer to receive the authentication tag
 *   tag_len   - desired length of the tag (must be valid for the MAC)
 *   opts      - optional CF_MAC_OPTS structure with MAC-specific options (can be NULL)
 *   subflags  - algorithm-specific subflags (e.g., hash variant for HMAC/KMAC)
 */
CF_API CF_STATUS CF_MAC_Compute(const CF_MAC *mac,
                                const uint8_t *key, size_t key_len,
                                const uint8_t *data, size_t data_len,
                                uint8_t *tag, size_t tag_len,
                                const CF_MAC_OPTS *opts, uint32_t subflags);

/*
 * CF_MAC_CloneCtx
 *
 * Copies a CF_MAC_CTX from src to dst.
 * Performs a shallow copy of metadata, options, and key pointer,
 * and deep copies key_ctx and low-level MAC context if they exist.
 *
 * Returns:
 *   CF_SUCCESS        - on success
 *   CF_ERR_NULL_PTR   - if dst or src is NULL
 *   CF_ERR_CTX_CORRUPT - if src context is invalid or inconsistent
 *   CF_ERR_ALLOC_FAILED - if memory allocation fails for deep copy
 *
 * Parameters:
 *   dst - destination CF_MAC_CTX struct (must be pre-allocated)
 *   src - source CF_MAC_CTX struct to clone
 */
CF_API CF_STATUS CF_MAC_CloneCtx(CF_MAC_CTX *dst, const CF_MAC_CTX *src);

/*
 * CF_MAC_CloneCtxAlloc
 *
 * Allocates a new CF_MAC_CTX on the heap and clones the contents of src.
 * Performs deep copy of key_ctx and low-level MAC context as needed.
 *
 * Returns:
 *   pointer to cloned CF_MAC_CTX on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   src    - source CF_MAC_CTX to clone
 *   status - pointer to receive CF_STATUS result
 */
CF_API CF_MAC_CTX* CF_MAC_CloneCtxAlloc(const CF_MAC_CTX *src, CF_STATUS *status);

/*
 * CF_MAC_ValidateCtx
 *
 * Validates a CF_MAC_CTX structure by checking the bound magic value.
 *
 * Returns:
 *   CF_SUCCESS         - if the context is valid
 *   CF_ERR_NULL_PTR    - if ctx is NULL
 *   CF_ERR_CTX_CORRUPT - if the context appears tampered or corrupt
 *
 * Parameters:
 *   ctx - pointer to CF_MAC_CTX to validate
 */
CF_API CF_STATUS CF_MAC_ValidateCtx(const CF_MAC_CTX *ctx);

/*
 * CF_MAC_GetName
 *
 * Returns the short, general name of a MAC type.
 * Examples: "HMAC", "AES-CMAC", "POLY-1305"
 *
 * Returns NULL if ctx is NULL.
 *
 * Parameters:
 *   ctx - pointer to CF_MAC structure
 */
CF_API const char* CF_MAC_GetName(const CF_MAC *ctx);

/*
 * CF_MAC_GetFullName
 *
 * Returns a more descriptive name for the MAC context, including
 * algorithm variant or key length.
 * Examples: "HMAC-SHA-256", "AES-GMAC-128", "KMAC-XOF-256"
 *
 * Returns NULL if ctx or ctx->mac is NULL.
 *
 * Parameters:
 *   ctx - pointer to CF_MAC_CTX structure
 */
CF_API const char* CF_MAC_GetFullName(const CF_MAC_CTX *ctx);

/*
 * CF_MAC_IsValidKeyLength
 *
 * Checks if the given key length is valid for the specified MAC.
 *
 * Returns:
 *   true  - if the key length is valid
 *   false - if invalid or mac is NULL
 *
 * Parameters:
 *   mac     - pointer to CF_MAC structure
 *   key_len - key length in bytes to validate
 */
CF_API bool CF_MAC_IsValidKeyLength(const CF_MAC *mac, size_t key_len);

/*
 * CF_MAC_IsValidTagLength
 *
 * Checks if the given tag length is valid for the specified MAC.
 *
 * Returns:
 *   true  - if the tag length is valid
 *   false - if invalid or mac is NULL
 *
 * Parameters:
 *   mac     - pointer to CF_MAC structure
 *   tag_len - tag length in bytes to validate
 */
CF_API bool CF_MAC_IsValidTagLength(const CF_MAC *mac, size_t tag_len);

/*
 * CF_MAC_GetValidKeySizes
 *
 * Returns a pointer to an array of valid key sizes for the specified MAC.
 * Sets *count to the number of valid sizes. For HMAC/KMAC, returns NULL
 * and sets count to 0 (all lengths allowed).
 *
 * Returns NULL on error (if mac or count is NULL).
 *
 * Parameters:
 *   mac   - pointer to CF_MAC structure
 *   count - pointer to size_t to receive the number of valid sizes
 */
CF_API const size_t* CF_MAC_GetValidKeySizes(const CF_MAC *mac, size_t *count);

/*
 * CF_MAC_GetValidTagSizes
 *
 * Returns a pointer to an array of valid tag sizes for the specified MAC.
 * Sets *count to the number of valid sizes. For HMAC/KMAC, returns NULL
 * and sets count to 0 (any tag length is acceptable).
 *
 * Returns NULL on error (if mac or count is NULL).
 *
 * Parameters:
 *   mac   - pointer to CF_MAC structure
 *   count - pointer to size_t to receive the number of valid tag sizes
 */
CF_API const size_t* CF_MAC_GetValidTagSizes(const CF_MAC *mac, size_t *count);

/*
 * CF_MACOpts_Init
 *
 * Initializes a CF_MAC_OPTS context with optional IV and custom data.
 * Performs a deep copy of the IV and shallow copy of the custom data.
 *
 * Returns:
 *   CF_SUCCESS         - on success
 *   CF_ERR_NULL_PTR    - if opts is NULL
 *   CF_ERR_INVALID_LEN - if iv_len > AES_BLOCK_SIZE
 *
 * Parameters:
 *   opts       - pointer to a CF_MAC_OPTS struct to initialize
 *   iv         - optional initialization vector
 *   iv_len     - length of IV in bytes (must not exceed AES block size)
 *   custom     - optional custom data pointer (caller manages lifetime)
 *   custom_len - length of custom data
 */
CF_API CF_STATUS CF_MACOpts_Init(CF_MAC_OPTS *opts,
                          const uint8_t *iv, size_t iv_len,
                          const uint8_t *custom, size_t custom_len);

/*
 * CF_MACOpts_InitAlloc
 *
 * Allocates a new CF_MAC_OPTS struct on the heap and initializes it.
 *
 * Returns:
 *   pointer to allocated CF_MAC_OPTS on success
 *   NULL on failure, setting *status to an error code
 *
 * Parameters:
 *   iv         - optional initialization vector
 *   iv_len     - length of IV
 *   custom     - optional custom data
 *   custom_len - length of custom data
 *   status     - pointer to receive CF_STATUS result
 */
CF_API CF_MAC_OPTS* CF_MACOpts_InitAlloc(const uint8_t *iv, size_t iv_len,
                                  const uint8_t *custom, size_t custom_len,
                                  CF_STATUS *status);

/*
 * CF_MACOpts_Reset
 *
 * Resets a CF_MAC_OPTS struct to an empty, zeroed state.
 * Clears IV and custom data pointers and resets all metadata.
 *
 * Returns:
 *   CF_SUCCESS      - on success
 *   CF_ERR_NULL_PTR - if opts is NULL
 *
 * Parameters:
 *   opts - pointer to CF_MAC_OPTS to reset
 */
CF_API CF_STATUS CF_MACOpts_Reset(CF_MAC_OPTS *opts);

/*
 * CF_MACOpts_Free
 *
 * Frees a CF_MAC_OPTS struct if it was allocated on the heap.
 * Resets the context before freeing and sets the caller's pointer to NULL.
 *
 * Returns:
 *   CF_SUCCESS      - on success
 *   CF_ERR_NULL_PTR - if p_opts or *p_opts is NULL
 *
 * Parameters:
 *   p_opts - pointer to the pointer of CF_MAC_OPTS
 */
CF_API CF_STATUS CF_MACOpts_Free(CF_MAC_OPTS **p_opts);

/*
 * CF_MACOpts_CloneCtx
 *
 * Copies a CF_MAC_OPTS context from src to dst.
 * Performs deep copy of IV and shallow copy of custom data.
 * Does not allocate memory; dst must be pre-allocated.
 *
 * Returns:
 *   CF_SUCCESS         - on success
 *   CF_ERR_NULL_PTR    - if dst or src is NULL
 *   CF_ERR_CTX_CORRUPT - if src magic value is invalid
 *
 * Parameters:
 *   dst - destination CF_MAC_OPTS struct
 *   src - source CF_MAC_OPTS struct
 */
CF_API CF_STATUS CF_MACOpts_CloneCtx(CF_MAC_OPTS *dst, const CF_MAC_OPTS *src);

/*
 * CF_MACOpts_CloneCtxAlloc
 *
 * Allocates a new CF_MAC_OPTS on the heap and clones the source context.
 * Performs deep copy of IV and shallow copy of custom data.
 *
 * Returns:
 *   pointer to cloned CF_MAC_OPTS on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   src    - source CF_MAC_OPTS to clone
 *   status - pointer to receive CF_STATUS result
 */
CF_API CF_MAC_OPTS* CF_MACOpts_CloneCtxAlloc(const CF_MAC_OPTS *src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // CF_MAC_H