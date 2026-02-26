/*
 * CryptoForge - cf_hash.h / High-level hash/XOF context and utility definitions
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

#ifndef CF_HASH_H
#define CF_HASH_H

#include "../utils/misc.h"
#include "../utils/mem.h"
#include "../utils/cf_status.h"

#include "../config/crypto_config.h"
#include "../config/libs.h"

#include "cf_defs.h"
#include "cf_flags.h"

#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"

#include "../crypto/keccak.h"
#include "../crypto/sha3.h"
#include "../crypto/shake.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// Hash Algorithm Descriptor
// ============================
// Describes a hash or XOF algorithm implementation.
// Each CF_HASH instance is static, immutable, and shared across contexts.
typedef struct _CF_HASH {

    // Unique algorithm identifier / flag.
    uint32_t id;

    // Optional Keccak domain/prefix for cSHAKE customization.
    uint8_t domain;

    // --- Size metadata ---
    // Output digest size in bytes.
    size_t digest_size;

    // Internal block size (bytes) used by the algorithm.
    size_t block_size;

    // Size of the low-level hash context (for allocation/stack usage).
    size_t ctx_size;

    // Default output length for XOF/SHAKE-style functions.
    size_t default_out_len;

    // --- Low-level entry points ---
    // Implement algorithm-specific logic; invoked by high-level API.

    // Initializes the low-level hash context.
    // Must be called before any update/final/squeeze operations.
    bool (*hash_init_fn)(void *ctx, const CF_HASH_OPTS *opts);

    // Updates the hash state with input data.
    // Can be called multiple times to process data in chunks.
    bool (*hash_update_fn)(void *ctx, const uint8_t *data, size_t data_len);

    // Finalizes the hash computation and writes digest output.
    // After calling, the context should not be reused unless reinitialized.
    bool (*hash_final_fn)(void *ctx, uint8_t *digest);

    // Squeezes output for XOF functions (e.g., SHAKE).
    // Can be called multiple times to generate extended output.
    bool (*hash_squeeze_fn)(void *ctx, uint8_t *output, size_t outlen);

} CF_HASH;

// ============================
// Optional Hash Parameters
// ============================
// Parameters that modify hash behavior.
// All pointer fields are borrowed and must remain valid for the duration
// of the hash operation.
typedef struct _CF_HASH_OPTS {

    // Integrity guard (CF_CTX_MAGIC).
    // Verified by public API entry points.
    uint32_t magic;

    // Optional customization strings (borrowed).
    const uint8_t *N;   // cSHAKE "N" string
    size_t N_len;

    const uint8_t *S;   // cSHAKE "S" string
    size_t S_len;

    // Bookkeeping flags.
    int finalized;         // Non-zero if final() was called
    int custom_absorbed;   // Non-zero if N/S was absorbed
    int emptyNameCustom;   // True if empty customization used

    // Indicates whether this structure was heap allocated.
    // If set, it must be released via the appropriate free routine.
    int isHeapAlloc;

} CF_HASH_OPTS;

// ============================
// Hash Context
// ============================
// Holds runtime state for a single hash computation.
// By default, not thread-safe; concurrent usage requires cloning via the library-provided clone function.
typedef struct _CF_HASH_CTX {

    // Integrity guard: CF_CTX_MAGIC ^ (uintptr_t)hash.
    uint64_t magic;

    // --- Algorithm binding (library-owned) ---
    // Descriptor is static and immutable.
    const struct _CF_HASH *hash;

    // Optional user-supplied parameters (borrowed).
    const void *opts;

    // Pointer to low-level hash context (algorithm-specific state).
    void *digest_ctx;

    // Optional output length for XOF/SHAKE functions.
    size_t out_len;

    // True if hash_final_fn has been called
    int isFinalized;

    // Indicates whether this structure was heap allocated.
    // If set, it must be released via the appropriate free routine.
    int isHeapAlloc;

} CF_HASH_CTX;

/*
 * CF_Hash_GetByFlag
 *
 * Retrieves a pointer to a CF_HASH descriptor based on a hash algorithm flag.
 * Iterates the internal CF_HASH_table and calls the associated getter function.
 *
 * Returns:
 *   pointer to CF_HASH - if flag matches a supported hash
 *   NULL               - if flag is invalid or unsupported
 *
 * Parameters:
 *   algo_flag - algorithm identifier flag (e.g., CF_SHA256, CF_SHA3_512)
 */
CF_API const CF_HASH *CF_Hash_GetByFlag(uint32_t algo_flag);

/*
 * CF_Hash_Init
 *
 * Initializes a stack-allocated hash context for one-shot or streaming
 * operations. Validates parameters, sets up internal state, allocates
 * low-level digest buffers, and prepares the context for updates/finalization.
 *
 * Returns:
 *   CF_SUCCESS               - initialization succeeded
 *   CF_ERR_NULL_PTR          - if ctx or hash is NULL
 *   CF_ERR_CTX_CORRUPT       - if opts are invalid or magic mismatch
 *   CF_ERR_CTX_UNINITIALIZED - if context heap flag is invalid
 *   CF_ERR_ALLOC_FAILED      - memory allocation for low-level digest context failed
 *   CF_ERR_BAD_STATE         - low-level hash init function failed
 *
 * Parameters:
 *   ctx  - pointer to stack-allocated CF_HASH_CTX
 *   hash - pointer to CF_HASH descriptor
 *   opts - optional hash options (can be NULL)
 */
CF_API CF_STATUS CF_Hash_Init(CF_HASH_CTX *ctx, const CF_HASH *hash, const CF_HASH_OPTS *opts);

/*
 * CF_Hash_InitAlloc
 *
 * Allocates a new CF_HASH_CTX on the heap and initializes it with the specified
 * hash descriptor and optional options. Marks the context as heap-allocated
 * for proper cleanup via CF_Hash_Free.
 *
 * Returns:
 *   pointer to allocated CF_HASH_CTX - on success
 *   NULL                             - on failure, with *status set
 *
 * Parameters:
 *   hash   - pointer to CF_HASH descriptor
 *   opts   - optional hash options (can be NULL)
 *   status - pointer to receive CF_STATUS result
 */
CF_API CF_HASH_CTX* CF_Hash_InitAlloc(const CF_HASH *hash, const CF_HASH_OPTS *opts, CF_STATUS *status);

/*
 * CF_Hash_Update
 *
 * Feeds input data into an initialized hash context. Can be called
 * repeatedly for streaming input before calling CF_Hash_Final.
 *
 * Returns:
 *   CF_SUCCESS               - update succeeded
 *   CF_ERR_NULL_PTR          - ctx or data is NULL
 *   CF_ERR_CTX_UNINITIALIZED - context or low-level digest not initialized
 *   CF_ERR_CTX_CORRUPT       - context integrity check failed (magic mismatch)
 *   CF_ERR_MAC_FINALIZED     - context already finalized (cannot update)
 *
 * Parameters:
 *   ctx      - pointer to initialized CF_HASH_CTX
 *   data     - pointer to input data bytes
 *   data_len - length of input data in bytes
 */
CF_API CF_STATUS CF_Hash_Update(CF_HASH_CTX *ctx, const uint8_t *data, size_t data_len);

/*
 * CF_Hash_Final
 *
 * Finalizes a hash computation and writes the digest to the provided buffer.
 * After finalization, the context is marked as finalized and cannot be updated
 * further without reinitialization. Supports XOF (variable-length output) and
 * fixed-size hashes.
 *
 * Returns:
 *   CF_SUCCESS                     - finalization succeeded
 *   CF_ERR_NULL_PTR                - ctx or digest is NULL
 *   CF_ERR_CTX_UNINITIALIZED       - context or low-level digest not initialized
 *   CF_ERR_CTX_CORRUPT             - context integrity check failed (magic mismatch)
 *   CF_ERR_HASH_FINALIZED          - non-XOF hash already finalized
 *   CF_ERR_OUTPUT_BUFFER_TOO_SMALL - output buffer too small for fixed-size hash
 *
 * Parameters:
 *   ctx         - pointer to initialized CF_HASH_CTX
 *   digest      - pointer to buffer to receive computed hash
 *   digest_len  - length of digest buffer in bytes (for XOFs, can be 0 to use default)
 */
CF_API CF_STATUS CF_Hash_Final(CF_HASH_CTX *ctx, uint8_t *digest, size_t digest_len);

/*
 * CF_Hash_Reset
 *
 * Resets a hash context to its initial, empty state. Frees any internal
 * low-level digest memory and clears all fields to prevent accidental reuse
 * or leakage of sensitive data.
 *
 * Returns:
 *   CF_SUCCESS               - reset completed successfully
 *   CF_ERR_NULL_PTR          - if ctx is NULL
 *   CF_ERR_CTX_UNINITIALIZED - if ctx->hash is NULL
 *   CF_ERR_CTX_CORRUPT       - if internal sizes or pointers are inconsistent
 *
 * Parameters:
 *   ctx - pointer to CF_HASH_CTX to reset
 */
CF_API CF_STATUS CF_Hash_Reset(CF_HASH_CTX *ctx);

/*
 * CF_Hash_Free
 *
 * Frees a heap-allocated hash context, including all internal state,
 * and securely clears the structure. Sets the caller pointer to NULL.
 * For stack-allocated contexts, only resets internal state without
 * freeing memory.
 *
 * Returns:
 *   CF_SUCCESS      - free/reset completed successfully
 *   CF_ERR_NULL_PTR - if p_ctx or *p_ctx is NULL
 *
 * Parameters:
 *   p_ctx - pointer to pointer of CF_HASH_CTX to free/reset
 */
CF_API CF_STATUS CF_Hash_Free(CF_HASH_CTX **p_ctx);

/*
 * CF_Hash_Compute
 *
 * Performs a one-shot hash computation on the input data using the specified
 * hash algorithm and optional customization options (CF_HASH_OPTS). Internally
 * allocates a temporary hash context on the stack, updates it with the data,
 * and finalizes the digest.
 *
 * Returns:
 *   CF_SUCCESS         - digest successfully computed
 *   CF_ERR_NULL_PTR    - if hash, data, or digest is NULL
 *   other CF_ERR_*     - from underlying CF_Hash_Init, CF_Hash_Update, or CF_Hash_Final
 *
 * Parameters:
 *   hash       - pointer to the CF_HASH descriptor
 *   data       - pointer to input data
 *   data_len   - length of input data in bytes
 *   digest     - pointer to buffer to receive the hash digest
 *   digest_len - desired length of output digest in bytes (for XOFs)
 *   opts       - optional CF_HASH_OPTS with customization parameters (may be NULL)
 */
CF_API CF_STATUS CF_Hash_Compute(
    const CF_HASH      *hash,
    const uint8_t      *data,
    size_t              data_len,
    uint8_t            *digest,
    size_t              digest_len,
    const CF_HASH_OPTS *opts
);

/*
 * CF_Hash_ComputeFixed
 *
 * Performs a one-shot hash computation for fixed-output hash functions
 * (non-XOF). Does not support variable-length output; digest length is
 * determined by the hash descriptor.
 *
 * Returns:
 *   CF_SUCCESS         - digest successfully computed
 *   CF_ERR_NULL_PTR    - if hash, data, or digest is NULL
 *   CF_ERR_UNSUPPORTED - if the hash algorithm is an XOF (variable-length output)
 *   other CF_ERR_*     - from underlying CF_Hash_Init, CF_Hash_Update, or CF_Hash_Final
 *
 * Parameters:
 *   hash     - pointer to the CF_HASH descriptor
 *   data     - pointer to input data
 *   data_len - length of input data in bytes
 *   digest   - pointer to buffer to receive the fixed-size digest
 */
CF_API CF_STATUS CF_Hash_ComputeFixed(
    const CF_HASH  *hash,
    const uint8_t  *data,
    size_t         data_len,
    uint8_t       *digest
);

/*
 * CF_Hash_CloneCtx
 *
 * Copies a CF_HASH_CTX structure from src to dst.
 * Performs a deep copy of the low-level digest context and a shallow
 * copy of metadata and options. dst must be pre-allocated.
 *
 * Returns:
 *   CF_SUCCESS               - context successfully cloned
 *   CF_ERR_NULL_PTR          - if dst or src is NULL
 *   CF_ERR_CTX_UNINITIALIZED - if src->hash is NULL
 *   CF_ERR_CTX_CORRUPT       - if src appears corrupted (magic mismatch)
 *   CF_ERR_ALLOC_FAILED      - if memory allocation for digest_ctx fails
 *
 * Parameters:
 *   dst - destination CF_HASH_CTX
 *   src - source CF_HASH_CTX
 *
 * Notes:
 *   Cloning allows safe concurrent use of the hash context across threads.
 */
CF_API CF_STATUS CF_Hash_CloneCtx(CF_HASH_CTX *dst, const CF_HASH_CTX *src);

/*
 * CF_Hash_CloneCtxAlloc
 *
 * Allocates a new CF_HASH_CTX on the heap and clones the source context.
 * Performs a deep copy of the low-level digest context and metadata.
 *
 * Returns:
 *   pointer to cloned CF_HASH_CTX on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   src    - source CF_HASH_CTX to clone
 *   status - pointer to receive CF_STATUS result
 *
 * Notes:
 *   The cloned context is heap-allocated and can be safely used concurrently
 *   with the source context in different threads.
 */
CF_API CF_HASH_CTX *CF_Hash_CloneCtxAlloc(const CF_HASH_CTX *src, CF_STATUS *status);

/*
 * CF_Hash_ValidateCtx
 *
 * Validates a CF_HASH_CTX structure by checking the bound magic value.
 *
 * Returns:
 *   CF_SUCCESS         - if the context is valid
 *   CF_ERR_NULL_PTR    - if ctx is NULL
 *   CF_ERR_CTX_CORRUPT - if the context appears tampered or corrupt
 *
 * Parameters:
 *   ctx - pointer to CF_HASH_CTX to validate
 */
CF_API CF_STATUS CF_Hash_ValidateCtx(const CF_HASH_CTX *ctx);

/*
 * CF_Hash_GetDigestSize
 *
 * Returns the fixed output size (in bytes) for a hash function.
 * For XOF/SHAKE variants, this may return a default output length.
 *
 * Returns 0 if hash is NULL.
 *
 * Parameters:
 *   hash - pointer to CF_HASH descriptor
 */
CF_API size_t CF_Hash_GetDigestSize(const CF_HASH *hash);

/*
 * CF_Hash_GetBlockSize
 *
 * Returns the internal block size (in bytes) of the hash function.
 * Useful for padding or HMAC-style constructions.
 *
 * Returns 0 if hash is NULL.
 *
 * Parameters:
 *   hash - pointer to CF_HASH descriptor
 */
CF_API size_t CF_Hash_GetBlockSize(const CF_HASH *hash);

/*
 * CF_Hash_GetName
 *
 * Returns the short, general name of a hash type.
 * Examples: "SHA-256", "SHAKE-128", "CSHAKE-256"
 *
 * Returns NULL if hash is NULL.
 *
 * Parameters:
 *   hash - pointer to CF_HASH descriptor
 */
CF_API const char* CF_Hash_GetName(const CF_HASH *hash);

/*
 * CF_HashOpts_Init
 *
 * Initializes a CF_HASH_OPTS context with optional cSHAKE customization strings.
 * Performs a shallow copy of N and S pointers into the context and sets internal flags.
 *
 * Returns:
 *   CF_SUCCESS      - on success
 *   CF_ERR_NULL_PTR - if opts is NULL
 *
 * Parameters:
 *   opts   - pointer to a CF_HASH_OPTS struct to initialize
 *   N      - optional cSHAKE "N" string (can be NULL)
 *   N_len  - length of N in bytes
 *   S      - optional cSHAKE "S" string (can be NULL)
 *   S_len  - length of S in bytes
 */
CF_API CF_STATUS CF_HashOpts_Init(
    CF_HASH_OPTS *opts,
    const uint8_t *N, size_t N_len,
    const uint8_t *S, size_t S_len
);

/*
 * CF_HashOpts_InitAlloc
 *
 * Allocates a new CF_HASH_OPTS struct on the heap and initializes it.
 * Performs a shallow copy of N and S pointers into the new context.
 *
 * Returns:
 *   pointer to allocated CF_HASH_OPTS on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   N      - optional cSHAKE "N" string (can be NULL)
 *   N_len  - length of N in bytes
 *   S      - optional cSHAKE "S" string (can be NULL)
 *   S_len  - length of S in bytes
 *   status - pointer to receive CF_STATUS result
 */
CF_API CF_HASH_OPTS* CF_HashOpts_InitAlloc(
    const uint8_t *N, size_t N_len,
    const uint8_t *S, size_t S_len,
    CF_STATUS *status
);

/*
 * CF_HashOpts_Reset
 *
 * Resets a CF_HASH_OPTS context to an empty, zeroed state.
 * Clears N/S pointers, lengths, flags, and magic field.
 *
 * Returns:
 *   CF_SUCCESS      - on success
 *   CF_ERR_NULL_PTR - if opts is NULL
 *
 * Parameters:
 *   opts - pointer to CF_HASH_OPTS to reset
 */
CF_API CF_STATUS CF_HashOpts_Reset(CF_HASH_OPTS *opts);

/*
 * CF_HashOpts_Free
 *
 * Frees a CF_HASH_OPTS struct if it was allocated on the heap.
 * Resets the context before freeing and sets the caller's pointer to NULL.
 *
 * Returns:
 *   CF_SUCCESS      - on success
 *   CF_ERR_NULL_PTR - if p_opts or *p_opts is NULL
 *
 * Parameters:
 *   p_opts - pointer to the pointer of CF_HASH_OPTS
 */
CF_API CF_STATUS CF_HashOpts_Free(CF_HASH_OPTS **p_opts);

/*
 * CF_HashOpts_Clone
 *
 * Copies a CF_HASH_OPTS context from src to dst.
 * Performs a shallow copy of N and S pointers.
 * Does not allocate memory; dst must be pre-allocated.
 *
 * Returns:
 *   CF_SUCCESS         - on success
 *   CF_ERR_NULL_PTR    - if dst or src is NULL
 *   CF_ERR_CTX_CORRUPT - if src magic value is invalid
 *
 * Parameters:
 *   dst - destination CF_HASH_OPTS struct
 *   src - source CF_HASH_OPTS struct
 */
CF_API CF_STATUS CF_HashOpts_Clone(CF_HASH_OPTS *dst, const CF_HASH_OPTS *src);

/*
 * CF_HashOpts_CloneAlloc
 *
 * Allocates a new CF_HASH_OPTS on the heap and clones the source context.
 * Performs a shallow copy of N and S pointers, copies flags and metadata.
 *
 * Returns:
 *   pointer to cloned CF_HASH_OPTS on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   src    - source CF_HASH_OPTS to clone
 *   status - pointer to receive CF_STATUS result
 */
CF_API CF_HASH_OPTS *CF_HashOpts_CloneAlloc(const CF_HASH_OPTS *src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // CF_HASH_H