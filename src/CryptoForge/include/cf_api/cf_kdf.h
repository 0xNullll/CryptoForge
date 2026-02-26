/*
 * CryptoForge - cf_kdf.h / High-level KDF context and utility definitions
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
#ifndef CF_KDF_H
#define CF_KDF_H

#include "../config/crypto_config.h"
#include "../config/libs.h"

#include "../utils/misc.h"
#include "../utils/mem.h"
#include "../utils/cf_status.h"

#include "cf_defs.h"
#include "cf_flags.h"

#include "../crypto/hkdf.h"
#include "../crypto/pbkdf2.h"
#include "../crypto/kmac.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// KDF Algorithm Descriptor
// ============================
// Describes a KDF algorithm implementation.
// Each CF_KDF instance is static, immutable, and shared across contexts.
typedef struct _CF_KDF {

    // Unique algorithm identifier / flag.
    uint32_t id;

    // Size (in bytes) required for the internal low-level KDF state.
    size_t ctx_size;

    // --- Low-level entry points ---
    // Implement algorithm-specific logic; invoked by high-level API.

    // Initializes the context and binds algorithm-specific state.
    // Must be called before any extract/expand operations.
    CF_STATUS (*kdf_init_fn)(
        struct _CF_KDF_CTX *ctx,
        const struct _CF_KDF_OPTS *opts);

    // Performs the extraction stage (if applicable).
    // Typically combines IKM and optional salt to produce a pseudorandom key.
    CF_STATUS (*kdf_extract_fn)(
        struct _CF_KDF_CTX *ctx,
        const struct _CF_KDF_OPTS *opts);

    // Performs the expansion stage and writes derived output to `out`.
    // Must be called after extraction; generates derived key material.
    CF_STATUS (*kdf_expand_fn)(
        struct _CF_KDF_CTX *ctx,
        uint8_t *out,
        size_t out_len,
        const struct _CF_KDF_OPTS *opts);

    // Resets the context to its initial state.
    // Allows reuse of the same context with new input material.
    CF_STATUS (*kdf_reset_fn)(
        struct _CF_KDF_CTX *ctx);

    // Clones internal state from src to dest.
    // Useful for checkpointing or branching computation without re-extracting.
    CF_STATUS (*kdf_clone_ctx_fn)(
        struct _CF_KDF_CTX *ctx_dest,
        const struct _CF_KDF_CTX *ctx_src);

} CF_KDF;

// ============================
// Optional KDF Parameters
// ============================
// Parameters that modify KDF behavior.
// All pointer fields are borrowed and must remain valid for the duration
// of the KDF operation.
typedef struct _CF_KDF_OPTS {

    // Integrity guard (CF_CTX_MAGIC).
    // Verified by public API entry points.
    uint32_t magic;

    // Optional context/application-specific information (HKDF "info").
    const uint8_t *info;
    size_t info_len;

    // Optional iteration count (PBKDF2).
    size_t iterations;

    // Optional customization string (KMAC-XOF).
    const uint8_t *S;
    size_t S_len;

    // Indicates whether this structure was heap allocated.
    // If set, it must be released via the appropriate free routine.
    int isHeapAlloc;

} CF_KDF_OPTS;

// ============================
// KDF Context
// ============================
// Holds runtime state for a single KDF computation.
// By default, not thread-safe; concurrent usage requires cloning via the library-provided clone function.
typedef struct _CF_KDF_CTX {

    // Integrity guard: CF_CTX_MAGIC ^ (uintptr_t)kdf.
    uint64_t magic;

    // --- Algorithm binding (library-owned) ---
    // Descriptor is static and immutable.
    const CF_KDF *kdf;

    // Optional hash descriptor (used by HKDF/PBKDF2).
    // Borrowed; must remain valid for the lifetime of this context.
    const CF_HASH *hash;

    // Optional user-supplied parameters (borrowed).
    const CF_KDF_OPTS *opts;

    void *kdf_ctx;           // Low-level KDF state

    const uint8_t *ikm;      // Input keying material (IKM)
    size_t ikm_len;

    const uint8_t *salt;     // Optional salt
    size_t salt_len;

    // Algorithm-specific flags
    uint32_t subflags;

    // True if extract stage completed
    int isExtracted;

    // Indicates whether this structure was heap allocated.
    // If set, it must be released via the appropriate free routine.
    int isHeapAlloc;

} CF_KDF_CTX;

/*
 * CF_KDF_GetByFlag
 *
 * Retrieves a pointer to a CF_KDF descriptor based on a KDF algorithm flag.
 * Iterates the internal cf_kdf_table and calls the associated getter function.
 *
 * Returns:
 *   pointer to CF_KDF - if flag matches a supported KDF
 *   NULL              - if flag is invalid or unsupported
 *
 * Parameters:
 *   kdf_flag - algorithm identifier flag (e.g., CF_HKDF, CF_PBKDF2, CF_KMAC_XOF)
 */
CF_API const CF_KDF *CF_KDF_GetByFlag(uint32_t kdf_flag);

/*
 * CF_KDF_Init
 *
 * Initializes a stack-allocated KDF context for one-shot or streaming
 * operations. Validates parameters, sets up internal state, allocates
 * KDF-specific buffers, and prepares the context for extract/expand operations.
 *
 * Returns:
 *   CF_SUCCESS               - initialization succeeded
 *   CF_ERR_NULL_PTR          - if ctx, kdf, or ikm is NULL
 *   CF_ERR_CTX_CORRUPT       - if opts are invalid or context corrupted
 *   CF_ERR_UNSUPPORTED       - unsupported KDF type or hash/subflag
 *   CF_ERR_INVALID_PARAM     - invalid subflags (hash/XOF/KMAC mismatch)
 *   CF_ERR_CTX_UNINITIALIZED - context heap flag invalid
 *   CF_ERR_ALLOC_FAILED      - memory allocation for internal context failed
 *
 * Parameters:
 *   ctx      - pointer to stack-allocated CF_KDF_CTX
 *   kdf      - pointer to CF_KDF descriptor
 *   opts     - optional KDF options (can be NULL)
 *   ikm      - pointer to input keying material
 *   ikm_len  - length of IKM in bytes
 *   subflags - KDF-specific flags (hash type, KMAC variant, etc.)
 */
CF_API CF_STATUS CF_KDF_Init(CF_KDF_CTX *ctx, const CF_KDF *kdf, const CF_KDF_OPTS *opts,
                             const uint8_t *ikm, size_t ikm_len, uint32_t subflags);

/*
 * CF_KDF_InitAlloc
 *
 * Allocates and initializes a heap-allocated KDF context. Equivalent to
 * CF_KDF_Init but allocates memory on the heap and marks the context as
 * heap-owned for automatic cleanup via CF_KDF_Free.
 *
 * Returns:
 *   pointer to CF_KDF_CTX  - on success
 *   NULL                   - on failure (status set accordingly)
 *
 * Parameters:
 *   kdf      - pointer to CF_KDF descriptor
 *   opts     - optional KDF options (can be NULL)
 *   ikm      - pointer to input keying material
 *   ikm_len  - length of IKM in bytes
 *   subflags - KDF-specific flags
 *   status   - optional pointer to receive CF_STATUS result
 */
CF_API CF_KDF_CTX* CF_KDF_InitAlloc(const CF_KDF *kdf, const CF_KDF_OPTS *opts,
                                    const uint8_t *ikm, size_t ikm_len,
                                    uint32_t subflags, CF_STATUS *status);

/*
 * CF_KDF_Extract
 *
 * Performs the extract phase of a KDF (if applicable). Stores salt in
 * the context and derives an intermediate key state.
 *
 * Returns:
 *   CF_SUCCESS                   - extraction succeeded
 *   CF_ERR_NULL_PTR              - ctx is NULL
 *   CF_ERR_CTX_UNINITIALIZED     - context or KDF not initialized
 *   CF_ERR_CTX_CORRUPT           - context integrity check failed
 *   CF_ERR_KDF_ALREADY_EXTRACTED - extract already performed
 *   other CF_ERR_*               - from underlying KDF extract function
 *
 * Parameters:
 *   ctx      - pointer to initialized CF_KDF_CTX
 *   salt     - optional salt bytes
 *   salt_len - length of salt in bytes
 */
CF_API CF_STATUS CF_KDF_Extract(CF_KDF_CTX *ctx, const uint8_t *salt, size_t salt_len);

/*
 * CF_KDF_Expand
 *
 * Performs the expand phase of a KDF to generate the derived key material.
 * Writes derived_key_len bytes into derived_key.
 *
 * Returns:
 *   CF_SUCCESS               - key derivation succeeded
 *   CF_ERR_NULL_PTR          - ctx or derived_key is NULL
 *   CF_ERR_CTX_UNINITIALIZED - context not initialized
 *   CF_ERR_INVALID_LEN       - derived_key_len is zero
 *   other CF_ERR_*           - from underlying KDF expand function
 *
 * Parameters:
 *   ctx             - pointer to initialized CF_KDF_CTX
 *   derived_key     - pointer to buffer to receive derived key
 *   derived_key_len - desired length of derived key in bytes
 */
CF_API CF_STATUS CF_KDF_Expand(CF_KDF_CTX *ctx, uint8_t *derived_key, size_t derived_key_len);

/*
 * CF_KDF_Reset
 *
 * Resets a KDF context to its initial, empty state. Frees any internal
 * KDF-specific context memory, and clears all fields to prevent accidental
 * reuse or leakage of sensitive data.
 *
 * Returns:
 *   CF_SUCCESS               - reset completed successfully
 *   CF_ERR_NULL_PTR          - ctx is NULL
 *   CF_ERR_CTX_UNINITIALIZED - ctx->kdf is NULL
 *   CF_ERR_UNSUPPORTED       - KDF type invalid
 *
 * Parameters:
 *   ctx - pointer to CF_KDF_CTX to reset
 */
CF_API CF_STATUS CF_KDF_Reset(CF_KDF_CTX *ctx);

/*
 * CF_KDF_Free
 *
 * Frees a heap-allocated KDF context, including all internal state,
 * and securely clears the structure. Sets the caller pointer to NULL.
 * For stack-allocated contexts, only resets internal state without freeing memory.
 *
 * Returns:
 *   CF_SUCCESS      - free/reset completed successfully
 *   CF_ERR_NULL_PTR - p_ctx or *p_ctx is NULL
 *
 * Parameters:
 *   p_ctx - pointer to pointer of CF_KDF_CTX to free/reset
 */
CF_API CF_STATUS CF_KDF_Free(CF_KDF_CTX **p_ctx);

/*
 * CF_KDF_Compute
 *
 * Performs a one-shot KDF computation on the input keying material (IKM)
 * using the specified KDF algorithm, salt, options, and subflags.
 * Internally allocates a temporary KDF context on the stack, performs
 * extract and expand phases (if applicable), and writes the derived key.
 *
 * Returns:
 *   CF_SUCCESS         - derived key successfully generated
 *   CF_ERR_NULL_PTR    - if kdf, ikm, or derived_key is NULL
 *   CF_ERR_INVALID_LEN - if derived_key_len is zero
 *   other CF_ERR_*     - from underlying CF_KDF_Init, CF_KDF_Extract, or CF_KDF_Expand
 *
 * Parameters:
 *   kdf             - pointer to the CF_KDF descriptor
 *   ikm             - pointer to input keying material
 *   ikm_len         - length of IKM in bytes
 *   salt            - optional salt (may be NULL)
 *   salt_len        - length of salt in bytes
 *   derived_key     - pointer to buffer to receive derived key
 *   derived_key_len - desired length of derived key in bytes
 *   opts            - optional CF_KDF_OPTS structure with algorithm-specific parameters
 *   subflags        - algorithm-specific subflags (hash variant or KMAC-XOF type)
 */
CF_API CF_STATUS CF_KDF_Compute(const CF_KDF *kdf,
                                const uint8_t *ikm, size_t ikm_len,
                                const uint8_t *salt, size_t salt_len,
                                uint8_t *derived_key, size_t derived_key_len,
                                const CF_KDF_OPTS *opts, uint32_t subflags);

/*
 * CF_KDF_CloneCtx
 *
 * Copies a CF_KDF_CTX from src to dst.
 * Performs a shallow copy of metadata, options, IKM pointer, and subflags,
 * and deep copies low-level KDF context if it exists.
 *
 * Returns:
 *   CF_SUCCESS          - on success
 *   CF_ERR_NULL_PTR     - if dst or src is NULL
 *   CF_ERR_CTX_CORRUPT  - if src context is invalid or inconsistent
 *   CF_ERR_ALLOC_FAILED - if memory allocation fails for deep copy
 *
 * Parameters:
 *   dst - destination CF_KDF_CTX struct (must be pre-allocated)
 *   src - source CF_KDF_CTX struct to clone
 */
CF_API CF_STATUS CF_KDF_CloneCtx(CF_KDF_CTX *dst, const CF_KDF_CTX *src);

/*
 * CF_KDF_CloneCtxAlloc
 *
 * Allocates a new CF_KDF_CTX on the heap and clones the contents of src.
 * Performs deep copy of low-level KDF context as needed.
 *
 * Returns:
 *   pointer to cloned CF_KDF_CTX on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   src    - source CF_KDF_CTX to clone
 *   status - pointer to receive CF_STATUS result
 */
CF_API CF_KDF_CTX* CF_KDF_CloneCtxAlloc(const CF_KDF_CTX *src, CF_STATUS *status);

/*
 * CF_KDF_ValidateCtx
 *
 * Validates a CF_KDF_CTX structure by checking the bound magic value.
 *
 * Returns:
 *   CF_SUCCESS         - if the context is valid
 *   CF_ERR_NULL_PTR    - if ctx is NULL
 *   CF_ERR_CTX_CORRUPT - if the context appears tampered or corrupt
 *
 * Parameters:
 *   ctx - pointer to CF_KDF_CTX to validate
 */
CF_API CF_STATUS CF_KDF_ValidateCtx(const CF_KDF_CTX *ctx);

/*
 * CF_KDF_GetName
 *
 * Returns the short, general name of a KDF type.
 * Examples: "HKDF", "PBKDF2", "KMAC-XOF"
 *
 * Returns NULL if kdf is NULL.
 *
 * Parameters:
 *   kdf - pointer to CF_KDF descriptor
 */
CF_API const char* CF_KDF_GetName(const CF_KDF *kdf);

/*
 * CF_KDF_GetFullName
 *
 * Returns a more descriptive name for a KDF context, including
 * algorithm variant or hash function used.
 * Examples: "HKDF-SHA-256", "PBKDF2-SHA-512", "KMAC-XOF-256"
 *
 * Returns NULL if ctx or ctx->kdf is NULL.
 *
 * Parameters:
 *   ctx - pointer to CF_KDF_CTX structure
 */
CF_API const char* CF_KDF_GetFullName(const CF_KDF_CTX *ctx);

/*
 * CF_KDFOpts_Init
 *
 * Initializes a CF_KDF_OPTS context with optional info and custom data.
 * Performs a shallow copy of info and custom pointers and sets iterations.
 *
 * Returns:
 *   CF_SUCCESS           - on success
 *   CF_ERR_NULL_PTR      - if opts is NULL
 *   CF_ERR_INVALID_PARAM - if info_len or custom_len is zero while pointer is non-NULL
 *
 * Parameters:
 *   opts       - pointer to a CF_KDF_OPTS struct to initialize
 *   info       - optional application-specific info (HKDF "info")
 *   info_len   - length of info in bytes
 *   custom     - optional custom string (KMAC-XOF)
 *   custom_len - length of custom string in bytes
 *   iterations - optional iteration count (PBKDF2)
 */
CF_API CF_STATUS CF_KDFOpts_Init(CF_KDF_OPTS *opts,
                                 const uint8_t *info, size_t info_len,
                                 const uint8_t *custom, size_t custom_len,
                                 size_t iterations);

/*
 * CF_KDFOpts_InitAlloc
 *
 * Allocates a new CF_KDF_OPTS struct on the heap and initializes it.
 *
 * Returns:
 *   pointer to allocated CF_KDF_OPTS on success
 *   NULL on failure, setting *status to an error code
 *
 * Parameters:
 *   info       - optional info string (HKDF "info")
 *   info_len   - length of info
 *   custom     - optional custom string (KMAC-XOF)
 *   custom_len - length of custom string
 *   iterations - iteration count (PBKDF2)
 *   status     - pointer to receive CF_STATUS result
 */
CF_API CF_KDF_OPTS* CF_KDFOpts_InitAlloc(const uint8_t *info, size_t info_len,
                                         const uint8_t *custom, size_t custom_len,
                                         size_t iterations, CF_STATUS *status);

/*
 * CF_KDFOpts_SetNewInfo
 *
 * Updates the info field in a pre-existing CF_KDF_OPTS context.
 *
 * Returns:
 *   CF_SUCCESS           - on success
 *   CF_ERR_NULL_PTR      - if opts is NULL
 *   CF_ERR_INVALID_PARAM - if new_info_len is zero while new_info is non-NULL
 *
 * Parameters:
 *   opts         - pointer to an initialized CF_KDF_OPTS
 *   new_info     - pointer to new info string
 *   new_info_len - length of new info in bytes
 */
CF_API CF_STATUS CF_KDFOpts_SetNewInfo(CF_KDF_OPTS *opts,
                                       const uint8_t *new_info, size_t new_info_len);

/*
 * CF_KDFOpts_Reset
 *
 * Resets a CF_KDF_OPTS context to an empty, zeroed state.
 * Clears info and custom pointers, iteration count, and magic field.
 *
 * Returns:
 *   CF_SUCCESS      - on success
 *   CF_ERR_NULL_PTR - if opts is NULL
 *
 * Parameters:
 *   opts - pointer to CF_KDF_OPTS to reset
 */
CF_API CF_STATUS CF_KDFOpts_Reset(CF_KDF_OPTS *opts);

/*
 * CF_KDFOpts_Free
 *
 * Frees a CF_KDF_OPTS struct if it was allocated on the heap.
 * Resets the context before freeing and sets the caller's pointer to NULL.
 *
 * Returns:
 *   CF_SUCCESS      - on success
 *   CF_ERR_NULL_PTR - if p_opts or *p_opts is NULL
 *
 * Parameters:
 *   p_opts - pointer to the pointer of CF_KDF_OPTS
 */
CF_API CF_STATUS CF_KDFOpts_Free(CF_KDF_OPTS **p_opts);

/*
 * CF_KDFOpts_CloneCtx
 *
 * Copies a CF_KDF_OPTS context from src to dst.
 * Performs a shallow copy of info and custom pointers.
 * Does not allocate memory; dst must be pre-allocated.
 *
 * Returns:
 *   CF_SUCCESS         - on success
 *   CF_ERR_NULL_PTR    - if dst or src is NULL
 *   CF_ERR_CTX_CORRUPT - if src magic value is invalid
 *
 * Parameters:
 *   dst - destination CF_KDF_OPTS struct
 *   src - source CF_KDF_OPTS struct
 */
CF_API CF_STATUS CF_KDFOpts_CloneCtx(CF_KDF_OPTS *dst, const CF_KDF_OPTS *src);

/*
 * CF_KDFOpts_CloneCtxAlloc
 *
 * Allocates a new CF_KDF_OPTS on the heap and clones the source context.
 * Performs a shallow copy of info and custom pointers, copies iteration count.
 *
 * Returns:
 *   pointer to cloned CF_KDF_OPTS on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   src    - source CF_KDF_OPTS to clone
 *   status - pointer to receive CF_STATUS result
 */
CF_API CF_KDF_OPTS* CF_KDFOpts_CloneCtxAlloc(const CF_KDF_OPTS *src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // CF_KDF_H