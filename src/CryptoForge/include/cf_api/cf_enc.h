/*
 * CryptoForge - cf_enc.h / High-level encoder/decoder context and utility definitions
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

#ifndef CF_ENCODER_H
#define CF_ENCODER_H

#include "../utils/mem.h"
#include "../utils/cf_status.h"
#include "../config/libs.h"

#include "cf_flags.h"
#include "cf_defs.h"

#include "../crypto/base16.h"
#include "../crypto/base32.h"
#include "../crypto/base58.h"
#include "../crypto/base64.h"
#include "../crypto/base85.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// Encoder Descriptor
// ============================
// Describes an encoding/decoding algorithm implementation
// (e.g., Base64, Base32, Hex, Z85, etc.).
// Each CF_ENCODER instance is static, immutable, and shared across contexts.
typedef struct _CF_ENCODER {

    // Encoding type mask (supported encode variants).
    // Used to validate encFlags in the context.
    uint32_t enc_mask;

    // Decoding type mask (supported decode variants).
    // Used to validate decFlags in the context.
    uint32_t dec_mask;

    // --- Size metadata ---
    // Minimum number of input bytes required per encoding block.
    // Example: Base64 processes 3-byte blocks.
    size_t min_input;

    // Minimum number of output characters per encoded block.
    // Example: Base64 produces 4 characters per block.
    size_t min_output;

    // Flags that bypass min_input/min_output enforcement.
    // Useful for streaming modes or relaxed decoding.
    uint32_t no_min_flags;

    // --- Character range validation ---
    // Minimum allowed character value for fast pre-check.
    char min_char;

    // Maximum allowed character value for fast pre-check.
    char max_char;

    // Primary reverse lookup table for decoding.
    // Maps input character → decoded value (or negative for invalid).
    const int8_t *rev_table;

    // Optional alternate reverse table.
    // Used for URL-safe Base64, alternate alphabets, Z85, etc.
    const int8_t *rev_table_alt;

    // Padding character (e.g., '=' for Base64).
    // May be 0 if padding is not used.
    char pad;
    
    // --- Low-level entry points ---
    // Implement algorithm-specific logic; invoked by high-level API.

    // Encodes binary input into textual representation.
    // Writes output to `out` and updates `out_len`.
    // `mode` selects encoding variant (must match enc_mask).
    bool (*encode_fn)(
        const uint8_t *data,
        size_t data_len,
        char *out,
        size_t *out_len,
        uint32_t mode
    );

    // Decodes textual input into binary output.
    // Writes decoded bytes to `out` and updates `out_len`.
    // `mode` selects decoding variant (must match dec_mask).
    bool (*decode_fn)(
        const char *data,
        size_t data_len,
        uint8_t *out,
        size_t *out_len,
        uint32_t mode
    );

} CF_ENCODER;


// ============================
// Encoder Context
// ============================
// Holds runtime state for a single encode/decode operation.
// Not thread-safe by default; separate contexts required per thread.
typedef struct _CF_ENCODER_CTX {

    // Integrity guard: CF_CTX_MAGIC ^ (uintptr_t)encoder.
    // Verified by public API entry points.
    uint64_t magic;

    // --- Algorithm binding (library-owned) ---
    // Descriptor is static and immutable.
    const CF_ENCODER *encoder;

    // Encoding variant flags (validated against enc_mask).
    uint32_t encFlags;

    // Decoding variant flags (validated against dec_mask).
    uint32_t decFlags;

    // Indicates whether this context was heap allocated.
    // If set, it must be released via the appropriate free routine.
    int isHeapAlloc;

} CF_ENCODER_CTX;

/*
 * CF_Enc_Init
 *
 * Initializes a stack-allocated encoder context for one-shot encoding
 * or decoding operations. Validates flags, retrieves the corresponding
 * encoder descriptor, binds integrity metadata, and prepares the
 * context for use.
 *
 * Returns:
 *   CF_SUCCESS               - initialization succeeded
 *   CF_ERR_NULL_PTR          - if ctx is NULL
 *   CF_ERR_INVALID_PARAM     - if enc_flags or dec_flags are invalid
 *   CF_ERR_CTX_UNINITIALIZED - if heap flag state is invalid
 *
 * Parameters:
 *   ctx       - pointer to stack-allocated CF_ENCODER_CTX
 *   enc_flags - encoding variant flags
 *   dec_flags - decoding variant flags
 *
 * Notes:
 *   The context must be reset or freed before reinitialization.
 *   A per-context magic value is bound for integrity verification.
 */
CF_API CF_STATUS CF_Enc_Init(
    CF_ENCODER_CTX *ctx,
    uint32_t        enc_flags,
    uint32_t        dec_flags
);

/*
 * CF_Enc_InitAlloc
 *
 * Allocates a new CF_ENCODER_CTX on the heap and initializes it
 * with the specified encoding and decoding flags. Marks the context
 * as heap-allocated for proper cleanup via CF_Enc_Free.
 *
 * Returns:
 *   pointer to allocated CF_ENCODER_CTX - on success
 *   NULL                                - on failure, with *status set
 *
 * Parameters:
 *   enc_flags - encoding variant flags
 *   dec_flags - decoding variant flags
 *   status    - pointer to receive CF_STATUS result
 *
 * Notes:
 *   The returned context must be released using CF_Enc_Free.
 */
CF_API CF_ENCODER_CTX* CF_Enc_InitAlloc(
    uint32_t   enc_flags,
    uint32_t   dec_flags,
    CF_STATUS *status
);

/*
 * CF_Enc_Reset
 *
 * Resets an encoder context to its initial, empty state.
 * Clears bound descriptor, flags, and integrity metadata
 * to prevent accidental reuse or misuse.
 *
 * Returns:
 *   CF_SUCCESS      - reset completed successfully
 *   CF_ERR_NULL_PTR - if ctx is NULL
 *
 * Parameters:
 *   ctx - pointer to CF_ENCODER_CTX to reset
 *
 * Notes:
 *   Does not free heap memory; use CF_Enc_Free for deallocation.
 */
CF_API CF_STATUS CF_Enc_Reset(CF_ENCODER_CTX *ctx);

/*
 * CF_Enc_Free
 *
 * Frees a heap-allocated encoder context and securely clears its state.
 * If the context was stack-allocated, only resets internal state without
 * freeing memory. Sets the caller pointer to NULL when heap memory is freed.
 *
 * Returns:
 *   CF_SUCCESS      - free/reset completed successfully
 *   CF_ERR_NULL_PTR - if p_ctx or *p_ctx is NULL
 *
 * Parameters:
 *   p_ctx - pointer to pointer of CF_ENCODER_CTX to free/reset
 */
CF_API CF_STATUS CF_Enc_Free(CF_ENCODER_CTX **p_ctx);

/*
 * CF_Enc_Encode
 *
 * Performs a one-shot encoding operation using the encoder bound
 * to the provided CF_ENCODER_CTX. Validates context integrity,
 * enforces block-size constraints (unless bypassed), and invokes
 * the low-level encode function.
 *
 * Returns:
 *   CF_SUCCESS               - encoding completed successfully
 *   CF_ERR_NULL_PTR          - if ctx, src, dst, or dst_len is NULL
 *   CF_ERR_CTX_UNINITIALIZED - if ctx->encoder is NULL
 *   CF_ERR_CTX_CORRUPT       - if context integrity check fails
 *   CF_ERR_INVALID_LEN       - if src_len is zero or violates block rules
 *   other CF_ERR_*           - from underlying encoder implementation
 *
 * Parameters:
 *   ctx     - pointer to initialized CF_ENCODER_CTX
 *   src     - pointer to input byte buffer
 *   src_len - length of input data in bytes
 *   dst     - output buffer for encoded characters
 *   dst_len - in/out parameter; receives number of characters written
 */
CF_API CF_STATUS CF_Enc_Encode(
    CF_ENCODER_CTX *ctx,
    const uint8_t  *src,
    size_t          src_len,
    char           *dst,
    size_t         *dst_len
);

/*
 * CF_Enc_EncodeRaw
 *
 * Identical to CF_Enc_Encode, but accepts a void* input pointer.
 * Internally casts input to const uint8_t* and forwards the call.
 *
 * Returns:
 *   Same as CF_Enc_Encode.
 *
 * Parameters:
 *   ctx     - pointer to initialized CF_ENCODER_CTX
 *   src     - pointer to raw input buffer
 *   src_len - length of input data in bytes
 *   dst     - output buffer for encoded characters
 *   dst_len - in/out parameter; receives number of characters written
 */
CF_API CF_STATUS CF_Enc_EncodeRaw(
    CF_ENCODER_CTX *ctx,
    const void     *src,
    size_t          src_len,
    char           *dst,
    size_t         *dst_len
);

/*
 * CF_Enc_EncodeAlloc
 *
 * Performs a one-shot encoding operation and allocates the output
 * buffer internally using SECURE_ALLOC. The required size is computed
 * via CF_Enc_RequiredEncLen.
 *
 * Returns:
 *   pointer to allocated encoded buffer on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   ctx      - pointer to initialized CF_ENCODER_CTX
 *   src      - pointer to input byte buffer
 *   src_len  - length of input data in bytes
 *   out_len  - pointer to receive number of characters written
 *   status   - pointer to receive CF_STATUS result
 *
 * Notes:
 *   The returned buffer is heap-allocated and must be freed using
 *   the appropriate secure free routine.
 */
CF_API char* CF_Enc_EncodeAlloc(
    CF_ENCODER_CTX *ctx,
    const uint8_t  *src,
    size_t          src_len,
    size_t         *out_len,
    CF_STATUS      *status
);

/*
 * CF_Enc_EncodeAllocRaw
 *
 * Identical to CF_Enc_EncodeAlloc, but accepts a void* input pointer.
 * Internally forwards to CF_Enc_EncodeAlloc.
 *
 * Returns:
 *   pointer to allocated encoded buffer on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   ctx      - pointer to initialized CF_ENCODER_CTX
 *   src      - pointer to raw input buffer
 *   src_len  - length of input data in bytes
 *   out_len  - pointer to receive number of characters written
 *   status   - pointer to receive CF_STATUS result
 */
CF_API char* CF_Enc_EncodeAllocRaw(
    CF_ENCODER_CTX *ctx,
    const void     *src,
    size_t          src_len,
    size_t         *out_len,
    CF_STATUS      *status
);

/*
 * CF_Enc_Decode
 *
 * Performs a one-shot decoding operation using the encoder bound
 * to the provided CF_ENCODER_CTX. Validates context integrity,
 * enforces block-size constraints (unless bypassed), and invokes
 * the low-level decode function.
 *
 * Returns:
 *   CF_SUCCESS               - decoding completed successfully
 *   CF_ERR_NULL_PTR          - if ctx, src, dst, or dst_len is NULL
 *   CF_ERR_CTX_UNINITIALIZED - if ctx->encoder is NULL
 *   CF_ERR_CTX_CORRUPT       - if context integrity check fails
 *   CF_ERR_INVALID_LEN       - if src_len is zero or violates block rules
 *   other CF_ERR_*           - from underlying decoder implementation
 *
 * Parameters:
 *   ctx     - pointer to initialized CF_ENCODER_CTX
 *   src     - pointer to encoded character buffer
 *   src_len - length of encoded input in characters
 *   dst     - output buffer for decoded bytes
 *   dst_len - in/out parameter; receives number of bytes written
 */
CF_API CF_STATUS CF_Enc_Decode(
    CF_ENCODER_CTX *ctx,
    const char     *src,
    size_t          src_len,
    uint8_t        *dst,
    size_t         *dst_len
);

/*
 * CF_Enc_DecodeRaw
 *
 * Identical to CF_Enc_Decode, but accepts a void* input pointer.
 * Internally casts input to const char* and forwards the call.
 *
 * Returns:
 *   Same as CF_Enc_Decode.
 *
 * Parameters:
 *   ctx     - pointer to initialized CF_ENCODER_CTX
 *   src     - pointer to raw encoded buffer
 *   src_len - length of encoded input in bytes
 *   dst     - output buffer for decoded bytes
 *   dst_len - in/out parameter; receives number of bytes written
 */
CF_API CF_STATUS CF_Enc_DecodeRaw(
    CF_ENCODER_CTX *ctx,
    const void     *src,
    size_t          src_len,
    uint8_t        *dst,
    size_t         *dst_len
);

/*
 * CF_Enc_DecodeAlloc
 *
 * Performs a one-shot decoding operation and allocates the output
 * buffer internally using SECURE_ALLOC. The required size is computed
 * via CF_Enc_RequiredDecLen.
 *
 * Returns:
 *   pointer to allocated decoded buffer on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   ctx      - pointer to initialized CF_ENCODER_CTX
 *   src      - pointer to encoded character buffer
 *   src_len  - length of encoded input in characters
 *   out_len  - pointer to receive number of bytes written
 *   status   - pointer to receive CF_STATUS result
 *
 * Notes:
 *   The returned buffer is heap-allocated and must be freed using
 *   the appropriate secure free routine.
 */
CF_API uint8_t* CF_Enc_DecodeAlloc(
    CF_ENCODER_CTX *ctx,
    const char     *src,
    size_t          src_len,
    size_t         *out_len,
    CF_STATUS      *status
);

/*
 * CF_Enc_DecodeAllocRaw
 *
 * Identical to CF_Enc_DecodeAlloc, but accepts a void* input pointer.
 * Internally forwards to CF_Enc_DecodeAlloc.
 *
 * Returns:
 *   pointer to allocated decoded buffer on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   ctx      - pointer to initialized CF_ENCODER_CTX
 *   src      - pointer to raw encoded buffer
 *   src_len  - length of encoded input in bytes
 *   out_len  - pointer to receive number of bytes written
 *   status   - pointer to receive CF_STATUS result
 */
CF_API uint8_t* CF_Enc_DecodeAllocRaw(
    CF_ENCODER_CTX *ctx,
    const void     *src,
    size_t          src_len,
    size_t         *out_len,
    CF_STATUS      *status
);

/*
 * CF_Enc_CloneCtx
 *
 * Copies a CF_ENCODER_CTX structure from src to dst.
 * Performs a shallow copy of encoder descriptor and flags.
 * dst must be pre-allocated by the caller.
 *
 * Returns:
 *   CF_SUCCESS         - context successfully cloned
 *   CF_ERR_NULL_PTR    - if dst or src is NULL
 *   CF_ERR_CTX_CORRUPT - if src appears corrupted (magic mismatch)
 *
 * Parameters:
 *   dst - destination CF_ENCODER_CTX
 *   src - source CF_ENCODER_CTX
 *
 * Notes:
 *   The cloned context is independent from the source and can be used
 *   concurrently in separate threads.
 */
CF_API CF_STATUS CF_Enc_CloneCtx(CF_ENCODER_CTX *dst, const CF_ENCODER_CTX *src);

/*
 * CF_Enc_CloneCtxAlloc
 *
 * Allocates a new CF_ENCODER_CTX on the heap and clones the source context.
 * Internally calls CF_Enc_CloneCtx to perform validation and copying.
 *
 * Returns:
 *   pointer to cloned CF_ENCODER_CTX on success
 *   NULL on failure, with *status set to an error code
 *
 * Parameters:
 *   src    - source CF_ENCODER_CTX to clone
 *   status - pointer to receive CF_STATUS result
 *
 * Notes:
 *   The returned context is heap-allocated and must be freed
 *   using the appropriate encoder free routine.
 */
CF_API CF_ENCODER_CTX* CF_Enc_CloneCtxAlloc(const CF_ENCODER_CTX *src, CF_STATUS *status);

/*
 * CF_Enc_ValidateCtx
 *
 * Validates a CF_ENCODER_CTX structure by checking its bound magic value.
 * Detects accidental corruption or misuse of the encoder context.
 *
 * Returns:
 *   CF_SUCCESS         - if the context is valid
 *   CF_ERR_NULL_PTR    - if ctx is NULL
 *   CF_ERR_CTX_CORRUPT - if the context appears tampered or invalid
 *
 * Parameters:
 *   ctx - pointer to CF_ENCODER_CTX to validate
 */
CF_API CF_STATUS CF_Enc_ValidateCtx(const CF_ENCODER_CTX *ctx);

/*
 * CF_Enc_IsValidInput
 *
 * Validates whether a character buffer is a syntactically valid
 * representation for the specified decoding flags.
 * Performs character range checks and reverse-table lookups.
 *
 * Returns:
 *   true  - if all characters are valid for the selected decoder
 *   false - otherwise
 *
 * Parameters:
 *   dec_flags - decoding variant flags
 *   src       - input character buffer
 *   len       - length of input buffer
 *
 * Notes:
 *   This function performs validation only; it does not decode.
 *   URL-safe and alternate alphabet variants are handled internally.
 */
CF_API bool CF_Enc_IsValidInput(uint32_t dec_flags, const char *src, size_t len);

/*
 * CF_Enc_GetName
 *
 * Returns a short human-readable name describing the encoder
 * associated with the provided context.
 *
 * Examples:
 *   "Base16"
 *   "Base32 (NoPad)"
 *   "Base64-URL"
 *   "Base85-Z85"
 *
 * Returns NULL if ctx or ctx->encoder is NULL.
 *
 * Parameters:
 *   ctx - pointer to CF_ENCODER_CTX
 */
CF_API const char* CF_Enc_GetName(const CF_ENCODER_CTX *ctx);


/*
 * CF_Enc_RequiredEncLen
 *
 * Computes the required output length (in characters) for encoding
 * a buffer of input_len bytes using the specified encoding flags.
 *
 * Returns 0 if enc_flags are invalid or input_len is 0.
 *
 * Parameters:
 *   enc_flags - encoding variant flags
 *   input_len - number of input bytes
 *
 * Notes:
 *   The returned size does not include any extra null terminator.
 */
CF_API size_t CF_Enc_RequiredEncLen(uint32_t enc_flags, size_t input_len);

/*
 * CF_Enc_RequiredDecLen
 *
 * Computes the required output length (in bytes) for decoding
 * a buffer of input_len characters using the specified decoding flags.
 *
 * Returns 0 if dec_flags are invalid or input_len is 0.
 *
 * Parameters:
 *   dec_flags - decoding variant flags
 *   input_len - number of encoded characters
 *
 * Notes:
 *   The returned size represents the maximum decoded output length.
 */
CF_API size_t CF_Enc_RequiredDecLen(uint32_t dec_flags, size_t input_len);

/*
 * CF_Enc_MinInput
 *
 * Returns the minimum input block size (in bytes) required
 * by the encoder bound to the context.
 *
 * Returns:
 *   encoder->min_input on success
 *   0 if ctx is NULL or uninitialized
 *   CF_ERR_CTX_CORRUPT if integrity check fails
 *
 * Parameters:
 *   ctx - pointer to CF_ENCODER_CTX
 */
CF_API size_t CF_Enc_MinInput(const CF_ENCODER_CTX *ctx);

/*
 * CF_Enc_MinOutput
 *
 * Returns the minimum output block size (in characters)
 * produced by the encoder bound to the context.
 *
 * Returns:
 *   encoder->min_output on success
 *   0 if ctx is NULL or uninitialized
 *   CF_ERR_CTX_CORRUPT if integrity check fails
 *
 * Parameters:
 *   ctx - pointer to CF_ENCODER_CTX
 */
CF_API size_t CF_Enc_MinOutput(const CF_ENCODER_CTX *ctx);


#ifdef __cplusplus
}
#endif

#endif // CF_ENCODER_H