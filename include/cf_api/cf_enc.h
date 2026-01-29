/*
 * CryptoForge - cf_enc.h / High-level encoder/decoder context and utility definitions
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the MIT License along with this program.
 * If not, see <https://opensource.org/licenses/MIT>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef CF_ENCODER_H
#define CF_ENCODER_H

#include "../utils/mem.h"
#include "../utils/cf_status.h"
#include "../config/libs.h"

#include "cf_flags.h"

#include "../crypto/base16.h"
#include "../crypto/base32.h"
#include "../crypto/base58.h"
#include "../crypto/base64.h"
#include "../crypto/base85.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// Encoder descriptor
// ============================
typedef struct _CF_ENCODER {
    uint32_t enc_mask;    // Encoding family / type
    uint32_t dec_mask;    // Encoding family / type

    size_t min_input;     // Minimum input bytes per block
    size_t min_output;    // Minimum output chars per block

    uint32_t no_min_flags;  // Flags that bypass min_input & min_output rule

    char min_char;
    char max_char;
    const int8_t *rev_table;      // primary table
    const int8_t *rev_table_alt;  // alternate (URL-safe, Z85, etc.)
    char pad;

    bool (*encode_fn)(
        const uint8_t *data, size_t data_len,
        char *out, size_t *out_len, uint32_t mode);

    bool (*decode_fn)(
        const char *data, size_t data_len,
        uint8_t *out, size_t *out_len, uint32_t mode);
} CF_ENCODER;

// ============================
// Encoder context
// ============================
typedef struct _CF_ENCODER_CTX {
    const CF_ENCODER *encoder;  // Pointer to encoder descriptor

    uint32_t encFlags;            // Variant flags (ENC/DEC/url/nopad, etc.)
    uint32_t decFlags;            // Variant flags (ENC/DEC/url/nopad, etc.)

    int isHeapAlloc;              // True if allocated on heap
} CF_ENCODER_CTX;

// ============================
// Initialization
// ============================
CF_API CF_STATUS CF_EncInit(CF_ENCODER_CTX *ctx, uint32_t enc_flags, uint32_t dec_flags);
CF_API CF_ENCODER_CTX* CF_EncInitAlloc(uint32_t enc_flags, uint32_t dec_flags, CF_STATUS *status);

// ============================
// Memory management
// ============================
CF_API CF_STATUS CF_EncReset(CF_ENCODER_CTX *ctx);
CF_API CF_STATUS CF_EncFree(CF_ENCODER_CTX **p_ctx);

// ============================
// One-shot encoding
// ============================
CF_API CF_STATUS CF_Encode(CF_ENCODER_CTX *ctx,
                            const uint8_t *src, size_t src_len,
                            char *dst, size_t *dst_len);

CF_API CF_STATUS CF_EncodeRaw(CF_ENCODER_CTX *ctx,
                               const void *src, size_t src_len,
                               char *dst, size_t *dst_len);

CF_API char* CF_EncodeAlloc(CF_ENCODER_CTX *ctx,
                             const uint8_t *src, size_t src_len,
                             size_t *out_len, CF_STATUS *status);

CF_API char* CF_EncodeAllocRaw(CF_ENCODER_CTX *ctx,
                                const void *src, size_t src_len,
                                size_t *out_len, CF_STATUS *status);

// ============================
// One-shot decoding
// ============================
CF_API CF_STATUS CF_Decode(CF_ENCODER_CTX *ctx,
                            const char *src, size_t src_len,
                            uint8_t *dst, size_t *dst_len);

CF_API CF_STATUS CF_DecodeRaw(CF_ENCODER_CTX *ctx,
                               const void *src, size_t src_len,
                               uint8_t *dst, size_t *dst_len);

CF_API uint8_t* CF_DecodeAlloc(CF_ENCODER_CTX *ctx,
                                const char *src, size_t src_len,
                                size_t *out_len, CF_STATUS *status);

CF_API uint8_t* CF_DecodeAllocRaw(CF_ENCODER_CTX *ctx,
                                   const void *src, size_t src_len,
                                   size_t *out_len, CF_STATUS *status);

// ============================
// Context cloning
// ============================
CF_API CF_STATUS CF_CloneEncCtx(CF_ENCODER_CTX *dst, const CF_ENCODER_CTX *src);
CF_API CF_ENCODER_CTX* CF_CloneEncCtxAlloc(const CF_ENCODER_CTX *src, CF_STATUS *status);

// ============================
// Utilities
// ============================
CF_API size_t CF_EncodeRequiredLen(uint32_t enc_flags, size_t input_len);
CF_API size_t CF_DecodeRequiredLen(uint32_t dec_flags, size_t input_len);

CF_API bool CF_EncodedIsValid(uint32_t dec_flags, const char *src, size_t len);

CF_API const char* CF_EncName(CF_ENCODER_CTX *ctx);

CF_API size_t CF_EncMinInput(CF_ENCODER_CTX *ctx);
CF_API size_t CF_EncMinOutput(CF_ENCODER_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif // CF_ENCODER_H