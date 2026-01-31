/*
 * CryptoForge - cf_enc.h / High-level encoder/decoder context and utility definitions
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the file LICENSE in the
 * source distribution or at:
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under
 * the License.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
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
// Encoder descriptor
// ============================
typedef struct _CF_ENCODER {
    uint32_t enc_mask;              // Encoding type mask
    uint32_t dec_mask;              // Decoding type mask

    size_t min_input;               // Minimum input bytes per block
    size_t min_output;              // Minimum output chars per block

    uint32_t no_min_flags;          // Flags that bypass min_input & min_output rules

    char min_char;
    char max_char;
    const int8_t *rev_table;       // Primary decoding table
    const int8_t *rev_table_alt;   // Alternate table (URL-safe, Z85, etc.)
    char pad;

    bool (*encode_fn)(const uint8_t *data, size_t data_len, char *out, size_t *out_len, uint32_t mode);
    bool (*decode_fn)(const char *data, size_t data_len, uint8_t *out, size_t *out_len, uint32_t mode);
} CF_ENCODER;

// ============================
// Encoder context
// ============================
typedef struct _CF_ENCODER_CTX {
    const CF_ENCODER *encoder;     // Encoder descriptor
    uint32_t encFlags;             // Encoding variant flags
    uint32_t decFlags;             // Decoding variant flags
    int isHeapAlloc;               // True if allocated on heap
} CF_ENCODER_CTX;

// ============================
// Initialization
// ============================
CF_API CF_STATUS CF_Enc_Init(CF_ENCODER_CTX *ctx, uint32_t enc_flags, uint32_t dec_flags);
CF_API CF_ENCODER_CTX* CF_Enc_InitAlloc(uint32_t enc_flags, uint32_t dec_flags, CF_STATUS *status);

// ============================
// Reset / Free
// ============================
CF_API CF_STATUS CF_Enc_Reset(CF_ENCODER_CTX *ctx);
CF_API CF_STATUS CF_Enc_Free(CF_ENCODER_CTX **p_ctx);

// ============================
// One-shot encoding
// ============================
CF_API CF_STATUS CF_Enc_Encode(CF_ENCODER_CTX *ctx,
                               const uint8_t *src, size_t src_len,
                               char *dst, size_t *dst_len);

CF_API CF_STATUS CF_Enc_EncodeRaw(CF_ENCODER_CTX *ctx,
                                  const void *src, size_t src_len,
                                  char *dst, size_t *dst_len);

CF_API char* CF_Enc_EncodeAlloc(CF_ENCODER_CTX *ctx,
                                const uint8_t *src, size_t src_len,
                                size_t *out_len, CF_STATUS *status);

CF_API char* CF_Enc_EncodeAllocRaw(CF_ENCODER_CTX *ctx,
                                   const void *src, size_t src_len,
                                   size_t *out_len, CF_STATUS *status);

// ============================
// One-shot decoding
// ============================
CF_API CF_STATUS CF_Enc_Decode(CF_ENCODER_CTX *ctx,
                               const char *src, size_t src_len,
                               uint8_t *dst, size_t *dst_len);

CF_API CF_STATUS CF_Enc_DecodeRaw(CF_ENCODER_CTX *ctx,
                                  const void *src, size_t src_len,
                                  uint8_t *dst, size_t *dst_len);

CF_API uint8_t* CF_Enc_DecodeAlloc(CF_ENCODER_CTX *ctx,
                                   const char *src, size_t src_len,
                                   size_t *out_len, CF_STATUS *status);

CF_API uint8_t* CF_Enc_DecodeAllocRaw(CF_ENCODER_CTX *ctx,
                                      const void *src, size_t src_len,
                                      size_t *out_len, CF_STATUS *status);

// ============================
// Cloning
// ============================
CF_API CF_STATUS CF_Enc_CloneCtx(CF_ENCODER_CTX *dst, const CF_ENCODER_CTX *src);
CF_API CF_ENCODER_CTX* CF_Enc_CloneCtxAlloc(const CF_ENCODER_CTX *src, CF_STATUS *status);

// ============================
// Utility functions
// ============================
CF_API size_t CF_Enc_RequiredEncLen(uint32_t enc_flags, size_t input_len);
CF_API size_t CF_Enc_RequiredDecLen(uint32_t dec_flags, size_t input_len);

CF_API bool CF_Enc_IsValid(uint32_t dec_flags, const char *src, size_t len);

CF_API const char* CF_Enc_GetName(const CF_ENCODER_CTX *ctx);

CF_API size_t CF_Enc_MinInput(const CF_ENCODER_CTX *ctx);
CF_API size_t CF_Enc_MinOutput(const CF_ENCODER_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif // CF_ENCODER_H