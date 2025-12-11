/*
 * CryptoForge - evp_enc.h / High-level encoder/decoder context and utility definitions
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef EVP_ENCODER_H
#define EVP_ENCODER_H

#include "../../utils/mem.h"
#include "../../utils/cf_status.h"
#include "../../config/libs.h"

#include "evp_flags.h"

#include "../enc/base16.h"
#include "../enc/base32.h"
#include "../enc/base58.h"
#include "../enc/base64.h"
#include "../enc/base85.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// Encoder descriptor
// ============================
typedef struct _EVP_ENCODER {
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
} EVP_ENCODER;

// ============================
// Encoder context
// ============================
typedef struct _EVP_ENCODER_CTX {
    const EVP_ENCODER *encoder;  // Pointer to encoder descriptor

    uint32_t encFlags;            // Variant flags (ENC/DEC/url/nopad, etc.)
    uint32_t decFlags;            // Variant flags (ENC/DEC/url/nopad, etc.)

    int isHeapAlloc;              // True if allocated on heap
} EVP_ENCODER_CTX;

// ============================
// Initialization
// ============================
CF_API CF_STATUS EVP_EncInit(EVP_ENCODER_CTX *ctx, uint32_t enc_flags, uint32_t dec_flags);
CF_API EVP_ENCODER_CTX* EVP_EncInitAlloc(uint32_t enc_flags, uint32_t dec_flags, CF_STATUS *status);

// ============================
// Memory management
// ============================
CF_API CF_STATUS EVP_EncFreeAlloc(EVP_ENCODER_CTX **p_ctx);

// ============================
// One-shot encoding
// ============================
CF_API CF_STATUS EVP_Encode(EVP_ENCODER_CTX *ctx,
                            const uint8_t *src, size_t src_len,
                            char *dst, size_t *dst_len);

CF_API CF_STATUS EVP_EncodeRaw(EVP_ENCODER_CTX *ctx,
                               const void *src, size_t src_len,
                               char *dst, size_t *dst_len);

CF_API char* EVP_EncodeAlloc(EVP_ENCODER_CTX *ctx,
                             const uint8_t *src, size_t src_len,
                             size_t *out_len, CF_STATUS *status);

CF_API char* EVP_EncodeAllocRaw(EVP_ENCODER_CTX *ctx,
                                const void *src, size_t src_len,
                                size_t *out_len, CF_STATUS *status);

// ============================
// One-shot decoding
// ============================
CF_API CF_STATUS EVP_Decode(EVP_ENCODER_CTX *ctx,
                            const char *src, size_t src_len,
                            uint8_t *dst, size_t *dst_len);

CF_API CF_STATUS EVP_DecodeRaw(EVP_ENCODER_CTX *ctx,
                               const void *src, size_t src_len,
                               uint8_t *dst, size_t *dst_len);

CF_API uint8_t* EVP_DecodeAlloc(EVP_ENCODER_CTX *ctx,
                                const char *src, size_t src_len,
                                size_t *out_len, CF_STATUS *status);

CF_API uint8_t* EVP_DecodeAllocRaw(EVP_ENCODER_CTX *ctx,
                                   const void *src, size_t src_len,
                                   size_t *out_len, CF_STATUS *status);

// ============================
// Context cloning
// ============================
CF_API CF_STATUS EVP_CloneEncCtx(EVP_ENCODER_CTX *dst, const EVP_ENCODER_CTX *src);
CF_API EVP_ENCODER_CTX* EVP_CloneEncCtxAlloc(const EVP_ENCODER_CTX *src, CF_STATUS *status);

// ============================
// Utilities
// ============================
CF_API size_t EVP_EncodeRequiredLen(uint32_t enc_flags, size_t input_len);
CF_API size_t EVP_DecodeRequiredLen(uint32_t dec_flags, size_t input_len);

CF_API bool EVP_IsValidEncoded(uint32_t dec_flags, const char *src, size_t len);

CF_API const char* EVP_EncName(EVP_ENCODER_CTX *ctx);

CF_API size_t EVP_EncMinInput(EVP_ENCODER_CTX *ctx);
CF_API size_t EVP_EncMinOutput(EVP_ENCODER_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif // EVP_ENCODER_H