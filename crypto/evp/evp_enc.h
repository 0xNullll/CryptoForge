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

    uint32_t no_min_out_flags;  // Flags that bypass min_output rule

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

    uint8_t buffer[5];            // Leftover input bytes for streaming
    size_t buffered_len;

    int isHeapAlloc;              // True if allocated on heap
} EVP_ENCODER_CTX;

// ============================
// Initialization
// ============================
CF_API CF_STATUS EVP_EncInit(EVP_ENCODER_CTX *ctx, uint32_t enc_flags, uint32_t dec_flags);
CF_API EVP_ENCODER_CTX* EVP_EncInitAlloc(uint32_t enc_flags, uint32_t dec_flags, CF_STATUS *status);

// Streaming / incremental encoding
CF_API CF_STATUS EVP_EncUpdate(EVP_ENCODER_CTX *ctx, const uint8_t *src, size_t src_len, char *dst, size_t *dst_len);
CF_API CF_STATUS EVP_EncFinal(EVP_ENCODER_CTX *ctx, char *dst, size_t *dst_len);

// Streaming / incremental decoding
CF_API CF_STATUS EVP_DecUpdate(EVP_ENCODER_CTX *ctx, const char *src, size_t src_len, uint8_t *dst, size_t *dst_len);
CF_API CF_STATUS EVP_DecFinal(EVP_ENCODER_CTX *ctx, uint8_t *dst, size_t *dst_len);

// ============================
// Memory management
// ============================
CF_API CF_STATUS EVP_EncFree(EVP_ENCODER_CTX *ctx);
CF_API CF_STATUS EVP_EncFreeAlloc(EVP_ENCODER_CTX **p_ctx);

// ============================
// One-shot encoding
// ============================
CF_API CF_STATUS EVP_Encode(uint32_t enc_flags,
                            const uint8_t *src, size_t src_len,
                            char *dst, size_t *dst_len);

CF_API CF_STATUS EVP_EncodeRaw(uint32_t enc_flags,
                               const void *src, size_t src_len,
                               char *dst, size_t *dst_len);

CF_API char* EVP_EncodeAlloc(uint32_t enc_flags,
                             const uint8_t *src, size_t src_len,
                             size_t *out_len, CF_STATUS *status);

CF_API char* EVP_EncodeAllocRaw(uint32_t enc_flags,
                                const void *src, size_t src_len,
                                size_t *out_len, CF_STATUS *status);

// ============================
// One-shot decoding
// ============================
CF_API CF_STATUS EVP_Decode(uint32_t dec_flags,
                            const char *src, size_t src_len,
                            uint8_t *dst, size_t *dst_len);

CF_API CF_STATUS EVP_DecodeRaw(uint32_t dec_flags,
                               const void *src, size_t src_len,
                               uint8_t *dst, size_t *dst_len);

CF_API uint8_t* EVP_DecodeAlloc(uint32_t dec_flags,
                                const char *src, size_t src_len,
                                size_t *out_len, CF_STATUS *status);

CF_API uint8_t* EVP_DecodeAllocRaw(uint32_t dec_flags,
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
size_t EVP_EncodeRequiredLen(uint32_t enc_flags, size_t input_len);
size_t EVP_DecodeRequiredLen(uint32_t dec_flags, size_t input_len);

bool EVP_IsValidEncoded(uint32_t dec_flags, const char *src, size_t len);

const char* EVP_EncoderName(EVP_ENCODER_CTX *ctx);
size_t EVP_EncoderMinInput(EVP_ENCODER_CTX *ctx);
size_t EVP_EncoderMinOutput(EVP_ENCODER_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif // EVP_ENCODER_H