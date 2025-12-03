#ifndef EVP_ENCODER_H
#define EVP_ENCODER_H

#include "../../utils/mem.h"
#include "../../utils/cf_status.h"
#include "../../config/libs.h"

#include "../enc/base64.h"
// #include "../enc/base32.h"
// #include "../enc/base58.h"
// etc.

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// Low-level encoder/decoder descriptor
// ============================
typedef struct _EVP_ENCODER {
    uint32_t id;                  // encoder ID / flag (e.g., BASE64_FLAG)
    size_t block_size;            // input bytes per block (3 for Base64)
    size_t encoded_block_size;    // output chars per block (4 for Base64)
    size_t ctx_size;              // low-level context size (e.g., ll_BASE64_ENC_CTX)
    size_t opts_size;             // optional encoder options size

    // Encoding function pointers
    bool (*init_fn)(void *ctx, const void *opts);
    bool (*update_fn)(void *ctx, const uint8_t *in, size_t in_len,
                           char *out, size_t *out_len);
    bool (*final_fn)(void *ctx, char *out, size_t *out_len);

    // Decoding function pointers
    bool (*dec_init_fn)(void *ctx, const void *opts);
    bool (*dec_update_fn)(void *ctx, const char *in, size_t in_len,
                               uint8_t *out, size_t *out_len);
    bool (*dec_final_fn)(void *ctx, uint8_t *out, size_t *out_len);
} EVP_ENCODER;

// Lookup encoder descriptor by flag
CF_API const EVP_ENCODER* EVP_EncodeoderByFlag(uint32_t encoder_flag);

// ============================
// Unified encoder/decoder context
// ============================
typedef struct _EVP_ENCODER_CTX {
    const EVP_ENCODER *encoder;   // pointer to descriptor
    void *low_level_ctx;          // allocated ll_BASE*_CTX
    const void *opts;             // optional encoder options

    int isFinalized;
    int isHeapAlloc;
} EVP_ENCODER_CTX;

// ============================
// Encoding functions
// ============================
CF_API CF_STATUS EVP_EncodeInit(EVP_ENCODER_CTX *ctx, const EVP_ENCODER *encoder, const void *opts);
CF_API EVP_ENCODER_CTX* EVP_EncodeInitAlloc(const EVP_ENCODER *encoder, const void *opts, CF_STATUS *status);

CF_API CF_STATUS EVP_EncodeUpdate(EVP_ENCODER_CTX *ctx,
                               const uint8_t *in, size_t in_len,
                               char *out, size_t *out_len);

CF_API CF_STATUS EVP_EncodeFinal(EVP_ENCODER_CTX *ctx, char *out, size_t *out_len);

CF_API CF_STATUS EVP_EncodeFree(EVP_ENCODER_CTX *ctx);
CF_API CF_STATUS EVP_EncodeFreeAlloc(EVP_ENCODER_CTX **p_ctx);

// One-shot encoding
CF_API CF_STATUS EVP_Encode(const EVP_ENCODER *encoder,
                            const uint8_t *in, size_t in_len,
                            char *out, size_t *out_len,
                            const void *opts);

CF_API CF_STATUS EVP_EncodeRaw(const EVP_ENCODER *encoder,
                               const void *in, size_t in_len,
                               char *out, size_t *out_len,
                               const void *opts);

// ============================
// Decoding functions
// ============================
CF_API CF_STATUS EVP_DecodeInit(EVP_ENCODER_CTX *ctx, const EVP_ENCODER *encoder, const void *opts);
CF_API EVP_ENCODER_CTX* EVP_DecodeInitAlloc(const EVP_ENCODER *encoder, const void *opts, CF_STATUS *status);

CF_API CF_STATUS EVP_DecodeUpdate(EVP_ENCODER_CTX *ctx,
                               const char *in, size_t in_len,
                               uint8_t *out, size_t *out_len);

CF_API CF_STATUS EVP_DecodeFinal(EVP_ENCODER_CTX *ctx, uint8_t *out, size_t *out_len);

CF_API CF_STATUS EVP_DecodeFree(EVP_ENCODER_CTX *ctx);
CF_API CF_STATUS EVP_DecodeFreeAlloc(EVP_ENCODER_CTX **p_ctx);

// One-shot decoding
CF_API CF_STATUS EVP_Decode(const EVP_ENCODER *encoder,
                            const char *in, size_t in_len,
                            uint8_t *out, size_t *out_len,
                            const void *opts);
CF_API CF_STATUS EVP_DecodeRaw(const EVP_ENCODER *encoder,
                               const void *in, size_t in_len,
                               uint8_t *out, size_t *out_len,
                               const void *opts);

#ifdef __cplusplus
}
#endif

#endif // EVP_ENCODER_H