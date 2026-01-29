/*
 * CryptoForge - cf_enc.c / High-level encoder/decoder context implementation
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

#include "../../include/cf_api/cf_enc.h"

// ======================
// Wrappers for all encoders
// ======================

// BASE-16
static bool base16_encode_wrapper(const uint8_t *data, size_t data_len, char *out, size_t *out_len, uint32_t mode) {
    return ll_BASE16_Encode(data, data_len, out, out_len, mode);
}

static bool base16_decode_wrapper(const char *data, size_t data_len, uint8_t *out, size_t *out_len, uint32_t mode) {
    (void)mode;
    return ll_BASE16_Decode(data, data_len, out, out_len);
}

// BASE-32
static bool base32_encode_wrapper(const uint8_t *data, size_t data_len, char *out, size_t *out_len, uint32_t mode) {
    return ll_BASE32_Encode(data, data_len, out, out_len, mode);
}

static bool base32_decode_wrapper(const char *data, size_t data_len, uint8_t *out, size_t *out_len, uint32_t mode) {
    return ll_BASE32_Decode(data, data_len, out, out_len, mode);
}

// BASE-58
static bool base58_encode_wrapper(const uint8_t *data, size_t data_len, char *out, size_t *out_len, uint32_t mode) {
    (void)mode;
    return ll_BASE58_Encode(data, data_len, out, out_len);
}

static bool base58_decode_wrapper(const char *data, size_t data_len, uint8_t *out, size_t *out_len, uint32_t mode) {
    (void)mode;
    return ll_BASE58_Decode(data, data_len, out, out_len);
}

// BASE-64
static bool base64_encode_wrapper(const uint8_t *data, size_t data_len, char *out, size_t *out_len, uint32_t mode) {
    return ll_BASE64_Encode(data, data_len, out, out_len, mode);
}

static bool base64_decode_wrapper(const char *data, size_t data_len, uint8_t *out, size_t *out_len, uint32_t mode) {
    return ll_BASE64_Decode(data, data_len, out, out_len, mode);
}

// BASE-85
static bool base85_encode_wrapper(const uint8_t *data, size_t data_len, char *out, size_t *out_len, uint32_t mode) {
    return ll_BASE85_Encode(data, data_len, out, out_len, mode);
}

static bool base85_decode_wrapper(const char *data, size_t data_len, uint8_t *out, size_t *out_len, uint32_t mode) {
    return ll_BASE85_Decode(data, data_len, out, out_len, mode);
}

static const CF_ENCODER *CF_get_base16(void) {
    static CF_ENCODER enc = {
        .enc_mask = CF_BASE16_UPPER | CF_BASE16_LOWER,
        .dec_mask = CF_BASE16_DEC,

        .min_input  = 0,
        .min_output = BASE16_BLOCK_SIZE,

        .no_min_flags = 0,

        .min_char = BASE16_MIN,
        .max_char = BASE16_MAX,
        .rev_table = BASE16_REV_TABLE,
        .rev_table_alt = NULL,
        .pad = 0,

        .encode_fn = base16_encode_wrapper,
        .decode_fn = base16_decode_wrapper
    };
    return &enc;
}

static const CF_ENCODER *CF_get_base32(void) {
    static CF_ENCODER enc = {
        .enc_mask = CF_BASE32_ENC | CF_BASE32_ENC_NOPAD,
        .dec_mask = CF_BASE32_DEC | CF_BASE32_DEC_NOPAD,

        .min_input  = 0,
        .min_output = BASE32_BLOCK_SIZE,

        .no_min_flags = CF_BASE32_ENC_NOPAD | CF_BASE32_DEC_NOPAD,

        .min_char  = BASE32_MIN,
        .max_char  = BASE32_MAX,
        .rev_table = BASE32_REV_TABLE,
        .rev_table_alt = NULL,
        .pad       = BASE32_PAD_CHAR,

        .encode_fn = base32_encode_wrapper,
        .decode_fn = base32_decode_wrapper
    };
    return &enc;
}

static const CF_ENCODER *CF_get_base58(void) {
    static CF_ENCODER enc = {
        .enc_mask = CF_BASE58_ENC,
        .dec_mask = CF_BASE58_DEC,

        .min_input  = 0,
        .min_output = 0,

        .no_min_flags = 0,

        .min_char  = BASE58_MIN,
        .max_char  = BASE58_MAX,
        .rev_table = BASE58_REV_TABLE,
        .rev_table_alt = NULL,
        .pad       = 0,

        .encode_fn = base58_encode_wrapper,
        .decode_fn = base58_decode_wrapper
    };
    return &enc;
}

static const CF_ENCODER *CF_get_base64(void) {
    static CF_ENCODER enc = {
        .enc_mask = CF_BASE64_STD_ENC | CF_BASE64_URL_ENC | CF_BASE64_NOPAD_ENC,
        .dec_mask = CF_BASE64_STD_DEC | CF_BASE64_URL_DEC | CF_BASE64_NOPAD_DEC,

        .min_input  = 0,
        .min_output = BASE64_BLOCK_SIZE,

        .no_min_flags = CF_BASE64_NOPAD_ENC | CF_BASE64_NOPAD_DEC,

        .min_char  = BASE64_MIN,
        .max_char  = BASE64_MAX,
        .rev_table     = BASE64_REV_TABLE,           
        .rev_table_alt = BASE64_REV_URL_SAFE_TABLE,
        .pad       = BASE64_PAD_CHAR,

        .encode_fn = base64_encode_wrapper,
        .decode_fn = base64_decode_wrapper
    };
    return &enc;
}

static const CF_ENCODER *CF_get_base85(void) {
    static CF_ENCODER enc = {
        .enc_mask = CF_BASE85_STD_ENC | CF_BASE85_EXT_ENC | CF_BASE85_Z85_ENC,
        .dec_mask = CF_BASE85_STD_DEC | CF_BASE85_EXT_DEC | CF_BASE85_Z85_DEC | CF_BASE85_IGNORE_WS,

        .min_input  = BASE85_Z85_IN_BLOCK_SIZE,
        .min_output = BASE85_Z85_OUT_BLOCK_SIZE,

        .no_min_flags = CF_BASE85_STD_ENC | CF_BASE85_EXT_ENC | CF_BASE85_STD_DEC | CF_BASE85_EXT_DEC,

        .min_char = BASE85_ASCII85_MIN,
        .max_char = BASE85_ASCII85_MAX,
        .rev_table     = BASE85_ASCII85_REV_TABLE,
        .rev_table_alt = BASE85_Z85_REV_TABLE,
        .pad = 0,

        .encode_fn = base85_encode_wrapper,
        .decode_fn = base85_decode_wrapper
    };
    return &enc;
}

// Iternal Lookup encoder descriptor by flag using masks
static const CF_ENCODER* CF_EncoderByFlag(uint32_t encoder_flag) {
    if (encoder_flag & CF_BASE16_MASK)
        return CF_get_base16();
    if (encoder_flag & CF_BASE32_MASK)
        return CF_get_base32();
    if (encoder_flag & CF_BASE58_MASK)
        return CF_get_base58();
    if (encoder_flag & CF_BASE64_MASK)
        return CF_get_base64();
    if (encoder_flag & CF_BASE85_MASK)
        return CF_get_base85();

    return NULL; // no matching encoder found
}

CF_STATUS CF_EncInit(CF_ENCODER_CTX *ctx, uint32_t enc_flags, uint32_t dec_flags) {
    if (!ctx)
        return CF_ERR_NULL_PTR;
    
    CF_EncReset(ctx);

    if (!CF_IS_ENC(enc_flags) || !CF_IS_DEC(dec_flags))
        return CF_ERR_INVALID_PARAM;

    const CF_ENCODER *encoder = CF_EncoderByFlag(enc_flags);
    if (!encoder)
        return CF_ERR_INVALID_PARAM;

    // Check that decoder is compatible with the same family
    if ((encoder->dec_mask & dec_flags) == 0)
        return CF_ERR_INVALID_PARAM;

    ctx->encoder = encoder;
    ctx->encFlags = enc_flags;
    ctx->decFlags = dec_flags;

    return CF_SUCCESS;
}

CF_ENCODER_CTX *CF_EncInitAlloc(uint32_t enc_flags, uint32_t dec_flags, CF_STATUS *status) {
    if (!CF_IS_ENC(enc_flags) || !CF_IS_DEC(dec_flags)) {
        if (status) *status = CF_ERR_INVALID_PARAM;
        return NULL;
    }

    CF_ENCODER_CTX *ctx = (CF_ENCODER_CTX *)SECURE_ALLOC(sizeof(CF_ENCODER_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = CF_EncInit(ctx, enc_flags, dec_flags);
    if (st != CF_SUCCESS) {
        SECURE_FREE(ctx, sizeof(CF_ENCODER_CTX));
        if (status) *status = st;
        return NULL;
    }

    ctx->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS CF_EncReset(CF_ENCODER_CTX *ctx) {
    if (!ctx) return CF_ERR_NULL_PTR;

    int wasHeapAlloc = ctx->isHeapAlloc;

    ctx->encoder = NULL;
    SECURE_ZERO(ctx, sizeof(*ctx));

    ctx->isHeapAlloc = wasHeapAlloc;

    return CF_SUCCESS;
}


CF_STATUS CF_EncFree(CF_ENCODER_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    CF_ENCODER_CTX *ctx = *p_ctx;

    int wasHeapAlloc = ctx->isHeapAlloc;

    CF_EncReset(ctx);

    if (wasHeapAlloc) {
        SECURE_FREE(ctx, sizeof(*ctx));  // free the heap memory
        *p_ctx = NULL;                   // nullify the pointer
    } else {
        SECURE_ZERO(ctx, sizeof(*ctx));  // reset stack context
    }

    return CF_SUCCESS;
}


CF_STATUS CF_Encode(CF_ENCODER_CTX *ctx, const uint8_t *src, size_t src_len,  char *dst, size_t *dst_len) {
    if (!ctx || !ctx->encoder || !src || !dst || !dst_len)
        return CF_ERR_NULL_PTR;

    if (src_len == 0)
        return CF_ERR_INVALID_LEN;

    // Only enforce min_input if bypass flag is NOT set
    if (!(ctx->encFlags & ctx->encoder->no_min_flags) &&
        ctx->encoder->min_input > 0 &&
        src_len % ctx->encoder->min_input != 0) {
        return CF_ERR_INVALID_LEN;
    }

    if (!ctx->encoder->encode_fn(src, src_len, dst, dst_len, ctx->encFlags)) {
        return CF_ERR_CTX_CORRUPT;
    }

    return CF_SUCCESS;
}

CF_STATUS CF_EncodeRaw(CF_ENCODER_CTX *ctx, const void *src, size_t src_len, char *dst, size_t *dst_len) {
    return CF_Encode(ctx, (const uint8_t *)src, src_len, dst, dst_len);
}

char* CF_EncodeAlloc(CF_ENCODER_CTX *ctx, const uint8_t *src, size_t src_len, size_t *out_len, CF_STATUS *status) {
    if (!ctx || !ctx->encoder || !src || !out_len) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Calculate required output length
    size_t required_len = CF_EncodeRequiredLen(ctx->encFlags, src_len);

    // Allocate memory
    char *dst = (char*)SECURE_ALLOC(required_len);
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    size_t written = 0;
    CF_STATUS res = CF_Encode(ctx, src, src_len, dst, &written);
    if (status) *status = res;

    if (res != CF_SUCCESS) {
        SECURE_FREE(dst, required_len);
        return NULL;
    }

    *out_len = written;
    return dst;
}

char *CF_EncodeAllocRaw(CF_ENCODER_CTX *ctx, const void *src, size_t src_len, size_t *out_len, CF_STATUS *status) {
    return CF_EncodeAlloc(ctx, (const uint8_t *)src, src_len, out_len, status);
}


CF_STATUS CF_Decode(CF_ENCODER_CTX *ctx, const char *src, size_t src_len, uint8_t *dst, size_t *dst_len)  {
    if (!ctx || !ctx->encoder || !src || !dst || !dst_len)
        return CF_ERR_NULL_PTR;

    if (src_len == 0)
        return CF_ERR_INVALID_LEN;

    const CF_ENCODER *enc = ctx->encoder;

    // Only enforce min_output if bypass flag is NOT set
    if (!(ctx->decFlags & enc->no_min_flags) &&
        enc->min_output > 0 &&
        src_len % enc->min_output != 0) {
        return CF_ERR_INVALID_LEN;
    }

    if (!enc->decode_fn(src, src_len, dst, dst_len, ctx->decFlags)) {
        return CF_ERR_CTX_CORRUPT;
    }

    return CF_SUCCESS;
}

CF_STATUS CF_DecodeRaw(CF_ENCODER_CTX *ctx, const void *src, size_t src_len, uint8_t *dst, size_t *dst_len) {
    return CF_Decode(ctx, (const char *)src, src_len, dst, dst_len);
}

uint8_t* CF_DecodeAlloc(CF_ENCODER_CTX *ctx, const char *src, size_t src_len, size_t *out_len, CF_STATUS *status) {
    if (!ctx || !ctx->encoder || !src || !out_len) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Calculate required output length
    size_t required_len = CF_DecodeRequiredLen(ctx->decFlags, src_len);

    // Allocate memory
    uint8_t *dst = (uint8_t *)SECURE_ALLOC(required_len);
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    size_t written = 0;
    CF_STATUS res = CF_Decode(ctx, src, src_len, dst, &written);
    if (status) *status = res;

    if (res != CF_SUCCESS) {
        SECURE_FREE(dst, required_len);
        return NULL;
    }

    *out_len = written;
    return dst;
}

uint8_t* CF_DecodeAllocRaw(CF_ENCODER_CTX *ctx, const void *src, size_t src_len, size_t *out_len, CF_STATUS *status) {
    return CF_DecodeAlloc(ctx, (const char *)src, src_len, out_len, status);
}


size_t CF_EncodeRequiredLen(uint32_t enc_flags, size_t input_len) {
    if (!CF_IS_ENC(enc_flags) || input_len == 0)
        return 0;

    if (enc_flags & CF_BASE16_MASK)
        return BASE16_ENC_LEN(input_len);
    if (enc_flags & CF_BASE32_MASK)
        return BASE32_ENC_LEN(input_len);
    if (enc_flags & CF_BASE58_MASK)
        return BASE58_ENC_LEN(input_len);
    if (enc_flags & CF_BASE64_MASK)
        return BASE64_ENC_LEN(input_len);
    if (enc_flags & CF_BASE85_MASK) {
        // Decide between ASCII85 or Z85
        if (enc_flags & CF_BASE85_Z85_ENC)
            return Z85_ENC_LEN(input_len);
        else
            return ASCII85_ENC_LEN(input_len);
    }

    return 0;
}

size_t CF_DecodeRequiredLen(uint32_t dec_flags, size_t input_len) {
    if (!CF_IS_DEC(dec_flags) || input_len == 0)
        return 0;

    if (dec_flags & CF_BASE16_MASK)
        return BASE16_DEC_LEN(input_len);
    if (dec_flags & CF_BASE32_MASK)
        return BASE32_DEC_LEN(input_len);
    if (dec_flags & CF_BASE58_MASK)
        return BASE58_DEC_LEN(input_len);
    if (dec_flags & CF_BASE64_MASK)
        return BASE64_DEC_LEN(input_len);
    if (dec_flags & CF_BASE85_MASK) {
        // Decide between ASCII85 or Z85
        if (dec_flags & CF_BASE85_Z85_DEC)
            return Z85_DEC_LEN(input_len);
        else
            return ASCII85_DEC_LEN(input_len);
    }

    return 0;
}


bool CF_EncodedIsValid(uint32_t dec_flags, const char *src, size_t len) {
    if (!CF_IS_DEC(dec_flags) || !src || len == 0)
        return false;

    const CF_ENCODER *encoder = CF_EncoderByFlag(dec_flags);
    if (!encoder || !encoder->rev_table)
        return false;

    // defaults from encoder
    const int8_t *table = encoder->rev_table;
    char minc = encoder->min_char;
    char maxc = encoder->max_char;
    char pad  = encoder->pad;

    //
    // Base64 URL-safe
    //
    if (dec_flags & CF_BASE64_URL_DEC) {

        if (encoder->rev_table_alt)
            table = encoder->rev_table_alt;

        minc = BASE64_URL_SAFE_MIN;
        maxc = BASE64_URL_SAFE_MAX;

        pad = (dec_flags & CF_BASE64_NOPAD_DEC) ? 0 : BASE64_PAD_CHAR;
    }

    //
    // Base64 NO-PAD
    //
    else if (dec_flags & CF_BASE64_NOPAD_DEC) {
        pad = 0;
    }

    //
    // Base85 Z85
    //
    else if (dec_flags & CF_BASE85_Z85_DEC) {

        if (encoder->rev_table_alt)
            table = encoder->rev_table_alt;

        minc = BASE85_Z85_MIN;
        maxc = BASE85_Z85_MAX;
        pad  = 0;
    }

    //
    // Validate characters
    //
    for (size_t i = 0; i < len; i++) {
        char c = src[i];

        // padding allowed?
        if (pad != 0 && c == pad)
            continue;

        // must be within encoding range
        if (c < minc || c > maxc)
            return false;

        // lookup via reverse table
        int8_t val = table[(unsigned char)(c - minc)];
        if (val == -1)
            return false;
    }

    return true;
}

const char *CF_EncName(CF_ENCODER_CTX *ctx) {
    if (!ctx || !ctx->encoder)
        return NULL;

    uint32_t f = ctx->encFlags;

    //
    // Base16
    //
    if (f & CF_BASE16_MASK)
        return "Base16";

    //
    // Base32
    //
    if (f & CF_BASE32_MASK) {
        if (f & CF_BASE32_ENC_NOPAD)
            return "Base32 (NoPad)";
        return "Base32";
    }

    //
    // Base58
    //
    if (f & CF_BASE58_MASK)
        return "Base58";

    //
    // Base64
    //
    if (f & CF_BASE64_MASK) {
        if (f & CF_BASE64_URL_ENC)
            return (f & CF_BASE64_NOPAD_ENC)
                ? "Base64-URL (NoPad)"
                : "Base64-URL";

        if (f & CF_BASE64_NOPAD_ENC)
            return "Base64 (NoPad)";

        return "Base64";
    }

    //
    // Base85 (ASCII85 & Z85)
    //
    if (f & CF_BASE85_MASK) {
        if (f & CF_BASE85_Z85_ENC)
            return "Base85-Z85";

        if (f & CF_BASE85_EXT_ENC)
            return "Base85-Extended";

        // default
        return "Base85-ASCII85";
    }

    return NULL;
}

size_t CF_EncMinInput(CF_ENCODER_CTX *ctx) {
    if (!ctx || !ctx->encoder)
        return 0;

    return ctx->encoder->min_input;
}

size_t CF_EncMinOutput(CF_ENCODER_CTX *ctx) {
    if (!ctx || !ctx->encoder)
        return 0;

    return ctx->encoder->min_output;
}