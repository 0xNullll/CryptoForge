/*
 * CryptoForge - cf_enc.c / High-level encoder/decoder context implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../include/cf_api/cf_enc.h"

//
// Wrappers for all encoders
//

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

// --- CF_ENCODER Return Functions ---

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

// Table of all supported MACs
static const CF_ALGO_ENTRY cf_encoder_table[] = {
    { CF_BASE16_MASK,  (const void* (*)(void))CF_get_base16 },
    { CF_BASE32_MASK,  (const void* (*)(void))CF_get_base32 },
    { CF_BASE58_MASK,  (const void* (*)(void))CF_get_base58 },
    { CF_BASE64_MASK,  (const void* (*)(void))CF_get_base64 },
    { CF_BASE85_MASK,  (const void* (*)(void))CF_get_base85 }
};

static const CF_ENCODER* CF_Enc_GetByFlag(uint32_t algo_flag) {
    size_t table_len = sizeof(cf_encoder_table) / sizeof(cf_encoder_table[0]);
    for (size_t i = 0; i < table_len; i++) {
        if (cf_encoder_table[i].flag & algo_flag) {
            return (const CF_ENCODER*)cf_encoder_table[i].getter_fn();
        }
    }
    return NULL;
}

CF_STATUS CF_Enc_Init(CF_ENCODER_CTX *ctx, uint32_t enc_flags, uint32_t dec_flags) {
    if (!ctx)
        return CF_ERR_NULL_PTR;
    
    // Ensure heap allocation flag is valid (0 or 1)
    if (ctx->isHeapAlloc != 0 && ctx->isHeapAlloc != 1)
        return CF_ERR_CTX_UNINITIALIZED;

    // Reset the encoder context to a clean state
    CF_Enc_Reset(ctx);

    // Validate encoder and decoder flags
    if (!CF_IS_ENC(enc_flags) || !CF_IS_DEC(dec_flags))
        return CF_ERR_INVALID_PARAM;

    // Retrieve encoder descriptor by flags
    const CF_ENCODER *encoder = CF_Enc_GetByFlag(enc_flags);
    if (!encoder)
        return CF_ERR_INVALID_PARAM;

    // Ensure decoder flags are compatible with the selected encoder
    if ((encoder->dec_mask & dec_flags) == 0)
        return CF_ERR_INVALID_PARAM;

    // Store encoder information and flags in context
    ctx->encoder  = encoder;
    ctx->encFlags = enc_flags;
    ctx->decFlags = dec_flags;

    // Bind a per-context "magic" value for integrity checking
    // Helps detect accidental misuse or memory corruption
    ctx->magic = CF_CTX_MAGIC ^ (uintptr_t)ctx->encoder;

    return CF_SUCCESS;
}

CF_ENCODER_CTX *CF_Enc_InitAlloc(uint32_t enc_flags, uint32_t dec_flags, CF_STATUS *status) {
    // Validate encoder and decoder flags
    if (!CF_IS_ENC(enc_flags) || !CF_IS_DEC(dec_flags)) {
        if (status) *status = CF_ERR_INVALID_PARAM;
        return NULL;
    }

    // Allocate memory for a new encoder context on the heap
    CF_ENCODER_CTX *ctx = (CF_ENCODER_CTX *)SECURE_ALLOC(sizeof(CF_ENCODER_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Initialize the encoder context
    CF_STATUS st = CF_Enc_Init(ctx, enc_flags, dec_flags);
    if (st != CF_SUCCESS) {
        if (status) *status = st;
        // Clean up on failure
        CF_Enc_Free(&ctx);
        return NULL;
    }

    // Mark context as heap-allocated for proper cleanup
    ctx->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return ctx;
}


CF_STATUS CF_Enc_Reset(CF_ENCODER_CTX *ctx) {
    // Validate input pointer
    if (!ctx) return CF_ERR_NULL_PTR;

    // Clear encoder-specific fields
    ctx->encoder = NULL;
    ctx->encFlags = 0;
    ctx->decFlags = 0;

    // Clear magic field to prevent accidental misuse
    ctx->magic = 0;

    return CF_SUCCESS;
}

CF_STATUS CF_Enc_Free(CF_ENCODER_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    CF_ENCODER_CTX *ctx = *p_ctx;

    CF_Enc_Reset(ctx);

    if (ctx->isHeapAlloc) {
        SECURE_FREE(ctx, sizeof(*ctx));  // free the heap memory
    }

    return CF_SUCCESS;
}

CF_STATUS CF_Enc_Encode(CF_ENCODER_CTX *ctx, const uint8_t *src, size_t src_len,  char *dst, size_t *dst_len) {
    if (!ctx || !src || !dst || !dst_len)
        return CF_ERR_NULL_PTR;

    // Ensure the encoder descriptor exists
    if (!ctx->encoder)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify context integrity using the bound magic value
    // Detects accidental corruption or misuse of the encoder context
    if ((ctx->magic ^ (uintptr_t)ctx->encoder) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Check that input length is non-zero
    if (src_len == 0)
        return CF_ERR_INVALID_LEN;

    // Enforce minimum input length if bypass flag is NOT set
    // Ensures encoder requirements are met for block-based encoders
    if (!(ctx->encFlags & ctx->encoder->no_min_flags) &&
        ctx->encoder->min_input > 0 &&
        src_len % ctx->encoder->min_input != 0) {
        return CF_ERR_INVALID_LEN;
    }

    // Call the low-level encoder function
    // This function performs the actual encoding based on ctx->encFlags
    if (!ctx->encoder->encode_fn(src, src_len, dst, dst_len, ctx->encFlags))
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

CF_STATUS CF_Enc_EncodeRaw(CF_ENCODER_CTX *ctx, const void *src, size_t src_len, char *dst, size_t *dst_len) {
    // Wrapper for raw void* input; simply casts to uint8_t* and calls standard encode
    return CF_Enc_Encode(ctx, (const uint8_t *)src, src_len, dst, dst_len);
}

char* CF_Enc_EncodeAlloc(CF_ENCODER_CTX *ctx, const uint8_t *src, size_t src_len, size_t *out_len, CF_STATUS *status) {
    if (!ctx || !src || !out_len) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Ensure the encoder descriptor exists
    if (!ctx->encoder) {
        if (status) *status = CF_ERR_CTX_UNINITIALIZED;
        return NULL;
    }

    // Compute required output buffer size for this encoding operation
    size_t required_len = CF_Enc_RequiredEncLen(ctx->encFlags, src_len);

    // Allocate memory for output
    char *dst = (char*)SECURE_ALLOC(required_len);
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Encode the data into the allocated buffer
    size_t written = 0;
    CF_STATUS res = CF_Enc_Encode(ctx, src, src_len, dst, &written);
    if (status) *status = res;

    // Free allocated memory on failure to prevent leaks
    if (res != CF_SUCCESS) {
        SECURE_FREE(dst, required_len);
        return NULL;
    }

    // Return number of bytes actually written
    *out_len = written;

    return dst;
}

char *CF_Enc_EncodeAllocRaw(CF_ENCODER_CTX *ctx, const void *src, size_t src_len, size_t *out_len, CF_STATUS *status) {
    // Wrapper for raw void* input; calls Allocate + Encode
    return CF_Enc_EncodeAlloc(ctx, (const uint8_t *)src, src_len, out_len, status);
}


CF_STATUS CF_Enc_Decode(CF_ENCODER_CTX *ctx, const char *src, size_t src_len, uint8_t *dst, size_t *dst_len)  {
    if (!ctx || !src || !dst || !dst_len)
        return CF_ERR_NULL_PTR;

    // Ensure the encoder descriptor exists
    if (!ctx->encoder)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify context integrity using the bound magic value
    // Detects accidental corruption or misuse of the encoder context
    if ((ctx->magic ^ (uintptr_t)ctx->encoder) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Check that input length is non-zero
    if (src_len == 0)
        return CF_ERR_INVALID_LEN;

    // Enforce minimum output length if bypass flag is NOT set
    // Ensures decoder requirements are met for block-based encoders
    if (!(ctx->decFlags & ctx->encoder->no_min_flags) &&
        ctx->encoder->min_output > 0 &&
        src_len % ctx->encoder->min_output != 0) {
        return CF_ERR_INVALID_LEN;
    }

    // Call the low-level decoder function
    // This function performs the actual decoding based on ctx->encFlags
    if (!ctx->encoder->decode_fn(src, src_len, dst, dst_len, ctx->decFlags))
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

CF_STATUS CF_Enc_DecodeRaw(CF_ENCODER_CTX *ctx, const void *src, size_t src_len, uint8_t *dst, size_t *dst_len) {
    // Wrapper for raw void* input; casts input to char* and calls standard decode
    return CF_Enc_Decode(ctx, (const char *)src, src_len, dst, dst_len);
}

uint8_t* CF_Enc_DecodeAlloc(CF_ENCODER_CTX *ctx, const char *src, size_t src_len, size_t *out_len, CF_STATUS *status) {
    if (!ctx || !src || !out_len) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Ensure the encoder descriptor exists
    if (!ctx->encoder) {
        if (status) *status = CF_ERR_CTX_UNINITIALIZED;
        return NULL;
    }

    // Compute required output buffer size for decoding
    size_t required_len = CF_Enc_RequiredDecLen(ctx->decFlags, src_len);

    // Allocate memory for decoded output
    uint8_t *dst = (uint8_t *)SECURE_ALLOC(required_len);
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Decode data into allocated buffer
    size_t written = 0;
    CF_STATUS res = CF_Enc_Decode(ctx, src, src_len, dst, &written);
    if (status) *status = res;

    // Free allocated memory on failure
    if (res != CF_SUCCESS) {
        SECURE_FREE(dst, required_len);
        return NULL;
    }

    // Return number of bytes actually written
    *out_len = written;

    return dst;
}

uint8_t* CF_Enc_DecodeAllocRaw(CF_ENCODER_CTX *ctx, const void *src, size_t src_len, size_t *out_len, CF_STATUS *status) {
    // Wrapper for raw void* input; calls Allocate + Decode
    return CF_Enc_DecodeAlloc(ctx, (const char *)src, src_len, out_len, status);
}


size_t CF_Enc_RequiredEncLen(uint32_t enc_flags, size_t input_len) {
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

size_t CF_Enc_RequiredDecLen(uint32_t dec_flags, size_t input_len) {
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

CF_STATUS CF_Enc_ValidateCtx(const CF_ENCODER_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    if ((ctx->magic ^ (uintptr_t)ctx->encoder) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

bool CF_Enc_IsValidInput(uint32_t dec_flags, const char *src, size_t len) {
    if (!CF_IS_DEC(dec_flags) || !src || len == 0)
        return false;

    const CF_ENCODER *encoder = CF_Enc_GetByFlag(dec_flags);
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

const char *CF_Enc_GetName(const CF_ENCODER_CTX *ctx) {
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

    return "UNKNOWN-ENCODER";
}

size_t CF_Enc_MinInput(const CF_ENCODER_CTX *ctx) {
    if (!ctx || !ctx->encoder)
        return 0;

    // Verify that the encoder pointer hasn’t been tampered with by checking it against the bound magic value.
    if ((ctx->magic ^ (uintptr_t)ctx->encoder) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    return ctx->encoder->min_input;
}

size_t CF_Enc_MinOutput(const CF_ENCODER_CTX *ctx) {
    if (!ctx || !ctx->encoder)
        return 0;

    // Verify that the encoder pointer hasn’t been tampered with by checking it against the bound magic value.
    if ((ctx->magic ^ (uintptr_t)ctx->encoder) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    return ctx->encoder->min_output;
}

CF_STATUS CF_Enc_CloneCtx(CF_ENCODER_CTX *dst, const CF_ENCODER_CTX *src) {
    if (!dst || !src)
        return CF_ERR_NULL_PTR;

    // Verify that the encoder pointer hasn’t been tampered with by checking it against the bound magic value.
    if ((src->magic ^ (uintptr_t)src->encoder) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Start with a clean slate
    CF_Enc_Reset(dst);

    // Copy metadata (shallow)
    dst->magic       = src->magic;
    dst->encoder     = src->encoder;
    dst->encFlags    = src->encFlags;
    dst->decFlags    = src->decFlags;

    return CF_SUCCESS;
}

CF_ENCODER_CTX *CF_Enc_CloneCtxAlloc(const CF_ENCODER_CTX *src, CF_STATUS *status) {
    if (!src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    CF_ENCODER_CTX *dst = (CF_ENCODER_CTX *)SECURE_ALLOC(sizeof(CF_ENCODER_CTX));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Deep copy contents
    CF_STATUS ret = CF_Enc_CloneCtx(dst, src);
    if (ret != CF_SUCCESS) {
        if (status) *status = ret;
        CF_Enc_Free(&dst);
        return NULL;
    }

    // cloned context is heap-allocated
    dst->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return dst;
}