#include "evp_enc.h"

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

static const EVP_ENCODER *EVP_get_base16(void) {
    static EVP_ENCODER enc = {
        .enc_mask = EVP_BASE16_UPPER | EVP_BASE16_LOWER,
        .dec_mask = EVP_BASE16_DEC,

        .min_input  = 1,
        .min_output = BASE16_BLOCK_SIZE,

        .no_min_out_flags = 0,

        .encode_fn = base16_encode_wrapper,
        .decode_fn = base16_decode_wrapper
    };
    return &enc;
}

static const EVP_ENCODER *EVP_get_base32(void) {
    static EVP_ENCODER enc = {
        .enc_mask = EVP_BASE32_ENC | EVP_BASE32_ENC_NOPAD,
        .dec_mask = EVP_BASE32_DEC | EVP_BASE32_DEC_NOPAD,

        .min_input  = 1,
        .min_output = BASE32_BLOCK_SIZE,

        .no_min_out_flags = EVP_BASE32_ENC_NOPAD | EVP_BASE32_DEC_NOPAD,

        .encode_fn = base32_encode_wrapper,
        .decode_fn = base32_decode_wrapper
    };
    return &enc;
}

static const EVP_ENCODER *EVP_get_base58(void) {
    static EVP_ENCODER enc = {
        .enc_mask = EVP_BASE58_ENC,
        .dec_mask = EVP_BASE58_DEC,

        .min_input  = 1,
        .min_output = 1,

        .no_min_out_flags = 0,

        .encode_fn = base58_encode_wrapper,
        .decode_fn = base58_decode_wrapper
    };
    return &enc;
}

static const EVP_ENCODER *EVP_get_base64(void) {
    static EVP_ENCODER enc = {
        .enc_mask = EVP_BASE64_STD_ENC | EVP_BASE64_URL_ENC | EVP_BASE64_NOPAD_ENC,
        .dec_mask = EVP_BASE64_STD_DEC | EVP_BASE64_URL_DEC | EVP_BASE64_NOPAD_DEC,

        .min_input  = 1,
        .min_output = BASE64_BLOCK_SIZE,

        .no_min_out_flags = EVP_BASE64_NOPAD_ENC | EVP_BASE64_NOPAD_DEC,

        .encode_fn = base64_encode_wrapper,
        .decode_fn = base64_decode_wrapper
    };
    return &enc;
}

static const EVP_ENCODER *EVP_get_base85(void) {
    static EVP_ENCODER enc = {
        .enc_mask = EVP_BASE85_STD_ENC | EVP_BASE85_EXT_ENC | EVP_BASE85_Z85_ENC,
        .dec_mask = EVP_BASE85_STD_DEC | EVP_BASE85_EXT_DEC | EVP_BASE85_Z85_DEC | EVP_BASE85_IGNORE_WS,

        .min_input  = BASE85_Z85_IN_BLOCK_SIZE,
        .min_output = BASE85_Z85_OUT_BLOCK_SIZE,

        .no_min_out_flags = EVP_BASE85_STD_ENC | EVP_BASE85_EXT_ENC | EVP_BASE85_STD_DEC | EVP_BASE85_EXT_DEC,

        .encode_fn = base64_encode_wrapper,
        .decode_fn = base64_decode_wrapper
    };
    return &enc;
}

// Lookup encoder descriptor by flag
static const EVP_ENCODER* EVP_EncoderByFlag(uint32_t encoder_flag) {
    if (IS_BASE16(encoder_flag))
        return EVP_get_base16();
    if (IS_BASE32(encoder_flag))
        return EVP_get_base32();
    if (IS_BASE58(encoder_flag))
        return EVP_get_base58();
    if (IS_BASE64(encoder_flag))
        return EVP_get_base64();
    if (IS_BASE85(encoder_flag))
        return EVP_get_base85();

    return NULL; // no matching encoder found
}