#include "../include/config/demo_config.h"

#if ENABLE_TESTS

void test_base16(const char *label, const uint8_t *input, size_t len, uint32_t mode) {
    char encoded[1024] = {0};   // big enough buffer
    uint8_t decoded[1024] = {0};
    size_t enc_len = sizeof(encoded);
    size_t dec_len = sizeof(decoded);

    bool enc_ok = ll_BASE16_Encode(input, len, encoded, &enc_len, mode);
    if (!enc_ok) {
        printf("[%s] Encode failed\n", label);
        return;
    }

    bool dec_ok = ll_BASE16_Decode(encoded, enc_len, decoded, &dec_len);
    if (!dec_ok) {
        printf("[%s] Decode failed\n", label);
        return;
    }

    int match = (dec_len == len && memcmp(input, decoded, len) == 0);

    printf("[%s]\n", label);
    printf("Input:     '");
    for (size_t i = 0; i < len; i++) putchar(input[i]);
    printf("'\n");

    printf("Encoded:   '%s'\n", encoded);

    printf("Decoded:   '");
    for (size_t i = 0; i < dec_len; i++) putchar(decoded[i]);
    printf("'\n");

    printf("Match:     %s\n\n", match ? "YES" : "NO");
}

void test_hex_base16(const char *label, const uint8_t *input, size_t len, uint32_t mode) {
    char encoded[512] = {0};   // big enough buffer
    uint8_t decoded[512] = {0};
    size_t enc_len = sizeof(encoded);
    size_t dec_len = sizeof(decoded);

    bool enc_ok = ll_BASE16_Encode(input, len, encoded, &enc_len, mode);
    if (!enc_ok) {
        printf("[%s] Encode failed\n", label);
        return;
    }

    bool dec_ok = ll_BASE16_Decode(encoded, enc_len, decoded, &dec_len);
    if (!dec_ok) {
        printf("[%s] Decode failed\n", label);
        return;
    }

    int match = (dec_len == len && memcmp(input, decoded, len) == 0);

    printf("[%s]\n", label);
    printf("Input:     ");
    for (size_t i = 0; i < len; i++) printf("%02X ", input[i]);
    printf("\n");

    printf("Encoded:   '%s'\n", encoded);

    printf("Decoded:   ");
    for (size_t i = 0; i < dec_len; i++) printf("%02X ", decoded[i]);
    printf("\n");

    printf("Match:     %s\n\n", match ? "YES" : "NO");
}

void test_base32(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mod) {
    char encoded[512] = {0};   // big enough buffer
    uint8_t decoded[512] = {0};
    size_t enc_len = 0, dec_len = 0;

    bool enc_ok = ll_BASE32_Encode(input, len, encoded, &enc_len, enc_mode);
    if (!enc_ok) {
        printf("[%s] Encode failed\n", label);
        return;
    }

    bool dec_ok = ll_BASE32_Decode(encoded, enc_len, decoded, &dec_len, dec_mod);
    if (!dec_ok) {
        printf("[%s] Decode failed\n", label);
        return;
    }

    int match = (dec_len == len && memcmp(input, decoded, len) == 0);

    printf("[%s]\n", label);
    printf("Input:     '");
    for (size_t i = 0; i < len; i++) putchar(input[i]);
    printf("'\n");

    printf("Encoded:   '%.*s'\n", (int)enc_len, encoded);

    printf("Decoded:   '");
    for (size_t i = 0; i < dec_len; i++) putchar(decoded[i]);
    printf("'\n");

    printf("Match:     %s\n\n", match ? "YES" : "NO");
}

void test_hex_base32(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mod) {
    char encoded[512] = {0};   // big enough buffer
    uint8_t decoded[512] = {0};
    size_t enc_len = 0, dec_len = 0;

    bool enc_ok = ll_BASE32_Encode(input, len, encoded, &enc_len, enc_mode);
    if (!enc_ok) {
        printf("[%s] Encode failed\n", label);
        return;
    }

    bool dec_ok = ll_BASE32_Decode(encoded, enc_len, decoded, &dec_len, dec_mod);
    if (!dec_ok) {
        printf("[%s] Decode failed\n", label);
        return;
    }

    int match = (dec_len == len && memcmp(input, decoded, len) == 0);

    printf("[%s]\n", label);
    printf("Input:     ");
    for (size_t i = 0; i < len; i++) printf("%02X ", input[i]);
    printf("\n");

    printf("Encoded:   '%.*s'\n", (int)enc_len, encoded);

    printf("Decoded:   ");
    for (size_t i = 0; i < dec_len; i++) printf("%02X ", decoded[i]);
    printf("\n");

    printf("Match:     %s\n\n", match ? "YES" : "NO");
}


void test_base58(const char *label, const uint8_t *input, size_t len) {
    char encoded[512] = {0};   // big enough buffer
    uint8_t decoded[512] = {0};
    size_t enc_len = sizeof(encoded);
    size_t dec_len = sizeof(decoded);

    bool enc_ok = ll_BASE58_Encode(input, len, encoded, &enc_len);
    if (!enc_ok) {
        printf("[%s] Encode failed\n", label);
        return;
    }

    bool dec_ok = ll_BASE58_Decode(encoded, enc_len, decoded, &dec_len);
    if (!dec_ok) {
        printf("[%s] Decode failed\n", label);
        return;
    }

    int match = (dec_len == len && memcmp(input, decoded, len) == 0);

    printf("[%s]\n", label);
    printf("Input:     '");
    for (size_t i = 0; i < len; i++) putchar(input[i]);
    printf("'\n");

    printf("Encoded:   '%s'\n", encoded);

    printf("Decoded:   '");
    for (size_t i = 0; i < dec_len; i++) putchar(decoded[i]);
    printf("'\n");

    printf("Match:     %s\n\n", match ? "YES" : "NO");
}

void test_hex_base58(const char *label, const uint8_t *input, size_t len) {
    char encoded[512] = {0};   // big enough buffer
    uint8_t decoded[512] = {0};
    size_t enc_len = sizeof(encoded);
    size_t dec_len = sizeof(decoded);

    bool enc_ok = ll_BASE58_Encode(input, len, encoded, &enc_len);
    if (!enc_ok) {
        printf("[%s] Encode failed\n", label);
        return;
    }

    bool dec_ok = ll_BASE58_Decode(encoded, enc_len, decoded, &dec_len);
    if (!dec_ok) {
        printf("[%s] Decode failed\n", label);
        return;
    }

    int match = (dec_len == len && memcmp(input, decoded, len) == 0);

    printf("[%s]\n", label);
    printf("Input:     ");
    for (size_t i = 0; i < len; i++) printf("%02X ", input[i]);
    printf("\n");

    printf("Encoded:   '%s'\n", encoded);

    printf("Decoded:   ");
    for (size_t i = 0; i < dec_len; i++) printf("%02X ", decoded[i]);
    printf("\n");

    printf("Match:     %s\n\n", match ? "YES" : "NO");
}

void test_base64(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mode) {
    char encoded[512] = {0};   // big enough buffer
    uint8_t decoded[512] = {0};
    size_t enc_len = 0, dec_len = 0;

    bool enc_ok = ll_BASE64_Encode(input, len, encoded, &enc_len, enc_mode);
    if (!enc_ok) {
        printf("[%s] Encode failed\n", label);
        return;
    }

    bool dec_ok = ll_BASE64_Decode(encoded, enc_len, decoded, &dec_len, dec_mode);
    if (!dec_ok) {
        printf("dec_Ok = %d\n", dec_ok);
        printf("[%s] Decode failed\n", label);
        return;
    }

    int match = (dec_len == len && memcmp(input, decoded, len) == 0);

    printf("[%s]\n", label);
    printf("Input:     '");
    for (size_t i = 0; i < len; i++) putchar(input[i]);
    printf("'\n");

    printf("Encoded:   '%.*s'\n", (int)enc_len, encoded);

    printf("Decoded:   '");
    for (size_t i = 0; i < dec_len; i++) putchar(decoded[i]);
    printf("'\n");

    printf("Match:     %s\n\n", match ? "YES" : "NO");
}

void test_hex_base64(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mode) {
    char encoded[512] = {0};   // big enough buffer
    uint8_t decoded[512] = {0};
    size_t enc_len = 0, dec_len = 0;

    bool enc_ok = ll_BASE64_Encode(input, len, encoded, &enc_len, enc_mode);
    if (!enc_ok) {
        printf("[%s] Encode failed\n", label);
        return;
    }

    bool dec_ok = ll_BASE64_Decode(encoded, enc_len, decoded, &dec_len, dec_mode);
    if (!dec_ok) {
        printf("[%s] Decode failed\n", label);
        return;
    }

    int match = (dec_len == len && memcmp(input, decoded, len) == 0);

    printf("[%s]\n", label);
    printf("Input:     ");
    for (size_t i = 0; i < len; i++) printf("%02X ", input[i]);
    printf("\n");

    printf("Encoded:   '%.*s'\n", (int)enc_len, encoded);

    printf("Decoded:   ");
    for (size_t i = 0; i < dec_len; i++) printf("%02X ", input[i]);
    printf("\n");

    printf("Match:     %s\n\n", match ? "YES" : "NO");
}

//
// if Z85 not multiple of 4 it fails which is normal
//
void test_base85(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mode) {
    char encoded[512] = {0};   // big enough buffer
    uint8_t decoded[512] = {0};
    size_t enc_len = 0, dec_len = 0;

    // Check Z85 input length before encoding
    if ((dec_mode & CF_BASE85_Z85_ENC) && (enc_len % 4 != 0)) {
        printf("[%s] Cannot encode Z85:  input length %zu is not a multiple of 4\n", label, enc_len);
        return;
    }

    bool enc_ok = ll_BASE85_Encode(input, len, encoded, &enc_len, enc_mode);
    if (!enc_ok) {
        printf("[%s] Encode failed\n", label);
        return;
    }

    // Check Z85 input length before decoding
    if ((dec_mode & CF_BASE85_Z85_DEC) && (enc_len % 5 != 0)) {
        printf("[%s] Cannot decode Z85: encoded length %zu is not a multiple of 5\n", label, enc_len);
        return;
    }

    bool dec_ok = ll_BASE85_Decode(encoded, enc_len, decoded, &dec_len, dec_mode);
    if (!dec_ok) {
        printf("[%s] Decode failed\n", label);
        return;
    }

    int match = (dec_len == len && memcmp(input, decoded, len) == 0);

    printf("[%s]\n", label);
    printf("Input:     '");
    for (size_t i = 0; i < len; i++) putchar(input[i]);
    printf("'\n");

    printf("Encoded:   '%.*s'\n", (int)enc_len, encoded);

    printf("Decoded:   '");
    for (size_t i = 0; i < dec_len; i++) putchar(decoded[i]);
    printf("'\n");

    printf("Match:     %s\n\n", match ? "YES" : "NO");
}

//
// if Z85 not multiple of 4 it fails which is normal
//
void test_hex_base85(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mode) {
    char encoded[512] = {0};   // big enough buffer
    uint8_t decoded[512] = {0};
    size_t enc_len = 0, dec_len = 0;

    // Check Z85 input length before encoding
    if ((dec_mode & CF_BASE85_Z85_ENC) && (enc_len % 4 != 0)) {
        printf("[%s] Cannot encode Z85:  input length %zu is not a multiple of 4\n", label, enc_len);
        return;
    }

    bool enc_ok = ll_BASE85_Encode(input, len, encoded, &enc_len, enc_mode);
    if (!enc_ok) {
        printf("[%s] Encode failed\n", label);
        return;
    }

    // Check Z85 input length before decoding
    if ((dec_mode & CF_BASE85_Z85_DEC) && (enc_len % 5 != 0)) {
        printf("[%s] Cannot decode Z85: encoded length %zu is not a multiple of 5\n", label, enc_len);
        return;
    }

    bool dec_ok = ll_BASE85_Decode(encoded, enc_len, decoded, &dec_len, dec_mode);
    if (!dec_ok) {
        printf("[%s] Decode failed\n", label);
        return;
    }

    int match = (dec_len == len && memcmp(input, decoded, len) == 0);

    printf("[%s]\n", label);
    printf("Input:     ");
    for (size_t i = 0; i < len; i++) printf("%02X ", input[i]);
    printf("\n");

    printf("Encoded:   '%.*s'\n", (int)enc_len, encoded);

    printf("Decoded:   ");
    for (size_t i = 0; i < dec_len; i++) printf("%02X ", decoded[i]);
    printf("\n");

    printf("Match:     %s\n\n", match ? "YES" : "NO");
}

void test_all_encoders_high(const uint8_t *input, size_t input_len) {
    // Each entry: encode_flags, decode_flags, optional description
    DEMO_ENC_TEST encoder_tests[] = {
        { CF_BASE16_UPPER, CF_BASE16_DEC, "Base16 Upper" },
        { CF_BASE16_LOWER, CF_BASE16_DEC, "Base16 Lower" },
        { CF_BASE32_ENC, CF_BASE32_DEC, "Base32 Standard" },
        { CF_BASE32_ENC | CF_BASE32_ENC_NOPAD, CF_BASE32_DEC | CF_BASE32_DEC_NOPAD, "Base32 NoPad" },
        { CF_BASE58_ENC, CF_BASE58_DEC, "Base58" },
        { CF_BASE64_STD_ENC, CF_BASE64_STD_DEC, "Base64 Std" },
        { CF_BASE64_URL_ENC, CF_BASE64_URL_DEC, "Base64 URL" },
        { CF_BASE64_STD_ENC | CF_BASE64_NOPAD_ENC, CF_BASE64_STD_DEC | CF_BASE64_NOPAD_DEC, "Base64 Std NoPad" },
        { CF_BASE64_URL_ENC | CF_BASE64_NOPAD_ENC, CF_BASE64_URL_DEC | CF_BASE64_NOPAD_DEC, "Base64 URL NoPad" },
        { CF_BASE85_STD_ENC, CF_BASE85_STD_DEC, "Base85 ASCII85" },
        { CF_BASE85_STD_ENC | CF_BASE85_EXT_ENC, CF_BASE85_STD_DEC | CF_BASE85_EXT_DEC, "Base85 ASCII85 Extended" },
        { CF_BASE85_Z85_ENC, CF_BASE85_Z85_DEC, "Base85 Z85" }
    };

    size_t num_tests = sizeof(encoder_tests) / sizeof(encoder_tests[0]);

    for (size_t i = 0; i < num_tests; i++) {
        const DEMO_ENC_TEST t = encoder_tests[i];

        CF_STATUS status;

        // Allocate encoder context
        CF_ENCODER_CTX *ctx = CF_Enc_InitAlloc(t.enc, t.dec, &status);
        if (!ctx || status != CF_SUCCESS) {
            printf("[FAIL] %s: Failed to init context\n", t.desc);
            continue;
        }

        // Prepare output buffer
        size_t out_len = CF_Enc_RequiredEncLen(t.enc, input_len);
        char *enc_buf = (char *)SECURE_ALLOC(out_len);
        if (!enc_buf) {
            printf("[FAIL] %s: Failed to allocate buffer\n", t.desc);
            CF_Enc_Free(&ctx);
            continue;
        }
        memset(enc_buf, 0, out_len);

        // Encode
        status = CF_Enc_Encode(ctx, input, input_len, enc_buf, &out_len);
        if (status != CF_SUCCESS) {
            printf("[FAIL] %s: Encoding failed\n", t.desc);
            free(enc_buf);
            CF_Enc_Free(&ctx);
            continue;
        }

        DEMO_print_str(t.desc, enc_buf, out_len);

        // Decode
        size_t dec_len = CF_Enc_RequiredDecLen(t.dec, out_len);
        uint8_t *dec_buf = (uint8_t *)SECURE_ALLOC(dec_len);
        if (!dec_buf) {
            printf("[FAIL] %s: Failed to allocate decode buffer\n", t.desc);
            free(enc_buf);
            CF_Enc_Free(&ctx);
            continue;
        }
        memset(dec_buf, 0, dec_len);

        status = CF_Enc_Decode(ctx, enc_buf, out_len, dec_buf, &dec_len);
        if (status != CF_SUCCESS) {
            printf("[FAIL] %s: Decoding failed\n", t.desc);
        } else if (dec_len != input_len || memcmp(dec_buf, input, input_len) != 0) {
            printf("[FAIL] %s: Decoded data mismatch\n", t.desc);
        } else {
            printf("[PASS] %s\n", t.desc);
        }

        SECURE_FREE(enc_buf, out_len);
        SECURE_FREE(dec_buf, dec_len);


        CF_Enc_Free(&ctx);
    }
}

#endif // ENABLE_TESTS