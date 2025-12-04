#include "../config/demo_config.h"

#if ENABLE_TESTS

void test_base32(const char *label, const uint8_t *input, size_t len, int noPad) {
    char encoded[512] = {0};   // big enough buffer
    uint8_t decoded[512] = {0};
    size_t enc_len = 0, dec_len = 0;

    bool enc_ok = ll_BASE32_Encode(input, len, encoded, &enc_len, noPad);
    if (!enc_ok) {
        printf("[%s] Encode failed\n", label);
        return;
    }

    bool dec_ok = ll_BASE32_Decode(encoded, enc_len, decoded, &dec_len, noPad);
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

void test_hex_base32(const char *label, const uint8_t *input, size_t len, int noPad) {
    char encoded[512] = {0};   // big enough buffer
    uint8_t decoded[512] = {0};
    size_t enc_len = 0, dec_len = 0;

    bool enc_ok = ll_BASE32_Encode(input, len, encoded, &enc_len, noPad);
    if (!enc_ok) {
        printf("[%s] Encode failed\n", label);
        return;
    }

    bool dec_ok = ll_BASE32_Decode(encoded, enc_len, decoded, &dec_len, noPad);
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


#endif // ENABLE_TESTS