#include "../../src/CryptoForge/include/config/test_config.h"

#if ENABLE_TESTS

#define MAX_TEST_ENCODER_BUF 620

void cf_encoder_api_test(void) {
    #if ENABLE_TESTS_VERBOSE
        printf("[*] Encoder API smoke-test starting...\n");
    #else
        printf("Encoder API tests:\n");
    #endif

    // -------------------------
    // Test strings
    // -------------------------
    const char *test_strings[] = {
        "hello",
        "foobar",
        "Base encoding test!",
        "any carnal pleasure.",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_",
        "Man is distinguished, not only by his reason, but by this singular passion from other animals, "
        "which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable "
        "generation of knowledge, exceeds the short vehemence of any carnal pleasure."
    };
    size_t num_test_strings = sizeof(test_strings) / sizeof(test_strings[0]);

    // -------------------------
    // Test hex arrays (binary)
    // -------------------------
    const uint8_t test_hex_1[] = { 0x14, 0xFB, 0x9C, 0x03, 0xD9, 0x7E };
    const uint8_t test_hex_2[] = { 0x14, 0xFB, 0x9C, 0x03, 0xD9 };
    const uint8_t test_hex_3[] = { 0x14, 0xFB, 0x9C, 0x03 };
    const uint8_t test_hex_4[] = { 0x00, 0x00, 0x01, 0x02 };
    const uint8_t test_hex_5[] = { 0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B };

    const uint8_t *test_hex[] = {
        test_hex_1, test_hex_2, test_hex_3, test_hex_4, test_hex_5
    };
    size_t test_hex_len[] = {
        sizeof(test_hex_1), sizeof(test_hex_2), sizeof(test_hex_3),
        sizeof(test_hex_4), sizeof(test_hex_5)
    };
    size_t num_test_hex = sizeof(test_hex) / sizeof(test_hex[0]);

    // -------------------------
    // Encoder flags
    // -------------------------
    uint32_t enc_flags[] = {
        CF_BASE16_UPPER,
        CF_BASE16_LOWER,
        CF_BASE32_ENC,
        CF_BASE32_ENC_NOPAD,
        CF_BASE58_ENC,
        CF_BASE64_STD_ENC,
        CF_BASE64_URL_ENC,
        CF_BASE64_NOPAD_ENC,
        CF_BASE85_STD_ENC,
        CF_BASE85_EXT_ENC,
        CF_BASE85_Z85_ENC
    };

    uint32_t dec_flags[] = {
        CF_BASE16_DEC,
        CF_BASE16_DEC,
        CF_BASE32_DEC,
        CF_BASE32_DEC_NOPAD,
        CF_BASE58_DEC,
        CF_BASE64_STD_DEC,
        CF_BASE64_URL_DEC,
        CF_BASE64_NOPAD_DEC,
        CF_BASE85_STD_DEC,
        CF_BASE85_EXT_DEC,
        CF_BASE85_Z85_DEC
    };

    size_t num_encoders = sizeof(enc_flags) / sizeof(enc_flags[0]);

    for (size_t i = 0; i < num_encoders; i++) {
        CF_STATUS st;
        CF_ENCODER_CTX *ctx = CF_Enc_InitAlloc(enc_flags[i], dec_flags[i], &st);
        CF_ASSERT(ctx != NULL && st == CF_SUCCESS);

        const char *enc_name = CF_Enc_GetName(ctx);
#if ENABLE_TESTS_VERBOSE
        printf("[*] Testing encoder: %s\n", enc_name);
#endif

        // -------------------------
        // String tests
        // -------------------------
        for (size_t s = 0; s < num_test_strings; s++) {
            const char *src = test_strings[s];
            size_t src_len = strlen(src);

            size_t enc_len = CF_Enc_RequiredEncLen(enc_flags[i], src_len);
            char enc_buf[MAX_TEST_ENCODER_BUF] = {0};
            CF_ASSERT(enc_len <= sizeof(enc_buf));

            // Skip Z85 if length is not multiple of 4 (adjust if needed)
            if ((enc_flags[i] & CF_BASE85_Z85_ENC) && (src_len % 4 != 0)) {
#if ENABLE_TESTS_VERBOSE
                printf("[!] Skipping Z85 decoding for non-multiple-of-4 input\n");
#endif
                continue;
            }

            st = CF_Enc_Encode(ctx, (const uint8_t*)src, src_len, enc_buf, &enc_len);
            CF_ASSERT(st == CF_SUCCESS);

            uint8_t dec_buf[MAX_TEST_ENCODER_BUF] = {0};
            size_t dec_len = CF_Enc_RequiredDecLen(dec_flags[i], enc_len);
            CF_ASSERT(dec_len <= sizeof(dec_buf));

            st = CF_Enc_Decode(ctx, enc_buf, enc_len, dec_buf, &dec_len);
            CF_ASSERT(st == CF_SUCCESS);
            CF_ASSERT(dec_len == src_len);
            CF_ASSERT(memcmp(src, dec_buf, src_len) == 0);

        }

        // -------------------------
        // Hex tests (binary data)
        // -------------------------
        for (size_t h = 0; h < num_test_hex; h++) {
            const uint8_t *src = test_hex[h];
            size_t src_len = test_hex_len[h];

            size_t enc_len = CF_Enc_RequiredEncLen(enc_flags[i], src_len);
            char enc_buf[MAX_TEST_ENCODER_BUF] = {0};
            CF_ASSERT(enc_len <= sizeof(enc_buf));

            // Skip Z85 if length is not multiple of 4 (adjust if needed)
            if ((enc_flags[i] & CF_BASE85_Z85_ENC) && (src_len % 4 != 0)) {
#if ENABLE_TESTS_VERBOSE
                printf("[!] Skipping Z85 decoding for non-multiple-of-4 input\n");
#endif
                continue;
            }

            st = CF_Enc_Encode(ctx, src, src_len, enc_buf, &enc_len);
            CF_ASSERT(st == CF_SUCCESS);

            uint8_t dec_buf[MAX_TEST_ENCODER_BUF] = {0};
            size_t dec_len = CF_Enc_RequiredDecLen(dec_flags[i], enc_len);
            CF_ASSERT(dec_len <= sizeof(dec_buf));


            st = CF_Enc_Decode(ctx, enc_buf, enc_len, dec_buf, &dec_len);
            CF_ASSERT(st == CF_SUCCESS);
            CF_ASSERT(dec_len == src_len);
            CF_ASSERT(memcmp(src, dec_buf, src_len) == 0);

        }

        // -------------------------
        //  clone / Reset / free
        // -------------------------
        CF_ENCODER_CTX *ctx_clone = CF_Enc_CloneCtxAlloc(ctx, &st);
        CF_ASSERT(ctx_clone != NULL && st == CF_SUCCESS);

        st = CF_Enc_Reset(ctx);
        CF_ASSERT(st == CF_SUCCESS);

        st = CF_Enc_Free(&ctx_clone);
        CF_ASSERT(st == CF_SUCCESS && ctx_clone == NULL);

        st = CF_Enc_Free(&ctx);
        CF_ASSERT(st == CF_SUCCESS && ctx == NULL);

#if ENABLE_TESTS_VERBOSE
        printf("[*] Passed smoke-test for encoder %s\n", enc_name);
#else
        printf("  %-20s  passed\n", enc_name);
#endif
    }

#if ENABLE_TESTS_VERBOSE
    printf("[*] Encoder API smoke-test completed successfully.\n");
#endif
}

#endif // ENABLE_TESTS