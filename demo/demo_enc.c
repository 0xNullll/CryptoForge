#include "../config/demo_config.h"

#if ENABLE_TESTS

void test_base64() {
    const char *tests[] = {
        "",             // empty string
        "f",            // 1 byte → padding ==
        "fo",           // 2 bytes → padding =
        "foo",          // 3 bytes → no padding
        "foob",         // 4 bytes → padding =
        "fooba",        // 5 bytes → padding =
        "foobar"        // 6 bytes → no padding
    };

    size_t num_tests = sizeof(tests) / sizeof(tests[0]);

    for (size_t t = 0; t < num_tests; t++) {
        const char *input = tests[t];
        size_t input_len = strlen(input);

        char encoded[228] = {0};
        size_t enc_len = 0;

        if (!ll_BASE64_Encode((const uint8_t *)input, input_len, encoded, &enc_len)) {
            printf("[FAIL] Encode failed for \"%s\"\n", input);
            continue;
        }

        uint8_t decoded[228] = {0};
        size_t dec_len = 0;

        if (!ll_BASE64_Decode(encoded, enc_len, decoded, &dec_len)) {
            printf("[FAIL] Decode failed for \"%s\"\n", input);
            continue;
        }

        if (dec_len != input_len || memcmp(input, decoded, input_len) != 0) {
            printf("[FAIL] Round-trip mismatch for \"%s\"\n", input);
            printf("Encoded: %s\n", encoded);
            printf("Decoded: %.*s\n", (int)dec_len, decoded);
        } else {
            printf("[PASS] \"%s\" → \"%s\" → OK\n", input, encoded);
        }
    }
}

#endif // ENABLE_TESTS