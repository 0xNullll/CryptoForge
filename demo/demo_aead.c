#include "../src/include/config/demo_config.h"

#if ENABLE_TESTS

#include "../vectors/wycheproof/tv_aes_gcm.h"
#include "../vectors/wycheproof/tv_chacha20_poly1305.h"
#include "../vectors/wycheproof/tv_xchacha20_poly1305.h"

void test_chacha20_poly1305_wychaproof(void) {
    ll_CHACHA20_POLY1305_CTX ctx = {0};
    uint8_t tag[LL_POLY1305_TAG_LEN] = {0};
    uint8_t ct[CHACHA_BLOCK_SIZE * 2] = {0};
    uint8_t dec[CHACHA_BLOCK_SIZE * 2] = {0};

    // --- Test Vector 1 ---
    uint8_t tv1_key[CHACHA_KEY_SIZE_256] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };

    uint8_t tv1_iv[CHACHA_IV_SIZE] = {
        0x07,0x00,0x00,0x00, 0x40,0x41,0x42,0x43,
        0x44,0x45,0x46,0x47
    };

    uint8_t tv1_aad[] = {
        0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3,
        0xc4,0xc5,0xc6,0xc7
    };

    uint8_t tv1_msg[] = {
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,
        0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,
        0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,
        0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,
        0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,
        0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
        0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,
        0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,
        0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,
        0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,
        0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,
        0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
        0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,
        0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,
        0x74,0x2e
    };

    uint8_t tv1_expected_ct[] = {
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,
        0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
        0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
        0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
        0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,
        0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
        0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,
        0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
        0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
        0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
        0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,
        0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
        0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,
        0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
        0x61,0x16
    };

    uint8_t tv1_expected_tag[LL_POLY1305_TAG_LEN] = {
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
        0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91
    };

    if (!ll_CHACHA20_POLY1305_Init(&ctx, tv1_key, tv1_iv, tv1_aad, sizeof(tv1_aad), true)) {
        printf("CHACHA20-POLY1305 RFC-7539 Encrypt ll_CHACHA20_POLY13051305_Init failed\n"); return;
    }

    if (!ll_CHACHA20_POLY1305_Update(&ctx, tv1_msg, sizeof(tv1_msg), ct)) {
        printf("CHACHA20-POLY1305 RFC-7539 Encrypt ll_CHACHA20_POLY1305_Update failed\n"); return;
    }

    if (!ll_CHACHA20_POLY1305_Final(&ctx, tag)) {
        printf("CHACHA20-POLY1305 RFC-7539 Encrypt ll_CHACHA20_POLY1305_Final failed\n"); return;
    }

    SECURE_ZERO(&ctx, sizeof(ctx));

    if (!ll_CHACHA20_POLY1305_Init(&ctx, tv1_key, tv1_iv, tv1_aad, sizeof(tv1_aad), false)) {
        printf("CHACHA20-POLY1305 RFC-7539 Decrypt ll_CHACHA20_POLY13051305_Init failed\n"); return;
    }

    if (!ll_CHACHA20_POLY1305_Update(&ctx, tv1_expected_ct, sizeof(tv1_expected_ct), dec)) {
        printf("CHACHA20-POLY1305 RFC-7539 Decrypt ll_CHACHA20_POLY1305_Update failed\n"); return;
    }

    if (!ll_CHACHA20_POLY1305_Final(&ctx, tag)) {
        printf("CHACHA20-POLY1305 RFC-7539 Decrypt ll_CHACHA20_POLY1305_Final failed\n"); return;
    }

    printf("CHACHA20-POLY1305 RFC-7539 Example Test:\n");
    printf("Key:       "); DEMO_print_hex(tv1_key, sizeof(tv1_key));
    printf("Plaintext: "); DEMO_print_hex(tv1_msg, sizeof(tv1_msg));
    printf("Ciphertext:"); DEMO_print_hex(ct, sizeof(tv1_expected_ct));
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(tv1_expected_tag, sizeof(tv1_expected_tag));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(tv1_msg));
    if (memcmp(ct, tv1_expected_ct, sizeof(tv1_expected_ct)) == 0 &&
        memcmp(dec, tv1_msg, sizeof(tv1_msg)) == 0 &&
        memcmp(tag, tv1_expected_tag, sizeof(tv1_expected_tag)) == 0) {
        printf("CHACHA20-POLY1305 RFC-7539 Example test PASSED\n");
    } else {
        printf("CHACHA20-POLY1305 RFC-7539 Example test FAILED\n");
    } 

    SECURE_ZERO(&ctx, sizeof(ctx));
    SECURE_ZERO(ct, sizeof(ctx));
    SECURE_ZERO(dec, sizeof(dec));

    // --- Test Vector 2 ---
    uint8_t tv2_key[CHACHA_KEY_SIZE_256] = {
        0x80,0xba,0x31,0x92,0xc8,0x03,0xce,0x96,
        0x5e,0xa3,0x71,0xd5,0xff,0x07,0x3c,0xf0,
        0xf4,0x3b,0x6a,0x2a,0xb5,0x76,0xb2,0x08,
        0x42,0x6e,0x11,0x40,0x9c,0x09,0xb9,0xb0
    };

    uint8_t tv2_iv[CHACHA_IV_SIZE] = {
        0x4d,0xa5,0xbf,0x8d, 0xfd,0x58,0x52,0xc1,
        0xea,0x12,0x37,0x9d
    };

    uint8_t tv2_aad[1] = {0}; // empty
    uint8_t tv2_msg[1] = {0}; // empty
    uint8_t tv2_expected_ct[1] = {0};  // empty

    uint8_t tv2_expected_tag[LL_POLY1305_TAG_LEN] = {
        0x76,0xac,0xb3,0x42,0xcf,0x31,0x66,0xa5,
        0xb6,0x3c,0x0c,0x0e,0xa1,0x38,0x3c,0x8d
    };

    if (!ll_CHACHA20_POLY1305_Init(&ctx, tv2_key, tv2_iv, tv2_aad, 0, true)) {
        printf("CHACHA20-POLY1305 RFC-7539 Encrypt ll_CHACHA20_POLY13051305_Init failed\n"); return;
    }

    if (!ll_CHACHA20_POLY1305_Final(&ctx, tag)) {
        printf("CHACHA20-POLY1305 RFC-7539 Encrypt ll_CHACHA20_POLY1305_Final failed\n"); return;
    }

    if (!ll_CHACHA20_POLY1305_Init(&ctx, tv2_key, tv2_iv, tv2_aad, 0, false)) {
        printf("CHACHA20-POLY1305 RFC-7539 Decrypt ll_CHACHA20_POLY13051305_Init failed\n"); return;
    }

    if (!ll_CHACHA20_POLY1305_Final(&ctx, tag)) {
        printf("CHACHA20-POLY1305 RFC-7539 Decrypt ll_CHACHA20_POLY1305_Final failed\n"); return;
    }

    printf("CHACHA20-POLY1305 RFC-7539 Example Test:\n");
    printf("Key:       "); DEMO_print_hex(tv2_key, sizeof(tv2_key));
    printf("Plaintext: "); DEMO_print_hex(tv2_msg, sizeof(tv2_msg));
    printf("Ciphertext:"); DEMO_print_hex(ct, sizeof(tv2_expected_ct));
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(tv2_expected_tag, sizeof(tv2_expected_tag));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(tv2_msg));
    if (memcmp(ct, tv2_expected_ct, sizeof(tv2_expected_ct)) == 0 &&
        memcmp(dec, tv2_msg, sizeof(tv2_msg)) == 0 &&
        memcmp(tag, tv2_expected_tag, sizeof(tv2_expected_tag)) == 0) {
        printf("CHACHA20-POLY1305 RFC-7539 Example test PASSED\n");
    } else {
        printf("CHACHA20-POLY1305 RFC-7539 Example test FAILED\n");
    } 

}

void test_xchacha20_poly1305_wychaproof(void) {
    ll_XCHACHA20_POLY1305_CTX ctx = {0};
    uint8_t tag[LL_POLY1305_TAG_LEN] = {0};
    uint8_t ct[CHACHA_BLOCK_SIZE * 2] = {0};
    uint8_t dec[CHACHA_BLOCK_SIZE * 2] = {0};

    // --- Test Vector 1 ---
    uint8_t tv1_key[XCHACHA_KEY_SIZE] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };

    uint8_t tv1_iv[XCHACHA_EXTENDED_IV_SIZE] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,
        0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57
    };

    uint8_t tv1_aad[] = {
        0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3,
        0xc4,0xc5,0xc6,0xc7
    };

    uint8_t tv1_msg[] = {
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,
        0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,
        0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,
        0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,
        0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,
        0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
        0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,
        0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,
        0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,
        0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,
        0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,
        0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
        0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,
        0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,
        0x74,0x2e
    };

    uint8_t tv1_expected_ct[] = {
        0xbd,0x6d,0x17,0x9d,0x3e,0x83,0xd4,0x3b,
        0x95,0x76,0x57,0x94,0x93,0xc0,0xe9,0x39,
        0x57,0x2a,0x17,0x00,0x25,0x2b,0xfa,0xcc,
        0xbe,0xd2,0x90,0x2c,0x21,0x39,0x6c,0xbb,
        0x73,0x1c,0x7f,0x1b,0x0b,0x4a,0xa6,0x44,
        0x0b,0xf3,0xa8,0x2f,0x4e,0xda,0x7e,0x39,
        0xae,0x64,0xc6,0x70,0x8c,0x54,0xc2,0x16,
        0xcb,0x96,0xb7,0x2e,0x12,0x13,0xb4,0x52,
        0x2f,0x8c,0x9b,0xa4,0x0d,0xb5,0xd9,0x45,
        0xb1,0x1b,0x69,0xb9,0x82,0xc1,0xbb,0x9e,
        0x3f,0x3f,0xac,0x2b,0xc3,0x69,0x48,0x8f,
        0x76,0xb2,0x38,0x35,0x65,0xd3,0xff,0xf9,
        0x21,0xf9,0x66,0x4c,0x97,0x63,0x7d,0xa9,
        0x76,0x88,0x12,0xf6,0x15,0xc6,0x8b,0x13,
        0xb5,0x2e
    };

    uint8_t tv1_expected_tag[LL_POLY1305_TAG_LEN] = {
        0xc0,0x87,0x59,0x24,0xc1,0xc7,0x98,0x79,
        0x47,0xde,0xaf,0xd8,0x78,0x0a,0xcf,0x49
    };

    if (!ll_XCHACHA20_POLY1305_Init(&ctx, tv1_key, tv1_iv, tv1_aad, sizeof(tv1_aad), true)) {
        printf("XCHACHA20-POLY1305 RFC-7539 Encrypt ll_XCHACHA20_POLY13051305_Init failed\n"); return;
    }

    if (!ll_XCHACHA20_POLY1305_Update(&ctx, tv1_msg, sizeof(tv1_msg), ct)) {
        printf("XCHACHA20-POLY1305 RFC-7539 Encrypt ll_XCHACHA20_POLY1305_Update failed\n"); return;
    }

    if (!ll_XCHACHA20_POLY1305_Final(&ctx, tag)) {
        printf("XCHACHA20-POLY1305 RFC-7539 Encrypt ll_XCHACHA20_POLY1305_Final failed\n"); return;
    }

    SECURE_ZERO(&ctx, sizeof(ctx));

    if (!ll_XCHACHA20_POLY1305_Init(&ctx, tv1_key, tv1_iv, tv1_aad, sizeof(tv1_aad), false)) {
        printf("XCHACHA20-POLY1305 RFC-7539 Decrypt ll_XCHACHA20_POLY13051305_Init failed\n"); return;
    }

    if (!ll_XCHACHA20_POLY1305_Update(&ctx, tv1_expected_ct, sizeof(tv1_expected_ct), dec)) {
        printf("XCHACHA20-POLY1305 RFC-7539 Decrypt ll_XCHACHA20_POLY1305_Update failed\n"); return;
    }

    if (!ll_XCHACHA20_POLY1305_Final(&ctx, tag)) {
        printf("XCHACHA20-POLY1305 RFC-7539 Decrypt ll_XCHACHA20_POLY1305_Final failed\n"); return;
    }

    printf("XCHACHA20-POLY1305 RFC-7539 Example Test:\n");
    printf("Key:       "); DEMO_print_hex(tv1_key, sizeof(tv1_key));
    printf("Plaintext: "); DEMO_print_hex(tv1_msg, sizeof(tv1_msg));
    printf("Ciphertext:"); DEMO_print_hex(ct, sizeof(tv1_expected_ct));
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(tv1_expected_tag, sizeof(tv1_expected_tag));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(tv1_msg));
    if (memcmp(ct, tv1_expected_ct, sizeof(tv1_expected_ct)) == 0 &&
        memcmp(dec, tv1_msg, sizeof(tv1_msg)) == 0 &&
        memcmp(tag, tv1_expected_tag, sizeof(tv1_expected_tag)) == 0) {
        printf("XCHACHA20-POLY1305 RFC-7539 Example test PASSED\n");
    } else {
        printf("XCHACHA20-POLY1305 RFC-7539 Example test FAILED\n");
    } 

    SECURE_ZERO(&ctx, sizeof(ctx));
    SECURE_ZERO(ct, sizeof(ctx));
    SECURE_ZERO(dec, sizeof(dec));

    // --- Test Vector 2 ---
    uint8_t tv2_key[XCHACHA_KEY_SIZE] = {
        0xab,0x15,0x62,0xfa,0xea,0x9f,0x47,0xaf,
        0x3a,0xe1,0xc3,0xd6,0xd0,0x30,0xe3,0xaf,
        0x23,0x02,0x55,0xdf,0xf3,0xdf,0x58,0x3c,
        0xed,0x6f,0xbb,0xcb,0xf9,0xd6,0x06,0xa9
    };

    uint8_t tv2_iv[XCHACHA_EXTENDED_IV_SIZE] = {
        0x6a,0x5e,0x0c,0x46,0x17,0xe0,0x70,0x91,
        0xb6,0x05,0xa4,0xde,0x2c,0x02,0xdd,0xe1,
        0x17,0xde,0x2e,0xbd,0x53,0xb2,0x34,0x97
    };

    uint8_t tv2_aad[1] = {0}; // empty
    uint8_t tv2_msg[1] = {0}; // empty
    uint8_t tv2_expected_ct[1] = {0};  // empty

    uint8_t tv2_expected_tag[LL_POLY1305_TAG_LEN] = {
        0xe2,0x69,0x7e,0xa6,0x87,0x7a,0xba,0x39,
        0xd9,0x55,0x5a,0x00,0xe1,0x4d,0xb0,0x41
    };

    if (!ll_XCHACHA20_POLY1305_Init(&ctx, tv2_key, tv2_iv, tv2_aad, 0, true)) {
        printf("XCHACHA20-POLY1305 RFC-7539 Encrypt ll_XCHACHA20_POLY13051305_Init failed\n"); return;
    }

    if (!ll_XCHACHA20_POLY1305_Final(&ctx, tag)) {
        printf("XCHACHA20-POLY1305 RFC-7539 Encrypt ll_XCHACHA20_POLY1305_Final failed\n"); return;
    }

    if (!ll_XCHACHA20_POLY1305_Init(&ctx, tv2_key, tv2_iv, tv2_aad, 0, false)) {
        printf("XCHACHA20-POLY1305 RFC-7539 Decrypt ll_XCHACHA20_POLY13051305_Init failed\n"); return;
    }

    if (!ll_XCHACHA20_POLY1305_Final(&ctx, tag)) {
        printf("XCHACHA20-POLY1305 RFC-7539 Decrypt ll_XCHACHA20_POLY1305_Final failed\n"); return;
    }

    printf("XCHACHA20-POLY1305 RFC-7539 Example Test:\n");
    printf("Key:       "); DEMO_print_hex(tv2_key, sizeof(tv2_key));
    printf("Plaintext: "); DEMO_print_hex(tv2_msg, sizeof(tv2_msg));
    printf("Ciphertext:"); DEMO_print_hex(ct, sizeof(tv2_expected_ct));
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(tv2_expected_tag, sizeof(tv2_expected_tag));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(tv2_msg));
    if (memcmp(ct, tv2_expected_ct, sizeof(tv2_expected_ct)) == 0 &&
        memcmp(dec, tv2_msg, sizeof(tv2_msg)) == 0 &&
        memcmp(tag, tv2_expected_tag, sizeof(tv2_expected_tag)) == 0) {
        printf("XCHACHA20-POLY1305 RFC-7539 Example test PASSED\n");
    } else {
        printf("XCHACHA20-POLY1305 RFC-7539 Example test FAILED\n");
    } 

}

void test_aes_gcm_fips_style(void) {
    uint8_t plain_text[4 * AES_BLOCK_SIZE] = {
        0x6b, 0xc1, 0xbe, 0xe2,
        0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11,
        0x73, 0x93, 0x17, 0x2a,

        0xae, 0x2d, 0x8a, 0x57,
        0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac,
        0x45, 0xaf, 0x8e, 0x51,

        0x30, 0xc8, 0x1c, 0x46,
        0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef,

        0xf6, 0x9f, 0x24, 0x45,
        0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10
    };

    uint8_t aad[AES_BLOCK_SIZE] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    uint8_t iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    // uint8_t iv[12] = {
    //     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    //     0x08, 0x09, 0x0a, 0x0b
    // };

    ll_AES_KEY key_ctx;
    ll_AES_GCM_CTX gcm_ctx;

    SECURE_ZERO(&key_ctx, sizeof(key_ctx));
    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));

    uint8_t ct[AES_BLOCK_SIZE * 4], tag[AES_BLOCK_SIZE], dec[AES_BLOCK_SIZE * 4];

    // ---------------- AES-128 ----------------
    uint8_t key128[AES_BLOCK_SIZE] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    uint8_t expected_ct128[AES_BLOCK_SIZE * 4] = {
        0x26, 0xdc, 0x83, 0x71,
        0xa5, 0xff, 0x7b, 0x69,
        0x7d, 0x60, 0x4f, 0x8b,
        0x95, 0x5e, 0x73, 0x3b,

        0x7a, 0x5d, 0x98, 0x03,
        0x03, 0x88, 0xdd, 0x96,
        0xb9, 0xc9, 0x6e, 0xad,
        0xd6, 0xe7, 0xe1, 0xa4,

        0x2a, 0x08, 0x16, 0x12,
        0x49, 0x91, 0xbc, 0x6b,
        0x29, 0x8b, 0xa8, 0x2e,
        0x1b, 0x51, 0x75, 0x04,

        0x30, 0xea, 0x7a, 0x54,
        0x02, 0xe8, 0x4e, 0xb2,
        0x10, 0x4e, 0xce, 0x03,
        0xfd, 0x11, 0xae, 0x7a
    };

    uint8_t expected_tag128[AES_BLOCK_SIZE] = {
        0x50, 0x5e, 0xb0, 0x76, 0x20, 0x26, 0x32, 0xc5,
        0x37, 0x8c, 0x74, 0x70, 0x2d, 0x89, 0x23, 0x81
    };

    if (!ll_AES_SetEncryptKey(&key_ctx, key128, sizeof(key128))) { 
        printf("AES-128 init failed\n"); return; 
    }

    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));

    if (!ll_AES_GCM_Init(&gcm_ctx, &key_ctx, iv, sizeof(iv), aad, sizeof(aad), true)) {
        printf("AES-128 GCM Encrypt ll_AES_GCM_Init failed\n"); return;
    }

    if (!ll_AES_GCM_Update(&gcm_ctx, plain_text, sizeof(plain_text), ct)) {
        printf("AES-128 GCM Encrypt ll_AES_GCM_Update failed\n"); return;
    }

    if (!ll_AES_GCM_Final(&gcm_ctx, tag, sizeof(tag))) {
        printf("AES-128 GCM Encrypt ll_AES_GCM_Final failed\n"); return;  
    }

    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));

    if (!ll_AES_GCM_Init(&gcm_ctx, &key_ctx, iv, sizeof(iv), aad, sizeof(aad), false)) {
        printf("AES-128 GCM Decrypt ll_AES_GCM_Init failed\n"); return;
    }

    if (!ll_AES_GCM_Update(&gcm_ctx, ct, sizeof(ct), dec)) {
        printf("AES-128 GCM Decrypt ll_AES_GCM_Update failed\n"); return;
    }

    if (!ll_AES_GCM_Final(&gcm_ctx, tag, sizeof(tag))) {
        printf("AES-128 GCM Decrypt ll_AES_GCM_Final failed\n"); return;  
    }

    ll_AES_ClearKey(&key_ctx);

    printf("AES-128 GCM Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected CT: "); DEMO_print_hex(expected_ct128, sizeof(expected_ct128));
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag128, sizeof(expected_tag128));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-128 GCM test %s\n\n", 
           (memcmp(ct, expected_ct128, sizeof(ct)) == 0 && 
            memcmp(tag, expected_tag128, sizeof(tag)) == 0 &&
            memcmp(dec, plain_text, sizeof(dec)) == 0) ? "PASSED" : "FAILED");


    // ---------------- AES-192 ----------------
    uint8_t key192[24] = {
        0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
        0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
        0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
    };
    uint8_t expected_ct192[AES_BLOCK_SIZE * 4] = {
        0xfa, 0x91, 0x42, 0x90,
        0x7e, 0xa1, 0xab, 0x3b,
        0x76, 0x90, 0x96, 0x9f,
        0x64, 0x43, 0x5b, 0x5e,
        
        0xe6, 0xdb, 0x63, 0xf0,
        0x12, 0x78, 0x84, 0x00,
        0x52, 0xda, 0x39, 0x7d,
        0x87, 0x98, 0x64, 0x5c,
        
        0xcc, 0x05, 0xbb, 0x49,
        0x07, 0x5c, 0x5d, 0x4b,
        0x41, 0x02, 0xf3, 0x5a,
        0x8f, 0x7a, 0x01, 0xbb,
        
        0x05, 0x76, 0xce, 0x3a,
        0xf0, 0x92, 0x3b, 0xfc,
        0xe0, 0xa7, 0x77, 0xbe,
        0xfb, 0x84, 0xd6, 0xea
    };

    uint8_t expected_tag192[AES_BLOCK_SIZE] = {
        0x18, 0x52, 0xdd, 0xc4, 0x55, 0x24, 0x87, 0x5f,
        0x2e, 0xd4, 0xfa, 0x31, 0x4a, 0x05, 0xea, 0x98
    };

    if (!ll_AES_SetEncryptKey(&key_ctx, key192, sizeof(key192))) { 
        printf("AES-192 init failed\n"); return; 
    }

    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));

    if (!ll_AES_GCM_Init(&gcm_ctx, &key_ctx, iv, sizeof(iv), aad, sizeof(aad), true)) {
        printf("AES-192 GCM Encrypt ll_AES_GCM_Init failed\n"); return;
    }

    if (!ll_AES_GCM_Update(&gcm_ctx, plain_text, sizeof(plain_text), ct)) {
        printf("AES-192 GCM Encrypt ll_AES_GCM_Update failed\n"); return;
    }

    if (!ll_AES_GCM_Final(&gcm_ctx, tag, sizeof(tag))) {
        printf("AES-192 GCM Encrypt ll_AES_GCM_Final failed\n"); return;  
    }

    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));

    if (!ll_AES_GCM_Init(&gcm_ctx, &key_ctx, iv, sizeof(iv), aad, sizeof(aad), false)) {
        printf("AES-192 GCM Decrypt ll_AES_GCM_Init failed\n"); return;
    }

    if (!ll_AES_GCM_Update(&gcm_ctx, ct, sizeof(ct), dec)) {
        printf("AES-192 GCM Decrypt ll_AES_GCM_Update failed\n"); return;
    }

    if (!ll_AES_GCM_Final(&gcm_ctx, tag, sizeof(tag))) {
        printf("AES-192 GCM Decrypt ll_AES_GCM_Final failed\n"); return;  
    }

    ll_AES_ClearKey(&key_ctx);

    printf("AES-192 GCM Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected CT: "); DEMO_print_hex(expected_ct192, sizeof(expected_ct192));
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag192, sizeof(expected_tag192));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-192 GCM test %s\n\n", 
           (memcmp(ct, expected_ct192, sizeof(ct)) == 0 && 
            memcmp(tag, expected_tag192, sizeof(tag)) == 0 &&
            memcmp(dec, plain_text, sizeof(dec)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-256 ----------------
    uint8_t key256[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    
    uint8_t expected_ct256[AES_BLOCK_SIZE * 4] = {
        0x95, 0x4e, 0xab, 0x0d,
        0x28, 0x3b, 0x03, 0x99,
        0x75, 0x42, 0xe9, 0x94,
        0x0a, 0xa8, 0x26, 0x49,
        
        0xe7, 0x7b, 0xe3, 0xaa,
        0x13, 0x2e, 0xc5, 0xb3,
        0xc4, 0x90, 0x03, 0x33,
        0xe0, 0xd6, 0x84, 0x16,
        
        0x07, 0x3e, 0xa7, 0x63,
        0x19, 0x5c, 0xee, 0x50,
        0x76, 0x15, 0x35, 0xc1,
        0xd4, 0xe1, 0x28, 0xa6,
        
        0x80, 0x1d, 0x4b, 0x09,
        0xd8, 0xee, 0x6e, 0x82,
        0x64, 0xc8, 0x76, 0xd8,
        0xa9, 0x79, 0xfb, 0xec
    };
    uint8_t expected_tag256[AES_BLOCK_SIZE] = {
        0x6f, 0x38, 0x48, 0x8e, 0xe7, 0x3b, 0x78, 0xe0,
        0x6c, 0xba, 0x37, 0xf0, 0x9b, 0x25, 0xd3, 0x86
    };

    if (!ll_AES_SetEncryptKey(&key_ctx, key256, sizeof(key256))) { 
        printf("AES-256 init failed\n"); return; 
    }

    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));
    
    if (!ll_AES_GCM_Init(&gcm_ctx, &key_ctx, iv, sizeof(iv), aad, sizeof(aad), true)) {
        printf("AES-256 GCM Encrypt ll_AES_GCM_Init failed\n"); return;
    }

    if (!ll_AES_GCM_Update(&gcm_ctx, plain_text, sizeof(plain_text), ct)) {
        printf("AES-256 GCM Encrypt ll_AES_GCM_Update failed\n"); return;
    }

    if (!ll_AES_GCM_Final(&gcm_ctx, tag, sizeof(tag))) {
        printf("AES-256 GCM Encrypt ll_AES_GCM_Final failed\n"); return;  
    }

    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));

    if (!ll_AES_GCM_Init(&gcm_ctx, &key_ctx, iv, sizeof(iv), aad, sizeof(aad), false)) {
        printf("AES-256 GCM Decrypt ll_AES_GCM_Init failed\n"); return;
    }

    if (!ll_AES_GCM_Update(&gcm_ctx, ct, sizeof(ct), dec)) {
        printf("AES-256 GCM Decrypt ll_AES_GCM_Update failed\n"); return;
    }

    if (!ll_AES_GCM_Final(&gcm_ctx, tag, sizeof(tag))) {
        printf("AES-256 GCM Decrypt ll_AES_GCM_Final failed\n"); return;  
    }

    ll_AES_ClearKey(&key_ctx);

    printf("AES-256 GCM Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected CT: "); DEMO_print_hex(expected_ct256, sizeof(expected_ct256));
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag256, sizeof(expected_tag256));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-256 GCM test %s\n", 
           (memcmp(ct, expected_ct256, sizeof(ct)) == 0 && 
            memcmp(tag, expected_tag256, sizeof(tag)) == 0 &&
            memcmp(dec, plain_text, sizeof(dec)) == 0) ? "PASSED" : "FAILED");
}

void test_aes_gcm_empty_plaintext(void) {
    uint8_t zero_string[AES_BLOCK_SIZE * 4] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };


    uint8_t aad[AES_BLOCK_SIZE] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    uint8_t iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    // uint8_t iv[12] = {
    //     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    //     0x08, 0x09, 0x0a, 0x0b
    // };

    uint8_t tag[AES_BLOCK_SIZE];

    ll_AES_KEY key_ctx;
    ll_AES_GCM_CTX gcm_ctx;

    SECURE_ZERO(&key_ctx, sizeof(key_ctx));
    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));

    // ---------------- AES-128 ----------------
    uint8_t key128[AES_BLOCK_SIZE] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    uint8_t expected_tag128[AES_BLOCK_SIZE] = {
        0x68, 0x16, 0xf5, 0x8a, 0x62, 0xc8, 0xf5, 0xff,
        0xbc, 0x2f, 0xf0, 0x92, 0xee, 0x29, 0xa1, 0x12
    };

    if (!ll_AES_SetEncryptKey(&key_ctx, key128, sizeof(key128))) { 
        printf("AES-128 init failed\n"); return; 
    }

    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));

    if (!ll_AES_GCM_Init(&gcm_ctx, &key_ctx, iv, sizeof(iv), aad, sizeof(aad), true)) {
        printf("AES-128 GCM Encrypt ll_AES_GCM_Init failed\n"); return;
    }

    if (!ll_AES_GCM_Final(&gcm_ctx, tag, sizeof(tag))) {
        printf("AES-128 GCM Encrypt ll_AES_GCM_Final failed\n"); return;  
    }

    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));

    if (!ll_AES_GCM_Init(&gcm_ctx, &key_ctx, iv, sizeof(iv), aad, sizeof(aad), false)) {
        printf("AES-128 GCM Decrypt ll_AES_GCM_Init failed\n"); return;
    }

    if (!ll_AES_GCM_Final(&gcm_ctx, tag, sizeof(tag))) {
        printf("AES-128 GCM Decrypt ll_AES_GCM_Final failed\n"); return;  
    }

    ll_AES_ClearKey(&key_ctx);

    printf("AES-128 No Plaintext GCM Test:\n");
    printf("Plaintext: "); DEMO_print_hex(zero_string, sizeof(zero_string));
    printf("Ciphertext: "); DEMO_print_hex(zero_string, sizeof(zero_string));
    printf("Expected CT: "); DEMO_print_hex(zero_string, sizeof(zero_string));
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag128, sizeof(expected_tag128));
    printf("Decrypted: "); DEMO_print_hex(zero_string, sizeof(zero_string));
    printf("AES-128 No Plaintext GCM test %s\n\n", 
           (memcmp(tag, expected_tag128, sizeof(tag)) == 0) ? "PASSED" : "FAILED");


    // ---------------- AES-192 ----------------
    uint8_t key192[24] = {
        0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
        0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
        0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
    };

    uint8_t expected_tag192[AES_BLOCK_SIZE] = {
        0xc4, 0x89, 0xfb, 0xf4, 0xf6, 0x0e, 0x70, 0x68,
        0xf0, 0x9d, 0x4f, 0x0e, 0xb5, 0x58, 0xe1, 0xb3
    };

    if (!ll_AES_SetEncryptKey(&key_ctx, key192, sizeof(key192))) { 
        printf("AES-192 init failed\n"); return; 
    }

    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));

    if (!ll_AES_GCM_Init(&gcm_ctx, &key_ctx, iv, sizeof(iv), aad, sizeof(aad), true)) {
        printf("AES-128 GCM Encrypt ll_AES_GCM_Init failed\n"); return;
    }

    if (!ll_AES_GCM_Final(&gcm_ctx, tag, sizeof(tag))) {
        printf("AES-128 GCM Encrypt ll_AES_GCM_Final failed\n"); return;  
    }

    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));

    if (!ll_AES_GCM_Init(&gcm_ctx, &key_ctx, iv, sizeof(iv), aad, sizeof(aad), false)) {
        printf("AES-128 GCM Decrypt ll_AES_GCM_Init failed\n"); return;
    }

    if (!ll_AES_GCM_Final(&gcm_ctx, tag, sizeof(tag))) {
        printf("AES-128 GCM Decrypt ll_AES_GCM_Final failed\n"); return;  
    }

    ll_AES_ClearKey(&key_ctx);

    printf("AES-192 No Plaintext GCM Test:\n");
    printf("Plaintext: "); DEMO_print_hex(zero_string, sizeof(zero_string));
    printf("Ciphertext: "); DEMO_print_hex(zero_string, sizeof(zero_string));
    printf("Expected CT: "); DEMO_print_hex(zero_string, sizeof(zero_string));
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag192, sizeof(expected_tag192));
    printf("Decrypted: "); DEMO_print_hex(zero_string, sizeof(zero_string));
    printf("AES-192 No Plaintext GCM test %s\n\n", 
           (memcmp(tag, expected_tag192, sizeof(tag)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-256 ----------------
    uint8_t key256[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    
    uint8_t expected_tag256[AES_BLOCK_SIZE] = {
        0xf6, 0xd9, 0x36, 0x9d, 0x0f, 0xec, 0xd0, 0x30,
        0xa1, 0x2d, 0x24, 0x7e, 0x2c, 0xca, 0x3d, 0x3d
    };

    if (!ll_AES_SetEncryptKey(&key_ctx, key256, sizeof(key256))) { 
        printf("AES-256 init failed\n"); return; 
    }

    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));

    if (!ll_AES_GCM_Init(&gcm_ctx, &key_ctx, iv, sizeof(iv), aad, sizeof(aad), true)) {
        printf("AES-128 GCM Encrypt ll_AES_GCM_Init failed\n"); return;
    }

    if (!ll_AES_GCM_Final(&gcm_ctx, tag, sizeof(tag))) {
        printf("AES-128 GCM Encrypt ll_AES_GCM_Final failed\n"); return;  
    }

    SECURE_ZERO(&gcm_ctx, sizeof(gcm_ctx));

    if (!ll_AES_GCM_Init(&gcm_ctx, &key_ctx, iv, sizeof(iv), aad, sizeof(aad), false)) {
        printf("AES-128 GCM Decrypt ll_AES_GCM_Init failed\n"); return;
    }

    if (!ll_AES_GCM_Final(&gcm_ctx, tag, sizeof(tag))) {
        printf("AES-128 GCM Decrypt ll_AES_GCM_Final failed\n"); return;  
    }

    ll_AES_ClearKey(&key_ctx);

    printf("AES-256 No Plaintext GCM Test:\n");
    printf("Plaintext: "); DEMO_print_hex(zero_string, sizeof(zero_string));
    printf("Ciphertext: "); DEMO_print_hex(zero_string, sizeof(zero_string));
    printf("Expected CT: "); DEMO_print_hex(zero_string, sizeof(zero_string));
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag256, sizeof(expected_tag256));
    printf("Decrypted: "); DEMO_print_hex(zero_string, sizeof(zero_string));
    printf("AES-256 No Plaintext GCM test %s\n", 
           (memcmp(tag, expected_tag256, sizeof(tag)) == 0) ? "PASSED" : "FAILED");
}

void test_all_aead_high(void) {
    uint32_t cf_chacha_flags[] = {
        CF_CHACHA20_POLY1305,
        CF_XCHACHA20_POLY1305,
    };

    size_t num_chacha_flags = sizeof(cf_chacha_flags)/sizeof(cf_chacha_flags[0]);

    // --- Test Vector 1 ---
    uint8_t chacha_key[CHACHA_KEY_SIZE_256] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };

    uint8_t chacha_iv[CHACHA_IV_SIZE] = {
        0x07,0x00,0x00,0x00, 0x40,0x41,0x42,0x43,
        0x44,0x45,0x46,0x47
    };


    uint8_t xchacha_iv[XCHACHA_EXTENDED_IV_SIZE] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,
        0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57
    };

    uint8_t chacha_aad[] = {
        0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3,
        0xc4,0xc5,0xc6,0xc7
    };

    uint8_t chacha_plain_text[] = {
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,
        0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,
        0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,
        0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,
        0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,
        0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
        0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,
        0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,
        0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,
        0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,
        0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,
        0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
        0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,
        0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,
        0x74,0x2e
    };

    uint8_t chacha_ct[CHACHA_BLOCK_SIZE * 2] = {0};
    uint8_t chacha_dec[CHACHA_BLOCK_SIZE * 2] = {0};
    uint8_t chacha_tag[CF_AEAD_TAG_128_SIZE] = {0};

    for (size_t i = 0; i < num_chacha_flags; i++) {
        const CF_AEAD *aead = CF_AEAD_GetByFlag(cf_chacha_flags[i]);
        if (!aead) {
            printf("Unknown Cipher flag %u\n", cf_chacha_flags[i]);
            continue;
        }

        CF_AEAD_CTX ctx = {0}; 

        const uint8_t *expected_iv = aead->id == CF_CHACHA20_POLY1305 ? chacha_iv : xchacha_iv;
        size_t expected_iv_len = (aead->id == CF_CHACHA20_POLY1305) ? sizeof(chacha_iv) : sizeof(xchacha_iv);

        // this init just to get the proper credentials for CF_AEAD_GetFullName() for algorithm name display for testing
        CF_STATUS status = CF_AEAD_Init(
            &ctx, aead,
            chacha_key, sizeof(chacha_key),
            expected_iv, expected_iv_len,
            chacha_aad, sizeof(chacha_aad),
            CF_OP_ENCRYPT);

        if (status != CF_SUCCESS) {
            printf("CF_AEAD_Init failed for %s, error status: %u\n", CF_AEAD_GetName(aead), status);
            CF_AEAD_Reset(&ctx);
            continue;
        }

        status = CF_AEAD_Encrypt(aead,
            chacha_key, sizeof(chacha_key),
            expected_iv, expected_iv_len,
            chacha_aad, sizeof(chacha_aad),
            chacha_plain_text, sizeof(chacha_plain_text),
            chacha_ct,
            chacha_tag, sizeof(chacha_tag));

        if (status != CF_SUCCESS) {
            printf("CF_AEAD_Encrypt failed for %s, error status: %u\n", CF_AEAD_GetFullName(&ctx), status);
            continue;
        }

        status = CF_AEAD_Decrypt(aead,
            chacha_key, sizeof(chacha_key),
            expected_iv, expected_iv_len,
            chacha_aad, sizeof(chacha_aad),
            chacha_ct, sizeof(chacha_plain_text),
            chacha_dec,
            chacha_tag, sizeof(chacha_tag));

        if (status != CF_SUCCESS) {
            printf("CF_AEAD_Decrypt failed for %s, error status: %u\n", CF_AEAD_GetFullName(&ctx), status);
            continue;
        }

        printf("%s CT : ", CF_AEAD_GetFullName(&ctx));
        DEMO_print_hex(chacha_ct, sizeof(chacha_plain_text));
        printf("%s DEC: ", CF_AEAD_GetFullName(&ctx));
        DEMO_print_hex(chacha_dec, sizeof(chacha_plain_text));
        printf("%s TAG : ", CF_AEAD_GetFullName(&ctx));
        DEMO_print_hex(chacha_tag, sizeof(chacha_tag));

        printf("\n");

        CF_AEAD_Reset(&ctx);
    }

    putchar('\n');

    uint8_t aes_plain_text[4 * AES_BLOCK_SIZE] = {
        0x6b, 0xc1, 0xbe, 0xe2,
        0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11,
        0x73, 0x93, 0x17, 0x2a,

        0xae, 0x2d, 0x8a, 0x57,
        0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac,
        0x45, 0xaf, 0x8e, 0x51,

        0x30, 0xc8, 0x1c, 0x46,
        0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef,

        0xf6, 0x9f, 0x24, 0x45,
        0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10
    };

    uint8_t aes_aad[AES_BLOCK_SIZE] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    uint8_t aes_iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    static const uint8_t aes_key128[AES_BLOCK_SIZE] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    static const uint8_t aes_key192[24] = {
        0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
        0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
        0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
    };

    static const uint8_t aes_key256[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    static const uint8_t *aes_key_test_vectors[] = {
        aes_key128,
        aes_key192,
        aes_key256
    };

    static const size_t aes_key_test_vectors_sizes[] = {
        sizeof(aes_key128),
        sizeof(aes_key192),
        sizeof(aes_key256)
    };

    size_t num_aes_keys = sizeof(aes_key_test_vectors)/sizeof(aes_key_test_vectors[0]);

    uint8_t aes_ct[AES_BLOCK_SIZE * 4] = {0};
    uint8_t aes_dec[AES_BLOCK_SIZE * 4] = {0};
    uint8_t aes_tag[CF_AEAD_TAG_96_SIZE] = {0};

    for (size_t i = 0; i < num_aes_keys; i++) {
        const CF_AEAD *aead = CF_AEAD_GetByFlag(CF_AES_GCM);
        if (!aead) {
            printf("Unknown Cipher flag %u\n", CF_AES_GCM);
            continue;
        }

        CF_AEAD_CTX ctx = {0};

        // this init just to get the proper credentials for CF_AEAD_GetFullName() for algorithm name display for testing
        CF_STATUS status = CF_AEAD_Init(
            &ctx, aead,
            aes_key_test_vectors[i], aes_key_test_vectors_sizes[i],
            aes_iv, sizeof(aes_iv),
            aes_aad, sizeof(aes_aad),
            CF_OP_ENCRYPT);

        if (status != CF_SUCCESS) {
            printf("CF_AEAD_Init failed for %s, error status: %u\n", CF_AEAD_GetName(aead), status);
            CF_AEAD_Reset(&ctx);
            continue;
        }

        status = CF_AEAD_Encrypt(aead,
            aes_key_test_vectors[i], aes_key_test_vectors_sizes[i],
            aes_iv, sizeof(aes_iv),
            aes_aad, sizeof(aes_aad),
            aes_plain_text, sizeof(aes_plain_text),
            aes_ct,
            aes_tag, sizeof(aes_tag));

        if (status != CF_SUCCESS) {
            printf("CF_AEAD_Encrypt failed for %s, error status: %u\n", CF_AEAD_GetFullName(&ctx), status);
            continue;
        }

        status = CF_AEAD_Decrypt(aead,
            aes_key_test_vectors[i], aes_key_test_vectors_sizes[i],
            aes_iv, sizeof(aes_iv),
            aes_aad, sizeof(aes_aad),
            aes_ct, sizeof(aes_plain_text),
            aes_dec,
            aes_tag, sizeof(aes_tag));

        if (status != CF_SUCCESS) {
            printf("CF_AEAD_Decrypt failed for %s, error status: %u\n", CF_AEAD_GetFullName(&ctx), status);
            continue;
        }

        printf("%s CT : ", CF_AEAD_GetFullName(&ctx));
        DEMO_print_hex(aes_ct, sizeof(chacha_plain_text));
        printf("%s DEC: ", CF_AEAD_GetFullName(&ctx));
        DEMO_print_hex(aes_dec, sizeof(chacha_plain_text));
        printf("%s TAG : ", CF_AEAD_GetFullName(&ctx));
        DEMO_print_hex(aes_tag, sizeof(aes_tag));

        printf("\n");

        CF_AEAD_Reset(&ctx);
    }
}

void test_aes_gcm_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(aes_gcm_test_vectors) / sizeof(aes_gcm_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_AEAD *aead = CF_AEAD_GetByFlag(CF_AES_GCM);
        if (!aead) {
            printf("Unknown Cipher flag %u\n", CF_AES_GCM);
            return;
        }

        uint8_t ct[600]  = {0};
        uint8_t dec[600] = {0};
        uint8_t tag[16]  = {0};

        int expected_valid = (strcmp(aes_gcm_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        /* ================= Encrypt ================= */

        CF_STATUS status = CF_AEAD_Encrypt(
            aead,
            aes_gcm_test_vectors[i].key, aes_gcm_test_vectors[i].key_len,
            aes_gcm_test_vectors[i].iv_len != 0 ? aes_gcm_test_vectors[i].iv : NULL,  aes_gcm_test_vectors[i].iv_len,
            aes_gcm_test_vectors[i].aad_len != 0 ? aes_gcm_test_vectors[i].aad : NULL, aes_gcm_test_vectors[i].aad_len,
            aes_gcm_test_vectors[i].msg_len != 0 ? aes_gcm_test_vectors[i].msg : NULL, aes_gcm_test_vectors[i].msg_len,
            ct, tag, sizeof(tag)
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("AES-GCM TcId %d FAILED (encrypt rejected valid vector)\n",
                   aes_gcm_test_vectors[i].tc_id);
            failure = 1;
            goto print_extra;
        }

        int ct_match =
            (aes_gcm_test_vectors[i].ct_len == aes_gcm_test_vectors[i].msg_len) &&
            (memcmp(ct, aes_gcm_test_vectors[i].ct, aes_gcm_test_vectors[i].ct_len) == 0);

        int tag_match =
            (memcmp(tag, aes_gcm_test_vectors[i].tag, aes_gcm_test_vectors[i].tag_len) == 0);

        if (expected_valid && (!ct_match || !tag_match)) {
            printf("AES-GCM TcId %d FAILED, Error code %u (expected valid)\n",
                   aes_gcm_test_vectors[i].tc_id, status);

            if (!ct_match)
                printf("  Ciphertext mismatch\n");

            if (!tag_match)
                printf("  Tag mismatch\n");

            printf("CT : ");
            DEMO_print_hex(ct, aes_gcm_test_vectors[i].ct_len);

            printf("Expected CT : ");
            DEMO_print_hex(aes_gcm_test_vectors[i].ct, aes_gcm_test_vectors[i].ct_len);

            printf("TAG : ");
            DEMO_print_hex(tag, aes_gcm_test_vectors[i].tag_len);
            printf("Expected TAG : ");
            DEMO_print_hex(aes_gcm_test_vectors[i].tag, aes_gcm_test_vectors[i].tag_len);

            failure = 1;
        }

        /* ================= Decrypt ================= */

        status = CF_AEAD_Decrypt(
            aead,
            aes_gcm_test_vectors[i].key, aes_gcm_test_vectors[i].key_len,
            aes_gcm_test_vectors[i].iv_len != 0 ? aes_gcm_test_vectors[i].iv : NULL,  aes_gcm_test_vectors[i].iv_len,
            aes_gcm_test_vectors[i].aad_len != 0 ? aes_gcm_test_vectors[i].aad : NULL, aes_gcm_test_vectors[i].aad_len,
            aes_gcm_test_vectors[i].ct_len != 0 ? ct : NULL, aes_gcm_test_vectors[i].ct_len,
            dec,
            (uint8_t *)aes_gcm_test_vectors[i].tag, aes_gcm_test_vectors[i].tag_len
        );

        int decrypt_success = (status == CF_SUCCESS);

        if ((expected_valid && !decrypt_success) ||
            (!expected_valid && decrypt_success)) {
            printf("AES-GCM TcId %d FAILED, error code %u\n",
                   aes_gcm_test_vectors[i].tc_id, status);
            failure = 1;
        }

        if (expected_valid && decrypt_success &&
            memcmp(dec, aes_gcm_test_vectors[i].msg, aes_gcm_test_vectors[i].msg_len) != 0) {
            printf("AES-GCM TcId %d FAILED, Error code %u (decrypted plaintext mismatch)\n",
                   aes_gcm_test_vectors[i].tc_id, status);
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

            if (aes_gcm_test_vectors[i].comment &&
                aes_gcm_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", aes_gcm_test_vectors[i].comment);
            }

            if (aes_gcm_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < aes_gcm_test_vectors[i].flags_len; f++) {
                    printf("%s", aes_gcm_test_vectors[i].flags[f]);
                    if (f + 1 < aes_gcm_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
        } else {
            total_success++;
        }
    }

    printf("AES-GCM Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_chacha20_poly1305_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(chacha20_poly1305_test_vectors) / sizeof(chacha20_poly1305_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_AEAD *aead = CF_AEAD_GetByFlag(CF_CHACHA20_POLY1305);
        if (!aead) {
            printf("Unknown Cipher flag %u\n", CF_CHACHA20_POLY1305);
            return;
        }

        uint8_t ct[520]  = {0};
        uint8_t dec[520] = {0};
        uint8_t tag[16]  = {0};

        int expected_valid = (strcmp(chacha20_poly1305_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        /* ================= Encrypt ================= */

        CF_STATUS status = CF_AEAD_Encrypt(
            aead,
            chacha20_poly1305_test_vectors[i].key, chacha20_poly1305_test_vectors[i].key_len,
            chacha20_poly1305_test_vectors[i].iv_len != 0 ? chacha20_poly1305_test_vectors[i].iv : NULL, chacha20_poly1305_test_vectors[i].iv_len,
            chacha20_poly1305_test_vectors[i].aad_len != 0 ? chacha20_poly1305_test_vectors[i].aad : NULL, chacha20_poly1305_test_vectors[i].aad_len,
            chacha20_poly1305_test_vectors[i].msg_len != 0 ? chacha20_poly1305_test_vectors[i].msg : NULL, chacha20_poly1305_test_vectors[i].msg_len,
            ct, tag, sizeof(tag)
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("ChaCha20-Poly1305 TcId %d FAILED (encrypt rejected valid vector)\n",
                   chacha20_poly1305_test_vectors[i].tc_id);
            failure = 1;
            goto print_extra;
        }

        int ct_match =
            (chacha20_poly1305_test_vectors[i].ct_len == chacha20_poly1305_test_vectors[i].msg_len) &&
            (memcmp(ct, chacha20_poly1305_test_vectors[i].ct, chacha20_poly1305_test_vectors[i].ct_len) == 0);

        int tag_match =
            (memcmp(tag, chacha20_poly1305_test_vectors[i].tag, chacha20_poly1305_test_vectors[i].tag_len) == 0);

        if (expected_valid && (!ct_match || !tag_match)) {
            printf("ChaCha20-Poly1305 TcId %d FAILED, Error code %u (expected valid)\n",
                   chacha20_poly1305_test_vectors[i].tc_id, status);

            if (!ct_match)
                printf("  Ciphertext mismatch\n");

            if (!tag_match)
                printf("  Tag mismatch\n");

            printf("CT : ");
            DEMO_print_hex(ct, chacha20_poly1305_test_vectors[i].ct_len);

            printf("Expected CT : ");
            DEMO_print_hex(chacha20_poly1305_test_vectors[i].ct, chacha20_poly1305_test_vectors[i].ct_len);

            printf("TAG : ");
            DEMO_print_hex(tag, chacha20_poly1305_test_vectors[i].tag_len);
            printf("Expected TAG : ");
            DEMO_print_hex(chacha20_poly1305_test_vectors[i].tag, chacha20_poly1305_test_vectors[i].tag_len);

            failure = 1;
        }

        /* ================= Decrypt ================= */

        status = CF_AEAD_Decrypt(
            aead,
            chacha20_poly1305_test_vectors[i].key, chacha20_poly1305_test_vectors[i].key_len,
            chacha20_poly1305_test_vectors[i].iv_len != 0 ? chacha20_poly1305_test_vectors[i].iv : NULL, chacha20_poly1305_test_vectors[i].iv_len,
            chacha20_poly1305_test_vectors[i].aad_len != 0 ? chacha20_poly1305_test_vectors[i].aad : NULL, chacha20_poly1305_test_vectors[i].aad_len,
            chacha20_poly1305_test_vectors[i].ct_len != 0 ? ct : NULL, chacha20_poly1305_test_vectors[i].ct_len,
            dec,
            (uint8_t *)chacha20_poly1305_test_vectors[i].tag, chacha20_poly1305_test_vectors[i].tag_len
        );

        int decrypt_success = (status == CF_SUCCESS);

        if ((expected_valid && !decrypt_success) ||
            (!expected_valid && decrypt_success)) {
            printf("ChaCha20-Poly1305 TcId %d FAILED, error code %u\n",
                   chacha20_poly1305_test_vectors[i].tc_id, status);
            failure = 1;
        }

        if (expected_valid && decrypt_success &&
            memcmp(dec, chacha20_poly1305_test_vectors[i].msg, chacha20_poly1305_test_vectors[i].msg_len) != 0) {
            printf("ChaCha20-Poly1305 TcId %d FAILED, Error code %u (decrypted plaintext mismatch)\n",
                   chacha20_poly1305_test_vectors[i].tc_id, status);
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

            if (chacha20_poly1305_test_vectors[i].comment &&
                chacha20_poly1305_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", chacha20_poly1305_test_vectors[i].comment);
            }

            if (chacha20_poly1305_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < chacha20_poly1305_test_vectors[i].flags_len; f++) {
                    printf("%s", chacha20_poly1305_test_vectors[i].flags[f]);
                    if (f + 1 < chacha20_poly1305_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
        } else {
            total_success++;
        }
    }

    printf("ChaCha20-Poly1305 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}


void test_xchacha20_poly1305_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(xchacha20_poly1305_test_vectors) / sizeof(xchacha20_poly1305_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_AEAD *aead = CF_AEAD_GetByFlag(CF_XCHACHA20_POLY1305);
        if (!aead) {
            printf("Unknown Cipher flag %u\n", CF_XCHACHA20_POLY1305);
            return;
        }

        uint8_t ct[520]  = {0};
        uint8_t dec[520] = {0};
        uint8_t tag[16]  = {0};

        int expected_valid = (strcmp(xchacha20_poly1305_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        /* ================= Encrypt ================= */

        CF_STATUS status = CF_AEAD_Encrypt(
            aead,
            xchacha20_poly1305_test_vectors[i].key, xchacha20_poly1305_test_vectors[i].key_len,
            xchacha20_poly1305_test_vectors[i].iv_len != 0 ? xchacha20_poly1305_test_vectors[i].iv : NULL, xchacha20_poly1305_test_vectors[i].iv_len,
            xchacha20_poly1305_test_vectors[i].aad_len != 0 ? xchacha20_poly1305_test_vectors[i].aad : NULL, xchacha20_poly1305_test_vectors[i].aad_len,
            xchacha20_poly1305_test_vectors[i].msg_len != 0 ? xchacha20_poly1305_test_vectors[i].msg : NULL, xchacha20_poly1305_test_vectors[i].msg_len,
            ct, tag, sizeof(tag)
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("XChaCha20-Poly1305 TcId %d FAILED (encrypt rejected valid vector)\n",
                   xchacha20_poly1305_test_vectors[i].tc_id);
            failure = 1;
            goto print_extra;
        }

        int ct_match =
            (xchacha20_poly1305_test_vectors[i].ct_len == xchacha20_poly1305_test_vectors[i].msg_len) &&
            (memcmp(ct, xchacha20_poly1305_test_vectors[i].ct, xchacha20_poly1305_test_vectors[i].ct_len) == 0);

        int tag_match =
            (memcmp(tag, xchacha20_poly1305_test_vectors[i].tag, xchacha20_poly1305_test_vectors[i].tag_len) == 0);

        if (expected_valid && (!ct_match || !tag_match)) {
            printf("XChaCha20-Poly1305 TcId %d FAILED, Error code %u (expected valid)\n",
                   xchacha20_poly1305_test_vectors[i].tc_id, status);

            if (!ct_match)
                printf("  Ciphertext mismatch\n");

            if (!tag_match)
                printf("  Tag mismatch\n");

            printf("CT : ");
            DEMO_print_hex(ct, xchacha20_poly1305_test_vectors[i].ct_len);

            printf("Expected CT : ");
            DEMO_print_hex(xchacha20_poly1305_test_vectors[i].ct, xchacha20_poly1305_test_vectors[i].ct_len);

            printf("TAG : ");
            DEMO_print_hex(tag, xchacha20_poly1305_test_vectors[i].tag_len);
            printf("Expected TAG : ");
            DEMO_print_hex(xchacha20_poly1305_test_vectors[i].tag, xchacha20_poly1305_test_vectors[i].tag_len);

            failure = 1;
        }

        /* ================= Decrypt ================= */

        status = CF_AEAD_Decrypt(
            aead,
            xchacha20_poly1305_test_vectors[i].key, xchacha20_poly1305_test_vectors[i].key_len,
            xchacha20_poly1305_test_vectors[i].iv_len != 0 ? xchacha20_poly1305_test_vectors[i].iv : NULL, xchacha20_poly1305_test_vectors[i].iv_len,
            xchacha20_poly1305_test_vectors[i].aad_len != 0 ? xchacha20_poly1305_test_vectors[i].aad : NULL, xchacha20_poly1305_test_vectors[i].aad_len,
            xchacha20_poly1305_test_vectors[i].ct_len != 0 ? ct : NULL, xchacha20_poly1305_test_vectors[i].ct_len,
            dec,
            (uint8_t *)xchacha20_poly1305_test_vectors[i].tag, xchacha20_poly1305_test_vectors[i].tag_len
        );

        int decrypt_success = (status == CF_SUCCESS);

        if ((expected_valid && !decrypt_success) ||
            (!expected_valid && decrypt_success)) {
            printf("XChaCha20-Poly1305 TcId %d FAILED, error code %u\n",
                   xchacha20_poly1305_test_vectors[i].tc_id, status);
            failure = 1;
        }

        if (expected_valid && decrypt_success &&
            memcmp(dec, xchacha20_poly1305_test_vectors[i].msg, xchacha20_poly1305_test_vectors[i].msg_len) != 0) {
            printf("XChaCha20-Poly1305 TcId %d FAILED, Error code %u (decrypted plaintext mismatch)\n",
                   xchacha20_poly1305_test_vectors[i].tc_id, status);
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

            if (xchacha20_poly1305_test_vectors[i].comment &&
                xchacha20_poly1305_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", xchacha20_poly1305_test_vectors[i].comment);
            }

            if (xchacha20_poly1305_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < xchacha20_poly1305_test_vectors[i].flags_len; f++) {
                    printf("%s", xchacha20_poly1305_test_vectors[i].flags[f]);
                    if (f + 1 < xchacha20_poly1305_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
        } else {
            total_success++;
        }
    }

    printf("XChaCha20-Poly1305 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

#endif // ENABLE_TESTS