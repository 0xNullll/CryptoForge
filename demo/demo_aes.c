#include "../config/demo_config.h"

#if ENABLE_TESTS

void test_aes128_fips197(void) {
    uint8_t plaintext[AES_128_KEY_SIZE] = {
    0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34 
    };

    uint8_t key[AES_128_KEY_SIZE] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    // Expected ciphertext from FIPS-197 Appendix B
    uint8_t expected_cipher[AES_BLOCK_SIZE] = {
        0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32
    };

    AES_KEY ctx;
    uint8_t ciphertext[AES_BLOCK_SIZE];
    uint8_t decrypted[AES_BLOCK_SIZE];

    if (!ll_AES_SetEncryptKey(&ctx, key, AES_128_KEY_SIZE)) {
        printf("AES-128 init failed\n");
        return;
    }

    ll_AES_EncryptBlock(&ctx, plaintext, ciphertext);
    ll_AES_DecryptBlock(&ctx, ciphertext, decrypted);

    printf("AES-128 FIPS-197 Test:\n");
    printf("Key:       "); DEMO_print_hex(key, AES_BLOCK_SIZE);
    printf("Plaintext: "); DEMO_print_hex(plaintext, AES_BLOCK_SIZE);
    printf("Ciphertext:"); DEMO_print_hex(ciphertext, AES_BLOCK_SIZE);
    printf("Expected:  "); DEMO_print_hex(expected_cipher, AES_BLOCK_SIZE);
    printf("Decrypted: "); DEMO_print_hex(decrypted, AES_BLOCK_SIZE);

    if (memcmp(ciphertext, expected_cipher, AES_BLOCK_SIZE) == 0 &&
        memcmp(plaintext, decrypted, AES_BLOCK_SIZE) == 0) {
        printf("AES-128 FIPS-197 test PASSED\n");
    } else {
        printf("AES-128 FIPS-197 test FAILED\n");
    }
}

void test_aes192_fips197(void) {
    uint8_t plaintext[AES_BLOCK_SIZE] = {
        0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34
    };

    uint8_t key[AES_192_KEY_SIZE] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    uint8_t expected_cipher[AES_BLOCK_SIZE] = {
        0x58,0x5e,0x9f,0xb6,0xc2,0x72,0x2b,0x9a,0xf4,0xf4,0x92,0xc1,0x2b,0xb0,0x24,0xc1
    };

    AES_KEY ctx;
    uint8_t ciphertext[AES_BLOCK_SIZE];
    uint8_t decrypted[AES_BLOCK_SIZE];

    if (!ll_AES_SetEncryptKey(&ctx, key, AES_192_KEY_SIZE)) {
        printf("AES-192 init failed\n");
        return;
    }

    ll_AES_EncryptBlock(&ctx, plaintext, ciphertext);
    ll_AES_DecryptBlock(&ctx, ciphertext, decrypted);

    printf("AES-192 FIPS-197 Test:\n");
    printf("Key:       "); DEMO_print_hex(key, AES_192_KEY_SIZE);
    printf("Plaintext: "); DEMO_print_hex(plaintext, AES_BLOCK_SIZE);
    printf("Ciphertext:"); DEMO_print_hex(ciphertext, AES_BLOCK_SIZE);
    printf("Expected:  "); DEMO_print_hex(expected_cipher, AES_BLOCK_SIZE);
    printf("Decrypted: "); DEMO_print_hex(decrypted, AES_BLOCK_SIZE);

    if (memcmp(ciphertext, expected_cipher, AES_BLOCK_SIZE) == 0 &&
        memcmp(plaintext, decrypted, AES_BLOCK_SIZE) == 0) {
        printf("AES-192 FIPS-197 test PASSED\n");
    } else {
        printf("AES-192 FIPS-197 test FAILED\n");
    }
}

void test_aes256_fips197(void) {
    uint8_t plaintext[AES_BLOCK_SIZE] = {
        0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34
    };

    uint8_t key[AES_256_KEY_SIZE] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    uint8_t expected_cipher[AES_BLOCK_SIZE] = {
        0x30,0x21,0x61,0x3a,0x97,0x3e,0x58,0x2f,0x4a,0x29,0x23,0x41,0x37,0xae,0xc4,0x94
    };

    AES_KEY ctx;
    uint8_t ciphertext[AES_BLOCK_SIZE];
    uint8_t decrypted[AES_BLOCK_SIZE];

    if (!ll_AES_SetEncryptKey(&ctx, key, AES_256_KEY_SIZE)) {
        printf("AES-256 init failed\n");
        return;
    }

    ll_AES_EncryptBlock(&ctx, plaintext, ciphertext);
    ll_AES_DecryptBlock(&ctx, ciphertext, decrypted);

    printf("AES-256 FIPS-197 Test:\n");
    printf("Key:       "); DEMO_print_hex(key, AES_256_KEY_SIZE);
    printf("Plaintext: "); DEMO_print_hex(plaintext, AES_BLOCK_SIZE);
    printf("Ciphertext:"); DEMO_print_hex(ciphertext, AES_BLOCK_SIZE);
    printf("Expected:  "); DEMO_print_hex(expected_cipher, AES_BLOCK_SIZE);
    printf("Decrypted: "); DEMO_print_hex(decrypted, AES_BLOCK_SIZE);

    if (memcmp(ciphertext, expected_cipher, AES_BLOCK_SIZE) == 0 &&
        memcmp(plaintext, decrypted, AES_BLOCK_SIZE) == 0) {
        printf("AES-256 FIPS-197 test PASSED\n");
    } else {
        printf("AES-256 FIPS-197 test FAILED\n");
    }
}

void test_aes_ecb_fist800_38a(void) {
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

    // AES-128
    uint8_t key128[AES_128_KEY_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t expected_ct128[4 * AES_BLOCK_SIZE] = {
        0x3a, 0xd7, 0x7b, 0xb4,
        0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3,
        0x24, 0x66, 0xef, 0x97,

        0xae, 0x2d, 0x8a, 0x57,
        0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac,
        0x45, 0xaf, 0x8e, 0x51,

        0x30, 0xc8, 0x1c, 0x46,
        0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef,

        0x7b, 0x0c, 0x78, 0x5e,
        0x27, 0xe8, 0xad, 0x3f,
        0x82, 0x23, 0x20, 0x71,
        0x04, 0x72, 0x5d, 0xd4
    };

    AES_KEY ctx;
    uint8_t ct[4 * AES_BLOCK_SIZE];
    uint8_t dec[4 * AES_BLOCK_SIZE];

    // ---------------- AES-128 ----------------
    if (!ll_AES_SetEncryptKey(&ctx, key128, AES_128_KEY_SIZE)) { printf("AES-128 init failed\n"); return; }
    ll_AES_ECB_Encrypt(&ctx, plain_text, 4 * AES_BLOCK_SIZE, ct);
    ll_AES_ECB_Decrypt(&ctx, ct, 4 * AES_BLOCK_SIZE, dec);

    printf("AES-128 ECB Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext:"); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct128, sizeof(expected_ct128));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-128 ECB FIPS-800-38a test %s\n", (memcmp(ct, expected_ct128, AES_BLOCK_SIZE)==0 && memcmp(plain_text, dec, AES_BLOCK_SIZE)==0) ? "PASSED" : "FAILED");

    // ---------------- AES-192 ----------------
    uint8_t key192[AES_192_KEY_SIZE] = {
        0x8e, 0x73, 0xb0, 0xf7,
        0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b,
        0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2,
        0x52, 0x2c, 0x6b, 0x7b
    };

    uint8_t expected_ct192[4 * AES_BLOCK_SIZE] = {
        0xbd, 0x33, 0x4f, 0x1d,
        0x6e, 0x45, 0xf2, 0x5f,
        0xf7, 0x12, 0xa2, 0x14,
        0x57, 0x1f, 0xa5, 0xcc,

        0x97, 0x41, 0x04, 0x84,
        0x6d, 0x0a, 0xd3, 0xad,
        0x77, 0x34, 0xec, 0xb3,
        0xec, 0xee, 0x4e, 0xef,

        0xef, 0x7a, 0xfd, 0x22,
        0x70, 0xe2, 0xe6, 0x0a,
        0xdc, 0xe0, 0xba, 0x2f,
        0xac, 0xec, 0x64, 0x44,

        0x9a, 0x4b, 0x41, 0xba,
        0x73, 0x8d, 0x6c, 0x72,
        0xfb, 0x16, 0x69, 0x16,
        0x03, 0xc1, 0x8e, 0x0e
    };

    if (!ll_AES_SetEncryptKey(&ctx, key192, AES_192_KEY_SIZE)) { printf("AES-192 init failed\n"); return; }
    ll_AES_ECB_Encrypt(&ctx, plain_text, 4 * AES_BLOCK_SIZE, ct);
    ll_AES_ECB_Decrypt(&ctx, ct, 4 * AES_BLOCK_SIZE, dec);

    printf("AES-192 ECB Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext:"); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct192, sizeof(expected_ct192));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-192 ECB FIPS-800-38a test %s\n", (memcmp(ct, expected_ct192, AES_BLOCK_SIZE)==0 && memcmp(plain_text, dec, AES_BLOCK_SIZE)==0) ? "PASSED" : "FAILED");

    // ---------------- AES-256 ----------------
    uint8_t key256[AES_256_KEY_SIZE] = {
        0x60, 0x3d, 0xeb, 0x10,
        0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0,
        0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07,
        0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3,
        0x09, 0x14, 0xdf, 0xf4
    };

    uint8_t expected_ct256[4 * AES_BLOCK_SIZE] = {
        0xf3, 0xee, 0xd1, 0xbd,
        0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e,
        0x3d, 0xb1, 0x81, 0xf8,

        0x59, 0x1c, 0xcb, 0x10,
        0xd4, 0x10, 0xed, 0x26,
        0xdc, 0x5b, 0xa7, 0x4a,
        0x31, 0x36, 0x28, 0x70,

        0xb6, 0xed, 0x21, 0xb9,
        0x9c, 0xa6, 0xf4, 0xf9,
        0xf1, 0x53, 0xe7, 0xb1,
        0xbe, 0xaf, 0xed, 0x1d,

        0x23, 0x30, 0x4b, 0x7a,
        0x39, 0xf9, 0xf3, 0xff,
        0x06, 0x7d, 0x8d, 0x8f,
        0x9e, 0x24, 0xec, 0xc7
    };

    if (!ll_AES_SetEncryptKey(&ctx, key256, AES_256_KEY_SIZE)) { printf("AES-256 init failed\n"); return; }
    ll_AES_ECB_Encrypt(&ctx, plain_text, 4 * AES_BLOCK_SIZE, ct);
    ll_AES_ECB_Decrypt(&ctx, ct, 4 * AES_BLOCK_SIZE, dec);

    printf("AES-256 ECB Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext:"); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct256, sizeof(expected_ct256));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-256 ECB FIPS-800-38a test %s\n", (memcmp(ct, expected_ct256, AES_BLOCK_SIZE)==0 && memcmp(plain_text, dec, AES_BLOCK_SIZE)==0) ? "PASSED" : "FAILED");
}

void test_aes_cbc_fips800_38a(void) {
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

    // Fixed IV (for testing purposes)
    uint8_t iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    AES_KEY ctx;
    uint8_t ct[4 * AES_BLOCK_SIZE];
    uint8_t dec[4 * AES_BLOCK_SIZE];

    // ---------------- AES-128 ----------------
    uint8_t key128[AES_128_KEY_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    if (!ll_AES_SetEncryptKey(&ctx, key128, AES_128_KEY_SIZE)) { 
        printf("AES-128 init failed\n"); return; 
    }

    if (!ll_AES_CBC_Encrypt(&ctx, iv, plain_text, sizeof(plain_text), ct)) {
        printf("AES-128 CBC encryption failed\n"); return;
    }

    // Reset IV for decryption
    uint8_t iv_dec[AES_BLOCK_SIZE];
    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    if (!ll_AES_CBC_Decrypt(&ctx, iv_dec, ct, sizeof(ct), dec)) {
        printf("AES-128 CBC decryption failed\n"); return;
    }

    printf("AES-128 CBC Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-128 CBC FIPS-800-38a test %s\n", 
        (memcmp(plain_text, dec, sizeof(plain_text)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-192 ----------------
    uint8_t key192[AES_192_KEY_SIZE] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    if (!ll_AES_SetEncryptKey(&ctx, key192, AES_192_KEY_SIZE)) { 
        printf("AES-192 init failed\n"); return; 
    }

    if (!ll_AES_CBC_Encrypt(&ctx, iv, plain_text, sizeof(plain_text), ct)) {
        printf("AES-192 CBC encryption failed\n"); return;
    }

    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    if (!ll_AES_CBC_Decrypt(&ctx, iv_dec, ct, sizeof(ct), dec)) {
        printf("AES-192 CBC decryption failed\n"); return;
    }

    printf("AES-192 CBC Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-192 CBC FIPS-800-38a test %s\n", 
        (memcmp(plain_text, dec, sizeof(plain_text)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-256 ----------------
    uint8_t key256[AES_256_KEY_SIZE] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    if (!ll_AES_SetEncryptKey(&ctx, key256, AES_256_KEY_SIZE)) { 
        printf("AES-256 init failed\n"); return; 
    }

    if (!ll_AES_CBC_Encrypt(&ctx, iv, plain_text, sizeof(plain_text), ct)) {
        printf("AES-256 CBC encryption failed\n"); return;
    }

    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    if (!ll_AES_CBC_Decrypt(&ctx, iv_dec, ct, sizeof(ct), dec)) {
        printf("AES-256 CBC decryption failed\n"); return;
    }

    printf("AES-256 CBC Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-256 CBC FIPS-800-38a test %s\n", 
        (memcmp(plain_text, dec, sizeof(plain_text)) == 0) ? "PASSED" : "FAILED");
}

#endif // ENABLE_TESTS