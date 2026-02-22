#include "../src/include/config/demo_config.h"

#if ENABLE_TESTS

#include "../vectors/NIST/KAT/tv_aes_ecb.h"
#include "../vectors/NIST/KAT/tv_aes_cbc.h"
#include "../vectors/NIST/KAT/tv_aes_cfb8.h"
#include "../vectors/NIST/KAT/tv_aes_cfb128.h"
#include "../vectors/NIST/KAT/tv_aes_ofb.h"

void test_chacha20_rfc7539(void) {
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    uint8_t iv[12] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };

    uint8_t plaintext[114] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };

    uint8_t expected_ciphertext[114] = {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d
    };


    uint32_t count = 1;

    uint8_t ciphertext[114] = {0};
    uint8_t decrypted[114] = {0};

    ll_CHACHA20_CTX ctx = {0};

    if (!ll_CHACHA20_Init(&ctx, key, sizeof(key), iv, count)) {
        printf("CHACHA20 RFC-7539 ll_CHACHA20_Init failed\n"); return;
    }

    if (!ll_CHACHA20_Cipher(&ctx, plaintext, sizeof(plaintext), ciphertext)) {
        printf("CHACHA20 RFC-7539 ll_CHACHA20_Cipher failed\n"); return;
    }

    SECURE_ZERO(&ctx, sizeof(ctx));

    if (!ll_CHACHA20_Init(&ctx, key, sizeof(key), iv, count)) {
        printf("CHACHA20 RFC-7539 Encrypt ll_CHACHA20_Init failed\n"); return;
    }

    if (!ll_CHACHA20_Cipher(&ctx, ciphertext, sizeof(ciphertext), decrypted)) {
        printf("CHACHA20 RFC-7539 Encrypt ll_CHACHA20_Cipher failed\n"); return;
    }

    printf("CHACHA20 RFC-7539 Example Test:\n");
    printf("Key:       "); DEMO_print_hex(key, sizeof(key));
    printf("Plaintext: "); DEMO_print_hex(plaintext, sizeof(plaintext));
    printf("Ciphertext:"); DEMO_print_hex(ciphertext, sizeof(expected_ciphertext));
    printf("Expected:  "); DEMO_print_hex(expected_ciphertext, sizeof(expected_ciphertext));
    printf("Decrypted: "); DEMO_print_hex(decrypted, sizeof(plaintext));

    if (memcmp(ciphertext, expected_ciphertext, sizeof(expected_ciphertext)) == 0 &&
        memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
        printf("CHACHA20 RFC-7539 Example test PASSED\n");
    } else {
        printf("CHACHA20 RFC-7539 Example test FAILED\n");
    }  

}

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

    ll_AES_KEY ctx;
    SECURE_ZERO(&ctx, sizeof(ctx));

    uint8_t ciphertext[AES_BLOCK_SIZE];
    uint8_t decrypted[AES_BLOCK_SIZE];

    if (!ll_AES_SetEncryptKey(&ctx, key, AES_128_KEY_SIZE)) {
        printf("AES-128 init failed\n");
        return;
    }

    ll_AES_EncryptBlock(&ctx, plaintext, ciphertext);
    ll_AES_DecryptBlock(&ctx, ciphertext, decrypted);
    ll_AES_ClearKey(&ctx);

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

    ll_AES_KEY ctx;
    SECURE_ZERO(&ctx, sizeof(ctx));

    uint8_t ciphertext[AES_BLOCK_SIZE];
    uint8_t decrypted[AES_BLOCK_SIZE];

    if (!ll_AES_SetEncryptKey(&ctx, key, AES_192_KEY_SIZE)) {
        printf("AES-192 init failed\n");
        return;
    }

    ll_AES_EncryptBlock(&ctx, plaintext, ciphertext);
    ll_AES_DecryptBlock(&ctx, ciphertext, decrypted);
    ll_AES_ClearKey(&ctx);

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

    ll_AES_KEY ctx;
    SECURE_ZERO(&ctx, sizeof(ctx));

    uint8_t ciphertext[AES_BLOCK_SIZE];
    uint8_t decrypted[AES_BLOCK_SIZE];

    if (!ll_AES_SetEncryptKey(&ctx, key, AES_256_KEY_SIZE)) {
        printf("AES-256 init failed\n");
        return;
    }

    ll_AES_EncryptBlock(&ctx, plaintext, ciphertext);
    ll_AES_DecryptBlock(&ctx, ciphertext, decrypted);
    ll_AES_ClearKey(&ctx);

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

        0xf5, 0xd3, 0xd5, 0x85,
        0x03, 0xb9, 0x69, 0x9d,
        0xe7, 0x85, 0x89, 0x5a,
        0x96, 0xfd, 0xba, 0xaf,

        0x43, 0xb1, 0xcd, 0x7f,
        0x59, 0x8e, 0xce, 0x23,
        0x88, 0x1b, 0x00, 0xe3,
        0xed, 0x03, 0x06, 0x88,

        0x7b, 0x0c, 0x78, 0x5e,
        0x27, 0xe8, 0xad, 0x3f,
        0x82, 0x23, 0x20, 0x71,
        0x04, 0x72, 0x5d, 0xd4
    };

    ll_AES_KEY ctx;
    SECURE_ZERO(&ctx, sizeof(ctx));

    uint8_t ct[4 * AES_BLOCK_SIZE];
    uint8_t dec[4 * AES_BLOCK_SIZE];

    // ---------------- AES-128 ----------------
    if (!ll_AES_SetEncryptKey(&ctx, key128, AES_128_KEY_SIZE)) { printf("AES-128 init failed\n"); return; }
    ll_AES_ECB_Encrypt(&ctx, plain_text, 4 * AES_BLOCK_SIZE, ct);
    ll_AES_ECB_Decrypt(&ctx, ct, 4 * AES_BLOCK_SIZE, dec);
    ll_AES_ClearKey(&ctx);

    printf("AES-128 ECB Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext:"); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct128, sizeof(expected_ct128));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-128 ECB FIPS-800-38a test %s\n", (memcmp(ct, expected_ct128, AES_BLOCK_SIZE * 4)==0 && memcmp(plain_text, dec, AES_BLOCK_SIZE * 4)==0) ? "PASSED" : "FAILED");

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
        0xac, 0xe6, 0x44, 0x4e,
 
        0x9a, 0x4b, 0x41, 0xba,
        0x73, 0x8d, 0x6c, 0x72,
        0xfb, 0x16, 0x69, 0x16,
        0x03, 0xc1, 0x8e, 0x0e
    };

    if (!ll_AES_SetEncryptKey(&ctx, key192, AES_192_KEY_SIZE)) { printf("AES-192 init failed\n"); return; }
    ll_AES_ECB_Encrypt(&ctx, plain_text, 4 * AES_BLOCK_SIZE, ct);
    ll_AES_ECB_Decrypt(&ctx, ct, 4 * AES_BLOCK_SIZE, dec);
    ll_AES_ClearKey(&ctx);

    printf("AES-192 ECB Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext:"); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct192, sizeof(expected_ct192));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-192 ECB FIPS-800-38a test %s\n", (memcmp(ct, expected_ct192, AES_BLOCK_SIZE * 4)==0 && memcmp(plain_text, dec, AES_BLOCK_SIZE * 4)==0) ? "PASSED" : "FAILED");

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
    ll_AES_ClearKey(&ctx);

    printf("AES-256 ECB Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext:"); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct256, sizeof(expected_ct256));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-256 ECB FIPS-800-38a test %s\n", (memcmp(ct, expected_ct256, AES_BLOCK_SIZE * 4)==0 && memcmp(plain_text, dec, AES_BLOCK_SIZE * 4)==0) ? "PASSED" : "FAILED");
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

    ll_AES_KEY ctx;
    SECURE_ZERO(&ctx, sizeof(ctx));

    uint8_t ct[4 * AES_BLOCK_SIZE];
    uint8_t dec[4 * AES_BLOCK_SIZE];

    // ---------------- AES-128 ----------------
    uint8_t key128[AES_128_KEY_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t expected_ct128[4 * AES_BLOCK_SIZE] = {
        0x76, 0x49, 0xab, 0xac,
        0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b,
        0x12, 0xe9, 0x19, 0x7d,

        0x50, 0x86, 0xcb, 0x9b,
        0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a,
        0x91, 0x76, 0x78, 0xb2,

        0x73, 0xbe, 0xd6, 0xb8,
        0xe3, 0xc1, 0x74, 0x3b,
        0x71, 0x16, 0xe6, 0x9e,
        0x22, 0x22, 0x95, 0x16,

        0x3f, 0xf1, 0xca, 0xa1,
        0x68, 0x1f, 0xac, 0x09,
        0x12, 0x0e, 0xca, 0x30,
        0x75, 0x86, 0xe1, 0xa7
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
    ll_AES_ClearKey(&ctx);

    printf("AES-128 CBC Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct128, sizeof(expected_ct128));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-128 CBC FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct128, ct, sizeof(expected_ct128)) == 0) && memcmp(plain_text, dec, sizeof(plain_text)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-192 ----------------
    uint8_t key192[AES_192_KEY_SIZE] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    uint8_t expected_ct192[4 * AES_BLOCK_SIZE] = {
        0x4f, 0x02, 0x1d, 0xb2,
        0x43, 0xbc, 0x63, 0x3d,
        0x71, 0x78, 0x18, 0x3a,
        0x9f, 0xa0, 0x71, 0xe8,

        0xb4, 0xd9, 0xad, 0xa9,
        0xad, 0x7d, 0xed, 0xf4,
        0xe5, 0xe7, 0x38, 0x76,
        0x3f, 0x69, 0x14, 0x5a,

        0x57, 0x1b, 0x24, 0x20,
        0x12, 0xfb, 0x7a, 0xe0,
        0x7f, 0xa9, 0xba, 0xac,
        0x3d, 0xf1, 0x02, 0xe0,

        0x08, 0xb0, 0xe2, 0x79,
        0x88, 0x59, 0x88, 0x81,
        0xd9, 0x20, 0xa9, 0xe6,
        0x4f, 0x56, 0x15, 0xcd
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
    ll_AES_ClearKey(&ctx);

    printf("AES-192 CBC Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct192, sizeof(expected_ct192));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-192 CBC FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct192, ct, sizeof(expected_ct192)) == 0) && memcmp(plain_text, dec, sizeof(plain_text)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-256 ----------------
    uint8_t key256[AES_256_KEY_SIZE] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    uint8_t expected_ct256[4 * AES_BLOCK_SIZE] = {
        0xf5, 0x8c, 0x4c, 0x04,
        0xd6, 0xe5, 0xf1, 0xba,
        0x77, 0x9e, 0xab, 0xfb,
        0x5f, 0x7b, 0xfb, 0xd6,

        0x9c, 0xfc, 0x4e, 0x96,
        0x7e, 0xdb, 0x80, 0x8d,
        0x67, 0x9f, 0x77, 0x7b,
        0xc6, 0x70, 0x2c, 0x7d,

        0x39, 0xf2, 0x33, 0x69,
        0xa9, 0xd9, 0xba, 0xcf,
        0xa5, 0x30, 0xe2, 0x63,
        0x04, 0x23, 0x14, 0x61,

        0xb2, 0xeb, 0x05, 0xe2,
        0xc3, 0x9b, 0xe9, 0xfc,
        0xda, 0x6c, 0x19, 0x07,
        0x8c, 0x6a, 0x9d, 0x1b
    };

    if (!ll_AES_SetEncryptKey(&ctx, key256, AES_256_KEY_SIZE)) { 
        printf("AES-256 init failed\n"); return; 
    }

    if (!ll_AES_CBC_Encrypt(&ctx, iv, plain_text, sizeof(plain_text), ct)) {
        printf("AES-256 CBC-8 encryption failed\n"); return;
    }

    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    if (!ll_AES_CBC_Decrypt(&ctx, iv_dec, ct, sizeof(ct), dec)) {
        printf("AES-256 CBC-8 decryption failed\n"); return;
    }
    ll_AES_ClearKey(&ctx);

    printf("AES-256 CBC Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct256, sizeof(expected_ct256));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-256 CBC-8 FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct256, ct, sizeof(expected_ct256)) == 0 && memcmp(plain_text, dec, sizeof(plain_text)) == 0)) ? "PASSED" : "FAILED");
}

void test_aes_cfb8_fips800_38a(void) {
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

    ll_AES_KEY ctx;
    SECURE_ZERO(&ctx, sizeof(ctx));

    uint8_t ct[4 * AES_BLOCK_SIZE];
    uint8_t dec[4 * AES_BLOCK_SIZE];

    // ---------------- AES-128 ----------------
    uint8_t key128[AES_128_KEY_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t expected_ct128[4 * AES_BLOCK_SIZE] = {
        0x3b, 0x79, 0x42, 0x4c,
        0x9c, 0x0d, 0xd4, 0x36,
        0xba, 0xce, 0x9e, 0x0e,
        0xd4, 0x58, 0x6a, 0x4f,

        0x32, 0xb9, 0xde, 0xd5,
        0x0a, 0xe3, 0xba, 0x69,
        0xd4, 0x72, 0xe8, 0x82,
        0x67, 0xfb, 0x50, 0x52,

        0x70, 0xcb, 0xad, 0x1e,
        0x25, 0x76, 0x91, 0xf7,
        0xc4, 0x7c, 0x50, 0x38,
        0x29, 0x7e, 0xdd, 0xa3,

        0x2f, 0xf2, 0x6d, 0x0e,
        0xd1, 0x91, 0x74, 0x09,
        0x61, 0x61, 0xec, 0xc1,
        0x40, 0x86, 0xdd, 0x62
    };

    if (!ll_AES_SetEncryptKey(&ctx, key128, AES_128_KEY_SIZE)) { 
        printf("AES-128 init failed\n"); return; 
    }

    if (!ll_AES_CFB8_Encrypt(&ctx, iv, plain_text, sizeof(plain_text), ct)) {
        printf("AES-128 CFB-8 encryption failed\n"); return;
    }

    // Reset IV for decryption
    uint8_t iv_dec[AES_BLOCK_SIZE];
    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    if (!ll_AES_CFB8_Decrypt(&ctx, iv_dec, ct, sizeof(ct), dec)) {
        printf("AES-128 CFB-8 decryption failed\n"); return;
    }
    ll_AES_ClearKey(&ctx);

    printf("AES-128 CFB-8 Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct128, sizeof(expected_ct128));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-128 CFB-8 FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct128, ct, sizeof(expected_ct128)) == 0) && memcmp(plain_text, dec, sizeof(plain_text)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-192 ----------------
    uint8_t key192[AES_192_KEY_SIZE] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    uint8_t expected_ct192[4 * AES_BLOCK_SIZE] = {
        0xcd, 0xa2, 0x52, 0x1e,
        0xf0, 0xa9, 0x05, 0xca,
        0x44, 0xcd, 0x05, 0x7c,
        0xbf, 0x0d, 0x47, 0xa0,

        0x67, 0x8a, 0x7b, 0xcf,
        0xb6, 0xae, 0xaa, 0x30,
        0x47, 0xb3, 0x89, 0x36,
        0x02, 0x1f, 0x48, 0xbb,

        0xb6, 0x3c, 0xef, 0xda,
        0xc0, 0x2b, 0x2e, 0x84,
        0x09, 0x04, 0xef, 0xce,
        0x6f, 0x43, 0x26, 0xbe,

        0x22, 0x86, 0x83, 0x73,
        0x90, 0x63, 0xdc, 0x30,
        0xe9, 0x37, 0xff, 0xed,
        0xd6, 0x3e, 0x3c, 0x94
    };

    if (!ll_AES_SetEncryptKey(&ctx, key192, AES_192_KEY_SIZE)) { 
        printf("AES-192 init failed\n"); return; 
    }

    if (!ll_AES_CFB8_Encrypt(&ctx, iv, plain_text, sizeof(plain_text), ct)) {
        printf("AES-192 CFB-8 encryption failed\n"); return;
    }

    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    if (!ll_AES_CFB8_Decrypt(&ctx, iv_dec, ct, sizeof(ct), dec)) {
        printf("AES-192 CFB-8 decryption failed\n"); return;
    }
    ll_AES_ClearKey(&ctx);

    printf("AES-192 CFB-8 Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct192, sizeof(expected_ct192));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-192 CFB-8 FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct192, ct, sizeof(expected_ct192)) == 0) && memcmp(plain_text, dec, sizeof(plain_text)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-256 ----------------
    uint8_t key256[AES_256_KEY_SIZE] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    uint8_t expected_ct256[4 * AES_BLOCK_SIZE] = {
        0xdc,0x1f,0x1a,0x85,
        0x20,0xa6,0x4d,0xb5,
        0x5f,0xcc,0x8a,0xc5,
        0x54,0x84,0x4e,0x88,

        0x97,0x00,0xad,0xc6,
        0xe1,0x0c,0x63,0xcf,
        0x2d,0x8c,0xd2,0xd8,
        0xce,0x66,0x8f,0x3e,

        0xb9,0x19,0x17,0x19,
        0xc4,0x74,0x44,0xfb,
        0x43,0xbf,0xf9,0xb9,
        0x88,0x3c,0x2c,0xd0,

        0x51,0x12,0x04,0x02,
        0x00,0x9f,0x97,0x49,
        0x98,0xc8,0x9d,0x19,
        0x57,0x22,0xa7,0x5b
    };

    if (!ll_AES_SetEncryptKey(&ctx, key256, AES_256_KEY_SIZE)) { 
        printf("AES-256 init failed\n"); return; 
    }

    if (!ll_AES_CFB8_Encrypt(&ctx, iv, plain_text, sizeof(plain_text), ct)) {
        printf("AES-256 CFB-8 encryption failed\n"); return;
    }

    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    if (!ll_AES_CFB8_Decrypt(&ctx, iv_dec, ct, sizeof(ct), dec)) {
        printf("AES-256 CFB-8 decryption failed\n"); return;
    }
    ll_AES_ClearKey(&ctx);

    printf("AES-256 CFB-8 Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct256, sizeof(expected_ct256));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-256 CFB-8 FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct256, ct, sizeof(expected_ct256)) == 0 && memcmp(plain_text, dec, sizeof(plain_text)) == 0)) ? "PASSED" : "FAILED");
}

void test_aes_cfb128_fips800_38a(void) {
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

    ll_AES_KEY ctx;
    SECURE_ZERO(&ctx, sizeof(ctx));

    uint8_t ct[4 * AES_BLOCK_SIZE];
    uint8_t dec[4 * AES_BLOCK_SIZE];

    // ---------------- AES-128 ----------------
    uint8_t key128[AES_128_KEY_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t expected_ct128[4 * AES_BLOCK_SIZE] = {
        0x3b,0x3f,0xd9,0x2e,
        0xb7,0x2d,0xad,0x20,
        0x33,0x34,0x49,0xf8,
        0xe8,0x3c,0xfb,0x4a,
        
        0xc8,0xa6,0x45,0x37,
        0xa0,0xb3,0xa9,0x3f,
        0xcd,0xe3,0xcd,0xad,
        0x9f,0x1c,0xe5,0x8b,
        
        0x26,0x75,0x1f,0x67,
        0xa3,0xcb,0xb1,0x40,
        0xb1,0x80,0x8c,0xf1,
        0x87,0xa4,0xf4,0xdf,
        
        0xc0,0x4b,0x05,0x35,
        0x7c,0x5d,0x1c,0x0e,
        0xea,0xc4,0xc6,0x6f,
        0x9f,0xf7,0xf2,0xe6
    };

    if (!ll_AES_SetEncryptKey(&ctx, key128, AES_128_KEY_SIZE)) { 
        printf("AES-128 init failed\n"); return; 
    }

    if (!ll_AES_CFB128_Encrypt(&ctx, iv, plain_text, sizeof(plain_text), ct)) {
        printf("AES-128 CFB-128 encryption failed\n"); return;
    }

    // Reset IV for decryption
    uint8_t iv_dec[AES_BLOCK_SIZE];
    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    if (!ll_AES_CFB128_Decrypt(&ctx, iv_dec, ct, sizeof(ct), dec)) {
        printf("AES-128 CFB-128 decryption failed\n"); return;
    }
    ll_AES_ClearKey(&ctx);

    printf("AES-128 CFB-128 Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct128, sizeof(expected_ct128));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-128 CFB-128 FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct128, ct, sizeof(expected_ct128)) == 0) && memcmp(plain_text, dec, sizeof(plain_text)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-192 ----------------
    uint8_t key192[AES_192_KEY_SIZE] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    uint8_t expected_ct192[4 * AES_BLOCK_SIZE] = {
        0xcd,0xc8,0x0d,0x6f,
        0xdd,0xf1,0x8c,0xab,
        0x34,0xc2,0x59,0x09,
        0xc9,0x9a,0x41,0x74,

        0x67,0xce,0x7f,0x7f,
        0x81,0x17,0x36,0x21,
        0x96,0x1a,0x2b,0x70,
        0x17,0x1d,0x3d,0x7a,
        
        0x2e,0x1e,0x8a,0x1d,
        0xd5,0x9b,0x88,0xb1,
        0xc8,0xe6,0x0f,0xed,
        0x1e,0xfa,0xc4,0xc9,

        0xc0,0x5f,0x9f,0x9c,
        0xa9,0x83,0x4f,0xa0,
        0x42,0xae,0x8f,0xba,
        0x58,0x4b,0x09,0xff
    };

    if (!ll_AES_SetEncryptKey(&ctx, key192, AES_192_KEY_SIZE)) { 
        printf("AES-192 init failed\n"); return; 
    }

    if (!ll_AES_CFB128_Encrypt(&ctx, iv, plain_text, sizeof(plain_text), ct)) {
        printf("AES-192 CFB-128 encryption failed\n"); return;
    }

    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    if (!ll_AES_CFB128_Decrypt(&ctx, iv_dec, ct, sizeof(ct), dec)) {
        printf("AES-192 CFB-128 decryption failed\n"); return;
    }
    ll_AES_ClearKey(&ctx);

    printf("AES-192 CFB-128 Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct192, sizeof(expected_ct192));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-192 CFB-128 FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct192, ct, sizeof(expected_ct192)) == 0) && memcmp(plain_text, dec, sizeof(plain_text)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-256 ----------------
    uint8_t key256[AES_256_KEY_SIZE] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    uint8_t expected_ct256[4 * AES_BLOCK_SIZE] = {
        0xdc,0x7e,0x84,0xbf,
        0xda,0x79,0x16,0x4b,
        0x7e,0xcd,0x84,0x86,
        0x98,0x5d,0x38,0x60,
        
        0x39,0xff,0xed,0x14,
        0x3b,0x28,0xb1,0xc8,
        0x32,0x11,0x3c,0x63,
        0x31,0xe5,0x40,0x7b,
        
        0xdf,0x10,0x13,0x24,
        0x15,0xe5,0x4b,0x92,
        0xa1,0x3e,0xd0,0xa8,
        0x26,0x7a,0xe2,0xf9,
        
        0x75,0xa3,0x85,0x74,
        0x1a,0xb9,0xce,0xf8,
        0x20,0x31,0x62,0x3d,
        0x55,0xb1,0xe4,0x71
    };

    if (!ll_AES_SetEncryptKey(&ctx, key256, AES_256_KEY_SIZE)) { 
        printf("AES-256 init failed\n"); return; 
    }

    if (!ll_AES_CFB128_Encrypt(&ctx, iv, plain_text, sizeof(plain_text), ct)) {
        printf("AES-256 CFB-128 encryption failed\n"); return;
    }

    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    if (!ll_AES_CFB128_Decrypt(&ctx, iv_dec, ct, sizeof(ct), dec)) {
        printf("AES-256 CFB-128 decryption failed\n"); return;
    }
    ll_AES_ClearKey(&ctx);

    printf("AES-256 CFB-128 Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct256, sizeof(expected_ct256));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-256 CFB-128 FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct256, ct, sizeof(expected_ct256)) == 0 && memcmp(plain_text, dec, sizeof(plain_text)) == 0)) ? "PASSED" : "FAILED");
}

void test_aes_ofb_fips800_38a(void) {
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

    ll_AES_KEY ctx;
    SECURE_ZERO(&ctx, sizeof(ctx));

    uint8_t ct[4 * AES_BLOCK_SIZE];
    uint8_t dec[4 * AES_BLOCK_SIZE];

    // ---------------- AES-128 ----------------
    uint8_t key128[AES_128_KEY_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t expected_ct128[4 * AES_BLOCK_SIZE] = {
        0x3b,0x3f,0xd9,0x2e,
        0xb7,0x2d,0xad,0x20,
        0x33,0x34,0x49,0xf8,
        0xe8,0x3c,0xfb,0x4a,

        0x77,0x89,0x50,0x8d,
        0x16,0x91,0x8f,0x03,
        0xf5,0x3c,0x52,0xda,
        0xc5,0x4e,0xd8,0x25,

        0x97,0x40,0x05,0x1e,
        0x9c,0x5f,0xec,0xf6,
        0x43,0x44,0xf7,0xa8,
        0x22,0x60,0xed,0xcc,

        0x30,0x4c,0x65,0x28,
        0xf6,0x59,0xc7,0x78,
        0x66,0xa5,0x10,0xd9,
        0xc1,0xd6,0xae,0x5e
    };

    if (!ll_AES_SetEncryptKey(&ctx, key128, AES_128_KEY_SIZE)) { 
        printf("AES-128 init failed\n"); return; 
    }

    if (!ll_AES_OFB_Encrypt(&ctx, iv, plain_text, sizeof(plain_text), ct)) {
        printf("AES-128 OFB encryption failed\n"); return;
    }

    // Reset IV for decryption
    uint8_t iv_dec[AES_BLOCK_SIZE];
    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    if (!ll_AES_OFB_Decrypt(&ctx, iv_dec, ct, sizeof(ct), dec)) {
        printf("AES-128 OFB decryption failed\n"); return;
    }
    ll_AES_ClearKey(&ctx);

    printf("AES-128 OFB Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct128, sizeof(expected_ct128));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-128 OFB FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct128, ct, sizeof(expected_ct128)) == 0) && memcmp(plain_text, dec, sizeof(plain_text)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-192 ----------------
    uint8_t key192[AES_192_KEY_SIZE] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    uint8_t expected_ct192[4 * AES_BLOCK_SIZE] = {
        0xcd,0xc8,0x0d,0x6f,
        0xdd,0xf1,0x8c,0xab,
        0x34,0xc2,0x59,0x09,
        0xc9,0x9a,0x41,0x74,
        
        0xfc,0xc2,0x8b,0x8d,
        0x4c,0x63,0x83,0x7c,
        0x09,0xe8,0x17,0x00,
        0xc1,0x10,0x04,0x01,
        
        0x8d,0x9a,0x9a,0xea,
        0xc0,0xf6,0x59,0x6f,
        0x55,0x9c,0x6d,0x4d,
        0xaf,0x59,0xa5,0xf2,

        0x6d,0x9f,0x20,0x08,
        0x57,0xca,0x6c,0x3e,
        0x9c,0xac,0x52,0x4b,
        0xd9,0xac,0xc9,0x2a
    };

    if (!ll_AES_SetEncryptKey(&ctx, key192, AES_192_KEY_SIZE)) { 
        printf("AES-192 init failed\n"); return; 
    }

    if (!ll_AES_OFB_Encrypt(&ctx, iv, plain_text, sizeof(plain_text), ct)) {
        printf("AES-192 OFB encryption failed\n"); return;
    }

    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    if (!ll_AES_OFB_Decrypt(&ctx, iv_dec, ct, sizeof(ct), dec)) {
        printf("AES-192 OFB decryption failed\n"); return;
    }
    ll_AES_ClearKey(&ctx);

    printf("AES-192 OFB Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct192, sizeof(expected_ct192));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-192 OFB FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct192, ct, sizeof(expected_ct192)) == 0) && memcmp(plain_text, dec, sizeof(plain_text)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-256 ----------------
    uint8_t key256[AES_256_KEY_SIZE] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    uint8_t expected_ct256[4 * AES_BLOCK_SIZE] = {
        0xdc,0x7e,0x84,0xbf,
        0xda,0x79,0x16,0x4b,
        0x7e,0xcd,0x84,0x86,
        0x98,0x5d,0x38,0x60,
        
        0x4f,0xeb,0xdc,0x67,
        0x40,0xd2,0x0b,0x3a,
        0xc8,0x8f,0x6a,0xd8,
        0x2a,0x4f,0xb0,0x8d,
        
        0x71,0xab,0x47,0xa0,
        0x86,0xe8,0x6e,0xed,
        0xf3,0x9d,0x1c,0x5b,
        0xba,0x97,0xc4,0x08,
        
        0x01,0x26,0x14,0x1d,
        0x67,0xf3,0x7b,0xe8,
        0x53,0x8f,0x5a,0x8b,
        0xe7,0x40,0xe4,0x84
    };

    if (!ll_AES_SetEncryptKey(&ctx, key256, AES_256_KEY_SIZE)) { 
        printf("AES-256 init failed\n"); return; 
    }

    if (!ll_AES_OFB_Encrypt(&ctx, iv, plain_text, sizeof(plain_text), ct)) {
        printf("AES-256 OFB encryption failed\n"); return;
    }

    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    if (!ll_AES_OFB_Decrypt(&ctx, iv_dec, ct, sizeof(ct), dec)) {
        printf("AES-256 OFB decryption failed\n"); return;
    }
    ll_AES_ClearKey(&ctx);

    printf("AES-256 OFB Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct256, sizeof(expected_ct256));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-256 OFB FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct256, ct, sizeof(expected_ct256)) == 0 && memcmp(plain_text, dec, sizeof(plain_text)) == 0)) ? "PASSED" : "FAILED");
}

void test_aes_ctr_fips800_38a(void) {
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

    // fixed counter (for testing purposes)
    uint8_t fixed_counter[AES_BLOCK_SIZE] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };

    // counter (for testing purposes)
    uint8_t enc_counter[AES_BLOCK_SIZE];
    memcpy(enc_counter, fixed_counter, AES_BLOCK_SIZE);

    ll_AES_KEY ctx;
    SECURE_ZERO(&ctx, sizeof(ctx));

    uint8_t ct[4 * AES_BLOCK_SIZE];
    uint8_t dec[4 * AES_BLOCK_SIZE];

    // ---------------- AES-128 ----------------
    uint8_t key128[AES_128_KEY_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t expected_ct128[4 * AES_BLOCK_SIZE] = {
        0x87,0x4d,0x61,0x91,
        0xb6,0x20,0xe3,0x26,
        0x1b,0xef,0x68,0x64,
        0x99,0x0d,0xb6,0xce,
        
        0x98,0x06,0xf6,0x6b,
        0x79,0x70,0xfd,0xff,
        0x86,0x17,0x18,0x7b,
        0xb9,0xff,0xfd,0xff,
        
        0x5a,0xe4,0xdf,0x3e,
        0xdb,0xd5,0xd3,0x5e,
        0x5b,0x4f,0x09,0x02,
        0x0d,0xb0,0x3e,0xab,
        
        0x1e,0x03,0x1d,0xda,
        0x2f,0xbe,0x03,0xd1,
        0x79,0x21,0x70,0xa0,
        0xf3,0x00,0x9c,0xee
    };

    if (!ll_AES_SetEncryptKey(&ctx, key128, AES_128_KEY_SIZE)) { 
        printf("AES-128 init failed\n"); return; 
    }

    if (!ll_AES_CTR_Encrypt(&ctx, enc_counter, plain_text, sizeof(plain_text), ct)) {
        printf("AES-128 OFB encryption failed\n"); return;
    }

    // Reset Counter for decryption
    uint8_t counter_dec[AES_BLOCK_SIZE];
    memcpy(counter_dec, fixed_counter, AES_BLOCK_SIZE);

    if (!ll_AES_CTR_Decrypt(&ctx, counter_dec, ct, sizeof(ct), dec)) {
        printf("AES-128 CTR decryption failed\n"); return;
    }
    ll_AES_ClearKey(&ctx);

    printf("AES-128 CTR Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct128, sizeof(expected_ct128));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-128 CTR FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct128, ct, sizeof(expected_ct128)) == 0) && memcmp(plain_text, dec, sizeof(plain_text)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-192 ----------------
    uint8_t key192[AES_192_KEY_SIZE] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    uint8_t expected_ct192[4 * AES_BLOCK_SIZE] = {
        0x1a,0xbc,0x93,0x24,
        0x17,0x52,0x1c,0xa2,
        0x4f,0x2b,0x04,0x59,
        0xfe,0x7e,0x6e,0x0b,
        
        0x09,0x03,0x39,0xec,
        0x0a,0xa6,0xfa,0xef,
        0xd5,0xcc,0xc2,0xc6,
        0xf4,0xce,0x8e,0x94,
        
        0x1e,0x36,0xb2,0x6b,
        0xd1,0xeb,0xc6,0x70,
        0xd1,0xbd,0x1d,0x66,
        0x56,0x20,0xab,0xf7,
        
        0x4f,0x78,0xa7,0xf6,
        0xd2,0x98,0x09,0x58,
        0x5a,0x97,0xda,0xec,
        0x58,0xc6,0xb0,0x50
    };

    if (!ll_AES_SetEncryptKey(&ctx, key192, AES_192_KEY_SIZE)) { 
        printf("AES-192 init failed\n"); return; 
    }

    // Reset Counter for encryption
    memcpy(enc_counter, fixed_counter, AES_BLOCK_SIZE);

    if (!ll_AES_CTR_Encrypt(&ctx, enc_counter, plain_text, sizeof(plain_text), ct)) {
        printf("AES-192 CTR encryption failed\n"); return;
    }

    // Reset Counter for decryption
    memcpy(counter_dec, fixed_counter, AES_BLOCK_SIZE);

    if (!ll_AES_CTR_Decrypt(&ctx, counter_dec, ct, sizeof(ct), dec)) {
        printf("AES-192 CTR decryption failed\n"); return;
    }
    ll_AES_ClearKey(&ctx);

    printf("AES-192 CTR Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct192, sizeof(expected_ct192));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-192 CTR FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct192, ct, sizeof(expected_ct192)) == 0) && memcmp(plain_text, dec, sizeof(plain_text)) == 0) ? "PASSED" : "FAILED");

    // ---------------- AES-256 ----------------
    uint8_t key256[AES_256_KEY_SIZE] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    uint8_t expected_ct256[4 * AES_BLOCK_SIZE] = {
        0x60,0x1e,0xc3,0x13,
        0x77,0x57,0x89,0xa5,
        0xb7,0xa7,0xf5,0x04,
        0xbb,0xf3,0xd2,0x28,
        
        0xf4,0x43,0xe3,0xca,
        0x4d,0x62,0xb5,0x9a,
        0xca,0x84,0xe9,0x90,
        0xca,0xca,0xf5,0xc5,
        
        0x2b,0x09,0x30,0xda,
        0xa2,0x3d,0xe9,0x4c,
        0xe8,0x70,0x17,0xba,
        0x2d,0x84,0x98,0x8d,
        
        0xdf,0xc9,0xc5,0x8d,
        0xb6,0x7a,0xad,0xa6,
        0x13,0xc2,0xdd,0x08,
        0x45,0x79,0x41,0xa6
    };

    if (!ll_AES_SetEncryptKey(&ctx, key256, AES_256_KEY_SIZE)) { 
        printf("AES-256 init failed\n"); return; 
    }

    memcpy(enc_counter, fixed_counter, AES_BLOCK_SIZE);

    if (!ll_AES_CTR_Encrypt(&ctx, enc_counter, plain_text, sizeof(plain_text), ct)) {
        printf("AES-256 CTR encryption failed\n"); return;
    }

    memcpy(counter_dec, fixed_counter, AES_BLOCK_SIZE);

    if (!ll_AES_CTR_Decrypt(&ctx, counter_dec, ct, sizeof(ct), dec)) {
        printf("AES-256 CTR decryption failed\n"); return;
    }
    ll_AES_ClearKey(&ctx);

    printf("AES-256 CTR Test:\n");
    printf("Plaintext: "); DEMO_print_hex(plain_text, sizeof(plain_text));
    printf("Ciphertext: "); DEMO_print_hex(ct, sizeof(ct));
    printf("Expected:  "); DEMO_print_hex(expected_ct256, sizeof(expected_ct256));
    printf("Decrypted: "); DEMO_print_hex(dec, sizeof(dec));
    printf("AES-256 CTR FIPS-800-38a test %s\n", 
        ((memcmp(expected_ct256, ct, sizeof(expected_ct256)) == 0 && memcmp(plain_text, dec, sizeof(plain_text)) == 0)) ? "PASSED" : "FAILED");
}

void test_all_cipher_high(void) {
    uint32_t cf_chacha_flags[] = {
        CF_CHACHA8,
        CF_CHACHA12,
        CF_CHACHA20,

        CF_XCHACHA8,
        CF_XCHACHA12,
        CF_XCHACHA20,
    };

    size_t num_cf_chacha_flags = sizeof(cf_chacha_flags)/sizeof(cf_chacha_flags[0]);

    static const uint8_t chacha_key128[CF_KEY_128_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    static const uint8_t chacha_key256[CF_KEY_256_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    static const uint8_t *chacha_key_test_vectors[] = {
        chacha_key128,
        chacha_key256
    };

    static const size_t chacha_key_test_vectors_sizes[] = {
        sizeof(chacha_key128),
        sizeof(chacha_key256)
    };

    size_t num_chacha_keys = sizeof(chacha_key_test_vectors)/sizeof(chacha_key_test_vectors_sizes[0]);

    uint8_t chacha_iv[12] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };

    uint8_t xchacha_iv[CF_MAX_CIPHER_IV_SIZE] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00,

        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };

    uint8_t chacha_plain_text[114] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };

    uint32_t chacha_count = 1;

    for (size_t i = 0; i < num_cf_chacha_flags; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(cf_chacha_flags[i]);
        if (!cipher) {
            printf("Unknown Cipher flag %u\n", cf_chacha_flags[i]);
            continue;
        }

        uint8_t output_ct[114] = {0};
        uint8_t output_dec[114] = {0};

        CF_STATUS status = CF_SUCCESS;
        for (size_t j = 0; j < num_chacha_keys; j++) { 
            if (chacha_key_test_vectors_sizes[j] == CF_KEY_128_SIZE &&
                ((cf_chacha_flags[i] == CF_XCHACHA8) ||
                (cf_chacha_flags[i] == CF_XCHACHA12) ||
                (cf_chacha_flags[i] == CF_XCHACHA20)))
                    continue;

            CF_CIPHER_OPTS *ctxOpts = NULL;
            CF_CIPHER_CTX ctx = {0};

            if (((cf_chacha_flags[i] == CF_XCHACHA8) ||
                (cf_chacha_flags[i] == CF_XCHACHA12) ||
                (cf_chacha_flags[i] == CF_XCHACHA20))) {
                ctxOpts = CF_CipherOpts_InitAlloc(chacha_iv, sizeof(chacha_iv), NULL, chacha_count, 0, &status);
            } else {
                ctxOpts = CF_CipherOpts_InitAlloc(xchacha_iv, sizeof(xchacha_iv), NULL, chacha_count, 0, &status);
            }

            if (status != CF_SUCCESS) {
                printf("CF_CipherOpts_InitAlloc failed for %s\n", CF_Cipher_GetName(cipher));
                continue;
            }

            // this init just to get the proper credentials for CF_Cipher_GetFullName() for algorithm name display for testing
            status = CF_Cipher_Init(&ctx, cipher, ctxOpts, chacha_key_test_vectors[j], chacha_key_test_vectors_sizes[j], CF_OP_ENCRYPT);
            if (status != CF_SUCCESS) {
                CF_CipherOpts_Free(&ctxOpts);
                printf("CF_Cipher_Init failed for %s, error status: %u\n", CF_Cipher_GetName(cipher), status);
                CF_Cipher_Reset(&ctx);
                continue;
            }

            status = CF_Cipher_Encrypt(cipher, chacha_key_test_vectors[j], chacha_key_test_vectors_sizes[j], chacha_plain_text, sizeof(chacha_plain_text), output_ct, ctxOpts);
            if (status != CF_SUCCESS) {
                CF_CipherOpts_Free(&ctxOpts);
                printf("CF_Cipher_Encrypt failed for %s, error status: %u\n", CF_Cipher_GetFullName(&ctx), status);
                continue;
            }

            // restart for testing
            ctxOpts->chacha_counter = chacha_count;

            status = CF_Cipher_Decrypt(cipher, chacha_key_test_vectors[j], chacha_key_test_vectors_sizes[j], output_ct, sizeof(output_ct), output_dec, ctxOpts);
            if (status != CF_SUCCESS) {
                CF_CipherOpts_Free(&ctxOpts);
                printf("CF_Cipher_Decrypt failed for %s, error status: %u\n", CF_Cipher_GetFullName(&ctx), status);
                continue;
            }

            printf("%s CT : ", CF_Cipher_GetFullName(&ctx));
            DEMO_print_hex(output_ct, sizeof(output_ct));
            printf("%s DEC: ", CF_Cipher_GetFullName(&ctx));
            DEMO_print_hex(output_dec, sizeof(output_dec));
            printf("\n");

            CF_Cipher_Reset(&ctx);
            CF_CipherOpts_Free(&ctxOpts);
        }
    }

    putchar('\n');

    static const uint8_t aes_plain_text[4 * AES_BLOCK_SIZE] = {
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

    static const uint8_t aes_key128[CF_KEY_128_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    static const uint8_t aes_key192[CF_KEY_192_SIZE] = {
        0x8e, 0x73, 0xb0, 0xf7,
        0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b,
        0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2,
        0x52, 0x2c, 0x6b, 0x7b
    };

    static const uint8_t aes_key256[CF_KEY_256_SIZE] = {
        0x60, 0x3d, 0xeb, 0x10,
        0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0,
        0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07,
        0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3,
        0x09, 0x14, 0xdf, 0xf4
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

    // Fixed AES IV (for testing purposes)
    uint8_t aes_test_iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };


    // fixed AES counter (for testing purposes)
    uint8_t aes_test_fixed_counter[AES_BLOCK_SIZE] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };

    uint32_t cf_aes_flags[] = {
        CF_AES_ECB,
        CF_AES_CBC,     // iv
        CF_AES_OFB,     // iv
        CF_AES_CFB8,    // iv
        CF_AES_CFB128,  // iv
        CF_AES_CTR      // counter
    };

    size_t num_cf_aes_flags = sizeof(cf_aes_flags)/sizeof(cf_aes_flags[0]);

    for (size_t i = 0; i < num_cf_aes_flags; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(cf_aes_flags[i]);
        if (!cipher) {
            printf("Unknown Cipher flag %u\n", cf_aes_flags[i]);
            continue;
        }

        CF_STATUS status;
        CF_CIPHER_OPTS *ctxOpts = NULL;

        if (cf_aes_flags[i] != CF_AES_ECB) {

            uint8_t enc_counter[AES_BLOCK_SIZE];
            memcpy(enc_counter, aes_test_fixed_counter, AES_BLOCK_SIZE);

            ctxOpts = CF_CipherOpts_InitAlloc(
                cf_aes_flags[i] != CF_AES_CTR ? aes_test_iv : NULL,      // mandetory for CBC/OFB/CFB8/CFB128
                cf_aes_flags[i] != CF_AES_CTR ? sizeof(aes_test_iv) : 0, // mandetory for CBC/OFB/CFB8/CFB128
                cf_aes_flags[i] == CF_AES_CTR ? enc_counter : NULL,      // mandetory for ctr
                0, // chacha counter is not used in aes modes
                0, // no padding flags yet
                &status);

            if (status != CF_SUCCESS) {
                printf("CF_CipherOpts_InitAlloc failed for %s\n", CF_Cipher_GetName(cipher));
                continue;
            }
        }

        for (size_t j = 0; j < num_aes_keys; j++) {
            CF_CIPHER_CTX ctx = {0};

            uint8_t output_ct[4 * AES_BLOCK_SIZE] = {0};
            uint8_t output_dec[4 * AES_BLOCK_SIZE] = {0};

            // this init just to get the proper credentials for CF_Cipher_GetFullName() for algorithm name display for testing
            status = CF_Cipher_Init(&ctx, cipher, ctxOpts, aes_key_test_vectors[j], aes_key_test_vectors_sizes[j], CF_OP_ENCRYPT);
            if (status != CF_SUCCESS) {
                printf("CF_Cipher_Init failed for %s, error status: %u\n", CF_Cipher_GetName(cipher), status);
                CF_Cipher_Reset(&ctx);
                continue;
            }

            status = CF_Cipher_Encrypt(cipher, aes_key_test_vectors[j], aes_key_test_vectors_sizes[j], aes_plain_text, sizeof(aes_plain_text), output_ct, ctxOpts);
            if (status != CF_SUCCESS) {
                printf("CF_Cipher_Encrypt failed for %s, error status: %u\n", CF_Cipher_GetFullName(&ctx), status);
                continue;
            }

            if (ctxOpts && cf_aes_flags[i] == CF_AES_CTR) {
                memcpy(ctxOpts->ctr_block, aes_test_fixed_counter, AES_BLOCK_SIZE);
            }

            status = CF_Cipher_Decrypt(cipher, aes_key_test_vectors[j], aes_key_test_vectors_sizes[j], output_ct, sizeof(output_ct), output_dec, ctxOpts);
            if (status != CF_SUCCESS) {
                printf("CF_Cipher_Decrypt failed for %s, error status: %u\n", CF_Cipher_GetFullName(&ctx), status);
                continue;
            }

            if (ctxOpts && cf_aes_flags[i] == CF_AES_CTR) {
                memcpy(ctxOpts->ctr_block, aes_test_fixed_counter, AES_BLOCK_SIZE);
            }

            printf("%s CT : ", CF_Cipher_GetFullName(&ctx));
            DEMO_print_hex(output_ct, sizeof(output_ct));
            printf("%s DEC: ", CF_Cipher_GetFullName(&ctx));
            DEMO_print_hex(output_dec, sizeof(output_dec));
            printf("\n");

            CF_Cipher_Reset(&ctx);
        }
        if (ctxOpts)
            CF_CipherOpts_Free(&ctxOpts);
    }
}

void test_ecb_kat(void) {
    size_t num_test_vectors = sizeof(ecb_kat_test_vectors) / sizeof(ecb_kat_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(CF_AES_ECB); // assuming AES-ECB
        if (!cipher) {
            printf("Unknown Cipher flag for test vector %d\n", ecb_kat_test_vectors[i].tc_id);
            return;
        }

        CF_CIPHER_OPTS opts = {0};

        uint8_t out[16] = {0};
        int failure = 0;
        int encrypt_mode = (strcmp(ecb_kat_test_vectors[i].mode, "ENCRYPT") == 0);

        CF_STATUS status = CF_CipherOpts_Init(&opts, NULL, 0, NULL, 0, 0);
        if (encrypt_mode) {
            status = CF_Cipher_Encrypt(
                cipher,
                ecb_kat_test_vectors[i].key, ecb_kat_test_vectors[i].key_len,
                ecb_kat_test_vectors[i].msg, ecb_kat_test_vectors[i].msg_len,
                out,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, ecb_kat_test_vectors[i].ct, ecb_kat_test_vectors[i].ct_len) != 0) {
                printf("ECB TcId %d FAILED (encryption mismatch)\n", ecb_kat_test_vectors[i].tc_id);
                printf("Expected CT: ");
                DEMO_print_hex(ecb_kat_test_vectors[i].ct, ecb_kat_test_vectors[i].ct_len);
                printf("Computed CT: ");
                DEMO_print_hex(out, ecb_kat_test_vectors[i].ct_len);
                failure = 1;
            }
        } else { // DECRYPT
            status = CF_Cipher_Decrypt(
                cipher,
                ecb_kat_test_vectors[i].key, ecb_kat_test_vectors[i].key_len,
                ecb_kat_test_vectors[i].ct, ecb_kat_test_vectors[i].ct_len,
                out,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, ecb_kat_test_vectors[i].msg, ecb_kat_test_vectors[i].msg_len) != 0) {
                printf("ECB TcId %d FAILED (decryption mismatch)\n", ecb_kat_test_vectors[i].tc_id);
                printf("Expected PT: ");
                DEMO_print_hex(ecb_kat_test_vectors[i].msg, ecb_kat_test_vectors[i].msg_len);
                printf("Computed PT: ");
                DEMO_print_hex(out, ecb_kat_test_vectors[i].msg_len);
                failure = 1;
            }
        }

        if (failure) {
            if (ecb_kat_test_vectors[i].comment && ecb_kat_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", ecb_kat_test_vectors[i].comment);
            }
            total_failures++;
        } else {
            total_success++;
        }
    }

    printf("ECB KAT tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_cbc_kat(void) {
    size_t num_test_vectors = sizeof(cbc_kat_test_vectors) / sizeof(cbc_kat_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(CF_AES_CBC); // assuming AES-CBC
        if (!cipher) {
            printf("Unknown Cipher flag for test vector %d\n", cbc_kat_test_vectors[i].tc_id);
            return;
        }

        uint8_t out[16] = {0};
        int failure = 0;
        int encrypt_mode = (strcmp(cbc_kat_test_vectors[i].mode, "ENCRYPT") == 0);

        CF_CIPHER_OPTS opts = {0};
        CF_STATUS status = CF_CipherOpts_Init(
            &opts,
            cbc_kat_test_vectors[i].iv,
            cbc_kat_test_vectors[i].iv_len,
            NULL, // No AES Counter for AES-CBC
            0,    // No ChaCha counter for AES-CBC
            0);   // No subflags for AES-CBC

        if (encrypt_mode) {
            status = CF_Cipher_Encrypt(
                cipher,
                cbc_kat_test_vectors[i].key, cbc_kat_test_vectors[i].key_len,
                cbc_kat_test_vectors[i].msg, cbc_kat_test_vectors[i].msg_len,
                out,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, cbc_kat_test_vectors[i].ct, cbc_kat_test_vectors[i].ct_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("CBC TcId %d FAILED (encryption mismatch)\n", cbc_kat_test_vectors[i].tc_id);
                printf("Expected CT: ");
                DEMO_print_hex(cbc_kat_test_vectors[i].ct, cbc_kat_test_vectors[i].ct_len);
                printf("Computed CT: ");
                DEMO_print_hex(out, cbc_kat_test_vectors[i].ct_len);
                failure = 1;
            }
        } else { // DECRYPT
            status = CF_Cipher_Decrypt(
                cipher,
                cbc_kat_test_vectors[i].key, cbc_kat_test_vectors[i].key_len,
                cbc_kat_test_vectors[i].ct, cbc_kat_test_vectors[i].ct_len,
                out,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, cbc_kat_test_vectors[i].msg, cbc_kat_test_vectors[i].msg_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("CBC TcId %d FAILED (decryption mismatch)\n", cbc_kat_test_vectors[i].tc_id);
                printf("Expected PT: ");
                DEMO_print_hex(cbc_kat_test_vectors[i].msg, cbc_kat_test_vectors[i].msg_len);
                printf("Computed PT: ");
                DEMO_print_hex(out, cbc_kat_test_vectors[i].msg_len);
                failure = 1;
            }
        }

        if (failure) {
            if (cbc_kat_test_vectors[i].comment && cbc_kat_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", cbc_kat_test_vectors[i].comment);
            }
            total_failures++;
        } else {
            total_success++;
        }

        CF_CipherOpts_Reset(&opts);
    }

    printf("CBC KAT tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_cfb8_kat(void) {
    size_t num_test_vectors = sizeof(cfb8_kat_test_vectors) / sizeof(cfb8_kat_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(CF_AES_CFB8); // assuming AES-CFB8
        if (!cipher) {
            printf("Unknown Cipher flag for test vector %d\n", cfb8_kat_test_vectors[i].tc_id);
            return;
        }

        uint8_t out[16] = {0};
        int failure = 0;
        int encrypt_mode = (strcmp(cfb8_kat_test_vectors[i].mode, "ENCRYPT") == 0);

        CF_CIPHER_OPTS opts = {0};
        CF_STATUS status = CF_CipherOpts_Init(
            &opts,
            cfb8_kat_test_vectors[i].iv,
            cfb8_kat_test_vectors[i].iv_len,
            NULL, // No AES Counter for AES-CFB8
            0,    // No ChaCha counter for AES-CFB8
            0);   // No subflags for AES-CFB8

        if (encrypt_mode) {
            status = CF_Cipher_Encrypt(
                cipher,
                cfb8_kat_test_vectors[i].key, cfb8_kat_test_vectors[i].key_len,
                cfb8_kat_test_vectors[i].msg, cfb8_kat_test_vectors[i].msg_len,
                out,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, cfb8_kat_test_vectors[i].ct, cfb8_kat_test_vectors[i].ct_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("CFB8 TcId %d FAILED (encryption mismatch)\n", cfb8_kat_test_vectors[i].tc_id);
                printf("Expected CT: ");
                DEMO_print_hex(cfb8_kat_test_vectors[i].ct, cfb8_kat_test_vectors[i].ct_len);
                printf("Computed CT: ");
                DEMO_print_hex(out, cfb8_kat_test_vectors[i].ct_len);
                failure = 1;
            }
        } else { // DECRYPT
            status = CF_Cipher_Decrypt(
                cipher,
                cfb8_kat_test_vectors[i].key, cfb8_kat_test_vectors[i].key_len,
                cfb8_kat_test_vectors[i].ct, cfb8_kat_test_vectors[i].ct_len,
                out,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, cfb8_kat_test_vectors[i].msg, cfb8_kat_test_vectors[i].msg_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("CFB8 TcId %d FAILED (decryption mismatch)\n", cfb8_kat_test_vectors[i].tc_id);
                printf("Expected PT: ");
                DEMO_print_hex(cfb8_kat_test_vectors[i].msg, cfb8_kat_test_vectors[i].msg_len);
                printf("Computed PT: ");
                DEMO_print_hex(out, cfb8_kat_test_vectors[i].msg_len);
                failure = 1;
            }
        }

        if (failure) {
            if (cfb8_kat_test_vectors[i].comment && cfb8_kat_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", cfb8_kat_test_vectors[i].comment);
            }
            total_failures++;
        } else {
            total_success++;
        }

        CF_CipherOpts_Reset(&opts);
    }

    printf("CFB8 KAT tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_cfb128_kat(void) {
    size_t num_test_vectors = sizeof(cfb128_kat_test_vectors) / sizeof(cfb128_kat_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(CF_AES_CFB128); // assuming AES-CFB128
        if (!cipher) {
            printf("Unknown Cipher flag for test vector %d\n", cfb128_kat_test_vectors[i].tc_id);
            return;
        }

        uint8_t out[16] = {0};
        int failure = 0;
        int encrypt_mode = (strcmp(cfb128_kat_test_vectors[i].mode, "ENCRYPT") == 0);

        CF_CIPHER_OPTS opts = {0};
        CF_STATUS status = CF_CipherOpts_Init(
            &opts,
            cfb128_kat_test_vectors[i].iv,
            cfb128_kat_test_vectors[i].iv_len,
            NULL, // No AES Counter for AES-CFB128
            0,    // No ChaCha counter for AES-CFB128
            0);   // No subflags for AES-CFB128

        if (encrypt_mode) {
            status = CF_Cipher_Encrypt(
                cipher,
                cfb128_kat_test_vectors[i].key, cfb128_kat_test_vectors[i].key_len,
                cfb128_kat_test_vectors[i].msg, cfb128_kat_test_vectors[i].msg_len,
                out,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, cfb128_kat_test_vectors[i].ct, cfb128_kat_test_vectors[i].ct_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("CFB128 TcId %d FAILED (encryption mismatch)\n", cfb128_kat_test_vectors[i].tc_id);
                printf("Expected CT: ");
                DEMO_print_hex(cfb128_kat_test_vectors[i].ct, cfb128_kat_test_vectors[i].ct_len);
                printf("Computed CT: ");
                DEMO_print_hex(out, cfb128_kat_test_vectors[i].ct_len);
                failure = 1;
            }
        } else { // DECRYPT
            status = CF_Cipher_Decrypt(
                cipher,
                cfb128_kat_test_vectors[i].key, cfb128_kat_test_vectors[i].key_len,
                cfb128_kat_test_vectors[i].ct, cfb128_kat_test_vectors[i].ct_len,
                out,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, cfb128_kat_test_vectors[i].msg, cfb128_kat_test_vectors[i].msg_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("CFB128 TcId %d FAILED (decryption mismatch)\n", cfb128_kat_test_vectors[i].tc_id);
                printf("Expected PT: ");
                DEMO_print_hex(cfb128_kat_test_vectors[i].msg, cfb128_kat_test_vectors[i].msg_len);
                printf("Computed PT: ");
                DEMO_print_hex(out, cfb128_kat_test_vectors[i].msg_len);
                failure = 1;
            }
        }

        if (failure) {
            if (cfb128_kat_test_vectors[i].comment && cfb128_kat_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", cfb128_kat_test_vectors[i].comment);
            }
            total_failures++;
        } else {
            total_success++;
        }

        CF_CipherOpts_Reset(&opts);
    }

    printf("CFB128 KAT tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_ofb_kat(void) {
    size_t num_test_vectors = sizeof(ofb_kat_test_vectors) / sizeof(ofb_kat_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(CF_AES_OFB); // assuming AES-OFB
        if (!cipher) {
            printf("Unknown Cipher flag for test vector %d\n", ofb_kat_test_vectors[i].tc_id);
            return;
        }

        uint8_t out[16] = {0};
        int failure = 0;
        int encrypt_mode = (strcmp(ofb_kat_test_vectors[i].mode, "ENCRYPT") == 0);

        CF_CIPHER_OPTS opts = {0};
        CF_STATUS status = CF_CipherOpts_Init(
            &opts,
            ofb_kat_test_vectors[i].iv,
            ofb_kat_test_vectors[i].iv_len,
            NULL, // No AES Counter for AES-OFB
            0,    // No ChaCha counter for AES-OFB
            0);   // No subflags for AES-OFB

        if (encrypt_mode) {
            status = CF_Cipher_Encrypt(
                cipher,
                ofb_kat_test_vectors[i].key, ofb_kat_test_vectors[i].key_len,
                ofb_kat_test_vectors[i].msg, ofb_kat_test_vectors[i].msg_len,
                out,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, ofb_kat_test_vectors[i].ct, ofb_kat_test_vectors[i].ct_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("CBC TcId %d FAILED (encryption mismatch)\n", ofb_kat_test_vectors[i].tc_id);
                printf("Expected CT: ");
                DEMO_print_hex(ofb_kat_test_vectors[i].ct, ofb_kat_test_vectors[i].ct_len);
                printf("Computed CT: ");
                DEMO_print_hex(out, ofb_kat_test_vectors[i].ct_len);
                failure = 1;
            }
        } else { // DECRYPT
            status = CF_Cipher_Decrypt(
                cipher,
                ofb_kat_test_vectors[i].key, ofb_kat_test_vectors[i].key_len,
                ofb_kat_test_vectors[i].ct, ofb_kat_test_vectors[i].ct_len,
                out,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, ofb_kat_test_vectors[i].msg, ofb_kat_test_vectors[i].msg_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("CBC TcId %d FAILED (decryption mismatch)\n", ofb_kat_test_vectors[i].tc_id);
                printf("Expected PT: ");
                DEMO_print_hex(ofb_kat_test_vectors[i].msg, ofb_kat_test_vectors[i].msg_len);
                printf("Computed PT: ");
                DEMO_print_hex(out, ofb_kat_test_vectors[i].msg_len);
                failure = 1;
            }
        }

        if (failure) {
            if (ofb_kat_test_vectors[i].comment && ofb_kat_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", ofb_kat_test_vectors[i].comment);
            }
            total_failures++;
        } else {
            total_success++;
        }

        CF_CipherOpts_Reset(&opts);
    }

    printf("OFB KAT tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

#endif // ENABLE_TESTS