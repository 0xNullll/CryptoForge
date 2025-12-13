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
        0x39, 0x02, 0xDC, 0x19,
        0x25, 0xDC, 0x11, 0x6A,
        0x84, 0x09, 0x85, 0x0B,
        0x1D, 0xFB, 0x97, 0x32
    };

    AES_KEY ctx;
    uint8_t ciphertext[AES_BLOCK_SIZE];
    uint8_t decrypted[AES_BLOCK_SIZE];

    if (!ll_AES_Init(key, AES_128_KEY_SIZE, &ctx)) {
        printf("AES-128 init failed\n");
        return;
    }

    ll_AES_EncryptBlock(plaintext, ciphertext, &ctx);
    ll_AES_DecryptBlock(ciphertext, decrypted, &ctx);

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
        0x58, 0xc2, 0xf4, 0x2b,
        0x5e, 0x72, 0xf4, 0xb0,
        0x9f, 0x2b, 0x92, 0x24,
        0xb6, 0x9a, 0xc1, 0xc1
    };

    AES_KEY ctx;
    uint8_t ciphertext[AES_BLOCK_SIZE];
    uint8_t decrypted[AES_BLOCK_SIZE];

    if (!ll_AES_Init(key, AES_192_KEY_SIZE, &ctx)) {
        printf("AES-192 init failed\n");
        return;
    }

    ll_AES_EncryptBlock(plaintext, ciphertext, &ctx);
    ll_AES_DecryptBlock(ciphertext, decrypted, &ctx);

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
        0x30, 0x97, 0x4a, 0x37,
        0x21, 0x3e, 0x29, 0xae,
        0x61, 0x58, 0x23, 0xc4,
        0x3a, 0x2f, 0x41, 0x94
    };

    AES_KEY ctx;
    uint8_t ciphertext[AES_BLOCK_SIZE];
    uint8_t decrypted[AES_BLOCK_SIZE];

    if (!ll_AES_Init(key, AES_256_KEY_SIZE, &ctx)) {
        printf("AES-256 init failed\n");
        return;
    }

    ll_AES_EncryptBlock(plaintext, ciphertext, &ctx);
    ll_AES_DecryptBlock(ciphertext, decrypted, &ctx);

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

#endif // ENABLE_TEST