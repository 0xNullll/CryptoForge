#include "../src/include/config/demo_config.h"

#if ENABLE_TESTS

#define TEST_OKM_MAX 1024  // fixed size for test

void test_all_hkdfs(const uint8_t *info, size_t info_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    size_t okm_len) {
    if (okm_len > TEST_OKM_MAX) return;
    
    uint8_t okm[TEST_OKM_MAX];

    // List of hash flags to test
    uint32_t hash_flags[] = {
        CF_MD5, // legacy: for testing not recomended for user use
        CF_SHA1,
        CF_SHA224,
        CF_SHA256,
        CF_SHA384,
        CF_SHA512,
        CF_SHA512_224,
        CF_SHA512_256,
        CF_SHA3_224,
        CF_SHA3_256,
        CF_SHA3_384,
        CF_SHA3_512
    };

    size_t num_hashes = sizeof(hash_flags)/sizeof(hash_flags[0]);

    for (size_t i = 0; i < num_hashes; i++) {
        const CF_HASH *hash = CF_Hash_GetByFlag(hash_flags[i]);
        if (!hash) {
            printf("Unknown hash flag %u\n", hash_flags[i]);
            continue;
        }

        ll_HKDF_CTX hkdf_ctx;
        SECURE_ZERO(&hkdf_ctx, sizeof(hkdf_ctx));

        CF_STATUS status = ll_HKDF_Init(&hkdf_ctx, hash, info, info_len);
        if (status != CF_SUCCESS) {
            printf("ll_HKDF_Init failed for %s\n", CF_Hash_GetName(hash));
            continue;
        }

        status = ll_HKDF_Extract(&hkdf_ctx, salt, salt_len, ikm, ikm_len);
        if (status != CF_SUCCESS) {
            printf("ll_HKDF_Extract failed for %s\n", CF_Hash_GetName(hash));
            ll_HKDF_Reset(&hkdf_ctx);
            continue;
        }

        status = ll_HKDF_Expand(&hkdf_ctx, okm, okm_len, NULL, 0);
        if (status != CF_SUCCESS) {
            printf("ll_HKDF_Expand failed for %s\n", CF_Hash_GetName(hash));
            ll_HKDF_Reset(&hkdf_ctx);
            continue;
        }

        printf("%s HKDF OKM: ", CF_Hash_GetName(hash));
        DEMO_print_hex(okm, okm_len);
        printf("\n");

        ll_HKDF_Reset(&hkdf_ctx);
    }
}


void test_all_pbkdf2s(const uint8_t *password, size_t password_len,
                       const uint8_t *salt, size_t salt_len,
                       size_t dk_len, size_t iteration_count) {

    // List of hash flags to test
    uint32_t hash_flags[] = {
        CF_SHA1,
        CF_SHA224,
        CF_SHA256,
        CF_SHA384,
        CF_SHA512,
        CF_SHA512_224,
        CF_SHA512_256,
        CF_SHA3_224,
        CF_SHA3_256,
        CF_SHA3_384,
        CF_SHA3_512
    };

    size_t num_hashes = sizeof(hash_flags)/sizeof(hash_flags[0]);
    uint8_t dk_buffer[CF_MAX_DEFAULT_DIGEST_SIZE * 8]; // big enough for test

    for (size_t i = 0; i < num_hashes; i++) {
        const CF_HASH *hash = CF_Hash_GetByFlag(hash_flags[i]);
        if (!hash) {
            printf("Unknown hash flag %u\n", hash_flags[i]);
            continue;
        }

        ll_PBKDF2_CTX ctx = {0};

        CF_STATUS status = ll_PBKDF2_Init(&ctx, hash, password, password_len);
        if (status != CF_SUCCESS) {
            printf("ll_PBKDF2_Init failed for %s\n", CF_Hash_GetName(hash));
            continue;
        }

        status = ll_PBKDF2_Extract(&ctx, salt, salt_len);
        if (status != CF_SUCCESS) {
            printf("ll_PBKDF2_Extract failed for %s\n", CF_Hash_GetName(hash));
            ll_PBKDF2_Reset(&ctx);
            continue;
        }

        SECURE_ZERO(dk_buffer, sizeof(dk_buffer));
        status = ll_PBKDF2_Expand(&ctx, dk_buffer, dk_len, iteration_count);
        if (status != CF_SUCCESS) {
            printf("ll_PBKDF2_Expand failed for %s, error status: %u\n", CF_Hash_GetName(hash), status);
            ll_PBKDF2_Reset(&ctx);
            continue;
        }

        printf("%s PBKDF2 DK: ", CF_Hash_GetName(hash));
        DEMO_print_hex(dk_buffer, dk_len);
        printf("\n");

        ll_PBKDF2_Reset(&ctx);
    }
}

void test_all_kdf_high(void) {

    // List of hash flags to test
    uint32_t hash_flags[] = {
        CF_SHA1,
        CF_SHA224,
        CF_SHA256,
        CF_SHA384,
        CF_SHA512,
        CF_SHA512_224,
        CF_SHA512_256,
        CF_SHA3_224,
        CF_SHA3_256,
        CF_SHA3_384,
        CF_SHA3_512
    };

    // List of KDF flags to test
    uint32_t kdf_flags[] = {
        CF_HKDF,
        CF_PBKDF2,
        CF_KMAC_XOF
    };

    size_t num_hashes = sizeof(hash_flags)/sizeof(hash_flags[0]);
    uint8_t dk_buffer[CF_MAX_DEFAULT_DIGEST_SIZE];

    // Input parameters
    uint8_t hkdf_ikm[] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    uint8_t hkdf_salt[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,
        0x07,0x08,0x09,0x0a,0x0b,0x0c
    };
    uint8_t hkdf_info[] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
    };

    size_t hkdf_dk_len = 42;

    // HKDF
    for (size_t i = 0; i < num_hashes; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(kdf_flags[0]);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", kdf_flags[0]);
            continue;
        }

        CF_KDF_OPTS ctxOpts = {0};
        CF_KDF_CTX ctx = {0};
        
        CF_STATUS status = CF_KDFOpts_Init(&ctxOpts, hkdf_info, sizeof(hkdf_info), NULL, 0, 0);
        if (status != CF_SUCCESS) {
            printf("CF_KDFOpts_Init failed for %s\n", CF_KDF_GetName(kdf));
            continue;
        }

        status = CF_KDF_Init(&ctx, kdf, &ctxOpts, hkdf_ikm, sizeof(hkdf_ikm), hash_flags[i]);
        if (status != CF_SUCCESS) {
            CF_KDFOpts_Reset(&ctxOpts);
            printf("CF_KDF_Init failed for %s\n", CF_KDF_GetName(kdf));
            continue;
        }

        status = CF_KDF_Extract(&ctx, hkdf_salt, sizeof(hkdf_salt));
        if (status != CF_SUCCESS) {
            printf("CF_KDF_Extract failed for %s\n", CF_KDF_GetFullName(&ctx));
            CF_KDFOpts_Reset(&ctxOpts);
            CF_KDF_Reset(&ctx);
            continue;
        }

        SECURE_ZERO(dk_buffer, sizeof(dk_buffer));
        status = CF_KDF_Expand(&ctx, dk_buffer, hkdf_dk_len);
        if (status != CF_SUCCESS) {
            printf("CF_KDF_Expand failed for %s, error status: %u\n", CF_KDF_GetFullName(&ctx), status);
            CF_KDFOpts_Reset(&ctxOpts);
            CF_KDF_Reset(&ctx);
            continue;
        }

        printf("%s DK: ", CF_KDF_GetFullName(&ctx));
        DEMO_print_hex(dk_buffer, hkdf_dk_len);
        printf("\n");

        CF_KDFOpts_Reset(&ctxOpts);
        CF_KDF_Reset(&ctx);
    }

    putchar('\n');

    size_t pbkdf2_dk_len = 42;

    // "password123" in hex
    uint8_t pbkdf2_password[] = {
        0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x31, 0x32, 0x33
    };

    // "salt111" in hex
    uint8_t pbkdf2_salt[] = {
        0x73, 0x61, 0x6C, 0x74, 0x31, 0x31, 0x31
    };

    uint32_t pbkdf2_iterations = 1000;

    // PBKDF2
    for (size_t i = 0; i < num_hashes; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(kdf_flags[1]);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", kdf_flags[1]);
            continue;
        }

        CF_KDF_OPTS ctxOpts = {0};
        CF_KDF_CTX ctx = {0};
        
        CF_STATUS status = CF_KDFOpts_Init(&ctxOpts, NULL, 0, NULL, 0, pbkdf2_iterations);
        if (status != CF_SUCCESS) {
            printf("CF_KDFOpts_Init failed for %s\n", CF_KDF_GetName(kdf));
            continue;
        }

        status = CF_KDF_Init(&ctx, kdf, &ctxOpts, pbkdf2_password, sizeof(pbkdf2_password), hash_flags[i]);
        if (status != CF_SUCCESS) {
            CF_KDFOpts_Reset(&ctxOpts);
            printf("CF_KDF_Init failed for %s\n", CF_KDF_GetName(kdf));
            continue;
        }

        status = CF_KDF_Extract(&ctx, pbkdf2_salt, sizeof(pbkdf2_salt));
        if (status != CF_SUCCESS) {
            printf("CF_KDF_Extract failed for %s\n", CF_KDF_GetFullName(&ctx));
            CF_KDFOpts_Reset(&ctxOpts);
            CF_KDF_Reset(&ctx);
            continue;
        }

        SECURE_ZERO(dk_buffer, sizeof(dk_buffer));
        status = CF_KDF_Expand(&ctx, dk_buffer, pbkdf2_dk_len);
        if (status != CF_SUCCESS) {
            printf("CF_KDF_Expand failed for %s, error status: %u\n", CF_KDF_GetFullName(&ctx), status);
            CF_KDFOpts_Reset(&ctxOpts);
            CF_KDF_Reset(&ctx);
            continue;
        }

        printf("%s DK: ", CF_KDF_GetFullName(&ctx));
        DEMO_print_hex(dk_buffer, pbkdf2_dk_len);
        printf("\n");

        CF_KDFOpts_Reset(&ctxOpts);
        CF_KDF_Reset(&ctx);
    }

    putchar('\n');

    // List of KMAC type flags to test
    uint32_t kmac_flags[] = {
        CF_KMAC_XOF128,
        CF_KMAC_XOF256
    };

    size_t num_kmac = sizeof(kmac_flags)/sizeof(kmac_flags[0]);

    // test vectors from:
    // - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMACXOF_samples.pdf

    const uint8_t test_vector_kmac_key[32] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
    };

    static const uint8_t test_vector_kmac_input[200] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
        0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7
    };

    const char *test_vector_kmac_s_input =  "My Tagged Application";

    // KMAC-XOF
    for (size_t i = 0; i < num_kmac; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(kdf_flags[2]);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", kdf_flags[2]);
            continue;
        }

        CF_KDF_OPTS ctxOpts = {0};
        CF_KDF_CTX ctx = {0};
        
        CF_STATUS status = CF_KDFOpts_Init(&ctxOpts, NULL, 0, (const uint8_t *)test_vector_kmac_s_input, strlen(test_vector_kmac_s_input), 0);
        if (status != CF_SUCCESS) {
            printf("CF_KDFOpts_Init failed for %s\n", CF_KDF_GetName(kdf));
            continue;
        }

        status = CF_KDF_Init(&ctx, kdf, &ctxOpts, test_vector_kmac_key, sizeof(test_vector_kmac_key), kmac_flags[i]);
        if (status != CF_SUCCESS) {
            CF_KDFOpts_Reset(&ctxOpts);
            printf("CF_KDF_Init failed for %s\n", CF_KDF_GetName(kdf));
            continue;
        }

        status = CF_KDF_Extract(&ctx, test_vector_kmac_input, sizeof(test_vector_kmac_input));
        if (status != CF_SUCCESS) {
            printf("CF_KDF_Extract failed for %s\n", CF_KDF_GetFullName(&ctx));
            CF_KDFOpts_Reset(&ctxOpts);
            CF_KDF_Reset(&ctx);
            continue;
        }

        SECURE_ZERO(dk_buffer, sizeof(dk_buffer));

        // Determine output length
        size_t kmac_out_len = (kmac_flags[i] == CF_KMAC_XOF128 || kmac_flags[i] == CF_KMAC_XOF256)
                                ? (kmac_flags[i] == CF_KMAC_XOF128 ? CF_KMAC_DEFAULT_OUTPUT_LEN_128: CF_KMAC_DEFAULT_OUTPUT_LEN_256) // just for testing, KMAC-XOF doesnt have a fixed length
                                : (kmac_flags[i] == CF_KMAC128 ? CF_KMAC_DEFAULT_OUTPUT_LEN_128: CF_KMAC_DEFAULT_OUTPUT_LEN_256);

        status = CF_KDF_Expand(&ctx, dk_buffer, kmac_out_len);
        if (status != CF_SUCCESS) {
            printf("CF_KDF_Expand failed for %s, error status: %u\n", CF_KDF_GetFullName(&ctx), status);
            CF_KDFOpts_Reset(&ctxOpts);
            CF_KDF_Reset(&ctx);
            continue;
        }

        printf("%s DK: ", CF_KDF_GetFullName(&ctx));
        DEMO_print_hex(dk_buffer, kmac_out_len);
        printf("\n");

        CF_KDFOpts_Reset(&ctxOpts);
        CF_KDF_Reset(&ctx);
    }
}


#endif // ENABLE_TESTS