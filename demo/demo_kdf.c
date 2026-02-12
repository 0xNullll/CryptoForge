#include "../include/config/demo_config.h"

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
        const CF_MD *md = CF_MD_GetByFlag(hash_flags[i]);
        if (!md) {
            printf("Unknown hash flag %u\n", hash_flags[i]);
            continue;
        }

        ll_HKDF_CTX hkdf_ctx;
        SECURE_ZERO(&hkdf_ctx, sizeof(hkdf_ctx));

        CF_STATUS status = ll_HKDF_Init(&hkdf_ctx, md, info, info_len);
        if (status != CF_SUCCESS) {
            printf("ll_HKDF_Init failed for %s\n", CF_Hash_GetName(md));
            continue;
        }

        status = ll_HKDF_Extract(&hkdf_ctx, salt, salt_len, ikm, ikm_len);
        if (status != CF_SUCCESS) {
            printf("ll_HKDF_Extract failed for %s\n", CF_Hash_GetName(md));
            ll_HKDF_Reset(&hkdf_ctx);
            continue;
        }

        status = ll_HKDF_Expand(&hkdf_ctx, okm, okm_len, NULL, 0);
        if (status != CF_SUCCESS) {
            printf("ll_HKDF_Expand failed for %s\n", CF_Hash_GetName(md));
            ll_HKDF_Reset(&hkdf_ctx);
            continue;
        }

        printf("%s HKDF OKM: ", CF_Hash_GetName(md));
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
        const CF_MD *md = CF_MD_GetByFlag(hash_flags[i]);
        if (!md) {
            printf("Unknown hash flag %u\n", hash_flags[i]);
            continue;
        }

        ll_PBKDF2_CTX ctx = {0};

        CF_STATUS status = ll_PBKDF2_Init(&ctx, md, password, password_len);
        if (status != CF_SUCCESS) {
            printf("ll_PBKDF2_Init failed for %s\n", CF_Hash_GetName(md));
            continue;
        }

        status = ll_PBKDF2_Extract(&ctx, salt, salt_len);
        if (status != CF_SUCCESS) {
            printf("ll_PBKDF2_Extract failed for %s\n", CF_Hash_GetName(md));
            ll_PBKDF2_Reset(&ctx);
            continue;
        }

        SECURE_ZERO(dk_buffer, sizeof(dk_buffer));
        status = ll_PBKDF2_Expand(&ctx, dk_buffer, dk_len, iteration_count);
        if (status != CF_SUCCESS) {
            printf("ll_PBKDF2_Expand failed for %s, error status: %u\n", CF_Hash_GetName(md), status);
            ll_PBKDF2_Reset(&ctx);
            continue;
        }

        printf("%s PBKDF2 DK: ", CF_Hash_GetName(md));
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

        status = CF_KDF_Init(&ctx, kdf, hkdf_ikm, sizeof(hkdf_ikm), &ctxOpts, hash_flags[i]);
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

        status = CF_KDF_Init(&ctx, kdf, pbkdf2_password, sizeof(pbkdf2_password), &ctxOpts, hash_flags[i]);
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
}


#endif // ENABLE_TESTS