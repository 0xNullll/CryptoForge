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

        ll_PBKDF2_CTX ctx;
        SECURE_ZERO(&ctx, sizeof(ctx));

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

#endif // ENABLE_TESTS