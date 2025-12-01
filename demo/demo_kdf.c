#include "../config/demo_config.h"

#if ENABLE_TESTS

void test_all_hkdfs(const uint8_t *info, size_t info_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    size_t okm_len) {
    uint8_t okm[LL_HKDF_MAX_OKM(EVP_MAX_DEFAULT_DIGEST_SIZE)];

    // List of hash flags to test
    uint32_t hash_flags[] = {
        EVP_MD5, // legacy: for testing not recomended for user use
        EVP_SHA1,
        EVP_SHA224,
        EVP_SHA256,
        EVP_SHA384,
        EVP_SHA512,
        EVP_SHA512_224,
        EVP_SHA512_256,
        EVP_SHA3_224,
        EVP_SHA3_256,
        EVP_SHA3_384,
        EVP_SHA3_512
    };

    size_t num_hashes = sizeof(hash_flags)/sizeof(hash_flags[0]);

    for (size_t i = 0; i < num_hashes; i++) {
        const EVP_MD *md = EVP_MDByFlag(hash_flags[i]);
        if (!md) {
            printf("Unknown hash flag %u\n", hash_flags[i]);
            continue;
        }

        ll_HKDF_CTX hkdf_ctx;
        CF_STATUS status = ll_HKDF_Init(&hkdf_ctx, md, info, info_len);
        if (status != CF_SUCCESS) {
            printf("ll_HKDF_Init failed for %s\n", EVP_HashName(md));
            continue;
        }

        status = ll_HKDF_Extract(&hkdf_ctx, salt, salt_len, ikm, ikm_len);
        if (status != CF_SUCCESS) {
            printf("ll_HKDF_Extract failed for %s\n", EVP_HashName(md));
            ll_HKDF_Free(&hkdf_ctx);
            continue;
        }

        status = ll_HKDF_Expand(&hkdf_ctx, okm, okm_len, NULL, 0);
        if (status != CF_SUCCESS) {
            printf("ll_HKDF_Expand failed for %s\n", EVP_HashName(md));
            ll_HKDF_Free(&hkdf_ctx);
            continue;
        }

        printf("%s HKDF OKM: ", EVP_HashName(md));
        DEMO_print_hex(okm, okm_len);
        printf("\n");

        ll_HKDF_Free(&hkdf_ctx);
    }
}

#endif // ENABLE_TESTS