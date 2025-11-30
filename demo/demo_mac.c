#include "../config/demo_config.h"

#if ENABLE_TESTS

void test_all_hmacs(const uint8_t *key, size_t key_len, const uint8_t *input, size_t input_len) {
    uint8_t digest[EVP_MAX_DEFAULT_DIGEST_SIZE];

    // List of hash flags to test
    uint32_t hash_flags[] = {
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

        ll_HMAC_CTX hmac_ctx;
        TCLIB_STATUS status = ll_HMAC_Init(&hmac_ctx, md, key, key_len);
        if (status != TCLIB_SUCCESS) { 
            printf("ll_HMAC_Init failed for %s\n", EVP_HashName(hmac_ctx.md)); 
            continue; 
        }

        status = ll_HMAC_Update(&hmac_ctx, input, input_len);
        if (status != TCLIB_SUCCESS) { 
            printf("ll_HMAC_Update failed for %s\n", EVP_HashName(hmac_ctx.md)); 
            ll_HMAC_Free(&hmac_ctx); 
            continue; 
        }

        size_t out_len = hmac_ctx.out_len;
        status = ll_HMAC_Final(&hmac_ctx, digest, out_len);
        if (status != TCLIB_SUCCESS) { 
            printf("ll_HMAC_Final failed for %s\n", EVP_HashName(hmac_ctx.md)); 
            ll_HMAC_Free(&hmac_ctx); 
            continue; 
        }

        printf("%s HMAC: ", EVP_HashName(hmac_ctx.md));
        DEMO_print_hex(digest, out_len);
        printf("\n");

        ll_HMAC_Free(&hmac_ctx);
    }
}

// Test all KMAC variants
// Test all KMAC variants
void test_all_kmacs(
    const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len,
    const uint8_t *S, size_t S_len)
{
    uint8_t digest[EVP_MAX_DEFAULT_DIGEST_SIZE];

    // KMAC types to test
    ll_KMAC_TYPE kmac_types[] = {
        KMAC128,
        KMACXOF128,
        KMAC256,
        KMACXOF256
    };

    size_t num_kmacs = sizeof(kmac_types) / sizeof(kmac_types[0]);

    for (size_t i = 0; i < num_kmacs; i++) {
        ll_KMAC_CTX kmac_ctx;

        // Determine output length
        size_t out_len = (kmac_types[i] == KMACXOF128 || kmac_types[i] == KMACXOF256)
                            ? (kmac_types[i] == KMACXOF128 ? CSHAKE128_DEFAULT_OUT_LEN : CSHAKE256_DEFAULT_OUT_LEN)
                            : (kmac_types[i] == KMAC128 ? CSHAKE128_DEFAULT_OUT_LEN : CSHAKE256_DEFAULT_OUT_LEN);

        // Initialize
        TCLIB_STATUS status = ll_KMAC_Init(&kmac_ctx, key, key_len, S, S_len, kmac_types[i]);
        if (status != TCLIB_SUCCESS) {
            printf("ll_KMAC_Init failed: error code = %u\n", status);
            continue;
        }

        // Absorb input
        status = ll_KMAC_Update(&kmac_ctx, input, input_len);
        if (status != TCLIB_SUCCESS) {
            printf("ll_KMAC_Update failed: error code = %u\n", status);
            ll_KMAC_Free(&kmac_ctx);
            continue;
        }

        // Finalize
        status = ll_KMAC_Final(&kmac_ctx, digest, out_len);
        if (status != TCLIB_SUCCESS) {
            printf("ll_KMAC_Final failed: error code = %u\n", status);
            ll_KMAC_Free(&kmac_ctx);
            continue;
        }

        // Print result
        printf("%s: ", (kmac_types[i] == KMAC128) ? "KMAC128" :
                        (kmac_types[i] == KMACXOF128) ? "KMACXOF128" :
                        (kmac_types[i] == KMAC256) ? "KMAC256" :
                        "KMACXOF256");

        DEMO_print_hex(digest, kmac_ctx.out_len);
        printf("\n");

        ll_KMAC_Free(&kmac_ctx);
    }
}

#endif // ENABLE_TESTS && ENABLE_HMAC