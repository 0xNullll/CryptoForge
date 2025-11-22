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
        EVP_STATUS status = ll_HMAC_Init(&hmac_ctx, md, key, key_len);
        if (status != EVP_OK) { 
            printf("ll_HMAC_Init failed for %s\n", EVP_HashName(hmac_ctx.md)); 
            continue; 
        }

        status = ll_HMAC_Update(&hmac_ctx, input, input_len);
        if (status != EVP_OK) { 
            printf("ll_HMAC_Update failed for %s\n", EVP_HashName(hmac_ctx.md)); 
            ll_HMAC_Free(&hmac_ctx); 
            continue; 
        }

        size_t out_len = hmac_ctx.out_len;
        status = ll_HMAC_Final(&hmac_ctx, digest, out_len);
        if (status != EVP_OK) { 
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

#endif // ENABLE_TESTS && ENABLE_HMAC