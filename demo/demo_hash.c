#include "../include/config/demo_config.h"

#if ENABLE_TESTS

void test_all_hashes(const uint8_t *input, size_t input_len, const CF_HASH_OPTS *opts) {
    uint8_t digest[CF_MAX_DEFAULT_DIGEST_SIZE];

    // List of hash flags to test
    uint32_t hash_flags[] = {
        CF_MD5,
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
        CF_SHA3_512,
        CF_SHAKE128,
        CF_SHAKE256,
        CF_CSHAKE128,
        CF_CSHAKE256
    };

    size_t num_hashes = sizeof(hash_flags) / sizeof(hash_flags[0]);

    for (size_t i = 0; i < num_hashes; i++) {
        const CF_HASH *hash = CF_Hash_GetByFlag(hash_flags[i]);
        if (!hash) {
            printf("Unknown hash flag %u\n", hash_flags[i]);
            continue;
        }

        void *ctx = malloc(hash->ctx_size);
        if (!ctx) {
            printf("%s: failed to allocate context\n", CF_Hash_GetName(hash));
            continue;
        }

        // Pass opts only for cSHAKE / XOF hashes
        const void *init_opts = NULL;
        if (hash_flags[i] == CF_CSHAKE128 || hash_flags[i] == CF_CSHAKE256) {
            init_opts = opts;
        }

        if (!hash->hash_init_fn(ctx, init_opts)) {
            printf("%s init failed\n", CF_Hash_GetName(hash));
            free(ctx);
            continue;
        }

        if (!hash->hash_update_fn(ctx, input, input_len)) {
            printf("%s update failed\n", CF_Hash_GetName(hash));
            free(ctx);
            continue;
        }

        size_t out_len = hash->digest_size != 0 ? hash->digest_size : hash->default_out_len;

        // Finalize hash
        if (!hash->hash_final_fn(ctx, digest)) {
            printf("%s final failed\n", CF_Hash_GetName(hash));
            free(ctx);
            continue;
        }

        // Optional squeeze for XOF hashes
        if (hash->hash_squeeze_fn) {
            if (!hash->hash_squeeze_fn(ctx, digest, out_len)) {
                printf("%s squeeze failed\n", CF_Hash_GetName(hash));
                free(ctx);
                continue;
            }
        }

        // Print digest
        printf("%s digest: ", CF_Hash_GetName(hash));
        DEMO_print_hex(digest, out_len);
        printf("\n");

        free(ctx);
    }
}

void test_all_hashes_high(const uint8_t *input, size_t input_len, const CF_HASH_OPTS *opts) {
    uint8_t digest[CF_MAX_DEFAULT_DIGEST_SIZE];

    uint32_t hash_flags[] = {
        CF_MD5,
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
        CF_SHA3_512,
        CF_SHAKE128,
        CF_SHAKE256,
        CF_CSHAKE128,
        CF_CSHAKE256
    };

    size_t num_hashes = sizeof(hash_flags) / sizeof(hash_flags[0]);

    for (size_t i = 0; i < num_hashes; i++) {

        const CF_HASH *hash = CF_Hash_GetByFlag(hash_flags[i]);
        if (!hash) {
            printf("Unknown hash flag %u\n", hash_flags[i]);
            continue;
        }

        size_t digest_len = hash->digest_size ? hash->digest_size
                                         : hash->default_out_len;

        CF_STATUS status;

        if (CF_IS_XOF(hash->id)) {
            // XOF and cSHAKE
            status = CF_Hash_Compute(
                hash,
                input,
                input_len,
                digest,
                digest_len,
                opts
            );
        } else {
            // normal fixed digest hash
            status = CF_Hash_ComputeFixed(
                hash,
                input,
                input_len,
                digest
            );
        }

        if (status != CF_SUCCESS) {
            printf("%s failed (status=%d)\n",
                   CF_Hash_GetName(hash),
                   status);
            continue;
        }

        printf("%s digest: ", CF_Hash_GetName(hash));
        DEMO_print_hex(digest, digest_len);
        printf("\n");

        CF_HASH_CTX test_copy_ctx = {0};
        CF_HASH_CTX test_copy_ctx2 = {0};

        status = CF_Hash_Init(&test_copy_ctx2, hash, opts);
        if (status != CF_SUCCESS) {
            printf("[FAIL] Init copying test failed\n");
        } else {
            printf("[PASS] init copying test succeeded\n");
        }

        status = CF_Hash_CloneCtx(&test_copy_ctx, &test_copy_ctx2);
        if (status != CF_SUCCESS) {
            printf("[FAIL] Copying test failed\n");
        } else {
            printf("[PASS] Copying test succeeded\n");
        }

        CF_Hash_Reset(&test_copy_ctx2);
        CF_Hash_Reset(&test_copy_ctx);
    }
}

#endif // ENABLE_TESTS