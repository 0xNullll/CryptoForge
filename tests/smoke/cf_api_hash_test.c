#include "../../src/CryptoForge/include/config/test_config.h"

#if ENABLE_TESTS

// ============================
// Placeholder helpers
// ============================
static void do_hash_init_test(const CF_HASH *hash) {
    CF_STATUS st;
    CF_HASH_CTX ctx = {0};

    st = CF_Hash_Init(&ctx, hash, NULL);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(ctx.digest_ctx != NULL);

    // Cleanup
    st = CF_Hash_Reset(&ctx);
    CF_ASSERT(st == CF_SUCCESS);
}

static void do_hash_update_test(CF_HASH_CTX *ctx) {
    uint8_t dummy_data[CF_MAX_DEFAULT_HASH_BLOCK_SIZE] = {0};
    CF_STATUS st;

    // Test update with empty data
    st = CF_Hash_Update(ctx, dummy_data, 0);
    CF_ASSERT(st == CF_SUCCESS);

    // Test update with some bytes
    dummy_data[0] = 0xAA;
    st = CF_Hash_Update(ctx, dummy_data, sizeof(dummy_data));
    CF_ASSERT(st == CF_SUCCESS);
}

static void do_hash_final_test(CF_HASH_CTX *ctx) {
    uint8_t digest[CF_MAX_DEFAULT_DIGEST_SIZE] = {0};
    CF_STATUS st;

    st = CF_Hash_Final(ctx, digest, ctx->hash->digest_size);
    CF_ASSERT(st == CF_SUCCESS);

    // Re-finalize to check error returns for non-XOF hashes
    st = CF_Hash_Final(ctx, digest, ctx->hash->digest_size);
    if (!(ctx->hash->id & CF_CAT_XOF)) {
        CF_ASSERT(st != CF_SUCCESS);
    }
}

static void do_hash_compute_test(const CF_HASH *hash) {
    uint8_t dummy_data[CF_MAX_DEFAULT_HASH_BLOCK_SIZE] = {0};
    uint8_t digest[CF_MAX_DEFAULT_DIGEST_SIZE] = {0};
    CF_STATUS st;

    // One-shot hash compute
    st = CF_Hash_Compute(hash, dummy_data, sizeof(dummy_data),
                         digest, hash->digest_size, NULL);
    CF_ASSERT(st == CF_SUCCESS);

    // Fixed-length compute (non-XOF)
    if (!(hash->id & CF_CAT_XOF)) {
        st = CF_Hash_ComputeFixed(hash, dummy_data, sizeof(dummy_data), digest);
        CF_ASSERT(st == CF_SUCCESS);
    }
}

static void do_hash_clone_test(CF_HASH_CTX *ctx) {
    CF_STATUS st;
    CF_HASH_CTX clone = {0};

    st = CF_Hash_CloneCtx(&clone, ctx);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(clone.digest_ctx != NULL);

    CF_Hash_Reset(&clone);
}

static void do_hash_opts_test(void) {
    CF_STATUS st;
    CF_HASH_OPTS opts = {0};
    uint8_t N[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t S[4] = {0x05, 0x06, 0x07, 0x08};

    // Init opts
    st = CF_HashOpts_Init(&opts, N, sizeof(N), S, sizeof(S));
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(opts.magic == CF_CTX_MAGIC);

    // Clone alloc
    CF_HASH_OPTS *clone = CF_HashOpts_CloneAlloc(&opts, &st);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(clone != NULL);

    // Reset opts
    st = CF_HashOpts_Reset(&opts);
    CF_ASSERT(st == CF_SUCCESS);

    // Reset clone opts
    st = CF_HashOpts_Free(&clone);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(clone == NULL);
}

void cf_hash_api_test(void) {
    printf("[*] Hash API smoke-test starting...\n");

    // Iterate over all hash algorithms
    uint32_t algo_flags[] = {
        CF_MD5, CF_SHA1, CF_SHA224, CF_SHA256, CF_SHA384, CF_SHA512,
        CF_SHA512_224, CF_SHA512_256, CF_SHA3_224, CF_SHA3_256,
        CF_SHA3_384, CF_SHA3_512, CF_SHAKE128, CF_SHAKE256,
        CF_RAWSHAKE128, CF_RAWSHAKE256, CF_CSHAKE128, CF_CSHAKE256
    };

    size_t num_algos = sizeof(algo_flags) / sizeof(algo_flags[0]);

    for (size_t i = 0; i < num_algos; i++) {
        const CF_HASH *hash = CF_Hash_GetByFlag(algo_flags[i]);
        CF_ASSERT(hash != NULL);

        // Init test
        do_hash_init_test(hash);

        // Alloc context test
        CF_STATUS st = CF_SUCCESS;
        CF_HASH_CTX *ctx = CF_Hash_InitAlloc(hash, NULL, &st);
        CF_ASSERT(ctx != NULL && st == CF_SUCCESS);

        // Update / final tests
        do_hash_update_test(ctx);
        do_hash_final_test(ctx);

        // Compute / one-shot test
        do_hash_compute_test(hash);

        // Clone context test
        do_hash_clone_test(ctx);

        // Free
        CF_STATUS fr = CF_Hash_Free(&ctx);
        CF_ASSERT(fr == CF_SUCCESS);
        CF_ASSERT(ctx == NULL);

        printf("[*] Passed smoke-test for hash %s\n", CF_Hash_GetName(hash));
    }

    // Test options API
    do_hash_opts_test();

    printf("[*] Hash API smoke-test completed successfully.\n");
}

#endif // ENABLE_TESTS