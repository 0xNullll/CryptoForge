#include "../../src/internal/config/test_config.h"

#if ENABLE_TESTS

// ============================
// Helpers
// ============================
static void do_kdf_init_test(const CF_KDF *kdf, const CF_KDF_OPTS *opts, uint8_t *ikm, size_t ikm_len, uint32_t subflags) {
    CF_STATUS st;
    CF_KDF_CTX ctx = {0};

    st = CF_KDF_Init(&ctx, kdf, opts, ikm, ikm_len, subflags);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(ctx.kdf_ctx != NULL);

    st = CF_KDF_Reset(&ctx);
    CF_ASSERT(st == CF_SUCCESS);
}

static void do_kdf_extract_expand_test(CF_KDF_CTX *ctx, uint32_t subflags) {
    CF_STATUS st;
    uint8_t derived[CF_MAX_DEFAULT_HASH_BLOCK_SIZE * 2] = {0};
    uint8_t dummy_salt[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

    ctx->subflags = subflags;

    // Extract test
    st = CF_KDF_Extract(ctx, dummy_salt, sizeof(dummy_salt));
    CF_ASSERT(st == CF_SUCCESS);

    // Expand test
    st = CF_KDF_Expand(ctx, derived, CF_MAX_DEFAULT_HASH_BLOCK_SIZE);
    CF_ASSERT(st == CF_SUCCESS);

    // Expand again test
    st = CF_KDF_Expand(ctx, derived + CF_MAX_DEFAULT_HASH_BLOCK_SIZE, CF_MAX_DEFAULT_HASH_BLOCK_SIZE);
    CF_ASSERT(st == CF_SUCCESS);
}

static void do_kdf_clone_test(CF_KDF_CTX *ctx) {
    CF_STATUS st;
    CF_KDF_CTX clone = {0};

    st = CF_KDF_CloneCtx(&clone, ctx);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(clone.kdf_ctx != NULL);

    CF_KDF_Reset(&clone);
}

static void do_kdf_opts_test(void) {
    CF_STATUS st;
    CF_KDF_OPTS opts = {0};
    uint8_t info[4] = {0x01,0x02,0x03,0x04};
    uint8_t custom[4] = {0x05,0x06,0x07,0x08};

    st = CF_KDFOpts_Init(&opts, info, sizeof(info), custom, sizeof(custom), 1000);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(opts.magic == CF_CTX_MAGIC);

    CF_KDF_OPTS *clone = CF_KDFOpts_CloneCtxAlloc(&opts, &st);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(clone != NULL);

    st = CF_KDFOpts_Reset(&opts);
    CF_ASSERT(st == CF_SUCCESS);

    st = CF_KDFOpts_Free(&clone);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(clone == NULL);
}

static void do_kdf_compute_test(const CF_KDF *kdf, const CF_KDF_OPTS *opts, uint32_t subflags) {
    uint8_t ikm[16] = {0};
    uint8_t salt[8] = {0};
    uint8_t derived[32] = {0};
    CF_STATUS st;

    st = CF_KDF_Compute(kdf, ikm, sizeof(ikm), salt, sizeof(salt),
                        derived, sizeof(derived), opts, subflags);
    CF_ASSERT(st == CF_SUCCESS);
}

// ============================
// Smoke-test entry
// ============================
void cf_kdf_api_test(void) {
#if ENABLE_TESTS_VERBOSE
    printf("[*] KDF API smoke-test starting...\n");
#else
    printf("KDF API tests:\n");
#endif

    uint8_t ikm[CF_MAX_DEFAULT_DIGEST_SIZE] = {0};

    uint32_t kdf_flags[] = { CF_HKDF, CF_PBKDF2, CF_KMAC_XOF };
    size_t num_kdfs = sizeof(kdf_flags) / sizeof(kdf_flags[0]);

    uint32_t non_xof_hashes[] = {
        CF_MD5, CF_SHA1, CF_SHA224, CF_SHA256, CF_SHA384, CF_SHA512,
        CF_SHA512_224, CF_SHA512_256, CF_SHA3_224, CF_SHA3_256, CF_SHA3_512
    };
    size_t num_non_xof = sizeof(non_xof_hashes) / sizeof(non_xof_hashes[0]);

    uint32_t kmac_xof_subflags[] = { CF_KMAC_XOF128, CF_KMAC_XOF256 };
    size_t num_kmac_xof = sizeof(kmac_xof_subflags) / sizeof(kmac_xof_subflags[0]);

    for (size_t i = 0; i < num_kdfs; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(kdf_flags[i]);
        CF_ASSERT(kdf != NULL);

        uint32_t *subflags = NULL;
        size_t n_subflags = 0;
        uint32_t tmp = 0;

        if (CF_KDF_IS_HKDF(kdf->id) || CF_KDF_IS_PBKDF2(kdf->id)) {
            subflags = non_xof_hashes;
            n_subflags = num_non_xof;
        } else if (CF_KDF_IS_KMAC_XOF(kdf->id)) {
            subflags = kmac_xof_subflags;
            n_subflags = num_kmac_xof;
        } else {
            subflags = &tmp;
            n_subflags = 1;
        }

        for (size_t j = 0; j < n_subflags; j++) {
            CF_STATUS st;

            CF_KDF_OPTS opts = {0};
            CF_KDF_OPTS *p_opts = NULL;

            if (CF_MAC_IS_HMAC(kdf->id)) {
                uint8_t info[4] = {0x01,0x02,0x03,0x04};
                st = CF_KDFOpts_Init(&opts, info, sizeof(info), NULL, 0, 0);
                CF_ASSERT(st == CF_SUCCESS);
                p_opts = &opts;             
            } else if (CF_KDF_IS_KMAC_XOF(kdf->id)) {
                // Optional customization (S)
                uint8_t S[4] = {0x01,0x02,0x03,0x04};
                st = CF_KDFOpts_Init(&opts, NULL, 0, S, sizeof(S), 0);
                CF_ASSERT(st == CF_SUCCESS);
                p_opts = &opts;
            } else if (CF_KDF_IS_PBKDF2(kdf->id)) {
                st = CF_KDFOpts_Init(&opts, NULL, 0, NULL, 0, 100);
                CF_ASSERT(st == CF_SUCCESS);
                p_opts = &opts;        
            }

            // Init test
            do_kdf_init_test(kdf, p_opts, ikm, sizeof(ikm), subflags[j]);

            // Alloc context
            st = CF_SUCCESS;
            CF_KDF_CTX *ctx = CF_KDF_InitAlloc(kdf, p_opts, ikm, sizeof(ikm), subflags[j], &st);
            CF_ASSERT(ctx != NULL && st == CF_SUCCESS);

            // Extract / Expand
            do_kdf_extract_expand_test(ctx, subflags[j]);

            // Clone
            do_kdf_clone_test(ctx);

            // One-shot compute
            do_kdf_compute_test(kdf, p_opts, subflags[j]);

#if ENABLE_TESTS_VERBOSE
            printf("[*] Passed smoke-test for KDF %s\n", CF_KDF_GetFullName(ctx));
#else
            printf("  %-20s  passed\n", CF_KDF_GetFullName(ctx));
#endif

            CF_STATUS fr = CF_KDF_Free(&ctx);
            CF_ASSERT(fr == CF_SUCCESS);
            CF_ASSERT(ctx == NULL);

            if (p_opts) CF_KDFOpts_Free(&p_opts);
        }
    }

    do_kdf_opts_test();

#if ENABLE_TESTS_VERBOSE
    printf("[*] KDF API smoke-test completed successfully.\n");
#endif
}

#endif // ENABLE_TESTS