#include "../config/demo_config.h"

#if ENABLE_TESTS

void test_all_hashes(const uint8_t *input, size_t input_len) {
    uint8_t digest[EVP_MAX_DEFAULT_DIGEST_SIZE];

    // List of hash flags to test
    uint32_t hash_flags[] = {
        EVP_MD5,
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
        EVP_SHA3_512,
        EVP_SHAKE128,
        EVP_SHAKE256
    };

    size_t num_hashes = sizeof(hash_flags) / sizeof(hash_flags[0]);

    for (size_t i = 0; i < num_hashes; i++) {
        const EVP_MD *md = EVP_MDByFlag(hash_flags[i]);
        if (!md) {
            printf("Unknown hash flag %u\n", hash_flags[i]);
            continue;
        }

        void *ctx = malloc(md->ctx_size);
        if (!ctx) {
            printf("%s: failed to allocate context\n", EVP_HashName(md));
            continue;
        }

        if (!md->hash_init_fn(ctx, NULL)) {
            printf("%s init failed\n", EVP_HashName(md));
            free(ctx);
            continue;
        }

        if (!md->hash_update_fn(ctx, input, input_len)) {
            printf("%s update failed\n", EVP_HashName(md));
            free(ctx);
            continue;
        }

        size_t out_len = md->digest_size != 0 ? md->digest_size : md->default_out_len;

        if (!md->hash_final_fn(ctx, digest, md->digest_size)) {
            printf("%s final failed\n", EVP_HashName(md));
            free(ctx);
            continue;
        }

        if (md->hash_squeeze_fn) {
            if (!md->hash_squeeze_fn(ctx, digest, out_len)) {
                printf("%s squeeze failed\n", EVP_HashName(md));
                free(ctx);
                continue;
            }
        }

        printf("%s digest: ", EVP_HashName(md));
        DEMO_print_hex(digest, out_len);
        
        free(ctx);
    }
}

#endif // ENABLE_TESTS
