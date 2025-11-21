#include "../config/demo_config.h"

#if ENABLE_TESTS

TC_API void DEMO_EVP_test_MD(const EVP_MD *md, const uint8_t *data, size_t len, size_t outlen) {
    if (outlen <= 0) return;

    uint8_t *digest = malloc(outlen);
    if (!digest) {
        printf("%s: failed to allocate digest buffer\n", md->name);
        return;
    }
    SECURE_ZERO(digest, outlen);

    void *ctx = malloc(md->ctx_size);
    if (!ctx) {
        printf("%s: failed to allocate context\n", md->name);
        free(digest);
        return;
    }

    if (!md->hash_init_fn(ctx)) {
        printf("%s init failed\n", md->name);
        free(ctx);
        free(digest);
        return;
    }

    if (!md->hash_update_fn(ctx, data, len)) {
        printf("%s update failed\n", md->name);
        free(ctx);
        free(digest);
        return;
    }

    if (!md->hash_final_fn(ctx, digest, md->digest_size)) {
        printf("%s final failed\n", md->name);
        free(ctx);
        free(digest);
        return;
    }

    // If the algorithm supports squeezing (SHA3 / SHAKE), use requested outlen
    if (md->hash_squeeze_fn) {
        if (!md->hash_squeeze_fn(ctx, digest, outlen)) {
            printf("%s squeeze failed\n", md->name);
            free(ctx);
            free(digest);
            return;
        }
    }

    printf("%s digest: ", md->name);
    for (size_t i = 0; i < outlen; i++)
        printf("%02x", digest[i]);
    printf("\n");

    free(ctx);
    free(digest);
}

#endif // ENABLE_TESTS
