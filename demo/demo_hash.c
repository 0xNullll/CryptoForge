#include "../config/demo_config.h"

#if ENABLE_TESTS

TC_API void DEMO_EVP_test_MD(const EVP_MD *md, const uint8_t *data, size_t len, size_t outlen) {
    if (outlen <= 0) return;

    uint8_t *digest = malloc(outlen);
    if (!digest) {
        printf("%u: failed to allocate digest buffer\n", md->id);
        return;
    }
    SECURE_ZERO(digest, outlen);

    void *ctx = malloc(md->ctx_size);
    if (!ctx) {
        printf("%u: failed to allocate context\n", md->id);
        free(digest);
        return;
    }

    if (!md->hash_init_fn(ctx)) {
        printf("%u init failed\n", md->id);
        free(ctx);
        free(digest);
        return;
    }

    if (!md->hash_update_fn(ctx, data, len)) {
        printf("%u update failed\n", md->id);
        free(ctx);
        free(digest);
        return;
    }

    if (!md->hash_final_fn(ctx, digest, md->digest_size)) {
        printf("%u final failed\n", md->id);
        free(ctx);
        free(digest);
        return;
    }

    // If the algorithm supports squeezing (SHA3 / SHAKE), use requested outlen
    if (md->hash_squeeze_fn) {
        if (!md->hash_squeeze_fn(ctx, digest, outlen)) {
            printf("%u squeeze failed\n", md->id);
            free(ctx);
            free(digest);
            return;
        }
    }

    printf("%u digest: ", md->id);
    for (size_t i = 0; i < outlen; i++)
        printf("%02x", digest[i]);
    printf("\n");

    free(ctx);
    free(digest);
}

#endif // ENABLE_TESTS
