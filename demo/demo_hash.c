#include "../config/demo_config.h"

#if ENABLE_TESTS

// =======================
// MD5 / MD-family demo
// =======================
TC_API void DEMO_md(const uint8_t *data, size_t len) {
    uint8_t digest[MD5_DIGEST_SIZE];
    if (!ll_md5(data, len, digest)) {
        printf("MD5 computation failed!\n");
    }
    printf("MD5:    ");
    DEMO_print_hex(digest, MD5_DIGEST_SIZE);
}

// =======================
// SHA1 / SHA2 demo
// =======================
TC_API void DEMO_sha(const uint8_t *data, size_t len) {
    // SHA1
    uint8_t digest1[SHA1_DIGEST_SIZE];
    if (!ll_sha1(data, len, digest1)) {
        printf("SHA1 computation failed!\n");
    }
    printf("SHA1:    ");
    DEMO_print_hex(digest1, SHA1_DIGEST_SIZE);

    // SHA224
    uint8_t digest224[SHA224_DIGEST_SIZE];
    if (!ll_sha224(data, len, digest224)) {
        printf("SHA224 computation failed!\n");
    }
    printf("SHA224:  ");
    DEMO_print_hex(digest224, SHA224_DIGEST_SIZE);

    // SHA256
    uint8_t digest256[SHA256_DIGEST_SIZE];
    if (!ll_sha256(data, len, digest256)) {
        printf("SHA256 computation failed!\n");
    }
    printf("SHA256:  ");
    DEMO_print_hex(digest256, SHA256_DIGEST_SIZE);

    // SHA384
    uint8_t digest384[SHA384_DIGEST_SIZE];
    if (!ll_sha384(data, len, digest384)) {
        printf("SHA384 computation failed!\n");
    }
    printf("SHA384:  ");
    DEMO_print_hex(digest384, SHA384_DIGEST_SIZE);

    // SHA512
    uint8_t digest512[SHA512_DIGEST_SIZE];
    if (!ll_sha512(data, len, digest512)) {
        printf("SHA512 computation failed!\n");
    }
    printf("SHA512:  ");
    DEMO_print_hex(digest512, SHA512_DIGEST_SIZE);

    // SHA512/224
    uint8_t digest512_224[SHA512_224_DIGEST_SIZE];
    if (!ll_sha512_224(data, len, digest512_224)) {
        printf("SHA512/224 computation failed!\n");
    }
    printf("SHA512/224: ");
    DEMO_print_hex(digest512_224, SHA512_224_DIGEST_SIZE);

    // SHA512/256
    uint8_t digest512_256[SHA512_256_DIGEST_SIZE];
    if (!ll_sha512_256(data, len, digest512_256)) {
        printf("SHA512/256 computation failed!\n");
    }
    printf("SHA512/256: ");
    DEMO_print_hex(digest512_256, SHA512_256_DIGEST_SIZE);
}

// =======================
// SHA3 / SHAKE demo
// =======================
TC_API void DEMO_sha3(const uint8_t *data, size_t len) {
    // SHA3-224
    uint8_t digest3_224[SHA3_224_DIGEST_SIZE];
    if (!ll_sha3_224(data, len, digest3_224)) {
        printf("SHA3-224 computation failed!\n");
    }
    printf("SHA3-224: ");
    DEMO_print_hex(digest3_224, SHA3_224_DIGEST_SIZE);

    // SHA3-256
    uint8_t digest3_256[SHA3_256_DIGEST_SIZE];
    if (!ll_sha3_256(data, len, digest3_256)) {
        printf("SHA3-256 computation failed!\n");
    }
    printf("SHA3-256: ");
    DEMO_print_hex(digest3_256, SHA3_256_DIGEST_SIZE);

    // SHA3-384
    uint8_t digest3_384[SHA3_384_DIGEST_SIZE];
    if (!ll_sha3_384(data, len, digest3_384)) {
        printf("SHA3-384 computation failed!\n");
    }
    printf("SHA3-384: ");
    DEMO_print_hex(digest3_384, SHA3_384_DIGEST_SIZE);

    // SHA3-512
    uint8_t digest3_512[SHA3_512_DIGEST_SIZE];
    if (!ll_sha3_512(data, len, digest3_512)) {
        printf("SHA3-512 computation failed!\n");
    }
    printf("SHA3-512: ");
    DEMO_print_hex(digest3_512, SHA3_512_DIGEST_SIZE);

    // SHAKE128 example
    size_t shake128_len = 32;
    uint8_t digest_shake128[shake128_len];
    if (!ll_shake128(data, len, digest_shake128, shake128_len)) {
        printf("SHAKE128 computation failed!\n");
    }
    printf("SHAKE128 (%zu bytes): ", shake128_len);
    DEMO_print_hex(digest_shake128, shake128_len);

    // SHAKE256 example
    size_t shake256_len = 64;
    uint8_t digest_shake256[shake256_len];
    if (!ll_shake256(data, len, digest_shake256, shake256_len)) {
        printf("SHAKE256 computation failed!\n");
    }
    printf("SHAKE256 (%zu bytes): ", shake256_len);
    DEMO_print_hex(digest_shake256, shake256_len);

    // RawSHAKE128 example
    size_t rawshake128_len = 32;
    uint8_t digest_rawshake128[rawshake128_len];
    if (!ll_rawshake128(data, len, digest_rawshake128, rawshake128_len)) {
        printf("RawSHAKE128 computation failed!\n");
    }
    printf("RawSHAKE128 (%zu bytes): ", rawshake128_len);
    DEMO_print_hex(digest_rawshake128, rawshake128_len);

    // RawSHAKE256 example
    size_t rawshake256_len = 64;
    uint8_t digest_rawshake256[rawshake256_len];
    if (!ll_rawshake256(data, len, digest_rawshake256, rawshake256_len)) {
        printf("RawSHAKE256 computation failed!\n");
    }
    printf("RawSHAKE256 (%zu bytes): ", rawshake256_len);
    DEMO_print_hex(digest_rawshake256, rawshake256_len);
}


TC_API void DEMO_EVP_test_MD(const EVP_MD *md, const uint8_t *data, size_t len, size_t outlen) {
    uint8_t *digest = malloc(outlen);
    if (!digest) {
        printf("%s: failed to allocate digest buffer\n", md->name);
        return;
    }
    memset(digest, 0, outlen);

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
