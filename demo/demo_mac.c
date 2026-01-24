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
        CF_STATUS status = ll_HMAC_Init(&hmac_ctx, md, key, key_len);
        if (status != CF_SUCCESS) { 
            printf("ll_HMAC_Init failed for %s\n", EVP_HashGetName(hmac_ctx.md)); 
            continue; 
        }

        status = ll_HMAC_Update(&hmac_ctx, input, input_len);
        if (status != CF_SUCCESS) { 
            printf("ll_HMAC_Update failed for %s\n", EVP_HashGetName(hmac_ctx.md)); 
            ll_HMAC_Free(&hmac_ctx); 
            continue; 
        }

        size_t out_len = hmac_ctx.out_len;
        status = ll_HMAC_Final(&hmac_ctx, digest, out_len);
        if (status != CF_SUCCESS) { 
            printf("ll_HMAC_Final failed for %s\n", EVP_HashGetName(hmac_ctx.md)); 
            ll_HMAC_Free(&hmac_ctx); 
            continue; 
        }

        printf("%s HMAC: ", EVP_HashGetName(hmac_ctx.md));
        DEMO_print_hex(digest, out_len);
        printf("\n");

        ll_HMAC_Free(&hmac_ctx);
    }
}

// Test all KMAC variants
void test_all_kmacs(
    const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len,
    const uint8_t *S, size_t S_len) {
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
        CF_STATUS status = ll_KMAC_Init(&kmac_ctx, key, key_len, S, S_len, kmac_types[i]);
        if (status != CF_SUCCESS) {
            printf("ll_KMAC_Init failed: error code = %u\n", status);
            continue;
        }

        // Absorb input
        status = ll_KMAC_Update(&kmac_ctx, input, input_len);
        if (status != CF_SUCCESS) {
            printf("ll_KMAC_Update failed: error code = %u\n", status);
            ll_KMAC_Free(&kmac_ctx);
            continue;
        }

        // Finalize
        status = ll_KMAC_Final(&kmac_ctx, digest, out_len);
        if (status != CF_SUCCESS) {
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


void test_all_gmacs(void) {
    uint8_t aad[AES_BLOCK_SIZE] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    uint8_t iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    // uint8_t iv[12] = {
    //     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    //     0x08, 0x09, 0x0a, 0x0b
    // };

    uint8_t tag[AES_BLOCK_SIZE];

    AES_KEY kctx;
    ll_GMAC_CTX gctx;

    // ---------------- AES-128 ----------------
    uint8_t key128[AES_BLOCK_SIZE] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    uint8_t expected_tag128[AES_BLOCK_SIZE] = {
        0x68, 0x16, 0xf5, 0x8a, 0x62, 0xc8, 0xf5, 0xff,
        0xbc, 0x2f, 0xf0, 0x92, 0xee, 0x29, 0xa1, 0x12
    };

    if (!ll_AES_SetEncryptKey(&kctx, key128, sizeof(key128))) { 
        printf("AES-128 init failed\n"); 
        return; 
    }

    if (ll_GMAC_Init(&gctx, &kctx, iv, sizeof(iv)) != CF_SUCCESS) {
        printf("GMAC init failed\n");
        return;
    }

    if (ll_GMAC_Update(&gctx, aad, sizeof(aad)) != CF_SUCCESS) {
        printf("GMAC update failed\n");
        ll_GMAC_Free(&gctx);
        return;
    }

    if (ll_GMAC_Final(&gctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("GMAC finalize failed\n");
        ll_GMAC_Free(&gctx);
        return;
    }

    printf("AES-128 GMAC Test:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag128, sizeof(expected_tag128));
    if (ll_GMAC_Verify(&gctx, expected_tag128, sizeof(expected_tag128)) != CF_SUCCESS) {
        printf("GMAC tag verification failed\n");
    } else {
        printf("GMAC tag verified successfully\n");
    }

    ll_GMAC_Free(&gctx);

    // ---------------- AES-192 ----------------
    uint8_t key192[24] = {
        0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
        0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
        0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
    };

    uint8_t expected_tag192[AES_BLOCK_SIZE] = {
        0xc4, 0x89, 0xfb, 0xf4, 0xf6, 0x0e, 0x70, 0x68,
        0xf0, 0x9d, 0x4f, 0x0e, 0xb5, 0x58, 0xe1, 0xb3
    };

    if (!ll_AES_SetEncryptKey(&kctx, key192, sizeof(key192))) { 
        printf("AES-192 init failed\n"); 
        return; 
    }

    if (ll_GMAC_Init(&gctx, &kctx, iv, sizeof(iv)) != CF_SUCCESS) {
        printf("GMAC init failed\n");
        return;
    }

    if (ll_GMAC_Update(&gctx, aad, sizeof(aad)) != CF_SUCCESS) {
        printf("GMAC update failed\n");
        ll_GMAC_Free(&gctx);
        return;
    }

    if (ll_GMAC_Final(&gctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("GMAC finalize failed\n");
        ll_GMAC_Free(&gctx);
        return;
    }

    printf("AES-192 GMAC Test:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag192, sizeof(expected_tag192));
    if (ll_GMAC_Verify(&gctx, expected_tag192, sizeof(expected_tag192)) != CF_SUCCESS) {
        printf("GMAC tag verification failed\n");
    } else {
        printf("GMAC tag verified successfully\n");
    }

    ll_GMAC_Free(&gctx);

    // ---------------- AES-256 ----------------
    uint8_t key256[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    
    uint8_t expected_tag256[AES_BLOCK_SIZE] = {
        0xf6, 0xd9, 0x36, 0x9d, 0x0f, 0xec, 0xd0, 0x30,
        0xa1, 0x2d, 0x24, 0x7e, 0x2c, 0xca, 0x3d, 0x3d
    };

    if (!ll_AES_SetEncryptKey(&kctx, key256, sizeof(key256))) { 
        printf("AES-256 init failed\n"); 
        return; 
    }

    if (ll_GMAC_Init(&gctx, &kctx, iv, sizeof(iv)) != CF_SUCCESS) {
        printf("GMAC init failed\n");
        return;
    }

    if (ll_GMAC_Update(&gctx, aad, sizeof(aad)) != CF_SUCCESS) {
        printf("GMAC update failed\n");
        ll_GMAC_Free(&gctx);
        return;
    }

    if (ll_GMAC_Final(&gctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("GMAC finalize failed\n");
        ll_GMAC_Free(&gctx);
        return;
    }

    printf("AES-256 GMAC Test:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag256, sizeof(expected_tag256));
    if (ll_GMAC_Verify(&gctx, expected_tag256, sizeof(expected_tag256)) != CF_SUCCESS) {
        printf("GMAC tag verification failed\n");
    } else {
        printf("GMAC tag verified successfully\n");
    }

    ll_GMAC_Free(&gctx);
}

#endif // ENABLE_TESTS