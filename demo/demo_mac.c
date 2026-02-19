#include "../src/include/config/demo_config.h"

#if ENABLE_TESTS

void test_all_hmacs(const uint8_t *key, size_t key_len, const uint8_t *input, size_t input_len) {
    uint8_t digest[CF_MAX_DEFAULT_DIGEST_SIZE];

    // List of hash flags to test
    uint32_t hash_flags[] = {
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
        CF_SHA3_512
    };

    size_t num_hashes = sizeof(hash_flags)/sizeof(hash_flags[0]);

    for (size_t i = 0; i < num_hashes; i++) {
        const CF_HASH *hash = CF_Hash_GetByFlag(hash_flags[i]);
        if (!hash) { 
            printf("Unknown hash flag %u\n", hash_flags[i]); 
            continue; 
        }

        ll_HMAC_CTX hmac_ctx;
        SECURE_ZERO(&hmac_ctx, sizeof(hmac_ctx));

        CF_STATUS status = ll_HMAC_Init(&hmac_ctx, hash, key, key_len);
        if (status != CF_SUCCESS) { 
            printf("ll_HMAC_Init failed for %s\n", CF_Hash_GetName(hash)); 
            continue; 
        }

        status = ll_HMAC_Update(&hmac_ctx, input, input_len);
        if (status != CF_SUCCESS) { 
            printf("ll_HMAC_Update failed for %s\n", CF_Hash_GetName(hash)); 
            ll_HMAC_Reset(&hmac_ctx); 
            continue; 
        }

        size_t out_len = hmac_ctx.out_len;
        status = ll_HMAC_Final(&hmac_ctx, digest, out_len);
        if (status != CF_SUCCESS) { 
            printf("ll_HMAC_Final failed for %s\n", CF_Hash_GetName(hash)); 
            ll_HMAC_Reset(&hmac_ctx); 
            continue; 
        }

        printf("%s HMAC: ", CF_Hash_GetName(hash));
        DEMO_print_hex(digest, out_len);
        printf("\n");

        ll_HMAC_Reset(&hmac_ctx);
    }
}

// Test all KMAC variants
void test_all_kmacs(
    const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len,
    const uint8_t *S, size_t S_len) {
    uint8_t digest[CF_MAX_DEFAULT_DIGEST_SIZE * 2];

    // KMAC types to test
    LL_KMAC_TYPE kmac_types[] = {
        LL_KMAC128,
        LL_KMAC_XOF128,
        LL_KMAC256,
        LL_KMAC_XOF256
    };

    size_t num_kmacs = sizeof(kmac_types) / sizeof(kmac_types[0]);

    for (size_t i = 0; i < num_kmacs; i++) {
        ll_KMAC_CTX kmac_ctx;
        SECURE_ZERO(&kmac_ctx, sizeof(kmac_ctx));

        // Determine output length
        size_t out_len = (kmac_types[i] == LL_KMAC_XOF128 || kmac_types[i] == LL_KMAC_XOF256)
                            ? (kmac_types[i] == LL_KMAC_XOF128 ? LL_KMAC_DEFAULT_OUTPUT_LEN_128: LL_KMAC_DEFAULT_OUTPUT_LEN_256) // just for testing, KMAC-XOF doesnt have a fixed length
                            : (kmac_types[i] == LL_KMAC128 ? LL_KMAC_DEFAULT_OUTPUT_LEN_128: LL_KMAC_DEFAULT_OUTPUT_LEN_256);

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
            ll_KMAC_Reset(&kmac_ctx);
            continue;
        }

        // Finalize
        status = ll_KMAC_Final(&kmac_ctx, digest, out_len);
        if (status != CF_SUCCESS) {
            printf("ll_KMAC_Final failed: error code = %u\n", status);
            ll_KMAC_Reset(&kmac_ctx);
            continue;
        }

        // Print result
        printf("%s: ", (kmac_types[i] == LL_KMAC128) ? "LL_KMAC128" :
                        (kmac_types[i] == LL_KMAC_XOF128) ? "LL_KMAC_XOF128" :
                        (kmac_types[i] == LL_KMAC256) ? "LL_KMAC256" :
                        "LL_KMAC_XOF256");

        DEMO_print_hex(digest, out_len);
        printf("\n");

        ll_KMAC_Reset(&kmac_ctx);
    }
}

void test_all_kmacs_verify_array(const uint8_t *key, size_t key_len,
                                 const uint8_t *input, size_t input_len,
                                 const uint8_t *S, size_t S_len,
                                 const uint8_t *expected_digests[4],
                                 const size_t expected_digests_len[4]) {
    LL_KMAC_TYPE kmac_types[] = { LL_KMAC128, LL_KMAC_XOF128, LL_KMAC256, LL_KMAC_XOF256 };
    const char *kmac_names[] = { "LL_KMAC128", "LL_KMAC_XOF128", "LL_KMAC256", "LL_KMAC_XOF256" };
    size_t num_kmacs = sizeof(kmac_types) / sizeof(kmac_types[0]);

    for (size_t i = 0; i < num_kmacs; i++) {
        CF_STATUS status = ll_KMAC_Verify(key, key_len,
                                    input, input_len,
                                    S, S_len,
                                    expected_digests[i],
                                    expected_digests_len[i],
                                    kmac_types[i]);
        
        if (status == CF_SUCCESS) {
            printf("%s: PASS\n", kmac_names[i]);
        } else if (LL_KMAC_IS_XOF(kmac_types[i])) {
            printf("%s: SKIPPED (XOF verification not supported)\n", kmac_names[i]);
        } else {
            printf("%s: FAIL (status=%d)\n", kmac_names[i], status);
        }
    }
}

// all tests vectors for this function come from 'https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf'
void test_aes_cmac_fips800_38b(void) {
    uint8_t plain_text_1 = 0; // acts as an empty string

    uint8_t plain_text_2[AES_BLOCK_SIZE] = {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
    };

    uint8_t plain_text_3[20] = {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57
    };

    uint8_t plain_text_4[AES_BLOCK_SIZE * 4] = {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
        0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
        0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
        0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
    };

    uint8_t tag[AES_BLOCK_SIZE];

    ll_AES_KEY kctx;
    SECURE_ZERO(&kctx, sizeof(kctx));

    ll_CMAC_CTX cctx;
    SECURE_ZERO(&cctx, sizeof(cctx));

    // ---------------- AES-128 ----------------
    uint8_t key128[AES_BLOCK_SIZE] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    if (!ll_AES_SetEncryptKey(&kctx, key128, sizeof(key128))) { 
        printf("AES-128 init failed\n"); 
        return; 
    }

    // ---------------- Example 1  ----------------
    uint8_t expected_tag128_1[AES_BLOCK_SIZE] = {
        0xBB, 0x1D, 0x69, 0x29, 0xE9, 0x59, 0x37, 0x28,
        0x7F, 0xA3, 0x7D, 0x12, 0x9B, 0x75, 0x67, 0x46
    };

    if (ll_CMAC_Init(&cctx, &kctx) != CF_SUCCESS) {
        printf("CMAC init failed\n");
        return;
    }

    if (ll_CMAC_Update(&cctx, &plain_text_1, (size_t)plain_text_1) != CF_SUCCESS) {
        printf("CMAC update failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    printf("AES-128 CMAC Test 1, Empty String:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag128_1, sizeof(expected_tag128_1));
    if (ll_CMAC_Verify(&kctx, &plain_text_1 , (size_t)plain_text_1, expected_tag128_1, sizeof(expected_tag128_1)) != CF_SUCCESS) {
        printf("CMAC tag verification failed\n");
    } else {
        printf("CMAC tag verified successfully\n");
    }

    ll_CMAC_Reset(&cctx);

    printf("--------------------------------\n");

    // ---------------- Example 2  ----------------
    uint8_t expected_tag128_2[AES_BLOCK_SIZE] = {
        0x07, 0x0A, 0x16, 0xB4, 0x6B, 0x4D, 0x41, 0x44,
        0xF7, 0x9B, 0xDD, 0x9D, 0xD0, 0x4A, 0x28, 0x7C
    };

    if (ll_CMAC_Init(&cctx, &kctx) != CF_SUCCESS) {
        printf("CMAC init failed\n");
        return;
    }

    if (ll_CMAC_Update(&cctx, plain_text_2, sizeof(plain_text_2)) != CF_SUCCESS) {
        printf("CMAC update failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    printf("AES-128 CMAC Test 2, Full block plain text:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag128_2, sizeof(expected_tag128_2));
    if (ll_CMAC_Verify(&kctx, plain_text_2 , sizeof(plain_text_2), expected_tag128_2, sizeof(expected_tag128_2)) != CF_SUCCESS) {
        printf("CMAC tag verification failed\n");
    } else {
        printf("CMAC tag verified successfully\n");
    }

    ll_CMAC_Reset(&cctx);

    printf("--------------------------------\n");

    // ---------------- Example 3  ----------------
    uint8_t expected_tag128_3[AES_BLOCK_SIZE] = {
        0x7D, 0x85, 0x44, 0x9E, 0xA6, 0xEA, 0x19, 0xC8,
        0x23, 0xA7, 0xBF, 0x78, 0x83, 0x7D, 0xFA, 0xDE
    };

    if (ll_CMAC_Init(&cctx, &kctx) != CF_SUCCESS) {
        printf("CMAC init failed\n");
        return;
    }

    if (ll_CMAC_Update(&cctx, plain_text_3, sizeof(plain_text_3)) != CF_SUCCESS) {
        printf("CMAC update failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    printf("AES-128 CMAC Test 3, Full block plain text and 20 Mlen size:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag128_3, sizeof(expected_tag128_3));
    if (ll_CMAC_Verify(&kctx, plain_text_3 , sizeof(plain_text_3), expected_tag128_3, sizeof(expected_tag128_3)) != CF_SUCCESS) {
        printf("CMAC tag verification failed\n");
    } else {
        printf("CMAC tag verified successfully\n");
    }

    ll_CMAC_Reset(&cctx);

    printf("--------------------------------\n");

    // ---------------- Example 4  ----------------
    uint8_t expected_tag128_4[AES_BLOCK_SIZE] = {
        0x51, 0xF0, 0xBE, 0xBF, 0x7E, 0x3B, 0x9D, 0x92,
        0xFC, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3C, 0xFE
    };

    if (ll_CMAC_Init(&cctx, &kctx) != CF_SUCCESS) {
        printf("CMAC init failed\n");
        return;
    }

    if (ll_CMAC_Update(&cctx, plain_text_4, sizeof(plain_text_4)) != CF_SUCCESS) {
        printf("CMAC update failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    printf("AES-128 CMAC Test 4, 64 byte plain text:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag128_4, sizeof(expected_tag128_4));
    if (ll_CMAC_Verify(&kctx, plain_text_4 , sizeof(plain_text_4), expected_tag128_4, sizeof(expected_tag128_4)) != CF_SUCCESS) {
        printf("CMAC tag verification failed\n");
    } else {
        printf("CMAC tag verified successfully\n");
    }

    ll_AES_ClearKey(&kctx);
    ll_CMAC_Reset(&cctx);

    printf("--------------------------------\n");

    // ---------------- AES-192 ----------------
    uint8_t key192[24] = {
        0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
        0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
        0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
    };

    if (!ll_AES_SetEncryptKey(&kctx, key192, sizeof(key192))) { 
        printf("AES-192 init failed\n"); 
        return; 
    }

    // ---------------- Example 1  ----------------
    uint8_t expected_tag192_1[AES_BLOCK_SIZE] = {
        0xD1, 0x7D, 0xDF, 0x46, 0xAD, 0xAA, 0xCD, 0xE5,
        0x31, 0xCA, 0xC4, 0x83, 0xDE, 0x7A, 0x93, 0x67
    };

    if (ll_CMAC_Init(&cctx, &kctx) != CF_SUCCESS) {
        printf("CMAC init failed\n");
        return;
    }

    if (ll_CMAC_Update(&cctx, &plain_text_1, (size_t)plain_text_1) != CF_SUCCESS) {
        printf("CMAC update failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    printf("AES-192 CMAC Test 1, Empty String:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag192_1, sizeof(expected_tag192_1));
    if (ll_CMAC_Verify(&kctx, &plain_text_1 , (size_t)plain_text_1, expected_tag192_1, sizeof(expected_tag192_1)) != CF_SUCCESS) {
        printf("CMAC tag verification failed\n");
    } else {
        printf("CMAC tag verified successfully\n");
    }

    ll_CMAC_Reset(&cctx);

    printf("--------------------------------\n");

    // ---------------- Example 2  ----------------
    uint8_t expected_tag192_2[AES_BLOCK_SIZE] = {
        0x9E, 0x99, 0xA7, 0xBF, 0x31, 0xE7, 0x10, 0x90,
        0x06, 0x62, 0xF6, 0x5E, 0x61, 0x7C, 0x51, 0x84
    };

    if (ll_CMAC_Init(&cctx, &kctx) != CF_SUCCESS) {
        printf("CMAC init failed\n");
        return;
    }

    if (ll_CMAC_Update(&cctx, plain_text_2, sizeof(plain_text_2)) != CF_SUCCESS) {
        printf("CMAC update failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    printf("AES-192 CMAC Test 2, Full block plain text:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag192_2, sizeof(expected_tag192_2));
    if (ll_CMAC_Verify(&kctx, plain_text_2 , sizeof(plain_text_2), expected_tag192_2, sizeof(expected_tag192_2)) != CF_SUCCESS) {
        printf("CMAC tag verification failed\n");
    } else {
        printf("CMAC tag verified successfully\n");
    }

    ll_CMAC_Reset(&cctx);

    printf("--------------------------------\n");

    // ---------------- Example 3  ----------------
    uint8_t expected_tag192_3[AES_BLOCK_SIZE] = {
        0x3D, 0x75, 0xC1, 0x94, 0xED, 0x96, 0x07, 0x04,
        0x44, 0xA9, 0xFA, 0x7E, 0xC7, 0x40, 0xEC, 0xF8
    };

    if (ll_CMAC_Init(&cctx, &kctx) != CF_SUCCESS) {
        printf("CMAC init failed\n");
        return;
    }

    if (ll_CMAC_Update(&cctx, plain_text_3, sizeof(plain_text_3)) != CF_SUCCESS) {
        printf("CMAC update failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    printf("AES-192 CMAC Test 3, Full block plain text and 20 Mlen size:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag192_3, sizeof(expected_tag192_3));
    if (ll_CMAC_Verify(&kctx, plain_text_3 , sizeof(plain_text_3), expected_tag192_3, sizeof(expected_tag192_3)) != CF_SUCCESS) {
        printf("CMAC tag verification failed\n");
    } else {
        printf("CMAC tag verified successfully\n");
    }

    ll_CMAC_Reset(&cctx);

    printf("--------------------------------\n");

    // ---------------- Example 4  ----------------
    uint8_t expected_tag192_4[AES_BLOCK_SIZE] = {
        0xA1, 0xD5, 0xDF, 0x0E, 0xED, 0x79, 0x0F, 0x79,
        0x4D, 0x77, 0x58, 0x96, 0x59, 0xF3, 0x9A, 0x11
    };

    if (ll_CMAC_Init(&cctx, &kctx) != CF_SUCCESS) {
        printf("CMAC init failed\n");
        return;
    }

    if (ll_CMAC_Update(&cctx, plain_text_4, sizeof(plain_text_4)) != CF_SUCCESS) {
        printf("CMAC update failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    printf("AES-192 CMAC Test 4, 64 byte plain text:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag192_4, sizeof(expected_tag192_4));
    if (ll_CMAC_Verify(&kctx, plain_text_4 , sizeof(plain_text_4), expected_tag192_4, sizeof(expected_tag192_4)) != CF_SUCCESS) {
        printf("CMAC tag verification failed\n");
    } else {
        printf("CMAC tag verified successfully\n");
    }

    ll_AES_ClearKey(&kctx);
    ll_CMAC_Reset(&cctx);

    printf("--------------------------------\n");

    // ---------------- AES-256 ----------------
    uint8_t key256[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    if (!ll_AES_SetEncryptKey(&kctx, key256, sizeof(key256))) { 
        printf("AES-256 init failed\n"); 
        return; 
    }

    // ---------------- Example 1  ----------------
    uint8_t expected_tag256_1[AES_BLOCK_SIZE] = {
        0x02, 0x89, 0x62, 0xF6, 0x1B, 0x7B, 0xF8, 0x9E,
        0xFC, 0x6B, 0x55, 0x1F, 0x46, 0x67, 0xD9, 0x83
    };

    if (ll_CMAC_Init(&cctx, &kctx) != CF_SUCCESS) {
        printf("CMAC init failed\n");
        return;
    }

    if (ll_CMAC_Update(&cctx, &plain_text_1, (size_t)plain_text_1) != CF_SUCCESS) {
        printf("CMAC update failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    printf("AES-256 CMAC Test 1, Empty String:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag256_1, sizeof(expected_tag256_1));
    if (ll_CMAC_Verify(&kctx, &plain_text_1 , (size_t)plain_text_1, expected_tag256_1, sizeof(expected_tag256_1)) != CF_SUCCESS) {
        printf("CMAC tag verification failed\n");
    } else {
        printf("CMAC tag verified successfully\n");
    }

    ll_CMAC_Reset(&cctx);

    printf("--------------------------------\n");

    // ---------------- Example 2  ----------------
    uint8_t expected_tag256_2[AES_BLOCK_SIZE] = {
        0x28, 0xA7, 0x02, 0x3F, 0x45, 0x2E, 0x8F, 0x82,
        0xBD, 0x4B, 0xF2, 0x8D, 0x8C, 0x37, 0xC3, 0x5C
    };

    if (ll_CMAC_Init(&cctx, &kctx) != CF_SUCCESS) {
        printf("CMAC init failed\n");
        return;
    }

    if (ll_CMAC_Update(&cctx, plain_text_2, sizeof(plain_text_2)) != CF_SUCCESS) {
        printf("CMAC update failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    printf("AES-256 CMAC Test 2, Full block plain text:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag256_2, sizeof(expected_tag256_2));
    if (ll_CMAC_Verify(&kctx, plain_text_2 , sizeof(plain_text_2), expected_tag256_2, sizeof(expected_tag256_2)) != CF_SUCCESS) {
        printf("CMAC tag verification failed\n");
    } else {
        printf("CMAC tag verified successfully\n");
    }

    ll_CMAC_Reset(&cctx);

    printf("--------------------------------\n");

    // ---------------- Example 3  ----------------
    uint8_t expected_tag256_3[AES_BLOCK_SIZE] = {
        0x15, 0x67, 0x27, 0xDC, 0x08, 0x78, 0x94, 0x4A,
        0x02, 0x3C, 0x1F, 0xE0, 0x3B, 0xAD, 0x6D, 0x93
    };

    if (ll_CMAC_Init(&cctx, &kctx) != CF_SUCCESS) {
        printf("CMAC init failed\n");
        return;
    }

    if (ll_CMAC_Update(&cctx, plain_text_3, sizeof(plain_text_3)) != CF_SUCCESS) {
        printf("CMAC update failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    printf("AES-256 CMAC Test 3, Full block plain text and 20 Mlen size:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag256_3, sizeof(expected_tag256_3));
    if (ll_CMAC_Verify(&kctx, plain_text_3 , sizeof(plain_text_3), expected_tag256_3, sizeof(expected_tag256_3)) != CF_SUCCESS) {
        printf("CMAC tag verification failed\n");
    } else {
        printf("CMAC tag verified successfully\n");
    }

    ll_CMAC_Reset(&cctx);

    printf("--------------------------------\n");

    // ---------------- Example 4  ----------------
    uint8_t expected_tag256_4[AES_BLOCK_SIZE] = {
        0xE1, 0x99, 0x21, 0x90, 0x54, 0x9F, 0x6E, 0xD5,
        0x69, 0x6A, 0x2C, 0x05, 0x6C, 0x31, 0x54, 0x10
    };

    if (ll_CMAC_Init(&cctx, &kctx) != CF_SUCCESS) {
        printf("CMAC init failed\n");
        return;
    }

    if (ll_CMAC_Update(&cctx, plain_text_4, sizeof(plain_text_4)) != CF_SUCCESS) {
        printf("CMAC update failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Reset(&cctx);
        return;
    }

    printf("AES-256 CMAC Test 4, 64 byte plain text:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag256_4, sizeof(expected_tag256_4));
    if (ll_CMAC_Verify(&kctx, plain_text_4 , sizeof(plain_text_4), expected_tag256_4, sizeof(expected_tag256_4)) != CF_SUCCESS) {
        printf("CMAC tag verification failed\n");
    } else {
        printf("CMAC tag verified successfully\n");
    }

    ll_AES_ClearKey(&kctx);
    ll_CMAC_Reset(&cctx);
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

    ll_AES_KEY kctx;
    SECURE_ZERO(&kctx, sizeof(kctx));

    ll_GMAC_CTX gctx;
    SECURE_ZERO(&gctx, sizeof(gctx));

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
        ll_GMAC_Reset(&gctx);
        return;
    }

    if (ll_GMAC_Final(&gctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("GMAC finalize failed\n");
        ll_GMAC_Reset(&gctx);
        return;
    }

    printf("AES-128 GMAC Test:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag128, sizeof(expected_tag128));
    if (ll_GMAC_Verify(&kctx, iv, sizeof(iv), aad, sizeof(aad), expected_tag128, sizeof(expected_tag128)) != CF_SUCCESS) {
        printf("GMAC tag verification failed\n");
    } else {
        printf("GMAC tag verified successfully\n");
    }

    ll_AES_ClearKey(&kctx);
    ll_GMAC_Reset(&gctx);

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
        ll_GMAC_Reset(&gctx);
        return;
    }

    if (ll_GMAC_Final(&gctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("GMAC finalize failed\n");
        ll_GMAC_Reset(&gctx);
        return;
    }

    printf("AES-192 GMAC Test:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag192, sizeof(expected_tag192));
    if (ll_GMAC_Verify(&kctx, iv, sizeof(iv), aad, sizeof(aad), expected_tag192, sizeof(expected_tag192)) != CF_SUCCESS) {
        printf("GMAC tag verification failed\n");
    } else {
        printf("GMAC tag verified successfully\n");
    }

    ll_AES_ClearKey(&kctx);
    ll_GMAC_Reset(&gctx);

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
        ll_GMAC_Reset(&gctx);
        return;
    }

    if (ll_GMAC_Final(&gctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("GMAC finalize failed\n");
        ll_GMAC_Reset(&gctx);
        return;
    }

    printf("AES-256 GMAC Test:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag256, sizeof(expected_tag256));
    if (ll_GMAC_Verify(&kctx, iv, sizeof(iv), aad, sizeof(aad), expected_tag256, sizeof(expected_tag256)) != CF_SUCCESS) {
        printf("GMAC tag verification failed\n");
    } else {
        printf("GMAC tag verified successfully\n");
    }

    ll_AES_ClearKey(&kctx);
    ll_GMAC_Reset(&gctx);
}

void test_all_poly1305(void) {
    // Message (from hex)
    // uint8_t message[] = {
    //     0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
    //     0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f,
    //     0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65,
    //     0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f,
    //     0x75, 0x70
    // };

    char *message = "Cryptographic Forum Research Group";

    // // 32-byte Poly1305 key (r + s)
    uint8_t key[32] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,  // r
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b   // s
    };

    uint8_t expected_tag[16] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    };

    ll_POLY1305_CTX ctx = {0};
    uint8_t tag[LL_POLY1305_TAG_LEN] = {0};

    if (ll_POLY1305_Init(&ctx, key) != CF_SUCCESS) {
        printf("POLY-1305 Init failed\n"); return;
    }

    if (ll_POLY1305_Update(&ctx, (uint8_t *)message, strlen(message)) != CF_SUCCESS) {
        printf("POLY-1305 Update failed\n"); return;
    }

    if (ll_POLY1305_Final(&ctx, tag) != CF_SUCCESS) {
        printf("POLY-1305 Final failed\n"); return;
    }

    printf("POLY-1305 Raw Key Test:\n");
    printf("Tag: "); DEMO_print_hex(tag, sizeof(tag));
    printf("Expected Tag: "); DEMO_print_hex(expected_tag, sizeof(expected_tag));
    if (ll_POLY1305_Verify(key, (uint8_t *)message, strlen(message), expected_tag) != CF_SUCCESS) {
        printf("POLY-1305 tag verification failed\n");
    } else {
        printf("POLY-1305 tag verified successfully\n");
    }

    ll_POLY1305_Reset(&ctx);
}

// all tests vectors for this function come from 
// -  https://datatracker.ietf.org/doc/html/rfc4231#section-4
// - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
// - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMACXOF_samples.pdf
// - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
void test_all_macs_high(void) {
    uint8_t tag[CF_MAX_DEFAULT_DIGEST_SIZE];

    // List of MAC flags to test
    uint32_t mac_flags[] = {
        CF_HMAC,
        CF_KMAC_STD,
        CF_CMAC,
        CF_GMAC,
        CF_POLY1305
    };

    // List of hash flags to test
    uint32_t hash_flags[] = {
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
        CF_SHA3_512
    };

    size_t num_hashes = sizeof(hash_flags)/sizeof(hash_flags[0]);

    //
    // source: https://datatracker.ietf.org/doc/html/rfc4231#section-4
    //
    uint8_t test_vector_hmac_key[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b
    };
    size_t test_vector_hmac_key_len = sizeof(test_vector_hmac_key)/sizeof(test_vector_hmac_key[0]);

    uint8_t test_vector_hmac_data[] = {
        0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65
    };
    size_t test_vector_hmac_data_len = sizeof(test_vector_hmac_data)/sizeof(test_vector_hmac_data[0]);

    // HMAC execution path
    for (size_t i = 0; i < num_hashes; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(mac_flags[0]);
        if (!mac) { 
            printf("Unknown MAC flag %u\n", mac_flags[0]); 
            continue; 
        }

        CF_MAC_CTX mac_ctx = {0};

        CF_STATUS status = CF_MAC_Init(&mac_ctx, mac, NULL, test_vector_hmac_key, test_vector_hmac_key_len, hash_flags[i]);
        if (status != CF_SUCCESS) { 
            printf("CF_MAC_Init failed for MAC ID: %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            continue; 
        }

        status = CF_MAC_Update(&mac_ctx, test_vector_hmac_data, test_vector_hmac_data_len);
        if (status != CF_SUCCESS) { 
            printf("CF_MAC_Update failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            CF_MAC_Reset(&mac_ctx); 
            continue; 
        }

        size_t out_len = mac_ctx.tag_len;
        status = CF_MAC_Final(&mac_ctx, tag, out_len);
        if (status != CF_SUCCESS) { 
            printf("CF_MAC_Final failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            CF_MAC_Reset(&mac_ctx); 
            continue; 
        }

        printf("%s: ", CF_MAC_GetFullName(&mac_ctx));
        DEMO_print_hex(tag, out_len);
        printf("\n");

        CF_MAC_Reset(&mac_ctx);
    }

    // List of KMAC type flags to test
    uint32_t kmac_flags[] = {
        CF_KMAC128,
        CF_KMAC_XOF128,
        CF_KMAC256,
        CF_KMAC_XOF256
    };

    size_t num_kmac = sizeof(kmac_flags)/sizeof(kmac_flags[0]);

    // test vectors from:
    // - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
    // - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMACXOF_samples.pdf

    const uint8_t test_vector_kmac_key[32] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
    };

    static const uint8_t test_vector_kmac_input[200] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
        0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7
    };

    const char *test_vector_kmac_s_input =  "My Tagged Application";


    // KMAC-128 test vector
    static const uint8_t test_vector_kmac_128[] = {
        0x1F, 0x5B, 0x4E, 0x6C, 0xCA, 0x02, 0x20, 0x9E,
        0x0D, 0xCB, 0x5C, 0xA6, 0x35, 0xB8, 0x9A, 0x15,
        0xE2, 0x71, 0xEC, 0xC7, 0x60, 0x07, 0x1D, 0xFD,
        0x80, 0x5F, 0xAA, 0x38, 0xF9, 0x72, 0x92, 0x30
    };

    // KMAC XOF-128 test vector
    static const uint8_t test_vector_kmac_xof_128[] = {
        0x47, 0x02, 0x6C, 0x7C, 0xD7, 0x93, 0x08, 0x4A,
        0xA0, 0x28, 0x3C, 0x25, 0x3E, 0xF6, 0x58, 0x49,
        0x0C, 0x0D, 0xB6, 0x14, 0x38, 0xB8, 0x32, 0x6F,
        0xE9, 0xBD, 0xDF, 0x28, 0x1B, 0x83, 0xAE, 0x0F
    };

    // KMAC-256 test vector
    static const uint8_t test_vector_kmac_256[] = {
        0xB5, 0x86, 0x18, 0xF7, 0x1F, 0x92, 0xE1, 0xD5,
        0x6C, 0x1B, 0x8C, 0x55, 0xDD, 0xD7, 0xCD, 0x18,
        0x8B, 0x97, 0xB4, 0xCA, 0x4D, 0x99, 0x83, 0x1E,
        0xB2, 0x69, 0x9A, 0x83, 0x7D, 0xA2, 0xE4, 0xD9,
        0x70, 0xFB, 0xAC, 0xFD, 0xE5, 0x00, 0x33, 0xAE,
        0xA5, 0x85, 0xF1, 0xA2, 0x70, 0x85, 0x10, 0xC3,
        0x2D, 0x07, 0x88, 0x08, 0x01, 0xBD, 0x18, 0x28,
        0x98, 0xFE, 0x47, 0x68, 0x76, 0xFC, 0x89, 0x65
    };

    // KMAC XOF-256 test vector
    static const uint8_t test_vector_kmac_xof_256[] = {
        0xD5, 0xBE, 0x73, 0x1C, 0x95, 0x4E, 0xD7, 0x73,
        0x28, 0x46, 0xBB, 0x59, 0xDB, 0xE3, 0xA8, 0xE3,
        0x0F, 0x83, 0xE7, 0x7A, 0x4B, 0xFF, 0x44, 0x59,
        0xF2, 0xF1, 0xC2, 0xB4, 0xEC, 0xEB, 0xB8, 0xCE,
        0x67, 0xBA, 0x01, 0xC6, 0x2E, 0x8A, 0xB8, 0x57,
        0x8D, 0x2D, 0x49, 0x9B, 0xD1, 0xBB, 0x27, 0x67,
        0x68, 0x78, 0x11, 0x90, 0x02, 0x0A, 0x30, 0x6A,
        0x97, 0xDE, 0x28, 0x1D, 0xCC, 0x30, 0x30, 0x5D
    };

    // Array of pointers to KMAC test vectors
    static const uint8_t *kmac_test_vectors[] = {
        test_vector_kmac_128,
        test_vector_kmac_xof_128,
        test_vector_kmac_256,
        test_vector_kmac_xof_256
    };

    // Corresponding sizes of each test vector
    static const size_t kmac_test_vector_sizes[] = {
        sizeof(test_vector_kmac_128),
        sizeof(test_vector_kmac_xof_128),
        sizeof(test_vector_kmac_256),
        sizeof(test_vector_kmac_xof_256)
    };

    // KMAC execution path
    for (size_t i = 0; i < num_kmac; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(mac_flags[1]);
        if (!mac) { 
            printf("Unknown MAC flag %u\n", mac_flags[1]); 
            continue; 
        }

        CF_MAC_CTX mac_ctx = {0};
        CF_MAC_OPTS mac_opts_ctx = {0};

        CF_STATUS status = CF_MACOpts_Init(&mac_opts_ctx, NULL, 0, (const uint8_t *)test_vector_kmac_s_input, strlen(test_vector_kmac_s_input));

        if (status != CF_SUCCESS) { 
            CF_MACOpts_Reset(&mac_opts_ctx);
            printf("CF_MACOpts_Init failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            continue; 
        }

         status = CF_MAC_Init(&mac_ctx, mac, &mac_opts_ctx, test_vector_kmac_key, sizeof(test_vector_kmac_key), kmac_flags[i]);
        if (status != CF_SUCCESS) { 
            CF_MACOpts_Reset(&mac_opts_ctx);
            printf("CF_MAC_Init failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            continue; 
        }

        status = CF_MAC_Update(&mac_ctx, test_vector_kmac_input, sizeof(test_vector_kmac_input));
        if (status != CF_SUCCESS) { 
            printf("CF_MAC_Update failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            CF_MAC_Reset(&mac_ctx); 
            CF_MACOpts_Reset(&mac_opts_ctx);
            continue; 
        }

        // Determine output length
        size_t kmac_out_len = (kmac_flags[i] == CF_KMAC_XOF128 || kmac_flags[i] == CF_KMAC_XOF256)
                                ? (kmac_flags[i] == CF_KMAC_XOF128 ? CF_KMAC_DEFAULT_OUTPUT_LEN_128: CF_KMAC_DEFAULT_OUTPUT_LEN_256) // just for testing, KMAC-XOF doesnt have a fixed length
                                : (kmac_flags[i] == CF_KMAC128 ? CF_KMAC_DEFAULT_OUTPUT_LEN_128: CF_KMAC_DEFAULT_OUTPUT_LEN_256);

        status = CF_MAC_Final(&mac_ctx, tag, kmac_out_len);
        if (status != CF_SUCCESS) { 
            printf("CF_MAC_Final failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            CF_MAC_Reset(&mac_ctx); 
            CF_MACOpts_Reset(&mac_opts_ctx);
            continue; 
        }

        printf("%s: ", CF_MAC_GetFullName(&mac_ctx));
        DEMO_print_hex(tag, kmac_out_len);

        status = CF_MAC_Verify(mac, test_vector_kmac_key, sizeof(test_vector_kmac_key),
                               test_vector_kmac_input, sizeof(test_vector_kmac_input),
                               kmac_test_vectors[i], kmac_test_vector_sizes[i],
                               &mac_opts_ctx, kmac_flags[i]);

        if (status != CF_SUCCESS) {
            printf("CF_MAC_Verify failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
        } else {
            printf("CF_MAC_Verify succeeded for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
        }

        CF_MAC_Reset(&mac_ctx);
        CF_MACOpts_Reset(&mac_opts_ctx);
    }

    // test vectors from:
    // - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
    uint8_t test_vector_cmac[AES_BLOCK_SIZE] = {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
    };

    // ---------------- AES-128 ----------------
    static const uint8_t test_cmac_key128[AES_BLOCK_SIZE] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
 
    // ---------------- AES-256 ----------------
    static const uint8_t test_cmac_key192[24] = {
        0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
        0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
        0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
    };

    // ---------------- AES-256 ----------------
    static const uint8_t test_cmac_key256[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    static const uint8_t test_vector_cmac_128[AES_BLOCK_SIZE] = {
        0x07, 0x0A, 0x16, 0xB4, 0x6B, 0x4D, 0x41, 0x44,
        0xF7, 0x9B, 0xDD, 0x9D, 0xD0, 0x4A, 0x28, 0x7C
    };

    static const uint8_t test_vector_cmac_192[AES_BLOCK_SIZE] = {
        0x9E, 0x99, 0xA7, 0xBF, 0x31, 0xE7, 0x10, 0x90,
        0x06, 0x62, 0xF6, 0x5E, 0x61, 0x7C, 0x51, 0x84
    };

    static const uint8_t test_vector_cmac_256[AES_BLOCK_SIZE] = {
        0x28, 0xA7, 0x02, 0x3F, 0x45, 0x2E, 0x8F, 0x82,
        0xBD, 0x4B, 0xF2, 0x8D, 0x8C, 0x37, 0xC3, 0x5C
    };

    static const uint8_t *cmac_test_keys[] = {
        test_cmac_key128,
        test_cmac_key192,
        test_cmac_key256        
    };

    static const size_t cmac_test_keys_size[] = {
        sizeof(test_cmac_key128),
        sizeof(test_cmac_key192),
        sizeof(test_cmac_key256)
    };

    static const uint8_t *cmac_test_vectors[] = {
        test_vector_cmac_128,
        test_vector_cmac_192,
        test_vector_cmac_256
    };

    static const size_t cmac_test_vector_sizes[] = {
        sizeof(test_vector_cmac_128),
        sizeof(test_vector_cmac_192),
        sizeof(test_vector_cmac_256)
    };

    putchar('\n');

    // CMAC execution path
    for (size_t i = 0; i < 3; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(mac_flags[2]);
        if (!mac) { 
            printf("Unknown MAC flag %u\n", mac_flags[2]); 
            continue; 
        }

        CF_MAC_CTX mac_ctx = {0};
        CF_STATUS status;

        status = CF_MAC_Init(&mac_ctx, mac, NULL, cmac_test_keys[i], cmac_test_keys_size[i], 0);
        if (status != CF_SUCCESS) { 
            printf("CF_MAC_Init failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            continue; 
        }

        status = CF_MAC_Update(&mac_ctx, test_vector_cmac, sizeof(test_vector_cmac));
        if (status != CF_SUCCESS) { 
            printf("CF_MAC_Update failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            CF_MAC_Reset(&mac_ctx); 
            continue; 
        }

        status = CF_MAC_Final(&mac_ctx, tag, cmac_test_vector_sizes[i]);
        if (status != CF_SUCCESS) { 
            printf("CF_MAC_Final failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            CF_MAC_Reset(&mac_ctx); 
            continue; 
        }

        printf("%s: ", CF_MAC_GetFullName(&mac_ctx));
        DEMO_print_hex(tag, cmac_test_vector_sizes[i]);

        status = CF_MAC_Verify(mac, cmac_test_keys[i], cmac_test_keys_size[i],
                               test_vector_cmac, sizeof(test_vector_cmac),
                               cmac_test_vectors[i], cmac_test_vector_sizes[i],
                               NULL, 0);

        if (status != CF_SUCCESS) {
            printf("CF_MAC_Verify failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
        } else {
            printf("CF_MAC_Verify succeeded for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
        }

        CF_MAC_Reset(&mac_ctx);
    }

    putchar('\n');

    static const uint8_t test_vector_gmac_aad[AES_BLOCK_SIZE] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    static const uint8_t test_vector_gmac_iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    static const uint8_t test_gmac_key128[AES_BLOCK_SIZE] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    static const uint8_t test_gmac_key192[24] = {
        0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
        0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
        0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
    };

    static const uint8_t test_gmac_key256[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    static const uint8_t test_vector_gmac128[AES_BLOCK_SIZE] = {
        0x68, 0x16, 0xf5, 0x8a, 0x62, 0xc8, 0xf5, 0xff,
        0xbc, 0x2f, 0xf0, 0x92, 0xee, 0x29, 0xa1, 0x12
    };

    static const uint8_t test_vector_gmac192[AES_BLOCK_SIZE] = {
        0xc4, 0x89, 0xfb, 0xf4, 0xf6, 0x0e, 0x70, 0x68,
        0xf0, 0x9d, 0x4f, 0x0e, 0xb5, 0x58, 0xe1, 0xb3
    };
    
    static const uint8_t test_vector_gmac256[AES_BLOCK_SIZE] = {
        0xf6, 0xd9, 0x36, 0x9d, 0x0f, 0xec, 0xd0, 0x30,
        0xa1, 0x2d, 0x24, 0x7e, 0x2c, 0xca, 0x3d, 0x3d
    };

    static const uint8_t *gmac_test_keys[] = {
        test_gmac_key128,
        test_gmac_key192,
        test_gmac_key256        
    };

    static const size_t gmac_test_keys_size[] = {
        sizeof(test_cmac_key128),
        sizeof(test_cmac_key192),
        sizeof(test_cmac_key256)
    };

    static const uint8_t *gmac_test_vectors[] = {
        test_vector_gmac128,
        test_vector_gmac192,
        test_vector_gmac256
    };

    static const size_t gmac_test_vector_sizes[] = {
        sizeof(test_vector_gmac128),
        sizeof(test_vector_gmac192),
        sizeof(test_vector_gmac256)
    };

    // GMAC execution path
    for (size_t i = 0; i < 3; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(mac_flags[3]);
        if (!mac) { 
            printf("Unknown MAC flag %u\n", mac_flags[3]); 
            continue; 
        }

        CF_MAC_CTX mac_ctx = {0};
        CF_MAC_OPTS mac_opts_ctx = {0};

        CF_STATUS status = CF_MACOpts_Init(&mac_opts_ctx, test_vector_gmac_iv, sizeof(test_vector_gmac_iv), NULL, 0);

        status = CF_MAC_Init(&mac_ctx, mac, &mac_opts_ctx, gmac_test_keys[i], gmac_test_keys_size[i], 0);
        if (status != CF_SUCCESS) { 
            printf("CF_MAC_Init failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            CF_MACOpts_Reset(&mac_opts_ctx);
            continue; 
        }

        status = CF_MAC_Update(&mac_ctx, test_vector_gmac_aad, sizeof(test_vector_gmac_aad));
        if (status != CF_SUCCESS) { 

            printf("CF_MAC_Update failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            CF_MACOpts_Reset(&mac_opts_ctx);
            CF_MAC_Reset(&mac_ctx); 
            continue; 
        }

        status = CF_MAC_Final(&mac_ctx, tag, gmac_test_vector_sizes[i]);
        if (status != CF_SUCCESS) { 
            printf("CF_MAC_Final failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            CF_MACOpts_Reset(&mac_opts_ctx);
            CF_MAC_Reset(&mac_ctx); 
            continue; 
        }

        printf("%s: ", CF_MAC_GetFullName(&mac_ctx));
        DEMO_print_hex(tag, cmac_test_vector_sizes[i]);

        status = CF_MAC_Verify(mac, gmac_test_keys[i], gmac_test_keys_size[i],
                               test_vector_gmac_aad, sizeof(test_vector_gmac_aad),
                               gmac_test_vectors[i], gmac_test_vector_sizes[i],
                               &mac_opts_ctx, 0);

        if (status != CF_SUCCESS) {
            printf("CF_MAC_Verify failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
        } else {
            printf("CF_MAC_Verify succeeded for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
        }

        CF_MAC_CTX test_copy_ctx = {0};

        status = CF_MAC_CloneCtx(&test_copy_ctx, &mac_ctx);
        if (status != CF_SUCCESS) {
            printf("[FAIL] Copying test failed\n");
        } else {
            printf("[PASS] Copying test succeeded\n");
        }

        CF_MACOpts_Reset(&mac_opts_ctx);
        CF_MAC_Reset(&mac_ctx);

    CF_MAC_Reset(&test_copy_ctx);
    }

    putchar('\n');

    char *test_poly1305_message = "Cryptographic Forum Research Group";

    // // 32-byte Poly1305 key (r + s)
    uint8_t test_poly1305_key[32] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,  // r
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b   // s
    };

    uint8_t test_poly1305_expected_tag[16] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    };

    // POLY-1305 execution path
    for (size_t i = 0; i < 1; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(mac_flags[4]);
        if (!mac) { 
            printf("Unknown MAC flag %u\n", mac_flags[4]); 
            continue; 
        }

        CF_MAC_CTX mac_ctx = {0};

        CF_STATUS status = CF_MAC_Init(&mac_ctx, mac, NULL, test_poly1305_key, sizeof(test_poly1305_key), 0);
        if (status != CF_SUCCESS) { 
            printf("CF_MAC_Init failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            continue; 
        }

        status = CF_MAC_Update(&mac_ctx, (uint8_t *)test_poly1305_message, strlen(test_poly1305_message));
        if (status != CF_SUCCESS) { 

            printf("CF_MAC_Update failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            CF_MAC_Reset(&mac_ctx); 
            continue; 
        }

        status = CF_MAC_Final(&mac_ctx, tag, mac_ctx.mac->default_tag_len);
        if (status != CF_SUCCESS) { 
            printf("CF_MAC_Final failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
            CF_MAC_Reset(&mac_ctx); 
            continue; 
        }

        printf("%s: ", CF_MAC_GetFullName(&mac_ctx));
        DEMO_print_hex(tag, mac_ctx.mac->default_tag_len);

        status = CF_MAC_Verify(mac, test_poly1305_key, sizeof(test_poly1305_key),
                               (uint8_t *)test_poly1305_message, strlen(test_poly1305_message),
                               test_poly1305_expected_tag, mac_ctx.mac->default_tag_len,
                               NULL, 0);

        if (status != CF_SUCCESS) {
            printf("CF_MAC_Verify failed for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
        } else {
            printf("CF_MAC_Verify succeeded for %s\n", CF_MAC_GetFullName(&mac_ctx)); 
        }

        CF_MAC_Reset(&mac_ctx);
    }
}

#endif // ENABLE_TESTS