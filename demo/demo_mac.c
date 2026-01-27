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
    uint8_t digest[EVP_MAX_DEFAULT_DIGEST_SIZE * 2];

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
                            ? (kmac_types[i] == KMACXOF128 ? LL_KMAC_DEFAULT_OUTPUT_LEN_128: LL_KMAC_DEFAULT_OUTPUT_LEN_256) // just for testing, KMAC-XOF doesnt have a default fixed length
                            : (kmac_types[i] == KMAC128 ? LL_KMAC_DEFAULT_OUTPUT_LEN_128: LL_KMAC_DEFAULT_OUTPUT_LEN_256);

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

        DEMO_print_hex(digest, out_len);
        printf("\n");

        ll_KMAC_Free(&kmac_ctx);
    }
}

void test_all_kmacs_verify_array(const uint8_t *key, size_t key_len,
                                 const uint8_t *input, size_t input_len,
                                 const uint8_t *S, size_t S_len,
                                 const uint8_t *expected_digests[4]) {
    ll_KMAC_TYPE kmac_types[] = { KMAC128, KMACXOF128, KMAC256, KMACXOF256 };
    const char *kmac_names[] = { "KMAC128", "KMACXOF128", "KMAC256", "KMACXOF256" };
    size_t num_kmacs = sizeof(kmac_types) / sizeof(kmac_types[0]);

    for (size_t i = 0; i < num_kmacs; i++) {
        CF_STATUS status = ll_KMAC_Verify(key, key_len,
                                    input, input_len,
                                    S, S_len,
                                    expected_digests[i],
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
    if (ll_GMAC_Verify(&kctx, iv, sizeof(iv), aad, sizeof(aad), expected_tag128, sizeof(expected_tag128)) != CF_SUCCESS) {
        printf("GMAC tag verification failed\n");
    } else {
        printf("GMAC tag verified successfully\n");
    }

    ll_AES_ClearKey(&kctx);
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
    if (ll_GMAC_Verify(&kctx, iv, sizeof(iv), aad, sizeof(aad), expected_tag192, sizeof(expected_tag192)) != CF_SUCCESS) {
        printf("GMAC tag verification failed\n");
    } else {
        printf("GMAC tag verified successfully\n");
    }

    ll_AES_ClearKey(&kctx);
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
    if (ll_GMAC_Verify(&kctx, iv, sizeof(iv), aad, sizeof(aad), expected_tag256, sizeof(expected_tag256)) != CF_SUCCESS) {
        printf("GMAC tag verification failed\n");
    } else {
        printf("GMAC tag verified successfully\n");
    }

    ll_AES_ClearKey(&kctx);
    ll_GMAC_Free(&gctx);
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
    ll_CMAC_CTX cctx;

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
        ll_CMAC_Free(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Free(&cctx);
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

    ll_CMAC_Free(&cctx);

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
        ll_CMAC_Free(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Free(&cctx);
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

    ll_CMAC_Free(&cctx);

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
        ll_CMAC_Free(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Free(&cctx);
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

    ll_CMAC_Free(&cctx);

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
        ll_CMAC_Free(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Free(&cctx);
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
    ll_CMAC_Free(&cctx);

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
        ll_CMAC_Free(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Free(&cctx);
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

    ll_CMAC_Free(&cctx);

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
        ll_CMAC_Free(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Free(&cctx);
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

    ll_CMAC_Free(&cctx);

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
        ll_CMAC_Free(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Free(&cctx);
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

    ll_CMAC_Free(&cctx);

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
        ll_CMAC_Free(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Free(&cctx);
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
    ll_CMAC_Free(&cctx);

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
        ll_CMAC_Free(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Free(&cctx);
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

    ll_CMAC_Free(&cctx);

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
        ll_CMAC_Free(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Free(&cctx);
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

    ll_CMAC_Free(&cctx);

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
        ll_CMAC_Free(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Free(&cctx);
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

    ll_CMAC_Free(&cctx);

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
        ll_CMAC_Free(&cctx);
        return;
    }

    if (ll_CMAC_Final(&cctx, tag, sizeof(tag)) != CF_SUCCESS) {
        printf("CMAC finalize failed\n");
        ll_CMAC_Free(&cctx);
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
    ll_CMAC_Free(&cctx);
}

#endif // ENABLE_TESTS