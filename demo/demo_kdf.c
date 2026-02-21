#include "../src/include/config/demo_config.h"

#if ENABLE_TESTS

#include "../vectors/wycheproof/tv_hkdf_sha1.h"
#include "../vectors/wycheproof/tv_hkdf_sha256.h"
#include "../vectors/wycheproof/tv_hkdf_sha384.h"
#include "../vectors/wycheproof/tv_hkdf_sha512.h"
#include "../vectors/wycheproof/tv_pbkdf2_hmac_sha1.h"
#include "../vectors/wycheproof/tv_pbkdf2_hmac_sha224.h"
#include "../vectors/wycheproof/tv_pbkdf2_hmac_sha256.h"
#include "../vectors/wycheproof/tv_pbkdf2_hmac_sha384.h"
#include "../vectors/wycheproof/tv_pbkdf2_hmac_sha512.h"

#define TEST_OKM_MAX 1024  // fixed size for test

void test_all_hkdfs(const uint8_t *info, size_t info_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    size_t okm_len) {
    if (okm_len > TEST_OKM_MAX) return;
    
    uint8_t okm[TEST_OKM_MAX];

    // List of hash flags to test
    uint32_t hash_flags[] = {
        CF_MD5, // legacy: for testing not recomended for user use
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

        ll_HKDF_CTX hkdf_ctx;
        SECURE_ZERO(&hkdf_ctx, sizeof(hkdf_ctx));

        CF_STATUS status = ll_HKDF_Init(&hkdf_ctx, hash, info, info_len);
        if (status != CF_SUCCESS) {
            printf("ll_HKDF_Init failed for %s\n", CF_Hash_GetName(hash));
            continue;
        }

        status = ll_HKDF_Extract(&hkdf_ctx, salt, salt_len, ikm, ikm_len);
        if (status != CF_SUCCESS) {
            printf("ll_HKDF_Extract failed for %s\n", CF_Hash_GetName(hash));
            ll_HKDF_Reset(&hkdf_ctx);
            continue;
        }

        status = ll_HKDF_Expand(&hkdf_ctx, okm, okm_len, NULL, 0);
        if (status != CF_SUCCESS) {
            printf("ll_HKDF_Expand failed for %s\n", CF_Hash_GetName(hash));
            ll_HKDF_Reset(&hkdf_ctx);
            continue;
        }

        printf("%s HKDF OKM: ", CF_Hash_GetName(hash));
        DEMO_print_hex(okm, okm_len);
        printf("\n");

        ll_HKDF_Reset(&hkdf_ctx);
    }
}


void test_all_pbkdf2s(const uint8_t *password, size_t password_len,
                       const uint8_t *salt, size_t salt_len,
                       size_t dk_len, size_t iteration_count) {

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
    uint8_t dk_buffer[CF_MAX_DEFAULT_DIGEST_SIZE * 8]; // big enough for test

    for (size_t i = 0; i < num_hashes; i++) {
        const CF_HASH *hash = CF_Hash_GetByFlag(hash_flags[i]);
        if (!hash) {
            printf("Unknown hash flag %u\n", hash_flags[i]);
            continue;
        }

        ll_PBKDF2_CTX ctx = {0};

        CF_STATUS status = ll_PBKDF2_Init(&ctx, hash, password, password_len);
        if (status != CF_SUCCESS) {
            printf("ll_PBKDF2_Init failed for %s\n", CF_Hash_GetName(hash));
            continue;
        }

        status = ll_PBKDF2_Extract(&ctx, salt, salt_len);
        if (status != CF_SUCCESS) {
            printf("ll_PBKDF2_Extract failed for %s\n", CF_Hash_GetName(hash));
            ll_PBKDF2_Reset(&ctx);
            continue;
        }

        SECURE_ZERO(dk_buffer, sizeof(dk_buffer));
        status = ll_PBKDF2_Expand(&ctx, dk_buffer, dk_len, iteration_count);
        if (status != CF_SUCCESS) {
            printf("ll_PBKDF2_Expand failed for %s, error status: %u\n", CF_Hash_GetName(hash), status);
            ll_PBKDF2_Reset(&ctx);
            continue;
        }

        printf("%s PBKDF2 DK: ", CF_Hash_GetName(hash));
        DEMO_print_hex(dk_buffer, dk_len);
        printf("\n");

        ll_PBKDF2_Reset(&ctx);
    }
}

void test_all_kdf_high(void) {

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

    // List of KDF flags to test
    uint32_t kdf_flags[] = {
        CF_HKDF,
        CF_PBKDF2,
        CF_KMAC_XOF
    };

    size_t num_hashes = sizeof(hash_flags)/sizeof(hash_flags[0]);
    uint8_t dk_buffer[CF_MAX_DEFAULT_DIGEST_SIZE];

    // Input parameters
    uint8_t hkdf_ikm[] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    uint8_t hkdf_salt[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,
        0x07,0x08,0x09,0x0a,0x0b,0x0c
    };
    uint8_t hkdf_info[] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
    };

    size_t hkdf_dk_len = 42;

    // HKDF
    for (size_t i = 0; i < num_hashes; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(kdf_flags[0]);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", kdf_flags[0]);
            continue;
        }

        CF_KDF_OPTS ctxOpts = {0};
        CF_KDF_CTX ctx = {0};
        
        CF_STATUS status = CF_KDFOpts_Init(&ctxOpts, hkdf_info, sizeof(hkdf_info), NULL, 0, 0);
        if (status != CF_SUCCESS) {
            printf("CF_KDFOpts_Init failed for %s\n", CF_KDF_GetName(kdf));
            continue;
        }

        status = CF_KDF_Init(&ctx, kdf, &ctxOpts, hkdf_ikm, sizeof(hkdf_ikm), hash_flags[i]);
        if (status != CF_SUCCESS) {
            CF_KDFOpts_Reset(&ctxOpts);
            printf("CF_KDF_Init failed for %s\n", CF_KDF_GetName(kdf));
            continue;
        }

        status = CF_KDF_Extract(&ctx, hkdf_salt, sizeof(hkdf_salt));
        if (status != CF_SUCCESS) {
            printf("CF_KDF_Extract failed for %s\n", CF_KDF_GetFullName(&ctx));
            CF_KDFOpts_Reset(&ctxOpts);
            CF_KDF_Reset(&ctx);
            continue;
        }

        SECURE_ZERO(dk_buffer, sizeof(dk_buffer));
        status = CF_KDF_Expand(&ctx, dk_buffer, hkdf_dk_len);
        if (status != CF_SUCCESS) {
            printf("CF_KDF_Expand failed for %s, error status: %u\n", CF_KDF_GetFullName(&ctx), status);
            CF_KDFOpts_Reset(&ctxOpts);
            CF_KDF_Reset(&ctx);
            continue;
        }

        printf("%s DK: ", CF_KDF_GetFullName(&ctx));
        DEMO_print_hex(dk_buffer, hkdf_dk_len);
        printf("\n");

        CF_KDFOpts_Reset(&ctxOpts);
        CF_KDF_Reset(&ctx);
    }

    putchar('\n');

    size_t pbkdf2_dk_len = 42;

    // "password123" in hex
    uint8_t pbkdf2_password[] = {
        0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x31, 0x32, 0x33
    };

    // "salt111" in hex
    uint8_t pbkdf2_salt[] = {
        0x73, 0x61, 0x6C, 0x74, 0x31, 0x31, 0x31
    };

    uint32_t pbkdf2_iterations = 1000;

    // PBKDF2
    for (size_t i = 0; i < num_hashes; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(kdf_flags[1]);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", kdf_flags[1]);
            continue;
        }

        CF_KDF_OPTS ctxOpts = {0};
        CF_KDF_CTX ctx = {0};
        
        CF_STATUS status = CF_KDFOpts_Init(&ctxOpts, NULL, 0, NULL, 0, pbkdf2_iterations);
        if (status != CF_SUCCESS) {
            printf("CF_KDFOpts_Init failed for %s\n", CF_KDF_GetName(kdf));
            continue;
        }

        status = CF_KDF_Init(&ctx, kdf, &ctxOpts, pbkdf2_password, sizeof(pbkdf2_password), hash_flags[i]);
        if (status != CF_SUCCESS) {
            CF_KDFOpts_Reset(&ctxOpts);
            printf("CF_KDF_Init failed for %s\n", CF_KDF_GetName(kdf));
            continue;
        }

        status = CF_KDF_Extract(&ctx, pbkdf2_salt, sizeof(pbkdf2_salt));
        if (status != CF_SUCCESS) {
            printf("CF_KDF_Extract failed for %s\n", CF_KDF_GetFullName(&ctx));
            CF_KDFOpts_Reset(&ctxOpts);
            CF_KDF_Reset(&ctx);
            continue;
        }

        SECURE_ZERO(dk_buffer, sizeof(dk_buffer));
        status = CF_KDF_Expand(&ctx, dk_buffer, pbkdf2_dk_len);
        if (status != CF_SUCCESS) {
            printf("CF_KDF_Expand failed for %s, error status: %u\n", CF_KDF_GetFullName(&ctx), status);
            CF_KDFOpts_Reset(&ctxOpts);
            CF_KDF_Reset(&ctx);
            continue;
        }

        printf("%s DK: ", CF_KDF_GetFullName(&ctx));
        DEMO_print_hex(dk_buffer, pbkdf2_dk_len);
        printf("\n");

        CF_KDFOpts_Reset(&ctxOpts);
        CF_KDF_Reset(&ctx);
    }

    putchar('\n');

    // List of KMAC type flags to test
    uint32_t kmac_flags[] = {
        CF_KMAC_XOF128,
        CF_KMAC_XOF256
    };

    size_t num_kmac = sizeof(kmac_flags)/sizeof(kmac_flags[0]);

    // test vectors from:
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

    // KMAC-XOF
    for (size_t i = 0; i < num_kmac; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(kdf_flags[2]);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", kdf_flags[2]);
            continue;
        }

        CF_KDF_OPTS ctxOpts = {0};
        CF_KDF_CTX ctx = {0};
        
        CF_STATUS status = CF_KDFOpts_Init(&ctxOpts, NULL, 0, (const uint8_t *)test_vector_kmac_s_input, strlen(test_vector_kmac_s_input), 0);
        if (status != CF_SUCCESS) {
            printf("CF_KDFOpts_Init failed for %s\n", CF_KDF_GetName(kdf));
            continue;
        }

        status = CF_KDF_Init(&ctx, kdf, &ctxOpts, test_vector_kmac_key, sizeof(test_vector_kmac_key), kmac_flags[i]);
        if (status != CF_SUCCESS) {
            CF_KDFOpts_Reset(&ctxOpts);
            printf("CF_KDF_Init failed for %s\n", CF_KDF_GetName(kdf));
            continue;
        }

        status = CF_KDF_Extract(&ctx, test_vector_kmac_input, sizeof(test_vector_kmac_input));
        if (status != CF_SUCCESS) {
            printf("CF_KDF_Extract failed for %s\n", CF_KDF_GetFullName(&ctx));
            CF_KDFOpts_Reset(&ctxOpts);
            CF_KDF_Reset(&ctx);
            continue;
        }

        SECURE_ZERO(dk_buffer, sizeof(dk_buffer));

        // Determine output length
        size_t kmac_out_len = (kmac_flags[i] == CF_KMAC_XOF128 || kmac_flags[i] == CF_KMAC_XOF256)
                                ? (kmac_flags[i] == CF_KMAC_XOF128 ? CF_KMAC_DEFAULT_OUTPUT_LEN_128: CF_KMAC_DEFAULT_OUTPUT_LEN_256) // just for testing, KMAC-XOF doesnt have a fixed length
                                : (kmac_flags[i] == CF_KMAC128 ? CF_KMAC_DEFAULT_OUTPUT_LEN_128: CF_KMAC_DEFAULT_OUTPUT_LEN_256);

        status = CF_KDF_Expand(&ctx, dk_buffer, kmac_out_len);
        if (status != CF_SUCCESS) {
            printf("CF_KDF_Expand failed for %s, error status: %u\n", CF_KDF_GetFullName(&ctx), status);
            CF_KDFOpts_Reset(&ctxOpts);
            CF_KDF_Reset(&ctx);
            continue;
        }

        printf("%s DK: ", CF_KDF_GetFullName(&ctx));
        DEMO_print_hex(dk_buffer, kmac_out_len);
        printf("\n");

        CF_KDFOpts_Reset(&ctxOpts);
        CF_KDF_Reset(&ctx);
    }
}

void test_hkdf_sha1_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(hkdf_sha1_test_vectors) / sizeof(hkdf_sha1_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(CF_HKDF);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", CF_HKDF);
            return;
        }

        uint8_t okm[5100] = {0};

        int expected_valid = (strcmp(hkdf_sha1_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        CF_STATUS status;
        CF_KDF_OPTS *opts = NULL;

        // -----------------------------
        // Initialize KDF options with info if possible
        // -----------------------------
        if (hkdf_sha1_test_vectors[i].info_len != 0) {
            opts = CF_KDFOpts_InitAlloc(
                hkdf_sha1_test_vectors[i].info,
                hkdf_sha1_test_vectors[i].info_len,
                NULL, 0,        // no custom field
                0,              // iterations unused for HKDF
                &status
            );

            if (!opts || status != CF_SUCCESS) {
                printf("HKDF TcId %d FAILED to init options\n", hkdf_sha1_test_vectors[i].tc_id);
                failure = 1;
                goto print_extra;
            }
        }

        // -----------------------------
        // Initialize KDF context
        // -----------------------------
        CF_KDF_CTX *ctx = CF_KDF_InitAlloc(
            kdf,
            opts,
            hkdf_sha1_test_vectors[i].ikm,
            hkdf_sha1_test_vectors[i].ikm_len,
            CF_SHA1, // subflag : SHA-1
            &status
        );

        if (!ctx || status != CF_SUCCESS) {
            printf("HKDF TcId %d FAILED to init context\n", hkdf_sha1_test_vectors[i].tc_id);
            failure = 1;
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Extract
        // -----------------------------
        status = CF_KDF_Extract(ctx,
            hkdf_sha1_test_vectors[i].salt,
            hkdf_sha1_test_vectors[i].salt_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("HKDF TcId %d FAILED (extract rejected valid vector)\n",
                   hkdf_sha1_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Expand
        // -----------------------------
        status = CF_KDF_Expand(ctx,
            okm,
            hkdf_sha1_test_vectors[i].okm_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("HKDF TcId %d FAILED (expand rejected valid vector)\n",
                   hkdf_sha1_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Compare output
        // -----------------------------
        if (expected_valid &&
            memcmp(okm, hkdf_sha1_test_vectors[i].okm, hkdf_sha1_test_vectors[i].okm_len) != 0) {
            printf("HKDF TcId %d FAILED, derived key mismatch\n",
                   hkdf_sha1_test_vectors[i].tc_id);
            failure = 1;

            printf("Derived OKM : ");
            DEMO_print_hex(okm, hkdf_sha1_test_vectors[i].okm_len);

            printf("Expected OKM : ");
            DEMO_print_hex(hkdf_sha1_test_vectors[i].okm, hkdf_sha1_test_vectors[i].okm_len);
        }

        CF_KDF_Free(&ctx);
        if (opts)
            CF_KDFOpts_Free(&opts);

print_extra:
        if (failure) {
            total_failures++;

            if (hkdf_sha1_test_vectors[i].comment &&
                hkdf_sha1_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hkdf_sha1_test_vectors[i].comment);
            }

            if (hkdf_sha1_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hkdf_sha1_test_vectors[i].flags_len; f++) {
                    printf("%s", hkdf_sha1_test_vectors[i].flags[f]);
                    if (f + 1 < hkdf_sha1_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
        } else {
            total_success++;
        }
    }

    printf("HKDF-SHA1 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_hkdf_sha256_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(hkdf_sha256_test_vectors) / sizeof(hkdf_sha256_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(CF_HKDF);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", CF_HKDF);
            return;
        }

        uint8_t okm[8160] = {0};

        int expected_valid = (strcmp(hkdf_sha256_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        CF_STATUS status;
        CF_KDF_OPTS *opts = NULL;

        // -----------------------------
        // Initialize KDF options with info if possible
        // -----------------------------
        if (hkdf_sha256_test_vectors[i].info_len != 0) {
            opts = CF_KDFOpts_InitAlloc(
                hkdf_sha256_test_vectors[i].info,
                hkdf_sha256_test_vectors[i].info_len,
                NULL, 0,        // no custom field
                0,              // iterations unused for HKDF
                &status
            );

            if (!opts || status != CF_SUCCESS) {
                printf("HKDF TcId %d FAILED to init options\n", hkdf_sha256_test_vectors[i].tc_id);
                failure = 1;
                goto print_extra;
            }
        }

        // -----------------------------
        // Initialize KDF context
        // -----------------------------
        CF_KDF_CTX *ctx = CF_KDF_InitAlloc(
            kdf,
            opts,
            hkdf_sha256_test_vectors[i].ikm,
            hkdf_sha256_test_vectors[i].ikm_len,
            CF_SHA256, // subflag : SHA-256
            &status
        );

        if (!ctx || status != CF_SUCCESS) {
            printf("HKDF TcId %d FAILED to init context\n", hkdf_sha256_test_vectors[i].tc_id);
            failure = 1;
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Extract
        // -----------------------------
        status = CF_KDF_Extract(ctx,
            hkdf_sha256_test_vectors[i].salt,
            hkdf_sha256_test_vectors[i].salt_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("HKDF TcId %d FAILED (extract rejected valid vector)\n",
                   hkdf_sha256_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Expand
        // -----------------------------
        status = CF_KDF_Expand(ctx,
            okm,
            hkdf_sha256_test_vectors[i].okm_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("HKDF TcId %d FAILED (expand rejected valid vector)\n",
                   hkdf_sha256_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Compare output
        // -----------------------------
        if (expected_valid &&
            memcmp(okm, hkdf_sha256_test_vectors[i].okm, hkdf_sha256_test_vectors[i].okm_len) != 0) {
            printf("HKDF TcId %d FAILED, derived key mismatch\n",
                   hkdf_sha256_test_vectors[i].tc_id);
            failure = 1;

            printf("Derived OKM : ");
            DEMO_print_hex(okm, hkdf_sha256_test_vectors[i].okm_len);

            printf("Expected OKM : ");
            DEMO_print_hex(hkdf_sha256_test_vectors[i].okm, hkdf_sha256_test_vectors[i].okm_len);
        }

        CF_KDF_Free(&ctx);
        if (opts)
            CF_KDFOpts_Free(&opts);

print_extra:
        if (failure) {
            total_failures++;

            if (hkdf_sha256_test_vectors[i].comment &&
                hkdf_sha256_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hkdf_sha256_test_vectors[i].comment);
            }

            if (hkdf_sha256_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hkdf_sha256_test_vectors[i].flags_len; f++) {
                    printf("%s", hkdf_sha256_test_vectors[i].flags[f]);
                    if (f + 1 < hkdf_sha256_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
        } else {
            total_success++;
        }
    }

    printf("HKDF-SHA256 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_hkdf_sha384_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(hkdf_sha384_test_vectors) / sizeof(hkdf_sha384_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(CF_HKDF);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", CF_HKDF);
            return;
        }

        uint8_t okm[12240] = {0};

        int expected_valid = (strcmp(hkdf_sha384_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        CF_STATUS status;
        CF_KDF_OPTS *opts = NULL;

        // -----------------------------
        // Initialize KDF options with info if possible
        // -----------------------------
        if (hkdf_sha384_test_vectors[i].info_len != 0) {
            opts = CF_KDFOpts_InitAlloc(
                hkdf_sha384_test_vectors[i].info,
                hkdf_sha384_test_vectors[i].info_len,
                NULL, 0,        // no custom field
                0,              // iterations unused for HKDF
                &status
            );

            if (!opts || status != CF_SUCCESS) {
                printf("HKDF TcId %d FAILED to init options\n", hkdf_sha384_test_vectors[i].tc_id);
                failure = 1;
                goto print_extra;
            }
        }

        // -----------------------------
        // Initialize KDF context
        // -----------------------------
        CF_KDF_CTX *ctx = CF_KDF_InitAlloc(
            kdf,
            opts,
            hkdf_sha384_test_vectors[i].ikm,
            hkdf_sha384_test_vectors[i].ikm_len,
            CF_SHA384, // subflag : SHA-384
            &status
        );

        if (!ctx || status != CF_SUCCESS) {
            printf("HKDF TcId %d FAILED to init context\n", hkdf_sha384_test_vectors[i].tc_id);
            failure = 1;
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Extract
        // -----------------------------
        status = CF_KDF_Extract(ctx,
            hkdf_sha384_test_vectors[i].salt,
            hkdf_sha384_test_vectors[i].salt_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("HKDF TcId %d FAILED (extract rejected valid vector)\n",
                   hkdf_sha384_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Expand
        // -----------------------------
        status = CF_KDF_Expand(ctx,
            okm,
            hkdf_sha384_test_vectors[i].okm_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("HKDF TcId %d FAILED (expand rejected valid vector)\n",
                   hkdf_sha384_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Compare output
        // -----------------------------
        if (expected_valid &&
            memcmp(okm, hkdf_sha384_test_vectors[i].okm, hkdf_sha384_test_vectors[i].okm_len) != 0) {
            printf("HKDF TcId %d FAILED, derived key mismatch\n",
                   hkdf_sha384_test_vectors[i].tc_id);
            failure = 1;

            printf("Derived OKM : ");
            DEMO_print_hex(okm, hkdf_sha384_test_vectors[i].okm_len);

            printf("Expected OKM : ");
            DEMO_print_hex(hkdf_sha384_test_vectors[i].okm, hkdf_sha384_test_vectors[i].okm_len);
        }

        CF_KDF_Free(&ctx);
        if (opts)
            CF_KDFOpts_Free(&opts);

print_extra:
        if (failure) {
            total_failures++;

            if (hkdf_sha384_test_vectors[i].comment &&
                hkdf_sha384_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hkdf_sha384_test_vectors[i].comment);
            }

            if (hkdf_sha384_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hkdf_sha384_test_vectors[i].flags_len; f++) {
                    printf("%s", hkdf_sha384_test_vectors[i].flags[f]);
                    if (f + 1 < hkdf_sha384_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
        } else {
            total_success++;
        }
    }

    printf("HKDF-SHA384 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_hkdf_sha512_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(hkdf_sha512_test_vectors) / sizeof(hkdf_sha512_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(CF_HKDF);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", CF_HKDF);
            return;
        }

        uint8_t okm[16320] = {0};

        int expected_valid = (strcmp(hkdf_sha512_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        CF_STATUS status;
        CF_KDF_OPTS *opts = NULL;

        // -----------------------------
        // Initialize KDF options with info if possible
        // -----------------------------
        if (hkdf_sha512_test_vectors[i].info_len != 0) {
            opts = CF_KDFOpts_InitAlloc(
                hkdf_sha512_test_vectors[i].info,
                hkdf_sha512_test_vectors[i].info_len,
                NULL, 0,        // no custom field
                0,              // iterations unused for HKDF
                &status
            );

            if (!opts || status != CF_SUCCESS) {
                printf("HKDF TcId %d FAILED to init options\n", hkdf_sha512_test_vectors[i].tc_id);
                failure = 1;
                goto print_extra;
            }
        }

        // -----------------------------
        // Initialize KDF context
        // -----------------------------
        CF_KDF_CTX *ctx = CF_KDF_InitAlloc(
            kdf,
            opts,
            hkdf_sha512_test_vectors[i].ikm,
            hkdf_sha512_test_vectors[i].ikm_len,
            CF_SHA512, // subflag : SHA-512
            &status
        );

        if (!ctx || status != CF_SUCCESS) {
            printf("HKDF TcId %d FAILED to init context\n", hkdf_sha512_test_vectors[i].tc_id);
            failure = 1;
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Extract
        // -----------------------------
        status = CF_KDF_Extract(ctx,
            hkdf_sha512_test_vectors[i].salt,
            hkdf_sha512_test_vectors[i].salt_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("HKDF TcId %d FAILED (extract rejected valid vector)\n",
                   hkdf_sha512_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Expand
        // -----------------------------
        status = CF_KDF_Expand(ctx,
            okm,
            hkdf_sha512_test_vectors[i].okm_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("HKDF TcId %d FAILED (expand rejected valid vector)\n",
                   hkdf_sha512_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Compare output
        // -----------------------------
        if (expected_valid &&
            memcmp(okm, hkdf_sha512_test_vectors[i].okm, hkdf_sha512_test_vectors[i].okm_len) != 0) {
            printf("HKDF TcId %d FAILED, derived key mismatch\n",
                   hkdf_sha512_test_vectors[i].tc_id);
            failure = 1;

            printf("Derived OKM : ");
            DEMO_print_hex(okm, hkdf_sha512_test_vectors[i].okm_len);

            printf("Expected OKM : ");
            DEMO_print_hex(hkdf_sha512_test_vectors[i].okm, hkdf_sha512_test_vectors[i].okm_len);
        }

        CF_KDF_Free(&ctx);
        if (opts)
            CF_KDFOpts_Free(&opts);

print_extra:
        if (failure) {
            total_failures++;

            if (hkdf_sha512_test_vectors[i].comment &&
                hkdf_sha512_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hkdf_sha512_test_vectors[i].comment);
            }

            if (hkdf_sha512_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hkdf_sha512_test_vectors[i].flags_len; f++) {
                    printf("%s", hkdf_sha512_test_vectors[i].flags[f]);
                    if (f + 1 < hkdf_sha512_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
        } else {
            total_success++;
        }
    }

    printf("HKDF-SHA512 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_pbkdf2_hmac_sha1_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(pbkdf2_hmac_sha1_test_vectors) / sizeof(pbkdf2_hmac_sha1_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(CF_PBKDF2);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", CF_PBKDF2);
            return;
        }

        uint8_t dk[75] = {0}; // derived key buffer

        int expected_valid = (strcmp(pbkdf2_hmac_sha1_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        CF_STATUS status;
        CF_KDF_OPTS *opts = NULL;

        // -----------------------------
        // Initialize KDF options with iteration count if possible
        // -----------------------------
        opts = CF_KDFOpts_InitAlloc(
            NULL, 0,                               // no info field
            NULL, 0,                               // no custom field
            pbkdf2_hmac_sha1_test_vectors[i].iteration_count,
            &status
        );

        if (!opts || status != CF_SUCCESS) {
            printf("PBKDF2 TcId %d FAILED to init options\n", pbkdf2_hmac_sha1_test_vectors[i].tc_id);
            failure = 1;
            goto print_extra;
        }

        // -----------------------------
        // Initialize KDF context
        // -----------------------------
        CF_KDF_CTX *ctx = CF_KDF_InitAlloc(
            kdf,
            opts,
            pbkdf2_hmac_sha1_test_vectors[i].password,
            pbkdf2_hmac_sha1_test_vectors[i].password_len,
            CF_SHA1, // subflag : SHA-1
            &status
        );

        if (!ctx || status != CF_SUCCESS) {
            printf("PBKDF2 TcId %d FAILED to init context\n", pbkdf2_hmac_sha1_test_vectors[i].tc_id);
            failure = 1;
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Derive
        // -----------------------------
        status = CF_KDF_Extract(ctx,
            pbkdf2_hmac_sha1_test_vectors[i].salt,
            pbkdf2_hmac_sha1_test_vectors[i].salt_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("PBKDF2 TcId %d FAILED (extract rejected valid vector)\n",
                   pbkdf2_hmac_sha1_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        status = CF_KDF_Expand(ctx,
            dk,
            pbkdf2_hmac_sha1_test_vectors[i].dk_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("PBKDF2 TcId %d FAILED (expand rejected valid vector)\n",
                   pbkdf2_hmac_sha1_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Compare output
        // -----------------------------
        if (expected_valid &&
            memcmp(dk, pbkdf2_hmac_sha1_test_vectors[i].dk, pbkdf2_hmac_sha1_test_vectors[i].dk_len) != 0) {
            printf("PBKDF2 TcId %d FAILED, derived key mismatch\n",
                   pbkdf2_hmac_sha1_test_vectors[i].tc_id);
            failure = 1;

            printf("Derived DK : ");
            DEMO_print_hex(dk, pbkdf2_hmac_sha1_test_vectors[i].dk_len);

            printf("Expected DK : ");
            DEMO_print_hex(pbkdf2_hmac_sha1_test_vectors[i].dk, pbkdf2_hmac_sha1_test_vectors[i].dk_len);
        }

        CF_KDF_Free(&ctx);
        if (opts)
            CF_KDFOpts_Free(&opts);

print_extra:
        if (failure) {
            total_failures++;

            if (pbkdf2_hmac_sha1_test_vectors[i].comment &&
                pbkdf2_hmac_sha1_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", pbkdf2_hmac_sha1_test_vectors[i].comment);
            }

            if (pbkdf2_hmac_sha1_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < pbkdf2_hmac_sha1_test_vectors[i].flags_len; f++) {
                    printf("%s", pbkdf2_hmac_sha1_test_vectors[i].flags[f]);
                    if (f + 1 < pbkdf2_hmac_sha1_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
        } else {
            total_success++;
        }
    }

    printf("PBKDF2-SHA1 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_pbkdf2_hmac_sha224_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(pbkdf2_hmac_sha224_test_vectors) / sizeof(pbkdf2_hmac_sha224_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(CF_PBKDF2);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", CF_PBKDF2);
            return;
        }

        uint8_t dk[75] = {0}; // derived key buffer

        int expected_valid = (strcmp(pbkdf2_hmac_sha224_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        CF_STATUS status;
        CF_KDF_OPTS *opts = NULL;

        // -----------------------------
        // Initialize KDF options with iteration count if possible
        // -----------------------------
        opts = CF_KDFOpts_InitAlloc(
            NULL, 0,                               // no info field
            NULL, 0,                               // no custom field
            pbkdf2_hmac_sha224_test_vectors[i].iteration_count,
            &status
        );

        if (!opts || status != CF_SUCCESS) {
            printf("PBKDF2 TcId %d FAILED to init options\n", pbkdf2_hmac_sha224_test_vectors[i].tc_id);
            failure = 1;
            goto print_extra;
        }

        // -----------------------------
        // Initialize KDF context
        // -----------------------------
        CF_KDF_CTX *ctx = CF_KDF_InitAlloc(
            kdf,
            opts,
            pbkdf2_hmac_sha224_test_vectors[i].password,
            pbkdf2_hmac_sha224_test_vectors[i].password_len,
            CF_SHA224, // subflag : SHA-1
            &status
        );

        if (!ctx || status != CF_SUCCESS) {
            printf("PBKDF2 TcId %d FAILED to init context\n", pbkdf2_hmac_sha224_test_vectors[i].tc_id);
            failure = 1;
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Derive
        // -----------------------------
        status = CF_KDF_Extract(ctx,
            pbkdf2_hmac_sha224_test_vectors[i].salt,
            pbkdf2_hmac_sha224_test_vectors[i].salt_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("PBKDF2 TcId %d FAILED (extract rejected valid vector)\n",
                   pbkdf2_hmac_sha224_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        status = CF_KDF_Expand(ctx,
            dk,
            pbkdf2_hmac_sha224_test_vectors[i].dk_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("PBKDF2 TcId %d FAILED (expand rejected valid vector)\n",
                   pbkdf2_hmac_sha224_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Compare output
        // -----------------------------
        if (expected_valid &&
            memcmp(dk, pbkdf2_hmac_sha224_test_vectors[i].dk, pbkdf2_hmac_sha224_test_vectors[i].dk_len) != 0) {
            printf("PBKDF2 TcId %d FAILED, derived key mismatch\n",
                   pbkdf2_hmac_sha224_test_vectors[i].tc_id);
            failure = 1;

            printf("Derived DK : ");
            DEMO_print_hex(dk, pbkdf2_hmac_sha224_test_vectors[i].dk_len);

            printf("Expected DK : ");
            DEMO_print_hex(pbkdf2_hmac_sha224_test_vectors[i].dk, pbkdf2_hmac_sha224_test_vectors[i].dk_len);
        }

        CF_KDF_Free(&ctx);
        if (opts)
            CF_KDFOpts_Free(&opts);

print_extra:
        if (failure) {
            total_failures++;

            if (pbkdf2_hmac_sha224_test_vectors[i].comment &&
                pbkdf2_hmac_sha224_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", pbkdf2_hmac_sha224_test_vectors[i].comment);
            }

            if (pbkdf2_hmac_sha224_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < pbkdf2_hmac_sha224_test_vectors[i].flags_len; f++) {
                    printf("%s", pbkdf2_hmac_sha224_test_vectors[i].flags[f]);
                    if (f + 1 < pbkdf2_hmac_sha224_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
        } else {
            total_success++;
        }
    }

    printf("PBKDF2-SHA224 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_pbkdf2_hmac_sha256_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(pbkdf2_hmac_sha256_test_vectors) / sizeof(pbkdf2_hmac_sha256_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(CF_PBKDF2);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", CF_PBKDF2);
            return;
        }

        uint8_t dk[75] = {0}; // derived key buffer

        int expected_valid = (strcmp(pbkdf2_hmac_sha256_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        CF_STATUS status;
        CF_KDF_OPTS *opts = NULL;

        // -----------------------------
        // Initialize KDF options with iteration count if possible
        // -----------------------------
        opts = CF_KDFOpts_InitAlloc(
            NULL, 0,                               // no info field
            NULL, 0,                               // no custom field
            pbkdf2_hmac_sha256_test_vectors[i].iteration_count,
            &status
        );

        if (!opts || status != CF_SUCCESS) {
            printf("PBKDF2 TcId %d FAILED to init options\n", pbkdf2_hmac_sha256_test_vectors[i].tc_id);
            failure = 1;
            goto print_extra;
        }

        // -----------------------------
        // Initialize KDF context
        // -----------------------------
        CF_KDF_CTX *ctx = CF_KDF_InitAlloc(
            kdf,
            opts,
            pbkdf2_hmac_sha256_test_vectors[i].password,
            pbkdf2_hmac_sha256_test_vectors[i].password_len,
            CF_SHA256, // subflag : SHA-1
            &status
        );

        if (!ctx || status != CF_SUCCESS) {
            printf("PBKDF2 TcId %d FAILED to init context\n", pbkdf2_hmac_sha256_test_vectors[i].tc_id);
            failure = 1;
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Derive
        // -----------------------------
        status = CF_KDF_Extract(ctx,
            pbkdf2_hmac_sha256_test_vectors[i].salt,
            pbkdf2_hmac_sha256_test_vectors[i].salt_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("PBKDF2 TcId %d FAILED (extract rejected valid vector)\n",
                   pbkdf2_hmac_sha256_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        status = CF_KDF_Expand(ctx,
            dk,
            pbkdf2_hmac_sha256_test_vectors[i].dk_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("PBKDF2 TcId %d FAILED (expand rejected valid vector)\n",
                   pbkdf2_hmac_sha256_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Compare output
        // -----------------------------
        if (expected_valid &&
            memcmp(dk, pbkdf2_hmac_sha256_test_vectors[i].dk, pbkdf2_hmac_sha256_test_vectors[i].dk_len) != 0) {
            printf("PBKDF2 TcId %d FAILED, derived key mismatch\n",
                   pbkdf2_hmac_sha256_test_vectors[i].tc_id);
            failure = 1;

            printf("Derived DK : ");
            DEMO_print_hex(dk, pbkdf2_hmac_sha256_test_vectors[i].dk_len);

            printf("Expected DK : ");
            DEMO_print_hex(pbkdf2_hmac_sha256_test_vectors[i].dk, pbkdf2_hmac_sha256_test_vectors[i].dk_len);
        }

        CF_KDF_Free(&ctx);
        if (opts)
            CF_KDFOpts_Free(&opts);

print_extra:
        if (failure) {
            total_failures++;

            if (pbkdf2_hmac_sha256_test_vectors[i].comment &&
                pbkdf2_hmac_sha256_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", pbkdf2_hmac_sha256_test_vectors[i].comment);
            }

            if (pbkdf2_hmac_sha256_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < pbkdf2_hmac_sha256_test_vectors[i].flags_len; f++) {
                    printf("%s", pbkdf2_hmac_sha256_test_vectors[i].flags[f]);
                    if (f + 1 < pbkdf2_hmac_sha256_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
        } else {
            total_success++;
        }
    }

    printf("PBKDF2-SHA256 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_pbkdf2_hmac_sha384_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(pbkdf2_hmac_sha384_test_vectors) / sizeof(pbkdf2_hmac_sha384_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(CF_PBKDF2);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", CF_PBKDF2);
            return;
        }

        uint8_t dk[75] = {0}; // derived key buffer

        int expected_valid = (strcmp(pbkdf2_hmac_sha384_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        CF_STATUS status;
        CF_KDF_OPTS *opts = NULL;

        // -----------------------------
        // Initialize KDF options with iteration count if possible
        // -----------------------------
        opts = CF_KDFOpts_InitAlloc(
            NULL, 0,                               // no info field
            NULL, 0,                               // no custom field
            pbkdf2_hmac_sha384_test_vectors[i].iteration_count,
            &status
        );

        if (!opts || status != CF_SUCCESS) {
            printf("PBKDF2 TcId %d FAILED to init options\n", pbkdf2_hmac_sha384_test_vectors[i].tc_id);
            failure = 1;
            goto print_extra;
        }

        // -----------------------------
        // Initialize KDF context
        // -----------------------------
        CF_KDF_CTX *ctx = CF_KDF_InitAlloc(
            kdf,
            opts,
            pbkdf2_hmac_sha384_test_vectors[i].password,
            pbkdf2_hmac_sha384_test_vectors[i].password_len,
            CF_SHA384, // subflag : SHA-1
            &status
        );

        if (!ctx || status != CF_SUCCESS) {
            printf("PBKDF2 TcId %d FAILED to init context\n", pbkdf2_hmac_sha384_test_vectors[i].tc_id);
            failure = 1;
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Derive
        // -----------------------------
        status = CF_KDF_Extract(ctx,
            pbkdf2_hmac_sha384_test_vectors[i].salt,
            pbkdf2_hmac_sha384_test_vectors[i].salt_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("PBKDF2 TcId %d FAILED (extract rejected valid vector)\n",
                   pbkdf2_hmac_sha384_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        status = CF_KDF_Expand(ctx,
            dk,
            pbkdf2_hmac_sha384_test_vectors[i].dk_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("PBKDF2 TcId %d FAILED (expand rejected valid vector)\n",
                   pbkdf2_hmac_sha384_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Compare output
        // -----------------------------
        if (expected_valid &&
            memcmp(dk, pbkdf2_hmac_sha384_test_vectors[i].dk, pbkdf2_hmac_sha384_test_vectors[i].dk_len) != 0) {
            printf("PBKDF2 TcId %d FAILED, derived key mismatch\n",
                   pbkdf2_hmac_sha384_test_vectors[i].tc_id);
            failure = 1;

            printf("Derived DK : ");
            DEMO_print_hex(dk, pbkdf2_hmac_sha384_test_vectors[i].dk_len);

            printf("Expected DK : ");
            DEMO_print_hex(pbkdf2_hmac_sha384_test_vectors[i].dk, pbkdf2_hmac_sha384_test_vectors[i].dk_len);
        }

        CF_KDF_Free(&ctx);
        if (opts)
            CF_KDFOpts_Free(&opts);

print_extra:
        if (failure) {
            total_failures++;

            if (pbkdf2_hmac_sha384_test_vectors[i].comment &&
                pbkdf2_hmac_sha384_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", pbkdf2_hmac_sha384_test_vectors[i].comment);
            }

            if (pbkdf2_hmac_sha384_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < pbkdf2_hmac_sha384_test_vectors[i].flags_len; f++) {
                    printf("%s", pbkdf2_hmac_sha384_test_vectors[i].flags[f]);
                    if (f + 1 < pbkdf2_hmac_sha384_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
        } else {
            total_success++;
        }
    }

    printf("PBKDF2-SHA384 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_pbkdf2_hmac_sha512_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(pbkdf2_hmac_sha512_test_vectors) / sizeof(pbkdf2_hmac_sha512_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_KDF *kdf = CF_KDF_GetByFlag(CF_PBKDF2);
        if (!kdf) {
            printf("Unknown KDF flag %u\n", CF_PBKDF2);
            return;
        }

        uint8_t dk[75] = {0}; // derived key buffer

        int expected_valid = (strcmp(pbkdf2_hmac_sha512_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        CF_STATUS status;
        CF_KDF_OPTS *opts = NULL;

        // -----------------------------
        // Initialize KDF options with iteration count if possible
        // -----------------------------
        opts = CF_KDFOpts_InitAlloc(
            NULL, 0,                               // no info field
            NULL, 0,                               // no custom field
            pbkdf2_hmac_sha512_test_vectors[i].iteration_count,
            &status
        );

        if (!opts || status != CF_SUCCESS) {
            printf("PBKDF2 TcId %d FAILED to init options\n", pbkdf2_hmac_sha512_test_vectors[i].tc_id);
            failure = 1;
            goto print_extra;
        }

        // -----------------------------
        // Initialize KDF context
        // -----------------------------
        CF_KDF_CTX *ctx = CF_KDF_InitAlloc(
            kdf,
            opts,
            pbkdf2_hmac_sha512_test_vectors[i].password,
            pbkdf2_hmac_sha512_test_vectors[i].password_len,
            CF_SHA512, // subflag : SHA-1
            &status
        );

        if (!ctx || status != CF_SUCCESS) {
            printf("PBKDF2 TcId %d FAILED to init context\n", pbkdf2_hmac_sha512_test_vectors[i].tc_id);
            failure = 1;
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Derive
        // -----------------------------
        status = CF_KDF_Extract(ctx,
            pbkdf2_hmac_sha512_test_vectors[i].salt,
            pbkdf2_hmac_sha512_test_vectors[i].salt_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("PBKDF2 TcId %d FAILED (extract rejected valid vector)\n",
                   pbkdf2_hmac_sha512_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        status = CF_KDF_Expand(ctx,
            dk,
            pbkdf2_hmac_sha512_test_vectors[i].dk_len
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("PBKDF2 TcId %d FAILED (expand rejected valid vector)\n",
                   pbkdf2_hmac_sha512_test_vectors[i].tc_id);
            failure = 1;
            CF_KDF_Free(&ctx);
            if (opts)
                CF_KDFOpts_Free(&opts);
            goto print_extra;
        }

        // -----------------------------
        // Compare output
        // -----------------------------
        if (expected_valid &&
            memcmp(dk, pbkdf2_hmac_sha512_test_vectors[i].dk, pbkdf2_hmac_sha512_test_vectors[i].dk_len) != 0) {
            printf("PBKDF2 TcId %d FAILED, derived key mismatch\n",
                   pbkdf2_hmac_sha512_test_vectors[i].tc_id);
            failure = 1;

            printf("Derived DK : ");
            DEMO_print_hex(dk, pbkdf2_hmac_sha512_test_vectors[i].dk_len);

            printf("Expected DK : ");
            DEMO_print_hex(pbkdf2_hmac_sha512_test_vectors[i].dk, pbkdf2_hmac_sha512_test_vectors[i].dk_len);
        }

        CF_KDF_Free(&ctx);
        if (opts)
            CF_KDFOpts_Free(&opts);

print_extra:
        if (failure) {
            total_failures++;

            if (pbkdf2_hmac_sha512_test_vectors[i].comment &&
                pbkdf2_hmac_sha512_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", pbkdf2_hmac_sha512_test_vectors[i].comment);
            }

            if (pbkdf2_hmac_sha512_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < pbkdf2_hmac_sha512_test_vectors[i].flags_len; f++) {
                    printf("%s", pbkdf2_hmac_sha512_test_vectors[i].flags[f]);
                    if (f + 1 < pbkdf2_hmac_sha512_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
        } else {
            total_success++;
        }
    }

    printf("PBKDF2-SHA512 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

#endif // ENABLE_TESTS