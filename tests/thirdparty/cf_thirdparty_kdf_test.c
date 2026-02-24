#include "../../src/CryptoForge/include/config/test_config.h"

#if ENABLE_TESTS

#include "../../vectors/wycheproof/tv_hkdf_sha1.h"
#include "../../vectors/wycheproof/tv_hkdf_sha256.h"
#include "../../vectors/wycheproof/tv_hkdf_sha384.h"
#include "../../vectors/wycheproof/tv_hkdf_sha512.h"
#include "../../vectors/wycheproof/tv_pbkdf2_hmac_sha1.h"
#include "../../vectors/wycheproof/tv_pbkdf2_hmac_sha224.h"
#include "../../vectors/wycheproof/tv_pbkdf2_hmac_sha256.h"
#include "../../vectors/wycheproof/tv_pbkdf2_hmac_sha384.h"
#include "../../vectors/wycheproof/tv_pbkdf2_hmac_sha512.h"

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