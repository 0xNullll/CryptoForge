#include "../../src/internal/config/test_config.h"

#if ENABLE_TESTS

#include "../../vectors/wycheproof/tv_hmac_sha1.h"
#include "../../vectors/wycheproof/tv_hmac_sha224.h"
#include "../../vectors/wycheproof/tv_hmac_sha256.h"
#include "../../vectors/wycheproof/tv_hmac_sha384.h"
#include "../../vectors/wycheproof/tv_hmac_sha512.h"
#include "../../vectors/wycheproof/tv_hmac_sha512_224.h"
#include "../../vectors/wycheproof/tv_hmac_sha512_256.h"
#include "../../vectors/wycheproof/tv_hmac_sha3_224.h"
#include "../../vectors/wycheproof/tv_hmac_sha3_256.h"
#include "../../vectors/wycheproof/tv_hmac_sha3_384.h"
#include "../../vectors/wycheproof/tv_hmac_sha3_512.h"
#include "../../vectors/wycheproof/tv_kmac128_no_customization.h"
#include "../../vectors/wycheproof/tv_kmac256_no_customization.h"
#include "../../vectors/wycheproof/tv_aes_cmac.h"
#include "../../vectors/wycheproof/tv_aes_gmac.h"

void test_hmac_sha1_wycheproof(void) {
    size_t num_test_vectors = sizeof(hmac_sha1_test_vectors) / sizeof(hmac_sha1_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_HMAC);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_HMAC);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        uint8_t tag[CF_SHA1_DIGEST_SIZE] = {0};

        int expected_valid = (strcmp(hmac_sha1_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,   // no opts for HMAC
                                       hmac_sha1_test_vectors[i].key,
                                       hmac_sha1_test_vectors[i].key_len,
                                       CF_SHA1);  // subflags = CF_SHA1

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA1 TcId %d FAILED: CF_MAC_Init failed\n", hmac_sha1_test_vectors[i].tc_id);
#endif
            failure = 1;
            continue;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               hmac_sha1_test_vectors[i].msg,
                               hmac_sha1_test_vectors[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA1 TcId %d FAILED: CF_MAC_Update failed\n", hmac_sha1_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, hmac_sha1_test_vectors[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA1 TcId %d FAILED: CF_MAC_Final failed\n", hmac_sha1_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, hmac_sha1_test_vectors[i].tag, hmac_sha1_test_vectors[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA1 TcId %d FAILED: Tag mismatch (expected valid)\n", hmac_sha1_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match && hmac_sha1_test_vectors[i].tag_len != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA1 TcId %d FAILED: Invalid vector matched output\n", hmac_sha1_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (hmac_sha1_test_vectors[i].comment && hmac_sha1_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hmac_sha1_test_vectors[i].comment);
            }

            if (hmac_sha1_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hmac_sha1_test_vectors[i].flags_len; f++) {
                    printf("%s", hmac_sha1_test_vectors[i].flags[f]);
                    if (f + 1 < hmac_sha1_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, hmac_sha1_test_vectors[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(hmac_sha1_test_vectors[i].tag, hmac_sha1_test_vectors[i].tag_len);

            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);

    }

#if ENABLE_TESTS_VERBOSE
    printf("HMAC-SHA1 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "HMAC-SHA1", total_successes, num_test_vectors, total_failures);
#endif
}

void test_hmac_sha224_wycheproof(void) {
    size_t num_test_vectors = sizeof(hmac_sha224_test_vectors) / sizeof(hmac_sha224_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_HMAC);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_HMAC);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        uint8_t tag[CF_SHA224_DIGEST_SIZE] = {0};

        int expected_valid = (strcmp(hmac_sha224_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,   // no opts for HMAC
                                       hmac_sha224_test_vectors[i].key,
                                       hmac_sha224_test_vectors[i].key_len,
                                       CF_SHA224);  // subflags = CF_SHA224

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA224 TcId %d FAILED: CF_MAC_Init failed\n", hmac_sha224_test_vectors[i].tc_id);
#endif
            failure = 1;
            continue;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               hmac_sha224_test_vectors[i].msg,
                               hmac_sha224_test_vectors[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA224 TcId %d FAILED: CF_MAC_Update failed\n", hmac_sha224_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, hmac_sha224_test_vectors[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA224 TcId %d FAILED: CF_MAC_Final failed\n", hmac_sha224_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, hmac_sha224_test_vectors[i].tag, hmac_sha224_test_vectors[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA224 TcId %d FAILED: Tag mismatch (expected valid)\n", hmac_sha224_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match && hmac_sha224_test_vectors[i].tag_len != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA224 TcId %d FAILED: Invalid vector matched output\n", hmac_sha224_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (hmac_sha224_test_vectors[i].comment && hmac_sha224_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hmac_sha224_test_vectors[i].comment);
            }

            if (hmac_sha224_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hmac_sha224_test_vectors[i].flags_len; f++) {
                    printf("%s", hmac_sha224_test_vectors[i].flags[f]);
                    if (f + 1 < hmac_sha224_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, hmac_sha224_test_vectors[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(hmac_sha224_test_vectors[i].tag, hmac_sha224_test_vectors[i].tag_len);

            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);

    }

#if ENABLE_TESTS_VERBOSE
    printf("HMAC-SHA224 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "HMAC-SHA224", total_successes, num_test_vectors, total_failures);
#endif
}

void test_hmac_sha256_wycheproof(void) {
    size_t num_test_vectors = sizeof(hmac_sha256_test_vectors) / sizeof(hmac_sha256_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_HMAC);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_HMAC);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        uint8_t tag[CF_SHA256_DIGEST_SIZE] = {0};

        int expected_valid = (strcmp(hmac_sha256_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,   // no opts for HMAC
                                       hmac_sha256_test_vectors[i].key,
                                       hmac_sha256_test_vectors[i].key_len,
                                       CF_SHA256);  // subflags = CF_SHA256

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA256 TcId %d FAILED: CF_MAC_Init failed\n", hmac_sha256_test_vectors[i].tc_id);
#endif
            failure = 1;
            continue;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               hmac_sha256_test_vectors[i].msg,
                               hmac_sha256_test_vectors[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA256 TcId %d FAILED: CF_MAC_Update failed\n", hmac_sha256_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, hmac_sha256_test_vectors[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA256 TcId %d FAILED: CF_MAC_Final failed\n", hmac_sha256_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, hmac_sha256_test_vectors[i].tag, hmac_sha256_test_vectors[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA256 TcId %d FAILED: Tag mismatch (expected valid)\n", hmac_sha256_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match && hmac_sha256_test_vectors[i].tag_len != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA256 TcId %d FAILED: Invalid vector matched output\n", hmac_sha256_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (hmac_sha256_test_vectors[i].comment && hmac_sha256_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hmac_sha256_test_vectors[i].comment);
            }

            if (hmac_sha256_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hmac_sha256_test_vectors[i].flags_len; f++) {
                    printf("%s", hmac_sha256_test_vectors[i].flags[f]);
                    if (f + 1 < hmac_sha256_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, hmac_sha256_test_vectors[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(hmac_sha256_test_vectors[i].tag, hmac_sha256_test_vectors[i].tag_len);

            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);

    }

#if ENABLE_TESTS_VERBOSE
    printf("HMAC-SHA256 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "HMAC-SHA256", total_successes, num_test_vectors, total_failures);
#endif
}

void test_hmac_sha384_wycheproof(void) {
    size_t num_test_vectors = sizeof(hmac_sha384_test_vectors) / sizeof(hmac_sha384_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_HMAC);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_HMAC);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        uint8_t tag[CF_SHA384_DIGEST_SIZE] = {0};

        int expected_valid = (strcmp(hmac_sha384_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,   // no opts for HMAC
                                       hmac_sha384_test_vectors[i].key,
                                       hmac_sha384_test_vectors[i].key_len,
                                       CF_SHA384);  // subflags = CF_SHA384

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA384 TcId %d FAILED: CF_MAC_Init failed\n", hmac_sha384_test_vectors[i].tc_id);
#endif
            failure = 1;
            continue;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               hmac_sha384_test_vectors[i].msg,
                               hmac_sha384_test_vectors[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA384 TcId %d FAILED: CF_MAC_Update failed\n", hmac_sha384_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, hmac_sha384_test_vectors[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA384 TcId %d FAILED: CF_MAC_Final failed\n", hmac_sha384_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, hmac_sha384_test_vectors[i].tag, hmac_sha384_test_vectors[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA384 TcId %d FAILED: Tag mismatch (expected valid)\n", hmac_sha384_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match && hmac_sha384_test_vectors[i].tag_len != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA384 TcId %d FAILED: Invalid vector matched output\n", hmac_sha384_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (hmac_sha384_test_vectors[i].comment && hmac_sha384_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hmac_sha384_test_vectors[i].comment);
            }

            if (hmac_sha384_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hmac_sha384_test_vectors[i].flags_len; f++) {
                    printf("%s", hmac_sha384_test_vectors[i].flags[f]);
                    if (f + 1 < hmac_sha384_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, hmac_sha384_test_vectors[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(hmac_sha384_test_vectors[i].tag, hmac_sha384_test_vectors[i].tag_len);

            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);

    }

#if ENABLE_TESTS_VERBOSE
    printf("HMAC-SHA384 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "HMAC-SHA384", total_successes, num_test_vectors, total_failures);
#endif
}

void test_hmac_sha512_wycheproof(void) {
    size_t num_test_vectors = sizeof(hmac_sha512_test_vectors) / sizeof(hmac_sha512_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_HMAC);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_HMAC);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        uint8_t tag[CF_SHA512_DIGEST_SIZE] = {0};

        int expected_valid = (strcmp(hmac_sha512_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,   // no opts for HMAC
                                       hmac_sha512_test_vectors[i].key,
                                       hmac_sha512_test_vectors[i].key_len,
                                       CF_SHA512);  // subflags = CF_SHA512

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512 TcId %d FAILED: CF_MAC_Init failed\n", hmac_sha512_test_vectors[i].tc_id);
#endif
            failure = 1;
            continue;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               hmac_sha512_test_vectors[i].msg,
                               hmac_sha512_test_vectors[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512 TcId %d FAILED: CF_MAC_Update failed\n", hmac_sha512_test_vectors[i].tc_id);
            CF_MAC_Reset(&mac_ctx);
#endif
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, hmac_sha512_test_vectors[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512 TcId %d FAILED: CF_MAC_Final failed\n", hmac_sha512_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, hmac_sha512_test_vectors[i].tag, hmac_sha512_test_vectors[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512 TcId %d FAILED: Tag mismatch (expected valid)\n", hmac_sha512_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match && hmac_sha512_test_vectors[i].tag_len != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512 TcId %d FAILED: Invalid vector matched output\n", hmac_sha512_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (hmac_sha512_test_vectors[i].comment && hmac_sha512_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hmac_sha512_test_vectors[i].comment);
            }

            if (hmac_sha512_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hmac_sha512_test_vectors[i].flags_len; f++) {
                    printf("%s", hmac_sha512_test_vectors[i].flags[f]);
                    if (f + 1 < hmac_sha512_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, hmac_sha512_test_vectors[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(hmac_sha512_test_vectors[i].tag, hmac_sha512_test_vectors[i].tag_len);

            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);

    }

#if ENABLE_TESTS_VERBOSE
    printf("HMAC-SHA512 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "HMAC-SHA512", total_successes, num_test_vectors, total_failures);
#endif
}

void test_hmac_sha512_224_wycheproof(void) {
    size_t num_test_vectors = sizeof(hmac_sha512_224_test_vectors) / sizeof(hmac_sha512_224_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_HMAC);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_HMAC);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        uint8_t tag[CF_SHA512_224_DIGEST_SIZE] = {0};

        int expected_valid = (strcmp(hmac_sha512_224_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,   // no opts for HMAC
                                       hmac_sha512_224_test_vectors[i].key,
                                       hmac_sha512_224_test_vectors[i].key_len,
                                       CF_SHA512_224);  // subflags = CF_SHA512_224

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512_224 TcId %d FAILED: CF_MAC_Init failed\n", hmac_sha512_224_test_vectors[i].tc_id);
#endif
            failure = 1;
            continue;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               hmac_sha512_224_test_vectors[i].msg,
                               hmac_sha512_224_test_vectors[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512_224 TcId %d FAILED: CF_MAC_Update failed\n", hmac_sha512_224_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, hmac_sha512_224_test_vectors[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512_224 TcId %d FAILED: CF_MAC_Final failed\n", hmac_sha512_224_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, hmac_sha512_224_test_vectors[i].tag, hmac_sha512_224_test_vectors[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512_224 TcId %d FAILED: Tag mismatch (expected valid)\n", hmac_sha512_224_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match && hmac_sha512_224_test_vectors[i].tag_len != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512_224 TcId %d FAILED: Invalid vector matched output\n", hmac_sha512_224_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (hmac_sha512_224_test_vectors[i].comment && hmac_sha512_224_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hmac_sha512_224_test_vectors[i].comment);
            }

            if (hmac_sha512_224_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hmac_sha512_224_test_vectors[i].flags_len; f++) {
                    printf("%s", hmac_sha512_224_test_vectors[i].flags[f]);
                    if (f + 1 < hmac_sha512_224_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, hmac_sha512_224_test_vectors[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(hmac_sha512_224_test_vectors[i].tag, hmac_sha512_224_test_vectors[i].tag_len);

            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);

    }

#if ENABLE_TESTS_VERBOSE
    printf("HMAC-SHA512_224 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "HMAC-SHA512_224", total_successes, num_test_vectors, total_failures);
#endif
}

void test_hmac_sha512_256_wycheproof(void) {
    size_t num_test_vectors = sizeof(hmac_sha512_256_test_vectors) / sizeof(hmac_sha512_256_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_HMAC);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_HMAC);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        uint8_t tag[CF_SHA512_256_DIGEST_SIZE] = {0};

        int expected_valid = (strcmp(hmac_sha512_256_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,   // no opts for HMAC
                                       hmac_sha512_256_test_vectors[i].key,
                                       hmac_sha512_256_test_vectors[i].key_len,
                                       CF_SHA512_256);  // subflags = CF_SHA512_256

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512_256 TcId %d FAILED: CF_MAC_Init failed\n", hmac_sha512_256_test_vectors[i].tc_id);
#endif
            failure = 1;
            continue;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               hmac_sha512_256_test_vectors[i].msg,
                               hmac_sha512_256_test_vectors[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512_256 TcId %d FAILED: CF_MAC_Update failed\n", hmac_sha512_256_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, hmac_sha512_256_test_vectors[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512_256 TcId %d FAILED: CF_MAC_Final failed\n", hmac_sha512_256_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, hmac_sha512_256_test_vectors[i].tag, hmac_sha512_256_test_vectors[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512_256 TcId %d FAILED: Tag mismatch (expected valid)\n", hmac_sha512_256_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match && hmac_sha512_256_test_vectors[i].tag_len != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA512_256 TcId %d FAILED: Invalid vector matched output\n", hmac_sha512_256_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (hmac_sha512_256_test_vectors[i].comment && hmac_sha512_256_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hmac_sha512_256_test_vectors[i].comment);
            }

            if (hmac_sha512_256_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hmac_sha512_256_test_vectors[i].flags_len; f++) {
                    printf("%s", hmac_sha512_256_test_vectors[i].flags[f]);
                    if (f + 1 < hmac_sha512_256_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, hmac_sha512_256_test_vectors[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(hmac_sha512_256_test_vectors[i].tag, hmac_sha512_256_test_vectors[i].tag_len);

            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);

    }

#if ENABLE_TESTS_VERBOSE
    printf("HMAC-SHA512_256 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "HMAC-SHA512_256", total_successes, num_test_vectors, total_failures);
#endif
}

void test_hmac_sha3_224_wycheproof(void) {
    size_t num_test_vectors = sizeof(hmac_sha3_224_test_vectors) / sizeof(hmac_sha3_224_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_HMAC);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_HMAC);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        uint8_t tag[CF_SHA3_224_DIGEST_SIZE] = {0};

        int expected_valid = (strcmp(hmac_sha3_224_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,   // no opts for HMAC
                                       hmac_sha3_224_test_vectors[i].key,
                                       hmac_sha3_224_test_vectors[i].key_len,
                                       CF_SHA3_224);  // subflags = CF_SHA3_224

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_224 TcId %d FAILED: CF_MAC_Init failed\n", hmac_sha3_224_test_vectors[i].tc_id);
#endif
            failure = 1;
            continue;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               hmac_sha3_224_test_vectors[i].msg,
                               hmac_sha3_224_test_vectors[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_224 TcId %d FAILED: CF_MAC_Update failed\n", hmac_sha3_224_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, hmac_sha3_224_test_vectors[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_224 TcId %d FAILED: CF_MAC_Final failed\n", hmac_sha3_224_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, hmac_sha3_224_test_vectors[i].tag, hmac_sha3_224_test_vectors[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_224 TcId %d FAILED: Tag mismatch (expected valid)\n", hmac_sha3_224_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match && hmac_sha3_224_test_vectors[i].tag_len != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_224 TcId %d FAILED: Invalid vector matched output\n", hmac_sha3_224_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (hmac_sha3_224_test_vectors[i].comment && hmac_sha3_224_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hmac_sha3_224_test_vectors[i].comment);
            }

            if (hmac_sha3_224_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hmac_sha3_224_test_vectors[i].flags_len; f++) {
                    printf("%s", hmac_sha3_224_test_vectors[i].flags[f]);
                    if (f + 1 < hmac_sha3_224_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, hmac_sha3_224_test_vectors[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(hmac_sha3_224_test_vectors[i].tag, hmac_sha3_224_test_vectors[i].tag_len);

            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);

    }

#if ENABLE_TESTS_VERBOSE
    printf("HMAC-SHA3_224 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "HMAC-SHA3_224", total_successes, num_test_vectors, total_failures);
#endif
}

void test_hmac_sha3_256_wycheproof(void) {
    size_t num_test_vectors = sizeof(hmac_sha3_256_test_vectors) / sizeof(hmac_sha3_256_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_HMAC);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_HMAC);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        uint8_t tag[CF_SHA3_256_DIGEST_SIZE] = {0};

        int expected_valid = (strcmp(hmac_sha3_256_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,   // no opts for HMAC
                                       hmac_sha3_256_test_vectors[i].key,
                                       hmac_sha3_256_test_vectors[i].key_len,
                                       CF_SHA3_256);  // subflags = CF_SHA3_256

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_256 TcId %d FAILED: CF_MAC_Init failed\n", hmac_sha3_256_test_vectors[i].tc_id);
#endif
            failure = 1;
            continue;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               hmac_sha3_256_test_vectors[i].msg,
                               hmac_sha3_256_test_vectors[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_256 TcId %d FAILED: CF_MAC_Update failed\n", hmac_sha3_256_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, hmac_sha3_256_test_vectors[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_256 TcId %d FAILED: CF_MAC_Final failed\n", hmac_sha3_256_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, hmac_sha3_256_test_vectors[i].tag, hmac_sha3_256_test_vectors[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_256 TcId %d FAILED: Tag mismatch (expected valid)\n", hmac_sha3_256_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match && hmac_sha3_256_test_vectors[i].tag_len != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_256 TcId %d FAILED: Invalid vector matched output\n", hmac_sha3_256_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (hmac_sha3_256_test_vectors[i].comment && hmac_sha3_256_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hmac_sha3_256_test_vectors[i].comment);
            }

            if (hmac_sha3_256_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hmac_sha3_256_test_vectors[i].flags_len; f++) {
                    printf("%s", hmac_sha3_256_test_vectors[i].flags[f]);
                    if (f + 1 < hmac_sha3_256_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, hmac_sha3_256_test_vectors[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(hmac_sha3_256_test_vectors[i].tag, hmac_sha3_256_test_vectors[i].tag_len);

            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);

    }

#if ENABLE_TESTS_VERBOSE
    printf("HMAC-SHA3_256 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "HMAC-SHA3_256", total_successes, num_test_vectors, total_failures);
#endif
}

void test_hmac_sha3_384_wycheproof(void) {
    size_t num_test_vectors = sizeof(hmac_sha3_384_test_vectors) / sizeof(hmac_sha3_384_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_HMAC);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_HMAC);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        uint8_t tag[CF_SHA3_384_DIGEST_SIZE] = {0};

        int expected_valid = (strcmp(hmac_sha3_384_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,   // no opts for HMAC
                                       hmac_sha3_384_test_vectors[i].key,
                                       hmac_sha3_384_test_vectors[i].key_len,
                                       CF_SHA3_384);  // subflags = CF_SHA3_384

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_384 TcId %d FAILED: CF_MAC_Init failed\n", hmac_sha3_384_test_vectors[i].tc_id);
#endif
            failure = 1;
            continue;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               hmac_sha3_384_test_vectors[i].msg,
                               hmac_sha3_384_test_vectors[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_384 TcId %d FAILED: CF_MAC_Update failed\n", hmac_sha3_384_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, hmac_sha3_384_test_vectors[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_384 TcId %d FAILED: CF_MAC_Final failed\n", hmac_sha3_384_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, hmac_sha3_384_test_vectors[i].tag, hmac_sha3_384_test_vectors[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_384 TcId %d FAILED: Tag mismatch (expected valid)\n", hmac_sha3_384_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match && hmac_sha3_384_test_vectors[i].tag_len != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_384 TcId %d FAILED: Invalid vector matched output\n", hmac_sha3_384_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (hmac_sha3_384_test_vectors[i].comment && hmac_sha3_384_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hmac_sha3_384_test_vectors[i].comment);
            }

            if (hmac_sha3_384_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hmac_sha3_384_test_vectors[i].flags_len; f++) {
                    printf("%s", hmac_sha3_384_test_vectors[i].flags[f]);
                    if (f + 1 < hmac_sha3_384_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, hmac_sha3_384_test_vectors[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(hmac_sha3_384_test_vectors[i].tag, hmac_sha3_384_test_vectors[i].tag_len);

            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);

    }

#if ENABLE_TESTS_VERBOSE
    printf("HMAC-SHA3_384 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "HMAC-SHA3_384", total_successes, num_test_vectors, total_failures);
#endif
}

void test_hmac_sha3_512_wycheproof(void) {
    size_t num_test_vectors = sizeof(hmac_sha3_512_test_vectors) / sizeof(hmac_sha3_512_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_HMAC);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_HMAC);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        uint8_t tag[CF_SHA3_512_DIGEST_SIZE] = {0};

        int expected_valid = (strcmp(hmac_sha3_512_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,   // no opts for HMAC
                                       hmac_sha3_512_test_vectors[i].key,
                                       hmac_sha3_512_test_vectors[i].key_len,
                                       CF_SHA3_512);  // subflags = CF_SHA3_512

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_512 TcId %d FAILED: CF_MAC_Init failed\n", hmac_sha3_512_test_vectors[i].tc_id);
#endif
            failure = 1;
            continue;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               hmac_sha3_512_test_vectors[i].msg,
                               hmac_sha3_512_test_vectors[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_512 TcId %d FAILED: CF_MAC_Update failed\n", hmac_sha3_512_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, hmac_sha3_512_test_vectors[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_512 TcId %d FAILED: CF_MAC_Final failed\n", hmac_sha3_512_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, hmac_sha3_512_test_vectors[i].tag, hmac_sha3_512_test_vectors[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_512 TcId %d FAILED: Tag mismatch (expected valid)\n", hmac_sha3_512_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match && hmac_sha3_512_test_vectors[i].tag_len != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("HMAC-SHA3_512 TcId %d FAILED: Invalid vector matched output\n", hmac_sha3_512_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (hmac_sha3_512_test_vectors[i].comment && hmac_sha3_512_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", hmac_sha3_512_test_vectors[i].comment);
            }

            if (hmac_sha3_512_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < hmac_sha3_512_test_vectors[i].flags_len; f++) {
                    printf("%s", hmac_sha3_512_test_vectors[i].flags[f]);
                    if (f + 1 < hmac_sha3_512_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, hmac_sha3_512_test_vectors[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(hmac_sha3_512_test_vectors[i].tag, hmac_sha3_512_test_vectors[i].tag_len);

            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);

    }

#if ENABLE_TESTS_VERBOSE
    printf("HMAC-SHA3_512 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "HMAC-SHA3_512", total_successes, num_test_vectors, total_failures);
#endif
}

void test_kmac128_no_customization_wycheproof(void) {
    size_t num_test_vectors = sizeof(kmac128_no_s_test_vector) /
                              sizeof(kmac128_no_s_test_vector[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_KMAC_STD);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_KMAC_STD);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        
        // default tag size for KMAC128 is usually 32 bytes but wycheproof tests tags are 64 bytes 
        uint8_t tag[CF_KMAC_DEFAULT_OUTPUT_LEN_128 * 2] = {0};   

        int expected_valid = (strcmp(kmac128_no_s_test_vector[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Optional Parameters ----------------
        // KMAC128-NO-CUSTOMIZATION has no customization string or IV
        // So we skip CF_MACOpts_Init

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,
                                       kmac128_no_s_test_vector[i].key,
                                       kmac128_no_s_test_vector[i].key_len,
                                       CF_KMAC128); // subflag: KMAC-128
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("KMAC128 TcId %d FAILED: CF_MAC_Init failed\n", kmac128_no_s_test_vector[i].tc_id);
#endif
            failure = 1;
            goto print_extra;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               kmac128_no_s_test_vector[i].msg,
                               kmac128_no_s_test_vector[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("KMAC128 TcId %d FAILED: CF_MAC_Update failed\n", kmac128_no_s_test_vector[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, kmac128_no_s_test_vector[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("KMAC128 TcId %d FAILED: CF_MAC_Final failed\n", kmac128_no_s_test_vector[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, kmac128_no_s_test_vector[i].tag,
                                kmac128_no_s_test_vector[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("KMAC128 TcId %d FAILED: Tag mismatch (expected valid)\n", kmac128_no_s_test_vector[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("KMAC128 TcId %d FAILED: Invalid vector matched output\n", kmac128_no_s_test_vector[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (kmac128_no_s_test_vector[i].comment &&
                kmac128_no_s_test_vector[i].comment[0] != '\0') {
                printf("  Comment: %s\n", kmac128_no_s_test_vector[i].comment);
            }

            if (kmac128_no_s_test_vector[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < kmac128_no_s_test_vector[i].flags_len; f++) {
                    printf("%s", kmac128_no_s_test_vector[i].flags[f]);
                    if (f + 1 < kmac128_no_s_test_vector[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, kmac128_no_s_test_vector[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(kmac128_no_s_test_vector[i].tag,
                           kmac128_no_s_test_vector[i].tag_len);
            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);
    }

#if ENABLE_TESTS_VERBOSE
    printf("KMAC128-No-Customization Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "KMAC128-No-Customization", total_successes, num_test_vectors, total_failures);
#endif
}

void test_kmac256_no_customization_wycheproof(void) {
    size_t num_test_vectors = sizeof(kmac256_no_s_test_vector) /
                              sizeof(kmac256_no_s_test_vector[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_KMAC_STD);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_KMAC_STD);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};

        // default tag size for KMAC128 is usually 64 bytes 
        uint8_t tag[CF_KMAC_DEFAULT_OUTPUT_LEN_256] = {0};

        int expected_valid = (strcmp(kmac256_no_s_test_vector[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Optional Parameters ----------------
        // KMAC256-NO-CUSTOMIZATION has no customization string or IV
        // So we skip CF_MACOpts_Init

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,
                                       kmac256_no_s_test_vector[i].key,
                                       kmac256_no_s_test_vector[i].key_len,
                                       CF_KMAC256); // subflag: KMAC-256
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("KMAC256 TcId %d FAILED: CF_MAC_Init failed\n", kmac256_no_s_test_vector[i].tc_id);
#endif
            failure = 1;
            goto print_extra;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               kmac256_no_s_test_vector[i].msg,
                               kmac256_no_s_test_vector[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("KMAC256 TcId %d FAILED: CF_MAC_Update failed\n", kmac256_no_s_test_vector[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, kmac256_no_s_test_vector[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("KMAC256 TcId %d FAILED: CF_MAC_Final failed\n", kmac256_no_s_test_vector[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, kmac256_no_s_test_vector[i].tag,
                                kmac256_no_s_test_vector[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("KMAC256 TcId %d FAILED: Tag mismatch (expected valid)\n", kmac256_no_s_test_vector[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("KMAC256 TcId %d FAILED: Invalid vector matched output\n", kmac256_no_s_test_vector[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (kmac256_no_s_test_vector[i].comment &&
                kmac256_no_s_test_vector[i].comment[0] != '\0') {
                printf("  Comment: %s\n", kmac256_no_s_test_vector[i].comment);
            }

            if (kmac256_no_s_test_vector[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < kmac256_no_s_test_vector[i].flags_len; f++) {
                    printf("%s", kmac256_no_s_test_vector[i].flags[f]);
                    if (f + 1 < kmac256_no_s_test_vector[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, kmac256_no_s_test_vector[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(kmac256_no_s_test_vector[i].tag,
                           kmac256_no_s_test_vector[i].tag_len);
            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);
    }

#if ENABLE_TESTS_VERBOSE
    printf("KMAC256-No-Customization Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "KMAC256-No-Customization", total_successes, num_test_vectors, total_failures);
#endif
}

void test_aes_cmac_wycheproof(void) {
    size_t num_test_vectors = sizeof(aes_cmac_test_vectors) / sizeof(aes_cmac_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_AES_CMAC);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_AES_CMAC);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        uint8_t tag[16] = {0};

        int expected_valid = (strcmp(aes_cmac_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       NULL,   // no opts for CMAC
                                       aes_cmac_test_vectors[i].key,
                                       aes_cmac_test_vectors[i].key_len,
                                       0);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-CMAC TcId %d FAILED: CF_MAC_Init failed\n", aes_cmac_test_vectors[i].tc_id);
#endif
            failure = 1;
            goto print_extra;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               aes_cmac_test_vectors[i].msg,
                               aes_cmac_test_vectors[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-CMAC TcId %d FAILED: CF_MAC_Update failed\n", aes_cmac_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, aes_cmac_test_vectors[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-CMAC TcId %d FAILED: CF_MAC_Final failed\n", aes_cmac_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, aes_cmac_test_vectors[i].tag, aes_cmac_test_vectors[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-CMAC TcId %d FAILED: Tag mismatch (expected valid)\n", aes_cmac_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match && aes_cmac_test_vectors[i].tag_len != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-CMAC TcId %d FAILED: Invalid vector matched output\n", aes_cmac_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (aes_cmac_test_vectors[i].comment && aes_cmac_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", aes_cmac_test_vectors[i].comment);
            }

            if (aes_cmac_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < aes_cmac_test_vectors[i].flags_len; f++) {
                    printf("%s", aes_cmac_test_vectors[i].flags[f]);
                    if (f + 1 < aes_cmac_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, aes_cmac_test_vectors[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(aes_cmac_test_vectors[i].tag, aes_cmac_test_vectors[i].tag_len);

            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);
    }

#if ENABLE_TESTS_VERBOSE
    printf("AES-CMAC Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "AES-CMAC", total_successes, num_test_vectors, total_failures);
#endif
}

void test_aes_gmac_wycheproof(void) {
    size_t num_test_vectors = sizeof(aes_gmac_test_vectors) / sizeof(aes_gmac_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(CF_AES_GMAC);
        if (!mac) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown MAC flag %u\n", CF_AES_GMAC);
#endif
            continue;
        }

        CF_MAC_CTX mac_ctx = {0};
        CF_MAC_OPTS opts = {0};        // optional IV / extras
        uint8_t tag[16] = {0};


        int expected_valid = (strcmp(aes_gmac_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Optional Parameters ----------------
        if (aes_gmac_test_vectors[i].iv_len > 0) {
            CF_STATUS opt_status = CF_MACOpts_Init(&opts,
                                                   aes_gmac_test_vectors[i].iv, aes_gmac_test_vectors[i].iv_len,
                                                   NULL, 0);  // custom data currently unused
            if (opt_status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
                printf("AES-GMAC TcId %d FAILED: CF_MACOpts_Init failed\n", aes_gmac_test_vectors[i].tc_id);
#endif
                failure = 1;
                goto print_extra;
            }
        }

        // ---------------- Initialize MAC ----------------
        CF_STATUS status = CF_MAC_Init(&mac_ctx,
                                       mac,
                                       &opts,
                                       aes_gmac_test_vectors[i].key,
                                       aes_gmac_test_vectors[i].key_len,
                                       0);

        if (status != CF_SUCCESS  && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-GMAC TcId %d FAILED: CF_MAC_Init failed\n", aes_gmac_test_vectors[i].tc_id);
#endif
            failure = 1;
            goto print_extra;
        }

        // ---------------- Update MAC ----------------
        status = CF_MAC_Update(&mac_ctx,
                               aes_gmac_test_vectors[i].msg,
                               aes_gmac_test_vectors[i].msg_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-GMAC TcId %d FAILED: CF_MAC_Update failed\n", aes_gmac_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Finalize MAC ----------------
        status = CF_MAC_Final(&mac_ctx, tag, aes_gmac_test_vectors[i].tag_len);
        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-GMAC TcId %d FAILED: CF_MAC_Final failed\n", aes_gmac_test_vectors[i].tc_id);
#endif
            CF_MAC_Reset(&mac_ctx);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Verify Output ----------------
        int tag_match = (memcmp(tag, aes_gmac_test_vectors[i].tag, aes_gmac_test_vectors[i].tag_len) == 0);

        if (expected_valid && !tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-GMAC TcId %d FAILED: Tag mismatch (expected valid)\n", aes_gmac_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

        if (!expected_valid && tag_match) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-GMAC TcId %d FAILED: Invalid vector matched output\n", aes_gmac_test_vectors[i].tc_id);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (aes_gmac_test_vectors[i].comment && aes_gmac_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", aes_gmac_test_vectors[i].comment);
            }

            if (aes_gmac_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < aes_gmac_test_vectors[i].flags_len; f++) {
                    printf("%s", aes_gmac_test_vectors[i].flags[f]);
                    if (f + 1 < aes_gmac_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("  Computed Tag: ");
            DEMO_print_hex(tag, aes_gmac_test_vectors[i].tag_len);
            printf("  Expected Tag: ");
            DEMO_print_hex(aes_gmac_test_vectors[i].tag, aes_gmac_test_vectors[i].tag_len);

            printf("\n");
#endif
        } else {
            total_successes++;
        }

        CF_MAC_Reset(&mac_ctx);
        CF_MACOpts_Reset(&opts);
    }

#if ENABLE_TESTS_VERBOSE
    printf("AES-GMAC Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "AES-GMAC", total_successes, num_test_vectors, total_failures);
#endif
}

#endif // ENABLE_TESTS