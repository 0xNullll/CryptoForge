#include "../../src/internal/config/test_config.h"

#if ENABLE_TESTS

#include "../../vectors/wycheproof/tv_aes_gcm.h"
#include "../../vectors/wycheproof/tv_chacha20_poly1305.h"
#include "../../vectors/wycheproof/tv_xchacha20_poly1305.h"

void test_aes_gcm_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(aes_gcm_test_vectors) / sizeof(aes_gcm_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_AEAD *aead = CF_AEAD_GetByFlag(CF_AES_GCM);
        if (!aead) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown Cipher flag %u\n", CF_AES_GCM);
#endif
            return;
        }

        uint8_t ct[600]  = {0};
        size_t ct_len;
        uint8_t dec[600] = {0};
        size_t dec_len;
        uint8_t tag[16]  = {0};

        int expected_valid = (strcmp(aes_gcm_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        /* ================= Encrypt ================= */

        CF_STATUS status = CF_AEAD_Encrypt(
            aead,
            aes_gcm_test_vectors[i].key, aes_gcm_test_vectors[i].key_len,
            aes_gcm_test_vectors[i].iv_len != 0 ? aes_gcm_test_vectors[i].iv : NULL,  aes_gcm_test_vectors[i].iv_len,
            aes_gcm_test_vectors[i].aad_len != 0 ? aes_gcm_test_vectors[i].aad : NULL, aes_gcm_test_vectors[i].aad_len,
            aes_gcm_test_vectors[i].msg_len != 0 ? aes_gcm_test_vectors[i].msg : NULL, aes_gcm_test_vectors[i].msg_len,
            ct, &ct_len, tag, sizeof(tag)
        );

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-GCM TcId %d FAILED (encrypt rejected valid vector)\n",
                   aes_gcm_test_vectors[i].tc_id);
#endif
            failure = 1;
            goto print_extra;
        }

        int ct_match =
            (aes_gcm_test_vectors[i].ct_len == aes_gcm_test_vectors[i].msg_len) &&
            (memcmp(ct, aes_gcm_test_vectors[i].ct, ct_len) == 0);

        int tag_match =
            (memcmp(tag, aes_gcm_test_vectors[i].tag, aes_gcm_test_vectors[i].tag_len) == 0);
            if (expected_valid && (!ct_match || !tag_match)) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-GCM TcId %d FAILED, Error code %u (expected valid)\n",
                aes_gcm_test_vectors[i].tc_id, status);

            if (!ct_match)
                printf("  Ciphertext mismatch\n");

            if (!tag_match)
                printf("  Tag mismatch\n");

            printf("CT : ");
            DEMO_print_hex(ct, ct_len);

            printf("Expected CT : ");
            DEMO_print_hex(aes_gcm_test_vectors[i].ct, aes_gcm_test_vectors[i].ct_len);

            printf("TAG : ");
            DEMO_print_hex(tag, aes_gcm_test_vectors[i].tag_len);
            printf("Expected TAG : ");
            DEMO_print_hex(aes_gcm_test_vectors[i].tag, aes_gcm_test_vectors[i].tag_len);
#endif
            failure = 1;
        }

        /* ================= Decrypt ================= */

        status = CF_AEAD_Decrypt(
            aead,
            aes_gcm_test_vectors[i].key, aes_gcm_test_vectors[i].key_len,
            aes_gcm_test_vectors[i].iv_len != 0 ? aes_gcm_test_vectors[i].iv : NULL,  aes_gcm_test_vectors[i].iv_len,
            aes_gcm_test_vectors[i].aad_len != 0 ? aes_gcm_test_vectors[i].aad : NULL, aes_gcm_test_vectors[i].aad_len,
            aes_gcm_test_vectors[i].ct_len != 0 ? ct : NULL, aes_gcm_test_vectors[i].ct_len,
            dec, &dec_len,
            (uint8_t *)aes_gcm_test_vectors[i].tag, aes_gcm_test_vectors[i].tag_len
        );

        int decrypt_success = (status == CF_SUCCESS);

        if ((expected_valid && !decrypt_success) ||
            (!expected_valid && decrypt_success)) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-GCM TcId %d FAILED, error code %u\n",
                   aes_gcm_test_vectors[i].tc_id, status);
#endif
            failure = 1;
        }

        if (expected_valid && decrypt_success &&
            memcmp(dec, aes_gcm_test_vectors[i].msg, dec_len) != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("AES-GCM TcId %d FAILED, Error code %u (decrypted plaintext mismatch)\n",
                   aes_gcm_test_vectors[i].tc_id, status);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (aes_gcm_test_vectors[i].comment &&
                aes_gcm_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", aes_gcm_test_vectors[i].comment);
            }

            if (aes_gcm_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < aes_gcm_test_vectors[i].flags_len; f++) {
                    printf("%s", aes_gcm_test_vectors[i].flags[f]);
                    if (f + 1 < aes_gcm_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
#endif
        } else {
            total_successes++;
        }
    }

#if ENABLE_TESTS_VERBOSE
    printf("AES-GCM Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "AES-GCM", total_successes, num_test_vectors, total_failures);
#endif
}

void test_chacha20_poly1305_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(chacha20_poly1305_test_vectors) / sizeof(chacha20_poly1305_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_AEAD *aead = CF_AEAD_GetByFlag(CF_CHACHA20_POLY1305);
        if (!aead) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown Cipher flag %u\n", CF_CHACHA20_POLY1305);
#endif
            return;
        }

        uint8_t ct[520]  = {0};
        size_t ct_len;
        uint8_t dec[520] = {0};
        size_t dec_len;
        uint8_t tag[16]  = {0};

        int expected_valid = (strcmp(chacha20_poly1305_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        /* ================= Encrypt ================= */

        CF_STATUS status = CF_AEAD_Encrypt(
            aead,
            chacha20_poly1305_test_vectors[i].key, chacha20_poly1305_test_vectors[i].key_len,
            chacha20_poly1305_test_vectors[i].iv_len != 0 ? chacha20_poly1305_test_vectors[i].iv : NULL, chacha20_poly1305_test_vectors[i].iv_len,
            chacha20_poly1305_test_vectors[i].aad_len != 0 ? chacha20_poly1305_test_vectors[i].aad : NULL, chacha20_poly1305_test_vectors[i].aad_len,
            chacha20_poly1305_test_vectors[i].msg_len != 0 ? chacha20_poly1305_test_vectors[i].msg : NULL, chacha20_poly1305_test_vectors[i].msg_len,
            ct, &ct_len, tag, sizeof(tag)
        );

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("ChaCha20-Poly1305 TcId %d FAILED (encrypt rejected valid vector)\n",
                   chacha20_poly1305_test_vectors[i].tc_id);
#endif
            failure = 1;
            goto print_extra;
        }

        int ct_match =
            (chacha20_poly1305_test_vectors[i].ct_len == chacha20_poly1305_test_vectors[i].msg_len) &&
            (memcmp(ct, chacha20_poly1305_test_vectors[i].ct, ct_len) == 0);

        int tag_match =
            (memcmp(tag, chacha20_poly1305_test_vectors[i].tag, chacha20_poly1305_test_vectors[i].tag_len) == 0);

        if (expected_valid && (!ct_match || !tag_match)) {
#if ENABLE_TESTS_VERBOSE
            printf("ChaCha20-Poly1305 TcId %d FAILED, Error code %u (expected valid)\n",
                   chacha20_poly1305_test_vectors[i].tc_id, status);

            if (!ct_match)
                printf("  Ciphertext mismatch\n");

            if (!tag_match)
                printf("  Tag mismatch\n");

            printf("CT : ");
            DEMO_print_hex(ct, ct_len);

            printf("Expected CT : ");
            DEMO_print_hex(chacha20_poly1305_test_vectors[i].ct, chacha20_poly1305_test_vectors[i].ct_len);

            printf("TAG : ");
            DEMO_print_hex(tag, chacha20_poly1305_test_vectors[i].tag_len);
            printf("Expected TAG : ");
            DEMO_print_hex(chacha20_poly1305_test_vectors[i].tag, chacha20_poly1305_test_vectors[i].tag_len);
#endif
            failure = 1;
        }

        /* ================= Decrypt ================= */

        status = CF_AEAD_Decrypt(
            aead,
            chacha20_poly1305_test_vectors[i].key, chacha20_poly1305_test_vectors[i].key_len,
            chacha20_poly1305_test_vectors[i].iv_len != 0 ? chacha20_poly1305_test_vectors[i].iv : NULL, chacha20_poly1305_test_vectors[i].iv_len,
            chacha20_poly1305_test_vectors[i].aad_len != 0 ? chacha20_poly1305_test_vectors[i].aad : NULL, chacha20_poly1305_test_vectors[i].aad_len,
            chacha20_poly1305_test_vectors[i].ct_len != 0 ? ct : NULL, chacha20_poly1305_test_vectors[i].ct_len,
            dec, &dec_len,
            (uint8_t *)chacha20_poly1305_test_vectors[i].tag, chacha20_poly1305_test_vectors[i].tag_len
        );

        int decrypt_success = (status == CF_SUCCESS);

        if ((expected_valid && !decrypt_success) ||
            (!expected_valid && decrypt_success)) {
#if ENABLE_TESTS_VERBOSE
            printf("ChaCha20-Poly1305 TcId %d FAILED, error code %u\n",
                   chacha20_poly1305_test_vectors[i].tc_id, status);
#endif
            failure = 1;
        }

        if (expected_valid && decrypt_success &&
            memcmp(dec, chacha20_poly1305_test_vectors[i].msg, dec_len) != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("ChaCha20-Poly1305 TcId %d FAILED, Error code %u (decrypted plaintext mismatch)\n",
                   chacha20_poly1305_test_vectors[i].tc_id, status);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (chacha20_poly1305_test_vectors[i].comment &&
                chacha20_poly1305_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", chacha20_poly1305_test_vectors[i].comment);
            }

            if (chacha20_poly1305_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < chacha20_poly1305_test_vectors[i].flags_len; f++) {
                    printf("%s", chacha20_poly1305_test_vectors[i].flags[f]);
                    if (f + 1 < chacha20_poly1305_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
#endif
        } else {
            total_successes++;
        }
    }

#if ENABLE_TESTS_VERBOSE
    printf("ChaCha20-Poly1305 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "ChaCha20-Poly1305", total_successes, num_test_vectors, total_failures);
#endif
}

void test_xchacha20_poly1305_wycheproof(void) {
    size_t num_test_vectors =
        sizeof(xchacha20_poly1305_test_vectors) / sizeof(xchacha20_poly1305_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_AEAD *aead = CF_AEAD_GetByFlag(CF_XCHACHA20_POLY1305);
        if (!aead) {
#if ENABLE_TESTS_VERBOSE
            printf("Unknown Cipher flag %u\n", CF_XCHACHA20_POLY1305);
#endif
            return;
        }

        uint8_t ct[520]  = {0};
        size_t ct_len;
        uint8_t dec[520] = {0};
        size_t dec_len;
        uint8_t tag[16]  = {0};

        int expected_valid = (strcmp(xchacha20_poly1305_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        /* ================= Encrypt ================= */

        CF_STATUS status = CF_AEAD_Encrypt(
            aead,
            xchacha20_poly1305_test_vectors[i].key, xchacha20_poly1305_test_vectors[i].key_len,
            xchacha20_poly1305_test_vectors[i].iv_len != 0 ? xchacha20_poly1305_test_vectors[i].iv : NULL, xchacha20_poly1305_test_vectors[i].iv_len,
            xchacha20_poly1305_test_vectors[i].aad_len != 0 ? xchacha20_poly1305_test_vectors[i].aad : NULL, xchacha20_poly1305_test_vectors[i].aad_len,
            xchacha20_poly1305_test_vectors[i].msg_len != 0 ? xchacha20_poly1305_test_vectors[i].msg : NULL, xchacha20_poly1305_test_vectors[i].msg_len,
            ct, &ct_len, tag, sizeof(tag)
        );

        if (status != CF_SUCCESS && expected_valid) {
#if ENABLE_TESTS_VERBOSE
            printf("XChaCha20-Poly1305 TcId %d FAILED (encrypt rejected valid vector)\n",
                   xchacha20_poly1305_test_vectors[i].tc_id);
#endif
            failure = 1;
            goto print_extra;
        }

        int ct_match =
            (xchacha20_poly1305_test_vectors[i].ct_len == xchacha20_poly1305_test_vectors[i].msg_len) &&
            (memcmp(ct, xchacha20_poly1305_test_vectors[i].ct, ct_len) == 0);

        int tag_match =
            (memcmp(tag, xchacha20_poly1305_test_vectors[i].tag, xchacha20_poly1305_test_vectors[i].tag_len) == 0);

        if (expected_valid && (!ct_match || !tag_match)) {
#if ENABLE_TESTS_VERBOSE
            printf("XChaCha20-Poly1305 TcId %d FAILED, Error code %u (expected valid)\n",
                   xchacha20_poly1305_test_vectors[i].tc_id, status);

            if (!ct_match)
                printf("  Ciphertext mismatch\n");

            if (!tag_match)
                printf("  Tag mismatch\n");

            printf("CT : ");
            DEMO_print_hex(ct, ct_len);

            printf("Expected CT : ");
            DEMO_print_hex(xchacha20_poly1305_test_vectors[i].ct, xchacha20_poly1305_test_vectors[i].ct_len);

            printf("TAG : ");
            DEMO_print_hex(tag, xchacha20_poly1305_test_vectors[i].tag_len);
            printf("Expected TAG : ");
            DEMO_print_hex(xchacha20_poly1305_test_vectors[i].tag, xchacha20_poly1305_test_vectors[i].tag_len);
#endif
            failure = 1;
        }

        /* ================= Decrypt ================= */

        status = CF_AEAD_Decrypt(
            aead,
            xchacha20_poly1305_test_vectors[i].key, xchacha20_poly1305_test_vectors[i].key_len,
            xchacha20_poly1305_test_vectors[i].iv_len != 0 ? xchacha20_poly1305_test_vectors[i].iv : NULL, xchacha20_poly1305_test_vectors[i].iv_len,
            xchacha20_poly1305_test_vectors[i].aad_len != 0 ? xchacha20_poly1305_test_vectors[i].aad : NULL, xchacha20_poly1305_test_vectors[i].aad_len,
            xchacha20_poly1305_test_vectors[i].ct_len != 0 ? ct : NULL, xchacha20_poly1305_test_vectors[i].ct_len,
            dec, &dec_len,
            (uint8_t *)xchacha20_poly1305_test_vectors[i].tag, xchacha20_poly1305_test_vectors[i].tag_len
        );

        int decrypt_success = (status == CF_SUCCESS);

        if ((expected_valid && !decrypt_success) ||
            (!expected_valid && decrypt_success)) {
#if ENABLE_TESTS_VERBOSE
            printf("XChaCha20-Poly1305 TcId %d FAILED, error code %u\n",
                   xchacha20_poly1305_test_vectors[i].tc_id, status);
#endif
            failure = 1;
        }

        if (expected_valid && decrypt_success &&
            memcmp(dec, xchacha20_poly1305_test_vectors[i].msg, dec_len) != 0) {
#if ENABLE_TESTS_VERBOSE
            printf("XChaCha20-Poly1305 TcId %d FAILED, Error code %u (decrypted plaintext mismatch)\n",
                   xchacha20_poly1305_test_vectors[i].tc_id, status);
#endif
            failure = 1;
        }

print_extra:
        if (failure) {
            total_failures++;

#if ENABLE_TESTS_VERBOSE
            if (xchacha20_poly1305_test_vectors[i].comment &&
                xchacha20_poly1305_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", xchacha20_poly1305_test_vectors[i].comment);
            }

            if (xchacha20_poly1305_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < xchacha20_poly1305_test_vectors[i].flags_len; f++) {
                    printf("%s", xchacha20_poly1305_test_vectors[i].flags[f]);
                    if (f + 1 < xchacha20_poly1305_test_vectors[i].flags_len)
                        printf(", ");
                }
                printf("\n");
            }

            printf("\n");
#endif
        } else {
            total_successes++;
        }
    }

#if ENABLE_TESTS_VERBOSE
    printf("XChaCha20-Poly1305 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
#else
    printf("  %-25s %zu/%zu passed, %zu failed\n", "XChaCha20-Poly1305", total_successes, num_test_vectors, total_failures);
#endif
}

#endif // ENABLE_TESTS