#include "../../src/CryptoForge/include/config/test_config.h"

#if ENABLE_TESTS

#include "../../vectors/NIST/KAT/tv_aes_ecb.h"
#include "../../vectors/NIST/KAT/tv_aes_cbc.h"
#include "../../vectors/NIST/KAT/tv_aes_cfb8.h"
#include "../../vectors/NIST/KAT/tv_aes_cfb128.h"
#include "../../vectors/NIST/KAT/tv_aes_ofb.h"

#include "../../vectors/wycheproof/tv_aes_cbc_pkcs5.h"

void test_aes_ecb_kat(void) {
    size_t num_test_vectors = sizeof(ecb_kat_test_vectors) / sizeof(ecb_kat_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(CF_AES_ECB); // assuming AES-ECB
        if (!cipher) {
            printf("Unknown Cipher flag for test vector %d\n", ecb_kat_test_vectors[i].tc_id);
            return;
        }

        CF_CIPHER_OPTS opts = {0};

        uint8_t out[16] = {0};
        size_t out_len;
        int failure = 0;
        int encrypt_mode = (strcmp(ecb_kat_test_vectors[i].mode, "ENCRYPT") == 0);

        CF_STATUS status = CF_CipherOpts_Init(&opts, NULL, 0, NULL, 0);
        if (encrypt_mode) {
            status = CF_Cipher_Encrypt(
                cipher,
                ecb_kat_test_vectors[i].key, ecb_kat_test_vectors[i].key_len,
                ecb_kat_test_vectors[i].msg, ecb_kat_test_vectors[i].msg_len,
                out,
                &out_len,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, ecb_kat_test_vectors[i].ct, ecb_kat_test_vectors[i].ct_len) != 0) {
                printf("AES-ECB TcId %d FAILED (encryption mismatch)\n", ecb_kat_test_vectors[i].tc_id);
                printf("Expected CT: ");
                DEMO_print_hex(ecb_kat_test_vectors[i].ct, ecb_kat_test_vectors[i].ct_len);
                printf("Computed CT: ");
                DEMO_print_hex(out, ecb_kat_test_vectors[i].ct_len);
                failure = 1;
            }
        } else { // DECRYPT
            status = CF_Cipher_Decrypt(
                cipher,
                ecb_kat_test_vectors[i].key, ecb_kat_test_vectors[i].key_len,
                ecb_kat_test_vectors[i].ct, ecb_kat_test_vectors[i].ct_len,
                out,
                &out_len,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, ecb_kat_test_vectors[i].msg, ecb_kat_test_vectors[i].msg_len) != 0) {
                printf("AES-ECB TcId %d FAILED (decryption mismatch)\n", ecb_kat_test_vectors[i].tc_id);
                printf("Expected PT: ");
                DEMO_print_hex(ecb_kat_test_vectors[i].msg, ecb_kat_test_vectors[i].msg_len);
                printf("Computed PT: ");
                DEMO_print_hex(out, ecb_kat_test_vectors[i].msg_len);
                failure = 1;
            }
        }

        if (failure) {
            if (ecb_kat_test_vectors[i].comment && ecb_kat_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", ecb_kat_test_vectors[i].comment);
            }
            total_failures++;
        } else {
            total_success++;
        }
    }

    printf("AES-ECB KAT tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_aes_cbc_kat(void) {
    size_t num_test_vectors = sizeof(cbc_kat_test_vectors) / sizeof(cbc_kat_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(CF_AES_CBC); // assuming AES-CBC
        if (!cipher) {
            printf("Unknown Cipher flag for test vector %d\n", cbc_kat_test_vectors[i].tc_id);
            return;
        }

        uint8_t out[16] = {0};
        size_t out_len;
        int failure = 0;
        int encrypt_mode = (strcmp(cbc_kat_test_vectors[i].mode, "ENCRYPT") == 0);

        CF_CIPHER_OPTS opts = {0};
        CF_STATUS status = CF_CipherOpts_Init(
            &opts,
            cbc_kat_test_vectors[i].iv,
            cbc_kat_test_vectors[i].iv_len,
            NULL, // No AES Counter for AES-CBC
            0);  // No ChaCha counter for AES-CBC

        if (encrypt_mode) {
            status = CF_Cipher_Encrypt(
                cipher,
                cbc_kat_test_vectors[i].key, cbc_kat_test_vectors[i].key_len,
                cbc_kat_test_vectors[i].msg, cbc_kat_test_vectors[i].msg_len,
                out,
                &out_len,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, cbc_kat_test_vectors[i].ct, cbc_kat_test_vectors[i].ct_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("AES-CBC TcId %d FAILED (encryption mismatch)\n", cbc_kat_test_vectors[i].tc_id);
                printf("Expected CT: ");
                DEMO_print_hex(cbc_kat_test_vectors[i].ct, cbc_kat_test_vectors[i].ct_len);
                printf("Computed CT: ");
                DEMO_print_hex(out, cbc_kat_test_vectors[i].ct_len);
                failure = 1;
            }
        } else { // DECRYPT
            status = CF_Cipher_Decrypt(
                cipher,
                cbc_kat_test_vectors[i].key, cbc_kat_test_vectors[i].key_len,
                cbc_kat_test_vectors[i].ct, cbc_kat_test_vectors[i].ct_len,
                out,
                &out_len,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, cbc_kat_test_vectors[i].msg, cbc_kat_test_vectors[i].msg_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("AES-CBC TcId %d FAILED (decryption mismatch)\n", cbc_kat_test_vectors[i].tc_id);
                printf("Expected PT: ");
                DEMO_print_hex(cbc_kat_test_vectors[i].msg, cbc_kat_test_vectors[i].msg_len);
                printf("Computed PT: ");
                DEMO_print_hex(out, cbc_kat_test_vectors[i].msg_len);
                failure = 1;
            }
        }

        if (failure) {
            if (cbc_kat_test_vectors[i].comment && cbc_kat_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", cbc_kat_test_vectors[i].comment);
            }
            total_failures++;
        } else {
            total_success++;
        }

        CF_CipherOpts_Reset(&opts);
    }

    printf("AES-CBC KAT tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_aes_cfb8_kat(void) {
    size_t num_test_vectors = sizeof(cfb8_kat_test_vectors) / sizeof(cfb8_kat_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(CF_AES_CFB8); // assuming AES-CFB8
        if (!cipher) {
            printf("Unknown Cipher flag for test vector %d\n", cfb8_kat_test_vectors[i].tc_id);
            return;
        }

        uint8_t out[16] = {0};
        size_t out_len;
        int failure = 0;
        int encrypt_mode = (strcmp(cfb8_kat_test_vectors[i].mode, "ENCRYPT") == 0);

        CF_CIPHER_OPTS opts = {0};
        CF_STATUS status = CF_CipherOpts_Init(
            &opts,
            cfb8_kat_test_vectors[i].iv,
            cfb8_kat_test_vectors[i].iv_len,
            NULL, // No AES Counter for AES-CFB8
            0);  // No ChaCha counter for AES-CFB8

        if (encrypt_mode) {
            status = CF_Cipher_Encrypt(
                cipher,
                cfb8_kat_test_vectors[i].key, cfb8_kat_test_vectors[i].key_len,
                cfb8_kat_test_vectors[i].msg, cfb8_kat_test_vectors[i].msg_len,
                out,
                &out_len,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, cfb8_kat_test_vectors[i].ct, cfb8_kat_test_vectors[i].ct_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("AES-CFB8 TcId %d FAILED (encryption mismatch)\n", cfb8_kat_test_vectors[i].tc_id);
                printf("Expected CT: ");
                DEMO_print_hex(cfb8_kat_test_vectors[i].ct, cfb8_kat_test_vectors[i].ct_len);
                printf("Computed CT: ");
                DEMO_print_hex(out, cfb8_kat_test_vectors[i].ct_len);
                failure = 1;
            }
        } else { // DECRYPT
            status = CF_Cipher_Decrypt(
                cipher,
                cfb8_kat_test_vectors[i].key, cfb8_kat_test_vectors[i].key_len,
                cfb8_kat_test_vectors[i].ct, cfb8_kat_test_vectors[i].ct_len,
                out,
                &out_len,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, cfb8_kat_test_vectors[i].msg, cfb8_kat_test_vectors[i].msg_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("AES-CFB8 TcId %d FAILED (decryption mismatch)\n", cfb8_kat_test_vectors[i].tc_id);
                printf("Expected PT: ");
                DEMO_print_hex(cfb8_kat_test_vectors[i].msg, cfb8_kat_test_vectors[i].msg_len);
                printf("Computed PT: ");
                DEMO_print_hex(out, cfb8_kat_test_vectors[i].msg_len);
                failure = 1;
            }
        }

        if (failure) {
            if (cfb8_kat_test_vectors[i].comment && cfb8_kat_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", cfb8_kat_test_vectors[i].comment);
            }
            total_failures++;
        } else {
            total_success++;
        }

        CF_CipherOpts_Reset(&opts);
    }

    printf("AES-CFB8 KAT tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_aes_cfb128_kat(void) {
    size_t num_test_vectors = sizeof(cfb128_kat_test_vectors) / sizeof(cfb128_kat_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(CF_AES_CFB128); // assuming AES-CFB128
        if (!cipher) {
            printf("Unknown Cipher flag for test vector %d\n", cfb128_kat_test_vectors[i].tc_id);
            return;
        }

        uint8_t out[16] = {0};
        size_t out_len;
        int failure = 0;
        int encrypt_mode = (strcmp(cfb128_kat_test_vectors[i].mode, "ENCRYPT") == 0);

        CF_CIPHER_OPTS opts = {0};
        CF_STATUS status = CF_CipherOpts_Init(
            &opts,
            cfb128_kat_test_vectors[i].iv,
            cfb128_kat_test_vectors[i].iv_len,
            NULL, // No AES Counter for AES-CFB128
            0);   // No ChaCha counter for AES-CFB128

        if (encrypt_mode) {
            status = CF_Cipher_Encrypt(
                cipher,
                cfb128_kat_test_vectors[i].key, cfb128_kat_test_vectors[i].key_len,
                cfb128_kat_test_vectors[i].msg, cfb128_kat_test_vectors[i].msg_len,
                out,
                &out_len,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, cfb128_kat_test_vectors[i].ct, cfb128_kat_test_vectors[i].ct_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("AES-CFB128 TcId %d FAILED (encryption mismatch)\n", cfb128_kat_test_vectors[i].tc_id);
                printf("Expected CT: ");
                DEMO_print_hex(cfb128_kat_test_vectors[i].ct, cfb128_kat_test_vectors[i].ct_len);
                printf("Computed CT: ");
                DEMO_print_hex(out, cfb128_kat_test_vectors[i].ct_len);
                failure = 1;
            }
        } else { // DECRYPT
            status = CF_Cipher_Decrypt(
                cipher,
                cfb128_kat_test_vectors[i].key, cfb128_kat_test_vectors[i].key_len,
                cfb128_kat_test_vectors[i].ct, cfb128_kat_test_vectors[i].ct_len,
                out,
                &out_len,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, cfb128_kat_test_vectors[i].msg, cfb128_kat_test_vectors[i].msg_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("AES-CFB128 TcId %d FAILED (decryption mismatch)\n", cfb128_kat_test_vectors[i].tc_id);
                printf("Expected PT: ");
                DEMO_print_hex(cfb128_kat_test_vectors[i].msg, cfb128_kat_test_vectors[i].msg_len);
                printf("Computed PT: ");
                DEMO_print_hex(out, cfb128_kat_test_vectors[i].msg_len);
                failure = 1;
            }
        }

        if (failure) {
            if (cfb128_kat_test_vectors[i].comment && cfb128_kat_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", cfb128_kat_test_vectors[i].comment);
            }
            total_failures++;
        } else {
            total_success++;
        }

        CF_CipherOpts_Reset(&opts);
    }

    printf("AES-CFB128 KAT tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_aes_ofb_kat(void) {
    size_t num_test_vectors = sizeof(ofb_kat_test_vectors) / sizeof(ofb_kat_test_vectors[0]);

    size_t total_failures = 0;
    size_t total_success = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(CF_AES_OFB); // assuming AES-OFB
        if (!cipher) {
            printf("Unknown Cipher flag for test vector %d\n", ofb_kat_test_vectors[i].tc_id);
            return;
        }

        uint8_t out[16] = {0};
        size_t out_len;
        int failure = 0;
        int encrypt_mode = (strcmp(ofb_kat_test_vectors[i].mode, "ENCRYPT") == 0);

        CF_CIPHER_OPTS opts = {0};
        CF_STATUS status = CF_CipherOpts_Init(
            &opts,
            ofb_kat_test_vectors[i].iv,
            ofb_kat_test_vectors[i].iv_len,
            NULL, // No AES Counter for AES-OFB
            0);   // No ChaCha counter for AES-OFB

        if (encrypt_mode) {
            status = CF_Cipher_Encrypt(
                cipher,
                ofb_kat_test_vectors[i].key, ofb_kat_test_vectors[i].key_len,
                ofb_kat_test_vectors[i].msg, ofb_kat_test_vectors[i].msg_len,
                out,
                &out_len,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, ofb_kat_test_vectors[i].ct, ofb_kat_test_vectors[i].ct_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("AES-OFB TcId %d FAILED (encryption mismatch)\n", ofb_kat_test_vectors[i].tc_id);
                printf("Expected CT: ");
                DEMO_print_hex(ofb_kat_test_vectors[i].ct, ofb_kat_test_vectors[i].ct_len);
                printf("Computed CT: ");
                DEMO_print_hex(out, ofb_kat_test_vectors[i].ct_len);
                failure = 1;
            }
        } else { // DECRYPT
            status = CF_Cipher_Decrypt(
                cipher,
                ofb_kat_test_vectors[i].key, ofb_kat_test_vectors[i].key_len,
                ofb_kat_test_vectors[i].ct, ofb_kat_test_vectors[i].ct_len,
                out,
                &out_len,
                &opts
            );

            if (status != CF_SUCCESS || memcmp(out, ofb_kat_test_vectors[i].msg, ofb_kat_test_vectors[i].msg_len) != 0) {
                CF_CipherOpts_Reset(&opts);
                printf("AES-OFB TcId %d FAILED (decryption mismatch)\n", ofb_kat_test_vectors[i].tc_id);
                printf("Expected PT: ");
                DEMO_print_hex(ofb_kat_test_vectors[i].msg, ofb_kat_test_vectors[i].msg_len);
                printf("Computed PT: ");
                DEMO_print_hex(out, ofb_kat_test_vectors[i].msg_len);
                failure = 1;
            }
        }

        if (failure) {
            if (ofb_kat_test_vectors[i].comment && ofb_kat_test_vectors[i].comment[0] != '\0') {
                printf("  Comment: %s\n", ofb_kat_test_vectors[i].comment);
            }
            total_failures++;
        } else {
            total_success++;
        }

        CF_CipherOpts_Reset(&opts);
    }

    printf("AES-OFB KAT tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_success,
           total_failures);
}

void test_aes_cbc_pkcs7_wycheproof(void) {
    size_t num_test_vectors = sizeof(cbc_pkcs5_test_vectors) / sizeof(cbc_pkcs5_test_vectors[0]);
    size_t total_failures = 0;
    size_t total_successes = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(CF_AES_CBC_PKCS7);
        if (!cipher) {
            printf("Unknown Cipher flag for test vector %d\n", cbc_pkcs5_test_vectors[i].tc_id);
            continue;
        }

        CF_CIPHER_OPTS opts = {0};
        CF_STATUS status = CF_CipherOpts_Init(
            &opts,
            cbc_pkcs5_test_vectors[i].iv,
            cbc_pkcs5_test_vectors[i].iv_len,
            NULL,
            0
        );

        if (status != CF_SUCCESS) {
            printf("AES-CBC-PKCS7 TcId %d FAILED: CF_CipherOpts_Init failed\n", cbc_pkcs5_test_vectors[i].tc_id);
            total_failures++;
            continue;
        }

        uint8_t ct[256] = {0};
        uint8_t dec[256] = {0};
        size_t out_len;
        int expected_valid = (strcmp(cbc_pkcs5_test_vectors[i].result, "valid") == 0);
        int failure = 0;

        // ---------------- Encrypt ----------------
        status = CF_Cipher_Encrypt(
            cipher,
            cbc_pkcs5_test_vectors[i].key, cbc_pkcs5_test_vectors[i].key_len,
            cbc_pkcs5_test_vectors[i].msg, cbc_pkcs5_test_vectors[i].msg_len,
            ct,
            &out_len,
            &opts
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("AES-CBC-PKCS7 TcId %d FAILED: CF_Cipher_Encrypt failed\n", cbc_pkcs5_test_vectors[i].tc_id);
            failure = 1;
            goto print_extra;
        }

        if (expected_valid && memcmp(ct, cbc_pkcs5_test_vectors[i].ct, cbc_pkcs5_test_vectors[i].ct_len) != 0) {
            printf("AES-CBC-PKCS7 TcId %d FAILED: Ciphertext mismatch\n", cbc_pkcs5_test_vectors[i].tc_id);
            failure = 1;
            goto print_extra;
        }

        // ---------------- Decrypt ----------------
        status = CF_Cipher_Decrypt(
            cipher,
            cbc_pkcs5_test_vectors[i].key, cbc_pkcs5_test_vectors[i].key_len,
            cbc_pkcs5_test_vectors[i].ct, cbc_pkcs5_test_vectors[i].ct_len,
            dec,
            &out_len,
            &opts
        );

        if (status != CF_SUCCESS && expected_valid) {
            printf("AES-CBC-PKCS7 TcId %d FAILED: CF_Cipher_Decrypt failed\n", cbc_pkcs5_test_vectors[i].tc_id);
            failure = 1;
            goto print_extra;
        }

        if (expected_valid && memcmp(dec, cbc_pkcs5_test_vectors[i].msg, cbc_pkcs5_test_vectors[i].msg_len) != 0) {
            printf("AES-CBC-PKCS7 TcId %d FAILED: Decrypted plaintext mismatch\n", cbc_pkcs5_test_vectors[i].tc_id);
            failure = 1;
            goto print_extra;
        }

print_extra:
        if (failure) {
            total_failures++;

            if (cbc_pkcs5_test_vectors[i].comment && cbc_pkcs5_test_vectors[i].comment[0] != '\0')
                printf("  Comment: %s\n", cbc_pkcs5_test_vectors[i].comment);

            if (cbc_pkcs5_test_vectors[i].flags_len > 0) {
                printf("  Flags: ");
                for (size_t f = 0; f < cbc_pkcs5_test_vectors[i].flags_len; f++) {
                    printf("%s", cbc_pkcs5_test_vectors[i].flags[f]);
                    if (f + 1 < cbc_pkcs5_test_vectors[i].flags_len) printf(", ");
                }
                printf("\n");
            }

            printf("  Computed CT: ");
            DEMO_print_hex(ct, cbc_pkcs5_test_vectors[i].ct_len);
            printf("  Expected CT: ");
            DEMO_print_hex(cbc_pkcs5_test_vectors[i].ct, cbc_pkcs5_test_vectors[i].ct_len);

            printf("  Computed PT: ");
            DEMO_print_hex(dec, cbc_pkcs5_test_vectors[i].msg_len);
            printf("  Expected PT: ");
            DEMO_print_hex(cbc_pkcs5_test_vectors[i].msg, cbc_pkcs5_test_vectors[i].msg_len);

            printf("\n");
        } else {
            total_successes++;
        }

        CF_CipherOpts_Reset(&opts);
    }

    printf("AES-CBC-PKCS7 Wycheproof tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors,
           total_successes,
           total_failures);
}

#endif // ENABLE_TESTS