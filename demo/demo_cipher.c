#include "../include/config/demo_config.h"

#if ENABLE_TESTS

void test_all_cipher_high(void) {
    uint32_t cf_chacha_flags[] = {
        CF_CHACHA8,
        CF_CHACHA12,
        CF_CHACHA20,

        CF_XCHACHA8,
        CF_XCHACHA12,
        CF_XCHACHA20,
    };

    size_t num_cf_chacha_flags = sizeof(cf_chacha_flags)/sizeof(cf_chacha_flags[0]);

    static const uint8_t chacha_key128[CF_KEY_128_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    static const uint8_t chacha_key256[CF_KEY_256_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    static const uint8_t *chacha_key_test_vectors[] = {
        chacha_key128,
        chacha_key256
    };

    static const size_t chacha_key_test_vectors_sizes[] = {
        sizeof(chacha_key128),
        sizeof(chacha_key256)
    };

    size_t num_chacha_keys = sizeof(chacha_key_test_vectors)/sizeof(chacha_key_test_vectors_sizes[0]);

    uint8_t chacha_iv[12] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };

    uint8_t xchacha_iv[CF_MAX_CIPHER_IV_SIZE] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00,

        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };

    uint8_t chacha_plain_text[114] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };

    uint32_t chacha_count = 1;

    for (size_t i = 0; i < num_cf_chacha_flags; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(cf_chacha_flags[i]);
        if (!cipher) {
            printf("Unknown Cipher flag %u\n", cf_chacha_flags[i]);
            continue;
        }

        uint8_t output_ct[114] = {0};
        uint8_t output_dec[114] = {0};

        CF_STATUS status = CF_SUCCESS;
        for (size_t j = 0; j < num_chacha_keys; j++) { 
            if (chacha_key_test_vectors_sizes[j] == CF_KEY_128_SIZE &&
                ((cf_chacha_flags[i] == CF_XCHACHA8) ||
                (cf_chacha_flags[i] == CF_XCHACHA12) ||
                (cf_chacha_flags[i] == CF_XCHACHA20)))
                    continue;

            CF_CIPHER_OPTS *ctxOpts = NULL;
            CF_CIPHER_CTX ctx = {0};

            if (((cf_chacha_flags[i] == CF_XCHACHA8) ||
                (cf_chacha_flags[i] == CF_XCHACHA12) ||
                (cf_chacha_flags[i] == CF_XCHACHA20))) {
                ctxOpts = CF_CipherOpts_InitAlloc(chacha_iv, sizeof(chacha_iv), NULL, chacha_count, 0, &status);
            } else {
                ctxOpts = CF_CipherOpts_InitAlloc(xchacha_iv, sizeof(xchacha_iv), NULL, chacha_count, 0, &status);
            }

            if (status != CF_SUCCESS) {
                printf("CF_CipherOpts_InitAlloc failed for %s\n", CF_Cipher_GetName(cipher));
                continue;
            }

            // this init just to get the proper credentiols for CF_Cipher_GetFullName() for algorithm name display for testing
            status = CF_Cipher_Init(&ctx, cipher, ctxOpts, chacha_key_test_vectors[j], chacha_key_test_vectors_sizes[j], CF_CIPHER_OP_ENCRYPT);
            if (status != CF_SUCCESS) {
                CF_CipherOpts_Free(&ctxOpts);
                printf("CF_Cipher_Init failed for %s, error status: %u\n", CF_Cipher_GetName(cipher), status);
                CF_Cipher_Reset(&ctx);
                continue;
            }

            status = CF_Cipher_Encrypt(cipher, chacha_key_test_vectors[j], chacha_key_test_vectors_sizes[j], chacha_plain_text, sizeof(chacha_plain_text), output_ct, ctxOpts);
            if (status != CF_SUCCESS) {
                CF_CipherOpts_Free(&ctxOpts);
                printf("CF_Cipher_Encrypt failed for %s, error status: %u\n", CF_Cipher_GetFullName(&ctx), status);
                continue;
            }

            // restart for testing
            ctxOpts->chacha_counter = chacha_count;

            status = CF_Cipher_Decrypt(cipher, chacha_key_test_vectors[j], chacha_key_test_vectors_sizes[j], output_ct, sizeof(output_ct), output_dec, ctxOpts);
            if (status != CF_SUCCESS) {
                CF_CipherOpts_Free(&ctxOpts);
                printf("CF_Cipher_Decrypt failed for %s, error status: %u\n", CF_Cipher_GetFullName(&ctx), status);
                continue;
            }

            printf("%s CT : ", CF_Cipher_GetFullName(&ctx));
            DEMO_print_hex(output_ct, sizeof(output_ct));
            printf("%s DEC: ", CF_Cipher_GetFullName(&ctx));
            DEMO_print_hex(output_dec, sizeof(output_dec));
            printf("\n");

            CF_Cipher_Reset(&ctx);
            CF_CipherOpts_Free(&ctxOpts);
        }
    }

    putchar('\n');

    static const uint8_t aes_plain_text[4 * AES_BLOCK_SIZE] = {
        0x6b, 0xc1, 0xbe, 0xe2,
        0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11,
        0x73, 0x93, 0x17, 0x2a,

        0xae, 0x2d, 0x8a, 0x57,
        0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac,
        0x45, 0xaf, 0x8e, 0x51,

        0x30, 0xc8, 0x1c, 0x46,
        0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef,

        0xf6, 0x9f, 0x24, 0x45,
        0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10
    };

    static const uint8_t aes_key128[CF_KEY_128_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    static const uint8_t aes_key192[CF_KEY_192_SIZE] = {
        0x8e, 0x73, 0xb0, 0xf7,
        0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b,
        0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2,
        0x52, 0x2c, 0x6b, 0x7b
    };

    static const uint8_t aes_key256[CF_KEY_256_SIZE] = {
        0x60, 0x3d, 0xeb, 0x10,
        0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0,
        0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07,
        0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3,
        0x09, 0x14, 0xdf, 0xf4
    };

    static const uint8_t *aes_key_test_vectors[] = {
        aes_key128,
        aes_key192,
        aes_key256
    };

    static const size_t aes_key_test_vectors_sizes[] = {
        sizeof(aes_key128),
        sizeof(aes_key192),
        sizeof(aes_key256)
    };

    size_t num_aes_keys = sizeof(aes_key_test_vectors)/sizeof(aes_key_test_vectors[0]);

    // Fixed AES IV (for testing purposes)
    uint8_t aes_test_iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };


    // fixed AES counter (for testing purposes)
    uint8_t aes_test_fixed_counter[AES_BLOCK_SIZE] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };

    uint32_t cf_aes_flags[] = {
        CF_AES_ECB,
        CF_AES_CBC,     // iv
        CF_AES_OFB,     // iv
        CF_AES_CFB8,    // iv
        CF_AES_CFB128,  // iv
        CF_AES_CTR      // counter
    };

    size_t num_cf_aes_flags = sizeof(cf_aes_flags)/sizeof(cf_aes_flags[0]);

    for (size_t i = 0; i < num_cf_aes_flags; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(cf_aes_flags[i]);
        if (!cipher) {
            printf("Unknown Cipher flag %u\n", cf_aes_flags[i]);
            continue;
        }

        CF_STATUS status;
        CF_CIPHER_OPTS *ctxOpts = NULL;

        if (cf_aes_flags[i] != CF_AES_ECB) {

            uint8_t enc_counter[AES_BLOCK_SIZE];
            memcpy(enc_counter, aes_test_fixed_counter, AES_BLOCK_SIZE);

            ctxOpts = CF_CipherOpts_InitAlloc(
                cf_aes_flags[i] != CF_AES_CTR ? aes_test_iv : NULL,      // mandetory for CBC/OFB/CFB8/CFB128
                cf_aes_flags[i] != CF_AES_CTR ? sizeof(aes_test_iv) : 0, // mandetory for CBC/OFB/CFB8/CFB128
                cf_aes_flags[i] == CF_AES_CTR ? enc_counter : NULL,      // mandetory for ctr
                0, // chacha counter is not used in aes modes
                0, // no padding flags yet
                &status);

            if (status != CF_SUCCESS) {
                printf("CF_CipherOpts_InitAlloc failed for %s\n", CF_Cipher_GetName(cipher));
                continue;
            }
        }

        for (size_t j = 0; j < num_aes_keys; j++) {
            CF_CIPHER_CTX ctx = {0};

            uint8_t output_ct[4 * AES_BLOCK_SIZE] = {0};
            uint8_t output_dec[4 * AES_BLOCK_SIZE] = {0};

            // this init just to get the proper credentiols for CF_Cipher_GetFullName() for algorithm name display for testing
            status = CF_Cipher_Init(&ctx, cipher, ctxOpts, aes_key_test_vectors[j], aes_key_test_vectors_sizes[j], CF_CIPHER_OP_ENCRYPT);
            if (status != CF_SUCCESS) {
                printf("CF_Cipher_Init failed for %s, error status: %u\n", CF_Cipher_GetName(cipher), status);
                CF_Cipher_Reset(&ctx);
                continue;
            }

            status = CF_Cipher_Encrypt(cipher, aes_key_test_vectors[j], aes_key_test_vectors_sizes[j], aes_plain_text, sizeof(aes_plain_text), output_ct, ctxOpts);
            if (status != CF_SUCCESS) {
                printf("CF_Cipher_Encrypt failed for %s, error status: %u\n", CF_Cipher_GetFullName(&ctx), status);
                continue;
            }

            if (ctxOpts && cf_aes_flags[i] == CF_AES_CTR) {
                memcpy(ctxOpts->ctr_block, aes_test_fixed_counter, AES_BLOCK_SIZE);
            }

            status = CF_Cipher_Decrypt(cipher, aes_key_test_vectors[j], aes_key_test_vectors_sizes[j], output_ct, sizeof(output_ct), output_dec, ctxOpts);
            if (status != CF_SUCCESS) {
                printf("CF_Cipher_Decrypt failed for %s, error status: %u\n", CF_Cipher_GetFullName(&ctx), status);
                continue;
            }

            if (ctxOpts && cf_aes_flags[i] == CF_AES_CTR) {
                memcpy(ctxOpts->ctr_block, aes_test_fixed_counter, AES_BLOCK_SIZE);
            }

            printf("%s CT : ", CF_Cipher_GetFullName(&ctx));
            DEMO_print_hex(output_ct, sizeof(output_ct));
            printf("%s DEC: ", CF_Cipher_GetFullName(&ctx));
            DEMO_print_hex(output_dec, sizeof(output_dec));
            printf("\n");

            CF_Cipher_Reset(&ctx);
        }
        if (ctxOpts)
            CF_CipherOpts_Free(&ctxOpts);
    }
}

#endif // ENABLE_TESTS