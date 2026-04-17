#include "../../src/internal/config/test_config.h"

#if ENABLE_TESTS

// ============================
// Helpers
// ============================
static void do_cipher_init_test(const CF_CIPHER *cipher, const uint8_t *key, size_t key_len, CF_OPERATION op) {
    CF_STATUS st;
    CF_CIPHER_CTX ctx = {0};
    CF_CIPHER_OPTS opts = {0};
    CF_CIPHER_OPTS *p_opts = NULL;

    // Only AES non-ECB modes need options
    if (CF_IS_CIPHER_AES(cipher->id) && cipher->id != CF_AES_ECB) {
        if (cipher->id == CF_AES_CTR) {
            uint8_t ctr[AES_BLOCK_SIZE] = {
                0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
            };
            st = CF_CipherOpts_Init(&opts, NULL, 0, ctr, 0);
        } else {
            uint8_t iv[AES_BLOCK_SIZE] = {
                0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
            };
            st = CF_CipherOpts_Init(&opts, iv, sizeof(iv), NULL, 0);
        }
        CF_ASSERT(st == CF_SUCCESS);
        p_opts = &opts;
    } else if (CF_IS_CIPHER_CHACHA(cipher->id)) {
        if (CF_IS_XCHACHA_MODE(cipher->id)) {
            uint8_t iv[XCHACHA_EXTENDED_IV_SIZE] = {
                0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
                0x11,0x12,0x12,0x13,0x14,0x15,0x16,0x17
            };
            st = CF_CipherOpts_Init(&opts, iv, sizeof(iv), NULL, 0);
        } else {
            uint8_t iv[CHACHA_IV_SIZE] = {
                0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                0x09,0x0A,0x0B,0x0C
            };
            st = CF_CipherOpts_Init(&opts, iv, sizeof(iv), NULL, 0);
        }
        CF_ASSERT(st == CF_SUCCESS);
        p_opts = &opts;
    }

    st = CF_Cipher_Init(&ctx, cipher, p_opts, key, key_len, op);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(ctx.cipher_ctx != NULL || ctx.key_ctx != NULL);

    st = CF_Cipher_Reset(&ctx);
    CF_ASSERT(st == CF_SUCCESS);

    if (p_opts) CF_CipherOpts_Reset(p_opts);
}

static void do_cipher_process_test(CF_CIPHER_CTX *ctx) {
    CF_STATUS st;
    uint8_t in[64] = {0};
    uint8_t out[128] = {0};
    size_t out_len = sizeof(out);

    st = CF_Cipher_Process(ctx, in, sizeof(in), out, &out_len);
    CF_ASSERT(st == CF_SUCCESS);
}

static void do_cipher_clone_test(CF_CIPHER_CTX *ctx) {
    CF_STATUS st;
    CF_CIPHER_CTX clone = {0};

    st = CF_Cipher_CloneCtx(&clone, ctx);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(clone.cipher_ctx != NULL || clone.key_ctx != NULL);

    CF_Cipher_Reset(&clone);
}

static void do_cipher_oneshot_test(const CF_CIPHER *cipher, const uint8_t *key, size_t key_len, CF_OPERATION op) {
    uint8_t in[64] = {0};
    uint8_t out[128] = {0};
    size_t out_len = sizeof(out);
    CF_CIPHER_OPTS opts = {0};
    CF_CIPHER_OPTS *p_opts = NULL;

    if (CF_IS_CIPHER_AES(cipher->id) && cipher->id != CF_AES_ECB) {
        if (cipher->id == CF_AES_CTR) {
            uint8_t ctr[AES_BLOCK_SIZE] = {
                0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
            };
            CF_CipherOpts_Init(&opts, NULL, 0, ctr, 0);
        } else {
            uint8_t iv[AES_BLOCK_SIZE] = {
                0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
            };
            CF_CipherOpts_Init(&opts, iv, sizeof(iv), NULL, 0);
        }
        p_opts = &opts;
    } else if (CF_IS_CIPHER_CHACHA(cipher->id)) {
        if (CF_IS_XCHACHA_MODE(cipher->id)) {
            uint8_t iv[XCHACHA_EXTENDED_IV_SIZE] = {
                0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
                0x11,0x12,0x12,0x13,0x14,0x15,0x16,0x17
            };
            CF_CipherOpts_Init(&opts, iv, sizeof(iv), NULL, 0);
        } else {
            uint8_t iv[CHACHA_IV_SIZE] = {
                0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                0x09,0x0A,0x0B,0x0C
            };
            CF_CipherOpts_Init(&opts, iv, sizeof(iv), NULL, 0);
        }
        p_opts = &opts;
    }

    CF_STATUS st;
    if (op == CF_OP_ENCRYPT) {
        st = CF_Cipher_Encrypt(cipher, key, key_len, in, sizeof(in), out, &out_len, p_opts);
    } else {
        st = CF_Cipher_Decrypt(cipher, key, key_len, in, sizeof(in), out, &out_len, p_opts);
    }
    CF_ASSERT(st == CF_SUCCESS);

    if (p_opts) CF_CipherOpts_Reset(p_opts);
}

// ============================
// Smoke-test entry
// ============================
void cf_cipher_api_test(void) {
#if ENABLE_TESTS_VERBOSE
    printf("[*] Cipher API smoke-test starting...\n");
#else
    printf("Cipher API tests:\n");
#endif

    uint8_t key[CF_KEY_256_SIZE] = {0};

    uint32_t cipher_flags[] = {
        CF_AES_ECB, CF_AES_CBC, CF_AES_CBC_PKCS7, CF_AES_OFB, CF_AES_CFB8, CF_AES_CFB128, CF_AES_CTR,
        CF_CHACHA8, CF_CHACHA12, CF_CHACHA20, CF_XCHACHA8, CF_XCHACHA12, CF_XCHACHA20
    };
    size_t num_ciphers = sizeof(cipher_flags) / sizeof(cipher_flags[0]);

    size_t aes_key_sizes[] = {CF_KEY_128_SIZE, CF_KEY_192_SIZE, CF_KEY_256_SIZE};

    for (size_t i = 0; i < num_ciphers; i++) {
        const CF_CIPHER *cipher = CF_Cipher_GetByFlag(cipher_flags[i]);
        CF_ASSERT(cipher != NULL);

        for (size_t k = 0; k < sizeof(aes_key_sizes)/sizeof(aes_key_sizes[0]); k++) {
            size_t key_len = aes_key_sizes[k];

            if (CF_IS_CIPHER_CHACHA(cipher->id) && key_len == CF_KEY_192_SIZE)
                continue;
            
            if (CF_IS_XCHACHA_MODE(cipher->id) && key_len != CF_KEY_256_SIZE) { 
                continue;
            }

            CF_STATUS st;
            CF_CIPHER_OPTS opts = {0};
            CF_CIPHER_OPTS *p_opts = NULL;

            // Only create options if mode is NOT ECB
            if (CF_IS_CIPHER_AES(cipher->id) && cipher->id != CF_AES_ECB) {
                if (cipher->id == CF_AES_CTR) {
                    // CTR mode: fill counter
                    uint8_t ctr[AES_BLOCK_SIZE] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                                   0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
                    st = CF_CipherOpts_Init(&opts, NULL, 0, ctr, 0);
                    CF_ASSERT(st == CF_SUCCESS);
                    p_opts = &opts;
                } else {
                    // Non-CTR: fill IV
                    uint8_t iv[AES_BLOCK_SIZE] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                                  0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
                    st = CF_CipherOpts_Init(&opts, iv, sizeof(iv), NULL, 0);
                    CF_ASSERT(st == CF_SUCCESS);
                    p_opts = &opts;
                }
            } else if (CF_IS_CIPHER_CHACHA(cipher->id)) {
                if (CF_IS_XCHACHA_MODE(cipher->id)) {
                    uint8_t iv[XCHACHA_EXTENDED_IV_SIZE] = {
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
                        0x11,0x12,0x12,0x13,0x14,0x15,0x16,0x17
                    };
                    st = CF_CipherOpts_Init(&opts, iv, sizeof(iv), NULL, 0);
                } else {
                    uint8_t iv[CHACHA_IV_SIZE] = {
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x09,0x0A,0x0B,0x0C
                    };
                    st = CF_CipherOpts_Init(&opts, iv, sizeof(iv), NULL, 0);
                }
                CF_ASSERT(st == CF_SUCCESS);
                p_opts = &opts;
            }

            // Init test
            do_cipher_init_test(cipher, key, key_len, CF_OP_ENCRYPT);

            // Alloc context
            st = CF_SUCCESS;
            CF_CIPHER_CTX *ctx = CF_Cipher_InitAlloc(cipher, p_opts, key, key_len, CF_OP_ENCRYPT, &st);
            CF_ASSERT(ctx != NULL && st == CF_SUCCESS);

            // Process / Clone / One-shot
            do_cipher_process_test(ctx);
            do_cipher_clone_test(ctx);
            do_cipher_oneshot_test(cipher, key, key_len, CF_OP_ENCRYPT);
            do_cipher_oneshot_test(cipher, key, key_len, CF_OP_DECRYPT);

#if ENABLE_TESTS_VERBOSE
            printf("[*] Passed smoke-test for cipher %s\n", CF_Cipher_GetFullName(ctx));
#else
            printf("  %-20s  passed\n", CF_Cipher_GetFullName(ctx));
#endif

            st = CF_Cipher_Free(&ctx);
            CF_ASSERT(st == CF_SUCCESS);
            CF_ASSERT(ctx == NULL);

            // Reset options
            if (p_opts) CF_CipherOpts_Reset(p_opts);
        }
    }

#if ENABLE_TESTS_VERBOSE
    printf("[*] Cipher API smoke-test completed successfully.\n");
#endif
}

#endif // ENABLE_TESTS