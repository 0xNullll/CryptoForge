
#include "../../src/CryptoForge/include/config/test_config.h"

#if ENABLE_TESTS

// ============================
// AEAD helpers
// ============================
static void do_aead_init_test(const CF_AEAD *aead, const uint8_t *key, size_t key_len,
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              CF_OPERATION op) {
    CF_STATUS st;
    CF_AEAD_CTX ctx = {0};

    st = CF_AEAD_Init(&ctx, aead, key, key_len, iv, iv_len, aad, aad_len, op);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(ctx.aead_ctx != NULL || ctx.key_ctx != NULL);

    st = CF_AEAD_Reset(&ctx);
    CF_ASSERT(st == CF_SUCCESS);
}

static void do_aead_oneshot_test(const CF_AEAD *aead,
                                 const uint8_t *key, size_t key_len,
                                 const uint8_t *iv, size_t iv_len,
                                 const uint8_t *aad, size_t aad_len,
                                 size_t tag_len) {
    CF_STATUS st;
    uint8_t in[64] = {0};
    uint8_t ct[64] = {0};
    size_t ct_len = sizeof(ct);
    uint8_t dec[64] = {0};
    size_t dec_len = sizeof(dec);
    uint8_t tag[CF_AEAD_TAG_128_SIZE] = {0};


    st = CF_AEAD_Encrypt(aead, key, key_len, iv, iv_len,
                        aad, aad_len, in, sizeof(in),
                        ct, &ct_len, tag, tag_len);
    CF_ASSERT(st == CF_SUCCESS);

    st = CF_AEAD_Decrypt(aead, key, key_len, iv, iv_len,
                        aad, aad_len, ct, ct_len,
                        dec, &dec_len, tag, tag_len);

    CF_ASSERT(st == CF_SUCCESS);
}

static void do_aead_clone_test(CF_AEAD_CTX *ctx) {
    CF_STATUS st;
    CF_AEAD_CTX *clone = CF_AEAD_CloneCtxAlloc(ctx, &st);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(clone != NULL && (clone->aead_ctx != NULL || clone->key_ctx != NULL));

    st = CF_AEAD_Free(&clone);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(clone == NULL);
}

// ============================
// Smoke-test entry
// ============================
void cf_aead_api_test(void) {
    printf("[*] AEAD API smoke-test starting...\n");

    uint8_t key_128[CF_KEY_128_SIZE] = {0};
    uint8_t key_192[CF_KEY_192_SIZE] = {0};
    uint8_t key_256[CF_KEY_256_SIZE] = {0};

    uint8_t iv_gcm[AES_BLOCK_SIZE] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                      0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
    uint8_t iv_chacha[CHACHA_IV_SIZE] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                        0x09,0x0A,0x0B,0x0C};
    uint8_t iv_xchacha[XCHACHA_EXTENDED_IV_SIZE] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                                    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
                                                    0x11,0x12,0x12,0x13,0x14,0x15,0x16,0x17};
    uint8_t aad[16] = {0};

    uint32_t aead_flags[] = {CF_AES_GCM, CF_CHACHA20_POLY1305, CF_XCHACHA20_POLY1305};
    size_t num_aeads = sizeof(aead_flags) / sizeof(aead_flags[0]);

    for (size_t i = 0; i < num_aeads; i++) {
        const CF_AEAD *aead = CF_AEAD_GetByFlag(aead_flags[i]);
        CF_ASSERT(aead != NULL);

        uint8_t *iv = (aead_flags[i] == CF_AES_GCM) ? iv_gcm :
                      (aead_flags[i] == CF_CHACHA20_POLY1305) ? iv_chacha : iv_xchacha;
        size_t iv_len = (aead_flags[i] == CF_AES_GCM) ? sizeof(iv_gcm) :
                        (aead_flags[i] == CF_CHACHA20_POLY1305) ? sizeof(iv_chacha) : sizeof(iv_xchacha);

        // AEAD key/tag loops
        if (aead_flags[i] == CF_AES_GCM) {
            size_t aes_keys[] = {CF_KEY_128_SIZE, CF_KEY_192_SIZE, CF_KEY_256_SIZE};
            uint8_t *key_ptrs[] = {key_128, key_192, key_256};
            size_t tag_sizes[] = {CF_AEAD_TAG_32_SIZE, CF_AEAD_TAG_64_SIZE,
                                  CF_AEAD_TAG_96_SIZE, CF_AEAD_TAG_128_SIZE};

            for (size_t k = 0; k < 3; k++) {
                size_t key_len = aes_keys[k];
                uint8_t *key = key_ptrs[k];

                for (size_t t = 0; t < 4; t++) {
                    size_t tag_len = tag_sizes[t];

                    // Init / alloc / clone / one-shot
                    do_aead_init_test(aead, key, key_len, iv, iv_len, aad, sizeof(aad), CF_OP_ENCRYPT);
                    CF_STATUS st;
                    CF_AEAD_CTX *ctx = CF_AEAD_InitAlloc(aead, key, key_len, iv, iv_len, aad, sizeof(aad), CF_OP_ENCRYPT, &st);
                    CF_ASSERT(ctx != NULL && st == CF_SUCCESS);

                    do_aead_clone_test(ctx);
                    do_aead_oneshot_test(aead, key, key_len, iv, iv_len, aad, sizeof(aad), tag_len);

                    printf("[*] Passed smoke-test for AEAD %s and tag %zu\n",
                           CF_AEAD_GetFullName(ctx), tag_len*8);

                    st = CF_AEAD_Free(&ctx);
                    CF_ASSERT(st == CF_SUCCESS);
                    CF_ASSERT(ctx == NULL);
                }
            }
        } else {
            // ChaCha20 / XChaCha20 run once (256-bit key, 128-bit tag)
            uint8_t *key = key_256;
            size_t key_len = CF_KEY_256_SIZE;
            size_t tag_len = CF_AEAD_TAG_128_SIZE;

            do_aead_init_test(aead, key, key_len, iv, iv_len, aad, sizeof(aad), CF_OP_ENCRYPT);
            CF_STATUS st;
            CF_AEAD_CTX *ctx = CF_AEAD_InitAlloc(aead, key, key_len, iv, iv_len, aad, sizeof(aad), CF_OP_ENCRYPT, &st);
            CF_ASSERT(ctx != NULL && st == CF_SUCCESS);

            do_aead_clone_test(ctx);
            do_aead_oneshot_test(aead, key, key_len, iv, iv_len, aad, sizeof(aad), tag_len);

            printf("[*] Passed smoke-test for AEAD %s and tag %zu\n",
                   CF_AEAD_GetFullName(ctx), tag_len*8);

            st = CF_AEAD_Free(&ctx);
            CF_ASSERT(st == CF_SUCCESS);
            CF_ASSERT(ctx == NULL);
        }
    }

    printf("[*] AEAD API smoke-test completed successfully.\n");
}

#endif // ENABLE_TESTS