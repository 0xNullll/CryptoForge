#include "../src/include/config/demo_config.h"

// ============================
// Placeholder helpers using macros
// ============================
static void do_mac_init_test(const CF_MAC *mac, const uint8_t *key, size_t key_len, uint32_t sub_flag) {
    CF_STATUS st;
    CF_MAC_CTX ctx = {0};

    CF_MAC_OPTS opts = {0};
    CF_MAC_OPTS *p_opts = NULL;

    // Only GMAC needs IV/options
    if (CF_MAC_IS_AES_GMAC(mac->id)) {
        uint8_t iv[AES_BLOCK_SIZE] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                      0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
        st = CF_MACOpts_Init(&opts, iv, sizeof(iv), NULL, 0);
        CF_ASSERT(st == CF_SUCCESS);
        p_opts = &opts;
    }

    st = CF_MAC_Init(&ctx, mac, p_opts, key, key_len, sub_flag);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(ctx.mac_ctx != NULL);

    st = CF_MAC_Reset(&ctx);
    CF_ASSERT(st == CF_SUCCESS);
}

static void do_mac_update_test(CF_MAC_CTX *ctx) {
    uint8_t dummy_data[CF_MAX_DEFAULT_HASH_BLOCK_SIZE] = {0};
    CF_STATUS st;

    st = CF_MAC_Update(ctx, dummy_data, 0);
    CF_ASSERT(st == CF_SUCCESS);

    dummy_data[0] = 0xAA;
    st = CF_MAC_Update(ctx, dummy_data, sizeof(dummy_data));
    CF_ASSERT(st == CF_SUCCESS);
}

static void do_mac_final_test(CF_MAC_CTX *ctx) {
    uint8_t tag[CF_MAX_DEFAULT_HASH_BLOCK_SIZE] = {0}; // max size buffer
    CF_STATUS st;

    size_t tag_len = ctx->tag_len != 0 ? ctx->tag_len : ctx->mac->default_tag_len;

    st = CF_MAC_Final(ctx, tag, tag_len);
    CF_ASSERT(st == CF_SUCCESS);

    // Re-finalize may fail for non-XOF MACs
    st = CF_MAC_Final(ctx, tag, tag_len);
    if (CF_MAC_IS_KMAC_STD(ctx->mac->id)) {
        CF_ASSERT(st == CF_SUCCESS);
    }
}

static void do_mac_compute_test(const CF_MAC *mac, const uint8_t *key, size_t key_len, uint32_t sub_flag) {
    uint8_t dummy_data[CF_MAX_DEFAULT_HASH_BLOCK_SIZE] = {0};
    uint8_t tag[CF_MAX_DEFAULT_HASH_BLOCK_SIZE] = {0};
    CF_STATUS st;

    size_t tag_len = mac->default_tag_len;

    if (CF_MAC_GET_HASH(sub_flag)) {
        const CF_HASH *hash = CF_Hash_GetByFlag(sub_flag);
        CF_ASSERT(hash != NULL);

        tag_len = CF_Hash_GetDigestSize(hash);
    }

    CF_MAC_OPTS opts = {0};
    CF_MAC_OPTS *p_opts = NULL;

    // Only GMAC needs IV/options
    if (CF_MAC_IS_AES_GMAC(mac->id)) {
        uint8_t iv[AES_BLOCK_SIZE] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                      0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
        st = CF_MACOpts_Init(&opts, iv, sizeof(iv), NULL, 0);
        CF_ASSERT(st == CF_SUCCESS);
        p_opts = &opts;
    }

    st = CF_MAC_Compute(mac, key, key_len,
                        dummy_data, sizeof(dummy_data),
                        tag, tag_len, p_opts, sub_flag);
    CF_ASSERT(st == CF_SUCCESS);
}

static void do_mac_clone_test(CF_MAC_CTX *ctx) {
    CF_STATUS st;
    CF_MAC_CTX clone = {0};

    st = CF_MAC_CloneCtx(&clone, ctx);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(clone.mac_ctx != NULL);

    CF_MAC_Reset(&clone);
}

static void do_mac_opts_test(void) {
    CF_STATUS st;
    CF_MAC_OPTS opts = {0};
    uint8_t iv[AES_BLOCK_SIZE] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                  0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
    uint8_t custom[CF_MAX_DEFAULT_HASH_BLOCK_SIZE] = {0xAA,0xBB,0xCC,0xDD};

    st = CF_MACOpts_Init(&opts, iv, sizeof(iv), custom, sizeof(custom));
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(opts.magic == CF_CTX_MAGIC);

    CF_MAC_OPTS *clone = CF_MACOpts_InitAlloc(iv, sizeof(iv),
                                              custom, sizeof(custom),
                                              &st);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(clone != NULL);

    st = CF_MACOpts_Reset(&opts);
    CF_ASSERT(st == CF_SUCCESS);

    st = CF_MACOpts_Free(&clone);
    CF_ASSERT(st == CF_SUCCESS);
    CF_ASSERT(clone == NULL);
}

void cf_mac_api_test(void) {
    printf("[*] MAC API smoke-test starting...\n");

    uint8_t key[CF_MAX_CIPHER_KEY_SIZE] = {0};

    uint32_t mac_flags[] = {CF_HMAC, CF_KMAC_STD, CF_AES_CMAC, CF_AES_GMAC, CF_POLY1305};
    size_t num_macs = sizeof(mac_flags)/sizeof(mac_flags[0]);

    uint32_t hmac_subflags[] = {
        CF_MD5, CF_SHA1, CF_SHA224, CF_SHA256, CF_SHA384, CF_SHA512,
        CF_SHA512_224, CF_SHA512_256, CF_SHA3_224, CF_SHA3_256, CF_SHA3_512
    };
    size_t num_hmac = sizeof(hmac_subflags)/sizeof(hmac_subflags[0]);

    uint32_t kmac_subflags[] = {CF_KMAC128, CF_KMAC256, CF_KMAC_XOF128, CF_KMAC_XOF256};
    size_t num_kmac = sizeof(kmac_subflags)/sizeof(kmac_subflags[0]);

    size_t cipher_key_sizes[] = {CF_KEY_128_SIZE, CF_KEY_192_SIZE, CF_KEY_256_SIZE}; // AES key sizes

    for (size_t i = 0; i < num_macs; i++) {
        const CF_MAC *mac = CF_MAC_GetByFlag(mac_flags[i]);
        CF_ASSERT(mac != NULL);

        uint32_t tmp_subflag = 0;
        uint32_t *sub_flags = NULL;
        size_t num_sub_flags = 0;

        if (mac_flags[i] == CF_HMAC) {
            sub_flags = hmac_subflags;
            num_sub_flags = num_hmac;
        } else if (mac_flags[i] == CF_KMAC_STD) {
            sub_flags = kmac_subflags;
            num_sub_flags = num_kmac;
        } else {
            sub_flags = &tmp_subflag;
            num_sub_flags = 1;
        }

        for (size_t j = 0; j < num_sub_flags; j++) {
            // Determine how many key sizes to iterate
            size_t num_key_sizes = (CF_MAC_IS_AES_CMAC(mac->id) || CF_MAC_IS_AES_GMAC(mac->id)) ? 3 : 1;

            for (size_t k = 0; k < num_key_sizes; k++) {
                size_t key_len = (num_key_sizes == 3) ? cipher_key_sizes[k] : sizeof(key);

                CF_MAC_OPTS opts = {0};
                CF_MAC_OPTS *p_opts = NULL;

                // GMAC needs IV/options
                if (CF_MAC_IS_AES_GMAC(mac->id)) {
                    uint8_t iv[AES_BLOCK_SIZE] = {
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
                    };
                    CF_STATUS st = CF_MACOpts_Init(&opts, iv, sizeof(iv), NULL, 0);
                    CF_ASSERT(st == CF_SUCCESS);
                    p_opts = &opts;
                }

                do_mac_init_test(mac, key, key_len, sub_flags[j]);

                CF_STATUS st = CF_SUCCESS;
                CF_MAC_CTX *ctx = CF_MAC_InitAlloc(mac, p_opts, key, key_len, sub_flags[j], &st);
                CF_ASSERT(ctx != NULL && st == CF_SUCCESS);

                do_mac_update_test(ctx);
                do_mac_final_test(ctx);
                do_mac_compute_test(mac, key, key_len, sub_flags[j]);
                do_mac_clone_test(ctx);

                printf("[*] Passed smoke-test for MAC %s\n",
                       CF_MAC_GetFullName(ctx));

                CF_STATUS fr = CF_MAC_Free(&ctx);
                CF_ASSERT(fr == CF_SUCCESS);
                CF_ASSERT(ctx == NULL);
            }
        }
    }

    do_mac_opts_test();

    printf("[*] MAC API smoke-test completed successfully.\n");
}