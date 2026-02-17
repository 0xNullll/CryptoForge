#include "../../../include/crypto/xchacha20_poly1305.h"

bool ll_XCHACHA20_POLY1305_Init(
    ll_XCHACHA20_POLY1305_CTX *ctx,
    const uint8_t key[XCHACHA_KEY_SIZE],
    const uint8_t iv[XCHACHA_EXTENDED_IV_SIZE],
    const uint8_t *aad, size_t aad_len,
    bool encrypt) {
    if (!ctx || !key || !iv || (aad_len > 0 && !aad))
        return false;

    if (aad_len > CHACHA20_POLY1305_MAX_AAD_LEN)
        return false; // exceed ~16 GB

    bool ok = false;

    ctx->isEncrypt = encrypt;

    uint8_t otk[32];         // Poly1305 one-time key
    uint8_t zero_block[32] = {0};
    uint8_t subkey[32];      // HChaCha subkey
    uint8_t chacha_iv[12];   // 12-byte nonce for actual encryption

    // Derive HChaCha subkey from key + first 16 bytes of XChaCha nonce
    if (!ll_HChaCha_DeriveSubkey(key, iv, subkey, XCHACHA20_ROUNDS))
        goto cleanup;

    // Construct 12-byte ChaCha nonce (4 zero bytes || last 8 bytes of XChaCha nonce)
    chacha_iv[0] = chacha_iv[1] = chacha_iv[2] = chacha_iv[3] = 0;
    SECURE_MEMCPY(chacha_iv + 4, iv + 16, 8);

    // Initialize ChaCha20 with subkey and counter 0 to generate Poly1305 key
    if (!ll_CHACHA_Init(&ctx->chacha_ctx, subkey, 32, chacha_iv, 0, XCHACHA20_ROUNDS))
        goto cleanup;

    if (!ll_CHACHA_Cipher(&ctx->chacha_ctx, zero_block, 32, otk))
        goto cleanup;

    // Initialize ChaCha20 again for actual encryption with counter = 1
    if (!ll_CHACHA_Init(&ctx->chacha_ctx, subkey, 32, chacha_iv, 1, XCHACHA20_ROUNDS))
        goto cleanup;

    // Initialize Poly1305 with derived one-time key
    if (ll_POLY1305_Init(&ctx->poly1305_ctx, otk) != CF_SUCCESS)
        goto cleanup;

    // Feed AAD if present
    if (aad_len > 0) {
        if (ll_POLY1305_Update(&ctx->poly1305_ctx, aad, aad_len) != CF_SUCCESS)
            goto cleanup;

        size_t rem = aad_len & 15;
        if (rem) {
            uint8_t pad[16] = {0};
            if (ll_POLY1305_Update(&ctx->poly1305_ctx, pad, 16 - rem) != CF_SUCCESS)
                goto cleanup;
        }
    }

    ctx->aad_len = (uint64_t)aad_len;
    ok = true;

cleanup:
    SECURE_ZERO(subkey, sizeof(subkey));
    SECURE_ZERO(otk, sizeof(otk));

    if (!ok)
        SECURE_ZERO(ctx, sizeof(*ctx));

    return ok;
}

bool ll_XCHACHA20_POLY1305_Update(
    ll_XCHACHA20_POLY1305_CTX *ctx,
    const uint8_t *in, size_t in_len,
    uint8_t *out) {

    if (!ctx || !in || !out)
        return false;

    if (ctx->total_data_len + in_len > CHACHA20_POLY1305_MAX_DATA_LEN)
        return false;

    bool ok = false;

    if (ctx->isEncrypt) {
        // Encrypt plaintext
        if (!ll_CHACHA_Cipher(&ctx->chacha_ctx, in, in_len, out))
            goto cleanup;

        // Feed ciphertext to Poly1305
        if (ll_POLY1305_Update(&ctx->poly1305_ctx, out, in_len) != CF_SUCCESS)
            goto cleanup;

    } else {
        // Feed ciphertext to Poly1305 first
        if (ll_POLY1305_Update(&ctx->poly1305_ctx, in, in_len) != CF_SUCCESS)
            goto cleanup;

        // Decrypt
        if (!ll_CHACHA_Cipher(&ctx->chacha_ctx, in, in_len, out))
            goto cleanup;
    }

    ctx->total_data_len += (uint64_t)in_len;
    ok = true;

cleanup:
    if (!ok)
        SECURE_ZERO(ctx, sizeof(*ctx));

    return ok;
}

bool ll_XCHACHA20_POLY1305_Final(
    ll_XCHACHA20_POLY1305_CTX *ctx,
    uint8_t tag[LL_POLY1305_TAG_LEN]) {
    if (!ctx || !tag)
        return false;

    bool ok = false;

    uint8_t temp[16] = {0};

    size_t rem = ctx->total_data_len & 15;
    if (rem) {
        uint8_t pad[16] = {0};
        ll_POLY1305_Update(&ctx->poly1305_ctx, pad, 16 - rem);
    }

    //Encode the length of the AAD
    STORE64LE(temp, ctx->aad_len);

    // //Encode the length of the plaintext/ciphertext
    STORE64LE(temp + 8, ctx->total_data_len);

    //Compute MAC over the AAD and plaintext/ciphertext length field
    if (ll_POLY1305_Update(&ctx->poly1305_ctx, temp, 16) != CF_SUCCESS)
        goto cleanup;  

    if (ctx->isEncrypt) {
        // --- Encryption: write the computed tag ---
        if (ll_POLY1305_Final(&ctx->poly1305_ctx, tag) != CF_SUCCESS)
            goto cleanup;
    } else {
        // --- Decryption: verify tag ---
        uint8_t computed_tag[LL_POLY1305_TAG_LEN];

        // Compute MAC into computed_tag
        if (ll_POLY1305_Final(&ctx->poly1305_ctx, computed_tag) != CF_SUCCESS)
            goto cleanup;

        // Constant-time comparison against provided tag
        ok = SECURE_MEM_EQUAL(computed_tag, tag, LL_POLY1305_TAG_LEN);

        // Optionally overwrite tag with computed value
        SECURE_MEMCPY(tag, computed_tag, LL_POLY1305_TAG_LEN);

        goto cleanup; // skip ok = true below
    }
  
    ok = true;

cleanup:
    // force wipe any sensitive data
    SECURE_ZERO(ctx, sizeof(*ctx));

    return ok;
}
