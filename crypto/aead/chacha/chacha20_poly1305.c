#include "../../../include/crypto/chacha20_poly1305.h"

bool ll_CHACHA20_POLY13051305_Init(
    ll_CHACHA20_POLY1305_CTX *ctx,
    const uint8_t *key, size_t key_len,
    const uint8_t iv[CHACHA20_POLY1305_IV_SIZE],
    const uint8_t *aad, size_t aad_len, bool encrypt) {
    if (!ctx || !key || !iv || (aad_len > 0 && !aad))
        return false;

    if (aad_len > CHACHA20_POLY1305_MAX_AAD_LEN)
        return false; // exceed ~16 GB

    bool ok = false;

    // Store cipher mode in context
    ctx->isEncrypt = encrypt;

    // Temporary buffer to hold Poly1305 key and padding bytes
    uint8_t otk[CHACHA_KEY_SIZE_256];
    uint8_t zero_block[32] = {0};


    // Initialize ChaCha20 context with key, iv, and default number of rounds
    if (!ll_CHACHA_Init(&ctx->chacha_ctx, key, key_len, iv, 0, CHACHA20_ROUNDS))
        goto cleanup;

    // Generate the Poly1305 one-time key (first 32 bytes of ChaCha20 keystream)
    if (!ll_CHACHA_Cipher(&ctx->chacha_ctx, zero_block, 32, otk))
        goto cleanup;

    SECURE_ZERO(&ctx->chacha_ctx, sizeof(ctx->chacha_ctx));

    // After deriving Poly1305 key
    if (!ll_CHACHA_Init(&ctx->chacha_ctx, key, key_len, iv, 1, CHACHA20_ROUNDS))
        goto cleanup;

    // Initialize Poly1305 with the derived one-time key
    if (ll_POLY1305_Init(&ctx->poly1305_ctx, otk) != CF_SUCCESS)
        goto cleanup;

    if (aad_len > 0) {
        //Feed the associated data (AAD) into Poly1305
        if (ll_POLY1305_Update(&ctx->poly1305_ctx, aad, aad_len) != CF_SUCCESS)
            goto cleanup;

        size_t rem = aad_len & 15;
        if (rem) {
            uint8_t pad[16] = {0};
            if (ll_POLY1305_Update(&ctx->poly1305_ctx, pad, 16 - rem) != CF_SUCCESS)
                goto cleanup;
        }
    }

    // Store the length of the associated data in the context
    ctx->aad_len = (uint64_t)aad_len;

    ok = true;

cleanup:
    SECURE_ZERO(otk, sizeof(otk));

    if (!ok) {
        // Only wipe context on failure
        SECURE_ZERO(ctx, sizeof(*ctx));
    }
    
    return ok;
}

bool ll_CHACHA20_POLY1305_Update(
    ll_CHACHA20_POLY1305_CTX *ctx,
    const uint8_t *in, size_t in_len,
    uint8_t *out) {

    if (!ctx || !in || !out)
        return false;

    if (ctx->data_len + in_len > CHACHA20_POLY1305_MAX_DATA_LEN)
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

    ctx->data_len += (uint64_t)in_len;
    ok = true;

cleanup:
    if (!ok)
        SECURE_ZERO(ctx, sizeof(*ctx));

    return ok;
}

bool ll_CHACHA20_POLY1305_Final(
    ll_CHACHA20_POLY1305_CTX *ctx,
    uint8_t tag[LL_POLY1305_TAG_LEN]) {
    if (!ctx || !tag)
        return false;

    bool ok = false;

    uint8_t temp[16] = {0};

    size_t rem = ctx->data_len & 15;
    if (rem) {
        uint8_t pad[16] = {0};
        ll_POLY1305_Update(&ctx->poly1305_ctx, pad, 16 - rem);
    }

    //Encode the length of the AAD
    STORE64LE(temp, ctx->aad_len);

    // //Encode the length of the plaintext/ciphertext
    STORE64LE(temp + 8, ctx->data_len);

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
