/*
 * CryptoForge - xchacha.c / XChaCha (XChaCha8, XChaCha12 And XChaCha20) Implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../../include/crypto/xchacha.h"

static bool ll_XCHACHA_Init(
    ll_CHACHA_CTX *ctx,
    const uint8_t key[XCHACHA_KEY_SIZE],
    const uint8_t iv[XCHACHA_EXTENDED_IV_SIZE],
    int rounds) {
    if (!ctx || !key || !iv)
        return false;

    bool ok = false;

    uint8_t hchacha_iv[16];
    SECURE_MEMCPY(hchacha_iv, iv, 16);  // upper 16 bytes for HChaCha

    uint8_t subkey[32];  // derived subkey
    if (!ll_HChaCha_DeriveSubkey(key, hchacha_iv, subkey, rounds))
        goto cleanup;

    // Construct 12-byte nonce for ChaCha20: 4 zero bytes + last 8 bytes of IV
    uint8_t chacha_iv[12] = {0};
    SECURE_MEMCPY(chacha_iv + 4, iv + 16, 8);

    // Initialize base ChaCha20 context with derived subkey
    if (!ll_CHACHA_Init(ctx, subkey, 32, chacha_iv, 1, rounds))
        goto cleanup;

    ok = true;

cleanup:
    SECURE_ZERO(subkey, sizeof(subkey));
    SECURE_ZERO(hchacha_iv, sizeof(hchacha_iv));

    return ok;
}

bool ll_XCHACHA8_Init(ll_XCHACHA8_CTX *ctx, const uint8_t key[XCHACHA_KEY_SIZE], const uint8_t iv[XCHACHA_EXTENDED_IV_SIZE]) {
    return ll_XCHACHA_Init((ll_CHACHA_CTX *)ctx, key, iv, XCHACHA8_ROUNDS);
}

bool ll_XCHACHA8_Cipher(ll_XCHACHA8_CTX *ctx,
                        const uint8_t *in, size_t in_len,
                        uint8_t *out) {
    return ll_CHACHA_Cipher((ll_CHACHA_CTX *)ctx, in, in_len, out);
}

bool ll_XCHACHA12_Init(ll_XCHACHA12_CTX *ctx, const uint8_t key[XCHACHA_KEY_SIZE], const uint8_t iv[XCHACHA_EXTENDED_IV_SIZE]) {
    return ll_XCHACHA_Init((ll_CHACHA_CTX *)ctx, key, iv, XCHACHA12_ROUNDS);
}

bool ll_XCHACHA12_Cipher(ll_XCHACHA12_CTX *ctx,
                        const uint8_t *in, size_t in_len,
                        uint8_t *out) {
    return ll_CHACHA_Cipher((ll_CHACHA_CTX *)ctx, in, in_len, out);
}

bool ll_XCHACHA20_Init(ll_XCHACHA20_CTX *ctx, const uint8_t key[XCHACHA_KEY_SIZE], const uint8_t iv[XCHACHA_EXTENDED_IV_SIZE]) {
    return ll_XCHACHA_Init((ll_CHACHA_CTX *)ctx, key, iv, XCHACHA20_ROUNDS);
}

bool ll_XCHACHA20_Cipher(ll_XCHACHA20_CTX *ctx,
                        const uint8_t *in, size_t in_len,
                        uint8_t *out) {
    return ll_CHACHA_Cipher((ll_CHACHA_CTX *)ctx, in, in_len, out);
}