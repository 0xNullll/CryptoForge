/*
 * CryptoForge - xchacha20_poly1305.h / XChaCha20-Poly1305 Interface
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef XCHACHA20_POLY1305_H
#define XCHACHA20_POLY1305_H

#include "../config/libs.h"

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../utils/bitops.h"
#include "../utils/cf_status.h"

#include "chacha_core.h"
#include "chacha20_poly1305.h"
#include "xchacha_core.h"
#include "xchacha.h"
#include "poly1305.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef ll_CHACHA20_POLY1305_CTX ll_XCHACHA20_POLY1305_CTX;

bool ll_XCHACHA20_POLY1305_Init(
    ll_XCHACHA20_POLY1305_CTX *ctx,
    const uint8_t key[XCHACHA_KEY_SIZE],
    const uint8_t iv[XCHACHA_EXTENDED_IV_SIZE],
    const uint8_t *aad, size_t aad_len,
    bool encrypt);

bool ll_XCHACHA20_POLY1305_Update(
    ll_XCHACHA20_POLY1305_CTX *ctx,
    const uint8_t *in, size_t in_len,
    uint8_t *out);

bool ll_XCHACHA20_POLY1305_Final(
    ll_XCHACHA20_POLY1305_CTX *ctx,
    uint8_t tag[LL_POLY1305_TAG_LEN]);

#ifdef __cplusplus
}
#endif

#endif // XCHACHA20_POLY1305_H