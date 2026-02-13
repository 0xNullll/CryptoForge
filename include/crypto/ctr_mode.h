/*
 * CryptoForge - ctr_mode.h / AES-CTR Interface
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef CTR_MODE_H
#define CTR_MODE_H

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../utils/bitops.h"

#include "../config/libs.h"

#include "aes_core.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// IV/nonce must be UNIQUE, randomness optional, no padding. Counter produces keystream; repeating IV/counter leaks plaintext.
//

bool ll_AES_CTR_Encrypt(
    const ll_AES_KEY *key,
    const uint8_t counter[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_CTR_Decrypt(
    const ll_AES_KEY *key,
    const uint8_t counter[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

#ifdef __cplusplus
}
#endif

#endif // CTR_MODE_H