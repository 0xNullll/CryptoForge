/*
 * CryptoForge - xchacha.h / XChaCha Core Interface
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef XCHACHA_CORE_H
#define XCHACHA_CORE_H

#include "../config/libs.h"

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../utils/bitops.h"

#include "chacha_core.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XCHACHA_KEY_SIZE 32           // 256-bit key
#define XCHACHA_EXTENDED_IV_SIZE 24   // 192-bit nonce

// Derive 256-bit subkey from 256-bit key + 16-byte nonce
bool ll_HChaCha_DeriveSubkey(
    const uint8_t key[XCHACHA_KEY_SIZE],
    const uint8_t iv[16],
    uint8_t out[32],
    int rounds);

#ifdef __cplusplus
}
#endif

#endif // XCHACHA_CORE_H