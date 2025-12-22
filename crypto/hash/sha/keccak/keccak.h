/*
 * CryptoForge - keccak.h / keccak Hash Interface
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the MIT License along with this program.
 * If not, see <https://opensource.org/licenses/MIT>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef KECCAK_H
#define KECCAK_H

#include "../../hash_common.h"
#include "../../../../config/crypto_config.h"
#include "../../../../utils/misc_utils.h"
#include "../../../../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
// KECCAK (Low-level)
// ======================================
#define KECCAK_ROUNDS 24
#define SHA3_KECCAK_F_WIDTH 1600
#define KECCAK_BLOCK_SIZE 200

typedef struct {
    uint64_t state[5][5];
    uint8_t buf[KECCAK_BLOCK_SIZE];
    size_t buf_len;
    size_t rate;
    uint8_t suffix;
    int finalized;
} ll_KECCAK_CTX;

// Low-level functions
bool ll_keccak_sponge_init(ll_KECCAK_CTX *ctx, size_t rate, uint8_t suffix);
bool ll_keccak_sponge_absorb(ll_KECCAK_CTX *ctx, const uint8_t *data, size_t len);
bool ll_keccak_sponge_final(ll_KECCAK_CTX *ctx);
bool ll_keccak_sponge_squeeze(ll_KECCAK_CTX *ctx, uint8_t *output, size_t outlen);

// Optional low-level permutation function
bool ll_keccak_p(uint64_t state[5][5], unsigned int w, unsigned int nr);

#ifdef __cplusplus
}
#endif

#endif // KECCAK_H