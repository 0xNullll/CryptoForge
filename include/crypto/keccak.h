/*
 * CryptoForge - keccak.h / keccak Core Interface
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KECCAK_H
#define KECCAK_H

#include "../utils/bitops.h"
#include "../config/crypto_config.h"
#include "../utils/misc.h"
#include "../utils/mem.h"

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