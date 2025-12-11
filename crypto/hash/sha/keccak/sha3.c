/*
 * CryptoForge - sha3.c / SHA-3 (SHA-3-224, SHA-3-256, SHA3-384, and SHA3-512) Core Implementation
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "sha3.h"

// ======================================
// SHA3-224 (Low-level)
// ======================================
bool ll_sha3_224_init(ll_SHA3_224_CTX *ctx) {
    return ll_keccak_sponge_init(ctx, SHA3_224_BLOCK_SIZE, SHA3_224_DOMAIN);
}

bool ll_sha3_224_absorb(ll_SHA3_224_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_sponge_absorb(ctx, data, len);
}

bool ll_sha3_224_final(ll_SHA3_224_CTX *ctx) {
    return ll_keccak_sponge_final(ctx);
}

bool ll_sha3_224_squeeze(ll_SHA3_224_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(ctx, output, outlen);
}

// ======================================
// SHA3-256 (Low-level)
// ======================================
bool ll_sha3_256_init(ll_SHA3_256_CTX *ctx) {
    return ll_keccak_sponge_init(ctx, SHA3_256_BLOCK_SIZE, SHA3_256_DOMAIN);
}

bool ll_sha3_256_absorb(ll_SHA3_256_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_sponge_absorb(ctx, data, len);
}

bool ll_sha3_256_final(ll_SHA3_256_CTX *ctx) {
    return ll_keccak_sponge_final(ctx);
}

bool ll_sha3_256_squeeze(ll_SHA3_256_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(ctx, output, outlen);
}

// ======================================
// SHA3-384 (Low-level)
// ======================================
bool ll_sha3_384_init(ll_SHA3_384_CTX *ctx) {
    return ll_keccak_sponge_init(ctx, SHA3_384_BLOCK_SIZE, SHA3_384_DOMAIN);
}

bool ll_sha3_384_absorb(ll_SHA3_384_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_sponge_absorb(ctx, data, len);
}

bool ll_sha3_384_final(ll_SHA3_384_CTX *ctx) {
    return ll_keccak_sponge_final(ctx);
}

bool ll_sha3_384_squeeze(ll_SHA3_384_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(ctx, output, outlen);
}

// ======================================
// SHA3-512 (Low-level)
// ======================================
bool ll_sha3_512_init(ll_SHA3_512_CTX *ctx) {
    return ll_keccak_sponge_init(ctx, SHA3_512_BLOCK_SIZE, SHA3_512_DOMAIN);
}

bool ll_sha3_512_absorb(ll_SHA3_512_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_sponge_absorb(ctx, data, len);
}

bool ll_sha3_512_final(ll_SHA3_512_CTX *ctx) {
    return ll_keccak_sponge_final(ctx);
}

bool ll_sha3_512_squeeze(ll_SHA3_512_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(ctx, output, outlen);
}
