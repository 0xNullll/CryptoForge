/*
 * CryptoForge - shake.c / SHAKE (rawSHAKE, SHAKE, and CSHAKE) Core Implementation
 * Copyright (C) 2026 0xNullll
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

#include "../../../../internal/crypto/shake.h"

/*
 * ================= FIPS 800-185 Helpers =================
 *
 * These functions implement low-level operations as defined in
 * NIST SP800-185 for cSHAKE, KMAC, TupleHash, and ParallelHash.
 *
 * - ll_right_encode_uint64(x, out):
 *     Encodes a 64-bit integer x as a variable-length big-endian
 *     byte string followed by a length byte at the end.
 *
 * - ll_left_encode_uint64(x, out):
 *     Encodes a 64-bit integer x as a variable-length big-endian
 *     byte string preceded by a length byte at the beginning.
 *
 * - ll_encode_string(S, S_len_bytes, out, out_len):
 *     Encodes a byte string S as left_encode(bitlen(S)) || S.
 *     Returns the total number of bytes written.
 *
 * - ll_encoded_string_len(S_len):
 *     Returns the number of bytes ll_encode_string will write
 *     without actually encoding.
 *
 * - ll_byte_pad(S, S_len, w, out, out_cap):
 *     Pads the string S to a multiple of w bytes after prepending
 *     left_encode(w). Returns the total number of bytes written.
 *
 * - ll_substring_bytes(S, S_len, start_idx, end_idx, out):
 *     Returns a byte-aligned substring from start_idx to end_idx-1.
 */

// Right-encode a 64-bit integer (x) in big-endian, length byte at the end
size_t ll_right_encode_uint64(uint64_t x, uint8_t *out) {
    size_t n = 1;
    uint64_t tmp = x;
    while (tmp >>= 8) n++;  // number of bytes needed

    // Encode x in big-endian
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)(x >> (8 * (n - 1 - i))) & 0xFF;

    out[n] = (uint8_t)n;  // append length byte at end
    return n + 1;
}

// Left-encode a 64-bit integer (x) in big-endian, length byte at start
size_t ll_left_encode_uint64(uint64_t x, uint8_t *out) {
    size_t n = 1;
    uint64_t tmp = x;
    while (tmp >>= 8) n++;  // number of bytes needed

    out[0] = (uint8_t)n;    // length byte at start

    // Encode x in big-endian
    for (size_t i = 0; i < n; i++)
        out[1 + i] = (uint8_t)(x >> (8 * (n - 1 - i))) & 0xFF;

    return n + 1;
}

// Encode a string according to SP800-185 (length in bytes)
size_t ll_encode_string(const uint8_t *S, size_t S_len_bytes, uint8_t *out, size_t out_len) {
    if (!out) return 0;  // output pointer must be valid

    // Calculate bit-length of the string
    uint64_t bitlen = (uint64_t)S_len_bytes * 8;

    // Encode bit-length
    uint8_t tmp[CSHAKE_MAX_ENCODED_HEADER_LEN] = {0};  // max bytes needed for ll_left_encode_uint64
    size_t n = ll_left_encode_uint64(bitlen, tmp);

    // Check if output buffer is large enough
    if (out_len < n + S_len_bytes) {
        // Not enough space
        return 0;
    }

    // Copy left-encoded length
    SECURE_MEMCPY(out, tmp, n);

    // Append string bytes
    if (S && S_len_bytes > 0) {
        SECURE_MEMCPY(out + n, S, S_len_bytes);
    }

    return n + S_len_bytes;  // total bytes written
}

// Compute the total encoded string length in bytes (bits-only)
size_t ll_encoded_string_len(size_t S_len) {
    uint64_t bits = (uint64_t)S_len * 8;
    size_t n = 1;
    uint64_t tmp = bits;
    while (tmp >>= 8) n++;  // number of bytes needed to encode bit-length
    return n + 1 + S_len;   // n bytes for bitlen + 1 length byte + string itself
}


// Bytepad a string (already bit-length encoded) to nearest multiple of w
size_t ll_byte_pad(const uint8_t *S, size_t S_len,
                   size_t w, uint8_t *out, size_t out_cap) {
    if (w == 0 || !out) return 0;

    uint8_t le[CSHAKE_MAX_ENCODED_HEADER_LEN] = {0};  // max bytes needed for ll_left_encode_uint64
    size_t le_len = ll_left_encode_uint64(w, le);     // left-encode w (bytes)

    size_t n = le_len + S_len;                        // total length before padding

    if (out_cap < n) return 0;

    // copy left_encode(w) || S
    SECURE_MEMCPY(out, le, le_len);
    if (S_len)
        SECURE_MEMCPY(out + le_len, S, S_len);

    // pad to nearest multiple of w
    size_t pad = (w - (n % w)) % w;
    if (out_cap < n + pad) return 0;
    if (pad)
        SECURE_ZERO(out + n, pad);

    return n + pad;
}

// Extract a byte-range (substring) from a byte array
size_t ll_substring_bytes(const uint8_t *S, size_t S_len,
                          size_t start_idx, size_t end_idx,
                          uint8_t *out) {
    if (!S || !out || start_idx >= end_idx || start_idx >= S_len) return 0;
    if (end_idx > S_len) end_idx = S_len;

    size_t len = end_idx - start_idx;
    SECURE_MEMCPY(out, S + start_idx, len);
    return len;
}

// ======================================
// SHAKE128 (Low-level)
// ======================================
bool ll_shake128_init(ll_SHAKE128_CTX *ctx) {
    return ll_keccak_sponge_init(ctx, SHAKE128_BLOCK_SIZE, SHAKE128_DOMAIN);
}

bool ll_shake128_absorb(ll_SHAKE128_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_sponge_absorb(ctx, data, len);
}

bool ll_shake128_final(ll_SHAKE128_CTX *ctx) {
    return ll_keccak_sponge_final(ctx);
}

bool ll_shake128_squeeze(ll_SHAKE128_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(ctx, output, outlen);
}

// ======================================
// SHAKE256 (Low-level)
// ======================================
bool ll_shake256_init(ll_SHAKE256_CTX *ctx) {
    return ll_keccak_sponge_init(ctx, SHAKE256_BLOCK_SIZE, SHAKE256_DOMAIN);
}

bool ll_shake256_absorb(ll_SHAKE256_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_sponge_absorb(ctx, data, len);
}

bool ll_shake256_final(ll_SHAKE256_CTX *ctx) {
    return ll_keccak_sponge_final(ctx);
}

bool ll_shake256_squeeze(ll_SHAKE256_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(ctx, output, outlen);
}

// ======================================
// RawSHAKE128
// ======================================
bool ll_rawshake128_init(ll_RawSHAKE128_CTX *ctx) {
    return ll_keccak_sponge_init(ctx, RAWSHAKE128_BLOCK_SIZE, RAWSHAKE128_DOMAIN);
}

bool ll_rawshake128_absorb(ll_RawSHAKE128_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_sponge_absorb(ctx, data, len);
}

bool ll_rawshake128_final(ll_RawSHAKE128_CTX *ctx) {
    return ll_keccak_sponge_final(ctx);
}

bool ll_rawshake128_squeeze(ll_RawSHAKE128_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(ctx, output, outlen);
}

// ======================================
// RawSHAKE256
// ======================================
bool ll_rawshake256_init(ll_RawSHAKE256_CTX *ctx) {
    return ll_keccak_sponge_init(ctx, RAWSHAKE256_BLOCK_SIZE, RAWSHAKE256_DOMAIN);
}

bool ll_rawshake256_absorb(ll_RawSHAKE256_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_sponge_absorb(ctx, data, len);
}

bool ll_rawshake256_final(ll_RawSHAKE256_CTX *ctx) {
    return ll_keccak_sponge_final(ctx);
}

bool ll_rawshake256_squeeze(ll_RawSHAKE256_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(ctx, output, outlen);
}

// ==============================
// cSHAKE low-level helpers
// ==============================
static bool ll_cshake_absorb_custom(
    ll_KECCAK_CTX *sponge,
    const uint8_t *N, size_t N_len,
    const uint8_t *S, size_t S_len,
    size_t rate_bytes) {
    if ((!N || N_len == 0) && (!S || S_len == 0))
        return true;

    uint8_t tmp[16];  // left_encode temporary
    size_t n, total = 0;

    // left_encode(rate)
    n = ll_left_encode_uint64(rate_bytes, tmp);
    if (!ll_keccak_sponge_absorb(sponge, tmp, n)) return false;
    total += n;

    // encode_string(N)
    if (N_len > (SIZE_MAX >> 3)) return false;
    n = ll_left_encode_uint64((uint64_t)N_len * 8, tmp);
    if (!ll_keccak_sponge_absorb(sponge, tmp, n)) return false;
    total += n;
    if (N_len > 0 && !ll_keccak_sponge_absorb(sponge, N, N_len)) return false;
    total += N_len;

    // encode_string(S)
    if (S_len > (SIZE_MAX >> 3)) return false;
    n = ll_left_encode_uint64((uint64_t)S_len * 8, tmp);
    if (!ll_keccak_sponge_absorb(sponge, tmp, n)) return false;
    total += n;
    if (S_len > 0 && !ll_keccak_sponge_absorb(sponge, S, S_len)) return false;
    total += S_len;

    // zero padding to rate boundary
    size_t pad = (rate_bytes - (total % rate_bytes)) % rate_bytes;
    if (pad) {
        uint8_t zeros[KECCAK_BLOCK_SIZE] = {0};
        while (pad > 0) {
            size_t chunk = pad > KECCAK_BLOCK_SIZE ? KECCAK_BLOCK_SIZE : pad;
            if (!ll_keccak_sponge_absorb(sponge, zeros, chunk)) return false;
            pad -= chunk;
        }
    }

    return true;
}

// ==============================
// cSHAKE128 init / absorb / final
// ==============================
bool ll_cshake128_init(ll_CSHAKE128_CTX *ctx,
                       const uint8_t *N, size_t N_len,
                       const uint8_t *S, size_t S_len) {
    if (!ctx) return false;

    SECURE_ZERO(ctx, sizeof(*ctx));

    ctx->finalized = 0;

    if (!ll_keccak_sponge_init(&ctx->internal_ctx, SHAKE128_BLOCK_SIZE, SHAKE128_DOMAIN))
        return false;

    // Stream absorb customization
    if (N_len > 0 || S_len > 0) {
        if (!ll_cshake_absorb_custom(&ctx->internal_ctx, N, N_len, S, S_len, SHAKE128_BLOCK_SIZE))
            return false;
    }

    return true;
}


bool ll_cshake128_absorb(ll_CSHAKE128_CTX *ctx, const uint8_t *X, size_t X_len) {
    if (!ctx->finalized || (X && X_len > 0))
        return ll_keccak_sponge_absorb(&ctx->internal_ctx, X, X_len);

    return true;
}

bool ll_cshake128_final(ll_CSHAKE128_CTX *ctx) {
    if (ctx->finalized)
        return false;

    // Set domain separation byte according to SP800-185
    uint8_t suffix = ctx->emptyNameCustom ? SHAKE128_DOMAIN : CSHAKE128_DOMAIN;
    ctx->internal_ctx.suffix = suffix;

    ctx->finalized = 1;
    return ll_keccak_sponge_final(&ctx->internal_ctx);
}

bool ll_cshake128_squeeze(ll_CSHAKE128_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(&ctx->internal_ctx, output, outlen);
}

// ==============================
// cSHAKE256 init / absorb / final
// ==============================
bool ll_cshake256_init(ll_CSHAKE256_CTX *ctx,
                       const uint8_t *N, size_t N_len,
                       const uint8_t *S, size_t S_len) {
    if (!ctx) return false;

    SECURE_ZERO(ctx, sizeof(*ctx));

    ctx->finalized = 0;

    if (!ll_keccak_sponge_init(&ctx->internal_ctx, SHAKE256_BLOCK_SIZE, SHAKE256_DOMAIN))
        return false;

    if (N_len > 0 || S_len > 0) {
        if (!ll_cshake_absorb_custom(&ctx->internal_ctx, N, N_len, S, S_len, SHAKE256_BLOCK_SIZE))
            return false;
    }

    return true;
}

bool ll_cshake256_absorb(ll_CSHAKE256_CTX *ctx, const uint8_t *X, size_t X_len) {
    if (!ctx->finalized || (X && X_len > 0))
        return ll_keccak_sponge_absorb(&ctx->internal_ctx, X, X_len);

    return true;
}

bool ll_cshake256_final(ll_CSHAKE256_CTX *ctx) {
    if (ctx->finalized)
        return false;

    uint8_t suffix = ctx->emptyNameCustom ? SHAKE256_DOMAIN : CSHAKE256_DOMAIN;
    ctx->internal_ctx.suffix = suffix;

    ctx->finalized = 1;
    return ll_keccak_sponge_final(&ctx->internal_ctx);
}

bool ll_cshake256_squeeze(ll_CSHAKE256_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(&ctx->internal_ctx, output, outlen);
}