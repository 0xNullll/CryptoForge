#include "shake.h"

// ======================================
// Bit-level helpers
// ======================================
void ll_trunc_s(const uint8_t *X, size_t Xlen, size_t s, uint8_t *out) {
    size_t full_bytes = s / 8;
    size_t rem_bits  = s % 8;

    if (full_bytes > Xlen) full_bytes = Xlen;
    memcpy(out, X, full_bytes);

    if (rem_bits && full_bytes < Xlen) {
        uint8_t mask = 0xFF << (8 - rem_bits);
        out[full_bytes] = X[full_bytes] & mask;
    }
}

void ll_concat_bits(const uint8_t *X, size_t x_bits,
                    const uint8_t *Y, size_t y_bits,
                    uint8_t *out) {

    size_t out_bits = x_bits + y_bits;
    size_t out_bytes = (out_bits + 7) / 8;
    memset(out, 0, out_bytes);

    size_t x_full_bytes = x_bits / 8;
    memcpy(out, X, x_full_bytes);

    size_t x_rem_bits = x_bits % 8;
    if (x_rem_bits && x_full_bytes < out_bytes) {
        out[x_full_bytes] = X[x_full_bytes] & (0xFF << (8 - x_rem_bits));
    }

    for (size_t i = 0; i < y_bits; i++) {
        size_t bit_index = x_bits + i;
        size_t out_byte = bit_index / 8;
        size_t out_bit  = 7 - (bit_index % 8);
        uint8_t y_bit = (Y[i / 8] >> (7 - (i % 8))) & 1;
        out[out_byte] |= y_bit << out_bit;
    }
}

// ======================================
// SHAKE128 (Low-level)
// ======================================
bool ll_shake128_init(ll_SHAKE128_CTX *ctx) {
    return ll_keccak_init(ctx, SHAKE128_BLOCK_SIZE, SHAKE128_DOMAIN);
}

bool ll_shake128_absorb(ll_SHAKE128_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_absorb(ctx, data, len);
}

bool ll_shake128_final(ll_SHAKE128_CTX *ctx) {
    return ll_keccak_final(ctx);
}

bool ll_shake128_squeeze(ll_SHAKE128_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_squeeze(ctx, output, outlen);
}

// ======================================
// SHAKE256 (Low-level)
// ======================================
bool ll_shake256_init(ll_SHAKE256_CTX *ctx) {
    return ll_keccak_init(ctx, SHAKE256_BLOCK_SIZE, SHAKE256_DOMAIN);
}

bool ll_shake256_absorb(ll_SHAKE256_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_absorb(ctx, data, len);
}

bool ll_shake256_final(ll_SHAKE256_CTX *ctx) {
    return ll_keccak_final(ctx);
}

bool ll_shake256_squeeze(ll_SHAKE256_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_squeeze(ctx, output, outlen);
}

// ======================================
// RawSHAKE128
// ======================================
bool ll_rawshake128_init(ll_RawSHAKE128_CTX *ctx) {
    return ll_keccak_init(ctx, RAWSHAKE128_BLOCK_SIZE, RAWSHAKE128_DOMAIN);
}

bool ll_rawshake128_absorb(ll_RawSHAKE128_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_absorb(ctx, data, len);
}

bool ll_rawshake128_final(ll_RawSHAKE128_CTX *ctx) {
    return ll_keccak_final(ctx);
}

bool ll_rawshake128_squeeze(ll_RawSHAKE128_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_squeeze(ctx, output, outlen);
}

// ======================================
// RawSHAKE256
// ======================================
bool ll_rawshake256_init(ll_RawSHAKE256_CTX *ctx) {
    return ll_keccak_init(ctx, RAWSHAKE256_BLOCK_SIZE, RAWSHAKE256_DOMAIN);
}

bool ll_rawshake256_absorb(ll_RawSHAKE256_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_absorb(ctx, data, len);
}

bool ll_rawshake256_final(ll_RawSHAKE256_CTX *ctx) {
    return ll_keccak_final(ctx);
}

bool ll_rawshake256_squeeze(ll_RawSHAKE256_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_squeeze(ctx, output, outlen);
}