#include "../../include/shake.h"

#if ENABLE_SHAKE_XOF

void Trunc_s(const uint8_t *X, size_t Xlen, size_t s, uint8_t *out) {
    size_t full_bytes = s / 8;
    size_t rem_bits  = s % 8;

    if (full_bytes > Xlen) full_bytes = Xlen;
    memcpy(out, X, full_bytes);

    if (rem_bits && full_bytes < Xlen) {
        uint8_t mask = 0xFF << (8 - rem_bits);
        out[full_bytes] = X[full_bytes] & mask;
    }
}

void concat_bits(const uint8_t *X, size_t x_bits,
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

#endif // ENABLE_SHAKE_XOF

#if ENABLE_SHAKE128

bool SHAKE128Init(SHAKE128_CTX *ctx) {
    return KeccakInit(ctx, SHAKE128_BLOCK_SIZE, SHAKE128_DOMAIN);
}

bool SHAKE128Absorb(SHAKE128_CTX *ctx, const uint8_t *data, size_t len) {
    return KeccakAbsorb(ctx, data, len);
}

bool SHAKE128Final(SHAKE128_CTX *ctx) {
    return KeccakFinal(ctx);
}

bool SHAKE128Squeeze(SHAKE128_CTX *ctx, uint8_t *output, size_t outlen) {
    return KeccakSqueeze(ctx, output, outlen);
}

bool SHAKE128(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen) {
    return Keccak(data, len, digest, outlen, SHAKE128_BLOCK_SIZE, SHAKE128_DOMAIN);
}

#endif // ENABLE_SHAKE128

#if ENABLE_SHAKE256

bool SHAKE256Init(SHAKE256_CTX *ctx) {
    return KeccakInit(ctx, SHAKE256_BLOCK_SIZE, SHAKE256_DOMAIN);
}

bool SHAKE256Absorb(SHAKE256_CTX *ctx, const uint8_t *data, size_t len) {
    return KeccakAbsorb(ctx, data, len);
}

bool SHAKE256Final(SHAKE256_CTX *ctx) {
    return KeccakFinal(ctx);
}

bool SHAKE256Squeeze(SHAKE256_CTX *ctx, uint8_t *output, size_t outlen) {
    return KeccakSqueeze(ctx, output, outlen);
}

bool SHAKE256(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen) {
    return Keccak(data, len, digest, outlen, SHAKE256_BLOCK_SIZE, SHAKE256_DOMAIN);
}

#endif // ENABLE_SHAKE256

#if ENABLE_RAWSHAKE128

bool RawSHAKE128Init(RawSHAKE128_CTX *ctx) {
    return KeccakInit(ctx, RAWSHAKE128_BLOCK_SIZE, RAWSHAKE128_DOMAIN);
}

bool RawSHAKE128Absorb(RawSHAKE128_CTX *ctx, const uint8_t *data, size_t len) {
    return KeccakAbsorb(ctx, data, len);
}

bool RawSHAKE128Final(RawSHAKE128_CTX *ctx) {
    return KeccakFinal(ctx);
}

bool RawSHAKE128Squeeze(RawSHAKE128_CTX *ctx, uint8_t *output, size_t outlen) {
    return KeccakSqueeze(ctx, output, outlen);
}

bool RawSHAKE128(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen) {
    return Keccak(data, len, digest, outlen, RAWSHAKE128_BLOCK_SIZE, RAWSHAKE128_DOMAIN);
}

#endif // ENABLE_RAWSHAKE128

#if ENABLE_RAWSHAKE256

bool RawSHAKE256Init(RawSHAKE256_CTX *ctx) {
    return KeccakInit(ctx, RAWSHAKE256_BLOCK_SIZE, RAWSHAKE256_DOMAIN);
}

bool RawSHAKE256Absorb(RawSHAKE256_CTX *ctx, const uint8_t *data, size_t len) {
    return KeccakAbsorb(ctx, data, len);
}

bool RawSHAKE256Final(RawSHAKE256_CTX *ctx) {
    return KeccakFinal(ctx);
}

bool RawSHAKE256Squeeze(RawSHAKE256_CTX *ctx, uint8_t *output, size_t outlen) {
    return KeccakSqueeze(ctx, output, outlen);
}

bool RawSHAKE256(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen) {
    return Keccak(data, len, digest, outlen, RAWSHAKE256_BLOCK_SIZE, RAWSHAKE256_DOMAIN);

}

#endif // ENABLE_RAWSHAKE256