#include "../../include/sha3.h"

#if ENABLE_SHA3_224

bool SHA3_224Init(SHA3_224_CTX *ctx) {
    return KeccakInit(ctx, SHA3_224_BLOCK_SIZE, SHA3_224_DOMAIN);
}

bool SHA3_224Absorb(SHA3_224_CTX *ctx, const uint8_t *data, size_t len) {
    return KeccakAbsorb(ctx, data, len);
}

bool SHA3_224Final(SHA3_224_CTX *ctx) {
    return KeccakFinal(ctx);
}

bool SHA3_224Squeeze(SHA3_224_CTX *ctx, uint8_t *output, size_t outlen) {
    return KeccakSqueeze(ctx, output, outlen);
}

bool SHA3_224(const uint8_t *data, size_t len, uint8_t digest[SHA3_224_DIGEST_SIZE]) {
    return Keccak(data, len, digest, SHA3_224_DIGEST_SIZE, SHA3_224_BLOCK_SIZE, SHA3_224_DOMAIN);
}

#endif // ENABLE_SHA3_224

#if ENABLE_SHA3_256

bool SHA3_256Init(SHA3_256_CTX *ctx) {
    return KeccakInit(ctx, SHA3_256_BLOCK_SIZE, SHA3_256_DOMAIN);
}

bool SHA3_256Absorb(SHA3_256_CTX *ctx, const uint8_t *data, size_t len) {
    return KeccakAbsorb(ctx, data, len);
}

bool SHA3_256Final(SHA3_256_CTX *ctx) {
    return KeccakFinal(ctx);
}

bool SHA3_256Squeeze(SHA3_256_CTX *ctx, uint8_t *output, size_t outlen) {
    return KeccakSqueeze(ctx, output, outlen);
}

bool SHA3_256(const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_SIZE]) {
    return Keccak(data, len, digest, SHA3_256_DIGEST_SIZE, SHA3_256_BLOCK_SIZE, SHA3_256_DOMAIN);
}

#endif // ENABLE_SHA3_256

#if ENABLE_SHA3_384

bool SHA3_384Init(SHA3_384_CTX *ctx) {
    return KeccakInit(ctx, SHA3_384_BLOCK_SIZE, SHA3_384_DOMAIN);
}

bool SHA3_384Absorb(SHA3_384_CTX *ctx, const uint8_t *data, size_t len) {
    return KeccakAbsorb(ctx, data, len);
}

bool SHA3_384Final(SHA3_384_CTX *ctx) {
    return KeccakFinal(ctx);
}

bool SHA3_384Squeeze(SHA3_384_CTX *ctx, uint8_t *output, size_t outlen) {
    return KeccakSqueeze(ctx, output, outlen);
}

bool SHA3_384(const uint8_t *data, size_t len, uint8_t digest[SHA3_384_DIGEST_SIZE]) {
    return Keccak(data, len, digest, SHA3_384_DIGEST_SIZE, SHA3_384_BLOCK_SIZE, SHA3_384_DOMAIN);
}

#endif // ENABLE_SHA3_384

#if ENABLE_SHA3_512

bool SHA3_512Init(SHA3_512_CTX *ctx) {
    return KeccakInit(ctx, SHA3_512_BLOCK_SIZE, SHA3_512_DOMAIN);
}

bool SHA3_512Absorb(SHA3_512_CTX *ctx, const uint8_t *data, size_t len) {
    return KeccakAbsorb(ctx, data, len);
}

bool SHA3_512Final(SHA3_512_CTX *ctx) {
    return KeccakFinal(ctx);
}

bool SHA3_512Squeeze(SHA3_512_CTX *ctx, uint8_t *output, size_t outlen) {
    return KeccakSqueeze(ctx, output, outlen);
}

bool SHA3_512(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_SIZE]) {
    return Keccak(data, len, digest, SHA3_512_DIGEST_SIZE, SHA3_512_BLOCK_SIZE, SHA3_512_DOMAIN);
}

#endif // ENABLE_SHA3_512