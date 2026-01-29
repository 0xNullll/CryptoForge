/*
 * CryptoForge - sha256.c / SHA-256 (SHA-256, and SHA-224) Core Implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the file LICENSE in the
 * source distribution or at:
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under
 * the License.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../../include/crypto/sha256.h"

// SHA-256 constants
static const uint32_t K256[64] = {
    0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
    0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
    0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
    0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
    0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
    0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
    0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
    0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
    0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
    0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
    0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
    0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
    0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
    0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
    0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
    0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

// Big sigma — used for working state
#define SHA256_BSIG0(x) (ROTR32((uint32_t)(x), 2)  ^ ROTR32((uint32_t)(x), 13) ^ ROTR32((uint32_t)(x), 22))
#define SHA256_BSIG1(x) (ROTR32((uint32_t)(x), 6)  ^ ROTR32((uint32_t)(x), 11) ^ ROTR32((uint32_t)(x), 25))

// Small sigma — used for message schedule expansion
#define SHA256_SSIG0(x) (ROTR32((uint32_t)(x),7) ^ ROTR32((uint32_t)(x),18) ^ ((uint32_t)(x) >> 3))
#define SHA256_SSIG1(x) (ROTR32((uint32_t)(x),17) ^ ROTR32((uint32_t)(x),19) ^ ((uint32_t)(x) >> 10))

// Logical functions
#define SHA256_CH(x,y,z)   ((x & y) ^ (~x & z))
#define SHA256_MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))

// ======================================
// SHA-256 Low-level implementation
// ======================================
bool ll_sha256_init(ll_SHA256_CTX *ctx) {
    SECURE_ZERO(ctx, sizeof(*ctx));
    ctx->state[0] = 0x6a09e667UL;
    ctx->state[1] = 0xbb67ae85UL;
    ctx->state[2] = 0x3c6ef372UL;
    ctx->state[3] = 0xa54ff53aUL;
    ctx->state[4] = 0x510e527fUL;
    ctx->state[5] = 0x9b05688cUL;
    ctx->state[6] = 0x1f83d9abUL;
    ctx->state[7] = 0x5be0cd19UL;
    return true;
}

static bool ll_sha256_process_block(ll_SHA256_CTX *ctx, const uint8_t *block) {
    uint32_t W[64], A,B,C,D,E,F,G,H,T1,T2;

    SECURE_ZERO(W, sizeof(W));

    for(int t=0;t<16;t++)
        W[t] = LOAD32(block + t*4);
    for(int t=16;t<64;t++)
        W[t] = SHA256_SSIG1(W[t-2]) + W[t-7] + SHA256_SSIG0(W[t-15]) + W[t-16];

    A=ctx->state[0]; B=ctx->state[1]; C=ctx->state[2]; D=ctx->state[3];
    E=ctx->state[4]; F=ctx->state[5]; G=ctx->state[6]; H=ctx->state[7];

    for(int t=0;t<64;t++){
        T1 = H + SHA256_BSIG1(E) + SHA256_CH(E,F,G) + K256[t] + W[t];
        T2 = SHA256_BSIG0(A) + SHA256_MAJ(A,B,C);
        H=G; G=F; F=E; E=D+T1;
        D=C; C=B; B=A; A=T1+T2;
    }

    ctx->state[0]+=A; ctx->state[1]+=B; ctx->state[2]+=C; ctx->state[3]+=D;
    ctx->state[4]+=E; ctx->state[5]+=F; ctx->state[6]+=G; ctx->state[7]+=H;

    SECURE_ZERO(W, sizeof(W));

    return true;
}

bool ll_sha256_update(ll_SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    ctx->len += len;

    if(ctx->buf_len){
        size_t fill = SHA256_BLOCK_SIZE - ctx->buf_len;
        if(fill>len) fill=len;
        SECURE_MEMCPY(ctx->buf+ctx->buf_len, data, fill);
        ctx->buf_len+=fill; i+=fill;
        if(ctx->buf_len==SHA256_BLOCK_SIZE){
            if(!ll_sha256_process_block(ctx, ctx->buf)) return false;
            ctx->buf_len=0;
        }
    }

    for(; i+SHA256_BLOCK_SIZE <= len; i+=SHA256_BLOCK_SIZE)
        if(!ll_sha256_process_block(ctx, data+i)) return false;

    if(i<len){
        ctx->buf_len=len-i;
        SECURE_MEMCPY(ctx->buf, data+i, ctx->buf_len);
    }

    return true;
}

bool ll_sha256_final(ll_SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_SIZE]) {
    if(!ctx || !digest) return false;

    uint8_t block[SHA256_BLOCK_SIZE];
    SECURE_ZERO(block, sizeof(block));

    SECURE_MEMCPY(block, ctx->buf, ctx->buf_len);
    block[ctx->buf_len++] = 0x80;

    size_t pad_len = (ctx->buf_len <= 56) ? (56 - ctx->buf_len) : (64 + 56 - ctx->buf_len);
    SECURE_MEMSET(block + ctx->buf_len, 0, pad_len);

    uint64_t bit_len = ctx->len * 8;
    STORE64(block + 56, bit_len);

    if(!ll_sha256_process_block(ctx, block)) return false;

    if(ctx->buf_len + pad_len + 8 > 64){
        SECURE_MEMSET(block, 0, SHA256_BLOCK_SIZE);
        if(!ll_sha256_process_block(ctx, block)) return false;
    }

    for(size_t i=0;i<8;i++)
        STORE32(digest + i*4, ctx->state[i]);

    SECURE_ZERO(block, sizeof(block));

    return true;
}

// ======================================
// SHA-224 Low-level implementation
// ======================================
bool ll_sha224_init(ll_SHA224_CTX *ctx) {
    SECURE_ZERO(ctx, sizeof(*ctx));
    ctx->state[0] = 0xc1059ed8UL;
    ctx->state[1] = 0x367cd507UL;
    ctx->state[2] = 0x3070dd17UL;
    ctx->state[3] = 0xf70e5939UL;
    ctx->state[4] = 0xffc00b31UL;
    ctx->state[5] = 0x68581511UL;
    ctx->state[6] = 0x64f98fa7UL;
    ctx->state[7] = 0xbefa4fa4UL;
    return true;
}

bool ll_sha224_update(ll_SHA224_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_sha256_update((ll_SHA256_CTX*)ctx, data, len);
}

bool ll_sha224_final(ll_SHA224_CTX *ctx, uint8_t digest[SHA224_DIGEST_SIZE]) {
    uint8_t full_digest[SHA256_DIGEST_SIZE];
    if(!ll_sha256_final((ll_SHA256_CTX*)ctx, full_digest)) return false;
    SECURE_MEMCPY(digest, full_digest, SHA224_DIGEST_SIZE);
    return true;
}
