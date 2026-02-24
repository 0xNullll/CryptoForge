/*
 * CryptoForge - sha1.c / SHA-1 Core Implementation
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

#include "../../../include/crypto/sha1.h"

// SHA-1 constants
#define K_00_19 0x5a827999UL
#define K_20_39 0x6ed9eba1UL
#define K_40_59 0x8f1bbcdcUL
#define K_60_79 0xca62c1d6UL

// SHA-1 round functions
#define F_00_19(B,C,D)  (((B) & (C)) | ((~(B)) & (D)))
#define F_20_39(B,C,D)  ((B) ^ (C) ^ (D))
#define F_40_59(B,C,D)  (((B) & (C)) | ((B) & (D)) | ((C) & (D)))
#define F_60_79(B,C,D)  F_20_39((B),(C),(D))

// -------------------------
// Low-level API functions
// -------------------------
bool ll_sha1_init(ll_SHA1_CTX *ctx) {
    SECURE_ZERO(ctx, sizeof(*ctx));
    ctx->h0 = 0x67452301UL;
    ctx->h1 = 0xefcdab89UL;
    ctx->h2 = 0x98badcfeUL;
    ctx->h3 = 0x10325476UL;
    ctx->h4 = 0xc3d2e1f0UL;
    return true;
}

static bool ll_sha1_process_block(ll_SHA1_CTX *ctx, const uint8_t *block) {
    uint32_t W[80];
    uint32_t A,B,C,D,E,TEMP;

    SECURE_ZERO(W, sizeof(W));

    // Copy block to W[0..15] (big-endian)
    for(int i = 0; i < 16; i++)
        W[i] = LOAD32BE(block + i*4);

    // Expand W[16..79]
    for(int t=16;t<80;t++) {
        W[t] = ROTL32(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    // Initialize working variables
    A = ctx->h0; B = ctx->h1; C = ctx->h2; D = ctx->h3; E = ctx->h4;

    // Main loop
    for(int t=0;t<80;t++) {
        uint32_t f,k;
        if(t<=19) {
            f=F_00_19(B,C,D); k=K_00_19;
        }
        else if(t<=39) {
            f=F_20_39(B,C,D); k=K_20_39;
        }
        else if(t<=59) {
            f=F_40_59(B,C,D); k=K_40_59;
        }
        else {
            f=F_60_79(B,C,D); k=K_60_79;
        }

        TEMP = ROTL32(A,5) + f + E + W[t] + k;
        E = D;
        D = C;
        C = ROTL32(B,30);
        B = A;
        A = TEMP;
    }

    // Update hash state
    ctx->h0 += A; ctx->h1 += B; ctx->h2 += C; ctx->h3 += D; ctx->h4 += E;

    SECURE_ZERO(W, sizeof(W));

    return true;
}

bool ll_sha1_update(ll_SHA1_CTX *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data) return false;

    ctx->len += (uint64_t)len;  // total length in bytes

    while (len > 0) {
        size_t to_copy = SHA1_BLOCK_SIZE - ctx->num;
        if (to_copy > len) to_copy = len;

        SECURE_MEMCPY(ctx->buf + ctx->num, data, to_copy);
        ctx->num += (uint32_t)to_copy;
        data += to_copy;
        len -= to_copy;

        if (ctx->num == SHA1_BLOCK_SIZE) {
            if (!ll_sha1_process_block(ctx, ctx->buf)) return false;
            ctx->num = 0;
        }
    }

    return true;
}

bool ll_sha1_final(ll_SHA1_CTX *ctx, uint8_t digest[SHA1_DIGEST_SIZE]) {
    if (!ctx || !digest) return false;

    uint8_t pad[SHA1_BLOCK_SIZE] = {0};
    pad[0] = 0x80;  // append the 1-bit

    // Message length in bits
    uint64_t bit_len = ctx->len * 8;
    uint8_t len_bytes[8];
    STORE64BE(len_bytes, bit_len); // 64-bit length in big-endian

    // Compute padding length: enough to leave 8 bytes at the end for length
    size_t pad_len = (ctx->num < 56) ? (56 - ctx->num) : (64 + 56 - ctx->num);

    // Feed padding
    if (!ll_sha1_update(ctx, pad, pad_len)) return false;

    // Feed length
    if (!ll_sha1_update(ctx, len_bytes, 8)) return false;

    // Output digest in big-endian
    STORE32BE(digest + 0,  ctx->h0);
    STORE32BE(digest + 4,  ctx->h1);
    STORE32BE(digest + 8,  ctx->h2);
    STORE32BE(digest + 12, ctx->h3);
    STORE32BE(digest + 16, ctx->h4);

    return true;
}