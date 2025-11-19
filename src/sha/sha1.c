#include "../../include/sha1.h"

#if ENABLE_SHA1

// SHA-1 constants
#define K_00_19 0x5a827999UL
#define K_20_39 0x6ed9eba1UL
#define K_40_59 0x8f1bbcdcUL
#define K_60_79 0xca62c1d6UL

// SHA-1 round functions f(t; B, C, D)
#define F_00_19(B,C,D)  (((B) & (C)) | ((~(B)) & (D)))            // Ch,           rounds 0–19
#define F_20_39(B,C,D)  ((B) ^ (C) ^ (D))                         // Parity,       rounds 20–39
#define F_40_59(B,C,D)  (((B) & (C)) | ((B) & (D)) | ((C) & (D))) // Maj,          rounds 40–59
#define F_60_79(B,C,D)  F_20_39((B),(C),(D))                      // Parity again, rounds 60–79

bool SHA1Init(SHA1_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->h0 = 0x67452301UL;
    ctx->h1 = 0xefcdab89UL;
    ctx->h2 = 0x98badcfeUL;
    ctx->h3 = 0x10325476UL;
    ctx->h4 = 0xc3d2e1f0UL;
    return true;
}

static bool SHA1ProcessBlock(SHA1_CTX *ctx, const uint8_t *block) {
    uint32_t W[80];
    uint32_t A,B,C,D,E,TEMP;

    // Copy block to W[0..15] (big-endian)
    for(int i = 0; i < 16; i++)
        W[i] = SHA_LOAD32(block + i*4);

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
    return true;
} 

bool SHA1Update(SHA1_CTX *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data) return false;

    ctx->len += (uint64_t)len * 8;  // total length in bits

    while (len > 0) {
        size_t to_copy = 64 - ctx->num;   // remaining space in buffer
        if (to_copy > len) to_copy = len;

        memcpy(ctx->buf + ctx->num, data, to_copy);
        ctx->num += (uint32_t)to_copy;    // ctx->num is 32-bit
        data += to_copy;
        len -= to_copy;

        if (ctx->num == 64) {
            if (!SHA1ProcessBlock(ctx, ctx->buf)) return false;
            ctx->num = 0;
        }
    }

    return true;
}

bool SHA1Final(SHA1_CTX *ctx, uint8_t digest[SHA1_DIGEST_SIZE]) {
    if (!ctx || !digest) return false;

    uint8_t block[SHA1_BLOCK_SIZE] = {0};

    // Copy leftover bytes and append 0x80
    memcpy(block, ctx->buf, ctx->num);
    block[ctx->num++] = 0x80;

    // Pad zeros
    if (ctx->num > 56) {
        memset(block + ctx->num, 0, SHA1_BLOCK_SIZE - ctx->num);
        if (!SHA1ProcessBlock(ctx, block)) return false;
        memset(block, 0, 56); // new zeroed block
    } else {
        memset(block + ctx->num, 0, 56 - ctx->num);
    }

    // Append length in bits using SHA_STORE64 (CPU-endian aware)
    SHA_STORE64(block + 56, ctx->len);

    // Process final block
    if (!SHA1ProcessBlock(ctx, block)) return false;

    // Output digest using STORE32
    SHA_STORE32(digest + 0,  ctx->h0);
    SHA_STORE32(digest + 4,  ctx->h1);
    SHA_STORE32(digest + 8,  ctx->h2);
    SHA_STORE32(digest + 12, ctx->h3);
    SHA_STORE32(digest + 16, ctx->h4);

    return true;
}

#endif // ENABLE_SHA1 