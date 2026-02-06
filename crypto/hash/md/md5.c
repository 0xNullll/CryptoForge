/*
 * CryptoForge - md5.c / MD5 Core Implementation
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

#include "../../../include/crypto/md5.h"

// =======================
// Word <-> Byte conversions
// =======================
#if CPU_BIG_ENDIAN
// On big-endian CPUs, swap bytes to little-endian
static FORCE_INLINE void HASH_PACK32(uint8_t *out, const uint32_t *in, unsigned int len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        out[j]   = (uint8_t)(in[i] & 0xff);
        out[j+1] = (uint8_t)((in[i] >> 8) & 0xff);
        out[j+2] = (uint8_t)((in[i] >>16) & 0xff);
        out[j+3] = (uint8_t)((in[i] >>24) & 0xff);
    }
}

static FORCE_INLINE void HASH_UNPACK32(uint32_t *out, const uint8_t *in, unsigned int len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        out[i] = ((uint32_t)in[j]) |
                 ((uint32_t)in[j+1] << 8) |
                 ((uint32_t)in[j+2] << 16) |
                 ((uint32_t)in[j+3] << 24);
    }
}
#else
// On little-endian CPUs, memory matches the format -> use direct memcpy
static FORCE_INLINE void HASH_PACK32(uint8_t *out, const uint32_t *in, unsigned int len) {
    SECURE_MEMCPY(out, in, len);
}

static FORCE_INLINE void HASH_UNPACK32(uint32_t *out, const uint8_t *in, unsigned int len) {
    SECURE_MEMCPY(out, in, len);
}
#endif

// MD5 constants
#define F(x,y,z) (((x)&(y)) | ((~(x)) & (z)))
#define G(x,y,z) (((x)&(z)) | ((y)&(~(z))))
#define H(x,y,z) ((x) ^ (y) ^ (z))
#define I(x,y,z) ((y) ^ ((x) | (~(z))))

#define FF(a,b,c,d,x,s,ac) { \
    (a)+=F((b),(c),(d))+(x)+(uint32_t)(ac); \
    (a)=ROTL32((a),(s)); \
    (a)+=(b); \
}

#define GG(a,b,c,d,x,s,ac) { \
    (a)+=G((b),(c),(d))+(x)+(uint32_t)(ac); \
    (a)=ROTL32((a),(s)); \
    (a)+=(b); \
}
#define HH(a,b,c,d,x,s,ac) { \
    (a)+=H((b),(c),(d))+(x)+(uint32_t)(ac); \
    (a)=ROTL32((a),(s)); \
    (a)+=(b); \
}
#define II(a,b,c,d,x,s,ac) { \
    (a)+=I((b),(c),(d))+(x)+(uint32_t)(ac); \
    (a)=ROTL32((a),(s)); \
    (a)+=(b); \
}

// MD5 block transform
static bool ll_md5_process_block(ll_MD5_CTX *ctx, const uint8_t block[64]){
    uint32_t a=ctx->state[0], b=ctx->state[1], c=ctx->state[2], d=ctx->state[3], x[16];
    HASH_UNPACK32(x, block, 64);

    // Round 1
    FF(a,b,c,d,x[0],7,0xd76aa478);   FF(d,a,b,c,x[1],12,0xe8c7b756);
    FF(c,d,a,b,x[2],17,0x242070db);  FF(b,c,d,a,x[3],22,0xc1bdceee);
    FF(a,b,c,d,x[4],7,0xf57c0faf);   FF(d,a,b,c,x[5],12,0x4787c62a);
    FF(c,d,a,b,x[6],17,0xa8304613);  FF(b,c,d,a,x[7],22,0xfd469501);
    FF(a,b,c,d,x[8],7,0x698098d8);   FF(d,a,b,c,x[9],12,0x8b44f7af);
    FF(c,d,a,b,x[10],17,0xffff5bb1); FF(b,c,d,a,x[11],22,0x895cd7be);
    FF(a,b,c,d,x[12],7,0x6b901122);  FF(d,a,b,c,x[13],12,0xfd987193);
    FF(c,d,a,b,x[14],17,0xa679438e); FF(b,c,d,a,x[15],22,0x49b40821);

    // Round 2
    GG(a,b,c,d,x[1],5,0xf61e2562);   GG(d,a,b,c,x[6],9,0xc040b340);
    GG(c,d,a,b,x[11],14,0x265e5a51); GG(b,c,d,a,x[0],20,0xe9b6c7aa);
    GG(a,b,c,d,x[5],5,0xd62f105d);   GG(d,a,b,c,x[10],9,0x02441453);
    GG(c,d,a,b,x[15],14,0xd8a1e681); GG(b,c,d,a,x[4],20,0xe7d3fbc8);
    GG(a,b,c,d,x[9],5,0x21e1cde6);   GG(d,a,b,c,x[14],9,0xc33707d6);
    GG(c,d,a,b,x[3],14,0xf4d50d87);  GG(b,c,d,a,x[8],20,0x455a14ed);
    GG(a,b,c,d,x[13],5,0xa9e3e905);  GG(d,a,b,c,x[2],9,0xfcefa3f8);
    GG(c,d,a,b,x[7],14,0x676f02d9);  GG(b,c,d,a,x[12],20,0x8d2a4c8a);

    // Round 3
    HH(a,b,c,d,x[5],4,0xfffa3942);   HH(d,a,b,c,x[8],11,0x8771f681);
    HH(c,d,a,b,x[11],16,0x6d9d6122); HH(b,c,d,a,x[14],23,0xfde5380c);
    HH(a,b,c,d,x[1],4,0xa4beea44);   HH(d,a,b,c,x[4],11,0x4bdecfa9);
    HH(c,d,a,b,x[7],16,0xf6bb4b60);  HH(b,c,d,a,x[10],23,0xbebfbc70);
    HH(a,b,c,d,x[13],4,0x289b7ec6);  HH(d,a,b,c,x[0],11,0xeaa127fa);
    HH(c,d,a,b,x[3],16,0xd4ef3085);  HH(b,c,d,a,x[6],23,0x04881d05);
    HH(a,b,c,d,x[9],4,0xd9d4d039);   HH(d,a,b,c,x[12],11,0xe6db99e5);
    HH(c,d,a,b,x[15],16,0x1fa27cf8); HH(b,c,d,a,x[2],23,0xc4ac5665);

    // Round 4
    II(a,b,c,d,x[0],6,0xf4292244);   II(d,a,b,c,x[7],10,0x432aff97);
    II(c,d,a,b,x[14],15,0xab9423a7); II(b,c,d,a,x[5],21,0xfc93a039);
    II(a,b,c,d,x[12],6,0x655b59c3);  II(d,a,b,c,x[3],10,0x8f0ccc92);
    II(c,d,a,b,x[10],15,0xffeff47d); II(b,c,d,a,x[1],21,0x85845dd1);
    II(a,b,c,d,x[8],6,0x6fa87e4f);   II(d,a,b,c,x[15],10,0xfe2ce6e0);
    II(c,d,a,b,x[6],15,0xa3014314);  II(b,c,d,a,x[13],21,0x4e0811a1);
    II(a,b,c,d,x[4],6,0xf7537e82);   II(d,a,b,c,x[11],10,0xbd3af235);
    II(c,d,a,b,x[2],15,0x2ad7d2bb);  II(b,c,d,a,x[9],21,0xeb86d391);

    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    SECURE_ZERO(x, sizeof(x));
    return true;
}

bool ll_md5_init(ll_MD5_CTX *ctx){
    SECURE_ZERO(ctx, sizeof(*ctx));
    ctx->state[0]=0x67452301UL;
    ctx->state[1]=0xefcdab89UL;
    ctx->state[2]=0x98badcfeUL;
    ctx->state[3]=0x10325476UL;

    ctx->bitlen=0;
    ctx->buffer_len=0;
    return true;
}

bool ll_md5_update(ll_MD5_CTX *ctx,const uint8_t *data,size_t len){
    if(!ctx || !data) return false;
    size_t i = 0;
    while(i < len){
        size_t space = MD5_BLOCK_SIZE-ctx->buffer_len;
        size_t to_copy = (len - i < space) ? len - i : space;
        SECURE_MEMCPY(ctx->buffer + ctx->buffer_len, data + i, to_copy);
        ctx->buffer_len += to_copy;
        ctx->bitlen += to_copy * 8;
        i += to_copy;
        if(ctx->buffer_len == MD5_BLOCK_SIZE){
            if(!ll_md5_process_block(ctx,ctx->buffer)) return false;
            ctx->buffer_len = 0;
        }
    }
    return true;
}

bool ll_md5_final(ll_MD5_CTX *ctx,uint8_t digest[MD5_DIGEST_SIZE]){
    if(!ctx || !digest) return false;

    uint8_t block[MD5_BLOCK_SIZE] = {0};
    SECURE_MEMCPY(block, ctx->buffer, ctx->buffer_len);
    block[ctx->buffer_len++] = 0x80;

    size_t padLen = (ctx->buffer_len > 56) ? (120 - ctx->buffer_len) : (56 - ctx->buffer_len);
    SECURE_MEMSET(block + ctx->buffer_len, 0, padLen);
    ctx->buffer_len += padLen;

    // Append length in bits
    STORE64LE(block + 56 ,ctx->bitlen);

    if(!ll_md5_process_block(ctx,block)) return false;
    
    HASH_PACK32(digest, ctx->state, MD5_DIGEST_SIZE);

    SECURE_ZERO(block, sizeof(*block));
    return true;
}