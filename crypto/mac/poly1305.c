/*
 * CryptoForge - poly1305.c / poly1305 Implementation
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
#include "../../include/crypto/poly1305.h"

/**
 * Poly1305 message-authentication code
 * 
 * Implementation inspired from CycloneCRYPTO (Oryx Embedded SARL, GPL-2.0-or-later)
 */
CF_STATUS ll_POLY1305_Init(ll_POLY1305_CTX *ctx, const uint8_t key[LL_POLY1305_KEY_LEN]) {
    if (!ctx || !key)
        return CF_ERR_NULL_PTR;

    //The 256-bit key is partitioned into two parts, called r and s
    ctx->r[0] = LOAD32LE(key);
    ctx->r[1] = LOAD32LE(key + 4);
    ctx->r[2] = LOAD32LE(key + 8);
    ctx->r[3] = LOAD32LE(key + 12);
    ctx->s[0] = LOAD32LE(key + 16);
    ctx->s[1] = LOAD32LE(key + 20);
    ctx->s[2] = LOAD32LE(key + 24);
    ctx->s[3] = LOAD32LE(key + 28);
  
    //Certain bits of r are required to be 0
    ctx->r[0] &= 0x0FFFFFFF;
    ctx->r[1] &= 0x0FFFFFFC;
    ctx->r[2] &= 0x0FFFFFFC;
    ctx->r[3] &= 0x0FFFFFFC;
  
    //The accumulator is set to zero
    ctx->acc[0] = 0;
    ctx->acc[1] = 0;
    ctx->acc[2] = 0;
    ctx->acc[3] = 0;
    ctx->acc[4] = 0;
  
    //Number of bytes in the buffer
    ctx->buffer_len = 0;
    
    return CF_SUCCESS;
}

ll_POLY1305_CTX* ll_POLY1305_InitAlloc(const uint8_t key[LL_POLY1305_KEY_LEN], CF_STATUS *status) {
    if (!key) {
        if (status) *status = CF_ERR_INVALID_PARAM;
        return NULL;
    }



    ll_POLY1305_CTX *ctx = (ll_POLY1305_CTX *)SECURE_ALLOC(sizeof(ll_POLY1305_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = ll_POLY1305_Init(ctx, key);
    if (st != CF_SUCCESS) {
        SECURE_FREE(ctx, sizeof(ll_POLY1305_CTX));
        if (status) *status = st;
        return NULL;
    }

    ctx->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return ctx;
}

static bool ll_POLY1305_ProcessBlock(ll_POLY1305_CTX *ctx) {
    if (!ctx)
        return false;

    size_t n;
    uint64_t temp;
    uint32_t u[8];
  
    //Retrieve the length of the last block
    n = ctx->buffer_len;
  
    ctx->buffer[n++] = 0x01;
  
    //If the resulting block is not 17 bytes long (the last block),
    //pad it with zeros
    while(n < 17) {
       ctx->buffer[n++] = 0x00;
    }
  
    //Read the block
    u[0] = LOAD32LE(ctx->buffer);
    u[1] = LOAD32LE(ctx->buffer + 4);
    u[2] = LOAD32LE(ctx->buffer + 8);
    u[3] = LOAD32LE(ctx->buffer + 12);
    u[4] = ctx->buffer[16];
  
    //Add this number to the accumulator
    temp = (uint64_t) ctx->acc[0] + u[0];
    ctx->acc[0] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[1] + u[1];
    ctx->acc[1] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[2] + u[2];
    ctx->acc[2] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[3] + u[3];
    ctx->acc[3] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[4] + u[4];
    ctx->acc[4] = temp & 0xFFFFFFFF;
  
    //Multiply the accumulator by r
    temp = (uint64_t) ctx->acc[0] * ctx->r[0];
    u[0] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[0] * ctx->r[1];
    temp += (uint64_t) ctx->acc[1] * ctx->r[0];
    u[1] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[0] * ctx->r[2];
    temp += (uint64_t) ctx->acc[1] * ctx->r[1];
    temp += (uint64_t) ctx->acc[2] * ctx->r[0];
    u[2] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[0] * ctx->r[3];
    temp += (uint64_t) ctx->acc[1] * ctx->r[2];
    temp += (uint64_t) ctx->acc[2] * ctx->r[1];
    temp += (uint64_t) ctx->acc[3] * ctx->r[0];
    u[3] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[1] * ctx->r[3];
    temp += (uint64_t) ctx->acc[2] * ctx->r[2];
    temp += (uint64_t) ctx->acc[3] * ctx->r[1];
    temp += (uint64_t) ctx->acc[4] * ctx->r[0];
    u[4] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[2] * ctx->r[3];
    temp += (uint64_t) ctx->acc[3] * ctx->r[2];
    temp += (uint64_t) ctx->acc[4] * ctx->r[1];
    u[5] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[3] * ctx->r[3];
    temp += (uint64_t) ctx->acc[4] * ctx->r[2];
    u[6] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[4] * ctx->r[3];
    u[7] = temp & 0xFFFFFFFF;
  
    //Perform modular reduction
    temp = u[0];
    temp += u[4] & 0xFFFFFFFC;
    temp += (u[4] >> 2) | (u[5] << 30);
    ctx->acc[0] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += u[1];
    temp += u[5];
    temp += (u[5] >> 2) | (u[6] << 30);
    ctx->acc[1] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += u[2];
    temp += u[6];
    temp += (u[6] >> 2) | (u[7] << 30);
    ctx->acc[2] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += u[3];
    temp += u[7];
    temp += u[7] >> 2;
    ctx->acc[3] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += u[4] & 0x00000003;
    ctx->acc[4] = temp & 0xFFFFFFFF;

    return true;
}

CF_STATUS ll_POLY1305_Update(ll_POLY1305_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx || !data)
        return CF_ERR_NULL_PTR;

    size_t i;

    while (data_len > 0) {
        // Copy up to remaining buffer space or remaining data
        i = data_len < (16 - ctx->buffer_len) ? data_len : (16 - ctx->buffer_len);

        SECURE_MEMCPY(ctx->buffer + ctx->buffer_len, data, i);

        ctx->buffer_len += i;
        data += i;
        data_len -= i;

        // Process full 16-byte blocks
       if(ctx->buffer_len == 16) {
          //Transform the 16-byte block
          ll_POLY1305_ProcessBlock(ctx);
          //Empty the buffer
          ctx->buffer_len = 0;
       }
    }

    return CF_SUCCESS;
}

CF_STATUS ll_POLY1305_Final(ll_POLY1305_CTX *ctx, uint8_t tag[LL_POLY1305_TAG_LEN]) {
    if (!ctx || !tag)
        return CF_ERR_NULL_PTR;

    uint64_t temp;
    uint32_t mask;
    uint32_t b[5];
  
    //Process the last block
    if(ctx->buffer_len != 0) {
       ll_POLY1305_ProcessBlock(ctx);
    }
  
    //Perform modular reduction (2^130 = 5)
    temp = ctx->acc[4] & 0xFFFFFFFC;
    temp += ctx->acc[4] >> 2;
    temp += ctx->acc[0];
    ctx->acc[0] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += ctx->acc[1];
    ctx->acc[1] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += ctx->acc[2];
    ctx->acc[2] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += ctx->acc[3];
    ctx->acc[3] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += ctx->acc[4];
    ctx->acc[4] = temp & 0x00000003;
  
    //Compute b = a + 5
    temp = 5;
    temp += ctx->acc[0];
    b[0] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += ctx->acc[1];
    b[1] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += ctx->acc[2];
    b[2] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += ctx->acc[3];
    b[3] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += ctx->acc[4];
    b[4] = temp & 0xFFFFFFFF;
  
    //If (a + 5) >= 2^130, form a mask with the value 0x00000000. Else,
    //form a mask with the value 0xffffffff
    mask = ((b[4] & 0x04) >> 2) - 1;
  
    //Select between (a % 2^128) and (b % 2^128)
    ctx->acc[0] = (ctx->acc[0] & mask) | (b[0] & ~mask);
    ctx->acc[1] = (ctx->acc[1] & mask) | (b[1] & ~mask);
    ctx->acc[2] = (ctx->acc[2] & mask) | (b[2] & ~mask);
    ctx->acc[3] = (ctx->acc[3] & mask) | (b[3] & ~mask);
  
    //Finally, the value of the secret key s is added to the accumulator
    temp = (uint64_t) ctx->acc[0] + ctx->s[0];
    b[0] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[1] + ctx->s[1];
    b[1] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[2] + ctx->s[2];
    b[2] = temp & 0xFFFFFFFF;
    temp >>= 32;
    temp += (uint64_t) ctx->acc[3] + ctx->s[3];
    b[3] = temp & 0xFFFFFFFF;
  
    //The result is serialized, producing
    //the 16 byte tag
    STORE32LE(tag, b[0]);
    STORE32LE(tag + 4, b[1]);
    STORE32LE(tag + 8, b[2]);
    STORE32LE(tag + 12, b[3]);
  
    //Clear the accumulator
    ctx->acc[0] = 0;
    ctx->acc[1] = 0;
    ctx->acc[2] = 0;
    ctx->acc[3] = 0;
    ctx->acc[4] = 0;
  
    //Clear r and s
    ctx->r[0] = 0;
    ctx->r[1] = 0;
    ctx->r[2] = 0;
    ctx->r[3] = 0;
    ctx->s[0] = 0;
    ctx->s[1] = 0;
    ctx->s[2] = 0;
    ctx->s[3] = 0;

    return CF_SUCCESS;
}

CF_STATUS ll_POLY1305_Reset(ll_POLY1305_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    SECURE_ZERO(ctx->r, sizeof(ctx->r));
    SECURE_ZERO(ctx->s, sizeof(ctx->s));
    SECURE_ZERO(ctx->acc, sizeof(ctx->acc));
    SECURE_ZERO(ctx->buffer, sizeof(ctx->buffer));
    ctx->buffer_len = 0;
    ctx->isFinalized = 0;
    
    return CF_SUCCESS;
}

CF_STATUS ll_POLY1305_Verify(
    const uint8_t key[LL_POLY1305_KEY_LEN],
    const uint8_t *data, size_t data_len,
    const uint8_t expected_tag[LL_POLY1305_TAG_LEN]) {
    if (!key || !data || !expected_tag)
        return CF_ERR_NULL_PTR;

    CF_STATUS st = CF_SUCCESS;

    uint8_t tag[LL_POLY1305_TAG_LEN] = {0};
    ll_POLY1305_CTX ctx = {0};

    // Initialize ctx with key
    st = ll_POLY1305_Init(&ctx, key);
    if (st != CF_SUCCESS) goto cleanup;

    // Update with message data
    st = ll_POLY1305_Update(&ctx, data, data_len);
    if (st != CF_SUCCESS) goto cleanup;

    // Finalize and compute tag
    st = ll_POLY1305_Final(&ctx, tag);
    if (st != CF_SUCCESS) goto cleanup;

    // Constant-time comparison
    st = SECURE_MEM_EQUAL(tag, expected_tag, LL_POLY1305_TAG_LEN) ? CF_SUCCESS : CF_ERR_MAC_VERIFY;

cleanup:
    ll_POLY1305_Reset(&ctx);
    SECURE_ZERO(tag, sizeof(tag));

    return st;
}

CF_STATUS ll_POLY1305_Free(ll_POLY1305_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    ll_POLY1305_CTX *ctx = *p_ctx;
    int wasHeapAlloc = ctx->isHeapAlloc;

    ll_POLY1305_Reset(ctx);

    // Free the outer struct if heap-allocated
    if (wasHeapAlloc)
        SECURE_FREE(ctx, sizeof(ll_POLY1305_CTX));

    return CF_SUCCESS;
}

CF_STATUS ll_POLY1305_CloneCtx(ll_POLY1305_CTX *ctx_dest, const ll_POLY1305_CTX *ctx_src) {
    if (!ctx_dest || !ctx_src)
        return CF_ERR_NULL_PTR;

    // Zero the destination first
    ll_POLY1305_Reset(ctx_dest);
    
    // Copy r, s, and accumulator arrays
    SECURE_MEMCPY(ctx_dest->r, ctx_src->r, sizeof(ctx_dest->r));
    SECURE_MEMCPY(ctx_dest->s, ctx_src->s, sizeof(ctx_dest->s));
    SECURE_MEMCPY(ctx_dest->acc, ctx_src->acc, sizeof(ctx_dest->acc));

    // Copy partial buffer and buffer length
    SECURE_MEMCPY(ctx_dest->buffer, ctx_src->buffer, sizeof(ctx_dest->buffer));
    ctx_dest->buffer_len = ctx_src->buffer_len;

    // Copy flags
    ctx_dest->isFinalized = ctx_src->isFinalized;
    ctx_dest->isHeapAlloc = 0; // caller owns this destination

    return CF_SUCCESS;
}

ll_POLY1305_CTX* ll_POLY1305_CloneCtxAlloc(const ll_POLY1305_CTX *ctx_src, CF_STATUS *status) {
    if (!ctx_src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Allocate a new ll_POLY1305_CTX on the heap
    ll_POLY1305_CTX *ctx_dest = (ll_POLY1305_CTX *)SECURE_ALLOC(sizeof(ll_POLY1305_CTX));
    if (!ctx_dest) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Use existing clone function to copy contents
    CF_STATUS ret = ll_POLY1305_CloneCtx(ctx_dest, ctx_src);
    if (ret != CF_SUCCESS) {
        SECURE_FREE(ctx_dest, sizeof(ll_POLY1305_CTX));
        if (status) *status = ret;
        return NULL;
    }

    ctx_dest->isHeapAlloc = 1; // library owns this memory

    if (status) *status = CF_SUCCESS;
    return ctx_dest;
}
