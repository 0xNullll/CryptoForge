/*
 * CryptoForge - cf_hash.h / High-level hash/XOF context and utility definitions
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

#ifndef CF_HASH_H
#define CF_HASH_H

#include "../utils/misc.h"
#include "../utils/mem.h"
#include "../utils/cf_status.h"

#include "../config/crypto_config.h"
#include "../config/libs.h"

#include "cf_defs.h"
#include "cf_flags.h"

#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"

#include "../crypto/keccak.h"
#include "../crypto/sha3.h"
#include "../crypto/shake.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _CF_MD {
    uint32_t id;             // CF hash ID/flag
    uint8_t domain;          // Optional Keccak domain/prefix for cSHAKE
    size_t digest_size;      // output size in bytes
    size_t block_size;       // internal block size
    size_t ctx_size;         // size of low-level context
    size_t opts_ctx_size;    // size of high-level optional context
    size_t default_out_len;  // for SHAKE / XOF functions

    bool (*hash_init_fn)(void *ctx, const CF_HASH_OPTS *opts);
    bool (*hash_update_fn)(void *ctx, const uint8_t *data, size_t data_len);
    bool (*hash_final_fn)(void *ctx, uint8_t *digest, size_t digest_size);
    bool (*hash_squeeze_fn)(void *ctx, uint8_t *output, size_t outlen);
} CF_MD;

typedef struct _CF_HASH_OPTS {
    // Output length
    size_t out_len;     // requested output length

    // Fixed-size customization strings
    uint8_t N[CF_MAX_CUSTOMIZATION];
    size_t N_len;
    uint8_t S[CF_MAX_CUSTOMIZATION];
    size_t S_len;

    // Bookkeeping
    int finalized;
    int custom_absorbed;
    int emptyNameCustom;

    int isHeapAlloc;          // 1 if allocated by library (heap), 0 if user stack
} CF_HASH_OPTS;

typedef struct _CF_HASH_CTX {
    const struct _CF_MD *md;  // selected algorithm
    const void *opts;
    void *digest_ctx;          // pointer to low-level context
    size_t out_len;            // optional output length for XOFs

    int isFinalized;
    int isHeapAlloc;           // 1 if allocated by library (heap), 0 if user stack
    int isHeapAllocOpts;
} CF_HASH_CTX;

//
// Algorithm selection
//
CF_API const CF_MD *CF_MD_GetByFlag(uint32_t algo_flag);

//
// Hash initialization / cleanup
//
CF_API CF_STATUS CF_Hash_Init(CF_HASH_CTX *ctx, const CF_MD *md, const CF_HASH_OPTS *opts);
CF_API CF_HASH_CTX* CF_Hash_InitAlloc(const CF_MD *md, const CF_HASH_OPTS *opts, CF_STATUS *status);

CF_API CF_STATUS CF_Hash_Update(CF_HASH_CTX *ctx, const uint8_t *data, size_t data_len);
CF_API CF_STATUS CF_Hash_Final(CF_HASH_CTX *ctx, uint8_t *digest, size_t digest_len);

// Frees internal buffers of a pre-allocated CF_HASH_CTX
CF_API CF_STATUS CF_Hash_Reset(CF_HASH_CTX *ctx);

// Frees internal buffers + heap-allocated CF_HASH_CTX
CF_API CF_STATUS CF_Hash_Free(CF_HASH_CTX **p_ctx);

//
// One-shot hash convenience
//
CF_API CF_STATUS CF_Hash_Compute(
    const CF_MD        *md,
    const uint8_t      *data,
    size_t              data_len,
    uint8_t            *digest,
    size_t              digest_len,
    const CF_HASH_OPTS *opts        // optional hash-specific options
);

CF_API CF_STATUS CF_Hash_ComputeFixed(
    const CF_MD  *md,
    const uint8_t *data,
    size_t         data_len,
    uint8_t       *digest
);

//
// Hash utility functions
//
CF_API CF_STATUS CF_Hash_CloneCtx(CF_HASH_CTX *dst, const CF_HASH_CTX *src);
CF_API CF_HASH_CTX *CF_Hash_CloneCtxAlloc(const CF_HASH_CTX *src, CF_STATUS *status);

CF_API size_t CF_Hash_GetDigestSize(const CF_HASH_CTX *ctx);  // fixed-output hashes
CF_API size_t CF_Hash_GetBlockSize(const CF_HASH_CTX *ctx);
CF_API const char* CF_Hash_GetName(const CF_MD *md);

//
// options initialization / cleanup
//
CF_API CF_STATUS CF_HashOpts_Init(
    CF_HASH_OPTS *opts,
    const uint8_t *N, size_t N_len,
    const uint8_t *S, size_t S_len,
    size_t out_len
);

CF_API CF_HASH_OPTS* CF_HashOpts_InitAlloc(
    const uint8_t *N, size_t N_len,
    const uint8_t *S, size_t S_len,
    size_t out_len,
    CF_STATUS *status
);

CF_API CF_STATUS CF_HashOpts_Reset(CF_HASH_OPTS *opts);
CF_API CF_STATUS CF_HashOpts_Free(CF_HASH_OPTS **p_opts);

CF_API CF_STATUS CF_HashOpts_Clone(CF_HASH_OPTS *dst, const CF_HASH_OPTS *src);
CF_API CF_HASH_OPTS *CF_HashOpts_CloneAlloc(const CF_HASH_OPTS *src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // CF_HASH_H