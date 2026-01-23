/*
 * CryptoForge - evp_hash.h / High-level hash/XOF context and utility definitions
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the MIT License along with this program.
 * If not, see <https://opensource.org/licenses/MIT>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef EVP_HASH_H
#define EVP_HASH_H

#include "../../utils/misc_utils.h"
#include "../../utils/mem.h"
#include "../../utils/cf_status.h"

#include "../../config/crypto_config.h"
#include "../../config/libs.h"

#include "evp_defs.h"
#include "evp_flags.h"

#include "../hash/md/md5.h"
#include "../hash/sha/sha1.h"
#include "../hash/sha/sha256.h"
#include "../hash/sha/sha512.h"

#include "../hash/sha/keccak/keccak.h"
#include "../hash/sha/keccak/sha3.h"
#include "../hash/sha/keccak/shake.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _EVP_MD {
    uint32_t id;             // EVP hash ID/flag
    uint8_t domain;          // Optional Keccak domain/prefix for cSHAKE
    size_t digest_size;      // output size in bytes
    size_t block_size;       // internal block size
    size_t ctx_size;         // size of low-level context
    size_t opts_ctx_size;    // size of high-level optional context
    size_t default_out_len;  // for SHAKE / XOF functions

    bool (*hash_init_fn)(void *ctx, const void *opts);
    bool (*hash_update_fn)(void *ctx, const uint8_t *data, size_t len);
    bool (*hash_final_fn)(void *ctx, uint8_t *digest, size_t digest_size);
    bool (*hash_squeeze_fn)(void *ctx, uint8_t *output, size_t outlen);
} EVP_MD;

typedef struct _EVP_MD_ENTRY {
    uint32_t flag;
    const EVP_MD *(*EVP_MDGetter)(void);
} EVP_MD_ENTRY;

typedef struct _EVP_XOF_OPTS {
    // Output length
    size_t out_len;     // requested output length

    // Fixed-size customization strings
    uint8_t N[EVP_MAX_CUSTOMIZATION];
    size_t N_len;
    uint8_t S[EVP_MAX_CUSTOMIZATION];
    size_t S_len;

    // Bookkeeping
    int finalized;
    int custom_absorbed;
    int emptyNameCustom;

    int isHeapAlloc;          // 1 if allocated by library (heap), 0 if user stack
} EVP_XOF_OPTS;

typedef struct _EVP_HASH_CTX {
    const struct _EVP_MD *md;  // selected algorithm
    const void *opts;
    void *digest_ctx;          // pointer to low-level context
    size_t out_len;            // optional output length for XOFs

    int isFinalized;
    int isHeapAlloc;           // 1 if allocated by library (heap), 0 if user stack
    int isHeapAllocOpts;
} EVP_HASH_CTX;

// ==========================
// Algorithm selection
// ==========================
CF_API const EVP_MD *EVP_MDByFlag(uint32_t algo_flag);

// ==========================
// Hash initialization / cleanup
// ==========================
CF_API CF_STATUS EVP_HashInit(EVP_HASH_CTX *ctx, const EVP_MD *md, const EVP_XOF_OPTS *opts);
CF_API EVP_HASH_CTX* EVP_HashInitAlloc(const EVP_MD *md, const EVP_XOF_OPTS *opts, CF_STATUS *status);

CF_API CF_STATUS EVP_HashUpdate(EVP_HASH_CTX *ctx, const uint8_t *data, size_t data_len);
CF_API CF_STATUS EVP_HashFinal(EVP_HASH_CTX *ctx, uint8_t *digest, size_t digest_len);

// Frees internal buffers of a pre-allocated EVP_HASH_CTX
CF_API CF_STATUS EVP_HashFree(EVP_HASH_CTX *ctx);

// Frees internal buffers + heap-allocated EVP_HASH_CTX
CF_API CF_STATUS EVP_HashFreeAlloc(EVP_HASH_CTX **p_ctx);

// ==========================
// One-shot hash convenience
// ==========================
CF_API CF_STATUS EVP_ComputeHashFixed(
    const EVP_MD  *md,
    uint8_t       *digest,
    const uint8_t *data,
    size_t         data_len
);

CF_API CF_STATUS EVP_ComputeHashXof(
    const EVP_MD       *md,
    uint8_t            *digest,
    const uint8_t      *data,
    size_t              data_len,
    size_t              out_len,
    const EVP_XOF_OPTS *opts     // Optional: hash-specific options
);

// ==========================
// Hash utility functions
// ==========================
CF_API CF_STATUS EVP_CloneHashCtx(EVP_HASH_CTX *dst, const EVP_HASH_CTX *src);
CF_API EVP_HASH_CTX *EVP_CloneHashCtxAlloc(const EVP_HASH_CTX *src, CF_STATUS *status);

CF_API size_t EVP_HashGetDigestSize(const EVP_HASH_CTX *ctx);  // fixed-output hashes
CF_API size_t EVP_HashGetBlockSize(const EVP_HASH_CTX *ctx);
CF_API const char* EVP_HashGetName(const EVP_MD *md);

// ==========================
// XOF options initialization / cleanup
// ==========================
CF_API CF_STATUS EVP_XOFOptsInit(
    EVP_XOF_OPTS *opts,
    const uint8_t *N, size_t N_len,
    const uint8_t *S, size_t S_len,
    size_t out_len
);

CF_API EVP_XOF_OPTS* EVP_XOFOptsInitAlloc(
    const uint8_t *N, size_t N_len,
    const uint8_t *S, size_t S_len,
    size_t out_len,
    CF_STATUS *status
);

CF_API void EVP_XOFOptsFree(EVP_XOF_OPTS *opts);
CF_API void EVP_XOFOptsFreeAlloc(EVP_XOF_OPTS **p_opts);

CF_API CF_STATUS EVP_CloneXOFOpts(EVP_XOF_OPTS *dst, const EVP_XOF_OPTS *src);
CF_API EVP_XOF_OPTS *EVP_CloneXOFOptsAlloc(const EVP_XOF_OPTS *src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // EVP_HASH_H