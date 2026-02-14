/*
 * CryptoForge - cf_hash.c / High-level hash/XOF context implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../include/cf_api/cf_hash.h"


//
// Wrappers for all hashes
//

// MD5
static bool md5_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_md5_init((ll_MD5_CTX *)ctx);
}

static bool md5_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_md5_update((ll_MD5_CTX *)ctx, data, data_len);
}
static bool md5_final_wrapper(void *ctx, uint8_t *digest) {
    return ll_md5_final((ll_MD5_CTX *)ctx, digest);
}

//
// SHA1 / SHA256 / SHA512
//

// SHA1
static bool sha1_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_sha1_init((ll_SHA1_CTX *)ctx);
}
static bool sha1_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_sha1_update((ll_SHA1_CTX *)ctx, data, data_len);
}
static bool sha1_final_wrapper(void *ctx, uint8_t *digest) {
    return ll_sha1_final((ll_SHA1_CTX *)ctx, digest);
}

// SHA224
static bool sha224_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_sha224_init((ll_SHA224_CTX *)ctx);
}
static bool sha224_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_sha224_update((ll_SHA224_CTX *)ctx, data, data_len);
}
static bool sha224_final_wrapper(void *ctx, uint8_t *digest) {
    return ll_sha224_final((ll_SHA224_CTX *)ctx, digest);
}

// SHA256
static bool sha256_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_sha256_init((ll_SHA256_CTX *)ctx);
}
static bool sha256_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_sha256_update((ll_SHA256_CTX *)ctx, data, data_len);
}
static bool sha256_final_wrapper(void *ctx, uint8_t *digest) {
    return ll_sha256_final((ll_SHA256_CTX *)ctx, digest);
}

// SHA384
static bool sha384_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_sha384_init((ll_SHA384_CTX *)ctx);
}
static bool sha384_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_sha384_update((ll_SHA384_CTX *)ctx, data, data_len);
}
static bool sha384_final_wrapper(void *ctx, uint8_t *digest) {
    return ll_sha384_final((ll_SHA384_CTX *)ctx, digest);
}

// SHA512
static bool sha512_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_sha512_init((ll_SHA512_CTX *)ctx);
}
static bool sha512_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_sha512_update((ll_SHA512_CTX *)ctx, data, data_len);
}
static bool sha512_final_wrapper(void *ctx, uint8_t *digest) {
    return ll_sha512_final((ll_SHA512_CTX *)ctx, digest);
}

// SHA512_224
static bool sha512_224_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_sha512_224_init((ll_SHA512_224_CTX *)ctx);
}
static bool sha512_224_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_sha512_224_update((ll_SHA512_224_CTX *)ctx, data, data_len);
}
static bool sha512_224_final_wrapper(void *ctx, uint8_t *digest) {
    return ll_sha512_224_final((ll_SHA512_224_CTX *)ctx, digest);
}

// SHA512_256
static bool sha512_256_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_sha512_256_init((ll_SHA512_256_CTX *)ctx);
}
static bool sha512_256_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_sha512_256_update((ll_SHA512_256_CTX *)ctx, data, data_len);
}
static bool sha512_256_final_wrapper(void *ctx, uint8_t *digest) {
    return ll_sha512_256_final((ll_SHA512_256_CTX *)ctx, digest);
}

//
// SHA3 / SHAKE / RawSHAKE
//
// SHA3-224
static bool sha3_224_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_sha3_224_init((ll_SHA3_224_CTX *)ctx);
}
static bool sha3_224_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_sha3_224_absorb((ll_SHA3_224_CTX *)ctx, data, data_len);
}
static bool sha3_224_final_wrapper(void *ctx, uint8_t *digest) {
    UNUSED(digest);
    return ll_sha3_224_final((ll_SHA3_224_CTX *)ctx);
}
static bool sha3_224_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_sha3_224_squeeze((ll_SHA3_224_CTX *)ctx, output, outlen);
}

// SHA3-256
static bool sha3_256_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_sha3_256_init((ll_SHA3_256_CTX *)ctx);
}
static bool sha3_256_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_sha3_256_absorb((ll_SHA3_256_CTX *)ctx, data, data_len);
}
static bool sha3_256_final_wrapper(void *ctx, uint8_t *digest) {
    UNUSED(digest);
    return ll_sha3_256_final((ll_SHA3_256_CTX *)ctx);
}
static bool sha3_256_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_sha3_256_squeeze((ll_SHA3_256_CTX *)ctx, output, outlen);
}

// SHA3-384
static bool sha3_384_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_sha3_384_init((ll_SHA3_384_CTX *)ctx);
}
static bool sha3_384_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_sha3_384_absorb((ll_SHA3_384_CTX *)ctx, data, data_len);
}
static bool sha3_384_final_wrapper(void *ctx, uint8_t *digest) {
    UNUSED(digest);
    return ll_sha3_384_final((ll_SHA3_384_CTX *)ctx);
}
static bool sha3_384_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_sha3_384_squeeze((ll_SHA3_384_CTX *)ctx, output, outlen);
}

// SHA3-512
static bool sha3_512_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_sha3_512_init((ll_SHA3_512_CTX *)ctx);
}
static bool sha3_512_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_sha3_512_absorb((ll_SHA3_512_CTX *)ctx, data, data_len);
}
static bool sha3_512_final_wrapper(void *ctx, uint8_t *digest) {
    UNUSED(digest);
    return ll_sha3_512_final((ll_SHA3_512_CTX *)ctx);
}
static bool sha3_512_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_sha3_512_squeeze((ll_SHA3_512_CTX *)ctx, output, outlen);
}

// SHAKE128
static bool shake128_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_shake128_init((ll_SHAKE128_CTX *)ctx);
}
static bool shake128_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_shake128_absorb((ll_SHAKE128_CTX *)ctx, data, data_len);
}
static bool shake128_final_wrapper(void *ctx, uint8_t *digest) {
    UNUSED(digest);
    return ll_shake128_final((ll_SHAKE128_CTX *)ctx);
}
static bool shake128_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_shake128_squeeze((ll_SHAKE128_CTX *)ctx, output, outlen);
}

// SHAKE256
static bool shake256_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_shake256_init((ll_SHAKE256_CTX *)ctx);
}
static bool shake256_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_shake256_absorb((ll_SHAKE256_CTX *)ctx, data, data_len);
}
static bool shake256_final_wrapper(void *ctx, uint8_t *digest) {
    UNUSED(digest);
    return ll_shake256_final((ll_SHAKE256_CTX *)ctx);
}
static bool shake256_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_shake256_squeeze((ll_SHAKE256_CTX *)ctx, output, outlen);
}

// RawSHAKE128
static bool rawshake128_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_rawshake128_init((ll_RawSHAKE128_CTX *)ctx);
}
static bool rawshake128_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_rawshake128_absorb((ll_RawSHAKE128_CTX *)ctx, data, data_len);
}
static bool rawshake128_final_wrapper(void *ctx, uint8_t *digest) {
    UNUSED(digest);
    return ll_rawshake128_final((ll_RawSHAKE128_CTX *)ctx);
}
static bool rawshake128_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_rawshake128_squeeze((ll_RawSHAKE128_CTX *)ctx, output, outlen);
}

// RawSHAKE256
static bool rawshake256_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    UNUSED(opts);
    return ll_rawshake256_init((ll_RawSHAKE256_CTX *)ctx);
}
static bool rawshake256_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_rawshake256_absorb((ll_RawSHAKE256_CTX *)ctx, data, data_len);
}
static bool rawshake256_final_wrapper(void *ctx, uint8_t *digest) {
    UNUSED(digest);
    return ll_rawshake256_final((ll_RawSHAKE256_CTX *)ctx);
}
static bool rawshake256_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_rawshake256_squeeze((ll_RawSHAKE256_CTX *)ctx, output, outlen);
}

//
// cSHAKE128 simple wrappers
//
static bool cshake128_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    return ll_cshake128_init(
        (ll_CSHAKE128_CTX *)ctx,
        opts ? opts->N : NULL,
        opts ? opts->N_len : 0,
        opts ? opts->S : NULL,
        opts ? opts->S_len : 0
    );
}

static bool cshake128_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_cshake128_absorb((ll_CSHAKE128_CTX *)ctx, data, data_len);
}

static bool cshake128_final_wrapper(void *ctx, uint8_t *digest) {
    UNUSED(digest);
    return ll_cshake128_final((ll_CSHAKE128_CTX *)ctx);
}

static bool cshake128_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_cshake128_squeeze((ll_CSHAKE128_CTX *)ctx, output, outlen);
}

//
// cSHAKE256 simple wrappers
//
static bool cshake256_init_wrapper(void *ctx, const CF_HASH_OPTS *opts) {
    return ll_cshake256_init(
        (ll_CSHAKE256_CTX *)ctx,
        opts ? opts->N : NULL,
        opts ? opts->N_len : 0,
        opts ? opts->S : NULL,
        opts ? opts->S_len : 0
    );
}

static bool cshake256_update_wrapper(void *ctx, const uint8_t *data, size_t data_len) {
    return ll_cshake256_absorb((ll_CSHAKE256_CTX *)ctx, data, data_len);
}

static bool cshake256_final_wrapper(void *ctx, uint8_t *digest) {
    UNUSED(digest);
    return ll_cshake256_final((ll_CSHAKE256_CTX *)ctx);
}

static bool cshake256_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_cshake256_squeeze((ll_CSHAKE256_CTX *)ctx, output, outlen);
}

// --- CF_MD Return Functions ---

//
// MD5
//
static const CF_MD *CF_get_md5(void) {
    static CF_MD md = {
        .id = CF_MD5,
        .domain = 0,
        .digest_size = MD5_DIGEST_SIZE,
        .block_size = MD5_BLOCK_SIZE,
        .ctx_size = sizeof(ll_MD5_CTX),
        .default_out_len = MD5_DIGEST_SIZE,
        .hash_init_fn = md5_init_wrapper,
        .hash_update_fn = md5_update_wrapper,
        .hash_final_fn = md5_final_wrapper,
        .hash_squeeze_fn = NULL,
    };
    return &md;
}

//
// SHA1
//
static const CF_MD *CF_get_sha1(void) {
    static CF_MD md = {
        .id = CF_SHA1,
        .domain = 0,
        .digest_size = SHA1_DIGEST_SIZE,
        .block_size = SHA1_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA1_CTX),
        .default_out_len = SHA1_DIGEST_SIZE,
        .hash_init_fn = sha1_init_wrapper,
        .hash_update_fn = sha1_update_wrapper,
        .hash_final_fn = sha1_final_wrapper,
        .hash_squeeze_fn = NULL,
    };
    return &md;
}

//
// SHA256
//
static const CF_MD *CF_get_sha224(void) {
    static CF_MD md = {
        .id = CF_SHA224,
        .domain = 0,
        .digest_size = SHA224_DIGEST_SIZE,
        .block_size = SHA224_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA224_CTX),
        .default_out_len = SHA224_DIGEST_SIZE,
        .hash_init_fn = sha224_init_wrapper,
        .hash_update_fn = sha224_update_wrapper,
        .hash_final_fn = sha224_final_wrapper,
        .hash_squeeze_fn = NULL,
    };
    return &md;
}

static const CF_MD *CF_get_sha256(void) {
    static CF_MD md = {
        .id = CF_SHA256,
        .domain = 0,
        .digest_size = SHA256_DIGEST_SIZE,
        .block_size = SHA256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA256_CTX),
        .default_out_len = SHA256_DIGEST_SIZE,
        .hash_init_fn = sha256_init_wrapper,
        .hash_update_fn = sha256_update_wrapper,
        .hash_final_fn = sha256_final_wrapper,
        .hash_squeeze_fn = NULL,
    };
    return &md;
}

//
// SHA512
//
static const CF_MD *CF_get_sha384(void) {
    static CF_MD md = {
        .id = CF_SHA384,
        .domain = 0,
        .digest_size = SHA384_DIGEST_SIZE,
        .block_size = SHA384_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA384_CTX),
        .default_out_len = SHA384_DIGEST_SIZE,
        .hash_init_fn = sha384_init_wrapper,
        .hash_update_fn = sha384_update_wrapper,
        .hash_final_fn = sha384_final_wrapper,
        .hash_squeeze_fn = NULL,
    };
    return &md;
}

static const CF_MD *CF_get_sha512(void) {
    static CF_MD md = {
        .id = CF_SHA512,
        .domain = 0,
        .digest_size = SHA512_DIGEST_SIZE,
        .block_size = SHA512_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA512_CTX),
        .default_out_len = SHA512_DIGEST_SIZE,
        .hash_init_fn = sha512_init_wrapper,
        .hash_update_fn = sha512_update_wrapper,
        .hash_final_fn = sha512_final_wrapper,
        .hash_squeeze_fn = NULL,
    };
    return &md;
}

static const CF_MD *CF_get_sha512_224(void) {
    static CF_MD md = {
        .id = CF_SHA512_224,
        .domain = 0,
        .digest_size = SHA512_224_DIGEST_SIZE,
        .block_size = SHA512_224_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA512_224_CTX),
        .default_out_len = SHA512_224_DIGEST_SIZE,
        .hash_init_fn = sha512_224_init_wrapper,
        .hash_update_fn = sha512_224_update_wrapper,
        .hash_final_fn = sha512_224_final_wrapper,
        .hash_squeeze_fn = NULL,
    };
    return &md;
}

static const CF_MD *CF_get_sha512_256(void) {
    static CF_MD md = {
        .id = CF_SHA512_256,
        .domain = 0,
        .digest_size = SHA512_256_DIGEST_SIZE,
        .block_size = SHA512_256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA512_256_CTX),
        .default_out_len = SHA512_256_DIGEST_SIZE,
        .hash_init_fn = sha512_256_init_wrapper,
        .hash_update_fn = sha512_256_update_wrapper,
        .hash_final_fn = sha512_256_final_wrapper,
        .hash_squeeze_fn = NULL,
    };
    return &md;
}

//
// SHA3
//
static const CF_MD *CF_get_sha3_224(void) {
    static CF_MD md = {
        .id = CF_SHA3_224,
        .domain = 0,
        .digest_size = SHA3_224_DIGEST_SIZE,
        .block_size = SHA3_224_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA3_224_CTX),
        .default_out_len = SHA3_224_DIGEST_SIZE,
        .hash_init_fn = sha3_224_init_wrapper,
        .hash_update_fn = sha3_224_update_wrapper,
        .hash_final_fn = sha3_224_final_wrapper,
        .hash_squeeze_fn = sha3_224_squeeze_wrapper,
    };
    return &md;
}

static const CF_MD *CF_get_sha3_256(void) {
    static CF_MD md = {
        .id = CF_SHA3_256,
        .domain = 0,
        .digest_size = SHA3_256_DIGEST_SIZE,
        .block_size = SHA3_256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA3_256_CTX),
        .default_out_len = SHA3_256_DIGEST_SIZE,
        .hash_init_fn = sha3_256_init_wrapper,
        .hash_update_fn = sha3_256_update_wrapper,
        .hash_final_fn = sha3_256_final_wrapper,
        .hash_squeeze_fn = sha3_256_squeeze_wrapper,
    };
    return &md;
}

static const CF_MD *CF_get_sha3_384(void) {
    static CF_MD md = {
        .id = CF_SHA3_384,
        .domain = 0,
        .digest_size = SHA3_384_DIGEST_SIZE,
        .block_size = SHA3_384_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA3_384_CTX),
        .default_out_len = SHA3_384_DIGEST_SIZE,
        .hash_init_fn = sha3_384_init_wrapper,
        .hash_update_fn = sha3_384_update_wrapper,
        .hash_final_fn = sha3_384_final_wrapper,
        .hash_squeeze_fn = sha3_384_squeeze_wrapper,
    };
    return &md;
}

static const CF_MD *CF_get_sha3_512(void) {
    static CF_MD md = {
        .id = CF_SHA3_512,
        .domain = 0,
        .digest_size = SHA3_512_DIGEST_SIZE,
        .block_size = SHA3_512_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA3_512_CTX),
        .default_out_len = SHA3_512_DIGEST_SIZE,
        .hash_init_fn = sha3_512_init_wrapper,
        .hash_update_fn = sha3_512_update_wrapper,
        .hash_final_fn = sha3_512_final_wrapper,
        .hash_squeeze_fn = sha3_512_squeeze_wrapper,
    };
    return &md;
}

//
// SHAKE / RawSHAKE
//
static const CF_MD *CF_get_shake128(void) {
    static CF_MD md = {
        .id = CF_SHAKE128,
        .domain = 0,
        .digest_size = 0,
        .block_size = SHAKE128_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHAKE128_CTX),
        .default_out_len = SHAKE128_DEFAULT_OUT_LEN,
        .hash_init_fn = shake128_init_wrapper,
        .hash_update_fn = shake128_update_wrapper,
        .hash_final_fn = shake128_final_wrapper,
        .hash_squeeze_fn = shake128_squeeze_wrapper,
    };
    return &md;
}

static const CF_MD *CF_get_shake256(void) {
    static CF_MD md = {
        .id = CF_SHAKE256,
        .domain = 0,
        .digest_size = 0,
        .block_size = SHAKE256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHAKE256_CTX),
        .default_out_len = SHAKE256_DEFAULT_OUT_LEN,
        .hash_init_fn = shake256_init_wrapper,
        .hash_update_fn = shake256_update_wrapper,
        .hash_final_fn = shake256_final_wrapper,
        .hash_squeeze_fn = shake256_squeeze_wrapper,
    };
    return &md;
}

//
// RawSHAKE
//
static const CF_MD *CF_get_raw_shake128(void) {
    static CF_MD md = {
        .id = CF_RAWSHAKE128,
        .domain = RAWSHAKE128_DOMAIN,
        .digest_size = 0,
        .block_size = RAWSHAKE128_BLOCK_SIZE,
        .ctx_size = sizeof(ll_RawSHAKE128_CTX),
        .default_out_len = RAWSHAKE128_DEFAULT_OUT_LEN,
        .hash_init_fn = rawshake128_init_wrapper,
        .hash_update_fn = rawshake128_update_wrapper,
        .hash_final_fn = rawshake128_final_wrapper,
        .hash_squeeze_fn = rawshake128_squeeze_wrapper,
    };
    return &md;
}

static const CF_MD *CF_get_raw_shake256(void) {
    static CF_MD md = {
        .id = CF_RAWSHAKE256,
        .domain = RAWSHAKE256_DOMAIN,
        .digest_size = 0,
        .block_size = RAWSHAKE256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_RawSHAKE256_CTX),
        .default_out_len = RAWSHAKE256_DEFAULT_OUT_LEN,
        .hash_init_fn = rawshake256_init_wrapper,
        .hash_update_fn = rawshake256_update_wrapper,
        .hash_final_fn = rawshake256_final_wrapper,
        .hash_squeeze_fn = rawshake256_squeeze_wrapper,
    };
    return &md;
}

//
// cSHAKE
//
static const CF_MD *CF_get_cshake128(void) {
    static CF_MD md = {
        .id = CF_CSHAKE128,
        .domain = CSHAKE128_DOMAIN,
        .digest_size = 0,
        .block_size = CSHAKE128_BLOCK_SIZE,
        .ctx_size = sizeof(ll_CSHAKE128_CTX),
        .default_out_len = CSHAKE128_DEFAULT_OUT_LEN,
        .hash_init_fn = cshake128_init_wrapper,
        .hash_update_fn = cshake128_update_wrapper,
        .hash_final_fn = cshake128_final_wrapper,
        .hash_squeeze_fn = cshake128_squeeze_wrapper,
    };
    return &md;
}

static const CF_MD *CF_get_cshake256(void) {
    static CF_MD md = {
        .id = CF_CSHAKE256,
        .domain = CSHAKE256_DOMAIN,
        .digest_size = 0,
        .block_size = CSHAKE256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_CSHAKE256_CTX),
        .default_out_len = CSHAKE256_DEFAULT_OUT_LEN,
        .hash_init_fn = cshake256_init_wrapper,
        .hash_update_fn = cshake256_update_wrapper,
        .hash_final_fn = cshake256_final_wrapper,
        .hash_squeeze_fn = cshake256_squeeze_wrapper,
    };
    return &md;
}

// Table of all supported hashes
static const CF_ALGO_ENTRY cf_md_table[] = {
    { CF_MD5,           (const void* (*)(void))CF_get_md5 },
    { CF_SHA1,          (const void* (*)(void))CF_get_sha1 },
    { CF_SHA224,        (const void* (*)(void))CF_get_sha224 },
    { CF_SHA256,        (const void* (*)(void))CF_get_sha256 },
    { CF_SHA384,        (const void* (*)(void))CF_get_sha384 },
    { CF_SHA512,        (const void* (*)(void))CF_get_sha512 },
    { CF_SHA512_224,    (const void* (*)(void))CF_get_sha512_224 },
    { CF_SHA512_256,    (const void* (*)(void))CF_get_sha512_256 },
    { CF_SHA3_224,      (const void* (*)(void))CF_get_sha3_224 },
    { CF_SHA3_256,      (const void* (*)(void))CF_get_sha3_256 },
    { CF_SHA3_384,      (const void* (*)(void))CF_get_sha3_384 },
    { CF_SHA3_512,      (const void* (*)(void))CF_get_sha3_512 },
    { CF_SHAKE128,      (const void* (*)(void))CF_get_shake128 },
    { CF_SHAKE256,      (const void* (*)(void))CF_get_shake256 },
    { CF_RAWSHAKE128,   (const void* (*)(void))CF_get_raw_shake128 },
    { CF_RAWSHAKE256,   (const void* (*)(void))CF_get_raw_shake256 },
    { CF_CSHAKE128,     (const void* (*)(void))CF_get_cshake128 },
    { CF_CSHAKE256,     (const void* (*)(void))CF_get_cshake256 }
};

const CF_MD *CF_MD_GetByFlag(uint32_t algo_flag) {
    size_t table_len = sizeof(cf_md_table) / sizeof(cf_md_table[0]);
    for (size_t i = 0; i < table_len; i++) {
        if (cf_md_table[i].flag == algo_flag) {
            return (const CF_MD*)cf_md_table[i].getter_fn();
        }
    }
    return NULL;
}

CF_STATUS CF_Hash_Init(CF_HASH_CTX *ctx, const CF_MD *md, const CF_HASH_OPTS *opts) {
    if (!ctx || !md) return CF_ERR_NULL_PTR;

    // Validate optional context options if provided
    if (opts && opts->magic != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Ensure the heap allocation flag is valid (0 or 1)
    if (ctx->isHeapAlloc != 0 && ctx->isHeapAlloc != 1)
        return CF_ERR_CTX_UNINITIALIZED;

    // Reset the hash context to a clean state
    CF_Hash_Reset(ctx);

    // Store core parameters in the context
    ctx->md      = md;
    ctx->opts    = opts;
    // Determine output length: prefer digest_size if set, otherwise use default_out_len
    ctx->out_len = md->digest_size != 0 ? md->digest_size : md->default_out_len;

    // Allocate memory for low-level hash context
    ctx->digest_ctx = (void *)SECURE_ALLOC(md->ctx_size);
    if (!ctx->digest_ctx)
        return CF_ERR_ALLOC_FAILED;

    // Initialize the low-level hash context
    if (!ctx->md->hash_init_fn(ctx->digest_ctx, ctx->opts)) {
        // Reset context on failure to avoid dangling pointers
        CF_Hash_Reset(ctx);
        return CF_ERR_BAD_STATE;
    }

    // Bind a per-context "magic" value for integrity checking
    // Helps detect accidental misuse or memory corruption
    ctx->magic = CF_CTX_MAGIC ^ (uintptr_t)ctx->md;

    return CF_SUCCESS;
}

CF_HASH_CTX* CF_Hash_InitAlloc(const CF_MD *md, const CF_HASH_OPTS *opts, CF_STATUS *status) {
    if (!md) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Allocate memory for a new hash context on the heap
    CF_HASH_CTX *ctx = (CF_HASH_CTX *)SECURE_ALLOC(sizeof(CF_HASH_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Initialize the newly allocated hash context
    CF_STATUS st = CF_Hash_Init(ctx, md, opts);
    if (st != CF_SUCCESS) {
        if (status) *status = st;
        // Clean up on failure
        CF_Hash_Free(&ctx);
        return NULL;
    }

    // Mark context as heap-allocated for later cleanup
    ctx->isHeapAlloc = 1;
    
    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS CF_Hash_Update(CF_HASH_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx || !data)
        return CF_ERR_NULL_PTR;

    // Ensure the hash context and descriptor are initialized
    if (!ctx->md || !ctx->digest_ctx)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify context integrity using the bound "magic" value
    // Detects accidental corruption or misuse of the context
    if ((ctx->magic ^ (uintptr_t)ctx->md) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Prevent updates after the context has been finalized
    if (ctx->isFinalized)
        return CF_ERR_MAC_FINALIZED;

    // Call the low-level hash update function to process data
    if (!ctx->md->hash_update_fn(ctx->digest_ctx, data, data_len))
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

CF_STATUS CF_Hash_Final(CF_HASH_CTX *ctx, uint8_t *digest, size_t digest_len) {
    if (!ctx || !digest)
        return CF_ERR_NULL_PTR;

    // Ensure the hash context and descriptor are properly initialized
    if (!ctx->md || !ctx->digest_ctx)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify context integrity using the bound "magic" value
    // Detects accidental corruption or misuse of the context
    if ((ctx->magic ^ (uintptr_t)ctx->md) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Handle XOF (Extendable-Output Function) hashes
    if (CF_IS_XOF(ctx->md->id)) {
        // Variable-length output requires non-zero length
        if (digest_len == 0)
            return CF_ERR_INVALID_LEN;

        // First call to final produces the initial output
        if (!ctx->isFinalized) {
            if (!ctx->md->hash_final_fn(ctx->digest_ctx, digest))
                return CF_ERR_CTX_CORRUPT;
            ctx->isFinalized = 1;
        } else {
            // Subsequent calls use the squeeze function to extend output
            if (!ctx->md->hash_squeeze_fn || 
                !ctx->md->hash_squeeze_fn(ctx->digest_ctx, digest, digest_len))
                return CF_ERR_CTX_CORRUPT;
        }

    } else {
        // Non-XOF hash: fixed-length output
        // Prevent multiple finalizations
        if (ctx->isFinalized)
            return CF_ERR_HASH_FINALIZED;

        // Validate that output buffer is large enough
        if (digest_len != 0 && digest_len < ctx->md->default_out_len)
            return CF_ERR_OUTPUT_BUFFER_TOO_SMALL;

        // Finalize the hash and write output
        if (!ctx->md->hash_final_fn(ctx->digest_ctx, digest))
            return CF_ERR_CTX_CORRUPT;

        // Mark context as finalized to prevent reuse
        ctx->isFinalized = 1;
    }

    return CF_SUCCESS;
}

CF_STATUS CF_Hash_Reset(CF_HASH_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    // Ensure the hash descriptor exists
    if (!ctx->md)
        return CF_ERR_CTX_UNINITIALIZED;

    // Free the low-level digest context if it exists
    if (ctx->digest_ctx) {
        // Ensure the context size is valid
        if (ctx->md->ctx_size == 0)
            return CF_ERR_CTX_CORRUPT;

        // Securely free allocated memory for the digest context
        SECURE_FREE(ctx->digest_ctx, ctx->md->ctx_size);
    }

    // Clear all context fields to prevent accidental reuse or leakage
    ctx->md = NULL;
    ctx->opts = NULL;
    ctx->out_len = 0;
    ctx->magic = 0;

    return CF_SUCCESS;
}

CF_STATUS CF_Hash_Free(CF_HASH_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    CF_HASH_CTX *ctx = *p_ctx;

    CF_Hash_Reset(ctx);

    if (ctx->isHeapAlloc)
        SECURE_ZERO(ctx, sizeof(CF_HASH_CTX));

    return CF_SUCCESS;
}

CF_STATUS CF_Hash_Compute(const CF_MD *md, const uint8_t *data, size_t data_len,
                        uint8_t *digest, size_t digest_len, const CF_HASH_OPTS *opts) {

    if (!md || !digest || !data)
        return CF_ERR_NULL_PTR;

    CF_HASH_CTX ctx = {0};
    CF_STATUS st = CF_SUCCESS;

    st = CF_Hash_Init(&ctx, md, opts);
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.md) != CF_CTX_MAGIC)
        goto cleanup;

    st = CF_Hash_Update(&ctx, data, data_len);
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.md) != CF_CTX_MAGIC)
        goto cleanup;

    st = CF_Hash_Final(&ctx, digest, digest_len);

cleanup:
    CF_Hash_Reset(&ctx);
    return st;
}

CF_STATUS CF_Hash_ComputeFixed(const CF_MD *md, const uint8_t *data, size_t data_len, uint8_t *digest) {
    if (!md || !digest || !data)
        return CF_ERR_NULL_PTR;

    // Doest accept XOF algorthims
    if (CF_IS_XOF(md->id))
        return CF_ERR_UNSUPPORTED;

    CF_HASH_CTX ctx = {0};
    CF_STATUS st = CF_SUCCESS;

    st = CF_Hash_Init(&ctx, md, NULL);
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.md) != CF_CTX_MAGIC)
        goto cleanup;

    st = CF_Hash_Update(&ctx, data, data_len);
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.md) != CF_CTX_MAGIC) 
        goto cleanup;

    // Fixed-length hash uses md->digest_size
    st = CF_Hash_Final(&ctx, digest, md->digest_size);

cleanup:
    CF_Hash_Reset(&ctx);
    return st;
}

CF_STATUS CF_Hash_CloneCtx(CF_HASH_CTX *dst, const CF_HASH_CTX *src) {
    if (!dst || !src)
        return CF_ERR_NULL_PTR;

    // Ensure the hash descriptor exists
    if (!src->md)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify context integrity using the bound "magic" value
    // Detects accidental corruption or misuse of the context
    if ((src->magic ^ (uintptr_t)src->md) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Reset the hash context to a clean state
    CF_Hash_Reset(dst);

    // Copy metadata (shallow)
    dst->magic       = src->magic;
    dst->md          = src->md;
    dst->out_len     = src->out_len;
    dst->opts        = src->opts;
    dst->isFinalized = src->isFinalized;

    // Deep copy low-level digest context
    if (src->digest_ctx) {
        if (src->md->ctx_size == 0)
            return CF_ERR_CTX_CORRUPT;

        dst->digest_ctx = SECURE_ALLOC(src->md->ctx_size);
        if (!dst->digest_ctx)
            goto cleanup;

        SECURE_MEMCPY(dst->digest_ctx, src->digest_ctx, src->md->ctx_size);
    }

    return CF_SUCCESS;

cleanup:
    // Cleanup partially allocated memory
    if (dst->digest_ctx && src->md->ctx_size)
        SECURE_FREE(dst->digest_ctx, src->md->ctx_size);

    return CF_ERR_ALLOC_FAILED;
}

CF_HASH_CTX *CF_Hash_CloneCtxAlloc(const CF_HASH_CTX *src, CF_STATUS *status) {
    if (!src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    CF_HASH_CTX *dst = (CF_HASH_CTX *)SECURE_ALLOC(sizeof(CF_HASH_CTX));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Deep copy contents
    CF_STATUS ret = CF_Hash_CloneCtx(dst, src);
    if (ret != CF_SUCCESS) {
        if (status) *status = ret;
        CF_Hash_Free(&dst);
        return NULL;
    }

    // cloned context is heap-allocated
    dst->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return dst;
}

size_t CF_Hash_GetDigestSize(const CF_HASH_CTX *ctx) {
    return ctx ? (ctx->md ? ctx->md->digest_size : 0) : 0;
}

size_t CF_Hash_GetBlockSize(const CF_HASH_CTX *ctx) {
    return ctx ? (ctx->md ? ctx->md->block_size : 0) : 0;
}

const char* CF_Hash_GetName(const CF_MD *md) {
    if (!md) return NULL;

    switch (md->id) {
        case CF_MD5:          return "MD-5";
        case CF_SHA1:         return "SHA-1";
        case CF_SHA224:       return "SHA-224";
        case CF_SHA256:       return "SHA-256";
        case CF_SHA384:       return "SHA-384";
        case CF_SHA512:       return "SHA-512";
        case CF_SHA512_224:   return "SHA-512/224";
        case CF_SHA512_256:   return "SHA-512/256";
        case CF_SHA3_224:     return "SHA-3/224";
        case CF_SHA3_256:     return "SHA-3/256";
        case CF_SHA3_384:     return "SHA-3/384";
        case CF_SHA3_512:     return "SHA-3/512";
        case CF_SHAKE128:     return "SHAKE-128";
        case CF_SHAKE256:     return "SHAKE-256";
        case CF_RAWSHAKE128:  return "RAWSHAKE-128";
        case CF_RAWSHAKE256:  return "RAWSHAKE-256";
        case CF_CSHAKE128:    return "CSHAKE-128";
        case CF_CSHAKE256:    return "CSHAKE-256";
        default:              return "UNKNOWN-HASH";
    }
}

CF_STATUS CF_Hash_ValidateCtx(const CF_HASH_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    if ((ctx->magic ^ (uintptr_t)ctx->md) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

CF_STATUS CF_HashOpts_Init(CF_HASH_OPTS *opts,
                             const uint8_t *N, size_t N_len,
                             const uint8_t *S, size_t S_len) {
    if (!opts)
        return CF_ERR_NULL_PTR;

    if (N_len > CF_MAX_CUSTOMIZATION || S_len > CF_MAX_CUSTOMIZATION)
        return CF_ERR_INVALID_LEN;

    CF_HashOpts_Reset(opts);

    opts->emptyNameCustom = 1;

    if (N && N_len > 0) {
        opts->N = N;
        opts->N_len = N_len;
        opts->emptyNameCustom = 0;
    }

    if (S && S_len > 0) {
        opts->S = S;
        opts->S_len = S_len;
        opts->emptyNameCustom = 0;
    }

    opts->magic = CF_CTX_MAGIC;

    return CF_SUCCESS;
}

CF_HASH_OPTS* CF_HashOpts_InitAlloc(const uint8_t *N, size_t N_len,
                                    const uint8_t *S, size_t S_len, CF_STATUS *status) {
    if (N_len > CF_MAX_CUSTOMIZATION || S_len > CF_MAX_CUSTOMIZATION) {
        if (status) *status = CF_ERR_INVALID_LEN;
        return NULL;
    }

    CF_HASH_OPTS *opts = (CF_HASH_OPTS *)SECURE_ALLOC(sizeof(CF_HASH_OPTS));
    if (!opts) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = CF_HashOpts_Init(opts, N, N_len, S, S_len);
    if (st != CF_SUCCESS) {
        if (status) *status = st;
        // Clean up on failure
        CF_HashOpts_Free(&opts);
        return NULL;
    }

    opts->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return opts;
}

CF_STATUS CF_HashOpts_Reset(CF_HASH_OPTS *opts) {
    if (!opts)
        return CF_ERR_NULL_PTR;

    opts->N               = NULL;
    opts->S               = NULL;
    opts->N_len           = 0;
    opts->S_len           = 0;
    opts->custom_absorbed = 0;
    opts->emptyNameCustom = 1;

    return CF_SUCCESS;
}

CF_STATUS CF_HashOpts_Free(CF_HASH_OPTS **p_opts) {
    if (!p_opts || !*p_opts)
        return CF_ERR_NULL_PTR;

    CF_HASH_OPTS *opts = *p_opts;

    CF_STATUS ret = CF_HashOpts_Reset(opts);
    if (ret != CF_SUCCESS)
        return ret;

    if (opts->isHeapAlloc)
        SECURE_FREE(opts, sizeof(*opts));

    return CF_SUCCESS;
}

CF_STATUS CF_HashOpts_Clone(CF_HASH_OPTS *dst, const CF_HASH_OPTS *src) {
    if (!dst || !src)
        return CF_ERR_NULL_PTR;

    if (src->magic != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Start with a clean slate
    CF_HashOpts_Reset(dst);

    // Copy metadata
    dst->finalized = src->finalized;
    dst->custom_absorbed = src->custom_absorbed;
    dst->emptyNameCustom = src->emptyNameCustom;

    // Shallow copy (caller manages lifetime)
    dst->N         = src->N;
    dst->N_len     = src->N_len;
    dst->S         = src->S;
    dst->S_len     = src->S_len;

    return CF_SUCCESS;
}

CF_HASH_OPTS *CF_HashOpts_CloneAlloc(const CF_HASH_OPTS *src, CF_STATUS *status) {
    if (!src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    CF_HASH_OPTS *dst = (CF_HASH_OPTS *)SECURE_ALLOC(sizeof(CF_HASH_OPTS));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Deep copy contents
    CF_STATUS ret = CF_HashOpts_Clone(dst, src);
    if (ret != CF_SUCCESS) {
        if (status) *status = ret;
        CF_HashOpts_Free(&dst);
        return NULL;
    }

    // cloned context is heap-allocated
    dst->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return dst;
}
