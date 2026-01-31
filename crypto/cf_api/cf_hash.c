/*
 * CryptoForge - cf_hash.c / High-level hash/XOF context implementation
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
static bool md5_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest_size);
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
static bool sha1_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest_size);
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
static bool sha224_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest_size);
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
static bool sha256_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest_size);
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
static bool sha384_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest_size);
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
static bool sha512_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest_size);
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
static bool sha512_224_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest_size);
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
static bool sha512_256_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest_size);
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
static bool sha3_224_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest);
    UNUSED(digest_size);
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
static bool sha3_256_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest);
    UNUSED(digest_size);
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
static bool sha3_384_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest);
    UNUSED(digest_size);
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
static bool sha3_512_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest);
    UNUSED(digest_size);
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
static bool shake128_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest);
    UNUSED(digest_size);
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
static bool shake256_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest);
    UNUSED(digest_size);
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
static bool rawshake128_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest);
    UNUSED(digest_size);
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
static bool rawshake256_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    UNUSED(digest);
    UNUSED(digest_size);
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

static bool cshake128_final_wrapper(void *ctx, uint8_t *digest, size_t digest_len) {
    UNUSED(digest);
    UNUSED(digest_len);
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

static bool cshake256_final_wrapper(void *ctx, uint8_t *digest, size_t digest_len) {
    UNUSED(digest);
    UNUSED(digest_len);
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
        .opts_ctx_size = 0,
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
        .opts_ctx_size = 0,
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
        .opts_ctx_size = 0,
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
        .opts_ctx_size = 0,
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
        .opts_ctx_size = 0,
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
        .opts_ctx_size = 0,
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
        .opts_ctx_size = 0,
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
        .opts_ctx_size = 0,
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
        .opts_ctx_size = 0,
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
        .opts_ctx_size = 0,
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
        .opts_ctx_size = 0,
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
        .opts_ctx_size = 0,
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
        .opts_ctx_size = sizeof(CF_HASH_OPTS),
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
        .opts_ctx_size = sizeof(CF_HASH_OPTS),
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
        .opts_ctx_size = sizeof(CF_HASH_OPTS),
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
        .opts_ctx_size = sizeof(CF_HASH_OPTS),
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
        .opts_ctx_size = sizeof(CF_HASH_OPTS),
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
        .opts_ctx_size = sizeof(CF_HASH_OPTS),
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

    if (ctx->isHeapAlloc != 0 && ctx->isHeapAlloc != 1)
        return CF_ERR_CTX_UNINITIALIZED;

    CF_Hash_Reset(ctx);

    ctx->md = md;

    // Use opts directly; caller owns memory
    ctx->opts = opts;

    // Allocate low-level digest context
    ctx->digest_ctx = SECURE_ALLOC(md->ctx_size);
    if (!ctx->digest_ctx) return CF_ERR_ALLOC_FAILED;

    // Init low-level hash
    if (!md->hash_init_fn(ctx->digest_ctx, ctx->opts)) {
        SECURE_FREE(ctx->digest_ctx, md->ctx_size);
        ctx->digest_ctx = NULL;
        return CF_ERR_BAD_STATE;
    }

    ctx->out_len = md->digest_size != 0 ? md->digest_size : md->default_out_len;
    
    return CF_SUCCESS;
}

CF_HASH_CTX* CF_Hash_InitAlloc(const CF_MD *md, const CF_HASH_OPTS *opts, CF_STATUS *status) {
    if (!md) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    CF_HASH_CTX *ctx = (CF_HASH_CTX *)SECURE_ALLOC(sizeof(CF_HASH_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = CF_Hash_Init(ctx, md, opts);
    if (st != CF_SUCCESS) {
        SECURE_FREE(ctx, sizeof(CF_HASH_CTX));
        if (status) *status = st;
        return NULL;
    }

    ctx->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS CF_Hash_Update(CF_HASH_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx || !ctx->digest_ctx || !ctx->md || !data)
        return CF_ERR_NULL_PTR;

    if (!ctx->md->hash_update_fn(ctx->digest_ctx, data, data_len))
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

CF_STATUS CF_Hash_Final(CF_HASH_CTX *ctx, uint8_t *digest, size_t digest_len) {
    if (!ctx || !ctx->digest_ctx || !ctx->md || !digest)
        return CF_ERR_NULL_PTR;

    size_t final_len;

    if (CF_IS_XOF(ctx->md->id)) {
        // XOF: allow variable-length output
        if (digest_len == 0)
            return CF_ERR_INVALID_LEN;
        final_len = digest_len;
    } else {
        // Fixed-length hash: always use default size
        final_len = ctx->md->default_out_len;

        // ensure caller buffer is large enough
        if (digest_len != 0 && digest_len < final_len)
            return CF_ERR_OUTPUT_BUFFER_TOO_SMALL;
    }

    if (!ctx->md->hash_final_fn(ctx->digest_ctx, digest, final_len))
        return CF_ERR_CTX_CORRUPT;

    // For XOFs or SHA3 variants that require squeezing
    if (ctx->md->hash_squeeze_fn && CF_IS_KECCAK(ctx->md->id)) {
        if (!ctx->md->hash_squeeze_fn(ctx->digest_ctx, digest, final_len))
            return CF_ERR_CTX_CORRUPT;
    }

    ctx->isFinalized = 1;
    return CF_SUCCESS;
}

CF_STATUS CF_Hash_Reset(CF_HASH_CTX *ctx) {
    if (!ctx || !ctx->md)
        return CF_ERR_NULL_PTR;

    int wasHeapAlloc = ctx->isHeapAlloc;

    if (ctx->digest_ctx) {
        SECURE_ZERO(ctx->digest_ctx, ctx->md->ctx_size);
        SECURE_FREE(ctx->digest_ctx, ctx->md->ctx_size);
        ctx->digest_ctx = NULL;
    }

    if (ctx->opts && ctx->isHeapAllocOpts) {
        CF_HashOpts_Free((CF_HASH_OPTS**)&ctx->opts);
        ctx->opts = NULL;
        ctx->isHeapAllocOpts = 0;
    }

    SECURE_ZERO(ctx, sizeof(*ctx));

    ctx->isFinalized = 0;
    ctx->isHeapAlloc = wasHeapAlloc;

    return CF_SUCCESS;
}

CF_STATUS CF_Hash_Free(CF_HASH_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    CF_HASH_CTX *ctx = *p_ctx;
    int wasHeapAlloc = ctx->isHeapAlloc;

    CF_Hash_Reset(ctx);

    if (wasHeapAlloc) {
        SECURE_ZERO(ctx, sizeof(CF_HASH_CTX));
        SECURE_FREE(ctx, sizeof(CF_HASH_CTX));
        *p_ctx = NULL;
    }

    return CF_SUCCESS;
}

CF_STATUS CF_Hash_Compute(const CF_MD *md, const uint8_t *data, size_t data_len,
                        uint8_t *digest, size_t digest_len, const CF_HASH_OPTS *opts) {

    if (!md || !digest || !data)
        return CF_ERR_NULL_PTR;

    CF_STATUS status;
    CF_HASH_CTX *ctx = CF_Hash_InitAlloc(md, opts, &status);
    if (!ctx) return status;

    status = CF_Hash_Update(ctx, data, data_len);
    if (status != CF_SUCCESS) {
        CF_Hash_Free(&ctx);
        return status;
    }

    status = CF_Hash_Final(ctx, digest, digest_len);

    CF_Hash_Free(&ctx);
    return status;
}

CF_STATUS CF_Hash_ComputeFixed(const CF_MD *md, const uint8_t *data, size_t data_len, uint8_t *digest) {
    if (!md || !digest || !data)
        return CF_ERR_NULL_PTR;

    // Doest accept XOF algorthims
    if (CF_IS_XOF(md->id))
        return CF_ERR_UNSUPPORTED;

    CF_STATUS status;
    CF_HASH_CTX *ctx = CF_Hash_InitAlloc(md, NULL, &status);
    if (!ctx) return status;

    status = CF_Hash_Update(ctx, data, data_len);
    if (status != CF_SUCCESS) {
        CF_Hash_Free(&ctx);
        return status;
    }

    // Fixed-length hash uses md->digest_size
    status = CF_Hash_Final(ctx, digest, md->digest_size);

    CF_Hash_Free(&ctx);
    return status;
}

CF_STATUS CF_Hash_CloneCtx(CF_HASH_CTX *dst, const CF_HASH_CTX *src) {
    if (!dst || !src)
        return CF_ERR_NULL_PTR;

    // dst must be uninitialized
    if (dst->digest_ctx || dst->opts || dst->isHeapAlloc || dst->isHeapAllocOpts)
        return CF_ERR_ALREADY_INITIALIZED;

    if (!src->md)
        return CF_ERR_CTX_UNINITIALIZED;

    // Copy metadata first (no allocation yet)
    dst->md          = src->md;
    dst->out_len     = src->out_len;
    dst->isFinalized = src->isFinalized;

    // Deep copy digest context
    if (src->digest_ctx) {
        dst->digest_ctx = SECURE_ALLOC(src->md->ctx_size);
        if (!dst->digest_ctx)
            return CF_ERR_ALLOC_FAILED;

        SECURE_MEMCPY(dst->digest_ctx,
                      src->digest_ctx,
                      src->md->ctx_size);
    } else {
        dst->digest_ctx = NULL;
    }

    // XOF options are shallow-copied by design
    dst->opts = src->opts;
    dst->isHeapAllocOpts = 0;

    dst->isHeapAlloc = 0;

    return CF_SUCCESS;
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

    CF_STATUS st = CF_Hash_CloneCtx(dst, src);
    if (status) *status = st;
    
    if (st != CF_SUCCESS) {
        SECURE_FREE(dst, sizeof(*dst));
        return NULL;
    }

    dst->isHeapAlloc = 1;
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
        case CF_MD5:          return "MD5";
        case CF_SHA1:         return "SHA1";
        case CF_SHA224:       return "SHA224";
        case CF_SHA256:       return "SHA256";
        case CF_SHA384:       return "SHA384";
        case CF_SHA512:       return "SHA512";
        case CF_SHA512_224:   return "SHA512_224";
        case CF_SHA512_256:   return "SHA512_256";
        case CF_SHA3_224:     return "SHA3_224";
        case CF_SHA3_256:     return "SHA3_256";
        case CF_SHA3_384:     return "SHA3_384";
        case CF_SHA3_512:     return "SHA3_512";
        case CF_SHAKE128:     return "SHAKE128";
        case CF_SHAKE256:     return "SHAKE256";
        case CF_RAWSHAKE128:  return "rawSHAKE128";
        case CF_RAWSHAKE256:  return "rawSHAKE256";
        case CF_CSHAKE128:    return "cSHAKE128";
        case CF_CSHAKE256:    return "cSHAKE256";
        default:               return NULL;
    }
}


CF_STATUS CF_HashOpts_Init(CF_HASH_OPTS *opts,
                             const uint8_t *N, size_t N_len,
                             const uint8_t *S, size_t S_len,
                             size_t out_len) {
    if (!opts) return CF_ERR_NULL_PTR;
    if (N_len > CF_MAX_CUSTOMIZATION || S_len > CF_MAX_CUSTOMIZATION)
        return CF_ERR_INVALID_LEN;

    CF_HashOpts_Reset(opts);

    opts->N_len = N_len;
    opts->S_len = S_len;
    opts->out_len = out_len;
    opts->emptyNameCustom = 1;

    if (N && N_len > 0) {
        SECURE_MEMCPY(opts->N, N, N_len);
        opts->emptyNameCustom = 0;
    }

    if (S && S_len > 0) {
        SECURE_MEMCPY(opts->S, S, S_len);
        opts->emptyNameCustom = 0;
    }

    return CF_SUCCESS;
}

CF_HASH_OPTS* CF_HashOpts_InitAlloc(const uint8_t *N, size_t N_len,
                                             const uint8_t *S, size_t S_len,
                                             size_t out_len, CF_STATUS *status) {
    if (N_len > CF_MAX_CUSTOMIZATION || S_len > CF_MAX_CUSTOMIZATION) {
        if (status) *status = CF_ERR_INVALID_LEN;
        return NULL;
    }

    CF_HASH_OPTS *opts = (CF_HASH_OPTS *)SECURE_ALLOC(sizeof(CF_HASH_OPTS));
    if (!opts) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = CF_HashOpts_Init(opts, N, N_len, S, S_len, out_len);
    if (st != CF_SUCCESS) {
        SECURE_FREE(opts, sizeof(CF_HASH_OPTS));
        if (status) *status = st;
        return NULL;
    }

    opts->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return opts;
}

CF_STATUS CF_HashOpts_Reset(CF_HASH_OPTS *opts) {
    if (!opts)
        return CF_ERR_NULL_PTR;

    int wasHeapAlloc = opts->isHeapAlloc;

    SECURE_ZERO(opts, sizeof(*opts));
    SECURE_ZERO(opts->N, sizeof(opts->N));
    SECURE_ZERO(opts->S, sizeof(opts->S));

    opts->emptyNameCustom = 1;
    opts->isHeapAlloc = wasHeapAlloc;

    return CF_SUCCESS;
}

CF_STATUS CF_HashOpts_Free(CF_HASH_OPTS **p_opts) {
    if (!p_opts || !*p_opts)
        return CF_ERR_NULL_PTR;

    CF_HASH_OPTS *opts = *p_opts;
    int wasHeapAlloc = opts->isHeapAlloc;

    CF_STATUS ret = CF_HashOpts_Reset(opts);
    if (ret != CF_SUCCESS)
        return ret;

    if (wasHeapAlloc) {
        SECURE_FREE(opts, sizeof(*opts));
        *p_opts = NULL;
    }

    return CF_SUCCESS;
}

CF_STATUS CF_HashOpts_Clone(CF_HASH_OPTS *dst, const CF_HASH_OPTS *src) {
    if (!dst || !src) return CF_ERR_NULL_PTR;

    SECURE_MEMCPY(dst->N, src->N, CF_MAX_CUSTOMIZATION);
    SECURE_MEMCPY(dst->S, src->S, CF_MAX_CUSTOMIZATION);

    dst->N_len = src->N_len;
    dst->S_len = src->S_len;
    dst->out_len = src->out_len;
    dst->finalized = src->finalized;
    dst->custom_absorbed = src->custom_absorbed;
    dst->emptyNameCustom = src->emptyNameCustom;
    dst->isHeapAlloc = 0;
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

    dst->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return dst;
}
