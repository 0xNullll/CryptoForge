/*
 * CryptoForge - evp_hash.c / High-level hash/XOF context implementation
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "evp_hash.h"

// ======================
// Wrappers for all hashes
// ======================

// MD5
static bool md5_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_md5_init((ll_MD5_CTX *)ctx);
}
static bool md5_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_md5_update((ll_MD5_CTX *)ctx, data, len);
}
static bool md5_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_md5_final((ll_MD5_CTX *)ctx, digest);
}

// ----------------------
// SHA1 / SHA256 / SHA512
// ----------------------

// SHA1
static bool sha1_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_sha1_init((ll_SHA1_CTX *)ctx);
}
static bool sha1_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha1_update((ll_SHA1_CTX *)ctx, data, len);
}
static bool sha1_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_sha1_final((ll_SHA1_CTX *)ctx, digest);
}

// SHA224
static bool sha224_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_sha224_init((ll_SHA224_CTX *)ctx);
}
static bool sha224_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha224_update((ll_SHA224_CTX *)ctx, data, len);
}
static bool sha224_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_sha224_final((ll_SHA224_CTX *)ctx, digest);
}

// SHA256
static bool sha256_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_sha256_init((ll_SHA256_CTX *)ctx);
}
static bool sha256_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha256_update((ll_SHA256_CTX *)ctx, data, len);
}
static bool sha256_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_sha256_final((ll_SHA256_CTX *)ctx, digest);
}

// SHA384
static bool sha384_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_sha384_init((ll_SHA384_CTX *)ctx);
}
static bool sha384_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha384_update((ll_SHA384_CTX *)ctx, data, len);
}
static bool sha384_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_sha384_final((ll_SHA384_CTX *)ctx, digest);
}

// SHA512
static bool sha512_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_sha512_init((ll_SHA512_CTX *)ctx);
}
static bool sha512_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha512_update((ll_SHA512_CTX *)ctx, data, len);
}
static bool sha512_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_sha512_final((ll_SHA512_CTX *)ctx, digest);
}

// SHA512_224
static bool sha512_224_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_sha512_224_init((ll_SHA512_224_CTX *)ctx);
}
static bool sha512_224_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha512_224_update((ll_SHA512_224_CTX *)ctx, data, len);
}
static bool sha512_224_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_sha512_224_final((ll_SHA512_224_CTX *)ctx, digest);
}

// SHA512_256
static bool sha512_256_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_sha512_256_init((ll_SHA512_256_CTX *)ctx);
}
static bool sha512_256_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha512_256_update((ll_SHA512_256_CTX *)ctx, data, len);
}
static bool sha512_256_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_sha512_256_final((ll_SHA512_256_CTX *)ctx, digest);
}

// ----------------------
// SHA3 / SHAKE / RawSHAKE
// ----------------------
// SHA3-224
static bool sha3_224_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_sha3_224_init((ll_SHA3_224_CTX *)ctx);
}
static bool sha3_224_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha3_224_absorb((ll_SHA3_224_CTX *)ctx, data, len);
}
static bool sha3_224_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest;
    (void)digest_size;
    return ll_sha3_224_final((ll_SHA3_224_CTX *)ctx);
}
static bool sha3_224_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_sha3_224_squeeze((ll_SHA3_224_CTX *)ctx, output, outlen);
}

// SHA3-256
static bool sha3_256_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_sha3_256_init((ll_SHA3_256_CTX *)ctx);
}
static bool sha3_256_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha3_256_absorb((ll_SHA3_256_CTX *)ctx, data, len);
}
static bool sha3_256_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest;
    (void)digest_size;
    return ll_sha3_256_final((ll_SHA3_256_CTX *)ctx);
}
static bool sha3_256_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_sha3_256_squeeze((ll_SHA3_256_CTX *)ctx, output, outlen);
}

// SHA3-384
static bool sha3_384_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_sha3_384_init((ll_SHA3_384_CTX *)ctx);
}
static bool sha3_384_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha3_384_absorb((ll_SHA3_384_CTX *)ctx, data, len);
}
static bool sha3_384_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest;
    (void)digest_size;
    return ll_sha3_384_final((ll_SHA3_384_CTX *)ctx);
}
static bool sha3_384_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_sha3_384_squeeze((ll_SHA3_384_CTX *)ctx, output, outlen);
}

// SHA3-512
static bool sha3_512_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_sha3_512_init((ll_SHA3_512_CTX *)ctx);
}
static bool sha3_512_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha3_512_absorb((ll_SHA3_512_CTX *)ctx, data, len);
}
static bool sha3_512_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest;
    (void)digest_size;
    return ll_sha3_512_final((ll_SHA3_512_CTX *)ctx);
}
static bool sha3_512_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_sha3_512_squeeze((ll_SHA3_512_CTX *)ctx, output, outlen);
}

// SHAKE128
static bool shake128_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_shake128_init((ll_SHAKE128_CTX *)ctx);
}
static bool shake128_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_shake128_absorb((ll_SHAKE128_CTX *)ctx, data, len);
}
static bool shake128_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest;
    (void)digest_size;
    return ll_shake128_final((ll_SHAKE128_CTX *)ctx);
}
static bool shake128_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_shake128_squeeze((ll_SHAKE128_CTX *)ctx, output, outlen);
}

// SHAKE256
static bool shake256_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_shake256_init((ll_SHAKE256_CTX *)ctx);
}
static bool shake256_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_shake256_absorb((ll_SHAKE256_CTX *)ctx, data, len);
}
static bool shake256_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest;
    (void)digest_size;
    return ll_shake256_final((ll_SHAKE256_CTX *)ctx);
}
static bool shake256_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_shake256_squeeze((ll_SHAKE256_CTX *)ctx, output, outlen);
}

// RawSHAKE128
static bool rawshake128_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_rawshake128_init((ll_RawSHAKE128_CTX *)ctx);
}
static bool rawshake128_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_rawshake128_absorb((ll_RawSHAKE128_CTX *)ctx, data, len);
}
static bool rawshake128_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest;
    (void)digest_size;
    return ll_rawshake128_final((ll_RawSHAKE128_CTX *)ctx);
}
static bool rawshake128_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_rawshake128_squeeze((ll_RawSHAKE128_CTX *)ctx, output, outlen);
}

// RawSHAKE256
static bool rawshake256_init_wrapper(void *ctx, const void *opts) {
    (void)opts;
    return ll_rawshake256_init((ll_RawSHAKE256_CTX *)ctx);
}
static bool rawshake256_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_rawshake256_absorb((ll_RawSHAKE256_CTX *)ctx, data, len);
}
static bool rawshake256_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest;
    (void)digest_size;
    return ll_rawshake256_final((ll_RawSHAKE256_CTX *)ctx);
}
static bool rawshake256_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_rawshake256_squeeze((ll_RawSHAKE256_CTX *)ctx, output, outlen);
}

// ======================================
// cSHAKE128 simple wrappers
// ======================================
static bool cshake128_init_wrapper(void *ctx, const void *opts) {
    const EVP_XOF_OPTS *xof_opts = (const EVP_XOF_OPTS *)opts;
    return ll_cshake128_init(
        (ll_CSHAKE128_CTX *)ctx,
        opts ? xof_opts->N : NULL,
        opts ? xof_opts->N_len : 0,
        opts ? xof_opts->S : NULL,
        opts ? xof_opts->S_len : 0
    );
}

static bool cshake128_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_cshake128_absorb((ll_CSHAKE128_CTX *)ctx, data, len);
}

static bool cshake128_final_wrapper(void *ctx, uint8_t *digest, size_t digest_len) {
    (void)digest;
    (void)digest_len;
    return ll_cshake128_final((ll_CSHAKE128_CTX *)ctx);
}

static bool cshake128_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_cshake128_squeeze((ll_CSHAKE128_CTX *)ctx, output, outlen);
}

// ======================================
// cSHAKE256 simple wrappers
// ======================================
static bool cshake256_init_wrapper(void *ctx, const void *opts) {
    const EVP_XOF_OPTS *xof_opts = (const EVP_XOF_OPTS *)opts;
    return ll_cshake256_init(
        (ll_CSHAKE256_CTX *)ctx,
        xof_opts ? xof_opts->N : NULL,
        xof_opts ? xof_opts->N_len : 0,
        xof_opts ? xof_opts->S : NULL,
        xof_opts ? xof_opts->S_len : 0
    );
}

static bool cshake256_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_cshake256_absorb((ll_CSHAKE256_CTX *)ctx, data, len);
}

static bool cshake256_final_wrapper(void *ctx, uint8_t *digest, size_t digest_len) {
    (void)digest;
    (void)digest_len;
    return ll_cshake256_final((ll_CSHAKE256_CTX *)ctx);
}

static bool cshake256_squeeze_wrapper(void *ctx, uint8_t *output, size_t outlen) {
    return ll_cshake256_squeeze((ll_CSHAKE256_CTX *)ctx, output, outlen);
}

// --- EVP_MD Return Functions ---

// =======================
// MD5
// =======================
static const EVP_MD *EVP_get_md5(void) {
    static EVP_MD md = {
        .id = EVP_MD5,
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

// =======================
// SHA1
// =======================
static const EVP_MD *EVP_get_sha1(void) {
    static EVP_MD md = {
        .id = EVP_SHA1,
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

// =======================
// SHA256
// =======================
static const EVP_MD *EVP_get_sha224(void) {
    static EVP_MD md = {
        .id = EVP_SHA224,
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

static const EVP_MD *EVP_get_sha256(void) {
    static EVP_MD md = {
        .id = EVP_SHA256,
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

// =======================
// SHA512
// =======================
static const EVP_MD *EVP_get_sha384(void) {
    static EVP_MD md = {
        .id = EVP_SHA384,
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

static const EVP_MD *EVP_get_sha512(void) {
    static EVP_MD md = {
        .id = EVP_SHA512,
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

static const EVP_MD *EVP_get_sha512_224(void) {
    static EVP_MD md = {
        .id = EVP_SHA512_224,
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

static const EVP_MD *EVP_get_sha512_256(void) {
    static EVP_MD md = {
        .id = EVP_SHA512_256,
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

// =======================
// SHA3
// =======================
static const EVP_MD *EVP_get_sha3_224(void) {
    static EVP_MD md = {
        .id = EVP_SHA3_224,
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

static const EVP_MD *EVP_get_sha3_256(void) {
    static EVP_MD md = {
        .id = EVP_SHA3_256,
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

static const EVP_MD *EVP_get_sha3_384(void) {
    static EVP_MD md = {
        .id = EVP_SHA3_384,
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

static const EVP_MD *EVP_get_sha3_512(void) {
    static EVP_MD md = {
        .id = EVP_SHA3_512,
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

// =======================
// SHAKE / RawSHAKE
// =======================
static const EVP_MD *EVP_get_shake128(void) {
    static EVP_MD md = {
        .id = EVP_SHAKE128,
        .domain = 0,
        .digest_size = 0,
        .block_size = SHAKE128_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHAKE128_CTX),
        .opts_ctx_size = sizeof(EVP_XOF_OPTS),
        .default_out_len = SHAKE128_DEFAULT_OUT_LEN,
        .hash_init_fn = shake128_init_wrapper,
        .hash_update_fn = shake128_update_wrapper,
        .hash_final_fn = shake128_final_wrapper,
        .hash_squeeze_fn = shake128_squeeze_wrapper,
    };
    return &md;
}

static const EVP_MD *EVP_get_shake256(void) {
    static EVP_MD md = {
        .id = EVP_SHAKE256,
        .domain = 0,
        .digest_size = 0,
        .block_size = SHAKE256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHAKE256_CTX),
        .opts_ctx_size = sizeof(EVP_XOF_OPTS),
        .default_out_len = SHAKE256_DEFAULT_OUT_LEN,
        .hash_init_fn = shake256_init_wrapper,
        .hash_update_fn = shake256_update_wrapper,
        .hash_final_fn = shake256_final_wrapper,
        .hash_squeeze_fn = shake256_squeeze_wrapper,
    };
    return &md;
}

// =======================
// RawSHAKE
// =======================
static const EVP_MD *EVP_get_raw_shake128(void) {
    static EVP_MD md = {
        .id = EVP_RAWSHAKE128,
        .domain = RAWSHAKE128_DOMAIN,
        .digest_size = 0,
        .block_size = RAWSHAKE128_BLOCK_SIZE,
        .ctx_size = sizeof(ll_RawSHAKE128_CTX),
        .opts_ctx_size = sizeof(EVP_XOF_OPTS),
        .default_out_len = RAWSHAKE128_DEFAULT_OUT_LEN,
        .hash_init_fn = rawshake128_init_wrapper,
        .hash_update_fn = rawshake128_update_wrapper,
        .hash_final_fn = rawshake128_final_wrapper,
        .hash_squeeze_fn = rawshake128_squeeze_wrapper,
    };
    return &md;
}

static const EVP_MD *EVP_get_raw_shake256(void) {
    static EVP_MD md = {
        .id = EVP_RAWSHAKE256,
        .domain = RAWSHAKE256_DOMAIN,
        .digest_size = 0,
        .block_size = RAWSHAKE256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_RawSHAKE256_CTX),
        .opts_ctx_size = sizeof(EVP_XOF_OPTS),
        .default_out_len = RAWSHAKE256_DEFAULT_OUT_LEN,
        .hash_init_fn = rawshake256_init_wrapper,
        .hash_update_fn = rawshake256_update_wrapper,
        .hash_final_fn = rawshake256_final_wrapper,
        .hash_squeeze_fn = rawshake256_squeeze_wrapper,
    };
    return &md;
}

// =======================
// cSHAKE
// =======================
static const EVP_MD *EVP_get_cshake128(void) {
    static EVP_MD md = {
        .id = EVP_CSHAKE128,
        .domain = CSHAKE128_DOMAIN,
        .digest_size = 0,
        .block_size = CSHAKE128_BLOCK_SIZE,
        .ctx_size = sizeof(ll_CSHAKE128_CTX),
        .opts_ctx_size = sizeof(EVP_XOF_OPTS),
        .default_out_len = CSHAKE128_DEFAULT_OUT_LEN,
        .hash_init_fn = cshake128_init_wrapper,
        .hash_update_fn = cshake128_update_wrapper,
        .hash_final_fn = cshake128_final_wrapper,
        .hash_squeeze_fn = cshake128_squeeze_wrapper,
    };
    return &md;
}

static const EVP_MD *EVP_get_cshake256(void) {
    static EVP_MD md = {
        .id = EVP_CSHAKE256,
        .domain = CSHAKE256_DOMAIN,
        .digest_size = 0,
        .block_size = CSHAKE256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_CSHAKE256_CTX),
        .opts_ctx_size = sizeof(EVP_XOF_OPTS),
        .default_out_len = CSHAKE256_DEFAULT_OUT_LEN,
        .hash_init_fn = cshake256_init_wrapper,
        .hash_update_fn = cshake256_update_wrapper,
        .hash_final_fn = cshake256_final_wrapper,
        .hash_squeeze_fn = cshake256_squeeze_wrapper,
    };
    return &md;
}

// Table of all supported hashes
static const EVP_MD_ENTRY evp_md_table[] = {
    { EVP_MD5,           EVP_get_md5 },
    { EVP_SHA1,          EVP_get_sha1 },
    { EVP_SHA224,        EVP_get_sha224 },
    { EVP_SHA256,        EVP_get_sha256 },
    { EVP_SHA384,        EVP_get_sha384 },
    { EVP_SHA512,        EVP_get_sha512 },
    { EVP_SHA512_224,    EVP_get_sha512_224 },
    { EVP_SHA512_256,    EVP_get_sha512_256 },
    { EVP_SHA3_224,      EVP_get_sha3_224 },
    { EVP_SHA3_256,      EVP_get_sha3_256 },
    { EVP_SHA3_384,      EVP_get_sha3_384 },
    { EVP_SHA3_512,      EVP_get_sha3_512 },
    { EVP_SHAKE128,      EVP_get_shake128 },
    { EVP_SHAKE256,      EVP_get_shake256 },
    { EVP_RAWSHAKE128,   EVP_get_raw_shake128 },
    { EVP_RAWSHAKE256,   EVP_get_raw_shake256 },
    { EVP_CSHAKE128,     EVP_get_cshake128 },
    { EVP_CSHAKE256,     EVP_get_cshake256 }
};

// Replace EVP_MDByFlag with table lookup
const EVP_MD *EVP_MDByFlag(uint32_t algo_flag) {
    size_t table_len = sizeof(evp_md_table) / sizeof(evp_md_table[0]);
    for (size_t i = 0; i < table_len; i++) {
        if (evp_md_table[i].flag == algo_flag) {
            return evp_md_table[i].EVP_MDGetter();
        }
    }
    return NULL; // invalid flag
}

CF_STATUS EVP_HashInit(EVP_HASH_CTX *ctx, const EVP_MD *md, const EVP_XOF_OPTS *opts) {
    if (!ctx || !md) return CF_ERR_NULL_PTR;

    SECURE_ZERO(ctx, sizeof(*ctx));
    ctx->md = md;

    // Use opts directly; caller owns memory
    ctx->opts = opts;
    ctx->isHeapAllocOpts = 0;

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
    ctx->isHeapAlloc = 0;
    ctx->isFinalized = 0;
    return CF_SUCCESS;
}

EVP_HASH_CTX* EVP_HashInitAlloc(const EVP_MD *md, const EVP_XOF_OPTS *opts, CF_STATUS *status) {
    if (!md) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    EVP_HASH_CTX *ctx = (EVP_HASH_CTX *)SECURE_ALLOC(sizeof(EVP_HASH_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = EVP_HashInit(ctx, md, opts);
    if (st != CF_SUCCESS) {
        SECURE_FREE(ctx, sizeof(EVP_HASH_CTX));
        if (status) *status = st;
        return NULL;
    }

    ctx->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS EVP_HashUpdate(EVP_HASH_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx || !ctx->digest_ctx || !ctx->md || !data)
        return CF_ERR_NULL_PTR;

    if (data_len == 0)
        return CF_ERR_INVALID_LEN;

    // Stream hashing
    if (!ctx->md->hash_update_fn(ctx->digest_ctx, data, data_len))
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

CF_STATUS EVP_HashFinal(EVP_HASH_CTX *ctx, uint8_t *digest, size_t digest_len) {
    if (!ctx || !ctx->digest_ctx || !ctx->md)
        return CF_ERR_NULL_PTR;
    if (!digest)
        return CF_ERR_NULL_PTR;

    size_t final_len;

    if (EVP_IS_XOF(ctx->md->id)) {
        // XOF: allow variable-length output
        if (digest_len == 0)
            return CF_ERR_INVALID_LEN;
        final_len = digest_len;
    } else {
        // Fixed-length hash: always use default size
        final_len = ctx->md->default_out_len;

        // Optional: ensure caller buffer is large enough
        if (digest_len != 0 && digest_len < final_len)
            return CF_ERR_OUTPUT_BUFFER_TOO_SMALL;
    }

    // Finalize hash
    if (!ctx->md->hash_final_fn(ctx->digest_ctx, digest, final_len))
        return CF_ERR_CTX_CORRUPT;

    // For XOFs or SHA3 variants that require squeezing
    if (ctx->md->hash_squeeze_fn && IS_KECCAK_BASED(ctx->md->id)) {
        if (!ctx->md->hash_squeeze_fn(ctx->digest_ctx, digest, final_len))
            return CF_ERR_CTX_CORRUPT;
    }

    return CF_SUCCESS;
}

CF_STATUS EVP_HashFree(EVP_HASH_CTX *ctx) {
    if (!ctx || !ctx->md)
        return CF_ERR_NULL_PTR;

    // Securely zero and free the digest context
    if (ctx->digest_ctx) {
        SECURE_ZERO(ctx->digest_ctx, ctx->md->ctx_size);
        SECURE_FREE(ctx->digest_ctx, ctx->md->ctx_size);
        ctx->digest_ctx = NULL;
    }

    // Free cloned XOF options if allocated
    if (ctx->opts && ctx->isHeapAllocOpts) {
        EVP_XOFOptsFreeAlloc((EVP_XOF_OPTS**)&ctx->opts);
        ctx->opts = NULL;
        ctx->isHeapAllocOpts = 0;
    }

    // zero the high level info
    SECURE_ZERO(ctx, sizeof(*ctx));

    ctx->isFinalized = 0;
    ctx->isHeapAlloc = 0;

    return CF_SUCCESS;
}

CF_STATUS EVP_HashFreeAlloc(EVP_HASH_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    EVP_HASH_CTX *ctx = *p_ctx;
    int wasHeapAlloc = ctx->isHeapAlloc;  // save flag

    // Reuse Free to clean internals
    EVP_HashFree(ctx);

    // Free the outer struct if heap-allocated
    if (wasHeapAlloc) {
        SECURE_ZERO(ctx, sizeof(EVP_HASH_CTX));
        SECURE_FREE(ctx, sizeof(EVP_HASH_CTX));
        *p_ctx = NULL;
    }

    return CF_SUCCESS;
}

CF_STATUS EVP_ComputeHashFixed(
    const EVP_MD *md,
    uint8_t *digest,
    const uint8_t *data,
    size_t data_len) {
    if (!md || !digest || !data)
        return CF_ERR_NULL_PTR;
    if (data_len == 0)
        return CF_ERR_INVALID_LEN;

    if (EVP_IS_XOF(md->id))
        return CF_ERR_UNSUPPORTED;

    CF_STATUS status;
    EVP_HASH_CTX *ctx = EVP_HashInitAlloc(md, NULL, &status);
    if (!ctx) return status;

    status = EVP_HashUpdate(ctx, data, data_len);
    if (status != CF_SUCCESS) {
        EVP_HashFreeAlloc(&ctx);
        return status;
    }

    // Fixed-length hash uses md->digest_size
    status = EVP_HashFinal(ctx, digest, md->digest_size);

    EVP_HashFreeAlloc(&ctx);
    return status;
}

CF_STATUS EVP_ComputeHashXof(
    const EVP_MD *md,
    uint8_t *digest,
    const uint8_t *data,
    size_t data_len,
    size_t out_len,
    const EVP_XOF_OPTS *opts) { // Optional: hash-specific options
    if (!md || !digest || !data)
        return CF_ERR_NULL_PTR;
    if (data_len == 0 || out_len == 0)
        return CF_ERR_INVALID_LEN;
    if (!EVP_IS_XOF(md->id))
        return CF_ERR_UNSUPPORTED;  // Ensure only XOFs used here

    CF_STATUS status;
    EVP_HASH_CTX *ctx = EVP_HashInitAlloc(md, opts, &status);
    if (!ctx) return status;

    status = EVP_HashUpdate(ctx, data, data_len);
    if (status != CF_SUCCESS) {
        EVP_HashFreeAlloc(&ctx);
        return status;
    }

    status = EVP_HashFinal(ctx, digest, out_len);

    EVP_HashFreeAlloc(&ctx);
    return status;
}


int EVP_HashCompare(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b)
        return CF_ERR_NULL_PTR;

    if (len == 0)
        return CF_ERR_INVALID_LEN;

    // this function record whether it already seen a difference (seen),
    // and record whether that first difference indicated a<b (lt)
    // or a>b (gt).  At the end result = gt - lt -> {1,0,-1}.
    uint32_t lt = 0;
    uint32_t gt = 0;
    uint32_t seen = 0;

    for (size_t i = 0; i < len; ++i) {
        // Work with zero extended 16-bit values to compute borrow on subtraction:
        // If ai < bi then (uint16_t)(ai - bi) will underflow and its top bit (bit 15)
        // will be 1.
        uint16_t ai = (uint16_t)a[i];
        uint16_t bi = (uint16_t)b[i];

        uint16_t d1 = (uint16_t)(ai - bi); // top bit 1 if ai < bi
        uint16_t d2 = (uint16_t)(bi - ai); // top bit 1 if bi < ai

        uint32_t is_lt = (uint32_t)(d1 >> 15); // 1 if ai < bi else 0
        uint32_t is_gt = (uint32_t)(d2 >> 15); // 1 if ai > bi else 0

        uint32_t diff = is_lt | is_gt;         // 1 iff bytes differ at this position
        uint32_t new_diff_mask = (~seen) & diff; // 1 iff this is the first differing byte

        // Only set lt/gt from the first differing byte; subsequent bytes ignored.
        lt |= is_lt & new_diff_mask;
        gt |= is_gt & new_diff_mask;

        // mark we have seen a difference (once set it stays set)
        seen |= diff;
    }

    // result: 1 if gt set, -1 if lt set, 0 otherwise.
    // Compute without branching.
    return (int)gt - (int)lt;
}

CF_STATUS EVP_CloneHashCtx(EVP_HASH_CTX *dst, const EVP_HASH_CTX *src) {
    if (!dst || !src) return CF_ERR_NULL_PTR;

    // Free existing low-level digest context if present
    if (dst->digest_ctx) {
        SECURE_FREE(dst->digest_ctx, dst->md ? dst->md->ctx_size : 0);
        dst->digest_ctx = NULL;
    }

    // Copy the top-level context
    SECURE_MEMCPY(dst, src, sizeof(EVP_HASH_CTX));

    // Allocate and copy low-level digest context if needed
    if (src->digest_ctx) {
        dst->digest_ctx = SECURE_ALLOC(src->md->ctx_size);
        if (!dst->digest_ctx) return CF_ERR_ALLOC_FAILED;
        SECURE_MEMCPY(dst->digest_ctx, src->digest_ctx, src->md->ctx_size);
    } else {
        dst->digest_ctx = NULL;
    }

    dst->opts = src->opts;      // just point to the same EVP_XOF_OPTS
    dst->isHeapAllocOpts = 0;   // do not free later, caller owns it

    // For XOFs, copy output length if applicable
    dst->out_len = src->out_len;
    dst->isFinalized = src->isFinalized;
    dst->isHeapAlloc = 0; // since caller owns dst

    return CF_SUCCESS;
}

EVP_HASH_CTX *EVP_CloneHashCtxAlloc(const EVP_HASH_CTX *src, CF_STATUS *status) {
    if (!src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Allocate top-level context
    EVP_HASH_CTX *dst = (EVP_HASH_CTX *)SECURE_ALLOC(sizeof(EVP_HASH_CTX));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Initialize clone
    CF_STATUS st = EVP_CloneHashCtx(dst, src);
    if (status) *status = st;
    
    if (st != CF_SUCCESS) {
        SECURE_FREE(dst, sizeof(*dst));
        return NULL;
    }

    dst->isHeapAlloc = 1; // library owns this memory
    return dst;
}

size_t EVP_HashDigestSize(const EVP_HASH_CTX *ctx) {
    return ctx ? (ctx->md ? ctx->md->digest_size : 0) : 0;
}

size_t EVP_HashBlockSize(const EVP_HASH_CTX *ctx) {
    return ctx ? (ctx->md ? ctx->md->block_size : 0) : 0;
}

const char* EVP_HashName(const EVP_MD *md) {
    if (!md) return NULL;

    switch (md->id) {
        case EVP_MD5:          return "MD5";
        case EVP_SHA1:         return "SHA1";
        case EVP_SHA224:       return "SHA224";
        case EVP_SHA256:       return "SHA256";
        case EVP_SHA384:       return "SHA384";
        case EVP_SHA512:       return "SHA512";
        case EVP_SHA512_224:   return "SHA512_224";
        case EVP_SHA512_256:   return "SHA512_256";
        case EVP_SHA3_224:     return "SHA3_224";
        case EVP_SHA3_256:     return "SHA3_256";
        case EVP_SHA3_384:     return "SHA3_384";
        case EVP_SHA3_512:     return "SHA3_512";
        case EVP_SHAKE128:     return "SHAKE128";
        case EVP_SHAKE256:     return "SHAKE256";
        case EVP_RAWSHAKE128:  return "rawSHAKE128";
        case EVP_RAWSHAKE256:  return "rawSHAKE256";
        case EVP_CSHAKE128:    return "cSHAKE128";
        case EVP_CSHAKE256:    return "cSHAKE256";
        default:               return NULL;
    }
}

// Fill the XOF options with fixed-size arrays
CF_STATUS EVP_XOFOptsInit(EVP_XOF_OPTS *opts,
                             const uint8_t *N, size_t N_len,
                             const uint8_t *S, size_t S_len,
                             size_t out_len) {
    if (!opts) return CF_ERR_NULL_PTR;
    if (N_len > EVP_MAX_CUSTOMIZATION || S_len > EVP_MAX_CUSTOMIZATION)
        return CF_ERR_INVALID_LEN;

    // Initialize fields
    SECURE_ZERO(opts->N, EVP_MAX_CUSTOMIZATION);
    SECURE_ZERO(opts->S, EVP_MAX_CUSTOMIZATION);

    opts->N_len = N_len;
    opts->S_len = S_len;
    opts->out_len = out_len;
    opts->finalized = 0;
    opts->custom_absorbed = 0;
    opts->emptyNameCustom = 1;

    // Copy N
    if (N && N_len > 0) {
        SECURE_MEMCPY(opts->N, N, N_len);
        opts->emptyNameCustom = 0;
    }

    // Copy S
    if (S && S_len > 0) {
        SECURE_MEMCPY(opts->S, S, S_len);
        opts->emptyNameCustom = 0;
    }

    opts->isHeapAlloc = 0;
    return CF_SUCCESS;
}

// Allocate + fill XOF options
EVP_XOF_OPTS* EVP_XOFOptsInitAlloc(const uint8_t *N, size_t N_len,
                                             const uint8_t *S, size_t S_len,
                                             size_t out_len, CF_STATUS *status) {
    if (N_len > EVP_MAX_CUSTOMIZATION || S_len > EVP_MAX_CUSTOMIZATION) {
        if (status) *status = CF_ERR_INVALID_LEN;
        return NULL;
    }

    EVP_XOF_OPTS *opts = (EVP_XOF_OPTS *)SECURE_ALLOC(sizeof(EVP_XOF_OPTS));
    if (!opts) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = EVP_XOFOptsInit(opts, N, N_len, S, S_len, out_len);
    if (st != CF_SUCCESS) {
        SECURE_FREE(opts, sizeof(EVP_XOF_OPTS));
        if (status) *status = st;
        return NULL;
    }

    opts->isHeapAlloc = 1; // mark heap allocation
    if (status) *status = CF_SUCCESS;
    return opts;
}

// Frees internal buffers only (for pre-allocated struct)
void EVP_XOFOptsFree(EVP_XOF_OPTS *opts) {
    if (!opts) return;

    // Zero sensitive buffers and reset bookkeeping
    SECURE_ZERO(opts->N, EVP_MAX_CUSTOMIZATION);
    SECURE_ZERO(opts->S, EVP_MAX_CUSTOMIZATION);

    opts->N_len = 0;
    opts->S_len = 0;
    opts->out_len = 0;
    opts->finalized = 0;
    opts->custom_absorbed = 0;
    opts->emptyNameCustom = 1;
    opts->isHeapAlloc = 0;
}

// Frees internal buffers + heap-allocated struct
void EVP_XOFOptsFreeAlloc(EVP_XOF_OPTS **p_opts) {
    if (!p_opts || !*p_opts) return;

    EVP_XOF_OPTS *opts = *p_opts;

    int wasHeapAlloc = opts->isHeapAlloc;  // save flag

    EVP_XOFOptsFree(opts);
    
    // Free whole struct if heap-allocated
    if (wasHeapAlloc) {
        SECURE_ZERO(opts, sizeof(EVP_XOF_OPTS));
        SECURE_FREE(opts, sizeof(EVP_XOF_OPTS));
    }

    *p_opts = NULL;
}

// Deep copy from src to dst (fixed arrays)
CF_STATUS EVP_CloneXOFOpts(EVP_XOF_OPTS *dst, const EVP_XOF_OPTS *src) {
    if (!dst || !src) return CF_ERR_NULL_PTR;

    SECURE_MEMCPY(dst->N, src->N, EVP_MAX_CUSTOMIZATION);
    SECURE_MEMCPY(dst->S, src->S, EVP_MAX_CUSTOMIZATION);

    dst->N_len = src->N_len;
    dst->S_len = src->S_len;
    dst->out_len = src->out_len;
    dst->finalized = src->finalized;
    dst->custom_absorbed = src->custom_absorbed;
    dst->emptyNameCustom = src->emptyNameCustom;
    dst->isHeapAlloc = 0;
    return CF_SUCCESS;
}

EVP_XOF_OPTS *EVP_CloneXOFOptsAlloc(const EVP_XOF_OPTS *src, CF_STATUS *status) {
    if (!src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Allocate new structure and zero it to avoid uninitialized reads
    EVP_XOF_OPTS *dst = (EVP_XOF_OPTS *)SECURE_ALLOC(sizeof(EVP_XOF_OPTS));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Deep copy contents
    CF_STATUS ret = EVP_CloneXOFOpts(dst, src);
    if (ret != CF_SUCCESS) {
        if (status) *status = ret;
        // Properly free internal buffers if cloning partially allocated them
        EVP_XOFOptsFreeAlloc(&dst);
        return NULL;
    }

    // Mark it as heap-allocated first
    dst->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return dst;
}
