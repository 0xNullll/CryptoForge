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
    const EVP_XOF_CSHAKE_OPTS *xof_opts = (const EVP_XOF_CSHAKE_OPTS *)opts;
    return ll_cshake128_init(
        (ll_CSHAKE128_CTX *)ctx,
        xof_opts ? xof_opts->N : NULL,
        xof_opts ? xof_opts->N_len : 0,
        xof_opts ? xof_opts->S : NULL,
        xof_opts ? xof_opts->S_len : 0
    );
}

static bool cshake128_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_cshake128_update((ll_CSHAKE128_CTX *)ctx, data, len);
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
    const EVP_XOF_CSHAKE_OPTS *xof_opts = (const EVP_XOF_CSHAKE_OPTS *)opts;
    return ll_cshake256_init(
        (ll_CSHAKE256_CTX *)ctx,
        xof_opts ? xof_opts->N : NULL,
        xof_opts ? xof_opts->N_len : 0,
        xof_opts ? xof_opts->S : NULL,
        xof_opts ? xof_opts->S_len : 0
    );
}

static bool cshake256_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_cshake256_update((ll_CSHAKE256_CTX *)ctx, data, len);
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
        .digest_size = EVP_MD5_DIGEST_SIZE,
        .block_size = EVP_MD5_BLOCK_SIZE,
        .ctx_size = sizeof(ll_MD5_CTX),
        .default_out_len = EVP_MD5_DIGEST_SIZE,
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
        .digest_size = EVP_SHA1_DIGEST_SIZE,
        .block_size = EVP_SHA1_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA1_CTX),
        .default_out_len = EVP_SHA1_DIGEST_SIZE,
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
        .digest_size = EVP_SHA224_DIGEST_SIZE,
        .block_size = EVP_SHA224_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA224_CTX),
        .default_out_len = EVP_SHA224_DIGEST_SIZE,
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
        .digest_size = EVP_SHA256_DIGEST_SIZE,
        .block_size = EVP_SHA256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA256_CTX),
        .default_out_len = EVP_SHA256_DIGEST_SIZE,
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
        .digest_size = EVP_SHA384_DIGEST_SIZE,
        .block_size = EVP_SHA384_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA384_CTX),
        .default_out_len = EVP_SHA384_DIGEST_SIZE,
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
        .digest_size = EVP_SHA512_DIGEST_SIZE,
        .block_size = EVP_SHA512_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA512_CTX),
        .default_out_len = EVP_SHA512_DIGEST_SIZE,
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
        .digest_size = EVP_SHA512_224_DIGEST_SIZE,
        .block_size = EVP_SHA512_224_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA512_224_CTX),
        .default_out_len = EVP_SHA512_224_DIGEST_SIZE,
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
        .digest_size = EVP_SHA512_256_DIGEST_SIZE,
        .block_size = EVP_SHA512_256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA512_256_CTX),
        .default_out_len = EVP_SHA512_256_DIGEST_SIZE,
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
        .digest_size = EVP_SHA3_224_DIGEST_SIZE,
        .block_size = EVP_SHA3_224_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA3_224_CTX),
        .default_out_len = EVP_SHA3_224_DIGEST_SIZE,
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
        .digest_size = EVP_SHA3_256_DIGEST_SIZE,
        .block_size = EVP_SHA3_256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA3_256_CTX),
        .default_out_len = EVP_SHA3_256_DIGEST_SIZE,
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
        .digest_size = EVP_SHA3_384_DIGEST_SIZE,
        .block_size = EVP_SHA3_384_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA3_384_CTX),
        .default_out_len = EVP_SHA3_384_DIGEST_SIZE,
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
        .digest_size = EVP_SHA3_512_DIGEST_SIZE,
        .block_size = EVP_SHA3_512_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA3_512_CTX),
        .default_out_len = EVP_SHA3_512_DIGEST_SIZE,
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
        .block_size = EVP_SHAKE128_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHAKE128_CTX),
        .default_out_len = EVP_SHAKE128_DEFAULT_DIGEST_SIZE,
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
        .block_size = EVP_SHAKE256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHAKE256_CTX),
        .default_out_len = EVP_SHAKE256_DEFAULT_DIGEST_SIZE,
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
        .block_size = EVP_RAWSHAKE128_BLOCK_SIZE,
        .ctx_size = sizeof(ll_RawSHAKE128_CTX),
        .default_out_len = EVP_RAWSHAKE128_DEFAULT_DIGEST_SIZE,
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
        .block_size = EVP_RAWSHAKE256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_RawSHAKE256_CTX),
        .default_out_len = EVP_RAWSHAKE256_DEFAULT_DIGEST_SIZE,
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
        .default_out_len = EVP_CSHAKE128_DEFAULT_DIGEST_SIZE,
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
        .default_out_len = EVP_CSHAKE256_DEFAULT_DIGEST_SIZE,
        .hash_init_fn = cshake256_init_wrapper,
        .hash_update_fn = cshake256_update_wrapper,
        .hash_final_fn = cshake256_final_wrapper,
        .hash_squeeze_fn = cshake256_squeeze_wrapper,
    };
    return &md;
}

TCLIB_STATUS EVP_HashInit(EVP_HASH_CTX *ctx, const EVP_MD *md, const void *opts) {
    if (!ctx || !md)
        return TCLIB_ERR_NULL_PTR;

    ctx->md = md;
    ctx->opts = opts;  // store opts for reset or clone

    // Allocate low-level context
    ctx->digest_ctx = SECURE_ALLOC(md->ctx_size);
    if (!ctx->digest_ctx)
        return TCLIB_ERR_ALLOC_FAILED;

    // Call the hash init function (pass opts for XOF, NULL for normal hashes)
    if (!md->hash_init_fn(ctx->digest_ctx, opts)) {
        SECURE_FREE(ctx->digest_ctx, md->ctx_size);
        return TCLIB_ERR_BAD_STATE;
    }

    // Set default output length for XOF / normal hashes
    ctx->out_len = md->digest_size != 0 ? md->digest_size : md->default_out_len;
    ctx->isHeapAlloc = 0;

    return TCLIB_SUCCESS;
}

EVP_HASH_CTX* EVP_HashInitAlloc(const EVP_MD *md, const void *opts, TCLIB_STATUS *status) {
    if (!md) {
        if (status) *status = TCLIB_ERR_NULL_PTR;
        return NULL;
    }

    EVP_HASH_CTX *ctx = CREATE_CTX(EVP_HASH_CTX);
    if (!ctx) {
        if (status) *status = TCLIB_ERR_ALLOC_FAILED;
        return NULL;
    }

    TCLIB_STATUS st = EVP_HashInit(ctx, md, opts);
    if (st != TCLIB_SUCCESS) {
        DESTROY_CTX(ctx, EVP_HASH_CTX);
        if (status) *status = st;
        return NULL;
    }

    ctx->isHeapAlloc = 1;
    if (status) *status = TCLIB_SUCCESS;
    return ctx;
}

TCLIB_STATUS EVP_HashUpdate(EVP_HASH_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx || !ctx->digest_ctx || !ctx->md || !data)
        return TCLIB_ERR_NULL_PTR;

    if (data_len == 0)
        return TCLIB_ERR_INVALID_LEN;

    // Stream hashing
    if (!ctx->md->hash_update_fn(ctx->digest_ctx, data, data_len))
        return TCLIB_ERR_CTX_CORRUPT;

    return TCLIB_SUCCESS;
}

TCLIB_STATUS EVP_HashFinal(EVP_HASH_CTX *ctx, uint8_t *digest, size_t digest_len) {
    if (!ctx || !ctx->digest_ctx || !ctx->md)
        return TCLIB_ERR_NULL_PTR;
    if (!digest)
        return TCLIB_ERR_NULL_PTR;

    size_t final_len = digest_len != 0 ? digest_len : ctx->out_len;

    if (!ctx->md->hash_final_fn(ctx->digest_ctx, digest, final_len))
        return TCLIB_ERR_CTX_CORRUPT;

    if (ctx->md->hash_squeeze_fn) {
        // For XOF and SHA3: only call hash_squeeze_fn
        if (!ctx->md->hash_squeeze_fn(ctx->digest_ctx, digest, final_len))
            return TCLIB_ERR_CTX_CORRUPT;
    }

    return TCLIB_SUCCESS;
}

TCLIB_STATUS EVP_HashFree(EVP_HASH_CTX *ctx) {
    if (!ctx) return TCLIB_ERR_NULL_PTR;

    if (ctx->digest_ctx) {
        SECURE_ZERO(ctx->digest_ctx, ctx->md->ctx_size);
        SECURE_FREE(ctx->digest_ctx, ctx->md->ctx_size);
    }

    if (ctx->isHeapAlloc) DESTROY_CTX(ctx, EVP_HASH_CTX);

    return TCLIB_SUCCESS;
}

TCLIB_STATUS EVP_HashReset(EVP_HASH_CTX *ctx) {
    if (!ctx || !ctx->md || !ctx->digest_ctx) return TCLIB_ERR_NULL_PTR;

    CLEAR_BUF(ctx->digest_ctx);

    // Reset using stored opts (for XOF)
    if (!ctx->md->hash_init_fn(ctx->digest_ctx, ctx->opts))
        return TCLIB_ERR_BAD_STATE;

    ctx->out_len = ctx->md->digest_size != 0 ? ctx->md->digest_size : ctx->md->default_out_len;

    return TCLIB_SUCCESS;
}

TCLIB_STATUS EVP_ComputeHash(const EVP_MD *md,
                             uint8_t *digest,
                             const uint8_t *data,
                             size_t data_len,
                             size_t out_len,
                             const void *opts) {
    if (!md || !digest || !data)
        return TCLIB_ERR_NULL_PTR;
    if (data_len == 0)
        return TCLIB_ERR_INVALID_LEN;

    TCLIB_STATUS status;
    EVP_HASH_CTX *ctx = EVP_HashInitAlloc(md, opts, &status);
    if (!ctx) return status;

    status = EVP_HashUpdate(ctx, data, data_len);
    if (status != TCLIB_SUCCESS) {
        EVP_HashFree(ctx);
        return status;
    }

    // XOF uses default_out_len if out_len not provided
    size_t final_len = out_len ? out_len : (EVP_IS_XOF(md->id) ? md->default_out_len : md->digest_size);
    status = EVP_HashFinal(ctx, digest, final_len);

    EVP_HashFree(ctx);
    return status;
}


int EVP_HashCompare(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b || len == 0)
        return 0;

    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }

    return (diff == 0) ? 1 : 0;
}

void* EVP_MDCloneCtx(const void *ctx, const EVP_MD *md, TCLIB_STATUS *status) {
    if (!ctx || !md || md->ctx_size == 0) {
        if (status) *status = TCLIB_ERR_NULL_PTR;
        return NULL;
    }

    void *new_ctx = SECURE_ALLOC(md->ctx_size);
    if (!new_ctx) {
        if (status) *status = TCLIB_ERR_ALLOC_FAILED;
        return NULL;
    }

    SECURE_MEMCPY(new_ctx, ctx, md->ctx_size); // shallow copy of internal context memory

    if (status) *status = TCLIB_SUCCESS;
    return new_ctx;
}

size_t EVP_HashDigestSize(const EVP_HASH_CTX *ctx)
{
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

// Table of all supported hashes
static const EVP_MDEntry evp_md_table[] = {
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

TCLIB_STATUS EVP_FillXOFOpts(EVP_XOF_CSHAKE_OPTS *opts,
                     const uint8_t *N, size_t N_len,
                     const uint8_t *S, size_t S_len,
                     size_t out_len) {
    if (!opts) return TCLIB_ERR_NULL_PTR;

    opts->N = N;
    opts->N_len = N_len;
    opts->S = S;
    opts->S_len = S_len;
    opts->out_len = out_len;

    return TCLIB_SUCCESS;
}