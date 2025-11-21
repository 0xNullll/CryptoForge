#include "evp_hash.h"

// ======================
// Wrappers for all hashes
// ======================

// ----------------------
// MD5
// ----------------------
static bool md5_init_wrapper(void *ctx) {
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
// SHA1
// ----------------------
static bool sha1_init_wrapper(void *ctx) {
    return ll_sha1_init((ll_SHA1_CTX *)ctx);
}
static bool sha1_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha1_update((ll_SHA1_CTX *)ctx, data, len);
}
static bool sha1_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_sha1_final((ll_SHA1_CTX *)ctx, digest);
}

// ----------------------
// SHA224
// ----------------------
static bool sha224_init_wrapper(void *ctx) {
    return ll_sha224_init((ll_SHA224_CTX *)ctx);
}
static bool sha224_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha224_update((ll_SHA224_CTX *)ctx, data, len);
}
static bool sha224_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_sha224_final((ll_SHA224_CTX *)ctx, digest);
}

// ----------------------
// SHA256
// ----------------------
static bool sha256_init_wrapper(void *ctx) {
    return ll_sha256_init((ll_SHA256_CTX *)ctx);
}
static bool sha256_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha256_update((ll_SHA256_CTX *)ctx, data, len);
}
static bool sha256_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_sha256_final((ll_SHA256_CTX *)ctx, digest);
}

// ----------------------
// SHA384
// ----------------------
static bool sha384_init_wrapper(void *ctx) {
    return ll_sha384_init((ll_SHA384_CTX *)ctx);
}
static bool sha384_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha384_update((ll_SHA384_CTX *)ctx, data, len);
}
static bool sha384_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_sha384_final((ll_SHA384_CTX *)ctx, digest);
}

// ----------------------
// SHA512
// ----------------------
static bool sha512_init_wrapper(void *ctx) {
    return ll_sha512_init((ll_SHA512_CTX *)ctx);
}
static bool sha512_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha512_update((ll_SHA512_CTX *)ctx, data, len);
}
static bool sha512_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_sha512_final((ll_SHA512_CTX *)ctx, digest);
}

// ----------------------
// SHA512_224
// ----------------------
static bool sha512_224_init_wrapper(void *ctx) {
    return ll_sha512_224_init((ll_SHA512_224_CTX *)ctx);
}
static bool sha512_224_update_wrapper(void *ctx, const uint8_t *data, size_t len) {
    return ll_sha512_224_update((ll_SHA512_224_CTX *)ctx, data, len);
}
static bool sha512_224_final_wrapper(void *ctx, uint8_t *digest, size_t digest_size) {
    (void)digest_size;
    return ll_sha512_224_final((ll_SHA512_224_CTX *)ctx, digest);
}

// ----------------------
// SHA512_256
// ----------------------
static bool sha512_256_init_wrapper(void *ctx) {
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
static bool sha3_224_init_wrapper(void *ctx) {
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
static bool sha3_256_init_wrapper(void *ctx) {
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
static bool sha3_384_init_wrapper(void *ctx) {
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
static bool sha3_512_init_wrapper(void *ctx) {
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
static bool shake128_init_wrapper(void *ctx) {
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
static bool shake256_init_wrapper(void *ctx) {
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
static bool rawshake128_init_wrapper(void *ctx) {
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
static bool rawshake256_init_wrapper(void *ctx) {
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

// ======================
// EVP_MD Return Functions
// ======================

// ----------------------
// SHA / SHA2
// ----------------------

static const EVP_MD *EVP_get_md5(void) {
    static EVP_MD md = {
        .name = "md5",
        .digest_size = EVP_MD5_DIGEST_SIZE,
        .block_size = EVP_MD5_BLOCK_SIZE,
        .ctx_size = sizeof(ll_MD5_CTX),
        .default_out_len = EVP_MD5_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = md5_init_wrapper,
        .hash_update_fn = md5_update_wrapper,
        .hash_final_fn = md5_final_wrapper,
        .hash_squeeze_fn = NULL
    };
    return &md;
}

static const EVP_MD *EVP_get_sha1(void) {
    static EVP_MD md = {
        .name = "sha1",
        .digest_size = EVP_SHA1_DIGEST_SIZE,
        .block_size = EVP_SHA1_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA1_CTX),
        .default_out_len = EVP_SHA1_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = sha1_init_wrapper,
        .hash_update_fn = sha1_update_wrapper,
        .hash_final_fn = sha1_final_wrapper,
        .hash_squeeze_fn = NULL
    };
    return &md;
}

static const EVP_MD *EVP_get_sha224(void) {
    static EVP_MD md = {
        .name = "sha224",
        .digest_size = EVP_SHA224_DIGEST_SIZE,
        .block_size = EVP_SHA224_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA224_CTX),
        .default_out_len = EVP_SHA224_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = sha224_init_wrapper,
        .hash_update_fn = sha224_update_wrapper,
        .hash_final_fn = sha224_final_wrapper,
        .hash_squeeze_fn = NULL
    };
    return &md;
}

static const EVP_MD *EVP_get_sha256(void) {
    static EVP_MD md = {
        .name = "sha256",
        .digest_size = EVP_SHA256_DIGEST_SIZE,
        .block_size = EVP_SHA256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA256_CTX),
        .default_out_len = EVP_SHA256_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = sha256_init_wrapper,
        .hash_update_fn = sha256_update_wrapper,
        .hash_final_fn = sha256_final_wrapper,
        .hash_squeeze_fn = NULL
    };
    return &md;
}

static const EVP_MD *EVP_get_sha384(void) {
    static EVP_MD md = {
        .name = "sha384",
        .digest_size = EVP_SHA384_DIGEST_SIZE,
        .block_size = EVP_SHA384_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA384_CTX),
        .default_out_len = EVP_SHA384_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = sha384_init_wrapper,
        .hash_update_fn = sha384_update_wrapper,
        .hash_final_fn = sha384_final_wrapper,
        .hash_squeeze_fn = NULL
    };
    return &md;
}

static const EVP_MD *EVP_get_sha512(void) {
    static EVP_MD md = {
        .name = "sha512",
        .digest_size = EVP_SHA512_DIGEST_SIZE,
        .block_size = EVP_SHA512_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA512_CTX),
        .default_out_len = EVP_SHA512_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = sha512_init_wrapper,
        .hash_update_fn = sha512_update_wrapper,
        .hash_final_fn = sha512_final_wrapper,
        .hash_squeeze_fn = NULL
    };
    return &md;
}

static const EVP_MD *EVP_get_sha512_224(void) {
    static EVP_MD md = {
        .name = "sha512_224",
        .digest_size = EVP_SHA512_224_DIGEST_SIZE,
        .block_size = EVP_SHA512_224_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA512_224_CTX),
        .default_out_len = EVP_SHA512_224_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = sha512_224_init_wrapper,
        .hash_update_fn = sha512_224_update_wrapper,
        .hash_final_fn = sha512_224_final_wrapper,
        .hash_squeeze_fn = NULL
    };
    return &md;
}

static const EVP_MD *EVP_get_sha512_256(void) {
    static EVP_MD md = {
        .name = "sha512_256",
        .digest_size = EVP_SHA512_256_DIGEST_SIZE,
        .block_size = EVP_SHA512_256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA512_256_CTX),
        .default_out_len = EVP_SHA512_256_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = sha512_256_init_wrapper,
        .hash_update_fn = sha512_256_update_wrapper,
        .hash_final_fn = sha512_256_final_wrapper,
        .hash_squeeze_fn = NULL
    };
    return &md;
}

// ----------------------
// SHA3
// ----------------------

static const EVP_MD *EVP_get_sha3_224(void) {
    static EVP_MD md = {
        .name = "sha3_224",
        .digest_size = EVP_SHA3_224_DIGEST_SIZE,
        .block_size = EVP_SHA3_224_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA3_224_CTX),
        .default_out_len = EVP_SHA3_224_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = sha3_224_init_wrapper,
        .hash_update_fn = sha3_224_update_wrapper,
        .hash_final_fn = sha3_224_final_wrapper,
        .hash_squeeze_fn = sha3_224_squeeze_wrapper
    };
    return &md;
}

static const EVP_MD *EVP_get_sha3_256(void) {
    static EVP_MD md = {
        .name = "sha3_256",
        .digest_size = EVP_SHA3_256_DIGEST_SIZE,
        .block_size = EVP_SHA3_256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA3_256_CTX),
        .default_out_len = EVP_SHA3_256_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = sha3_256_init_wrapper,
        .hash_update_fn = sha3_256_update_wrapper,
        .hash_final_fn = sha3_256_final_wrapper,
        .hash_squeeze_fn = sha3_256_squeeze_wrapper
    };
    return &md;
}

static const EVP_MD *EVP_get_sha3_384(void) {
    static EVP_MD md = {
        .name = "sha3_384",
        .digest_size = EVP_SHA3_384_DIGEST_SIZE,
        .block_size = EVP_SHA3_384_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA3_384_CTX),
        .default_out_len = EVP_SHA3_384_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = sha3_384_init_wrapper,
        .hash_update_fn = sha3_384_update_wrapper,
        .hash_final_fn = sha3_384_final_wrapper,
        .hash_squeeze_fn = sha3_384_squeeze_wrapper
    };
    return &md;
}

static const EVP_MD *EVP_get_sha3_512(void) {
    static EVP_MD md = {
        .name = "sha3_512",
        .digest_size = EVP_SHA3_512_DIGEST_SIZE,
        .block_size = EVP_SHA3_512_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHA3_512_CTX),
        .default_out_len = EVP_SHA3_512_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = sha3_512_init_wrapper,
        .hash_update_fn = sha3_512_update_wrapper,
        .hash_final_fn = sha3_512_final_wrapper,
        .hash_squeeze_fn = sha3_512_squeeze_wrapper
    };
    return &md;
}

// ----------------------
// SHAKE / RawSHAKE
// ----------------------

static const EVP_MD *EVP_get_shake128(void) {
    static EVP_MD md = {
        .name = "shake128",
        .digest_size = 0,
        .block_size = EVP_SHAKE128_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHAKE128_CTX),
        .default_out_len = EVP_SHAKE128_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = shake128_init_wrapper,
        .hash_update_fn = shake128_update_wrapper,
        .hash_final_fn = shake128_final_wrapper,
        .hash_squeeze_fn = shake128_squeeze_wrapper
    };
    return &md;
}

static const EVP_MD *EVP_get_shake256(void) {
    static EVP_MD md = {
        .name = "shake256",
        .digest_size = 0,
        .block_size = EVP_SHAKE256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_SHAKE256_CTX),
        .default_out_len = EVP_SHAKE256_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = shake256_init_wrapper,
        .hash_update_fn = shake256_update_wrapper,
        .hash_final_fn = shake256_final_wrapper,
        .hash_squeeze_fn = shake256_squeeze_wrapper
    };
    return &md;
}

static const EVP_MD *EVP_get_shake128_raw(void) {
    static EVP_MD md = {
        .name = "shake128_raw",
        .digest_size = 0,
        .block_size = EVP_RAWSHAKE128_BLOCK_SIZE,
        .ctx_size = sizeof(ll_RawSHAKE128_CTX),
        .default_out_len = EVP_RAWSHAKE128_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = rawshake128_init_wrapper,
        .hash_update_fn = rawshake128_update_wrapper,
        .hash_final_fn = rawshake128_final_wrapper,
        .hash_squeeze_fn = rawshake128_squeeze_wrapper
    };
    return &md;
}

static const EVP_MD *EVP_get_shake256_raw(void) {
    static EVP_MD md = {
        .name = "shake256_raw",
        .digest_size = 0,
        .block_size = EVP_RAWSHAKE256_BLOCK_SIZE,
        .ctx_size = sizeof(ll_RawSHAKE256_CTX),
        .default_out_len = EVP_RAWSHAKE256_DEFAULT_OUT_LEN,
        .ctx = NULL,
        .hash_init_fn = rawshake256_init_wrapper,
        .hash_update_fn = rawshake256_update_wrapper,
        .hash_final_fn = rawshake256_final_wrapper,
        .hash_squeeze_fn = rawshake256_squeeze_wrapper
    };
    return &md;
}

typedef const EVP_MD *(*EVP_MDGetter)(void);

typedef struct {
    uint32_t flag;
    EVP_MDGetter getter;
} EVP_MDEntry;

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
    { EVP_RAWSHAKE128,   EVP_get_shake128_raw },
    { EVP_RAWSHAKE256,   EVP_get_shake256_raw },
};

// Replace EVP_MDByFlag with table lookup
TC_API const EVP_MD *EVP_MDByFlag(uint32_t algo_flag) {
    size_t table_len = sizeof(evp_md_table) / sizeof(evp_md_table[0]);
    for (size_t i = 0; i < table_len; i++) {
        if (evp_md_table[i].flag == algo_flag) {
            return evp_md_table[i].getter();
        }
    }
    return NULL; // invalid flag
}