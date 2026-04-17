#ifndef CF_FLAGS_H
#define CF_FLAGS_H

// #include "../config/crypto_config.h"
#include <stdint.h>
#include <assert.h>
// #include "../config/libs.h"

_Static_assert(sizeof(uint32_t) == 4, "uint32_t must be 32-bit");

/* =======================================
   MAX SIZES & GENERAL CONSTANTS
   ======================================= */
#define CF_MAX_HASH_CTX_SIZE         512
#define CF_MAX_CIPHER_IV_SIZE        24
#define CF_CIPHER_MAX_BLOCK_SIZE     16

#define CF_MAX_DEFAULT_HASH_BLOCK_SIZE 168
#define CF_MAX_DEFAULT_DIGEST_SIZE     64
#define CF_MAX_DEFAULT_MAC_SIZE        16
#define CF_MAX_CIPHER_KEY_SIZE         32

#define CF_CTX_MAGIC 0x43464D47  // "CFMG"

_Static_assert(CF_CTX_MAGIC == 0x43464D47u, "CF_CTX_MAGIC modified unexpectedly");

/* =======================================
   HASH / DIGEST BLOCK SIZES
   ======================================= */
typedef enum {
    /* MD5 / SHA1 */
    CF_MD5_BLOCK_SIZE        = 64,
    CF_SHA1_BLOCK_SIZE       = 64,

    /* SHA2 family */
    CF_SHA224_BLOCK_SIZE     = 64,
    CF_SHA256_BLOCK_SIZE     = 64,
    CF_SHA384_BLOCK_SIZE     = 128,
    CF_SHA512_BLOCK_SIZE     = 128,
    CF_SHA512_224_BLOCK_SIZE = 128,
    CF_SHA512_256_BLOCK_SIZE = 128,

    /* SHA3 family */
    CF_SHA3_224_BLOCK_SIZE   = 144,
    CF_SHA3_256_BLOCK_SIZE   = 136,
    CF_SHA3_384_BLOCK_SIZE   = 104,
    CF_SHA3_512_BLOCK_SIZE   = 72,

    /* SHAKE / RawSHAKE */
    CF_SHAKE128_BLOCK_SIZE    = 168,
    CF_SHAKE256_BLOCK_SIZE    = 136,
    CF_RAWSHAKE128_BLOCK_SIZE = 168,
    CF_RAWSHAKE256_BLOCK_SIZE = 136,

    /* cSHAKE */
    CF_CSHAKE128_BLOCK_SIZE   = 168,
    CF_CSHAKE256_BLOCK_SIZE   = 136
} CF_HASH_BLOCK_SIZE;

typedef enum {
    CF_MD5_DIGEST_SIZE        = 16,
    CF_SHA1_DIGEST_SIZE       = 20,
    CF_SHA224_DIGEST_SIZE     = 28,
    CF_SHA256_DIGEST_SIZE     = 32,
    CF_SHA384_DIGEST_SIZE     = 48,
    CF_SHA512_DIGEST_SIZE     = 64,
    CF_SHA512_224_DIGEST_SIZE = 28,
    CF_SHA512_256_DIGEST_SIZE = 32,
    CF_SHA3_224_DIGEST_SIZE   = 28,
    CF_SHA3_256_DIGEST_SIZE   = 32,
    CF_SHA3_384_DIGEST_SIZE   = 48,
    CF_SHA3_512_DIGEST_SIZE   = 64
} CF_DIGEST_SIZE;

typedef enum {
    CF_SHAKE128_DEFAULT_DIGEST_SIZE    = 32,
    CF_SHAKE256_DEFAULT_DIGEST_SIZE    = 64,
    CF_RAWSHAKE128_DEFAULT_DIGEST_SIZE = 32,
    CF_RAWSHAKE256_DEFAULT_DIGEST_SIZE = 64,
    CF_CSHAKE128_DEFAULT_DIGEST_SIZE   = 32,
    CF_CSHAKE256_DEFAULT_DIGEST_SIZE   = 64,
    CF_KMAC_DEFAULT_OUTPUT_LEN_128     = 32,
    CF_KMAC_DEFAULT_OUTPUT_LEN_256     = 64,
    CF_KMAC_XOF_DEFAULT_OUTPUT_LEN_128 = 32,
    CF_KMAC_XOF_DEFAULT_OUTPUT_LEN_256 = 64
} CF_DIGEST_DEFAULT_SIZE;

/* =======================================
   CATEGORY FLAGS
   ======================================= */
typedef enum {
    CF_CAT_DIGEST  = 0x00000000, // Standard digest algorithms
    CF_CAT_XOF     = 0x10000000, // SHAKE / cSHAKE / RawXOF
    CF_CAT_MAC     = 0x20000000, // MAC algorithms: HMAC, CMAC, GMAC, Poly1305
    CF_CAT_KDF     = 0x40000000  // Key derivation algorithms: HKDF, PBKDF2, KMAC-XOF
} CF_CATEGORY;

#define CF_CATEGORY_MASK 0xF0000000u

// Ensure each category fits within the mask
static_assert((CF_CAT_DIGEST & CF_CATEGORY_MASK) == CF_CAT_DIGEST, "CF_CAT_DIGEST exceeds category mask");
static_assert((CF_CAT_XOF    & CF_CATEGORY_MASK) == CF_CAT_XOF,    "CF_CAT_XOF exceeds category mask");
static_assert((CF_CAT_MAC    & CF_CATEGORY_MASK) == CF_CAT_MAC,    "CF_CAT_MAC exceeds category mask");
static_assert((CF_CAT_KDF    & CF_CATEGORY_MASK) == CF_CAT_KDF,    "CF_CAT_KDF exceeds category mask");

static_assert((CF_CAT_DIGEST & CF_CAT_XOF) == 0, "CF_CAT_DIGEST and CF_CAT_XOF overlap");
static_assert((CF_CAT_DIGEST & CF_CAT_MAC) == 0, "CF_CAT_DIGEST and CF_CAT_MAC overlap");
static_assert((CF_CAT_DIGEST & CF_CAT_KDF) == 0, "CF_CAT_DIGEST and CF_CAT_KDF overlap");

static_assert((CF_CAT_XOF & CF_CAT_MAC) == 0, "CF_CAT_XOF and CF_CAT_MAC overlap");
static_assert((CF_CAT_XOF & CF_CAT_KDF) == 0, "CF_CAT_XOF and CF_CAT_KDF overlap");

static_assert((CF_CAT_MAC & CF_CAT_KDF) == 0, "CF_CAT_MAC and CF_CAT_KDF overlap");

typedef enum {
    /* Standard Digest IDs */
    CF_MD5         = CF_CAT_DIGEST | 0x0001,
    CF_SHA1        = CF_CAT_DIGEST | 0x0002,
    CF_SHA224      = CF_CAT_DIGEST | 0x0003,
    CF_SHA256      = CF_CAT_DIGEST | 0x0004,
    CF_SHA384      = CF_CAT_DIGEST | 0x0005,
    CF_SHA512      = CF_CAT_DIGEST | 0x0006,
    CF_SHA512_224  = CF_CAT_DIGEST | 0x0007,
    CF_SHA512_256  = CF_CAT_DIGEST | 0x0008,

    /* KECCAK variants */
    CF_SHA3_224    = CF_CAT_DIGEST | 0x0010,
    CF_SHA3_256    = CF_CAT_DIGEST | 0x0011,
    CF_SHA3_384    = CF_CAT_DIGEST | 0x0012,
    CF_SHA3_512    = CF_CAT_DIGEST | 0x0013,

    /* XOFs */
    CF_SHAKE128    = CF_CAT_DIGEST | CF_CAT_XOF | 0x0010,
    CF_SHAKE256    = CF_CAT_DIGEST | CF_CAT_XOF | 0x0011,
    CF_RAWSHAKE128 = CF_CAT_DIGEST | CF_CAT_XOF | 0x0020,
    CF_RAWSHAKE256 = CF_CAT_DIGEST | CF_CAT_XOF | 0x0021,
    CF_CSHAKE128   = CF_CAT_DIGEST | CF_CAT_XOF | 0x0030,
    CF_CSHAKE256   = CF_CAT_DIGEST | CF_CAT_XOF | 0x0031
} CF_HASH_FLAGS;

/* Category checks */
#define CF_IS_DIGEST(id)  (((id) & CF_CATEGORY_MASK) == CF_CAT_DIGEST)
#define CF_IS_XOF(id)     (((id) & CF_CATEGORY_MASK) == CF_CAT_XOF)
#define CF_IS_MAC(id)     (((id) & CF_CATEGORY_MASK) == CF_CAT_MAC)
#define CF_IS_KDF(id)     (((id) & CF_CATEGORY_MASK) == CF_CAT_KDF)

#define CF_IS_KECCAK(id)  ((id) == CF_SHA3_224 || (id) == CF_SHA3_256 || \
                           (id) == CF_SHA3_384 || (id) == CF_SHA3_512)

/* =======================================
   MAC FLAGS
   ======================================= */
#define CF_MAC_FLAG_MASK    0xFFFFF000
#define CF_MAC_SUBFLAG_MASK 0x00000FFF
#define CF_XOF_MASK         0x00100000
#define CF_HASH_MASK        0x000000FF
#define CF_MAC_KMAC_MASK    0x00000F00

// Compile-time checks
static_assert((CF_HASH_MASK & CF_MAC_KMAC_MASK) == 0, "HASH/KMAC overlap");
static_assert((CF_HASH_MASK & CF_MAC_FLAG_MASK) == 0, "HASH/MAC_FLAG overlap");
static_assert((CF_HASH_MASK & CF_XOF_MASK) == 0, "HASH/XOF overlap");

static_assert((CF_MAC_KMAC_MASK & CF_XOF_MASK) == 0, "KMAC/XOF overlap");

static_assert((CF_MAC_SUBFLAG_MASK & CF_MAC_FLAG_MASK) == 0, "SUBFLAG/MAC_FLAG overlap");
static_assert((CF_MAC_SUBFLAG_MASK & CF_XOF_MASK) == 0, "SUBFLAG/XOF overlap");

typedef enum {
    CF_HMAC     = CF_CAT_MAC | 0x1000,
    CF_KMAC_STD = CF_CAT_MAC | 0x2000,
    CF_AES_CMAC = CF_CAT_MAC | 0x3000,
    CF_AES_GMAC = CF_CAT_MAC | 0x4000,
    CF_POLY1305 = CF_CAT_MAC | 0x5000
} CF_MAC_FLAGS;

typedef enum {
    CF_KMAC128      = 0x100,
    CF_KMAC256      = 0x200,
    CF_KMAC_XOF128  = 0x300,
    CF_KMAC_XOF256  = 0x400
} CF_KMAC_TYPE_FLAGS;

#define CF_IS_KMAC_XOF(id) ((id) == CF_KMAC_XOF128 || (id) == CF_KMAC_XOF256)

/* MAC Checks */
#define CF_MAC_IS_HMAC(id)      (((id) & CF_MAC_FLAG_MASK) == CF_HMAC)
#define CF_MAC_IS_KMAC_STD(id)  (((id) & CF_MAC_FLAG_MASK) == CF_KMAC_STD)
#define CF_MAC_IS_AES_CMAC(id)  (((id) & CF_MAC_FLAG_MASK) == CF_AES_CMAC)
#define CF_MAC_IS_AES_GMAC(id)  (((id) & CF_MAC_FLAG_MASK) == CF_AES_GMAC)
#define CF_MAC_IS_POLY1305(id)  (((id) & CF_MAC_FLAG_MASK) == CF_POLY1305)
#define CF_MAC_IS_XOF(id)       (((id) & CF_XOF_MASK) != 0)
#define CF_MAC_GET_HASH(id)     ((id) & CF_HASH_MASK)

/* =======================================
   KDF FLAGS
   ======================================= */
typedef enum {
    CF_HKDF     = CF_CAT_KDF | 0x1000,
    CF_PBKDF2   = CF_CAT_KDF | 0x2000,
    CF_KMAC_XOF = CF_CAT_KDF | 0x3000
} CF_KDF_FLAGS;

#define CF_KDF_IS_HKDF(id)      ((id) == CF_HKDF)
#define CF_KDF_IS_PBKDF2(id)    ((id) == CF_PBKDF2)
#define CF_KDF_IS_KMAC_XOF(id)  ((id) == CF_KMAC_XOF)

/* =======================================
   ENCODING / DECODING FLAGS
   ======================================= */
typedef enum {
    /* Base16 / Hex */
    CF_BASE16_UPPER       = 0x01,  // '0'-'9','A'-'F'
    CF_BASE16_LOWER       = 0x02,  // '0'-'9','a'-'f'
    CF_BASE16_DEC         = 0x04,

    /* Base32 */
    CF_BASE32_ENC         = 0x10,
    CF_BASE32_DEC         = 0x20,
    CF_BASE32_ENC_NOPAD   = 0x40,
    CF_BASE32_DEC_NOPAD   = 0x80,

    /* Base58 */
    CF_BASE58_ENC         = 0x100,
    CF_BASE58_DEC         = 0x200,

    /* Base64 */
    CF_BASE64_STD_ENC        = 0x400,
    CF_BASE64_STD_DEC        = 0x800,
    CF_BASE64_URL_ENC        = 0x1000,
    CF_BASE64_URL_DEC        = 0x2000,
    CF_BASE64_NOPAD_ENC      = 0x4000,
    CF_BASE64_NOPAD_DEC      = 0x8000,

    /* Base85 variants */
    CF_BASE85_STD_ENC     = 0x10000,   // Standard ASCII85 ('z' supported)
    CF_BASE85_STD_DEC     = 0x20000,
    CF_BASE85_EXT_ENC     = 0x40000,   // Extended ASCII85 ('y' optional)
    CF_BASE85_EXT_DEC     = 0x80000,
    CF_BASE85_Z85_ENC     = 0x100000,  // Z85 variant (no z/y, different charset)
    CF_BASE85_Z85_DEC     = 0x200000,
    CF_BASE85_IGNORE_WS   = 0x400000   // Ignore white spaces
} CF_ENCODING_FLAGS;

#define CF_IS_ENC(v)   ((v) & ( \
        CF_BASE16_UPPER | CF_BASE16_LOWER | \
        CF_BASE32_ENC | CF_BASE32_ENC_NOPAD | \
        CF_BASE58_ENC | \
        CF_BASE64_STD_ENC | CF_BASE64_URL_ENC | CF_BASE64_NOPAD_ENC | \
        CF_BASE85_STD_ENC | CF_BASE85_EXT_ENC | CF_BASE85_Z85_ENC ))

#define CF_IS_DEC(v)   ((v) & ( \
        CF_BASE16_DEC | \
        CF_BASE32_DEC | CF_BASE32_DEC_NOPAD | \
        CF_BASE58_DEC | \
        CF_BASE64_STD_DEC | CF_BASE64_URL_DEC | CF_BASE64_NOPAD_DEC | \
        CF_BASE85_STD_DEC | CF_BASE85_EXT_DEC | CF_BASE85_Z85_DEC ))

#define CF_BASE16_MASK 0x00000007  // Mask for all Base16 flags (UPPER, LOWER, DEC)
#define CF_BASE32_MASK 0x000000F0  // Mask for all Base32 flags (ENC, DEC, NOPAD)
#define CF_BASE58_MASK 0x00000300  // Mask for all Base58 flags (ENC, DEC)
#define CF_BASE64_MASK 0x0000FC00  // Mask for all Base64 flags (STD, URL, NOPAD, ENC/DEC)
#define CF_BASE85_MASK 0x007F0000  // Mask for all Base85 flags (STD, EXT, Z85, IGNORE_WS)

// Static assertions to ensure masks don't overlap outside their intended bit positions
static_assert((CF_BASE16_MASK & ~0x0000000F) == 0, "CF_BASE16_MASK exceeds 4 bits");
static_assert((CF_BASE32_MASK & ~0x000000F0) == 0, "CF_BASE32_MASK exceeds bits 4-7");
static_assert((CF_BASE58_MASK & ~0x00000300) == 0, "CF_BASE58_MASK exceeds bits 8-9");
static_assert((CF_BASE64_MASK & ~0x0000FC00) == 0, "CF_BASE64_MASK exceeds bits 10-15");
static_assert((CF_BASE85_MASK & ~0x007F0000) == 0, "CF_BASE85_MASK exceeds bits 16-22");

/* =======================================
   CIPHER FLAGS
   ======================================= */
#define CF_AES_BLOCK_SIZE   16

typedef enum {
    CF_OP_DECRYPT = 0,
    CF_OP_ENCRYPT = 1
} CF_OPERATION;

typedef enum {
    CF_CAT_AES    = 0x00010000, // AES family
    CF_CAT_CHACHA = 0x00020000, // ChaCha family
    CF_CAT_AEAD   = 0x00040000  // AEAD family
} CF_CIPHER_CATEGORY;

/* AES modes */
typedef enum {
    CF_AES_ECB       = CF_CAT_AES | 0x0001,
    CF_AES_CBC       = CF_CAT_AES | 0x0002,
    CF_AES_CBC_PKCS7 = CF_CAT_AES | 0x0004,
    CF_AES_OFB       = CF_CAT_AES | 0x0008,
    CF_AES_CFB8      = CF_CAT_AES | 0x0010,
    CF_AES_CFB128    = CF_CAT_AES | 0x0020,
    CF_AES_CTR       = CF_CAT_AES | 0x0030
} CF_AES_MODE_FLAGS;

/* ChaCha modes */
typedef enum {
    CF_CHACHA8    = CF_CAT_CHACHA | 0x0001,
    CF_CHACHA12   = CF_CAT_CHACHA | 0x0002,
    CF_CHACHA20   = CF_CAT_CHACHA | 0x0004,
    CF_XCHACHA8   = CF_CAT_CHACHA | 0x0008,
    CF_XCHACHA12  = CF_CAT_CHACHA | 0x0010,
    CF_XCHACHA20  = CF_CAT_CHACHA | 0x0020
} CF_CHACHA_MODE_FLAGS;

/* AEAD modes */
typedef enum {
    CF_AES_GCM = CF_CAT_AEAD | 0x0001,
    CF_CHACHA20_POLY1305  = CF_CAT_AEAD | 0x0010,
    CF_XCHACHA20_POLY1305 = CF_CAT_AEAD | 0x0020
} CF_AEAD_MODE_FLAGS;

/* Cipher checks */
#define CF_CIPHER_FAMILY_MASK 0xFFFF0000u
#define CF_CIPHER_MODE_MASK   0x0000FFFFu

#define CF_IS_CIPHER(mode)        ((((mode) & CF_CIPHER_FAMILY_MASK) == CF_CAT_AES) || (((mode) & CF_CIPHER_FAMILY_MASK) == CF_CAT_CHACHA))
#define CF_IS_CIPHER_AES(mode)    (((mode) & CF_CIPHER_FAMILY_MASK) == CF_CAT_AES)
#define CF_IS_CIPHER_CHACHA(mode) (((mode) & CF_CIPHER_FAMILY_MASK) == CF_CAT_CHACHA)
#define CF_IS_AEAD(mode)          (((mode) & CF_CIPHER_FAMILY_MASK) == CF_CAT_AEAD)
#define CF_IS_AEAD_AES(mode)      (CF_IS_AEAD(mode) && ((mode) & 0x00F0) == 0x0000)
#define CF_IS_AEAD_CHACHA(mode)   (CF_IS_AEAD(mode) && ((mode) & 0x00F0) != 0x0000)
#define CF_IS_XCHACHA_MODE(mode)  ((mode) == CF_XCHACHA8 || \
                                   (mode) == CF_XCHACHA12 || \
                                   (mode) == CF_XCHACHA20)

/* =======================================
   KEY & TAG SIZES
   ======================================= */
typedef enum {
    CF_KEY_128_SIZE = 16,
    CF_KEY_192_SIZE = 24,
    CF_KEY_256_SIZE = 32
} CF_KEY_SIZE;

_Static_assert(CF_KEY_128_SIZE == 16, "128-bit key size incorrect");
_Static_assert(CF_KEY_192_SIZE == 24, "192-bit key size incorrect");
_Static_assert(CF_KEY_256_SIZE == 32, "256-bit key size incorrect");

#define CF_IS_CIPHER_AES_KEY_VALID(len)     ((len) == CF_KEY_128_SIZE || (len) == CF_KEY_192_SIZE || (len) == CF_KEY_256_SIZE)
#define CF_IS_CIPHER_CHACHA_KEY_VALID(len)  ((len) == CF_KEY_128_SIZE || (len) == CF_KEY_256_SIZE)
#define CF_IS_CIPHER_XCHACHA_KEY_VALID(len) ((len) == CF_KEY_256_SIZE)
#define CF_IS_AEAD_CHACHA_KEY_VALID(len)    ((len) == CF_KEY_256_SIZE)

typedef enum {
    CF_AEAD_TAG_32_SIZE  = 4,
    CF_AEAD_TAG_64_SIZE  = 8,
    CF_AEAD_TAG_96_SIZE  = 12,
    CF_AEAD_TAG_128_SIZE = 16
} CF_AEAD_TAG_SIZE;

#define CF_IS_VALID_AEAD_GCM_TAG_SIZE(len) ((len) == CF_AEAD_TAG_32_SIZE  || \
                                           (len) == CF_AEAD_TAG_64_SIZE  || \
                                           (len) == CF_AEAD_TAG_96_SIZE || \
                                           (len) == CF_AEAD_TAG_128_SIZE)

#define CF_IS_VALID_AEAD_CHACHA_TAG_SIZE(len) ((len) == CF_AEAD_TAG_128_SIZE)

_Static_assert(CF_AEAD_TAG_32_SIZE  == 4,  "32-bit tag size incorrect");
_Static_assert(CF_AEAD_TAG_64_SIZE  == 8,  "64-bit tag size incorrect");
_Static_assert(CF_AEAD_TAG_96_SIZE  == 12, "96-bit tag size incorrect");
_Static_assert(CF_AEAD_TAG_128_SIZE == 16, "128-bit tag size incorrect");

#endif // CF_FLAGS_H