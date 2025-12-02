#ifndef EVP_FLAGS_H
#define EVP_FLAGS_H

#include "../../config/crypto_config.h"

#define EVP_MAX_KEY_SIZE MAX_KEY_SIZE                     // bytes
#define EVP_MAX_CUSTOMIZATION MAX_CUSTOMIZATION           // bytes
#define EVP_MAX_ENCODED_HEADER_LEN MAX_ENCODED_HEADER_LEN // bytes

// ======================
// Maximum default sizes
// ======================
#define EVP_MAX_DEFAULT_BLOCK_SIZE 168  // SHAKE
#define EVP_MAX_DEFAULT_DIGEST_SIZE 64  // SHA512 / SHA3-512

// ======================
// Block / Digest Sizes
// ======================
typedef enum {
    // MD5
    EVP_MD5_BLOCK_SIZE        = 64,
    // SHA1
    EVP_SHA1_BLOCK_SIZE       = 64,
    // SHA2 family
    EVP_SHA224_BLOCK_SIZE     = 64,
    EVP_SHA256_BLOCK_SIZE     = 64,
    EVP_SHA384_BLOCK_SIZE     = 128,
    EVP_SHA512_BLOCK_SIZE     = 128,
    EVP_SHA512_224_BLOCK_SIZE = 128,
    EVP_SHA512_256_BLOCK_SIZE = 128,
    // SHA3 family
    EVP_SHA3_224_BLOCK_SIZE   = 144,
    EVP_SHA3_256_BLOCK_SIZE   = 136,
    EVP_SHA3_384_BLOCK_SIZE   = 104,
    EVP_SHA3_512_BLOCK_SIZE   = 72,
    // SHAKE / RawSHAKE
    EVP_SHAKE128_BLOCK_SIZE    = 168,
    EVP_SHAKE256_BLOCK_SIZE    = 136,
    EVP_RAWSHAKE128_BLOCK_SIZE = 168,
    EVP_RAWSHAKE256_BLOCK_SIZE = 136,
    // cSHAKE
    EVP_CSHAKE128_BLOCK_SIZE   = 168,
    EVP_CSHAKE256_BLOCK_SIZE   = 136
} EVP_BlockSize;

// ======================
// Digest / Output Sizes (bytes)
// ======================
typedef enum {
    // MD5
    EVP_MD5_DIGEST_SIZE        = 16,
    // SHA1
    EVP_SHA1_DIGEST_SIZE       = 20,
    // SHA2 family
    EVP_SHA224_DIGEST_SIZE     = 28,
    EVP_SHA256_DIGEST_SIZE     = 32,
    EVP_SHA384_DIGEST_SIZE     = 48,
    EVP_SHA512_DIGEST_SIZE     = 64,
    EVP_SHA512_224_DIGEST_SIZE = 28,
    EVP_SHA512_256_DIGEST_SIZE = 32,
    // SHA3 family
    EVP_SHA3_224_DIGEST_SIZE   = 28,
    EVP_SHA3_256_DIGEST_SIZE   = 32,
    EVP_SHA3_384_DIGEST_SIZE   = 48,
    EVP_SHA3_512_DIGEST_SIZE   = 64,
} EVP_DigestSize;

// ======================
// Default Digest Sizes for XOFs (bytes)
// ======================
typedef enum {
    EVP_SHAKE128_DEFAULT_DIGEST_SIZE    = 32,
    EVP_SHAKE256_DEFAULT_DIGEST_SIZE    = 64,
    EVP_RAWSHAKE128_DEFAULT_DIGEST_SIZE = 32,
    EVP_RAWSHAKE256_DEFAULT_DIGEST_SIZE = 64,
    EVP_CSHAKE128_DEFAULT_DIGEST_SIZE   = 32,
    EVP_CSHAKE256_DEFAULT_DIGEST_SIZE   = 64
} EVP_DigestDefaultSize;

// ======================
// 1. Hash / Digest IDs & Flags
// ======================
typedef enum {
    EVP_CAT_DIGEST = 0x00000000, // MD5, SHA1, SHA2, SHA3
    EVP_CAT_XOF    = 0x10000000, // SHAKE / cSHAKE / RAWXOF
    EVP_CAT_MAC    = 0x20000000, // HMAC / KMAC
    EVP_CAT_RNG    = 0x40000000
} EVP_Category;

// Unique algorithm IDs
typedef enum {
    EVP_MD5        = EVP_CAT_DIGEST | 0x0001,
    EVP_SHA1       = EVP_CAT_DIGEST | 0x0002,
    EVP_SHA224     = EVP_CAT_DIGEST | 0x0003,
    EVP_SHA256     = EVP_CAT_DIGEST | 0x0004,
    EVP_SHA384     = EVP_CAT_DIGEST | 0x0005,
    EVP_SHA512     = EVP_CAT_DIGEST | 0x0006,
    EVP_SHA512_224 = EVP_CAT_DIGEST | 0x0007,
    EVP_SHA512_256 = EVP_CAT_DIGEST | 0x0008,
    EVP_SHA3_224   = EVP_CAT_DIGEST | 0x0010,
    EVP_SHA3_256   = EVP_CAT_DIGEST | 0x0011,
    EVP_SHA3_384   = EVP_CAT_DIGEST | 0x0012,
    EVP_SHA3_512   = EVP_CAT_DIGEST | 0x0013,
    EVP_SHAKE128   = EVP_CAT_XOF    | 0x0010,
    EVP_SHAKE256   = EVP_CAT_XOF    | 0x0011,
    EVP_RAWSHAKE128= EVP_CAT_XOF    | 0x0020,
    EVP_RAWSHAKE256= EVP_CAT_XOF    | 0x0021,
    EVP_CSHAKE128  = EVP_CAT_XOF    | 0x0030,
    EVP_CSHAKE256  = EVP_CAT_XOF    | 0x0031
} EVP_Algorithm;

// Helper macros for category checks
#define EVP_IS_DIGEST_SIZE(id) (((id) & 0xF0000000) == EVP_CAT_DIGEST)

#define IS_KECCAK_BASED(id) \
    (((id) == EVP_SHA3_224)   || ((id) == EVP_SHA3_256)   || \
     ((id) == EVP_SHA3_384)   || ((id) == EVP_SHA3_512)   || \
     ((id) == EVP_SHAKE128)   || ((id) == EVP_SHAKE256)   || \
     ((id) == EVP_RAWSHAKE128)|| ((id) == EVP_RAWSHAKE256)|| \
     ((id) == EVP_CSHAKE128)  || ((id) == EVP_CSHAKE256))

#define EVP_IS_XOF(id)    (((id) & 0xF0000000) == EVP_CAT_XOF)
#define EVP_IS_MAC(id)    (((id) & 0xF0000000) == EVP_CAT_MAC)

// ======================
// 2. HMAC / KMAC Flags
// ======================
typedef enum {
    EVP_HMAC       = EVP_CAT_MAC | 0x0001,
    EVP_KMAC128    = EVP_CAT_MAC | 0x0002,
    EVP_KMAC256    = EVP_CAT_MAC | 0x0003,
    EVP_KMACXOF128 = EVP_CAT_MAC | 0x0004,
    EVP_KMACXOF256 = EVP_CAT_MAC | 0x0005
} EVP_MAC;

// ======================
// 3. RNG / DRBG Flags
// ======================
typedef enum {
    EVP_PRNG_XORSHIFT   = EVP_CAT_RNG | 0x0001,
    EVP_PRNG_PCG        = EVP_CAT_RNG | 0x0002,
    EVP_DRBG_SHA        = EVP_CAT_RNG | 0x0004,
    EVP_SEED_USER       = EVP_CAT_RNG | 0x0008
} EVP_RNG;

// ======================
// 4. Encoding / Decoding Flags
// ======================
typedef enum {
    EVP_ENC_HEX      = 0x00010000,
    EVP_DEC_HEX      = 0x00020000,
    EVP_ENC_BASE64   = 0x00040000,
    EVP_DEC_BASE64   = 0x00080000,
    EVP_ENC_BASE32   = 0x00100000,
    EVP_DEC_BASE32   = 0x00200000
} EVP_Encoding;

// ======================
// 5. Cipher Flags
// ======================

// Cipher types
typedef enum {
    EVP_AES_128  = 0x00000001,
    EVP_AES_192  = 0x00000002,
    EVP_AES_256  = 0x00000004,
    EVP_CHACHA20 = 0x00000008
} EVP_CipherType;

// Cipher modes
typedef enum {
    EVP_MODE_CBC = 0x00000100,
    EVP_MODE_CTR = 0x00000200,
    EVP_MODE_GCM = 0x00000400,
    EVP_MODE_CFB = 0x00000800,
    EVP_MODE_OFB = 0x00001000
} EVP_CipherMode;

// Padding / KDF (upper 32 bits)
typedef enum {
    EVP_PADDING_PKCS7 = 0x000100000000ULL,
    EVP_PADDING_ZERO  = 0x000200000000ULL,
    EVP_KDF_PBKDF2    = 0x000400000000ULL,
    EVP_KDF_HKDF      = 0x000800000000ULL
} EVP_CipherOption;

#endif // EVP_FLAGS_H