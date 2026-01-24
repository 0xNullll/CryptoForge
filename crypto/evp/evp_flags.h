/*
 * CryptoForge -  evp_flags.h / EVP (hash, MAC, RNG, and encoding) flags and definitions
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
    // --- Base16 / Hex ---
    EVP_BASE16_UPPER       = 0x01,  // '0'-'9','A'-'F'
    EVP_BASE16_LOWER       = 0x02,  // '0'-'9','a'-'f'
    EVP_BASE16_DEC         = 0x04,

    // --- Base32 ---
    EVP_BASE32_ENC         = 0x10,
    EVP_BASE32_DEC         = 0x20,
    EVP_BASE32_ENC_NOPAD   = 0x40,
    EVP_BASE32_DEC_NOPAD   = 0x80,

    // --- Base58 ---
    EVP_BASE58_ENC         = 0x100,
    EVP_BASE58_DEC         = 0x200,

    // --- Base64 ---
    EVP_BASE64_STD_ENC        = 0x400,
    EVP_BASE64_STD_DEC        = 0x800,
    EVP_BASE64_URL_ENC        = 0x1000,
    EVP_BASE64_URL_DEC        = 0x2000,
    EVP_BASE64_NOPAD_ENC      = 0x4000,
    EVP_BASE64_NOPAD_DEC      = 0x8000,

    // --- Base85 variants ---
    EVP_BASE85_STD_ENC     = 0x10000,   // Standard ASCII85 ('z' supported)
    EVP_BASE85_STD_DEC     = 0x20000,
    EVP_BASE85_EXT_ENC     = 0x40000,   // Extended ASCII85 ('y' optional)
    EVP_BASE85_EXT_DEC     = 0x80000,
    EVP_BASE85_Z85_ENC     = 0x100000,  // Z85 variant (no z/y, different charset)
    EVP_BASE85_Z85_DEC     = 0x200000,
    EVP_BASE85_IGNORE_WS   = 0x400000   // Ignore white spaces
} EVP_Encoding;

// Helper macros for category checks

#define EVP_IS_ENC(v)   ((v) & ( \
        EVP_BASE16_UPPER | EVP_BASE16_LOWER | \
        EVP_BASE32_ENC | EVP_BASE32_ENC_NOPAD | \
        EVP_BASE58_ENC | \
        EVP_BASE64_STD_ENC | EVP_BASE64_URL_ENC | EVP_BASE64_NOPAD_ENC | \
        EVP_BASE85_STD_ENC | EVP_BASE85_EXT_ENC | EVP_BASE85_Z85_ENC ))

#define EVP_IS_DEC(v)   ((v) & ( \
        EVP_BASE16_DEC | \
        EVP_BASE32_DEC | EVP_BASE32_DEC_NOPAD | \
        EVP_BASE58_DEC | \
        EVP_BASE64_STD_DEC | EVP_BASE64_URL_DEC | EVP_BASE64_NOPAD_DEC | \
        EVP_BASE85_STD_DEC | EVP_BASE85_EXT_DEC | EVP_BASE85_Z85_DEC ))

#define EVP_BASE16_MASK 0x07      // 0b00000111
#define EVP_BASE32_MASK 0xF0      // 0b11110000
#define EVP_BASE58_MASK 0x300     // 0b001100000000
#define EVP_BASE64_MASK 0xFC00    // 0b11111100000000
#define EVP_BASE85_MASK 0x7F0000  // 0b0111111100000000000000

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
#define EVP_PADDING_PKCS7 0x000100000000ULL
#define EVP_PADDING_ZERO  0x000200000000ULL
#define EVP_KDF_PBKDF2    0x000400000000ULL
#define EVP_KDF_HKDF      0x000800000000ULL

// typedef enum {
//     EVP_PADDING_PKCS7 = 0x000100000000ULL,
//     EVP_PADDING_ZERO  = 0x000200000000ULL,
//     EVP_KDF_PBKDF2    = 0x000400000000ULL,
//     EVP_KDF_HKDF      = 0x000800000000ULL
// } EVP_CipherOption;

#endif // EVP_FLAGS_H