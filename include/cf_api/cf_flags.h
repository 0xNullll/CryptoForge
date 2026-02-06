/*
 * CryptoForge -  cf_flags.h / CryptoForge API (hash, MAC, RNG, and encoding) flags and definitions
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

#ifndef CF_FLAGS_H
#define CF_FLAGS_H

#include "../config/crypto_config.h"

#define CF_MAX_HASH_CTX_SIZE 512                         // bytes
#define CF_MAX_KEY_SIZE MAX_KEY_SIZE                     // bytes
#define CF_MAX_CUSTOMIZATION MAX_CUSTOMIZATION           // bytes
#define CF_MAX_ENCODED_HEADER_LEN MAX_ENCODED_HEADER_LEN // bytes

// ======================
// Maximum default sizes
// ======================
#define CF_MAX_DEFAULT_BLOCK_SIZE 168  // SHAKE
#define CF_MAX_DEFAULT_DIGEST_SIZE 64  // SHA512 / SHA3-512

// ======================
// Block / Digest Sizes
// ======================
typedef enum {
    // MD5
    CF_MD5_BLOCK_SIZE        = 64,
    // SHA1
    CF_SHA1_BLOCK_SIZE       = 64,
    // SHA2 family
    CF_SHA224_BLOCK_SIZE     = 64,
    CF_SHA256_BLOCK_SIZE     = 64,
    CF_SHA384_BLOCK_SIZE     = 128,
    CF_SHA512_BLOCK_SIZE     = 128,
    CF_SHA512_224_BLOCK_SIZE = 128,
    CF_SHA512_256_BLOCK_SIZE = 128,
    // SHA3 family
    CF_SHA3_224_BLOCK_SIZE   = 144,
    CF_SHA3_256_BLOCK_SIZE   = 136,
    CF_SHA3_384_BLOCK_SIZE   = 104,
    CF_SHA3_512_BLOCK_SIZE   = 72,
    // SHAKE / RawSHAKE
    CF_SHAKE128_BLOCK_SIZE    = 168,
    CF_SHAKE256_BLOCK_SIZE    = 136,
    CF_RAWSHAKE128_BLOCK_SIZE = 168,
    CF_RAWSHAKE256_BLOCK_SIZE = 136,
    // cSHAKE
    CF_CSHAKE128_BLOCK_SIZE   = 168,
    CF_CSHAKE256_BLOCK_SIZE   = 136
} CF_BlockSize;

// ======================
// Digest / Output Sizes (bytes)
// ======================
typedef enum {
    // MD5
    CF_MD5_DIGEST_SIZE        = 16,
    // SHA1
    CF_SHA1_DIGEST_SIZE       = 20,
    // SHA2 family
    CF_SHA224_DIGEST_SIZE     = 28,
    CF_SHA256_DIGEST_SIZE     = 32,
    CF_SHA384_DIGEST_SIZE     = 48,
    CF_SHA512_DIGEST_SIZE     = 64,
    CF_SHA512_224_DIGEST_SIZE = 28,
    CF_SHA512_256_DIGEST_SIZE = 32,
    // SHA3 family
    CF_SHA3_224_DIGEST_SIZE   = 28,
    CF_SHA3_256_DIGEST_SIZE   = 32,
    CF_SHA3_384_DIGEST_SIZE   = 48,
    CF_SHA3_512_DIGEST_SIZE   = 64,
} CF_DigestSize;

// ======================
// Default Digest Sizes for XOFs (bytes)
// ======================
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
} CF_DigestDefaultSize;

// ======================
// 1. Hash / Digest IDs & Flags
// ======================
typedef enum {
    CF_CAT_DIGEST  = 0x00000000, // MD5, SHA1, SHA2, SHA3
    CF_CAT_XOF     = 0x10000000, // SHAKE / cSHAKE / RAWXOF
    CF_CAT_MAC     = 0x20000000, // HMAC / KMAC
    CF_CAT_RNG     = 0x40000000,
    CF_CAT_KECCAK  = 0x08000000  // optional bit to group KECCAK-based algorithms
} CF_Category;

typedef enum {
    CF_MD5         = CF_CAT_DIGEST  | 0x0001,
    CF_SHA1        = CF_CAT_DIGEST  | 0x0002,
    CF_SHA224      = CF_CAT_DIGEST  | 0x0003,
    CF_SHA256      = CF_CAT_DIGEST  | 0x0004,
    CF_SHA384      = CF_CAT_DIGEST  | 0x0005,
    CF_SHA512      = CF_CAT_DIGEST  | 0x0006,
    CF_SHA512_224  = CF_CAT_DIGEST  | 0x0007,
    CF_SHA512_256  = CF_CAT_DIGEST  | 0x0008,

    CF_SHA3_224    = CF_CAT_DIGEST | CF_CAT_KECCAK | 0x0010,
    CF_SHA3_256    = CF_CAT_DIGEST | CF_CAT_KECCAK | 0x0011,
    CF_SHA3_384    = CF_CAT_DIGEST | CF_CAT_KECCAK | 0x0012,
    CF_SHA3_512    = CF_CAT_DIGEST | CF_CAT_KECCAK | 0x0013,

    CF_SHAKE128    = CF_CAT_DIGEST | CF_CAT_XOF | 0x0010,
    CF_SHAKE256    = CF_CAT_DIGEST | CF_CAT_XOF | 0x0011,
    CF_RAWSHAKE128 = CF_CAT_DIGEST | CF_CAT_XOF | 0x0020,
    CF_RAWSHAKE256 = CF_CAT_DIGEST | CF_CAT_XOF | 0x0021,
    CF_CSHAKE128   = CF_CAT_DIGEST | CF_CAT_XOF | 0x0030,
    CF_CSHAKE256   = CF_CAT_DIGEST | CF_CAT_XOF | 0x0031
} CF_Algorithm;

typedef enum {
    CF_KMAC128      = 0x100,
    CF_KMAC256      = 0x200,
    CF_KMAC_XOF128  = 0x300,
    CF_KMAC_XOF256  = 0x400
} CF_KMAC_TYPE;

// ======================
// Helper macros
// ======================
#define CF_IS_DIGEST(id)  (((id) & 0xF0000000) == CF_CAT_DIGEST)
#define CF_IS_XOF(id)     (((id) & 0xF0000000) == CF_CAT_XOF)
#define CF_IS_MAC(id)     (((id) & 0xF0000000) == CF_CAT_MAC)
#define CF_IS_KECCAK(id) \
    ((id) == CF_SHA3_224    || (id) == CF_SHA3_256   || \
     (id) == CF_SHA3_384    || (id) == CF_SHA3_512   || \
     (id) == CF_SHAKE128    || (id) == CF_SHAKE256   || \
     (id) == CF_RAWSHAKE128 || (id) == CF_RAWSHAKE256|| \
     (id) == CF_CSHAKE128   || (id) == CF_CSHAKE256)

// ======================
// MAC flags / subflags
// ======================
#define CF_MAC_FLAG_MASK    0xFFFFF000
#define CF_MAC_SUBFLAG_MASK 0x00000FFF
#define CF_MAC_XOF_FLAG     0x00100000
#define CF_MAC_HASH_MASK    0x000000FF
#define CF_MAC_KMAC_MASK    0x00000F00

typedef enum {
    CF_HMAC     = CF_CAT_MAC | 0x1000, // subflags: hash ID
    CF_KMAC     = CF_CAT_MAC | 0x2000, // subflags: KMAC type
    CF_CMAC     = CF_CAT_MAC | 0x3000, // no subflags
    CF_GMAC     = CF_CAT_MAC | 0x4000, // no subflags
    CF_POLY1305 = CF_CAT_MAC | 0x5000  // no subflags
} CF_MAC_FLAGS;

#define CF_MAC_IS_HMAC(id)      (((id) & CF_MAC_FLAG_MASK) == CF_HMAC)
#define CF_MAC_IS_KMAC(id)      (((id) & CF_MAC_FLAG_MASK) == CF_KMAC)
#define CF_MAC_IS_CMAC(id)      (((id) & CF_MAC_FLAG_MASK) == CF_CMAC)
#define CF_MAC_IS_GMAC(id)      (((id) & CF_MAC_FLAG_MASK) == CF_GMAC)
#define CF_MAC_IS_POLY1305(id)  (((id) & CF_MAC_FLAG_MASK) == CF_POLY1305)
#define CF_MAC_IS_XOF(id)       (((id) & CF_MAC_XOF_FLAG) != 0)
#define CF_MAC_GET_HASH(id)     ((id) & CF_MAC_HASH_MASK)

// ======================
// 3. RNG / DRBG Flags
// ======================
typedef enum {
    CF_PRNG_XORSHIFT   = CF_CAT_RNG | 0x0001,
    CF_PRNG_PCG        = CF_CAT_RNG | 0x0002,
    CF_DRBG_SHA        = CF_CAT_RNG | 0x0004,
    CF_SEED_USER       = CF_CAT_RNG | 0x0008
} CF_RNG_FLAGS;

// ======================
// 4. Encoding / Decoding Flags
// ======================

typedef enum {
    // --- Base16 / Hex ---
    CF_BASE16_UPPER       = 0x01,  // '0'-'9','A'-'F'
    CF_BASE16_LOWER       = 0x02,  // '0'-'9','a'-'f'
    CF_BASE16_DEC         = 0x04,

    // --- Base32 ---
    CF_BASE32_ENC         = 0x10,
    CF_BASE32_DEC         = 0x20,
    CF_BASE32_ENC_NOPAD   = 0x40,
    CF_BASE32_DEC_NOPAD   = 0x80,

    // --- Base58 ---
    CF_BASE58_ENC         = 0x100,
    CF_BASE58_DEC         = 0x200,

    // --- Base64 ---
    CF_BASE64_STD_ENC        = 0x400,
    CF_BASE64_STD_DEC        = 0x800,
    CF_BASE64_URL_ENC        = 0x1000,
    CF_BASE64_URL_DEC        = 0x2000,
    CF_BASE64_NOPAD_ENC      = 0x4000,
    CF_BASE64_NOPAD_DEC      = 0x8000,

    // --- Base85 variants ---
    CF_BASE85_STD_ENC     = 0x10000,   // Standard ASCII85 ('z' supported)
    CF_BASE85_STD_DEC     = 0x20000,
    CF_BASE85_EXT_ENC     = 0x40000,   // Extended ASCII85 ('y' optional)
    CF_BASE85_EXT_DEC     = 0x80000,
    CF_BASE85_Z85_ENC     = 0x100000,  // Z85 variant (no z/y, different charset)
    CF_BASE85_Z85_DEC     = 0x200000,
    CF_BASE85_IGNORE_WS   = 0x400000   // Ignore white spaces
} CF_ENCODING_FLAGS;

// Helper macros for category checks

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

#define CF_BASE16_MASK 0x07      // 0b00000111
#define CF_BASE32_MASK 0xF0      // 0b11110000
#define CF_BASE58_MASK 0x300     // 0b001100000000
#define CF_BASE64_MASK 0xFC00    // 0b11111100000000
#define CF_BASE85_MASK 0x7F0000  // 0b0111111100000000000000

// ======================
// 5. Cipher Flags
// ======================

#define CF_IS_AES_KEY_VALID(len) \
    ((len) == AES_128_KEY_SIZE || \
     (len) == AES_192_KEY_SIZE || \
     (len) == AES_256_KEY_SIZE)

// Cipher types
typedef enum {
    CF_AES_128  = 0x00000001,
    CF_AES_192  = 0x00000002,
    CF_AES_256  = 0x00000004,
    CF_CHACHA20 = 0x00000008
} CF_CIPHER_TYPE_FLAGS;

// Cipher modes
typedef enum {
    CF_MODE_CBC = 0x00000100,
    CF_MODE_CTR = 0x00000200,
    CF_MODE_GCM = 0x00000400,
    CF_MODE_CFB = 0x00000800,
    CF_MODE_OFB = 0x00001000
} CF_CIPHER_MODE__FLAGS;

// Padding / KDF (upper 32 bits)
#define CF_PADDING_PKCS7 0x000100000000ULL
#define CF_PADDING_ZERO  0x000200000000ULL
#define CF_KDF_PBKDF2    0x000400000000ULL
#define CF_KDF_HKDF      0x000800000000ULL

// typedef enum {
//     CF_PADDING_PKCS7 = 0x000100000000ULL,
//     CF_PADDING_ZERO  = 0x000200000000ULL,
//     CF_KDF_PBKDF2    = 0x000400000000ULL,
//     CF_KDF_HKDF      = 0x000800000000ULL
// } CF_CipherOption;

#endif // CF_FLAGS_H