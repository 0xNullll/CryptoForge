/*
 * CryptoForge - cf_flags.h / CryptoForge API flags and definitions (hash, MAC, KDF, RNG, encoding, cipher)
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef CF_FLAGS_H
#define CF_FLAGS_H

#include "../config/crypto_config.h"

/* Maximum context / key / IV / buffer sizes */
#define CF_MAX_HASH_CTX_SIZE         512 // safe max
#define CF_MAX_KEY_SIZE              MAX_KEY_SIZE
#define CF_MAX_CUSTOMIZATION         MAX_CUSTOMIZATION
#define CF_MAX_ENCODED_HEADER_LEN    MAX_ENCODED_HEADER_LEN
#define CF_MAX_CIPHER_IV_SIZE        XCHACHA_EXTENDED_IV_SIZE
#define CF_CIPHER_MAX_BLOCK_SIZE     AES_BLOCK_SIZE

#define CF_MAX_DEFAULT_HASH_BLOCK_SIZE 168
#define CF_MAX_DEFAULT_DIGEST_SIZE     64

// ======================
// Digest / Hash Sizes
// ======================

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

// ======================
// Digest / Hash IDs
// ======================

typedef enum {
    CF_CAT_DIGEST  = 0x00000000, // Standard digest algorithms
    CF_CAT_XOF     = 0x10000000, // SHAKE / cSHAKE / RawXOF
    CF_CAT_MAC     = 0x20000000, // MAC algorithms: HMAC, CMAC, GMAC, Poly1305
    CF_CAT_KDF     = 0x30000000, // Key derivation algorithms: HKDF, PBKDF2, KMAC-XOF
    CF_CAT_KECCAK  = 0x08000000  // KECCAK-based family marker
} CF_CATEGORY;

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
    CF_SHA3_224    = CF_CAT_DIGEST | CF_CAT_KECCAK | 0x0010,
    CF_SHA3_256    = CF_CAT_DIGEST | CF_CAT_KECCAK | 0x0011,
    CF_SHA3_384    = CF_CAT_DIGEST | CF_CAT_KECCAK | 0x0012,
    CF_SHA3_512    = CF_CAT_DIGEST | CF_CAT_KECCAK | 0x0013,

    /* XOFs */
    CF_SHAKE128    = CF_CAT_DIGEST | CF_CAT_XOF | 0x0010,
    CF_SHAKE256    = CF_CAT_DIGEST | CF_CAT_XOF | 0x0011,
    CF_RAWSHAKE128 = CF_CAT_DIGEST | CF_CAT_XOF | 0x0020,
    CF_RAWSHAKE256 = CF_CAT_DIGEST | CF_CAT_XOF | 0x0021,
    CF_CSHAKE128   = CF_CAT_DIGEST | CF_CAT_XOF | 0x0030,
    CF_CSHAKE256   = CF_CAT_DIGEST | CF_CAT_XOF | 0x0031
} CF_HASH_FLAGS;

typedef enum {
    CF_KMAC128      = 0x100,
    CF_KMAC256      = 0x200,
    CF_KMAC_XOF128  = 0x300,
    CF_KMAC_XOF256  = 0x400
} CF_KMAC_TYPE_FLAGS;

// ======================
// Digest / MAC helper macros
// ======================
#define CF_IS_DIGEST(id)   (((id) & 0xF0000000) == CF_CAT_DIGEST)
#define CF_IS_XOF(id)      (((id) & 0xF0000000) == CF_CAT_XOF)
#define CF_IS_MAC(id)      (((id) & 0xF0000000) == CF_CAT_MAC)
#define CF_IS_KMAC_XOF(id) ((id) == CF_KMAC_XOF128 || (id) == CF_KMAC_XOF256)
#define CF_IS_KECCAK(id) \
    ((id) == CF_SHA3_224    || (id) == CF_SHA3_256   || \
     (id) == CF_SHA3_384    || (id) == CF_SHA3_512   || \
     (id) == CF_SHAKE128    || (id) == CF_SHAKE256   || \
     (id) == CF_RAWSHAKE128 || (id) == CF_RAWSHAKE256|| \
     (id) == CF_CSHAKE128   || (id) == CF_CSHAKE256)


// ======================
// MAC Flags
// ======================
#define CF_MAC_FLAG_MASK    0xFFFFF000
#define CF_MAC_SUBFLAG_MASK 0x00000FFF
#define CF_XOF_MASK         0x00100000
#define CF_HASH_MASK        0x000000FF
#define CF_MAC_KMAC_MASK    0x00000F00

typedef enum {
    CF_HMAC     = CF_CAT_MAC | 0x1000, // HMAC with hash subflags
    CF_KMAC_STD = CF_CAT_MAC | 0x2000, // KMAC standard with type subflags
    CF_CMAC     = CF_CAT_MAC | 0x3000, // CMAC standard
    CF_GMAC     = CF_CAT_MAC | 0x4000, // GMAC standard
    CF_POLY1305 = CF_CAT_MAC | 0x5000  // Poly1305 standard
} CF_MAC_FLAGS;

#define CF_MAC_IS_HMAC(id)      (((id) & CF_MAC_FLAG_MASK) == CF_HMAC)
#define CF_MAC_IS_KMAC_STD(id)  (((id) & CF_MAC_FLAG_MASK) == CF_KMAC_STD)
#define CF_MAC_IS_KMAC_XOF(id)  (((id) & CF_MAC_FLAG_MASK ) == CF_KMAC_XOF)
#define CF_MAC_IS_CMAC(id)      (((id) & CF_MAC_FLAG_MASK) == CF_CMAC)
#define CF_MAC_IS_GMAC(id)      (((id) & CF_MAC_FLAG_MASK) == CF_GMAC)
#define CF_MAC_IS_POLY1305(id)  (((id) & CF_MAC_FLAG_MASK) == CF_POLY1305)
#define CF_MAC_IS_XOF(id)       (((id) & CF_XOF_MASK) != 0)
#define CF_MAC_GET_HASH(id)     ((id) & CF_HASH_MASK)

// ======================
// KDF IDs
// ======================
typedef enum {
    CF_HKDF         = CF_CAT_KDF | 0x1000, // HKDF with hash subflags
    CF_PBKDF2       = CF_CAT_KDF | 0x2000, // PBKDF2 with hash subflags
    CF_KMAC_XOF     = CF_CAT_KDF | 0x3000  // KMAC-XOF type
} CF_KDF_FLAGS;

#define CF_IS_KDF(id)          (((id) & 0xF0000000) == CF_CAT_KDF)
#define CF_KDF_IS_PBKDF2(id)    ((id) == CF_HKDF)
#define CF_KDF_IS_HKDF(id)      ((id) == CF_PBKDF2)
#define CF_KDF_IS_KMAC_XOF(id)  ((id) == CF_KMAC_XOF)

// ======================
// Encoding / Decoding Flags
// ======================
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

// ======================
// Cipher Families
// ======================
typedef enum {
    CF_OP_DECRYPT = 0,
    CF_OP_ENCRYPT = 1
} CF_OPERATION;

typedef enum {
    CF_CAT_AES    = 0x00010000, // AES family
    CF_CAT_CHACHA = 0x00020000, // ChaCha family
    CF_CAT_AEAD   = 0x00040000  // AEAD family
} CF_CIPHER_CATEGORY;

// ======================
// AES / ChaCha Mode Flags
// ======================
typedef enum {
    /* AES Block Cipher Modes */
    CF_AES_ECB    = CF_CAT_AES | 0x0001,
    CF_AES_CBC    = CF_CAT_AES | 0x0002,
    CF_AES_OFB    = CF_CAT_AES | 0x0004,
    CF_AES_CFB8   = CF_CAT_AES | 0x0008,
    CF_AES_CFB128 = CF_CAT_AES | 0x0010,
    CF_AES_CTR    = CF_CAT_AES | 0x0020,

    /* ChaCha Stream Cipher Modes */
    CF_CHACHA8    = CF_CAT_CHACHA | 0x0001,
    CF_CHACHA12   = CF_CAT_CHACHA | 0x0002,
    CF_CHACHA20   = CF_CAT_CHACHA | 0x0004,
    CF_XCHACHA8   = CF_CAT_CHACHA | 0x0008,
    CF_XCHACHA12  = CF_CAT_CHACHA | 0x0010,
    CF_XCHACHA20  = CF_CAT_CHACHA | 0x0020
} CF_CIPHER_MODE_FLAGS;

// ======================
// AEAD Mode Flags (split AES vs ChaCha families)
// ======================
typedef enum {
    /* AES-GCM Modes */
    CF_AEAD_AES_GCM_128 = CF_CAT_AEAD | 0x0001,  // AES-GCM 128-bit key
    CF_AEAD_AES_GCM_192 = CF_CAT_AEAD | 0x0002,  // AES-GCM 192-bit key
    CF_AEAD_AES_GCM_256 = CF_CAT_AEAD | 0x0004,  // AES-GCM 256-bit key

    /* ChaCha20-Poly1305 Modes */
    CF_AEAD_CHACHA20_POLY1305  = CF_CAT_AEAD | 0x0010, // ChaCha20-Poly1305
    CF_AEAD_XCHACHA20_POLY1305 = CF_CAT_AEAD | 0x0020  // XChaCha20-Poly1305
} CF_AEAD_MODE_FLAGS;

// ======================
// Masks & helpers
// ======================
#define CF_CIPHER_FAMILY_MASK 0xFFFF0000
#define CF_CIPHER_MODE_MASK   0x0000FFFF

#define CF_IS_CIPHER(mode)     (((mode) & CF_CIPHER_FAMILY_MASK) == CF_CAT_AES || \
                                ((mode) & CF_CIPHER_FAMILY_MASK) == CF_CAT_CHACHA)

#define CF_IS_AES(mode)         (((mode) & CF_CIPHER_FAMILY_MASK) == CF_CAT_AES)
#define CF_IS_CHACHA(mode)      (((mode) & CF_CIPHER_FAMILY_MASK) == CF_CAT_CHACHA)
#define CF_IS_AEAD(mode)        (((mode) & CF_CIPHER_FAMILY_MASK) == CF_CAT_AEAD)

#define CF_IS_AES_AEAD(mode)    (CF_IS_AEAD(mode) && ((mode) & 0x00F0) == 0x0000)
#define CF_IS_CHACHA_AEAD(mode) (CF_IS_AEAD(mode) && ((mode) & 0x00F0) != 0x0000)

#define CF_GET_MODE(mode)       ((mode) & CF_CIPHER_MODE_MASK)

// ======================
// AES / ChaCha Key Sizes
// ======================
typedef enum {
    CF_KEY_128_SIZE = 16,
    CF_KEY_192_SIZE = 24,
    CF_KEY_256_SIZE = 32
} CF_KEY_SIZE;

#define CF_IS_AES_KEY_VALID(len) \
    ((len) == CF_KEY_128_SIZE || (len) == CF_KEY_192_SIZE || (len) == CF_KEY_256_SIZE)

#define CF_IS_CHACHA_KEY_VALID(len) \
    ((len) == CF_KEY_128_SIZE || (len) == CF_KEY_256_SIZE)

// ======================
// Padding
// ======================
typedef enum {
    CF_PAD_PKCS7,
    CF_PAD_ISO7816_4,
    CF_PAD_X923
} CF_PADDING_TYPE;

#define CF_CTX_MAGIC 0x43464D47  // "CFMG"

#endif // CF_FLAGS_H