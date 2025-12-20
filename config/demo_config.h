/*
 * CryptoForge - demo_config.h / Demo and Test Configuration
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

#ifndef DEMO_CONFIG_H
#define DEMO_CONFIG_H

#include "crypto_config.h"  // include high-level flags
#include "../utils/cf_status.h"
#include "../utils/misc_utils.h"

#if ENABLE_TESTS  // only include/demo code if tests are enabled

#include "../crypto/hash/sha/keccak/shake.h"

#include "../crypto/mac/hmac.h"
#include "../crypto/mac/kmac.h"
#include "../crypto/kdf/hkdf.h"
#include "../crypto/enc/base16.h"
#include "../crypto/enc/base32.h"
#include "../crypto/enc/base58.h"
#include "../crypto/enc/base64.h"
#include "../crypto/enc/base85.h"

#include "../crypto/cipher/aes/aes_core.h"
#include "../crypto/cipher/aes/ecb_mode.h"
#include "../crypto/cipher/aes/cbc_mode.h"
#include "../crypto/cipher/aes/cfb_mode.h"
#include "../crypto/cipher/aes/ofb_mode.h"
#include "../crypto/cipher/aes/ctr_mode.h"
#include "../crypto/cipher/aes/gcm_mode.h"

#include "../crypto/evp/evp_defs.h"
#include "../crypto/evp/evp_flags.h"
#include "../crypto/evp/evp_hash.h"
#include "../crypto/evp/evp_enc.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct _DEMO_ENC_TEST{
    uint32_t enc;
    uint32_t dec;
    const char *desc;
} DEMO_ENC_TEST;

// Utility to print a digest in hex
FORCE_INLINE void DEMO_print_hex(const uint8_t *digest, size_t size) {
    for (size_t i = 0; i < size; i++)
        printf("%02x", digest[i]);
    printf("\n");
}

FORCE_INLINE void DEMO_print_str(const char *label, const char *data, size_t len) {
    printf("%s: \"", label);
    for (size_t i = 0; i < len; i++)
        putchar(data[i]);
    printf("\"\n");
}

// Test helper (for dev)
CF_API void test_all_hashes(const uint8_t *input, size_t input_len, const EVP_XOF_OPTS *opts);

CF_API void test_all_hashes_high(const uint8_t *input, size_t input_len, const EVP_XOF_OPTS *opts);

CF_API void test_all_hmacs(const uint8_t *key, size_t key_len, const uint8_t *input, size_t input_len);

CF_API void test_all_kmacs(
    const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len,
    const uint8_t *S, size_t S_len);

CF_API void test_all_hkdfs(
    const uint8_t *info, size_t info_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    size_t okm_len);

CF_API void test_base16(const char *label, const uint8_t *input, size_t len, uint32_t mode);
CF_API void test_hex_base16(const char *label, const uint8_t *input, size_t len, uint32_t mode);

CF_API void test_base32(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mod);
CF_API void test_hex_base32(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mod);

CF_API void test_base58(const char *label, const uint8_t *input, size_t len);
CF_API void test_hex_base58(const char *label, const uint8_t *input, size_t len);

CF_API void test_base64(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mode);
CF_API void test_hex_base64(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mode);

CF_API void test_base85(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mode);
CF_API void test_hex_base85(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mode);

CF_API void test_all_encoders_high(const uint8_t *input, size_t input_len);

CF_API void test_aes128_fips197(void);
CF_API void test_aes192_fips197(void);
CF_API void test_aes256_fips197(void);

CF_API void test_aes_ecb_fist800_38a(void);
CF_API void test_aes_cbc_fips800_38a(void);
CF_API void test_aes_cfb8_fips800_38a(void);
CF_API void test_aes_cfb128_fips800_38a(void);
CF_API void test_aes_ofb_fips800_38a(void);
CF_API void test_aes_ctr_fips800_38a(void);

void process_rsp_file(const char *filepath);

#ifdef __cplusplus
}
#endif

#endif // ENABLE_TESTS

#endif // DEMO_CONFIG_H
