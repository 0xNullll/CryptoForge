/*
 * CryptoForge - demo_config.h / Demo and Test Configuration
 * Copyright (C) 2025 0xNullll
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

#ifndef DEMO_CONFIG_H
#define DEMO_CONFIG_H

#include "crypto_config.h"  // include high-level flags
#include "../utils/cf_status.h"
#include "../utils/misc.h"

#if ENABLE_TESTS  // only include/demo code if tests are enabled

#include "../crypto/shake.h"

#include "../crypto/hmac.h"
#include "../crypto/kmac.h"
#include "../crypto/gmac.h"
#include "../crypto/cmac.h"

#include "../crypto/hkdf.h"

#include "../crypto/base16.h"
#include "../crypto/base32.h"
#include "../crypto/base58.h"
#include "../crypto/base64.h"
#include "../crypto/base85.h"

#include "../crypto/aes_core.h"
#include "../crypto/ecb_mode.h"
#include "../crypto/cbc_mode.h"
#include "../crypto/cfb_mode.h"
#include "../crypto/ofb_mode.h"
#include "../crypto/ctr_mode.h"
#include "../crypto/gcm_mode.h"

#include "../cf_api/cf_defs.h"
#include "../cf_api/cf_flags.h"
#include "../cf_api/cf_hash.h"
#include "../cf_api/cf_mac.h"
#include "../cf_api/cf_enc.h"

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
CF_API void test_all_hashes(const uint8_t *input, size_t input_len, const CF_HASH_OPTS *opts);
CF_API void test_all_hashes_high(const uint8_t *input, size_t input_len, const CF_HASH_OPTS *opts);

CF_API void test_all_hmacs(const uint8_t *key, size_t key_len, const uint8_t *input, size_t input_len);
CF_API void test_all_kmacs(
    const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len,
    const uint8_t *S, size_t S_len);
CF_API void test_all_kmacs_verify_array(const uint8_t *key, size_t key_len,
                                 const uint8_t *input, size_t input_len,
                                 const uint8_t *S, size_t S_len,
                                 const uint8_t *expected_digests[4]);
CF_API void test_all_gmacs(void);
CF_API void test_aes_cmac_fips800_38b(void);
CF_API void test_all_macs_high(void);

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
CF_API void test_aes_gcm_fips_style(void);
CF_API void test_aes_gcm_empty_plaintext(void);

#ifdef __cplusplus
}
#endif

#endif // ENABLE_TESTS

#endif // DEMO_CONFIG_H