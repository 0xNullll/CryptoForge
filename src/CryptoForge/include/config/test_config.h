/*
 * CryptoForge - demo_config.h / Demo and Test Configuration
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TEST_CONFIG_H
#define TEST_CONFIG_H

#include "crypto_config.h"
#include "../utils/cf_status.h"
#include "../utils/misc.h"

#if ENABLE_TESTS

#include "../crypto/shake.h"

#include "../crypto/hmac.h"
#include "../crypto/kmac.h"
#include "../crypto/gmac.h"
#include "../crypto/cmac.h"

#include "../crypto/hkdf.h"
#include "../crypto/pbkdf2.h"

#include "../crypto/base16.h"
#include "../crypto/base32.h"
#include "../crypto/base58.h"
#include "../crypto/base64.h"
#include "../crypto/base85.h"

#include "../crypto/chacha.h"
#include "../crypto/xchacha.h"

#include "../crypto/aes_core.h"
#include "../crypto/ecb_mode.h"
#include "../crypto/cbc_mode.h"
#include "../crypto/cfb_mode.h"
#include "../crypto/ofb_mode.h"
#include "../crypto/ctr_mode.h"

#include "../crypto/chacha20_poly1305.h"
#include "../crypto/xchacha20_poly1305.h"
#include "../crypto/aes_gcm.h"


#include "../cf_api/cf_defs.h"
#include "../cf_api/cf_flags.h"
#include "../cf_api/cf_hash.h"
#include "../cf_api/cf_mac.h"
#include "../cf_api/cf_kdf.h"
#include "../cf_api/cf_cipher.h"
#include "../cf_api/cf_aead.h"
#include "../cf_api/cf_enc.h"

#ifdef __cplusplus
extern "C" {
#endif

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

CF_API void cf_encoder_api_test(void);
CF_API void cf_hash_api_test(void);
CF_API void cf_mac_api_test(void);
CF_API void cf_kdf_api_test(void);
CF_API void cf_cipher_api_test(void);
CF_API void cf_aead_api_test(void);

CF_API void test_aes_ecb_kat(void);
CF_API void test_aes_cbc_kat(void);
CF_API void test_aes_cfb8_kat(void);
CF_API void test_aes_cfb128_kat(void);
CF_API void test_aes_ofb_kat(void);

CF_API void test_hmac_sha1_wycheproof(void);
CF_API void test_hmac_sha224_wycheproof(void);
CF_API void test_hmac_sha256_wycheproof(void);
CF_API void test_hmac_sha384_wycheproof(void);
CF_API void test_hmac_sha512_wycheproof(void);
CF_API void test_hmac_sha512_224_wycheproof(void);
CF_API void test_hmac_sha512_256_wycheproof(void);
CF_API void test_hmac_sha3_224_wycheproof(void);
CF_API void test_hmac_sha3_256_wycheproof(void);
CF_API void test_hmac_sha3_384_wycheproof(void);
CF_API void test_hmac_sha3_512_wycheproof(void);
CF_API void test_kmac128_no_customization_wycheproof(void);
CF_API void test_kmac256_no_customization_wycheproof(void);
CF_API void test_aes_cmac_wycheproof(void);
CF_API void test_aes_gmac_wycheproof(void);
CF_API void test_hkdf_sha1_wycheproof(void);
CF_API void test_hkdf_sha256_wycheproof(void);
CF_API void test_hkdf_sha384_wycheproof(void);
CF_API void test_hkdf_sha512_wycheproof(void);
CF_API void test_pbkdf2_hmac_sha1_wycheproof(void);
CF_API void test_pbkdf2_hmac_sha224_wycheproof(void);
CF_API void test_pbkdf2_hmac_sha256_wycheproof(void);
CF_API void test_pbkdf2_hmac_sha384_wycheproof(void);
CF_API void test_pbkdf2_hmac_sha512_wycheproof(void);
CF_API void test_aes_cbc_pkcs7_wycheproof(void);
CF_API void test_aes_gcm_wycheproof(void);
CF_API void test_chacha20_poly1305_wycheproof(void);
CF_API void test_xchacha20_poly1305_wycheproof(void);

#ifdef __cplusplus
}
#endif

#endif // ENABLE_TESTS

#endif // TEST_CONFIG_H