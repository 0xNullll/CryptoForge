#include "../src/include/config/test_config.h"

int main(void) {

#if ENABLE_TESTS
    cf_encoder_api_test();
    cf_hash_api_test();
    cf_mac_api_test();
    cf_kdf_api_test();
    cf_cipher_api_test();
    cf_aead_api_test();

    test_aes_ecb_kat();
    test_aes_cbc_kat();
    test_aes_cfb8_kat();
    test_aes_cfb128_kat();
    test_aes_ofb_kat();

    test_aes_cbc_pkcs7_wycheproof();

    test_hmac_sha1_wycheproof();
    test_hmac_sha224_wycheproof();
    test_hmac_sha256_wycheproof();
    test_hmac_sha384_wycheproof();
    test_hmac_sha512_wycheproof();
    test_hmac_sha512_224_wycheproof(); 
    test_hmac_sha512_256_wycheproof();
    test_hmac_sha3_224_wycheproof();
    test_hmac_sha3_256_wycheproof();
    test_hmac_sha3_384_wycheproof();
    test_hmac_sha3_512_wycheproof();
    test_kmac128_no_customization_wycheproof();
    test_kmac256_no_customization_wycheproof();
    test_aes_cmac_wycheproof();
    test_aes_gmac_wycheproof();
    test_hkdf_sha1_wycheproof();
    test_hkdf_sha256_wycheproof();
    test_hkdf_sha384_wycheproof();
    test_hkdf_sha512_wycheproof();
    test_pbkdf2_hmac_sha1_wycheproof();
    test_pbkdf2_hmac_sha224_wycheproof();
    test_pbkdf2_hmac_sha256_wycheproof();
    test_pbkdf2_hmac_sha384_wycheproof();
    test_pbkdf2_hmac_sha512_wycheproof();
    test_aes_gcm_wycheproof();
    test_chacha20_poly1305_wycheproof();
    test_xchacha20_poly1305_wycheproof();

#endif // ENABLE_TESTS

    return 0;
}