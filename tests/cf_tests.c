#include "../src/internal/config/test_config.h"

int main(void) {

#if ENABLE_TESTS
    printf("------------------------------------------------------------\n");
    printf("CryptoForge Version %s Test Suite\n", CRYPTOFORGE_VERSION_STR);
    printf("------------------------------------------------------------\n");

    /* Run bulk tests */
    printf("NIST KAT Tests:\n");
    test_shake128_kat();
    test_shake256_kat();
    putchar('\n');

    test_aes_ecb_kat();
    test_aes_cbc_kat();
    test_aes_cfb8_kat();
    test_aes_cfb128_kat();
    test_aes_ofb_kat();

    printf("Wycheproof Tests:\n");
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
    putchar('\n');

    test_kmac128_no_customization_wycheproof();
    test_kmac256_no_customization_wycheproof();
    putchar('\n');

    test_aes_cmac_wycheproof();
    test_aes_gmac_wycheproof();
    putchar('\n');

    test_hkdf_sha1_wycheproof();
    test_hkdf_sha256_wycheproof();
    test_hkdf_sha384_wycheproof();
    test_hkdf_sha512_wycheproof();
    putchar('\n');

    test_pbkdf2_hmac_sha1_wycheproof();
    test_pbkdf2_hmac_sha224_wycheproof();
    test_pbkdf2_hmac_sha256_wycheproof();
    test_pbkdf2_hmac_sha384_wycheproof();
    test_pbkdf2_hmac_sha512_wycheproof();
    putchar('\n');

    test_aes_cbc_pkcs7_wycheproof();
    test_aes_gcm_wycheproof();
    putchar('\n');

    test_chacha20_poly1305_wycheproof();
    test_xchacha20_poly1305_wycheproof();
    putchar('\n');

    /* API smoke tests */
    printf("API smoke test:\n");
    cf_encoder_api_test();
    cf_hash_api_test();
    cf_mac_api_test();
    cf_kdf_api_test();
    cf_cipher_api_test();
    cf_aead_api_test();
    putchar('\n');

    /* Print missing in bulk tests */
    printf("------------------------------------------------------------\n");
    printf("Algorithms working but missing dedicated in bulk tests:\n");

    /* Hashes */
    printf(" * MD5\n");
    printf(" * SHA1\n");
    printf(" * SHA224\n");
    printf(" * SHA256\n");
    printf(" * SHA384\n");
    printf(" * SHA512\n");
    printf(" * SHA512_224\n");
    printf(" * SHA512_256\n");
    printf(" * SHA3-224\n");
    printf(" * SHA3-256\n");
    printf(" * SHA3-384\n");
    printf(" * SHA3-512\n");
    printf(" * rawSHAKE128\n");
    printf(" * rawSHAKE256\n");
    printf(" * cSHAKE128\n");
    printf(" * cSHAKE256\n");

    /* MACs */
    printf(" * HMAC-MD5\n");
    printf(" * KMAC128\n");
    printf(" * KMAC256\n");
    printf(" * KMAC128-XOF\n");
    printf(" * KMAC256-XOF\n");
    printf(" * Poly1305\n");

    /* KDFs */
    printf(" * HKDF-MD5\n");
    printf(" * HKDF-SHA512/224\n");
    printf(" * HKDF-SHA512/256\n");
    printf(" * HKDF-SHA3-224\n");
    printf(" * HKDF-SHA3-256\n");
    printf(" * HKDF-SHA3-512\n");
    printf(" * PBKDF2-MD5\n");
    printf(" * PBKDF2-SHA512/224\n");
    printf(" * PBKDF2-SHA512/256\n");
    printf(" * PBKDF2-SHA3-224\n");
    printf(" * PBKDF2-SHA3-256\n");
    printf(" * PBKDF2-SHA3-512\n");
    printf(" * KMAC-XOF-128\n");
    printf(" * KMAC-XOF-256\n");

    /* Symmetric Ciphers */
    printf(" * AES-CTR\n");
    printf(" * ChaCha8\n");
    printf(" * ChaCha12\n");
    printf(" * ChaCha20\n");
    printf(" * XChaCha8\n");
    printf(" * XChaCha12\n");
    printf(" * XChaCha20\n");

    printf("------------------------------------------------------------\n");
    printf("Test suite completed\n");
    printf("------------------------------------------------------------\n");

#endif // ENABLE_TESTS

    return 0;
}