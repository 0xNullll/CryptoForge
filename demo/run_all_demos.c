#include "../config/demo_config.h"

int main(void) {
    CF_STATUS status;

    const char *input = "My Tagged Application";
    size_t input_len = strlen(input);

#if ENABLE_TESTS
    printf("\nEVP_MD structure test:\n");

    // Example: XOF (cSHAKE / SHAKE) setup
    EVP_XOF_OPTS xof_opts;
    uint8_t raw_bytes[] = {0x00, 0x01, 0x02, 0x03};
    size_t raw_len = sizeof(raw_bytes);

    status = EVP_XOFOptsInit(&xof_opts,
                            //  raw_bytes, raw_len,
                             NULL, 0,    // N and S empty
                             raw_bytes, raw_len,
                             32          // Output length in bytes
    );

    if (status != CF_SUCCESS) {
        printf("EVP_FillXOFOpts failed\n");
        return 1;
    }

    printf("low level funcs:\n");
    test_all_hashes((const uint8_t *)input, input_len, &xof_opts);
    printf("**************************************\n");
    printf("high level funcs:\n");
    test_all_hashes_high((const uint8_t *)input, input_len, &xof_opts);
    printf("**************************************\n");

    // Example: Incremental hash using EVP_Hash* API
    uint8_t digest[64];  // large enough for SHA3-512
    size_t out_len = 64;
    const EVP_MD *md = EVP_MDByFlag(EVP_SHA256);
    EVP_HASH_CTX ctx;

    status = EVP_HashInit(&ctx, md, NULL);
    if (status != CF_SUCCESS) { printf("EVP_HashInit failed\n"); return 1; }

    status = EVP_HashUpdate(&ctx, (uint8_t*)input, input_len);
    if (status != CF_SUCCESS) { printf("EVP_HashUpdate failed\n"); return 1; }

    status = EVP_HashFinal(&ctx, digest, out_len);
    if (status != CF_SUCCESS) { printf("EVP_HashFinal failed\n"); return 1; }

    printf("Digest %s: ", EVP_HashGetName(md));
    for (size_t i = 0; i < EVP_HashGetDigestSize(&ctx); i++)
        printf("%02x", digest[i]);
    printf("\n");

    EVP_HashFree(&ctx);
    EVP_XOFOptsFree(&xof_opts);

    // HMAC tests
    uint8_t key[] = "My Tagged Applicationnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";

    test_all_hmacs(key, strlen((char*)key), (uint8_t*)input, input_len);

    uint8_t sha256_expected_hash[] = {
        0xd0, 0xcd, 0x05, 0xa2, 0xd9, 0x01, 0x50, 0xc9,
        0xe8, 0x5d, 0xbc, 0x82, 0x27, 0x8d, 0xa2, 0x8d,
        0xe3, 0xde, 0x8f, 0x29, 0x85, 0x9d, 0xb0, 0x96,
        0xa2, 0xfb, 0x7d, 0x38, 0x2e, 0xdf, 0x81, 0xee
    };

    size_t sha256_expected_hash_len = sizeof(sha256_expected_hash) / sizeof(sha256_expected_hash[0]);

    if (ll_HMAC_Verify(md, key, strlen((char*)key), (uint8_t*)input, input_len, sha256_expected_hash, sha256_expected_hash_len) != CF_SUCCESS) {
        printf("HMAC-256 verification failed\n");
    } else {
        printf("HMAC-256 verification succeeded\n");
    }

    printf("**************************************\n");

    test_all_kmacs(key, strlen((char*)key), (uint8_t*)input, input_len, (uint8_t*)input, input_len);

    // KMAC expected digests (hex to byte arrays)
    static const uint8_t expected_kmac128[] = {
        0x34, 0x3e, 0x46, 0x04, 0xfd, 0xbd, 0xbe, 0xc6,
        0x60, 0x5f, 0xb8, 0xea, 0xdf, 0x56, 0xce, 0x2e
    };

    static const uint8_t expected_kmacxof128[] = {
        0xa0, 0xf4, 0x39, 0xc1, 0x09, 0x72, 0x97, 0x77,
        0x03, 0x20, 0x70, 0xf0, 0x6a, 0x93, 0x13, 0x32
    };

    static const uint8_t expected_kmac256[] = {
        0x53, 0xe2, 0x28, 0x79, 0x2f, 0x2f, 0x80, 0x8a, 
        0xc4, 0x6d, 0xbc, 0x58, 0x7b, 0x6f, 0x45, 0x5c,
        0xb0, 0x77, 0xbc, 0xc9, 0xd2, 0x67, 0xab, 0x39, 
        0x0b, 0x96, 0xff, 0xe9, 0x49, 0xc5, 0xc3, 0x8f
    };

    static const uint8_t expected_kmacxof256[] = {
        0x35, 0x2a, 0x8c, 0xa4, 0x53, 0xaa, 0xd6, 0x74,
        0x34, 0x94, 0x91, 0x0b, 0x87, 0x68, 0x9c, 0xe4,
        0x30, 0x72, 0x4c, 0x2e, 0x99, 0xb0, 0x13, 0x36,
        0x2e, 0x19, 0x49, 0x8c, 0x6a, 0x90, 0xd1, 0x3a
    };


    // Array of pointers to expected digests
    static const uint8_t *expected_digests[4] = {
        expected_kmac128,
        expected_kmacxof128,
        expected_kmac256,
        expected_kmacxof256
    };

    test_all_kmacs_verify_array(key, strlen((char*)key), (uint8_t*)input, input_len, (uint8_t*)input, input_len, expected_digests);

    printf("**************************************\n");

    test_all_gmacs();

    printf("**************************************\n");

    test_aes_cmac_fips800_38b();

    printf("**************************************\n");

    // Input parameters
    uint8_t ikm[] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    uint8_t salt[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,
        0x07,0x08,0x09,0x0a,0x0b,0x0c
    };
    uint8_t info[] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
    };

    size_t okm_len = 42;

    test_all_hkdfs(info, sizeof(info), salt, sizeof(salt), ikm, sizeof(ikm), okm_len);

    printf("**************************************\n");

    // All Base64 characters for testing
    const char *all_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_";

    const char *test_strings[] = {
        "hello",
        "foobar",
        "Base encoding test!",
        "any carnal pleasure.",
        all_chars,
        "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure."
    };

    const uint8_t test_hex_1[] = { 0x14, 0xFB, 0x9C, 0x03, 0xD9, 0x7E };
    const uint8_t test_hex_2[] = { 0x14, 0xFB, 0x9C, 0x03, 0xD9 };
    const uint8_t test_hex_3[] = { 0x14, 0xFB, 0x9C, 0x03 };
    const uint8_t test_hex_4[] = { 0x00, 0x00, 0x01, 0x02 };
    const uint8_t test_hex_5[] = { 0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B};

    const uint8_t *test_hex[] = {
        test_hex_1,
        test_hex_2,
        test_hex_3,
        test_hex_4,
        test_hex_5
    };

    size_t test_hex_len[] = {
        sizeof(test_hex_1),
        sizeof(test_hex_2),
        sizeof(test_hex_3),
        sizeof(test_hex_4),
        sizeof(test_hex_5)
    };

    size_t n = sizeof(test_strings) / sizeof(test_strings[0]);
    for (size_t i = 0; i < n; i++) {
        const uint8_t *base_input = (const uint8_t *)test_strings[i];
        size_t len = strlen(test_strings[i]);

        test_base16("Standard Uppercase-Base16", base_input, len, EVP_BASE16_UPPER);
        test_base16("Standard Lowercase-Base16", base_input, len, EVP_BASE16_LOWER);

        printf("---------------------------------------------\n");

        test_base32("Standard Base32", base_input, len, EVP_BASE32_ENC, EVP_BASE32_DEC);
        test_base32("No Padding Base32", base_input, len, EVP_BASE32_ENC_NOPAD, EVP_BASE32_DEC_NOPAD);
    
        printf("---------------------------------------------\n");

        test_base58("Standard Base58", base_input, len);

        printf("---------------------------------------------\n");

        test_base64("Standard Base64", base_input, len, EVP_BASE64_STD_ENC, EVP_BASE64_STD_DEC);
        test_base64("No Padding Standard Base64", base_input, len, EVP_BASE64_STD_ENC | EVP_BASE64_NOPAD_ENC, EVP_BASE64_STD_DEC | EVP_BASE64_NOPAD_DEC);
        test_base64("URL-safe Base64", base_input, len, EVP_BASE64_URL_ENC, EVP_BASE64_URL_DEC);
        test_base64("No Padding URL-safe Base64", base_input, len, EVP_BASE64_URL_ENC | EVP_BASE64_NOPAD_ENC, EVP_BASE64_URL_DEC | EVP_BASE64_NOPAD_DEC);

        printf("---------------------------------------------\n");

        test_base85("Standard Base85", base_input, len, EVP_BASE85_STD_ENC, EVP_BASE85_STD_DEC);
        test_base85("Optional 'y' ascii85 Base85", base_input, len, EVP_BASE85_STD_ENC | EVP_BASE85_EXT_ENC, EVP_BASE85_STD_DEC | EVP_BASE85_EXT_DEC);
        test_base85("z85 Base85", base_input, len, EVP_BASE85_Z85_ENC, EVP_BASE85_Z85_DEC);

        printf("-------------- high level encode test -------------------\n");

        test_all_encoders_high(base_input, len);

        printf("-------------- end of high level encode test ----------------\n");
    }

    for (size_t i = 0; i < 5; i++) {

        test_hex_base16("test vector Standard Uppercase-Base16", test_hex[i], test_hex_len[i], EVP_BASE16_UPPER);
        test_hex_base16("test vector Standard Lowercase-Base16", test_hex[i], test_hex_len[i], EVP_BASE16_LOWER);

        printf("---------------------------------------------\n");

        test_hex_base32("test vector Standard Base32", test_hex[i], test_hex_len[i], EVP_BASE32_ENC, EVP_BASE32_DEC);
        test_hex_base32("test vector No Padding Base32", test_hex[i], test_hex_len[i], EVP_BASE32_ENC_NOPAD, EVP_BASE32_DEC_NOPAD);

        printf("---------------------------------------------\n");

        test_hex_base58("test vector Standard Base58", test_hex[i], test_hex_len[i]);

        printf("---------------------------------------------\n");

        test_hex_base64("test vector Standard Base64", test_hex[i], test_hex_len[i], EVP_BASE64_STD_ENC, EVP_BASE64_STD_DEC);
        test_hex_base64("test vector No Padding Standard Base64", test_hex[i], test_hex_len[i], EVP_BASE64_STD_ENC | EVP_BASE64_NOPAD_ENC, EVP_BASE64_STD_DEC | EVP_BASE64_NOPAD_DEC);
        test_hex_base64("test vector URL-safe Base64", test_hex[i], test_hex_len[i], EVP_BASE64_URL_ENC, EVP_BASE64_URL_DEC);
        test_hex_base64("test vector No Padding URL-safe Base64", test_hex[i], test_hex_len[i], EVP_BASE64_URL_ENC | EVP_BASE64_NOPAD_ENC, EVP_BASE64_URL_DEC | EVP_BASE64_NOPAD_DEC);

        printf("---------------------------------------------\n");

        test_hex_base85("test vector Standard Base85", test_hex[i], test_hex_len[i], EVP_BASE85_STD_ENC, EVP_BASE85_STD_DEC);
        test_hex_base85("test vector Optional 'y' ascii85 Base85", test_hex[i], test_hex_len[i], EVP_BASE85_STD_ENC | EVP_BASE85_EXT_ENC, EVP_BASE85_STD_DEC | EVP_BASE85_EXT_DEC);
        test_hex_base85("test vector z85 Base85", test_hex[i], test_hex_len[i], EVP_BASE85_Z85_ENC, EVP_BASE85_Z85_DEC);

        printf("-------------- high level encode test -------------------\n");

        test_all_encoders_high(test_hex[i], test_hex_len[i]);

        printf("-------------- end of high level encode test ----------------\n");
    }

    printf("**************************************\n");
    test_aes128_fips197();
    printf("**************************************\n");
    test_aes192_fips197();
    printf("**************************************\n");
    test_aes256_fips197();
    printf("**************************************\n");
    test_aes_ecb_fist800_38a();
    printf("**************************************\n");
    test_aes_cbc_fips800_38a();
    printf("**************************************\n");
    test_aes_cfb8_fips800_38a();
    printf("**************************************\n");
    test_aes_cfb128_fips800_38a();
    printf("**************************************\n");
    test_aes_ofb_fips800_38a();
    printf("**************************************\n");
    test_aes_ctr_fips800_38a();
    printf("**************************************\n");
    test_aes_gcm_fips_style();
    printf("**************************************\n");
    test_aes_gcm_empty_plaintext();
    printf("**************************************\n");

#endif // ENABLE_TESTS

    return 0;
}