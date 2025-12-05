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
    printf("------------------------------------------------------\n\n");
    printf("high level funcs:\n");
    test_all_hashes_high((const uint8_t *)input, input_len, &xof_opts);
    printf("------------------------------------------------------\n\n");

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

    printf("Digest %s: ", EVP_HashName(md));
    for (size_t i = 0; i < EVP_HashDigestSize(&ctx); i++)
        printf("%02x", digest[i]);
    printf("\n");

    EVP_HashFree(&ctx);
    EVP_XOFOptsFree(&xof_opts);

    // HMAC tests
    uint8_t key[] = "My Tagged Applicationnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";

    test_all_hmacs(key, strlen((char*)key), (uint8_t*)input, input_len);

    printf("\n------------------------------------------------------\n");

    test_all_kmacs(key, strlen((char*)key), (uint8_t*)input, input_len, (uint8_t*)input, input_len);

    printf("\n------------------------------------------------------\n");

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

    printf("---------------------------------------------\n");

    // All Base64 characters for testing
    const char *all_chars_std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char *all_chars_url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    const char *test_strings[] = {
        "hello",
        "foobar",
        "Base encoding test!",
        "any carnal pleasure.",
        all_chars_std,
        all_chars_url
    };

    const uint8_t test_hex_1[] = { 0x14, 0xFB, 0x9C, 0x03, 0xD9, 0x7E };
    const uint8_t test_hex_2[] = { 0x14, 0xFB, 0x9C, 0x03, 0xD9 };
    const uint8_t test_hex_3[] = { 0x14, 0xFB, 0x9C, 0x03 };
    const uint8_t test_hex_4[] = { 0x00, 0x00, 0x01, 0x02 };

    const uint8_t *test_hex[] = {
        test_hex_1,
        test_hex_2,
        test_hex_3,
        test_hex_4
    };

    size_t test_hex_len[] = {
        sizeof(test_hex_1),
        sizeof(test_hex_2),
        sizeof(test_hex_3),
        sizeof(test_hex_4)
    };

    size_t n = sizeof(test_strings) / sizeof(test_strings[0]);
    for (size_t i = 0; i < n; i++) {
        const uint8_t *base_input = (const uint8_t *)test_strings[i];
        size_t len = strlen(test_strings[i]);

        test_base16("Standard Uppercase-Base16", base_input, len, ENC_BASE16_UPPER);
        test_base16("Standard Lowercase-Base16", base_input, len, ENC_BASE16_LOWER);

        printf("---------------------------------------------\n");

        test_base32("Standard Base32", base_input, len, 0);
        test_base32("No Padding Base32", base_input, len, 1);
    
        printf("---------------------------------------------\n");

        test_base58("Standard Base58", base_input, len);

        printf("---------------------------------------------\n");

        test_base64("Standard Base64", base_input, len, ENC_BASE64, DEC_BASE64);
        test_base64("URL-safe Base64", base_input, len, ENC_BASE64_URL, DEC_BASE64_URL);
        test_base64("No Padding URL-safe Base64", base_input, len, ENC_BASE64_URL_NOPAD, DEC_BASE64_URL_NOPAD);

        printf("---------------------------------------------\n");
    }

    for (size_t i = 0; i < 4; i++) {

        test_hex_base16("test vector Standard Uppercase-Base16", test_hex[i], test_hex_len[i], ENC_BASE16_UPPER);
        test_hex_base16("test vector Standard Lowercase-Base16", test_hex[i], test_hex_len[i], ENC_BASE16_LOWER);

        printf("---------------------------------------------\n");

        test_hex_base32("test vector Standard Base32", test_hex[i], test_hex_len[i], 0);
        test_hex_base32("test vector No Padding Base32", test_hex[i], test_hex_len[i], 1);

        printf("---------------------------------------------\n");

        test_hex_base58("test vector Standard Base58", test_hex[i], test_hex_len[i]);

        printf("---------------------------------------------\n");

        test_hex_base64("test vector Standard Base64", test_hex[i], test_hex_len[i], ENC_BASE64, DEC_BASE64);
        test_hex_base64("test vector URL-safe Base64", test_hex[i], test_hex_len[i], ENC_BASE64_URL, DEC_BASE64_URL);
        test_hex_base64("test vector No Padding URL-safe Base64", test_hex[i], test_hex_len[i], ENC_BASE64_URL_NOPAD, DEC_BASE64_URL_NOPAD);

        printf("---------------------------------------------\n");
    }


#endif // ENABLE_TESTS

    return 0;
}