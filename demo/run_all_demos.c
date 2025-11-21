#include "../config/demo_config.h"

int main(void) {
    // Fake command-line arguments
    const char *fake_input = "hello";
    int fake_argc = 2;
    char *fake_argv[] = { "program_name", (char *)fake_input };

    if (fake_argc < 2) {
        printf("Usage: %s <text-to-hash>\n", fake_argv[0]);
        return 1; }

    // Use fake argc/argv
    const char *input = fake_argv[1];
    size_t input_len = strlen(input);

    DEMO_md((const uint8_t*)input, input_len);
    putchar('\n');

    DEMO_sha((const uint8_t*)input, input_len);
    putchar('\n');

    DEMO_sha3((const uint8_t*)input, input_len);

    printf("\nEVP_MD structure test:\n");

    // Test some hashes
    DEMO_EVP_test_MD(EVP_MDByFlag(EVP_MD5), (const uint8_t *)input, input_len, EVP_MD5_DIGEST_SIZE);
    DEMO_EVP_test_MD(EVP_MDByFlag(EVP_SHA1), (const uint8_t *)input, input_len, EVP_SHA1_DIGEST_SIZE);
    DEMO_EVP_test_MD(EVP_MDByFlag(EVP_SHA256), (const uint8_t *)input, input_len, EVP_SHA256_DIGEST_SIZE);
    DEMO_EVP_test_MD(EVP_MDByFlag(EVP_SHAKE128), (const uint8_t*)input, input_len, 64);   // 64-byte output
    DEMO_EVP_test_MD(EVP_MDByFlag(EVP_SHAKE256), (const uint8_t*)input, input_len, 100);  // 100-byte output

    return 0;
}