#include "../config/demo_config.h"

int main(void) {
    // Fake command-line arguments
    const char *fake_input = "what do ya want for nothing?";
    int fake_argc = 2;
    char *fake_argv[] = { "program_name", (char *)fake_input };

    if (fake_argc < 2) {
        printf("Usage: %s <text-to-hash>\n", fake_argv[0]);
        return 1; }

    // Use fake argc/argv
    const char *input = fake_argv[1];
    size_t input_len = strlen(input);

#if ENABLE_TESTS
    printf("\nEVP_MD structure test:\n");

    // Test some hashes
    DEMO_EVP_test_MD(EVP_MDByFlag(EVP_MD5), (const uint8_t *)input, input_len, EVP_MD5_DIGEST_SIZE);
    DEMO_EVP_test_MD(EVP_MDByFlag(EVP_SHA1), (const uint8_t *)input, input_len, EVP_SHA1_DIGEST_SIZE);
    DEMO_EVP_test_MD(EVP_MDByFlag(EVP_SHA256), (const uint8_t *)input, input_len, EVP_SHA256_DIGEST_SIZE);
    DEMO_EVP_test_MD(EVP_MDByFlag(EVP_SHAKE128), (const uint8_t*)input, input_len, 64);   // 64-byte output
    DEMO_EVP_test_MD(EVP_MDByFlag(EVP_SHAKE256), (const uint8_t*)input, input_len, 100);  // 100-byte output


    uint8_t digest[64];  // large enough for SHA3-512
    size_t out_len = 64;

    // Choose your hash algorithm (replace with actual MD)
    const EVP_MD *md = EVP_MDByFlag(EVP_SHA256);  

    // --- Test 1: Init + Update + Final ---
    TCLIB_STATUS status;
    EVP_HASH_CTX ctx;
    
    status = EVP_HashInit(&ctx, md);
    if (status != TCLIB_SUCCESS) {
        printf("EVP_HashInit failed\n");
        return 1;
    }

    // Update (process stored data)
    status = EVP_HashUpdate(&ctx, (const uint8_t*)input, input_len);
    if (status != TCLIB_SUCCESS) {
        printf("EVP_HashUpdate failed\n");
        return 1;
    }

    // Final
    status = EVP_HashFinal(&ctx, digest, out_len);
    if (status != TCLIB_SUCCESS) {
        printf("EVP_HashFinal failed\n");
        return 1;
    }

    // Print digest
    printf("Digest: ");
    for (size_t i = 0; i < EVP_HashDigestSize(&ctx); i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    EVP_HashFree(&ctx);

    // --- Test 2: One-shot hash ---
    status = EVP_ComputeHash(md, digest, (const uint8_t*)input, input_len, out_len);
    if (status != TCLIB_SUCCESS) {
        printf("EVP_ComputeHash failed\n");
        return 1;
    }

    printf("One-shot digest: ");
    DEMO_print_hex(digest, md->digest_size);
    printf("\n");

    // hmac tests
    uint8_t key[] = "Jefe";
    test_all_hmacs(key, strlen((char*)key), input, strlen((char*)input));

#endif // ENABLE_TESTS
    return 0;
}