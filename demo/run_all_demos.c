#include "../config/demo_config.h"

int main(void) {
    const char *input = "what do ya want for nothing?";
    size_t input_len = strlen(input);

#if ENABLE_TESTS
    printf("\nEVP_MD structure test:\n");

    // Test multiple hashes with NULL options

    test_all_hashes((uint8_t *)input, input_len);

    // Example of using EVP_Hash* API
    uint8_t digest[64];  // large enough for SHA3-512
    size_t out_len = 64;
    const EVP_MD *md = EVP_MDByFlag(EVP_SHA256);  
    TCLIB_STATUS status;
    EVP_HASH_CTX ctx;

    status = EVP_HashInit(&ctx, md, NULL);
    if (status != TCLIB_SUCCESS) { printf("EVP_HashInit failed\n"); return 1; }

    status = EVP_HashUpdate(&ctx, (uint8_t*)input, input_len);
    if (status != TCLIB_SUCCESS) { printf("EVP_HashUpdate failed\n"); return 1; }

    status = EVP_HashFinal(&ctx, digest, out_len);
    if (status != TCLIB_SUCCESS) { printf("EVP_HashFinal failed\n"); return 1; }

    printf("Digest: ");
    for (size_t i = 0; i < EVP_HashDigestSize(&ctx); i++)
        printf("%02x", digest[i]);
    printf("\n");

    EVP_HashFree(&ctx);

    // One-shot hash
    status = EVP_ComputeHash(md, digest, (uint8_t*)input, input_len, out_len, NULL);
    if (status != TCLIB_SUCCESS) { printf("EVP_ComputeHash failed\n"); return 1; }

    printf("One-shot digest: ");
    DEMO_print_hex(digest, md->digest_size);
    printf("\n");

    // HMAC tests
    uint8_t key[] = "Jefe";
    test_all_hmacs(key, strlen((char*)key), (uint8_t *)input, input_len);

#endif // ENABLE_TESTS

    return 0;
}