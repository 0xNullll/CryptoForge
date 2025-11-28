#include "../config/demo_config.h"

// int main(void) {
//     TCLIB_STATUS status;
//     const char *input = "hello";
//     size_t input_len = strlen(input);

// #if ENABLE_TESTS
//     printf("\nEVP_MD structure test:\n");

//     // Test multiple hashes with NULL options
//     EVP_XOF_CTX opt_ctx;

//     uint8_t raw_bytes[] = {0x68};
//     size_t raw_len = sizeof(raw_bytes);

//     status = EVP_FillXOFOpts(&opt_ctx,
//         (const uint8_t *)raw_bytes, raw_len,
//         NULL, 0,
//         32     // or 64 for cSHAKE256
//     );

//     // status = EVP_FillXOFOpts(
//     //     &opt_ctx,           // pointer to the XOF context
//     //     // (const uint8_t *)"test1", strlen("test1"),  // N string
//     //     // (const uint8_t *)"test2", strlen("test2"),  // S string
//     //     NULL, 0, NULL, 0,
//     //     32                  // requested output length
//     // );

//     if (status != TCLIB_SUCCESS) { printf("EVP_FillXOFOpts failed\n"); return 1; }

//     test_all_hashes(raw_bytes, raw_len, &opt_ctx);

//     // Example of using EVP_Hash* API
//     uint8_t digest[64];  // large enough for SHA3-512
//     size_t out_len = 64;
//     const EVP_MD *md = EVP_MDByFlag(EVP_SHA256);  
//     EVP_HASH_CTX ctx;

//     status = EVP_HashInit(&ctx, md, NULL);
//     if (status != TCLIB_SUCCESS) { printf("EVP_HashInit failed\n"); return 1; }

//     status = EVP_HashUpdate(&ctx, (uint8_t*)input, input_len);
//     if (status != TCLIB_SUCCESS) { printf("EVP_HashUpdate failed\n"); return 1; }

//     status = EVP_HashFinal(&ctx, digest, out_len);
//     if (status != TCLIB_SUCCESS) { printf("EVP_HashFinal failed\n"); return 1; }

//     printf("Digest: ");
//     for (size_t i = 0; i < EVP_HashDigestSize(&ctx); i++)
//         printf("%02x", digest[i]);
//     printf("\n");

//     EVP_HashFree(&ctx);

//     // One-shot hash
//     status = EVP_ComputeHash(md, digest, (uint8_t*)input, input_len, out_len, NULL);
//     if (status != TCLIB_SUCCESS) { printf("EVP_ComputeHash failed\n"); return 1; }

//     printf("One-shot digest: ");
//     DEMO_print_hex(digest, md->digest_size);
//     printf("\n");

//     // HMAC tests
//     uint8_t key[] = "Jefe";
//     test_all_hmacs(key, strlen((char*)key), (uint8_t *)input, input_len);

// #endif // ENABLE_TESTS

//     return 0;
// }

int main() {
    // Message to hash
    const uint8_t msg[] = {0x00, 0x01, 0x02, 0x03};
    size_t msg_len = sizeof(msg);


    // Customization string
    const uint8_t S_buf[] = "Email Signature";
    size_t S_len = sizeof(S_buf) - 1; // exclude null terminator

    // Output buffer (32 bytes = 256 bits)
    uint8_t out[32];

    // Context
    ll_CSHAKE128_CTX ctx;

    // Initialize cSHAKE128 (N empty, S non-empty)
    if (!ll_cshake128_init(&ctx,
                           NULL, 0,        // N empty
                           S_buf, S_len    // S non-empty
                        // NULL, 0
                        ))
    {
        printf("cSHAKE128 init failed\n");
        return 1;
    }

    // Absorb message
    if (!ll_cshake128_absorb(&ctx, S_buf, S_len)) {
        printf("cSHAKE128 absorb failed\n");
        return 1;
    }

    // Finalize
    if (!ll_cshake128_final(&ctx)) {
        printf("cSHAKE128 final failed\n");
        return 1;
    }

    // Squeeze 128-bit output
    if (!ll_cshake128_squeeze(&ctx, out, sizeof(out))) {
        printf("cSHAKE256 squeeze failed\n");
        return 1;
    }

    // Print output
    printf("cSHAKE128 output: ");
    for (size_t i = 0; i < sizeof(out); i++) {
        printf("%02x", out[i]);
    }
    printf("\n");

    ll_SHAKE128_CTX ctx2;
    uint8_t out2[32];


    // Initialize cSHAKE128 (N empty, S non-empty)
    if (!ll_shake128_init(&ctx2))  // S non-empty
    {
        printf("cSHAKE128 init failed\n");
        return 1;
    }

    // Absorb message
    if (!ll_shake128_absorb(&ctx2, S_buf, S_len)) {
        printf("cSHAKE128 absorb failed\n");
        return 1;
    }

    // Finalize
    if (!ll_shake128_final(&ctx2)) {
        printf("cSHAKE128 final failed\n");
        return 1;
    }

    // Squeeze 128-bit output
    if (!ll_shake128_squeeze(&ctx2, out2, sizeof(out2))) {
        printf("cSHAKE256 squeeze failed\n");
        return 1;
    }

    // Print output
    printf("SHAKE128 output: ");
    for (size_t i = 0; i < sizeof(out2); i++) {
        printf("%02x", out2[i]);
    }
    printf("\n");

    return 0;
}
