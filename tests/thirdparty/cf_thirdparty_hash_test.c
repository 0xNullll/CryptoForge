#include "../../src/CryptoForge/include/config/test_config.h"

#if ENABLE_TESTS

#include "../../vectors/NIST/KAT/tv_shake128.h"
#include "../../vectors/NIST/KAT/tv_shake256.h"

void test_shake128_kat(void) {
    size_t num_test_vectors = sizeof(shake128_kat_vectors) / sizeof(shake128_kat_vectors[0]);
    size_t total_failures = 0;
    size_t total_success = 0;

    const CF_HASH *hash = CF_Hash_GetByFlag(CF_SHAKE128);
    if (!hash) {
        printf("SHAKE128 not available\n");
        return;
    }

    for (size_t i = 0; i < num_test_vectors; i++) {
        const shake128_kat_vector_t *tv = &shake128_kat_vectors[i];
        uint8_t out[260] = {0};  // match your struct max output
        CF_STATUS status;

        CF_HASH_CTX *ctx = CF_Hash_InitAlloc(hash, NULL, &status);
        if (!ctx || status != CF_SUCCESS) {
            printf("Failed to init SHAKE128 ctx for TcId %d\n", tv->tc_id);
            total_failures++;
            continue;
        }

        status = CF_Hash_Update(ctx, tv->msg, tv->msg_len);
        if (status != CF_SUCCESS) {
            printf("SHAKE128 update failed for TcId %d\n", tv->tc_id);
            CF_Hash_Free(&ctx);
            total_failures++;
            continue;
        }

        status = CF_Hash_Final(ctx, out, tv->out_len);
        if (status != CF_SUCCESS) {
            printf("SHAKE128 final failed for TcId %d\n", tv->tc_id);
            CF_Hash_Free(&ctx);
            total_failures++;
            continue;
        }

        if (status != CF_SUCCESS || memcmp(out, tv->output, tv->out_len) != 0) {
            printf("SHAKE128 TcId %d FAILED\n", tv->tc_id);
            if (tv->type && tv->type[0] != '\0') {
                printf("  Comment: %s\n", tv->type);
            }
            printf("Expected: ");
            for (size_t j = 0; j < tv->out_len; j++) printf("%02x", tv->output[j]);
            printf("\nComputed: ");
            for (size_t j = 0; j < tv->out_len; j++) printf("%02x", out[j]);
            printf("\n");
            total_failures++;
        } else {
            total_success++;
        }

        CF_Hash_Free(&ctx);
    }

    printf("SHAKE128 KAT tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors, total_success, total_failures);
}

void test_shake256_kat(void) {
    size_t num_test_vectors = sizeof(shake256_kat_vectors) / sizeof(shake256_kat_vectors[0]);
    size_t total_failures = 0;
    size_t total_success = 0;

    const CF_HASH *hash = CF_Hash_GetByFlag(CF_SHAKE256);
    if (!hash) {
        printf("SHAKE256 not available\n");
        return;
    }

    for (size_t i = 0; i < num_test_vectors; i++) {
        const shake256_kat_vector_t *tv = &shake256_kat_vectors[i];
        uint8_t out[260] = {0};  // match your struct max output
        CF_STATUS status;

        CF_HASH_CTX *ctx = CF_Hash_InitAlloc(hash, NULL, &status);
        if (!ctx || status != CF_SUCCESS) {
            printf("Failed to init SHAKE256 ctx for TcId %d\n", tv->tc_id);
            total_failures++;
            continue;
        }

        status = CF_Hash_Update(ctx, tv->msg, tv->msg_len);
        if (status != CF_SUCCESS) {
            printf("SHAKE256 update failed for TcId %d\n", tv->tc_id);
            CF_Hash_Free(&ctx);
            total_failures++;
            continue;
        }

        status = CF_Hash_Final(ctx, out, tv->out_len);
        if (status != CF_SUCCESS) {
            printf("SHAKE256 final failed for TcId %d\n", tv->tc_id);
            CF_Hash_Free(&ctx);
            total_failures++;
            continue;
        }

        if (status != CF_SUCCESS || memcmp(out, tv->output, tv->out_len) != 0) {
            printf("SHAKE256 TcId %d FAILED\n", tv->tc_id);
            if (tv->type && tv->type[0] != '\0') {
                printf("  Comment: %s\n", tv->type);
            }
            printf("Expected: ");
            for (size_t j = 0; j < tv->out_len; j++) printf("%02x", tv->output[j]);
            printf("\nComputed: ");
            for (size_t j = 0; j < tv->out_len; j++) printf("%02x", out[j]);
            printf("\n");
            total_failures++;
        } else {
            total_success++;
        }

        CF_Hash_Free(&ctx);
    }

    printf("SHAKE256 KAT tests completed: %zu total, %zu passed, %zu failed\n",
           num_test_vectors, total_success, total_failures);
}

#endif // ENABLE_TESTS