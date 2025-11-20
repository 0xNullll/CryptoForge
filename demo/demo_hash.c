#include "../config/demo_config.h"

#if ENABLE_TESTS && (ENABLE_SHA || ENABLE_SHA3)

void compute_and_print_hashes(const uint8_t *data, size_t len) {

    uint8_t digest1[SHA1_DIGEST_SIZE];
    if (!ll_sha1(data, len, digest1)) {
        printf("SHA1 computation failed!\n");
    }
    printf("SHA1:    ");
    print_hex(digest1, SHA1_DIGEST_SIZE);

    uint8_t digest224[SHA224_DIGEST_SIZE];
    if (!ll_sha224(data, len, digest224)) {
        printf("SHA224 computation failed!\n");
    }
    printf("SHA224:  ");
    print_hex(digest224, SHA224_DIGEST_SIZE);

    uint8_t digest256[SHA256_DIGEST_SIZE];
    if (!ll_sha256(data, len, digest256)) {
        printf("SHA256 computation failed!\n");
    }
    printf("SHA256:  ");
    print_hex(digest256, SHA256_DIGEST_SIZE);

    uint8_t digest384[SHA384_DIGEST_SIZE];
    if (!ll_sha384(data, len, digest384)) {
        printf("SHA384 computation failed!\n");
    }
    printf("SHA384:  ");
    print_hex(digest384, SHA384_DIGEST_SIZE);

    uint8_t digest512[SHA512_DIGEST_SIZE];
    if (!ll_sha512(data, len, digest512)) {
        printf("SHA512 computation failed!\n");
    }
    printf("SHA512:  ");
    print_hex(digest512, SHA512_DIGEST_SIZE);

    uint8_t digest512_224[SHA512_224_DIGEST_SIZE];
    if (!ll_sha512_224(data, len, digest512_224)) {
        printf("SHA512/224 computation failed!\n");
    }
    printf("SHA512/224: ");
    print_hex(digest512_224, SHA512_224_DIGEST_SIZE);

    uint8_t digest512_256[SHA512_256_DIGEST_SIZE];
    if (!ll_sha512_256(data, len, digest512_256)) {
        printf("SHA512/256 computation failed!\n");
    }
    printf("SHA512/256: ");
    print_hex(digest512_256, SHA512_256_DIGEST_SIZE);

    uint8_t digest3_224[SHA3_224_DIGEST_SIZE];
    if (!ll_sha3_224(data, len, digest3_224)) {
        printf("SHA3-224 computation failed!\n");
    }
    printf("SHA3-224: ");
    print_hex(digest3_224, SHA3_224_DIGEST_SIZE);

    uint8_t digest3_256[SHA3_256_DIGEST_SIZE];
    if (!ll_sha3_256(data, len, digest3_256)) {
        printf("SHA3-256 computation failed!\n");
    }
    printf("SHA3-256: ");
    print_hex(digest3_256, SHA3_256_DIGEST_SIZE);

    uint8_t digest3_384[SHA3_384_DIGEST_SIZE];
    if (!ll_sha3_384(data, len, digest3_384)) {
        printf("SHA3-384 computation failed!\n");
    }
    printf("SHA3-384: ");
    print_hex(digest3_384, SHA3_384_DIGEST_SIZE);

    uint8_t digest3_512[SHA3_512_DIGEST_SIZE];
    if (!ll_sha3_512(data, len, digest3_512)) {
        printf("SHA3-512 computation failed!\n");
    }
    printf("SHA3-512: ");
    print_hex(digest3_512, SHA3_512_DIGEST_SIZE);

    size_t _shake128_len = 32; // example digest length
    uint8_t digest_shake128[_shake128_len];
    if (!ll_shake128(data, len, digest_shake128, _shake128_len)) {
        printf("SHAKE128 computation failed!\n");
    }
    printf("SHAKE128 (%zu bytes): ", _shake128_len);
    print_hex(digest_shake128, _shake128_len);

    size_t _shake256_len = 64; // example digest length
    uint8_t digest_shake256[_shake256_len];
    if (!ll_shake256(data, len, digest_shake256, _shake256_len)) {
        printf("SHAKE256 computation failed!\n");
    }
    printf("SHAKE256 (%zu bytes): ", _shake256_len);
    print_hex(digest_shake256, _shake256_len);

    size_t _rawshake128_len = 32; // example digest length
    uint8_t digest_rawshake128[_rawshake128_len];
    if (!ll_rawshake128(data, len, digest_rawshake128, _rawshake128_len)) {
        printf("RawSHAKE128 computation failed!\n");
    }
    printf("RawSHAKE128 (%zu bytes): ", _rawshake128_len);
    print_hex(digest_rawshake128, _rawshake128_len);

    size_t _rawshake256_len = 64; // example digest length
    uint8_t digest_rawshake256[_rawshake256_len];
    if (!ll_rawshake256(data, len, digest_rawshake256, _rawshake256_len)) {
        printf("RawSHAKE256 computation failed!\n");
    }
    printf("RawSHAKE256 (%zu bytes): ", _rawshake256_len);
    print_hex(digest_rawshake256, _rawshake256_len);
}

#endif // ENABLE_TESTS && (ENABLE_SHA || ENABLE_SHA3)