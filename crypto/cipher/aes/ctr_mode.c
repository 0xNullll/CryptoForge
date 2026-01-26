#include "ctr_mode.h"

bool ll_AES_CTR_Process(
    const AES_KEY *key,
    uint8_t counter[16],
    const uint8_t *in,
    size_t in_len_bytes,
    uint8_t *out) {
    if (!key || !counter || !in || !out) return false;

    uint8_t keystream[AES_BLOCK_SIZE] = {0};
    size_t keystream_used = AES_BLOCK_SIZE; // force first block generation

    for (size_t i = 0; i < in_len_bytes; ) {
        // Generate new keystream block if all bytes used
        if (keystream_used == AES_BLOCK_SIZE) {
            if (!ll_AES_EncryptBlock(key, counter, keystream)) return false;

            // 16-byte counter increment (big-endian)
            uint64_t val_hi = AES_LOAD64(counter);
            uint64_t val_lo = AES_LOAD64(counter + 8);

            if (++val_lo == 0) val_hi++;

            AES_STORE64(counter, val_hi);
            AES_STORE64(counter + 8, val_lo);

            keystream_used = 0;
        }

        size_t remaining = in_len_bytes - i;
        size_t chunk = AES_BLOCK_SIZE - keystream_used;
        if (chunk > remaining) chunk = remaining;

        // XOR in 8-byte chunks when possible
        size_t j = 0;
        for (; j + 8 <= chunk; j += 8) {
            uint64_t *k64 = (uint64_t*)(keystream + keystream_used + j);
            uint64_t *p64 = (uint64_t*)(out + i + j);
            uint64_t *in64 = (uint64_t*)(in + i + j);

            *p64 = *in64 ^ *k64;
        }

        // handle remaining bytes
        for (; j < chunk; j++) {
            out[i + j] = in[i + j] ^ keystream[keystream_used + j];
        }

        i += chunk;
        keystream_used += chunk;
    }

    SECURE_ZERO(keystream, sizeof(keystream));

    return true;
}

bool ll_AES_CTR_Encrypt(const AES_KEY *key, uint8_t counter[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_CTR_Process(key, counter, in, in_len, out);
}

bool ll_AES_CTR_Decrypt(const AES_KEY *key, uint8_t counter[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_CTR_Process(key, counter, in, in_len, out);   
}