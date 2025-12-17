#include "ctr_mode.h"

static bool ll_AES_CTR_Process(const AES_KEY *key, uint8_t counter[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bytes, uint8_t *out) {
    if (!key || !counter || !in || !out) return false;

    uint8_t keystream[AES_BLOCK_SIZE];
    size_t keystream_used = AES_BLOCK_SIZE; // force first block generation

    for (size_t i = 0; i < in_len_bytes; i++) {
        // Generate new keystream block if all bytes used
        if (keystream_used == AES_BLOCK_SIZE) {
            if (!ll_AES_EncryptBlock(key, counter, keystream)) return false;

            // Increment counter as a big-endian number, carry propagates automatically
            for (int j = AES_BLOCK_SIZE - 1; j >= 0; j--) {
                if (++counter[j] != 0) break; // stop if no overflow, else carry to next byte
            }

            keystream_used = 0;
        }

        // XOR plaintext byte with current keystream byte
        out[i] = in[i] ^ keystream[keystream_used++];
    }

    return true;
}

bool ll_AES_CTR_Encrypt(const AES_KEY *key, uint8_t counter[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_CTR_Process(key, counter, in, in_len, out);
}

bool ll_AES_CTR_Decrypt(const AES_KEY *key, uint8_t counter[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_CTR_Process(key, counter, in, in_len, out);   
}