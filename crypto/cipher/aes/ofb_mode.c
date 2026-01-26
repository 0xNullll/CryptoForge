#include "ofb_mode.h"

static bool ll_AES_OFB_Process(const ll_AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bytes, uint8_t *out) {
    if (!key || !iv || !in || !out) return false;

    uint8_t state[AES_BLOCK_SIZE];
    uint8_t keystream[AES_BLOCK_SIZE];
    size_t keystream_used = AES_BLOCK_SIZE; // force first block generation

    SECURE_MEMCPY(state, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < in_len_bytes; i++) {
        // Generate new keystream block if all bytes used
        if (keystream_used == AES_BLOCK_SIZE) {
            if (!ll_AES_EncryptBlock(key, state, keystream)) return false;
            SECURE_MEMCPY(state, keystream, AES_BLOCK_SIZE); // update OFB feedback
            keystream_used = 0;
        }

        // XOR plaintext byte with current keystream byte
        out[i] = in[i] ^ keystream[keystream_used++];
    }

    SECURE_ZERO(state, sizeof(state));
    SECURE_ZERO(keystream, sizeof(keystream));

    return true;
}

bool ll_AES_OFB_Encrypt(const ll_AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_OFB_Process(key, iv, in, in_len, out);
}

bool ll_AES_OFB_Decrypt(const ll_AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_OFB_Process(key, iv, in, in_len, out);
}
