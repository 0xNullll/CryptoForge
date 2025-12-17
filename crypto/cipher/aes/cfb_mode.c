#include "cfb_mode.h"


static bool ll_AES_CFB8_Process( const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bytes, uint8_t *out, bool enc) {
    if (!key || !iv || !in || !out) return false;

    uint8_t feedback[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];
    SECURE_MEMCPY(feedback, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < in_len_bytes; i++) {
        // Encrypt current feedback block
        if (!ll_AES_EncryptBlock(key, feedback, block))
            return false;

        uint8_t out_byte = in[i] ^ block[0];
        out[i] = out_byte;

        // Shift feedback left by 1 byte manually
        for (int j = 0; j < AES_BLOCK_SIZE - 1; j++) {
            feedback[j] = feedback[j + 1];
        }

        // Append ciphertext byte
        feedback[AES_BLOCK_SIZE - 1] = enc ? out_byte : in[i];
    }

    return true;
}

static bool ll_AES_CFB128_Process(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bytes, uint8_t *out, bool enc) {
    if (!key || !iv || !in || !out) return false;

    uint8_t feedback[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];
    SECURE_MEMCPY(feedback, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < in_len_bytes; i += AES_BLOCK_SIZE) {
        // Encrypt feedback block
        if (!ll_AES_EncryptBlock(key, feedback, block))
            return false;

        // Determine how many bytes to process
        size_t chunk = (in_len_bytes - i >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : in_len_bytes - i;

        // XOR and update feedback manually in one inner loop
        for (size_t j = 0; j < chunk; j++) {
            uint8_t c = in[i + j] ^ block[j];
            out[i + j] = c;
            feedback[j] = enc ? c : in[i + j];  // update feedback inline
        }
    }

    return true;
}

bool ll_AES_CFB8_Encrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_CFB8_Process(key, iv, in, in_len, out, true);
}

bool ll_AES_CFB8_Decrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
        return ll_AES_CFB8_Process(key, iv, in, in_len, out, false);
}

bool ll_AES_CFB128_Encrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_CFB128_Process(key, iv, in, in_len, out, true);
}

bool ll_AES_CFB128_Decrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_CFB128_Process(key, iv, in, in_len, out, false);
}
