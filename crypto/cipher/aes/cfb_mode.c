#include "cfb_mode.h"


static bool ll_AES_CFB8_Process( const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bytes, uint8_t *out, bool enc) {
    if (!key || !iv || !in || !out) return false;

    uint8_t feedback[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];
    SECURE_MEMCPY(feedback, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < in_len_bytes; i++) {
        // Encrypt current feedback block
        if (!ll_AES_EncryptBlock(key, feedback, block)) return false;

        uint8_t out_byte;
        if (enc) {
            // Encrypt: XOR plaintext byte with first byte of AES output
            out_byte = in[i] ^ block[0];

            // Shift feedback left by 1 byte manually  and append ciphertext byte
            for (int j = 0; j < AES_BLOCK_SIZE - 1; j++) {
                feedback[j] = feedback[j + 1];
            }

            feedback[AES_BLOCK_SIZE - 1] = out_byte;
        } else {
            // Decrypt: XOR ciphertext byte with first byte of AES output
            out_byte = in[i] ^ block[0];

            // Shift feedback left by 1 byte manually  and append ciphertext byte
            for (int j = 0; j < AES_BLOCK_SIZE - 1; j++) {
                feedback[j] = feedback[j + 1];
            }

            feedback[AES_BLOCK_SIZE - 1] = in[i];  // feedback always gets ciphertext
        }

        out[i] = out_byte;
    }

    return true;
}

static bool ll_AES_CFB128_Process(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bytes, uint8_t *out, bool enc) {
    if (!key || !iv || !in || !out) return false;

    uint8_t feedback[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];
    SECURE_MEMCPY(feedback, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < in_len_bytes; i++) {
        // Encrypt current feedback block
        if (!ll_AES_EncryptBlock(key, feedback, block)) return false;

        uint8_t out_byte;
        if (enc) {
            // Encryption: XOR plaintext with AES(feedback)
            out_byte = in[i] ^ block[0];
            feedback[i % AES_BLOCK_SIZE] = out_byte;  // feedback updated with ciphertext
        } else {
            // Decryption: XOR ciphertext with AES(feedback)
            out_byte = in[i] ^ block[0];
            feedback[i % AES_BLOCK_SIZE] = in[i];      // feedback updated with ciphertext
        }

        out[i] = out_byte;

        // Shift feedback left by 1 byte manually
        for (int j = 0; j < AES_BLOCK_SIZE - 1; j++) {
            feedback[j] = feedback[j + 1];
        }

        feedback[AES_BLOCK_SIZE - 1] = enc ? out_byte : in[i];
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
