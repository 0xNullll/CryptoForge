#include "ecb_mode.h"

bool ll_AES_ECB_Encrypt(const AES_KEY *key, const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !in || (in_len % AES_BLOCK_SIZE) != 0 || !out) return false; 

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        if (!ll_AES_EncryptBlock(key, in + i, out + i)) return false;
    }

    return true;
}

bool ll_AES_ECB_Decrypt(const AES_KEY *key, const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !in || (in_len % AES_BLOCK_SIZE) != 0 || !out) return false; 

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        if (!ll_AES_DecryptBlock(key, in + i, out + i)) return false;
    }

    return true;
}