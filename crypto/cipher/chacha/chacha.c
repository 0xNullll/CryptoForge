#include "../../../include/crypto/chacha.h"

bool ll_CHACHA8_init(ll_CHACHA8_CTX *ctx,
                     const uint8_t *key, size_t key_len,
                     const uint8_t nonce[CHACHA_NONCE_SIZE],
                     uint32_t counter) {
    return ll_CHACHA_Init((ll_CHACHA_CTX *)ctx, key, key_len, nonce, counter, CHACHA8_ROUNDS);                 
}

bool ll_CHACHA8_Cipher(ll_CHACHA8_CTX *ctx,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out) {
    return ll_CHACHA_Cipher((ll_CHACHA_CTX *)ctx, in, in_len, out);
}

bool ll_CHACHA12_init(ll_CHACHA12_CTX *ctx,
                     const uint8_t *key, size_t key_len,
                     const uint8_t nonce[CHACHA_NONCE_SIZE],
                     uint32_t counter) {
    return ll_CHACHA_Init((ll_CHACHA_CTX *)ctx, key, key_len, nonce, counter, CHACHA12_ROUNDS);                 
}

bool ll_CHACHA12_Cipher(ll_CHACHA12_CTX *ctx,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out) {
    return ll_CHACHA_Cipher((ll_CHACHA_CTX *)ctx, in, in_len, out);
}

bool ll_CHACHA20_init(ll_CHACHA20_CTX *ctx,
                     const uint8_t *key, size_t key_len,
                     const uint8_t nonce[CHACHA_NONCE_SIZE],
                     uint32_t counter) {
    return ll_CHACHA_Init((ll_CHACHA_CTX *)ctx, key, key_len, nonce, counter, CHACHA20_ROUNDS);                 
}

bool ll_CHACHA20_Cipher(ll_CHACHA20_CTX *ctx,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out) {
    return ll_CHACHA_Cipher((ll_CHACHA_CTX *)ctx, in, in_len, out);
}