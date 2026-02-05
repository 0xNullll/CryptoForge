#ifndef CHACHA_CORE_H
#define CHACHA_CORE_H

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../utils/bitops.h"
#include "../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA_BLOCK_SIZE 64   // 512-bit block
#define CHACHA_KEY_SIZE   32   // 256-bit key (default)
#define CHACHA_NONCE_SIZE 12   // 96-bit nonce

// Low-level ChaCha state
typedef struct {
    uint32_t state[16];           // internal 16-word state
    uint8_t  keystream[CHACHA_BLOCK_SIZE]; // buffer for generated block
    size_t   position;            // current position in keystream buffer
    uint32_t rounds;              // number of ChaCha rounds (can be any even number)
    uint8_t  buffer[CHACHA_BLOCK_SIZE]; // buffer for leftover input data
    size_t   buffer_len;               // how many bytes are currently in the buffer
} ll_CHACHA_CTX;

// Initialize ChaCha context with key, nonce, counter, and custom rounds
bool ll_CHACHA_Init(ll_CHACHA_CTX *ctx, const uint8_t key[CHACHA_KEY_SIZE], 
                    const uint8_t nonce[CHACHA_NONCE_SIZE], uint32_t counter,
                    uint32_t rounds);

// Generate keystream and XOR with input (in-place or to output)
bool ll_CHACHA_Update(ll_CHACHA_CTX *ctx, const uint8_t *in, uint8_t *out, size_t len);

// Clean up and zero the context
bool ll_CHACHA_Final(ll_CHACHA_CTX *ctx, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif // CHACHA_CORE_H
