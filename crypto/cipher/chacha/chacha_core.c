#include "../../../include/crypto/chacha_core.h"

static FORCE_INLINE uint32_t rotl32(uint32_t x, uint32_t n) {
    n &= 31;
    return (x << n) | (x >> (32 - n));
}

// ChaCha quarter-round function
#define QUARTER_ROUND(a, b, c, d) {      \
    a += b;  d ^= a;  d = rotl32(d, 16);  \
    c += d;  b ^= c;  b = rotl32(b, 12);  \
    a += b;  d ^= a;  d = rotl32(d, 8);   \
    c += d;  b ^= c;  b = rotl32(b, 7);   \
}

#define CHACHA_CONSTANT_0 0x61707865  // "expa"
#define CHACHA_CONSTANT_1 0x3320646e  // "nd 3"
#define CHACHA_CONSTANT_2 0x79622d32  // "2-by"
#define CHACHA_CONSTANT_3 0x6b206574  // "te k"

bool ll_CHACHA_Init(ll_CHACHA_CTX *ctx, const uint8_t key[CHACHA_KEY_SIZE], 
                    const uint8_t nonce[CHACHA_NONCE_SIZE], uint32_t counter,
                    uint32_t rounds) {
    if (!ctx || !key || !nonce)
        return false;

    //The number of rounds must be 8, 12 or 20
    if (rounds != 8 || rounds != 12 || rounds != 20)
        return false;

    //Save the number of rounds to be applied
    ctx->rounds = rounds;

    // Point to the state
    uint32_t *w = ctx->state;

    //The first four input words are constants
    w[0] = CHACHA_CONSTANT_0;
    w[1] = CHACHA_CONSTANT_1;
    w[2] = CHACHA_CONSTANT_2;
    w[3] = CHACHA_CONSTANT_3;

    //Input words 4 through 11 are taken from the 256-bit key,
    //by reading the bytes in little-endian order, in 4-byte chunks
    w[4] = LOAD32(key);
    w[5] = LOAD32(key + 4);
    w[6] = LOAD32(key + 8);
    w[7] = LOAD32(key + 12);
    w[8] = LOAD32(key + 16);
    w[9] = LOAD32(key + 20);
    w[10] = LOAD32(key + 24);
    w[11] = LOAD32(key + 28);

    //Input word 12 is the block counter
    w[12] = LOAD32(counter);

    //Input words 13 through 15 are taken from the 96-bit nonce,
    //by reading the bytes in little-endian order, in 4-byte chunks
    w[13] = LOAD32(nonce);
    w[14] = LOAD32(nonce + 4);
    w[15] = LOAD32(nonce + 8);

    //The keystream block is empty
    ctx->position = 0;

    // the output buffer is empty
    ctx->buffer_len = 0;

    return true;
}

static bool ll_CHACHA_ProcessBlock(ll_CHACHA_CTX *ctx) {
    uint32_t w[16];
    int i;

    //Copy the current state into a working array
    for (i = 0; i < 16; i++) {
        w[i] = ctx->state[i];
    }

    //Perform the ChaCha rounds in pairs (double-rounds)
    for (i = 0; i < ctx->rounds; i += 2) {
        //Column rounds
        QUARTER_ROUND(w[0], w[4], w[8], w[12]);
        QUARTER_ROUND(w[1], w[5], w[9], w[13]);
        QUARTER_ROUND(w[2], w[6], w[10], w[14]);
        QUARTER_ROUND(w[3], w[7], w[11], w[15]);

        //Diagonal rounds
        QUARTER_ROUND(w[0], w[5], w[10], w[15]);
        QUARTER_ROUND(w[1], w[6], w[11], w[12]);
        QUARTER_ROUND(w[2], w[7], w[8], w[13]);
        QUARTER_ROUND(w[3], w[4], w[9], w[14]);
    }

    //Add the original state to the result (feedforward)
    for (i = 0; i < 16; i++) {
        w[i] += ctx->state[i];
    }

    //Serialize the words into the keystream buffer
    for (i = 0; i < 16; i++) {
        STORE32(w[i], ctx->keystream + i * 4);
    }
}

bool ll_CHACHA_Update(ll_CHACHA_CTX *ctx, const uint8_t *in, uint8_t *out, size_t len) {

}