#include "gcm_mode.h"

typedef struct {
    uint64_t hi;
    uint64_t lo;
} uint128_t;

static const uint8_t R[AES_BLOCK_SIZE] = {
    0xe1, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

static uint128_t load_uint128(const uint8_t b[AES_BLOCK_SIZE]) {
    uint128_t x;
    x.hi = ((uint64_t)b[0] << 56)  | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40)  | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24)  | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)   | ((uint64_t)b[7]);
    x.lo = ((uint64_t)b[8] << 56)  | ((uint64_t)b[9] << 48) |
           ((uint64_t)b[10] << 40) | ((uint64_t)b[11] << 32) |
           ((uint64_t)b[12] << 24) | ((uint64_t)b[13] << 16) |
           ((uint64_t)b[14] << 8)  | ((uint64_t)b[15]);
    return x;
}

static void store_uint128(uint8_t out[AES_BLOCK_SIZE], uint128_t x) {
    out[0]  = (uint8_t)(x.hi >> 56); out[1]  = (uint8_t)(x.hi >> 48); out[2]  = (uint8_t)(x.hi >> 40); out[3]  = (uint8_t)(x.hi >> 32);
    out[4]  = (uint8_t)(x.hi >> 24); out[5]  = (uint8_t)(x.hi >> 16); out[6]  = (uint8_t)(x.hi >> 8);  out[7]  = (uint8_t)(x.hi & 0xFF);
    out[8]  = (uint8_t)(x.lo >> 56); out[9]  = (uint8_t)(x.lo >> 48); out[10] = (uint8_t)(x.lo >> 40); out[11] = (uint8_t)(x.lo >> 32);
    out[12] = (uint8_t)(x.lo >> 24); out[13] = (uint8_t)(x.lo >> 16); out[14] = (uint8_t)(x.lo >> 8);  out[15] = (uint8_t)(x.lo & 0xFF);
}

static void GFmul128(uint8_t Z[AES_BLOCK_SIZE],
    const uint8_t X[AES_BLOCK_SIZE],
    const uint8_t Y[AES_BLOCK_SIZE]) {

    uint128_t z = {0, 0};
    uint128_t v = load_uint128(Y);
    uint128_t r = load_uint128(R);
    uint128_t x = load_uint128(X);

    for (int i = 0; i < 128; i++) {
        // MSB of X determines addition
        uint64_t bit = (x.hi >> 63) & 1;
        if (bit) {
            z.hi ^= v.hi;
            z.lo ^= v.lo;
        }

        // Shift V right by 1 and reduce if needed
        uint8_t lsb = v.lo & 1;

        v.hi = v.hi >> 1;
        v.hi |= (v.lo & 1) << 63;   // carry LSB from lo to hi
        v.lo = v.lo >> 1;

        if (lsb) {
            v.hi ^= r.hi;
            v.lo ^= r.lo;
        }

        // Shift X left to move next bit into MSB
        x.hi = (x.hi << 1) | (x.lo >> 63);
        x.lo <<= 1;
    }

    store_uint128(Z, z);
}

static void GHASH(uint8_t H[AES_BLOCK_SIZE], uint8_t *aad, size_t aad_len,
           uint8_t *ct, size_t ct_len, uint8_t X_out[AES_BLOCK_SIZE]) {

    uint8_t X[AES_BLOCK_SIZE] = {0};
    uint8_t block[AES_BLOCK_SIZE] = {0};

    size_t len = 0;
    size_t num_blocks;

    // --- Process AAD ---
    if (aad) {
        num_blocks = (aad_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
        len = 0;
        for (size_t i = 0; i < num_blocks; i++) {
            SECURE_ZERO(block, AES_BLOCK_SIZE);
            for (int j = 0; j < AES_BLOCK_SIZE && len < aad_len; j++) {
                block[j] = aad[len++];
            }
            GFmul128(X, block, H);
        }
    }

    // --- Process Ciphertext ---
    if (ct) {
        num_blocks = (ct_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
        len = 0;
        for (size_t i = 0; i < num_blocks; i++) {
            SECURE_ZERO(block, AES_BLOCK_SIZE);
            for (int j = 0; j < AES_BLOCK_SIZE && len < ct_len; j++) {
                block[j] = ct[len++];
            }
            GFmul128(X, block, H);
        }
    }

    // --- Length block ---
    SECURE_ZERO(block, AES_BLOCK_SIZE);
    // Encode lengths in bits: high 64 bits = AAD in big-endian
    uint64_t aad_bits = aad_len * 8;
    for (int i = 0; i < 8; i++) {
        block[i] = (aad_bits >> (56 - i * 8)) & 0xFF;
    }

    // Encode length in bits: low 64 bits = CT in big-endian
    uint64_t ct_bits = ct_len * 8;
    for (int i = 0; i < 8; i++) {
        block[8 + i] = (ct_bits >> (56 - i * 8)) & 0xFF;
    }

    GFmul128(X, block, H);

    SECURE_MEMCPY(X_out, X, AES_BLOCK_SIZE);
}

static FORCE_INLINE void Inc32(uint8_t counter[AES_BLOCK_SIZE]) {
    // Increment last 32 bits (big-endian) modulo 2^32
    for (int i = 15; i >= 12; i--) {
        if (++counter[i] != 0)
            break;  
    }
}

static bool GCTR(const AES_KEY *key, uint8_t ICB[AES_BLOCK_SIZE], const uint8_t *X, size_t X_len, uint8_t *Y) {
    uint8_t CB[AES_BLOCK_SIZE], encrypted[AES_BLOCK_SIZE];
    SECURE_MEMCPY(CB, ICB, AES_BLOCK_SIZE);

    size_t num_blocks = (X_len + 16 - 1) / 16;
    size_t offset = 0;

    for (size_t i = 0; i < num_blocks; i++) {
        if (i > 0) Inc32(CB);

        if (!ll_AES_EncryptBlock(key, CB, encrypted)) return false;

        size_t block_len = (X_len - offset > 16) ? 16 : (X_len - offset);
        for (size_t j = 0; j < block_len; j++) {
            Y[offset + j] = X[offset + j] ^ encrypted[j];
        }

        offset += block_len;
    }
    return true;
}
