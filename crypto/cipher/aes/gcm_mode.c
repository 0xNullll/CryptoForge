#include "gcm_mode.h"

static FORCE_INLINE uint64_t load_uint64_be(const uint8_t *b) {
    return ((uint64_t)b[0] << 56) |
           ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) |
           ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) |
           ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  |
           ((uint64_t)b[7]);
}

static FORCE_INLINE void store_uint64_be(uint8_t *out, uint64_t x) {
    out[0] = (uint8_t)(x >> 56);
    out[1] = (uint8_t)(x >> 48);
    out[2] = (uint8_t)(x >> 40);
    out[3] = (uint8_t)(x >> 32);
    out[4] = (uint8_t)(x >> 24);
    out[5] = (uint8_t)(x >> 16);
    out[6] = (uint8_t)(x >> 8);
    out[7] = (uint8_t)(x);
}

void gcm_mult(uint8_t Z[AES_BLOCK_SIZE],
            const uint8_t X[AES_BLOCK_SIZE],
            const uint8_t Y[AES_BLOCK_SIZE]) {
    uint64_t zh = 0, zl = 0;
    uint64_t yh = load_uint64_be(Y);
    uint64_t yl = load_uint64_be(Y + 8);

    for (int i = 0; i < 128; i++) {
        uint8_t bit = (X[i >> 3] >> (7 - (i & 7))) & 1;
        uint64_t mask = -(int64_t)bit;

        zh ^= yh & mask;
        zl ^= yl & mask;

        uint64_t lsb = yl & 1;
        yl = (yl >> 1) | (yh << 63);
        yh = (yh >> 1) ^ (U64(0xe100000000000000) & ((uint64_t)0 - lsb));
    }

    store_uint64_be(Z, zh);
    store_uint64_be(Z + 8, zl);
}

void GHASH_Process(
    const uint8_t H[AES_BLOCK_SIZE],    // GHASH key (H = AES(K,0^128))
    const uint8_t *in, size_t in_len,   // data to GHASH
    uint8_t out[AES_BLOCK_SIZE]) {      // accumulator (X), updated in-place
    uint8_t block[AES_BLOCK_SIZE];

    size_t offset = 0;
    while (offset < in_len) {
        size_t blk_len = (in_len - offset > AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (in_len - offset);

        // Copy bytes from input and zero-pad if partial block
        for (int i = 0; i < AES_BLOCK_SIZE; i++)
            block[i] = ((size_t)i < blk_len) ? in[offset + (size_t)i] : 0;

        // XOR into current accumulator
        for (int i = 0; i < AES_BLOCK_SIZE; i++)
            out[i] ^= block[i];

        // Multiply in GF(2^128)
        gcm_mult(out, out, H);
        offset += blk_len;
    }
}

static FORCE_INLINE void Inc32(uint8_t counter[AES_BLOCK_SIZE]) {
    // Increment last 32 bits (big-endian) modulo 2^32
    for (int i = 15; i >= 12; i--) {
        if (++counter[i] != 0)
            break;  
    }
}

bool ll_AES_GCTR_Process(const AES_KEY *key, uint8_t ICB[AES_BLOCK_SIZE], const uint8_t *X, size_t X_len, uint8_t *Y) {
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

bool ll_AES_GCM_Encrypt(
    const AES_KEY *key,
    const uint8_t *iv,
    size_t iv_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    uint8_t *tag,
    size_t tag_len) {

    if (!key || !iv || iv_len < AES_GCM_IV_MIN || !tag) return false;
    if (!IS_VALID_GCM_TAG_SIZE(tag_len)) return false;

    // Length limits (from NIST SP 800‑38D)
    if (aad_len > ((U64(0x1) << 61) - 1)) return false;
    if (in_len  > ((U64(0x1) << 36) - 32)) return false;

    // Prevent NULL misuse
    if (in_len != 0 && !in) return false;
    if (aad_len != 0 && !aad) return false;

    uint8_t zero_block[AES_BLOCK_SIZE] = {0};
    uint8_t H[AES_BLOCK_SIZE] = {0};
    uint8_t J0[AES_BLOCK_SIZE] = {0};

    // 1. Compute H = AES_K(0^128)
    if (!ll_AES_EncryptBlock(key, zero_block, H)) return false;

    // 2. Prepare initial counter block J0
    if (iv_len == 12) { // 12-byte IV (most common)
        SECURE_MEMCPY(J0, iv, 12);
        J0[12] = 0x00;
        J0[13] = 0x00;
        J0[14] = 0x00;
        J0[15] = 0x01;
    } else { // arbitrary IV length
        uint8_t X[AES_BLOCK_SIZE] = {0};
        GHASH_Process(H, iv, iv_len, X);

        // Append IV length (64-bit) in bits as last 8 bytes
        uint8_t len_block[AES_BLOCK_SIZE] = {0};
        uint64_t iv_bits = iv_len * 8;
        for (int i = 0; i < 8; i++)
            len_block[8 + i] = (uint8_t)((iv_bits >> (56 - i*8)) & 0xFF);

        GHASH_Process(H, len_block, AES_BLOCK_SIZE, X);
        SECURE_MEMCPY(J0, X, AES_BLOCK_SIZE);
    }

    // 3. Prepare GCTR counter block
    uint8_t ctr[AES_BLOCK_SIZE];
    SECURE_MEMCPY(ctr, J0, AES_BLOCK_SIZE);
    Inc32(ctr);  // start from J0 + 1

    // 4. Encrypt plaintext
    if (in_len > 0 && out && !ll_AES_GCTR_Process(key, ctr, in, in_len, out))
        return false;

    // 5. Compute GHASH over AAD + ciphertext
    uint8_t X[AES_BLOCK_SIZE] = {0};
    if (aad_len > 0) GHASH_Process(H, aad, aad_len, X);
    if (in_len  > 0 && out) GHASH_Process(H, out, in_len, X);

    // 6. Append lengths of AAD and ciphertext in bits
    uint8_t len_block[AES_BLOCK_SIZE] = {0};
    uint64_t aad_bits = aad_len * 8;
    uint64_t ct_bits  = in_len  * 8;

    for (int i = 0; i < 8; i++)      len_block[i]     = (uint8_t)((aad_bits >> (56 - i*8)) & 0xFF);
    for (int i = 0; i < 8; i++)      len_block[8 + i] = (uint8_t)((ct_bits  >> (56 - i*8)) & 0xFF);

    for (int i = 0; i < AES_BLOCK_SIZE; i++)
        X[i] ^= len_block[i];

    gcm_mult(X, X, H);  // multiply by H in GF(2^128)

    // 7. Compute tag: T = AES_K(J0) XOR GHASH
    uint8_t EK0[AES_BLOCK_SIZE] = {0};
    if (!ll_AES_EncryptBlock(key, J0, EK0)) return false;

    for (size_t i = 0; i < tag_len && i < AES_BLOCK_SIZE; i++)
        tag[i] = EK0[i] ^ X[i];

    return true;
}

bool ll_AES_GCM_Decrypt(
    const AES_KEY *key,
    const uint8_t *iv,
    size_t iv_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    const uint8_t *tag,
    size_t tag_len) {

    if (!key || !iv || iv_len < AES_GCM_IV_MIN || !tag) return false;
    if (!IS_VALID_GCM_TAG_SIZE(tag_len)) return false;

    // Prevent NULL misuse
    if (in_len != 0 && !in) return false;
    if (aad_len != 0 && !aad) return false;

    // Length limits (from NIST SP 800‑38D)
    if (aad_len > ((U64(0x1) << 61) - 1)) return false;
    if (in_len  > ((U64(0x1) << 36) - 32)) return false;

    uint8_t zero_block[AES_BLOCK_SIZE] = {0};
    uint8_t H[AES_BLOCK_SIZE] = {0};
    uint8_t J0[AES_BLOCK_SIZE] = {0};

    // 1. Compute H = AES_K(0^128)
    if (!ll_AES_EncryptBlock(key, zero_block, H)) return false;

    // 2. Prepare initial counter block J0
    if (iv_len == 12) { // 12-byte IV (fast path)
        SECURE_MEMCPY(J0, iv, 12);
        J0[12] = 0x00;
        J0[13] = 0x00;
        J0[14] = 0x00;
        J0[15] = 0x01;
    } else { // arbitrary IV
        uint8_t X[AES_BLOCK_SIZE] = {0};
        GHASH_Process(H, iv, iv_len, X);

        // Append IV length (64-bit) in bits
        uint8_t len_block[AES_BLOCK_SIZE] = {0};
        uint64_t iv_bits = iv_len * 8;
        for (int i = 0; i < 8; i++)
            len_block[8 + i] = (uint8_t)((iv_bits >> (56 - i*8)) & 0xFF);

        GHASH_Process(H, len_block, AES_BLOCK_SIZE, X);
        SECURE_MEMCPY(J0, X, AES_BLOCK_SIZE);
    }

    // 3. Compute GHASH over AAD + ciphertext
    uint8_t X[AES_BLOCK_SIZE] = {0};
    if (aad_len > 0) GHASH_Process(H, aad, aad_len, X);
    if (in_len  > 0) GHASH_Process(H, in, in_len, X);

    // 4. Append lengths of AAD and ciphertext in bits
    uint8_t len_block[AES_BLOCK_SIZE] = {0};
    uint64_t aad_bits = aad_len * 8;
    uint64_t ct_bits  = in_len  * 8;

    for (int i = 0; i < 8; i++)      len_block[i]     = (uint8_t)((aad_bits >> (56 - i*8)) & 0xFF);
    for (int i = 0; i < 8; i++)      len_block[8 + i] = (uint8_t)((ct_bits  >> (56 - i*8)) & 0xFF);

    for (int i = 0; i < AES_BLOCK_SIZE; i++)
        X[i] ^= len_block[i];

    gcm_mult(X, X, H);  // multiply by H in GF(2^128)

    // 5. Compute expected tag: T' = AES_K(J0) XOR GHASH
    uint8_t EK0[AES_BLOCK_SIZE] = {0};
    if (!ll_AES_EncryptBlock(key, J0, EK0)) return false;

    uint8_t computed_tag[AES_BLOCK_SIZE] = {0};
    for (size_t i = 0; i < tag_len && i < AES_BLOCK_SIZE; i++)
        computed_tag[i] = EK0[i] ^ X[i];

    // 6. Constant-time tag comparison
    if (!SECURE_MEM_EQUAL(tag, computed_tag, tag_len)) return false; // tag mismatch

    // 7. Decrypt ciphertext using GCTR
    if (in_len > 0 && out) {
        uint8_t ctr[AES_BLOCK_SIZE];
        SECURE_MEMCPY(ctr, J0, AES_BLOCK_SIZE);
        Inc32(ctr);  // start from J0 + 1
        if (!ll_AES_GCTR_Process(key, ctr, in, in_len, out))
            return false;
    }

    return true;
}
