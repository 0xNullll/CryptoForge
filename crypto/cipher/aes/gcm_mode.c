#include "gcm_mode.h"

void gcm_mult(uint8_t Z[AES_BLOCK_SIZE],
            const uint8_t X[AES_BLOCK_SIZE],
            const uint8_t Y[AES_BLOCK_SIZE]) {
    uint64_t zh = 0, zl = 0;
    uint64_t yh = AES_LOAD64(Y);
    uint64_t yl = AES_LOAD64(Y + 8);

    for (int i = 0; i < 128; i++) {
        uint8_t bit = (X[i >> 3] >> (7 - (i & 7))) & 1;
        uint64_t mask = -(int64_t)bit;

        zh ^= yh & mask;
        zl ^= yl & mask;

        uint64_t lsb = yl & 1;
        yl = (yl >> 1) | (yh << 63);
        yh = (yh >> 1) ^ (U64(0xe100000000000000) & ((uint64_t)0 - lsb));
    }

    AES_STORE64(Z, zh);
    AES_STORE64(Z + 8, zl);
}

void GHASH_Process(
    const uint8_t H[AES_BLOCK_SIZE],    // GHASH key (H = AES(K,0^128))
    const uint8_t *in, size_t in_len,   // data to GHASH
    uint8_t out[AES_BLOCK_SIZE]) {      // accumulator (X), updated in-place
    uint8_t block[AES_BLOCK_SIZE] = {0};

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

    SECURE_ZERO(block, sizeof(block));
}

// Increment last 32 bits of 16-byte block (GCM counter)
static void Inc32(uint8_t CB[16]) {
    uint32_t val = AES_LOAD32(CB + 12);
    val++;
    AES_STORE32(CB + 12, val);
}

bool ll_AES_GCTR_Process(
    const AES_KEY *key,
    uint8_t ICB[16],
    const uint8_t *X,
    size_t X_len,
    uint8_t *Y) {
    uint8_t CB[16] = {0}, encrypted[16] = {0};
    SECURE_MEMCPY(CB, ICB, 16);

    size_t offset = 0;

    while (X_len >= 16) {
        if (offset > 0) Inc32(CB);

        if (!ll_AES_EncryptBlock(key, CB, encrypted)) return false;

        // XOR in 64-bit chunks
        uint64_t x0 = AES_LOAD64(X + offset);
        uint64_t x1 = AES_LOAD64(X + offset + 8);

        uint64_t e0 = AES_LOAD64(encrypted);
        uint64_t e1 = AES_LOAD64(encrypted + 8);

        // XOR and store back in big-endian order
        AES_STORE64(Y + offset, x0 ^ e0);
        AES_STORE64(Y + offset + 8, x1 ^ e1);

        offset += 16;
        X_len -= 16;
    }

    // Handle remaining bytes if input not multiple of 16
    if (X_len > 0) {
        if (!ll_AES_EncryptBlock(key, CB, encrypted)) return false;
        for (size_t j = 0; j < X_len; j++) {
            Y[offset + j] = X[offset + j] ^ encrypted[j];
        }
    }

    SECURE_ZERO(CB, sizeof(CB));
    SECURE_ZERO(encrypted, sizeof(encrypted));

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
        SECURE_ZERO(X, sizeof(X));
    }

    // 3. Prepare GCTR counter block
    uint8_t ctr[AES_BLOCK_SIZE] = {0};
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

    SECURE_ZERO(zero_block, sizeof(zero_block));
    SECURE_ZERO(H, sizeof(H));
    SECURE_ZERO(J0, sizeof(J0));
    SECURE_ZERO(ctr, sizeof(ctr));
    SECURE_ZERO(X, sizeof(X));
    SECURE_ZERO(len_block, sizeof(len_block));
    SECURE_ZERO(EK0, sizeof(EK0));

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
        SECURE_ZERO(X, sizeof(X));
        SECURE_ZERO(len_block, sizeof(len_block));
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
        uint8_t ctr[AES_BLOCK_SIZE] = {0};
        SECURE_MEMCPY(ctr, J0, AES_BLOCK_SIZE);

        Inc32(ctr);  // start from J0 + 1
        if (!ll_AES_GCTR_Process(key, ctr, in, in_len, out))
            return false;

        SECURE_ZERO(ctr, sizeof(ctr));
    }

    SECURE_ZERO(zero_block, sizeof(zero_block));
    SECURE_ZERO(H, sizeof(H));
    SECURE_ZERO(J0, sizeof(J0));
    SECURE_ZERO(X, sizeof(X));
    SECURE_ZERO(len_block, sizeof(len_block));
    SECURE_ZERO(EK0, sizeof(EK0));
    SECURE_ZERO(computed_tag, sizeof(computed_tag));

    return true;
}
