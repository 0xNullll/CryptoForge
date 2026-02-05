#include "../../../include/crypto/gcm_mode.h"

void ll_gcm_mult(uint8_t Z[AES_BLOCK_SIZE],
            const uint8_t X[AES_BLOCK_SIZE],
            const uint8_t Y[AES_BLOCK_SIZE]) {
    uint64_t zh = 0, zl = 0;
    uint64_t yh = LOAD64(Y);
    uint64_t yl = LOAD64(Y + 8);

    for (int i = 0; i < 128; i++) {
        uint8_t bit = (X[i >> 3] >> (7 - (i & 7))) & 1;
        uint64_t mask = -(int64_t)bit;

        zh ^= yh & mask;
        zl ^= yl & mask;

        uint64_t lsb = yl & 1;
        yl = (yl >> 1) | (yh << 63);
        yh = (yh >> 1) ^ (U64(0xe100000000000000) & ((uint64_t)0 - lsb));
    }

    STORE64(Z, zh);
    STORE64(Z + 8, zl);
}

void ll_GHASH_Process(
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
        ll_gcm_mult(out, out, H);
        offset += blk_len;
    }

    SECURE_ZERO(block, sizeof(block));
}

// Increment last 32 bits of 16-byte block (GCM counter)
static void Inc32(uint8_t CB[16]) {
    uint32_t val = LOAD32(CB + 12);
    val++;
    STORE32(CB + 12, val);
}

bool ll_AES_GCTR_Process(
    const ll_AES_KEY *key,
    uint8_t ICB[AES_BLOCK_SIZE],
    const uint8_t *X,
    size_t X_len,
    uint8_t *Y) {

    uint8_t CB[AES_BLOCK_SIZE], encrypted[AES_BLOCK_SIZE];
    SECURE_MEMCPY(CB, ICB, AES_BLOCK_SIZE);

    size_t offset = 0;

    while (X_len >= AES_BLOCK_SIZE) {
        if (offset > 0) Inc32(CB);

        if (!ll_AES_EncryptBlock(key, CB, encrypted))
            return false;

        // simple byte-wise XOR
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++)
            Y[offset + j] = X[offset + j] ^ encrypted[j];

        offset += AES_BLOCK_SIZE;
        X_len -= AES_BLOCK_SIZE;
    }

    if (X_len > 0) {
        if (!ll_AES_EncryptBlock(key, CB, encrypted))
            return false;

        for (size_t j = 0; j < X_len; j++)
            Y[offset + j] = X[offset + j] ^ encrypted[j];
    }

    SECURE_ZERO(CB, sizeof(CB));
    SECURE_ZERO(encrypted, sizeof(encrypted));

    return true;
}

// --- Initialization with optional AAD ---
bool ll_AES_GCM_Init(ll_AES_GCM_CTX *ctx,
                     const ll_AES_KEY *key,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len) {
    if (!ctx || !key || !iv || iv_len < AES_GCM_IV_MIN)
        return false;

    // Length limits (from NIST SP 800‑38D)
    if (aad_len > ((U64(0x1) << 61) - 1)) return false;

    ctx->key = key;

    // 1. Compute H = AES_K(0^128)
    uint8_t zero_block[AES_BLOCK_SIZE] = {0};
    if (!ll_AES_EncryptBlock(key, zero_block, ctx->H))
        return false;

    // 2. Prepare J0
    if (iv_len == 12) {
        SECURE_MEMCPY(ctx->J0, iv, 12);
        ctx->J0[12] = 0; ctx->J0[13] = 0; ctx->J0[14] = 0; ctx->J0[15] = 1;
    } else {
        uint8_t tmp[AES_BLOCK_SIZE] = {0};
        ll_GHASH_Process(ctx->H, iv, iv_len, tmp);

        uint8_t len_block[AES_BLOCK_SIZE] = {0};
        uint64_t iv_bits = iv_len * 8;
        for (int i = 0; i < 8; i++) len_block[8+i] = (uint8_t)((iv_bits >> (56 - i*8)) & 0xFF);

        ll_GHASH_Process(ctx->H, len_block, AES_BLOCK_SIZE, tmp);
        SECURE_MEMCPY(ctx->J0, tmp, AES_BLOCK_SIZE);
        SECURE_ZERO(tmp, sizeof(tmp));
        SECURE_ZERO(len_block, sizeof(len_block));
    }

    SECURE_MEMCPY(ctx->ctr, ctx->J0, AES_BLOCK_SIZE);
    Inc32(ctx->ctr); // start counter at J0 + 1
    SECURE_ZERO(ctx->X, sizeof(ctx->X));

    // 3. Process AAD immediately if present
    if (aad_len && aad) {
        ll_GHASH_Process(ctx->H, aad, aad_len, ctx->X);
        ctx->aad_len = aad_len;
    }

    ctx->data_len = 0;
    return true;
}

// --- Data encryption/decryption update ---
bool ll_AES_GCM_Update(ll_AES_GCM_CTX *ctx,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out, bool encrypt)  {
    if (!ctx) return false;

    // If in_len == 0, do nothing (mimics GMAC)
    if (in_len == 0)
        return true;

    // Length limits (from NIST SP 800‑38D)
    if (in_len > ((U64(0x1) << 36) - 32))
        return false;

    // Ensure non-NULL buffers for non-zero length
    if (!in || !out) return false;

    bool ok = false;

    if (encrypt) {
        if (!ll_AES_GCTR_Process(ctx->key, ctx->ctr, in, in_len, out))
            goto cleanup;
        ll_GHASH_Process(ctx->H, out, in_len, ctx->X);
    } else {
        ll_GHASH_Process(ctx->H, in, in_len, ctx->X);
        if (!ll_AES_GCTR_Process(ctx->key, ctx->ctr, in, in_len, out))
            goto cleanup;
    }

    ctx->data_len += in_len;
    ok = true;

cleanup:
    if (!ok) {
        // Only wipe context on failure
        SECURE_ZERO(ctx, sizeof(*ctx));
    }

    return ok;
}

// --- Final tag computation ---
bool ll_AES_GCM_Final(ll_AES_GCM_CTX *ctx, uint8_t *tag, size_t tag_len) {
    if (!ctx || !tag || !IS_VALID_GCM_TAG_SIZE(tag_len)) return false;

    bool ok = false;

    // Append lengths
    uint8_t len_block[AES_BLOCK_SIZE] = {0};
    uint64_t aad_bits = ctx->aad_len * 8;
    uint64_t data_bits = ctx->data_len * 8;

    for (int i = 0; i < 8; i++)      len_block[i]     = (uint8_t)((aad_bits >> (56 - i*8)) & 0xFF);
    for (int i = 0; i < 8; i++)      len_block[8 + i] = (uint8_t)((data_bits >> (56 - i*8)) & 0xFF);

    for (int i = 0; i < AES_BLOCK_SIZE; i++)
        ctx->X[i] ^= len_block[i];

    ll_gcm_mult(ctx->X, ctx->X, ctx->H);

    // Compute final tag
    uint8_t EK0[AES_BLOCK_SIZE] = {0};
    if (!ll_AES_EncryptBlock(ctx->key, ctx->J0, EK0))
        goto cleanup;

    for (size_t i = 0; i < tag_len && i < AES_BLOCK_SIZE; i++)
        tag[i] = EK0[i] ^ ctx->X[i];

    ok = true;

cleanup:
    SECURE_ZERO(EK0, sizeof(EK0));
    SECURE_ZERO(ctx, sizeof(*ctx)); // force wipe any sensitive data
    return ok;
}