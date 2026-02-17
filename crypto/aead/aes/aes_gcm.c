#include "../../../include/crypto/aes_gcm.h"

void ll_gcm_mult(uint8_t Z[AES_BLOCK_SIZE],
                 const uint8_t X[AES_BLOCK_SIZE],
                 const uint8_t Y[AES_BLOCK_SIZE]) {
    uint64_t zh = 0, zl = 0;

    //Load the 128-bit multiplier Y as two 64-bit words (big-endian)
    uint64_t yh = LOAD64BE(Y);       // high 64 bits
    uint64_t yl = LOAD64BE(Y + 8);   // low 64 bits

    //Perform 128-bit GF(2^128) multiplication using X as the multiplicand
    for (int i = 0; i < 128; i++) {
        //Extract the current bit of X (process from MSB to LSB)
        uint8_t bit = (X[i >> 3] >> (7 - (i & 7))) & 1;

        //Create a mask: 0xFFFFFFFFFFFFFFFF if bit == 1, 0 otherwise
        uint64_t mask = -(int64_t)bit;

        //Conditional XOR: accumulate Y into Z only if current X bit is 1
        zh ^= yh & mask;
        zl ^= yl & mask;

        //Shift Y to the right by 1 bit, apply reduction polynomial if LSB was 1
        uint64_t lsb = yl & 1;
        yl = (yl >> 1) | (yh << 63);                     // shift combined 128-bit value
        yh = (yh >> 1) ^ (U64(0xe100000000000000) & ((uint64_t)0 - lsb));
        //0xe1... is the GHASH reduction polynomial R(x) for GF(2^128)
    }

    //Store the resulting 128-bit GHASH product into Z (big-endian)
    STORE64BE(Z, zh);
    STORE64BE(Z + 8, zl);
}


void ll_GHASH_Process(
    const uint8_t H[AES_BLOCK_SIZE],
    const uint8_t *in, size_t in_len,
    uint8_t out[AES_BLOCK_SIZE]) {
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
    uint32_t val = LOAD32BE(CB + 12);
    val++;
    STORE32BE(CB + 12, val);
}

bool ll_AES_GCTR_Process(
    const ll_AES_KEY *key,
    uint8_t ICB[AES_BLOCK_SIZE],
    const uint8_t *X,
    size_t X_len,
    uint8_t *Y) {
    //Temporary buffers: CB holds the current counter block,
    //encrypted holds the AES-encrypted counter block
    uint8_t CB[AES_BLOCK_SIZE], encrypted[AES_BLOCK_SIZE];

    //Initialize counter block from input ICB
    SECURE_MEMCPY(CB, ICB, AES_BLOCK_SIZE);

    size_t offset = 0;

    //Process full 16-byte blocks
    while (X_len >= AES_BLOCK_SIZE) {
        //Increment counter if this is not the first block
        if (offset > 0)
            Inc32(CB);

        //Encrypt the current counter block with AES
        if (!ll_AES_EncryptBlock(key, CB, encrypted))
            return false;

        //XOR plaintext/ciphertext block with encrypted counter to produce output
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++)
            Y[offset + j] = X[offset + j] ^ encrypted[j];

        offset += AES_BLOCK_SIZE;
        X_len -= AES_BLOCK_SIZE;
    }

    //Process final partial block, if any
    if (X_len > 0) {
        //Encrypt counter block (do not increment, last block)
        if (!ll_AES_EncryptBlock(key, CB, encrypted))
            return false;

        //XOR remaining bytes
        for (size_t j = 0; j < X_len; j++)
            Y[offset + j] = X[offset + j] ^ encrypted[j];
    }

    //Wipe temporary buffers to avoid leaking sensitive data
    SECURE_ZERO(CB, sizeof(CB));
    SECURE_ZERO(encrypted, sizeof(encrypted));

    return true;
}

bool ll_AES_GCM_Init(ll_AES_GCM_CTX *ctx,
                     const ll_AES_KEY *key,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len, bool encrypt) {
    if (!ctx || !key || !iv || !aad)
        return false;

    // Length minimum/limit (from NIST SP 800‑38D)
    if (iv_len < AES_GCM_IV_MIN || aad_len > AES_GCM_AAD_MAX_DATA_LEN)
        return false;

    ctx->isEncrypt = encrypt;
    ctx->key = key;

    //Compute H = AES_K(0^128), used as the GHASH subkey
    uint8_t zero_block[AES_BLOCK_SIZE] = {0};
    if (!ll_AES_EncryptBlock(key, zero_block, ctx->H))
        return false;

    //Prepare the initial counter block J0
    if (iv_len == 12) {
        //For 96-bit IV, append 0x00000001 to form J0
        SECURE_MEMCPY(ctx->J0, iv, 12);
        ctx->J0[12] = 0; ctx->J0[13] = 0; ctx->J0[14] = 0; ctx->J0[15] = 1;
    } else {
        //For non-96-bit IV, GHASH the IV and append length
        uint8_t tmp[AES_BLOCK_SIZE] = {0};
        ll_GHASH_Process(ctx->H, iv, iv_len, tmp);

        uint8_t len_block[AES_BLOCK_SIZE] = {0};
        uint64_t iv_bits = iv_len * 8;
        for (int i = 0; i < 8; i++) len_block[8+i] = (uint8_t)((iv_bits >> (56 - i*8)) & 0xFF);

        ll_GHASH_Process(ctx->H, len_block, AES_BLOCK_SIZE, tmp);

        //Wipe temporary buffers to avoid leaking sensitive data
        SECURE_MEMCPY(ctx->J0, tmp, AES_BLOCK_SIZE);
        SECURE_ZERO(tmp, sizeof(tmp));
        SECURE_ZERO(len_block, sizeof(len_block));
    }

    //Initialize the counter to J0 + 1
    SECURE_MEMCPY(ctx->ctr, ctx->J0, AES_BLOCK_SIZE);
    Inc32(ctx->ctr); // start counter at J0 + 1

    //Clear the running GHASH state
    SECURE_ZERO(ctx->X, sizeof(ctx->X));

    // Process AAD through GHASH
    ll_GHASH_Process(ctx->H, aad, aad_len, ctx->X);

    //Store AAD length — mandatory for final tag computation
    ctx->aad_len = aad_len;

    ctx->data_len = 0;
    return true;
}

bool ll_AES_GCM_Update(ll_AES_GCM_CTX *ctx,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out) {
    if (!ctx || !in || !out)
        return false;

    //Enforce maximum input length per NIST SP 800‑38D
    if (in_len > AES_GCM_MAX_DATA_LEN)
        return false;

    bool ok = false;

    //Encrypt or decrypt input using AES-CTR
    if (ctx->isEncrypt) {
        if (!ll_AES_GCTR_Process(ctx->key, ctx->ctr, in, in_len, out))
            goto cleanup;

        //Update running GHASH with ciphertext
        ll_GHASH_Process(ctx->H, out, in_len, ctx->X);
    } else {
        //Update running GHASH with ciphertext first
        ll_GHASH_Process(ctx->H, in, in_len, ctx->X);

        //Decrypt using AES-CTR
        if (!ll_AES_GCTR_Process(ctx->key, ctx->ctr, in, in_len, out))
            goto cleanup;
    }

    //Update total data length processed — mandatory for final tag computation
    ctx->data_len += in_len;

    ok = true;

cleanup:
    //On failure, wipe context to avoid leaking sensitive data
    if (!ok)
        SECURE_ZERO(ctx, sizeof(*ctx));

    return ok;
}

bool ll_AES_GCM_Final(ll_AES_GCM_CTX *ctx, uint8_t *tag, size_t tag_len) {
    if (!ctx || !tag)
        return false;

    if (!IS_VALID_GCM_TAG_SIZE(tag_len))
        return false;

    bool ok = false;

    //Append lengths of AAD and ciphertext for GHASH finalization
    uint8_t len_block[AES_BLOCK_SIZE] = {0};
    uint64_t aad_bits = ctx->aad_len * 8;
    uint64_t data_bits = ctx->data_len * 8;

    //Store AAD length in the first 8 bytes
    for (int i = 0; i < 8; i++)
        len_block[i] = (uint8_t)((aad_bits >> (56 - i*8)) & 0xFF);

    //Store data length in the next 8 bytes
    for (int i = 0; i < 8; i++)
        len_block[8 + i] = (uint8_t)((data_bits >> (56 - i*8)) & 0xFF);

    //XOR lengths into running GHASH state
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
        ctx->X[i] ^= len_block[i];

    //Multiply GHASH state by H to finalize
    ll_gcm_mult(ctx->X, ctx->X, ctx->H);

    //Encrypt J0 to produce the mask for the tag
    uint8_t EK0[AES_BLOCK_SIZE] = {0};
    if (!ll_AES_EncryptBlock(ctx->key, ctx->J0, EK0))
        goto cleanup;

    if (ctx->isEncrypt) {
        // --- Encryption: write the computed tag ---
        for (size_t i = 0; i < tag_len && i < AES_BLOCK_SIZE; i++)
            tag[i] = EK0[i] ^ ctx->X[i];
    } else {
        // --- Decryption: verify tag ---
        uint8_t computed_tag[AES_BLOCK_SIZE];
        for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
            computed_tag[i] = EK0[i] ^ ctx->X[i];

        //Constant-time comparison
        ok = SECURE_MEM_EQUAL(computed_tag, tag, tag_len);

        //tag with computed value for consistency
        SECURE_MEMCPY(tag, computed_tag, tag_len);

        goto cleanup; // skip setting ok = true below
    }

    ok = true;

cleanup:
    //Wipe temporary buffers and context to avoid leaking sensitive data
    SECURE_ZERO(EK0, sizeof(EK0));
    SECURE_ZERO(ctx, sizeof(*ctx));
    return ok;
}