/*
 * CryptoForge - cbc_mode.c / AES-CBC Implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "../../../internal/crypto/cbc_mode.h"

static size_t ll_pkcs7_pad(uint8_t *buf, size_t buf_len, size_t data_len, size_t block_size) {
    size_t pad_len = block_size - (data_len % block_size);
    if (buf_len < data_len + pad_len)
        return 0; // still need this check

    // Constant-time fill
    uint8_t pad_byte = (uint8_t)pad_len;
    for (size_t i = 0; i < pad_len; i++) {
        buf[data_len + i] = pad_byte;
    }

    return data_len + pad_len;
}

static size_t ll_pkcs7_unpad(uint8_t *buf, size_t buf_len) {
    if (buf_len == 0) return 0;

    uint8_t pad_len = buf[buf_len - 1];

    // Reject obviously invalid values (still safe)
    if (pad_len == 0 || pad_len > AES_BLOCK_SIZE || pad_len > buf_len) return 0;

    // Constant-time check of all padding bytes
    uint8_t bad = 0;
    for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
        // Only check bytes within pad_len
        uint8_t mask = (i < pad_len) ? 0xFF : 0x00;
        bad |= (buf[buf_len - 1 - i] ^ pad_len) & mask;
    }

    // If any byte was bad, return 0
    size_t out_len = buf_len - pad_len;
    return (bad == 0) ? out_len : 0;
}

bool ll_AES_CBC_Encrypt(
    const ll_AES_KEY *key,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out) {
    if (!key || !iv || !in || !out || (in_len % AES_BLOCK_SIZE) != 0)
        return false;

    bool ok = false;

    uint8_t prev[AES_BLOCK_SIZE] = {0};
    SECURE_MEMCPY(prev, iv, AES_BLOCK_SIZE);

    uint8_t block[AES_BLOCK_SIZE]; // temporary encrypt block

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        // XOR with previous ciphertext (CBC step)
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++)
            block[j] = in[i + j] ^ prev[j];

        // Encrypt the block
        if (!ll_AES_EncryptBlock(key, block, out + i)) goto cleanup;
        
        // Update prev to current ciphertext
        SECURE_MEMCPY(prev, out + i, AES_BLOCK_SIZE);
    }

    ok = true;

cleanup:
    SECURE_ZERO(prev, sizeof(prev));
    SECURE_ZERO(block, sizeof(block));

    return ok;
}

bool ll_AES_CBC_Decrypt(
    const ll_AES_KEY *key,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out) {
    if (!key || !iv || !in || !out || (in_len % AES_BLOCK_SIZE) != 0) return false;

    bool ok = false;

    uint8_t prev[AES_BLOCK_SIZE] = {0};
    SECURE_MEMCPY(prev, iv, AES_BLOCK_SIZE);

    uint8_t block[AES_BLOCK_SIZE] = {0}; // temporary decrypted block

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        // Decrypt ciphertext block into temporary buffer
        if (!ll_AES_DecryptBlock(key, in + i, block)) goto cleanup;

        // XOR with previous ciphertext (CBC step)
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++)
            out[i + j] = block[j] ^ prev[j];
    
        // Update prev to current ciphertext
        SECURE_MEMCPY(prev, in + i, AES_BLOCK_SIZE);
    }

    ok = true;

cleanup:
    SECURE_ZERO(prev, sizeof(prev));
    SECURE_ZERO(block, sizeof(block));

    return ok;
}

bool ll_AES_CBC_Encrypt_PKCS7(
    const ll_AES_KEY *key,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    size_t *out_len) {
    if (!key || !iv || !in || !out || !out_len) return false;

    size_t full_blocks = in_len / AES_BLOCK_SIZE;
    size_t rem = in_len % AES_BLOCK_SIZE;

    uint8_t prev[AES_BLOCK_SIZE];
    SECURE_MEMCPY(prev, iv, AES_BLOCK_SIZE);

    uint8_t block[AES_BLOCK_SIZE];

    // Encrypt all full blocks
    for (size_t i = 0; i < full_blocks * AES_BLOCK_SIZE; i += AES_BLOCK_SIZE) {
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++)
            block[j] = in[i + j] ^ prev[j];

        if (!ll_AES_EncryptBlock(key, block, out + i)) return false;
        SECURE_MEMCPY(prev, out + i, AES_BLOCK_SIZE);
    }

    // Prepare last block with PKCS7 padding
    uint8_t last_block[AES_BLOCK_SIZE] = {0};
    size_t last_len = rem ? rem : 0;
    if (rem) SECURE_MEMCPY(last_block, in + full_blocks * AES_BLOCK_SIZE, rem);

    size_t padded_len = ll_pkcs7_pad(last_block, AES_BLOCK_SIZE, last_len, AES_BLOCK_SIZE);
    if (padded_len == 0) return false;

    // Encrypt padded last block
    for (size_t j = 0; j < AES_BLOCK_SIZE; j++)
        block[j] = last_block[j] ^ prev[j];

    if (!ll_AES_EncryptBlock(key, block, out + full_blocks * AES_BLOCK_SIZE)) return false;

    SECURE_ZERO(prev, sizeof(prev));
    SECURE_ZERO(block, sizeof(block));
    SECURE_ZERO(last_block, sizeof(last_block));

    *out_len = padded_len;

    return true;
}

bool ll_AES_CBC_Decrypt_PKCS7(
    const ll_AES_KEY *key,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    size_t *out_len) {
    if (!key || !iv || !in || !out  || !out_len || (in_len % AES_BLOCK_SIZE) != 0) return false;

    uint8_t prev[AES_BLOCK_SIZE];
    SECURE_MEMCPY(prev, iv, AES_BLOCK_SIZE);

    uint8_t block[AES_BLOCK_SIZE];
    uint8_t tmp[AES_BLOCK_SIZE];

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        if (!ll_AES_DecryptBlock(key, in + i, tmp)) return false;

        for (size_t j = 0; j < AES_BLOCK_SIZE; j++)
            block[j] = tmp[j] ^ prev[j];

        SECURE_MEMCPY(prev, in + i, AES_BLOCK_SIZE);
        SECURE_MEMCPY(out + i, block, AES_BLOCK_SIZE);
    }

    // Remove PKCS7 padding in-place
    size_t unpadded_len = ll_pkcs7_unpad(out, in_len);
    *out_len = unpadded_len;

    return true;
}