/*
 * CryptoForge - cf_utils.c / CryptoForge API Layer Utilities
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../include/cf_api/cf_utils.h"

int CF_IsEqual(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b)
        return CF_ERR_NULL_PTR;
    if (len == 0)
        return CF_ERR_INVALID_LEN;

    // constant-time equality
    return SECURE_MEM_EQUAL(a, b, len) ? 1 : 0;
}

int CF_CompareLex(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b)
        return CF_ERR_NULL_PTR;
    if (len == 0)
        return CF_ERR_INVALID_LEN;

    // lexicographical comparison
    return SECURE_MEM_CMP_LEX(a, b, len);
}

CF_STATUS CF_Pad_Apply(uint8_t *buf, size_t buf_len, size_t data_len,
                              size_t block_size, CF_PADDING_TYPE type) {
    return CF_ERR_UNKNOWN;
}

CF_STATUS CF_Pad_Remove(uint8_t *buf, size_t buf_len, size_t *data_len,
                               size_t block_size, CF_PADDING_TYPE type) {
    return CF_ERR_UNKNOWN;
}