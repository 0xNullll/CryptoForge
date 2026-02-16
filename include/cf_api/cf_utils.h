/*
 * CryptoForge - cf_utils.h / CryptoForge API Layer Utilities
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef CF_UTILS_H
#define CF_UTILS_H

#include "../config/libs.h"
#include "../utils/mem.h"
#include "../utils/cf_status.h"

#include "cf_flags.h"

/**
 * @brief Constant-time hash comparison
 * 
 * Returns 1 if the buffers are equal, 0 if not, or a CF_ERR_* code on error.
 * @param a Pointer to first buffer
 * @param b Pointer to second buffer
 * @param len Length of buffers
 * @return int 1 = equal, 0 = not equal, <0 = error
 */
CF_API int CF_IsEqual(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * @brief Constant-time lexicographical comparison
 * 
 * Compares two buffers byte-wise, in constant time.
 * Returns:
 *   -1 if a < b,
 *    0 if a == b,
 *    1 if a > b,
 * or a CF_ERR_* code on error.
 * @param a Pointer to first buffer
 * @param b Pointer to second buffer
 * @param len Length of buffers
 * @return int Comparison result or error code
 */
CF_API int CF_CompareLex(const uint8_t *a, const uint8_t *b, size_t len);

// ========================
// Padding Helpers
// ========================
CF_API CF_STATUS CF_Pad_Apply(uint8_t *buf, size_t buf_len, size_t data_len,
                              size_t block_size, CF_PADDING_TYPE type);

CF_API CF_STATUS CF_Pad_Remove(uint8_t *buf, size_t buf_len, size_t *data_len,
                               size_t block_size, CF_PADDING_TYPE type);

#endif // CF_UTILS_H