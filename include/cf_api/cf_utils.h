/*
 * CryptoForge - cf_utils.h / CryptoForge API Layer Utilities
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