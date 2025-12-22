/*
 * CryptoForge - evp_utils.h / EVP Layer Utilities
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the MIT License along with this program.
 * If not, see <https://opensource.org/licenses/MIT>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef EVP_UTILS_H
#define EVP_UTILS_H

#include "../../config/libs.h"
#include "../../utils/mem.h"
#include "../../utils/cf_status.h"
#include "evp_defs.h"

/**
 * @brief Constant-time hash comparison
 * 
 * Returns 1 if the buffers are equal, 0 if not, or a CF_ERR_* code on error.
 * @param a Pointer to first buffer
 * @param b Pointer to second buffer
 * @param len Length of buffers
 * @return int 1 = equal, 0 = not equal, <0 = error
 */
CF_API int EVP_IsEqual(const uint8_t *a, const uint8_t *b, size_t len);

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
CF_API int EVP_CompareLex(const uint8_t *a, const uint8_t *b, size_t len);

#endif // EVP_UTILS_H