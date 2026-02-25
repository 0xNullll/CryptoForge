/*
 * CryptoForge - cf_utils.h / CryptoForge API Layer Utilities
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
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

/* 
 * CF_Compare
 *
 * Performs a constant-time comparison of two buffers.
 * Returns:
 *   1  if the buffers are equal
 *   0  if the buffers are not equal
 *  <0  if an error occurs (CF_ERR_* code)
 *
 * Parameters:
 *   a   - pointer to the first buffer
 *   b   - pointer to the second buffer
 *   len - length of the buffers
 */
CF_API int CF_Compare(const uint8_t *a, const uint8_t *b, size_t len);

/* 
 * CF_CompareLex
 *
 * Performs a constant-time lexicographical comparison of two buffers.
 * Returns:
 *  -1 if a < b
 *   0 if a == b
 *   1 if a > b
 *  <0 if an error occurs (CF_ERR_* code)
 *
 * Parameters:
 *   a   - pointer to the first buffer
 *   b   - pointer to the second buffer
 *   len - length of the buffers
 */
CF_API int CF_CompareLex(const uint8_t *a, const uint8_t *b, size_t len);

/* 
 * CF_EntropyFromOS
 *
 * Fills a buffer with cryptographic-quality entropy from the operating system.
 * On Linux, uses getrandom() if available, falling back to /dev/urandom.
 * On Windows, uses BCryptGenRandom.
 *
 * Returns CF_SUCCESS on success, or a CF_ERR_* code on failure:
 *   CF_ERR_NULL_PTR - if buf is NULL or len is zero
 *   CF_ERR_OS_FAIL  - if the OS entropy source failed
 *
 * Parameters:
 *   buf - pointer to buffer to fill with entropy
 *   len - number of bytes to generate
 */
CF_API CF_STATUS CF_EntropyFromOS(uint8_t *buf, size_t len);

#endif // CF_UTILS_H