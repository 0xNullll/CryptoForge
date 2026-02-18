/*
 * CryptoForge - cf_utils.c / CryptoForge API Layer Utilities
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

#include "../../include/cf_api/cf_utils.h"

int CF_Compare(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b)
        return CF_ERR_NULL_PTR;
        
    if (len == 0)
        return 1;

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