/*
 * CryptoForge - cf_utils.c / CryptoForge API Layer Utilities
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
