/*
 * CryptoForge - evp_utils.h / EVP Layer Utilities
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "evp_utils.h"

int EVP_IsEqual(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b)
        return CF_ERR_NULL_PTR;
    if (len == 0)
        return CF_ERR_INVALID_LEN;

    // constant-time equality
    return SECURE_MEM_EQUAL(a, b, len) ? 1 : 0;
}

int EVP_CompareLex(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b)
        return CF_ERR_NULL_PTR;
    if (len == 0)
        return CF_ERR_INVALID_LEN;

    // lexicographical comparison
    return SECURE_MEM_CMP_LEX(a, b, len);
}
