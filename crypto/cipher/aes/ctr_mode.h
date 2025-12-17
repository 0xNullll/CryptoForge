#ifndef CTR_MODE_H
#define CTR_MODE_H

#include "../../../utils/mem.h"
#include "../../../utils/misc_utils.h"
#include "../../../config/libs.h"
#include "aes_core.h"

#ifdef __cplusplus
extern "C" {
#endif

bool ll_AES_CTR_Encrypt(
    const AES_KEY *key,
    uint8_t counter[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_CTR_Decrypt(
    const AES_KEY *key,
    uint8_t counter[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

#ifdef __cplusplus
}
#endif

#endif // CTR_MODE_H