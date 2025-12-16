#include "ctr_mode.h"

bool ll_AES_CTR_Crypt(
    const AES_KEY *key,
    uint8_t counter[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);