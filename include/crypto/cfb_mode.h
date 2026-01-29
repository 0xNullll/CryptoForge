#ifndef CFB_MODE_H
#define CFB_MODE_H

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../config/libs.h"

#include "aes_core.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// IV must be UNPREDICTABLE, no padding needed. Converts block cipher to stream; first block sensitive to IV.
//

bool ll_AES_CFB8_Encrypt(
    const ll_AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_CFB8_Decrypt(
    const ll_AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_CFB128_Encrypt(
    const ll_AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_CFB128_Decrypt(
    const ll_AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

#ifdef __cplusplus
}
#endif

#endif // CFB_MODE_H