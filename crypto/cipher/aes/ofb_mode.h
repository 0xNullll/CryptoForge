#ifndef OFB_MODE_H
#define OFB_MODE_H

#include "../../../utils/mem.h"
#include "../../../utils/misc_utils.h"
#include "../../../config/libs.h"
#include "aes_core.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// IV must be UNIQUE, randomness optional, no padding. Generates keystream; repeating IV = keystream reuse (catastrophic).
//

bool ll_AES_OFB_Encrypt(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_OFB_Decrypt(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

#ifdef __cplusplus
}
#endif

#endif // OFB_MODE_H