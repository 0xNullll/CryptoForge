#ifndef CBC_MODE_H
#define CBC_MODE_H

#include "../../../utils/mem.h"
#include "../../../utils/misc_utils.h"
#include "../../../config/libs.h"

#include "aes_core.h"
#include "aes_common.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// IV must be UNPREDICTABLE, padding needed. C[i] = E(P[i] XOR C[i-1]); first block leaks if IV predictable.
//

bool ll_AES_CBC_Encrypt(
    const ll_AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_CBC_Decrypt(
    const ll_AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

#ifdef __cplusplus
}
#endif

#endif // CBC_MODE_H