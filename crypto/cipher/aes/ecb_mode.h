#ifndef ECB_MODE_H
#define ECB_MODE_H

#include "../../../utils/mem.h"
#include "../../../utils/misc_utils.h"
#include "../../../config/libs.h"
#include "aes_core.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// No IV, padding needed if plaintext not multiple of block. Independent blocks, patterns leak.
//

bool ll_AES_ECB_Encrypt(
    const ll_AES_KEY *key,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_ECB_Decrypt(
    const ll_AES_KEY *key,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

#ifdef __cplusplus
}
#endif

#endif // ECB_MODE_H