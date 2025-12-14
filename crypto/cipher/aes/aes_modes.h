#ifndef AES_MODES_H
#define AES_MODES_H

#include "../../../utils/mem.h"
#include "../../../utils/misc_utils.h"
#include "../../../config/libs.h"
#include "aes_core.h"

#ifdef __cplusplus
extern "C" {
#endif

// ------------------------
// ECB Mode
// ------------------------
bool ll_AES_ECB_Encrypt(
    const AES_KEY *key,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_ECB_Decrypt(
    const AES_KEY *key,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

// ------------------------
// CBC Mode
// ------------------------
bool ll_AES_CBC_Encrypt(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_CBC_Decrypt(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

// ------------------------
// CFB Mode
// ------------------------
bool ll_AES_CFB_Encrypt(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_CFB_Decrypt(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

// ------------------------
// OFB Mode
// ------------------------
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

// ------------------------
// CTR Mode
// ------------------------
bool ll_AES_CTR_Crypt(
    const AES_KEY *key,
    uint8_t counter[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

#ifdef __cplusplus
}
#endif

#endif // AES_MODES_H