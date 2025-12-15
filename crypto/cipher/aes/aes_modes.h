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
// CFB1 Mode (bitwise)
// ------------------------

// Internal helper for CFB1
bool ll_AES_CFB1_Process(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len_bits,
    uint8_t *out,
    bool enc
);

bool ll_AES_CFB1_Encrypt(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len_bytes,
    uint8_t *out
);

bool ll_AES_CFB1_Decrypt(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len_bytes,
    uint8_t *out
);

// ------------------------
// CFB8 Mode (bytewise)
// ------------------------

// Internal helper for CFB8
bool ll_AES_CFB8_Process(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in, size_t in_len_bytes,
    uint8_t *out,
    bool enc
);

bool ll_AES_CFB8_Encrypt(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_CFB8_Decrypt(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

// ------------------------
// CFB128 Mode (full block)
// ------------------------

// Internal helper for CFB128
bool ll_AES_CFB128_Process(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in, size_t in_len_bytes,
    uint8_t *out,
    bool enc
);

bool ll_AES_CFB128_Encrypt(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_CFB128_Decrypt(
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