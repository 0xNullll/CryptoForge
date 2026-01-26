#ifndef AES_CORE_H
#define AES_CORE_H

#include "../../../utils/mem.h"
#include "../../../utils/misc_utils.h"
#include "../../../config/libs.h"

#include "aes_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE   16
#define AES_128_KEY_SIZE 16
#define AES_192_KEY_SIZE 24
#define AES_256_KEY_SIZE 32
#define AES_MAX_KEY_SIZE 32

#define AES_128_ROUNDS 10
#define AES_192_ROUNDS 12
#define AES_256_ROUNDS 14
#define AES_MAX_ROUND 14

// Round up length to next AES_BLOCK_SIZE multiple
#define AES_CIPHER_SIZE(len) (((len) + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE)

typedef struct {
    uint32_t rk[4 * (AES_MAX_ROUND + 1)];  // max size for AES-256
    uint32_t Nr;                           // number of rounds
} ll_AES_KEY;

bool ll_AES_SetEncryptKey(ll_AES_KEY *key, const uint8_t *userKey, size_t UserkeySize);
bool ll_AES_SetDecryptKey(ll_AES_KEY *key, const uint8_t *userKey, size_t UserkeySize);

bool ll_AES_EncryptBlock(const ll_AES_KEY *key, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);
bool ll_AES_DecryptBlock(const ll_AES_KEY *key, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);

#ifdef __cplusplus
}
#endif


#endif // AES_CORE_H