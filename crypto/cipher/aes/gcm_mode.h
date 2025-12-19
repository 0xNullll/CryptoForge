#ifndef GCM_MODE_H
#define GCM_MODE_H

#include "../../../utils/mem.h"
#include "../../../utils/misc_utils.h"
#include "../../../config/libs.h"

#include "../aes/aes_core.h"
#include "../../mac/ghash.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * AES-GCM (Galois/Counter Mode)
 *
 * - AEAD mode: encryption + authentication
 * - IV must be UNIQUE per key (96-bit recommended)
 * - No padding (CTR-based)
 * - Tag verification MUST be constant-time
 *
 * Security notes:
 *  - IV reuse is catastrophic
 *  - Tag verification failure MUST invalidate plaintext
 */

/* Recommended IV size (per NIST SP 800-38D) */
#define AES_GCM_IV_MIN   12

#define AES_GCM_TAG_SIZE_4   4    // 32-bit tag
#define AES_GCM_TAG_SIZE_8   8    // 64-bit tag
#define AES_GCM_TAG_SIZE_12 12    // 96-bit tag (recommended default)
#define AES_GCM_TAG_SIZE_16 16    // 128-bit tag (maximum)
#define AES_GCM_TAG_SIZE_DEFAULT AES_GCM_TAG_SIZE_16  // default tag size

bool ll_AES_GCM_Encrypt(
    const AES_KEY *key,
    const uint8_t *iv,
    size_t iv_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    uint8_t *tag,
    size_t tag_len
);

bool ll_AES_GCM_Decrypt(
    const AES_KEY *key,
    const uint8_t *iv,
    size_t iv_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *in,
    size_t in_len,
    const uint8_t *tag,
    size_t tag_len,
    uint8_t *out
);

#ifdef __cplusplus
}
#endif

#endif // GCM_MODE_H