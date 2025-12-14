#include "aes_modes.h"

/*
 * SP 800-38A plaintext sizing rules:
 *
 * - ECB / CBC:
 *   Plaintext length MUST be an exact multiple of the block size
 *   (AES block size = 128 bits). No partial blocks without padding.
 *
 * - CFB:
 *   Plaintext length MUST be a multiple of the segment size (s bits).
 *   Ciphertext is produced per segment (CFB-s), not per full block.
 *
 * - OFB / CTR:
 *   Plaintext may end with a partial block.
 *   No padding is required; the final block may be truncated.
 *
 * Note:
 * AES always operates on full 128-bit blocks internally.
 * Segments and partial blocks are handled at the mode level.
 */

/*
 * Initialization Vector (IV) rules for CBC, CFB, and OFB modes:
 *
 * - The encryption input includes the plaintext AND a data block called the IV.
 * - The IV is used in the initial step of encryption and in the corresponding decryption.
 *
 * - IV secrecy:
 *   The IV does NOT need to be secret. 
 *
 * - IV requirements per mode:
 *   * CBC and CFB: IV must be unpredictable for each execution.
 *   * OFB: IV must be unique for each execution (reusing an IV can compromise security).
 *
 * Note:
 * Proper IV generation is critical for security.
 * See SP 800-38A Appendix C for recommended IV generation methods.
*/

bool ll_AES_ECB_Encrypt(const AES_KEY *key, const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !in || (in_len % AES_BLOCK_SIZE) != 0 || !out) return false; 

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        if (!ll_AES_EncryptBlock(key, in + i, out + i)) return false;
    }

    return true;
}

bool ll_AES_ECB_Decrypt(const AES_KEY *key, const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !in || (in_len % AES_BLOCK_SIZE) != 0 || !out) return false; 

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        if (!ll_AES_DecryptBlock(key, in + i, out + i)) return false;
    }

    return true;
}