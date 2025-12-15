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


bool ll_AES_CBC_Encrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !iv || !in || (in_len % AES_BLOCK_SIZE) != 0 || !out) return false; 

    uint8_t x[AES_BLOCK_SIZE];

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            // XOR with previous ciphertext block (or IV for first block)
            x[j] = in[i + (size_t)j] ^ (i == 0 ? iv[j] : out[i - AES_BLOCK_SIZE + (size_t)j]);
        }

        // Encrypt current ciphertext block
        if (!ll_AES_EncryptBlock(key, x, out + i)) return false;
    }

    return true;
}

bool ll_AES_CBC_Decrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !iv || !in || (in_len % AES_BLOCK_SIZE) != 0 || !out) return false; 

    uint8_t x[AES_BLOCK_SIZE];      // temporary buffer for decrypted block
    uint8_t prev[AES_BLOCK_SIZE];   // previous ciphertext (or IV)

    SECURE_MEMCPY(prev, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        // Decrypt current ciphertext block
        if (!ll_AES_DecryptBlock(key, in + i, x)) return false;

        // XOR with previous ciphertext block (or IV for first block)
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            out[i + (size_t)j] = x[j] ^ prev[j];
        }

        // Update prev for next block
        SECURE_MEMCPY(prev, in + i, AES_BLOCK_SIZE);
    }

    return true;
}


static bool ll_AES_CFB1_Process(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bits, uint8_t *out, bool enc) {
    if (!key || !iv || !in || !out) return false;

    uint8_t feedback[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];
    SECURE_MEMCPY(feedback, iv, AES_BLOCK_SIZE);

    for (size_t n = 0; n < in_len_bits; n++) {
        // Extract input bit (MSB first)
        uint8_t in_bit = (in[n / 8] >> (7 - (n % 8))) & 1;

        // Encrypt current feedback block
        if (!ll_AES_EncryptBlock(key, feedback, block)) return false;

        // MSB of AES output
        uint8_t msb = block[0] >> 7;

        uint8_t out_bit;
        if (enc) {
            out_bit = in_bit ^ msb;
            // Feedback updated with ciphertext bit
            for (int i = 0; i < AES_BLOCK_SIZE; i++) {
                uint8_t next = (i + 1 < AES_BLOCK_SIZE) ? (feedback[i + 1] >> 7) : 0;
                feedback[i] = (feedback[i] << 1) | next;
            }
            feedback[AES_BLOCK_SIZE - 1] |= out_bit;
        } else {
            out_bit = in_bit ^ msb;
            // Feedback updated with ciphertext bit
            for (int i = 0; i < AES_BLOCK_SIZE; i++) {
                uint8_t next = (i + 1 < AES_BLOCK_SIZE) ? (feedback[i + 1] >> 7) : 0;
                feedback[i] = (feedback[i] << 1) | next;
            }
            feedback[AES_BLOCK_SIZE - 1] |= in_bit;
        }

        // Write output bit (MSB first)
        out[n / 8] &= ~(1 << (7 - (n % 8)));        // clear bit
        out[n / 8] |= (out_bit << (7 - (n % 8)));   // set bit
    }

    return true;
}

static bool ll_AES_CFB8_Process( const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bytes, uint8_t *out, bool enc) {
    if (!key || !iv || !in || !out) return false;

    uint8_t feedback[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];
    SECURE_MEMCPY(feedback, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < in_len_bytes; i++) {
        // Encrypt current feedback block
        if (!ll_AES_EncryptBlock(key, feedback, block)) return false;

        uint8_t out_byte;
        if (enc) {
            // Encrypt: XOR plaintext byte with first byte of AES output
            out_byte = in[i] ^ block[0];

            // Shift feedback left by 1 byte and append ciphertext byte
            memmove(feedback, feedback + 1, AES_BLOCK_SIZE - 1);
            feedback[AES_BLOCK_SIZE - 1] = out_byte;
        } else {
            // Decrypt: XOR ciphertext byte with first byte of AES output
            out_byte = in[i] ^ block[0];

            // Shift feedback left by 1 byte and append ciphertext byte
            memmove(feedback, feedback + 1, AES_BLOCK_SIZE - 1);
            feedback[AES_BLOCK_SIZE - 1] = in[i];  // feedback always gets ciphertext
        }

        out[i] = out_byte;
    }

    return true;
}

static bool ll_AES_CFB128_Process(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bytes, uint8_t *out, bool enc) {
    if (!key || !iv || !in || !out) return false;

    uint8_t feedback[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];
    SECURE_MEMCPY(feedback, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < in_len_bytes; i++) {
        // Encrypt current feedback block
        if (!ll_AES_EncryptBlock(key, feedback, block)) return false;

        uint8_t out_byte;
        if (enc) {
            // Encryption: XOR plaintext with AES(feedback)
            out_byte = in[i] ^ block[0];
            feedback[i % AES_BLOCK_SIZE] = out_byte;  // feedback updated with ciphertext
        } else {
            // Decryption: XOR ciphertext with AES(feedback)
            out_byte = in[i] ^ block[0];
            feedback[i % AES_BLOCK_SIZE] = in[i];      // feedback updated with ciphertext
        }

        out[i] = out_byte;

        // Shift feedback block left by 1 byte if needed
        if ((i + 1) % AES_BLOCK_SIZE == 0) {
            // Move to next block of feedback
            memmove(feedback, feedback + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        }
    }

    return true;
}

bool ll_AES_CFB1_Encrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
        return ll_AES_CFB1_Process(key, iv, in, in_len, out, true);
}

bool ll_AES_CFB1_Decrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
        return ll_AES_CFB1_Process(key, iv, in, in_len, out, false);
}

bool ll_AES_CFB_Encrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !iv || !in || !out) return false;
    if (in_len == 0) return true;

    if (in_len < AES_BLOCK_SIZE) {
        return ll_AES_CFB8_Process(key, iv, in, in_len, out, true);
    }

    return ll_AES_CFB128_Process(key, iv, in, in_len, out, true);
}

bool ll_AES_CFB_Decrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !iv || !in || !out) return false;
    if (in_len == 0) return true;

    if (in_len < AES_BLOCK_SIZE) {
        return ll_AES_CFB8_Process(key, iv, in, in_len, out, false);
    }

    return ll_AES_CFB128_Process(key, iv, in, in_len, out, false);
}


static bool ll_AES_OFB1_Process(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bits, uint8_t *out) {
    if (!key || !iv || !in || !out) return false;

    uint8_t state[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];
    SECURE_MEMCPY(state, iv, AES_BLOCK_SIZE);

    for (size_t bit_idx = 0; bit_idx < in_len_bits; bit_idx++) {

        // Generate AES block if needed
        if (bit_idx % 8 == 0) {
            if (!ll_AES_EncryptBlock(key, state, block)) return false;

            // OFB feedback = AES output
            SECURE_MEMCPY(state, block, AES_BLOCK_SIZE);
        }

        // Extract the next plaintext bit (MSB first)
        uint8_t in_byte = in[bit_idx / 8];
        uint8_t in_bit  = (in_byte >> (7 - (bit_idx % 8))) & 1;

        // Take the MSB of current keystream block
        uint8_t ks_bit  = (block[0] >> 7) & 1;

        // XOR to get output bit
        uint8_t out_bit = in_bit ^ ks_bit;

        // Write the bit into output byte (MSB first)
        out[bit_idx / 8] &= ~(1 << (7 - (bit_idx % 8)));    // clear bit
        out[bit_idx / 8] |= out_bit << (7 - (bit_idx % 8));

        // Shift state left by 1 bit, append keystream bit
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            uint8_t next = (i + 1 < AES_BLOCK_SIZE) ? (state[i + 1] >> 7) : 0;
            state[i] = (state[i] << 1) | next;
        }
        state[AES_BLOCK_SIZE - 1] |= ks_bit;
    }

    return true;
}

static bool ll_AES_OFB8_Process(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bytes, uint8_t *out) {
    if (!key || !iv || !in || !out) return false;

    uint8_t state[AES_BLOCK_SIZE];
    uint8_t keystream[AES_BLOCK_SIZE];
    SECURE_MEMCPY(state, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < in_len_bytes; i++) {
        // Encrypt current state to produce keystream block
        if (!ll_AES_EncryptBlock(key, state, keystream)) return false;

        // XOR next byte
        out[i] = in[i] ^ keystream[0];

        // Shift state left by 1 byte and append keystream byte
        for (int j = 0; j < AES_BLOCK_SIZE - 1; j++) {
            state[j] = state[j + 1];
        }
        state[AES_BLOCK_SIZE - 1] = keystream[0];
    }

    return true;
}

static bool ll_AES_OFB128_Process(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bytes, uint8_t *out) {
    if (!key || !iv || !in || !out) return false;

    uint8_t state[AES_BLOCK_SIZE];
    uint8_t keystream[AES_BLOCK_SIZE];
    size_t used = 0;

    SECURE_MEMCPY(state, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < in_len_bytes; i++) {
        // Generate AES block if needed
        if (used == 0) {
            if (!ll_AES_EncryptBlock(key, state, keystream)) return false;
            SECURE_MEMCPY(state, keystream, AES_BLOCK_SIZE);  // OFB feedback
        }

        // XOR one byte
        out[i] = in[i] ^ keystream[used];
        used = (used + 1) % AES_BLOCK_SIZE;
    }

    return true;
}

bool ll_AES_OFB1_Encrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bits, uint8_t *out) {
    return ll_AES_OFB1_Process(key, iv, in, in_len_bits, out);
}

bool ll_AES_OFB1_Decrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bits, uint8_t *out) {
    return ll_AES_OFB1_Process(key, iv, in, in_len_bits, out);
}

bool ll_AES_OFB_Encrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !iv || !in || !out) return false;
    if (in_len == 0) return true;

    if (in_len < AES_BLOCK_SIZE) {
        return ll_AES_OFB8_Process(key, iv, in, in_len, out);
    }

    return ll_AES_OFB128_Process(key, iv, in, in_len, out);
}

bool ll_AES_OFB_Decrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !iv || !in || !out) return false;
    if (in_len == 0) return true;

    if (in_len < AES_BLOCK_SIZE) {
        return ll_AES_OFB8_Process(key, iv, in, in_len, out);
    }

    return ll_AES_OFB128_Process(key, iv, in, in_len, out);
}
