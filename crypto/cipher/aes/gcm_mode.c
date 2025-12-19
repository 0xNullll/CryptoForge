#include "gcm_mode.h"

static FORCE_INLINE void Inc32(uint8_t counter[AES_BLOCK_SIZE]) {
    // Increment last 32 bits (big-endian) modulo 2^32
    for (int i = 15; i >= 12; i--) {
        if (++counter[i] != 0)
            break;  
    }
}

