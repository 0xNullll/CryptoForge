#ifndef CRYPTO_CONFIG_H
#define CRYPTO_CONFIG_H

// ------------------------
// High-level module flags
// ------------------------
#ifndef ENABLE_SHA
#define ENABLE_SHA 1         // full SHA family: SHA1 + SHA2 + SHA3 + SHAKE + Keccak
#endif

#ifndef ENABLE_SHA3
#define ENABLE_SHA3 0        // SHA3 + SHAKE + raw Keccak only (exclude SHA1/SHA2)
#endif

#ifndef ENABLE_HMAC
#define ENABLE_HMAC 1        // enable HMAC/KMAC
#endif

#ifndef ENABLE_TESTS
#define ENABLE_TESTS 1       // enable demo/test code
#endif

// ------------------------
// Automatic dependency handling
// ------------------------
#if ENABLE_HMAC && !(ENABLE_SHA || ENABLE_SHA3)
  #undef ENABLE_SHA
  #define ENABLE_SHA 1
#endif

// ------------------------
// Function name prefix support
// ------------------------
#ifndef TSHASH_PREFIX
#define TSHASH_PREFIX
#endif

#define _TS_CAT(a,b) a##b
#define _TS_CAT2(a,b) _TS_CAT(a,b)
#define TSHASH_FN(name) _TS_CAT2(TSHASH_PREFIX, name)

// ------------------------
// Endianness detection
// ------------------------
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define CPU_BIG_ENDIAN 1
#elif defined(_BIG_ENDIAN) || defined(__BIG_ENDIAN__) || defined(__ARMEB__) || defined(__MIPSEB__)
#define CPU_BIG_ENDIAN 1
#else
#define CPU_BIG_ENDIAN 0
#endif

#endif // CRYPTO_CONFIG_H