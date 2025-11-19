#ifndef CRYPTO_CONFIG_H
#define CRYPTO_CONFIG_H

// ------------------------
// Feature Flags
// Users can define these as 0 (disable) or 1 (enable)
// before including the header, or via compiler -D flags.
// ------------------------

// ------------------------
// Function name prefix support
// ------------------------
#ifndef TSHASH_PREFIX
#define TSHASH_PREFIX // empty by default
#endif

#define _TS_CAT(a,b) a##b
#define _TS_CAT2(a,b) _TS_CAT(a,b)
#define TSHASH_FN(name) _TS_CAT2(TSHASH_PREFIX, name)

// ========================
// SHA-1 / SHA-2 variants
// ========================
#ifndef ENABLE_SHA1
#define ENABLE_SHA1 1          // enable SHA-1 by default
#endif

#ifndef ENABLE_SHA224
#define ENABLE_SHA224 1        // enable SHA-224 by default
#endif

#ifndef ENABLE_SHA256
#define ENABLE_SHA256 1        // enable SHA-256 by default
#endif

#ifndef ENABLE_SHA384
#define ENABLE_SHA384 1        // enable SHA-384 by default
#endif

#ifndef ENABLE_SHA512
#define ENABLE_SHA512 1        // enable SHA-512 by default
#endif

#ifndef ENABLE_SHA512_224
#define ENABLE_SHA512_224 1    // enable SHA-512/224 by default
#endif

#ifndef ENABLE_SHA512_256
#define ENABLE_SHA512_256 1    // enable SHA-512/256 by default
#endif

// ========================
// SHA-3 variants
// ========================
#ifndef ENABLE_SHA3_224
#define ENABLE_SHA3_224 1      // enable SHA3-224 by default
#endif

#ifndef ENABLE_SHA3_256
#define ENABLE_SHA3_256 1      // enable SHA3-256 by default
#endif

#ifndef ENABLE_SHA3_384
#define ENABLE_SHA3_384 1      // enable SHA3-384 by default
#endif

#ifndef ENABLE_SHA3_512
#define ENABLE_SHA3_512 1      // enable SHA3-512 by default
#endif

// ========================
// SHAKE / RawSHAKE variants
// ========================
#ifndef ENABLE_SHAKE128
#define ENABLE_SHAKE128 1      // enable SHAKE128 by default
#endif

#ifndef ENABLE_SHAKE256
#define ENABLE_SHAKE256 1      // enable SHAKE256 by default
#endif

#ifndef ENABLE_RAWSHAKE128
#define ENABLE_RAWSHAKE128 1   // enable RawSHAKE128 by default
#endif

#ifndef ENABLE_RAWSHAKE256
#define ENABLE_RAWSHAKE256 1   // enable RawSHAKE256 by default
#endif

// ========================
// Raw Keccak core
// ========================
#ifndef ENABLE_RAW_KECCAK
#define ENABLE_RAW_KECCAK 0    // off by default
#endif

// ========================
// HMAC
// ========================
#ifndef ENABLE_HMAC
#define ENABLE_HMAC 1          // enable HMAC by default
#endif

// ========================
// Internal auto-enabling
// ========================

// SHA-224 uses SHA-256 internally
#if ENABLE_SHA224
  #undef ENABLE_SHA256
  #define ENABLE_SHA256 1
#endif

// SHA-384 uses SHA-512 internally
#if ENABLE_SHA384
  #undef ENABLE_SHA512
  #define ENABLE_SHA512 1
#endif

// SHA-512/224 and SHA-512/256 use SHA-512 internally
#if ENABLE_SHA512_224 || ENABLE_SHA512_256
  #undef ENABLE_SHA512
  #define ENABLE_SHA512 1
#endif

// Core Keccak engine (permutation + sponge)
// Automatically enabled if ANY Keccak-based algorithm is requested
#if ENABLE_SHA3_224     || \
    ENABLE_SHA3_256     || \
    ENABLE_SHA3_384     || \
    ENABLE_SHA3_512     || \
    ENABLE_SHAKE128     || \
    ENABLE_SHAKE256     || \
    ENABLE_RAWSHAKE128  || \
    ENABLE_RAWSHAKE256  || \
    ENABLE_RAW_KECCAK
  #ifndef ENABLE_KECCAK_CORE
    #define ENABLE_KECCAK_CORE 1
  #endif
#endif

// Enable SHAKE XOF helper functions if any SHAKE/RawSHAKE variant is enabled
#if ENABLE_SHAKE128     || \
    ENABLE_SHAKE256     || \
    ENABLE_RAWSHAKE128  || \
    ENABLE_RAWSHAKE256
  #ifndef ENABLE_SHAKE_XOF
    #define ENABLE_SHAKE_XOF 1
  #endif
#endif

#endif // CRYPTO_CONFIG_H