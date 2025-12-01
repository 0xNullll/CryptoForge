#ifndef CRYPTO_CONFIG_H
#define CRYPTO_CONFIG_H

#ifndef BUILDING_CF_DLL
#define BUILDING_CF_DLL 1
#endif

#ifndef HASH_FALLBACK_DEFAULT_LEN
#define HASH_FALLBACK_DEFAULT_LEN 1 // If defined, digest_len=0 will fall back to default hash size
#endif 

#ifndef HMAC_FALLBACK_DEFAULT_LEN
#define HMAC_FALLBACK_DEFAULT_LEN 1 // If defined, digest_len=0 will fall back to default HMAC size
#endif 

#ifndef KMAC_FALLBACK_DEFAULT_LEN
#define KMAC_FALLBACK_DEFAULT_LEN 1 // If defined, digest_len=0 will fall back to default KMAC size
#endif 

#ifndef HKDF_FALLBACK_DEFAULT_LEN
#define HKDF_FALLBACK_DEFAULT_LEN 1 // If defined, digest_len=0 will fall back to default HKDF size
#endif 

#ifndef ENABLE_TESTS
#define ENABLE_TESTS 1       // enable demo/test code
#endif

// ------------------------
// Function name prefix support
// ------------------------
#ifndef TSHASH_PREFIX
#define TSHASH_PREFIX
#endif

#define _TS_CAT(a,b) a##b
#define _TS_CAT2(a,b) _TS_CAT(a,b)
#define TC_TSHASH_FN(name) _TS_CAT2(TSHASH_PREFIX, name)

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