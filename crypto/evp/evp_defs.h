#ifndef EVP_DEFS_H
#define EVP_DEFS_H

#include "../../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _EVP_MD EVP_MD;

typedef struct _EVP_MD_ENTRY EVP_MD_ENTRY;

typedef struct _EVP_XOF_OPTS EVP_XOF_OPTS;

typedef struct _EVP_HASH_CTX EVP_HASH_CTX;

typedef struct _EVP_ENCODER EVP_ENCODER;

typedef struct _EVP_ENCODER_CTX EVP_ENCODER_CTX;

#ifdef __cplusplus
}
#endif

#endif // EVP_DEFS_H