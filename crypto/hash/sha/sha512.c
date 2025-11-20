#include "sha512.h"

#if ENABLE_SHA

// SHA-512 constants
static const uint64_t K512[80] = {
    U64(0x428a2f98d728ae22), U64(0x7137449123ef65cd),
    U64(0xb5c0fbcfec4d3b2f), U64(0xe9b5dba58189dbbc),
    U64(0x3956c25bf348b538), U64(0x59f111f1b605d019),
    U64(0x923f82a4af194f9b), U64(0xab1c5ed5da6d8118),
    U64(0xd807aa98a3030242), U64(0x12835b0145706fbe),
    U64(0x243185be4ee4b28c), U64(0x550c7dc3d5ffb4e2),
    U64(0x72be5d74f27b896f), U64(0x80deb1fe3b1696b1),
    U64(0x9bdc06a725c71235), U64(0xc19bf174cf692694),
    U64(0xe49b69c19ef14ad2), U64(0xefbe4786384f25e3),
    U64(0x0fc19dc68b8cd5b5), U64(0x240ca1cc77ac9c65),
    U64(0x2de92c6f592b0275), U64(0x4a7484aa6ea6e483),
    U64(0x5cb0a9dcbd41fbd4), U64(0x76f988da831153b5),
    U64(0x983e5152ee66dfab), U64(0xa831c66d2db43210),
    U64(0xb00327c898fb213f), U64(0xbf597fc7beef0ee4),
    U64(0xc6e00bf33da88fc2), U64(0xd5a79147930aa725),
    U64(0x06ca6351e003826f), U64(0x142929670a0e6e70),
    U64(0x27b70a8546d22ffc), U64(0x2e1b21385c26c926),
    U64(0x4d2c6dfc5ac42aed), U64(0x53380d139d95b3df),
    U64(0x650a73548baf63de), U64(0x766a0abb3c77b2a8),
    U64(0x81c2c92e47edaee6), U64(0x92722c851482353b),
    U64(0xa2bfe8a14cf10364), U64(0xa81a664bbc423001),
    U64(0xc24b8b70d0f89791), U64(0xc76c51a30654be30),
    U64(0xd192e819d6ef5218), U64(0xd69906245565a910),
    U64(0xf40e35855771202a), U64(0x106aa07032bbd1b8),
    U64(0x19a4c116b8d2d0c8), U64(0x1e376c085141ab53),
    U64(0x2748774cdf8eeb99), U64(0x34b0bcb5e19b48a8),
    U64(0x391c0cb3c5c95a63), U64(0x4ed8aa4ae3418acb),
    U64(0x5b9cca4f7763e373), U64(0x682e6ff3d6b2b8a3),
    U64(0x748f82ee5defb2fc), U64(0x78a5636f43172f60),
    U64(0x84c87814a1f0ab72), U64(0x8cc702081a6439ec),
    U64(0x90befffa23631e28), U64(0xa4506cebde82bde9),
    U64(0xbef9a3f7b2c67915), U64(0xc67178f2e372532b),
    U64(0xca273eceea26619c), U64(0xd186b8c721c0c207),
    U64(0xeada7dd6cde0eb1e), U64(0xf57d4f7fee6ed178),
    U64(0x06f067aa72176fba), U64(0x0a637dc5a2c898a6),
    U64(0x113f9804bef90dae), U64(0x1b710b35131c471b),
    U64(0x28db77f523047d84), U64(0x32caab7b40c72493),
    U64(0x3c9ebe0a15c9bebc), U64(0x431d67c49c100d4c),
    U64(0x4cc5d4becb3e42b6), U64(0x597f299cfc657e2a),
    U64(0x5fcb6fab3ad6faec), U64(0x6c44198c4a475817)
};

// Big sigma
#define SHA512_BSIG0(x) (ROTR64(x,28) ^ ROTR64(x,34) ^ ROTR64(x,39))
#define SHA512_BSIG1(x) (ROTR64(x,14) ^ ROTR64(x,18) ^ ROTR64(x,41))

// small sigma 
#define SHA512_SSIG0(x) (ROTR64(x,1)  ^ ROTR64(x,8)  ^ ((x) >> 7))
#define SHA512_SSIG1(x) (ROTR64(x,19) ^ ROTR64(x,61) ^ ((x) >> 6))

#define SHA512_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA512_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// ======================================
// SHA-512 Low-level functions
// ======================================
bool ll_sha512_init(ll_SHA512_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = U64(0x6a09e667f3bcc908);
    ctx->state[1] = U64(0xbb67ae8584caa73b);
    ctx->state[2] = U64(0x3c6ef372fe94f82b);
    ctx->state[3] = U64(0xa54ff53a5f1d36f1);
    ctx->state[4] = U64(0x510e527fade682d1);
    ctx->state[5] = U64(0x9b05688c2b3e6c1f);
    ctx->state[6] = U64(0x1f83d9abfb41bd6b);
    ctx->state[7] = U64(0x5be0cd19137e2179);
    ctx->Nl = ctx->Nh = 0;
    ctx->buf_len = 0;
    return true;
}

static bool SHA512ProcessBlock(ll_SHA512_CTX *ctx, const uint8_t *block) {
    uint64_t W[80], a,b,c,d,e,f,g,h,T1,T2;

    for (int t=0; t<16; t++)
        W[t] = LOAD64(block + t*8);

    for (int t=16; t<80; t++)
        W[t] = SHA512_SSIG1(W[t-2]) + W[t-7] + SHA512_SSIG0(W[t-15]) + W[t-16];

    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];

    for (int t=0; t<80; t++) {
        T1 = h + SHA512_BSIG1(e) + SHA512_CH(e,f,g) + K512[t] + W[t];
        T2 = SHA512_BSIG0(a) + SHA512_MAJ(a,b,c);
        h=g; g=f; f=e; e=d+T1;
        d=c; c=b; b=a; a=T1+T2;
    }

    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;

    return true;
}

bool ll_sha512_update(ll_SHA512_CTX *ctx, const uint8_t *data, size_t len) {
    if (!data || !len) return false;

    size_t i = 0;
    uint64_t nbits = ((uint64_t)len) << 3;
    ctx->Nl += nbits;
    if (ctx->Nl < nbits) ctx->Nh++;  
    ctx->Nh += ((uint64_t)len) >> 61;

    if (ctx->buf_len && ctx->buf_len + len >= 128) {
        size_t fill = 128 - ctx->buf_len;
        memcpy(ctx->buf + ctx->buf_len, data, fill);
        if (!SHA512ProcessBlock(ctx, ctx->buf)) return false;
        ctx->buf_len = 0;
        i = fill;
    }

    for (; i + 127 < len; i += 128)
        if (!SHA512ProcessBlock(ctx, data + i)) return false;

    if (i < len) {
        memcpy(ctx->buf + ctx->buf_len, data + i, len - i);
        ctx->buf_len += (len - i);
    }

    return true;
}

bool ll_sha512_final(ll_SHA512_CTX *ctx, uint8_t digest[SHA512_DIGEST_SIZE]) {
    if (!ctx || !digest) return false;

    uint8_t pad[128] = {0};
    pad[0] = 0x80;

    uint8_t len_bytes[16];
    STORE64(len_bytes, ctx->Nh);
    STORE64(len_bytes + 8, ctx->Nl);

    size_t pad_len = (ctx->buf_len < 112) ? (112 - ctx->buf_len) : (128 + 112 - ctx->buf_len);

    if (!ll_sha512_update(ctx, pad, pad_len)) return false;
    if (!ll_sha512_update(ctx, len_bytes, 16)) return false;

    for (int i = 0; i < 8; i++)
        STORE64(digest + i*8, ctx->state[i]);

    return true;
}

// ======================================
// SHA-384
// ======================================
bool ll_sha384_init(ll_SHA384_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = U64(0xcbbb9d5dc1059ed8);
    ctx->state[1] = U64(0x629a292a367cd507);
    ctx->state[2] = U64(0x9159015a3070dd17);
    ctx->state[3] = U64(0x152fecd8f70e5939);
    ctx->state[4] = U64(0x67332667ffc00b31);
    ctx->state[5] = U64(0x8eb44a8768581511);
    ctx->state[6] = U64(0xdb0c2e0d64f98fa7);
    ctx->state[7] = U64(0x47b5481dbefa4fa4);
    ctx->Nl = ctx->Nh = 0;
    ctx->buf_len = 0;
    return true;
}

bool ll_sha384_update(ll_SHA384_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_sha512_update((ll_SHA512_CTX*)ctx, data, len);
}

bool ll_sha384_final(ll_SHA384_CTX *ctx, uint8_t digest[SHA384_DIGEST_SIZE]) {
    uint8_t full_digest[SHA512_DIGEST_SIZE];
    if (!ll_sha512_final((ll_SHA512_CTX*)ctx, full_digest)) return false;
    memcpy(digest, full_digest, SHA384_DIGEST_SIZE);
    return true;
}

// ======================================
// SHA-512/224
// ======================================
bool ll_sha512_224_init(ll_SHA512_224_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = U64(0x8c3d37c819544da2);
    ctx->state[1] = U64(0x73e1996689dcd4d6);
    ctx->state[2] = U64(0x1dfab7ae32ff9c82);
    ctx->state[3] = U64(0x679dd514582f9fcf);
    ctx->state[4] = U64(0x0f6d2b697bd44da8);
    ctx->state[5] = U64(0x77e36f7304c48942);
    ctx->state[6] = U64(0x3f9d85a86a1d36c8);
    ctx->state[7] = U64(0x1112e6ad91d692a1);
    ctx->Nl = ctx->Nh = 0;
    ctx->buf_len = 0;
    return true;
}

bool ll_sha512_224_update(ll_SHA512_224_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_sha512_update((ll_SHA512_CTX*)ctx, data, len);
}

bool ll_sha512_224_final(ll_SHA512_224_CTX *ctx, uint8_t digest[SHA512_224_DIGEST_SIZE]) {
    uint8_t full_digest[SHA512_DIGEST_SIZE];
    if (!ll_sha512_final((ll_SHA512_CTX*)ctx, full_digest)) return false;
    memcpy(digest, full_digest, SHA512_224_DIGEST_SIZE);
    return true;
}

// ======================================
// SHA-512/256
// ======================================
bool ll_sha512_256_init(ll_SHA512_256_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = U64(0x22312194fc2bf72c);
    ctx->state[1] = U64(0x9f555fa3c84c64c2);
    ctx->state[2] = U64(0x2393b86b6f53b151);
    ctx->state[3] = U64(0x963877195940eabd);
    ctx->state[4] = U64(0x96283ee2a88effe3);
    ctx->state[5] = U64(0xbe5e1e2553863992);
    ctx->state[6] = U64(0x2b0199fc2c85b8aa);
    ctx->state[7] = U64(0x0eb72ddc81c52ca2);
    ctx->Nl = ctx->Nh = 0;
    ctx->buf_len = 0;
    return true;
}

bool ll_sha512_256_update(ll_SHA512_256_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_sha512_update((ll_SHA512_CTX*)ctx, data, len);
}

bool ll_sha512_256_final(ll_SHA512_256_CTX *ctx, uint8_t digest[SHA512_256_DIGEST_SIZE]) {
    uint8_t full_digest[SHA512_DIGEST_SIZE];
    if (!ll_sha512_final((ll_SHA512_CTX*)ctx, full_digest)) return false;
    memcpy(digest, full_digest, SHA512_256_DIGEST_SIZE);
    return true;
}

#endif // ENABLE_SHA