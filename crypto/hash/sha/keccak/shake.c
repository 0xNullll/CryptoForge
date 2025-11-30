#include "shake.h"

// ======================================
// Bit-level helpers
// ======================================
void ll_trunc_s(const uint8_t *X, size_t Xlen, size_t s, uint8_t *out) {
    size_t full_bytes = s / 8;
    size_t rem_bits  = s % 8;

    if (full_bytes > Xlen) full_bytes = Xlen;
    memcpy(out, X, full_bytes);

    if (rem_bits && full_bytes < Xlen) {
        uint8_t mask = 0xFF << (8 - rem_bits);
        out[full_bytes] = X[full_bytes] & mask;
    }
}

void ll_concat_bits(const uint8_t *X, size_t x_bits,
                    const uint8_t *Y, size_t y_bits,
                    uint8_t *out) {

    size_t out_bits = x_bits + y_bits;
    size_t out_bytes = (out_bits + 7) / 8;
    memset(out, 0, out_bytes);

    size_t x_full_bytes = x_bits / 8;
    memcpy(out, X, x_full_bytes);

    size_t x_rem_bits = x_bits % 8;
    if (x_rem_bits && x_full_bytes < out_bytes) {
        out[x_full_bytes] = X[x_full_bytes] & (0xFF << (8 - x_rem_bits));
    }

    for (size_t i = 0; i < y_bits; i++) {
        size_t bit_index = x_bits + i;
        size_t out_byte = bit_index / 8;
        size_t out_bit  = 7 - (bit_index % 8);
        uint8_t y_bit = (Y[i / 8] >> (7 - (i % 8))) & 1;
        out[out_byte] |= y_bit << out_bit;
    }
}

/*
 * ================= FIPS 800-185 Helpers =================
 *
 * These functions implement low-level operations as defined in
 * NIST SP800-185 for cSHAKE, KMAC, TupleHash, and ParallelHash.
 *
 * - ll_right_encode_uint64(x, out):
 *     Encodes a 64-bit integer x as a variable-length big-endian
 *     byte string followed by a length byte at the end.
 *
 * - ll_left_encode_uint64(x, out):
 *     Encodes a 64-bit integer x as a variable-length big-endian
 *     byte string preceded by a length byte at the beginning.
 *
 * - ll_encode_string(S, S_len_bytes, out, out_len):
 *     Encodes a byte string S as left_encode(bitlen(S)) || S.
 *     Returns the total number of bytes written.
 *
 * - ll_encoded_string_len(S_len):
 *     Returns the number of bytes ll_encode_string will write
 *     without actually encoding.
 *
 * - ll_byte_pad(S, S_len, w, out, out_cap):
 *     Pads the string S to a multiple of w bytes after prepending
 *     left_encode(w). Returns the total number of bytes written.
 *
 * - ll_substring_bytes(S, S_len, start_idx, end_idx, out):
 *     Returns a byte-aligned substring from start_idx to end_idx-1.
 */

// Right-encode a 64-bit integer (x) in big-endian, length byte at the end
size_t ll_right_encode_uint64(uint64_t x, uint8_t *out) {
    size_t n = 1;
    uint64_t tmp = x;
    while (tmp >>= 8) n++;  // number of bytes needed

    // Encode x in big-endian
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)(x >> (8 * (n - 1 - i))) & 0xFF;

    out[n] = (uint8_t)n;  // append length byte at end
    return n + 1;
}

// Left-encode a 64-bit integer (x) in big-endian, length byte at start
size_t ll_left_encode_uint64(uint64_t x, uint8_t *out) {
    size_t n = 1;
    uint64_t tmp = x;
    while (tmp >>= 8) n++;  // number of bytes needed

    out[0] = (uint8_t)n;    // length byte at start

    // Encode x in big-endian
    for (size_t i = 0; i < n; i++)
        out[1 + i] = (uint8_t)(x >> (8 * (n - 1 - i))) & 0xFF;

    return n + 1;
}

// Encode a string according to SP800-185 (length in bytes)
size_t ll_encode_string(const uint8_t *S, size_t S_len_bytes, uint8_t *out, size_t out_len) {
    if (!out) return 0;  // output pointer must be valid

    // Calculate bit-length of the string
    uint64_t bitlen = (uint64_t)S_len_bytes * 8;

    // Encode bit-length
    uint8_t tmp[16];  // max bytes needed for ll_left_encode_uint64
    size_t n = ll_left_encode_uint64(bitlen, tmp);

    // Check if output buffer is large enough
    if (out_len < n + S_len_bytes) {
        // Not enough space
        return 0;
    }

    // Copy left-encoded length
    memcpy(out, tmp, n);

    // Append string bytes
    if (S && S_len_bytes > 0) {
        memcpy(out + n, S, S_len_bytes);
    }

    return n + S_len_bytes;  // total bytes written
}

// Compute the total encoded string length in bytes (bits-only)
size_t ll_encoded_string_len(size_t S_len) {
    uint64_t bits = (uint64_t)S_len * 8;
    size_t n = 1;
    uint64_t tmp = bits;
    while (tmp >>= 8) n++;  // number of bytes needed to encode bit-length
    return n + 1 + S_len;   // n bytes for bitlen + 1 length byte + string itself
}


// Bytepad a string (already bit-length encoded) to nearest multiple of w
size_t ll_byte_pad(const uint8_t *S, size_t S_len,
                   size_t w, uint8_t *out, size_t out_cap) {
    if (w == 0 || !out) return 0;

    uint8_t le[9];
    size_t le_len = ll_left_encode_uint64(w, le);  // left-encode w (bytes)

    size_t n = le_len + S_len;                     // total length before padding

    if (out_cap < n) return 0;

    // copy left_encode(w) || S
    memcpy(out, le, le_len);
    if (S_len)
        memcpy(out + le_len, S, S_len);

    // pad to nearest multiple of w
    size_t pad = (w - (n % w)) % w;
    if (out_cap < n + pad) return 0;
    if (pad)
        memset(out + n, 0, pad);

    return n + pad;
}

// Extract a byte-range (substring) from a byte array
size_t ll_substring_bytes(const uint8_t *S, size_t S_len,
                          size_t start_idx, size_t end_idx,
                          uint8_t *out) {
    if (!S || !out || start_idx >= end_idx || start_idx >= S_len) return 0;
    if (end_idx > S_len) end_idx = S_len;

    size_t len = end_idx - start_idx;
    memcpy(out, S + start_idx, len);
    return len;
}

// ======================================
// SHAKE128 (Low-level)
// ======================================
bool ll_shake128_init(ll_SHAKE128_CTX *ctx) {
    return ll_keccak_sponge_init(ctx, SHAKE128_BLOCK_SIZE, SHAKE128_DOMAIN);
}

bool ll_shake128_absorb(ll_SHAKE128_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_sponge_absorb(ctx, data, len);
}

bool ll_shake128_final(ll_SHAKE128_CTX *ctx) {
    return ll_keccak_sponge_final(ctx);
}

bool ll_shake128_squeeze(ll_SHAKE128_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(ctx, output, outlen);
}

// ======================================
// SHAKE256 (Low-level)
// ======================================
bool ll_shake256_init(ll_SHAKE256_CTX *ctx) {
    return ll_keccak_sponge_init(ctx, SHAKE256_BLOCK_SIZE, SHAKE256_DOMAIN);
}

bool ll_shake256_absorb(ll_SHAKE256_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_sponge_absorb(ctx, data, len);
}

bool ll_shake256_final(ll_SHAKE256_CTX *ctx) {
    return ll_keccak_sponge_final(ctx);
}

bool ll_shake256_squeeze(ll_SHAKE256_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(ctx, output, outlen);
}

// ======================================
// RawSHAKE128
// ======================================
bool ll_rawshake128_init(ll_RawSHAKE128_CTX *ctx) {
    return ll_keccak_sponge_init(ctx, RAWSHAKE128_BLOCK_SIZE, RAWSHAKE128_DOMAIN);
}

bool ll_rawshake128_absorb(ll_RawSHAKE128_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_sponge_absorb(ctx, data, len);
}

bool ll_rawshake128_final(ll_RawSHAKE128_CTX *ctx) {
    return ll_keccak_sponge_final(ctx);
}

bool ll_rawshake128_squeeze(ll_RawSHAKE128_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(ctx, output, outlen);
}

// ======================================
// RawSHAKE256
// ======================================
bool ll_rawshake256_init(ll_RawSHAKE256_CTX *ctx) {
    return ll_keccak_sponge_init(ctx, RAWSHAKE256_BLOCK_SIZE, RAWSHAKE256_DOMAIN);
}

bool ll_rawshake256_absorb(ll_RawSHAKE256_CTX *ctx, const uint8_t *data, size_t len) {
    return ll_keccak_sponge_absorb(ctx, data, len);
}

bool ll_rawshake256_final(ll_RawSHAKE256_CTX *ctx) {
    return ll_keccak_sponge_final(ctx);
}

bool ll_rawshake256_squeeze(ll_RawSHAKE256_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(ctx, output, outlen);
}

// ==============================
// cSHAKE low-level helpers
// ==============================

bool ll_cshake_absorb_custom(
    ll_KECCAK_CTX *sponge,
    const uint8_t *N, size_t N_len,
    const uint8_t *S, size_t S_len) {
    if ((!N || N_len == 0) && (!S || S_len == 0))
        return true;  // nothing to absorb

    // Temporary buffer for encoded N + S
    uint8_t tmp[2 * MAX_CUSTOMIZATION + MAX_ENCODED_HEADER_LEN * 8]; 
    size_t pos = 0;

    // Encode N in bits
    pos += ll_encode_string(N, N_len, tmp + pos, sizeof(tmp));
    pos += ll_encode_string(S, S_len, tmp + pos, sizeof(tmp));

    // Bytepad to rate multiple
    uint8_t padded[2 * KECCAK_BLOCK_SIZE]; // safe over-estimate
    size_t padded_len = ll_byte_pad(tmp, pos, sponge->rate, padded, sizeof(padded));

    // Absorb into sponge
    return ll_keccak_sponge_absorb(sponge, padded, padded_len);
}

// ==============================
// cSHAKE128 init / absorb / final
// ==============================
bool ll_cshake128_init(ll_CSHAKE128_CTX *ctx,
                       const uint8_t *N, size_t N_len,
                       const uint8_t *S, size_t S_len) {
    if (N_len > MAX_CUSTOMIZATION || S_len > MAX_CUSTOMIZATION)
        return false;

    memset(ctx, 0, sizeof(*ctx));

    // Copy N and S into the fixed arrays
    if (N && N_len > 0) {
        memcpy(ctx->N, N, N_len);
        ctx->N_len = N_len;
    } else {
        ctx->N_len = 0;
    }

    if (S && S_len > 0) {
        memcpy(ctx->S, S, S_len);
        ctx->S_len = S_len;
    } else {
        ctx->S_len = 0;
    }

    ctx->finalized = 0;
    ctx->customAbsorbed = 0;
    ctx->emptyNameCustom = (N_len == 0) && (S_len == 0);

    // initialize Keccak sponge
    if (!ll_keccak_sponge_init(&ctx->internal_ctx, SHAKE128_BLOCK_SIZE, SHAKE128_DOMAIN))
        return false;

    // absorb customization strings if present
    if (!ctx->emptyNameCustom) {
        if (!ll_cshake_absorb_custom(&ctx->internal_ctx, ctx->N, ctx->N_len, ctx->S, ctx->S_len))
            return false;
        ctx->customAbsorbed = 1;
    }

    return true;
}


bool ll_cshake128_absorb(ll_CSHAKE128_CTX *ctx, const uint8_t *X, size_t X_len) {
    if (X && X_len > 0)
        return ll_keccak_sponge_absorb(&ctx->internal_ctx, X, X_len);

    return true;
}

bool ll_cshake128_final(ll_CSHAKE128_CTX *ctx) {
    if (ctx->finalized) return false;

    // Set domain separation byte according to SP800-185
    uint8_t suffix = ctx->emptyNameCustom ? SHAKE128_DOMAIN : CSHAKE128_DOMAIN;
    ctx->internal_ctx.suffix = suffix;

    ctx->finalized = 1;
    return ll_keccak_sponge_final(&ctx->internal_ctx);
}

bool ll_cshake128_squeeze(ll_CSHAKE128_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(&ctx->internal_ctx, output, outlen);
}

// ==============================
// cSHAKE256 init / absorb / final
// ==============================
bool ll_cshake256_init(ll_CSHAKE256_CTX *ctx,
                       const uint8_t *N, size_t N_len,
                       const uint8_t *S, size_t S_len) {
    if (N_len > MAX_CUSTOMIZATION || S_len > MAX_CUSTOMIZATION)
        return false;

    memset(ctx, 0, sizeof(*ctx));

    // Copy N and S into the fixed arrays
    if (N && N_len > 0)
        memcpy(ctx->N, N, N_len);
    ctx->N_len = N_len;

    if (S && S_len > 0)
        memcpy(ctx->S, S, S_len);
    ctx->S_len = S_len;

    ctx->finalized = 0;
    ctx->customAbsorbed = 0;
    ctx->emptyNameCustom = (N_len == 0) && (S_len == 0);

    if (!ll_keccak_sponge_init(&ctx->internal_ctx, SHAKE256_BLOCK_SIZE, SHAKE256_DOMAIN))
        return false;

    if (!ctx->emptyNameCustom) {
        if (!ll_cshake_absorb_custom(&ctx->internal_ctx, ctx->N, ctx->N_len, ctx->S, ctx->S_len))
            return false;
        ctx->customAbsorbed = 1;
    }

    return true;
}

bool ll_cshake256_absorb(ll_CSHAKE256_CTX *ctx, const uint8_t *X, size_t X_len) {
    if (X && X_len > 0)
        return ll_keccak_sponge_absorb(&ctx->internal_ctx, X, X_len);

    return true;
}

bool ll_cshake256_final(ll_CSHAKE256_CTX *ctx) {
    if (ctx->finalized) return false;

    uint8_t suffix = ctx->emptyNameCustom ? SHAKE256_DOMAIN : CSHAKE256_DOMAIN;
    ctx->internal_ctx.suffix = suffix;

    ctx->finalized = 1;
    return ll_keccak_sponge_final(&ctx->internal_ctx);
}

bool ll_cshake256_squeeze(ll_CSHAKE256_CTX *ctx, uint8_t *output, size_t outlen) {
    return ll_keccak_sponge_squeeze(&ctx->internal_ctx, output, outlen);
}