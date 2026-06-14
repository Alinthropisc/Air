/*
 * air-crypto — C23 MIC / PRF helpers.
 *
 * Cryptographic primitives for WPA/WPA2 handshake MIC verification:
 *
 *   air_hmac_md5()  — HMAC-MD5       (WPA/TKIP MIC, key version 1)
 *   air_hmac_sha1() — HMAC-SHA1      (WPA2/CCMP MIC + IEEE 802.11 PRF input)
 *   air_prf512()    — IEEE 802.11 PRF-512 (PTK derivation, §12.7.1.2)
 *
 * Each function is self-contained with no cross-file coupling.
 * Built with: clang -std=c23 -O3
 */

#include "mic.h"

#include <stdint.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════════
 *  SHA-1 internal (FIPS 180-4)
 * ═══════════════════════════════════════════════════════════════════════ */

constexpr size_t SHA1_BLOCK = 64;
constexpr size_t SHA1_DLEN  = 20;

typedef struct { uint32_t s[5]; uint64_t bits; uint8_t buf[64]; } sha1_ctx_t;

static inline uint32_t rol32(uint32_t v, unsigned n)
{
    return (v << n) | (v >> (32 - n));
}

static void sha1_compress(uint32_t s[static 5], const uint8_t b[static 64])
{
    uint32_t w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = ((uint32_t)b[i*4]<<24) | ((uint32_t)b[i*4+1]<<16)
             | ((uint32_t)b[i*4+2]<<8) | b[i*4+3];
    for (int i = 16; i < 80; ++i)
        w[i] = rol32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);

    uint32_t a=s[0], bv=s[1], c=s[2], d=s[3], e=s[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if      (i < 20) { f = (bv & c) | ((~bv) & d); k = 0x5A827999u; }
        else if (i < 40) { f = bv ^ c ^ d;              k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (bv&c)|(bv&d)|(c&d);    k = 0x8F1BBCDCu; }
        else             { f = bv ^ c ^ d;              k = 0xCA62C1D6u; }
        uint32_t t = rol32(a,5) + f + e + k + w[i];
        e = d; d = c; c = rol32(bv,30); bv = a; a = t;
    }
    s[0]+=a; s[1]+=bv; s[2]+=c; s[3]+=d; s[4]+=e;
}

static void sha1_init(sha1_ctx_t *ctx)
{
    ctx->s[0]=0x67452301u; ctx->s[1]=0xEFCDAB89u; ctx->s[2]=0x98BADCFEu;
    ctx->s[3]=0x10325476u; ctx->s[4]=0xC3D2E1F0u;
    ctx->bits = 0;
    memset(ctx->buf, 0, SHA1_BLOCK);
}

static void sha1_feed(sha1_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t idx = (size_t)((ctx->bits >> 3) & (SHA1_BLOCK - 1));
    ctx->bits += (uint64_t)len << 3;
    size_t part = SHA1_BLOCK - idx, i = 0;
    if (len >= part) {
        memcpy(&ctx->buf[idx], data, part);
        sha1_compress(ctx->s, ctx->buf);
        for (i = part; i + SHA1_BLOCK <= len; i += SHA1_BLOCK)
            sha1_compress(ctx->s, data + i);
        idx = 0;
    }
    memcpy(&ctx->buf[idx], data + i, len - i);
}

static void sha1_done(sha1_ctx_t *ctx, uint8_t out[static SHA1_DLEN])
{
    uint8_t len8[8];
    for (int i = 0; i < 8; ++i) len8[i] = (uint8_t)(ctx->bits >> ((7 - i) * 8));
    uint8_t pad = 0x80; sha1_feed(ctx, &pad, 1);
    pad = 0;
    while (((ctx->bits >> 3) & (SHA1_BLOCK - 1)) != 56)
        sha1_feed(ctx, &pad, 1);
    sha1_feed(ctx, len8, 8);
    for (int i = 0; i < 20; ++i)
        out[i] = (uint8_t)(ctx->s[i >> 2] >> ((3 - (i & 3)) * 8));
}

/* Internal HMAC-SHA1 — used by both air_hmac_sha1 and air_prf512. */
static void hmac_sha1_raw(const uint8_t *key,  size_t klen,
                           const uint8_t *msg,  size_t mlen,
                           uint8_t out[static SHA1_DLEN])
{
    uint8_t bkey[SHA1_BLOCK], tmp[SHA1_DLEN];
    sha1_ctx_t ctx;

    if (klen > SHA1_BLOCK) {
        sha1_init(&ctx); sha1_feed(&ctx, key, klen); sha1_done(&ctx, tmp);
        key = tmp; klen = SHA1_DLEN;
    }
    memset(bkey, 0, SHA1_BLOCK);
    memcpy(bkey, key, klen);

    uint8_t ipad[SHA1_BLOCK], opad[SHA1_BLOCK];
    for (size_t i = 0; i < SHA1_BLOCK; ++i) {
        ipad[i] = bkey[i] ^ 0x36u;
        opad[i] = bkey[i] ^ 0x5Cu;
    }

    uint8_t inner[SHA1_DLEN];
    sha1_init(&ctx);
    sha1_feed(&ctx, ipad, SHA1_BLOCK);
    sha1_feed(&ctx, msg,  mlen);
    sha1_done(&ctx, inner);

    sha1_init(&ctx);
    sha1_feed(&ctx, opad,  SHA1_BLOCK);
    sha1_feed(&ctx, inner, SHA1_DLEN);
    sha1_done(&ctx, out);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  air_hmac_sha1 — public API
 * ═══════════════════════════════════════════════════════════════════════ */

int air_hmac_sha1(const uint8_t *key,  size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t out[static AIR_SHA1_LEN])
{
    if (!key || !data || !out || key_len == 0) return 1;
    hmac_sha1_raw(key, key_len, data, data_len, out);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  MD5 (RFC 1321)
 * ═══════════════════════════════════════════════════════════════════════ */

constexpr size_t MD5_BLOCK = 64;
constexpr size_t MD5_DLEN  = 16;

typedef struct { uint32_t s[4]; uint64_t bits; uint8_t buf[64]; } md5_ctx_t;

static constexpr uint32_t MD5_K[64] = {
    0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
    0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
    0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
    0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
    0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
    0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
    0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
    0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u,
};
static constexpr uint8_t MD5_S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
};

static void md5_compress(uint32_t s[static 4], const uint8_t b[static 64])
{
    uint32_t w[16];
    for (int i = 0; i < 16; ++i)
        w[i] = ((uint32_t)b[i*4+3]<<24)|((uint32_t)b[i*4+2]<<16)
             | ((uint32_t)b[i*4+1]<<8 )| b[i*4];

    uint32_t a=s[0], bv=s[1], c=s[2], d=s[3];
    for (int i = 0; i < 64; ++i) {
        uint32_t f; int g;
        if      (i < 16) { f = (bv & c) | (~bv & d); g = i; }
        else if (i < 32) { f = (d & bv) | (~d & c);  g = (5*i+1) % 16; }
        else if (i < 48) { f = bv ^ c ^ d;            g = (3*i+5) % 16; }
        else             { f = c ^ (bv | ~d);         g = (7*i)   % 16; }
        f += a + MD5_K[i] + w[g];
        a = d; d = c; c = bv;
        bv += rol32(f, MD5_S[i]);
    }
    s[0]+=a; s[1]+=bv; s[2]+=c; s[3]+=d;
}

static void md5_init(md5_ctx_t *ctx)
{
    ctx->s[0]=0x67452301u; ctx->s[1]=0xEFCDAB89u;
    ctx->s[2]=0x98BADCFEu; ctx->s[3]=0x10325476u;
    ctx->bits = 0; memset(ctx->buf, 0, MD5_BLOCK);
}

static void md5_feed(md5_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t idx = (size_t)((ctx->bits >> 3) & (MD5_BLOCK - 1)), i = 0;
    ctx->bits += (uint64_t)len << 3;
    size_t part = MD5_BLOCK - idx;
    if (len >= part) {
        memcpy(&ctx->buf[idx], data, part); md5_compress(ctx->s, ctx->buf);
        for (i = part; i + MD5_BLOCK <= len; i += MD5_BLOCK)
            md5_compress(ctx->s, data + i);
        idx = 0;
    }
    memcpy(&ctx->buf[idx], data + i, len - i);
}

static void md5_done(md5_ctx_t *ctx, uint8_t out[static MD5_DLEN])
{
    uint8_t len8[8];
    for (int i = 0; i < 8; ++i) len8[i] = (uint8_t)(ctx->bits >> (i * 8));
    uint8_t pad = 0x80; md5_feed(ctx, &pad, 1);
    pad = 0;
    while (((ctx->bits >> 3) & (MD5_BLOCK - 1)) != 56)
        md5_feed(ctx, &pad, 1);
    md5_feed(ctx, len8, 8);
    for (int i = 0; i < 16; ++i) out[i] = (uint8_t)(ctx->s[i >> 2] >> (8 * (i & 3)));
}

/* ═══════════════════════════════════════════════════════════════════════
 *  air_hmac_md5 — public API
 * ═══════════════════════════════════════════════════════════════════════ */

int air_hmac_md5(const uint8_t *key,  size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[static AIR_MD5_LEN])
{
    if (!key || !data || !out || key_len == 0) return 1;

    uint8_t bkey[MD5_BLOCK], tmp[MD5_DLEN];
    md5_ctx_t ctx;

    if (key_len > MD5_BLOCK) {
        md5_init(&ctx); md5_feed(&ctx, key, key_len); md5_done(&ctx, tmp);
        key = tmp; key_len = MD5_DLEN;
    }
    memset(bkey, 0, MD5_BLOCK);
    memcpy(bkey, key, key_len);

    uint8_t ipad[MD5_BLOCK], opad[MD5_BLOCK];
    for (size_t i = 0; i < MD5_BLOCK; ++i) {
        ipad[i] = bkey[i] ^ 0x36u;
        opad[i] = bkey[i] ^ 0x5Cu;
    }

    uint8_t inner[MD5_DLEN];
    md5_init(&ctx);
    md5_feed(&ctx, ipad, MD5_BLOCK);
    md5_feed(&ctx, data, data_len);
    md5_done(&ctx, inner);

    md5_init(&ctx);
    md5_feed(&ctx, opad,  MD5_BLOCK);
    md5_feed(&ctx, inner, MD5_DLEN);
    md5_done(&ctx, out);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  air_prf512 — IEEE 802.11 PRF-512 (§12.7.1.2)
 *
 *  PRF(K, A, B) = Σ HMAC-SHA1(K, A || 0x00 || B || i)  for i = 0..3
 *  Produces exactly 64 bytes (PTK for WPA2).
 *
 *  A = label (e.g. "Pairwise key expansion")
 *  B = data  (min(AA,STA)||max(AA,STA)||min(ANonce,SNonce)||max(ANonce,SNonce))
 * ═══════════════════════════════════════════════════════════════════════ */

int air_prf512(const uint8_t *key,   size_t key_len,
               const uint8_t *label, size_t label_len,
               const uint8_t *data,  size_t data_len,
               uint8_t out[static AIR_PRF512_LEN])
{
    if (!key || !label || !data || !out || key_len == 0) return 1;

    /* Build buffer: label || 0x00 || data || i (i is last byte, changes) */
    size_t   buf_len = label_len + 1 + data_len + 1;
    uint8_t *buf     = (uint8_t *)__builtin_alloca(buf_len);

    memcpy(buf, label, label_len);
    buf[label_len] = 0x00;
    memcpy(buf + label_len + 1, data, data_len);

    uint8_t h[SHA1_DLEN];
    size_t  offset = 0;

    for (uint8_t i = 0; offset < AIR_PRF512_LEN; ++i) {
        buf[buf_len - 1] = i;
        hmac_sha1_raw(key, key_len, buf, buf_len, h);
        size_t copy = (AIR_PRF512_LEN - offset < SHA1_DLEN)
                      ? (AIR_PRF512_LEN - offset)
                      : SHA1_DLEN;
        memcpy(out + offset, h, copy);
        offset += copy;
    }
    return 0;
}
