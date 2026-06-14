/*
 * AES generic back-end: ECB block cipher + CTR + GCM + Key Wrap (RFC 3394).
 *
 * Used when neither gcrypt nor OpenSSL is available.
 * Implements AES-128/192/256 block cipher (FIPS 197).
 *
 * Original authors: Joseph Benden <joe@benden.us>, Jouni Malinen <j@w1.fi>
 * CTR/GCM/KeyWrap: Air Project 2026.
 *
 * SPDX-License-Identifier: BSD-3-CLAUSE
 *
 * Design patterns:
 *   Strategy      — selected at build time; callers see only aes.h API.
 *   Template Method — GCM reuses Cipher_AES_Encrypt as its core primitive.
 *
 * WARNING: Table-lookup AES is NOT constant-time (cache-timing side channel).
 * For cracking workloads this is acceptable. For TLS/session-key protection,
 * link the OpenSSL or gcrypt back-end.
 * TODO(rust): constant-time AES via the `aes` crate (bitsliced) for the
 *             WPA passphrase cracking hot path.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "../defs.h"
#include "aes.h"

/* ══════════════════════════════════════════════════════════════════════
 * §1 — AES S-box and round constants (FIPS 197 §5.1.1)
 * ══════════════════════════════════════════════════════════════════════ */

static const uint8_t k_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

/* Round constants: rcon[i] = x^(i-1) mod p(x) in GF(2^8) */
static const uint8_t k_rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
};

/* ══════════════════════════════════════════════════════════════════════
 * §2 — Internal AES context (opaque type defined in aes.h)
 * ══════════════════════════════════════════════════════════════════════ */

enum : size_t {
    AES_MAX_RK_WORDS = 60u,  /* AES-256: 60 round-key words */
};

struct Air_AES_CTX {
    uint32_t rk[AES_MAX_RK_WORDS];
    int      nr;   /* rounds: 10 / 12 / 14 */
};

/* GF(2^8) xtime (multiply by x) */
static inline uint8_t xtime(uint8_t b)
{
    return (uint8_t)((b << 1) ^ ((b >> 7) * 0x1bu));
}

/* AES key expansion (FIPS 197 §5.2) */
static void aes_key_expand(struct Air_AES_CTX *ctx,
                             const uint8_t *key, size_t key_len)
{
    int nk    = (int)(key_len / 4);
    ctx->nr   = nk + 6;

    for (int i = 0; i < nk; ++i)
        ctx->rk[i] = ((uint32_t)key[4*i  ] << 24)
                   | ((uint32_t)key[4*i+1] << 16)
                   | ((uint32_t)key[4*i+2] <<  8)
                   |  (uint32_t)key[4*i+3];

    for (int i = nk; i < 4 * (ctx->nr + 1); ++i) {
        uint32_t w = ctx->rk[i - 1];
        if (i % nk == 0) {
            /* RotWord + SubWord + Rcon */
            w = ((uint32_t)k_sbox[(w >> 16) & 0xffu] << 24)
              | ((uint32_t)k_sbox[(w >>  8) & 0xffu] << 16)
              | ((uint32_t)k_sbox[(w      ) & 0xffu] <<  8)
              | ((uint32_t)k_sbox[(w >> 24) & 0xffu]      );
            w ^= (uint32_t)k_rcon[i / nk] << 24;
        } else if (nk > 6 && i % nk == 4) {
            w = ((uint32_t)k_sbox[(w >> 24) & 0xffu] << 24)
              | ((uint32_t)k_sbox[(w >> 16) & 0xffu] << 16)
              | ((uint32_t)k_sbox[(w >>  8) & 0xffu] <<  8)
              | ((uint32_t)k_sbox[(w      ) & 0xffu]      );
        }
        ctx->rk[i] = ctx->rk[i - nk] ^ w;
    }
}

/* AES block encrypt — SubBytes + ShiftRows + MixColumns + AddRoundKey */
static void aes_block_encrypt(const struct Air_AES_CTX *ctx,
                               const uint8_t in[static AES_BLOCK_LEN],
                               uint8_t       out[static AES_BLOCK_LEN])
{
    uint8_t s[16], t[16];
    memcpy(s, in, 16);

    /* AddRoundKey round 0 */
    for (int c = 0; c < 4; ++c) {
        s[4*c  ] ^= (uint8_t)(ctx->rk[c] >> 24);
        s[4*c+1] ^= (uint8_t)(ctx->rk[c] >> 16);
        s[4*c+2] ^= (uint8_t)(ctx->rk[c] >>  8);
        s[4*c+3] ^= (uint8_t)(ctx->rk[c]      );
    }

    for (int round = 1; round <= ctx->nr; ++round) {
        /* SubBytes + ShiftRows */
        t[ 0]=k_sbox[s[ 0]]; t[ 1]=k_sbox[s[ 5]];
        t[ 2]=k_sbox[s[10]]; t[ 3]=k_sbox[s[15]];
        t[ 4]=k_sbox[s[ 4]]; t[ 5]=k_sbox[s[ 9]];
        t[ 6]=k_sbox[s[14]]; t[ 7]=k_sbox[s[ 3]];
        t[ 8]=k_sbox[s[ 8]]; t[ 9]=k_sbox[s[13]];
        t[10]=k_sbox[s[ 2]]; t[11]=k_sbox[s[ 7]];
        t[12]=k_sbox[s[12]]; t[13]=k_sbox[s[ 1]];
        t[14]=k_sbox[s[ 6]]; t[15]=k_sbox[s[11]];

        if (round < ctx->nr) {
            /* MixColumns */
            for (int c = 0; c < 4; ++c) {
                uint8_t a0=t[4*c], a1=t[4*c+1], a2=t[4*c+2], a3=t[4*c+3];
                s[4*c  ] = xtime(a0)^xtime(a1)^a1^a2^a3;
                s[4*c+1] = a0^xtime(a1)^xtime(a2)^a2^a3;
                s[4*c+2] = a0^a1^xtime(a2)^xtime(a3)^a3;
                s[4*c+3] = xtime(a0)^a0^a1^a2^xtime(a3);
            }
        } else {
            memcpy(s, t, 16);
        }

        /* AddRoundKey */
        const uint32_t *rk = &ctx->rk[round * 4];
        for (int c = 0; c < 4; ++c) {
            s[4*c  ] ^= (uint8_t)(rk[c] >> 24);
            s[4*c+1] ^= (uint8_t)(rk[c] >> 16);
            s[4*c+2] ^= (uint8_t)(rk[c] >>  8);
            s[4*c+3] ^= (uint8_t)(rk[c]      );
        }
    }
    memcpy(out, s, 16);
}

/* ══════════════════════════════════════════════════════════════════════
 * §3 — Public ECB API (Cipher_AES_* from aes.h)
 * ══════════════════════════════════════════════════════════════════════ */

AIR_EXPORT
Cipher_AES_CTX *Cipher_AES_Encrypt_Init(size_t key_len, const uint8_t *key)
{
    REQUIRE(key != nullptr);
    REQUIRE(key_len == AES_KEY_LEN_128
         || key_len == AES_KEY_LEN_192
         || key_len == AES_KEY_LEN_256);

    struct Air_AES_CTX *ctx = malloc(sizeof *ctx);
    if (ctx == nullptr) return nullptr;
    aes_key_expand(ctx, key, key_len);
    return ctx;
}

AIR_EXPORT
int Cipher_AES_Encrypt(Cipher_AES_CTX *ctx,
                        const uint8_t  *plain,
                        uint8_t        *crypt)
{
    REQUIRE(ctx   != nullptr);
    REQUIRE(plain != nullptr);
    REQUIRE(crypt != nullptr);
    aes_block_encrypt(ctx, plain, crypt);
    return 0;
}

AIR_EXPORT
void Cipher_AES_Encrypt_Deinit(Cipher_AES_CTX *ctx)
{
    REQUIRE(ctx != nullptr);
    /* Wipe key material before freeing */
    memset(ctx, 0, sizeof(struct Air_AES_CTX));
    free(ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 * §4 — AES-CTR (96-bit nonce + 32-bit block counter, in-place)
 * ══════════════════════════════════════════════════════════════════════ */

AIR_EXPORT
int air_aes_ctr_xcrypt(const uint8_t *key, size_t key_len,
                        const uint8_t  nonce[12],
                        uint32_t       counter,
                        uint8_t       *data, size_t len)
{
    REQUIRE(key   != nullptr);
    REQUIRE(nonce != nullptr);
    REQUIRE(data  != nullptr || len == 0u);

    struct Air_AES_CTX ctx;
    aes_key_expand(&ctx, key, key_len);

    uint8_t block[AES_BLOCK_LEN], ks[AES_BLOCK_LEN];
    memcpy(block, nonce, 12);

    for (size_t off = 0u; off < len; ) {
        block[12] = (uint8_t)(counter >> 24);
        block[13] = (uint8_t)(counter >> 16);
        block[14] = (uint8_t)(counter >>  8);
        block[15] = (uint8_t)(counter      );
        aes_block_encrypt(&ctx, block, ks);
        ++counter;

        size_t take = len - off;
        if (take > AES_BLOCK_LEN) take = AES_BLOCK_LEN;
        for (size_t i = 0u; i < take; ++i) data[off + i] ^= ks[i];
        off += take;
    }

    memset(&ctx, 0, sizeof ctx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §5 — GHASH for AES-GCM (GF(2^128), NIST SP 800-38D §6.4)
 * ══════════════════════════════════════════════════════════════════════ */

/* Portable bit-by-bit GF(2^128) multiply. Reduction poly: x^128+x^7+x^2+x+1 */
static void ghash_mul(uint8_t z[16], const uint8_t x[16], const uint8_t h[16])
{
    uint8_t v[16], r[16];
    memcpy(v, h, 16);
    memset(r, 0, 16);

    for (int i = 0; i < 128; ++i) {
        if ((x[i / 8] >> (7 - (i % 8))) & 1u)
            for (int j = 0; j < 16; ++j) r[j] ^= v[j];

        uint8_t lsb = v[15] & 1u;
        for (int j = 15; j > 0; --j)
            v[j] = (uint8_t)((v[j] >> 1) | (v[j-1] << 7));
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1u;
    }
    memcpy(z, r, 16);
}

static void ghash(const uint8_t  h[16],
                  const uint8_t *aad,  size_t aad_len,
                  const uint8_t *ct,   size_t ct_len,
                  uint8_t        tag[16])
{
    uint8_t y[16] = {0}, block[16];

    for (size_t off = 0u; off < aad_len; ) {
        size_t take = aad_len - off; if (take > 16u) take = 16u;
        memset(block, 0, 16); memcpy(block, aad + off, take);
        for (int i = 0; i < 16; ++i) y[i] ^= block[i];
        ghash_mul(y, y, h);
        off += take;
    }
    for (size_t off = 0u; off < ct_len; ) {
        size_t take = ct_len - off; if (take > 16u) take = 16u;
        memset(block, 0, 16); memcpy(block, ct + off, take);
        for (int i = 0; i < 16; ++i) y[i] ^= block[i];
        ghash_mul(y, y, h);
        off += take;
    }

    /* Length block: len(AAD)*8 || len(CT)*8 in big-endian 64-bit */
    uint64_t al = (uint64_t)aad_len * 8u, cl = (uint64_t)ct_len * 8u;
    for (int i = 0; i < 8; ++i) {
        block[    i] = (uint8_t)(al >> (56 - 8*i));
        block[8 + i] = (uint8_t)(cl >> (56 - 8*i));
    }
    for (int i = 0; i < 16; ++i) y[i] ^= block[i];
    ghash_mul(y, y, h);
    memcpy(tag, y, 16);
}

/* ══════════════════════════════════════════════════════════════════════
 * §6 — AES-GCM encrypt / decrypt (NIST SP 800-38D)
 * ══════════════════════════════════════════════════════════════════════ */

AIR_EXPORT
int air_aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                         const uint8_t  iv[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, size_t len,
                         uint8_t       *ciphertext,
                         uint8_t        tag[AES_GCM_TAG_LEN])
{
    REQUIRE(key != nullptr && iv != nullptr && tag != nullptr);
    REQUIRE(plaintext  != nullptr || len == 0u);
    REQUIRE(ciphertext != nullptr || len == 0u);

    struct Air_AES_CTX ctx;
    aes_key_expand(&ctx, key, key_len);

    uint8_t h[16] = {0};
    aes_block_encrypt(&ctx, h, h); /* H = AES_K(0^128) */

    if (len > 0u) {
        memcpy(ciphertext, plaintext, len);
        air_aes_ctr_xcrypt(key, key_len, iv, 1u, ciphertext, len);
    }

    /* E(K, J0) — J0 = iv || 00000001 */
    uint8_t j0[16], j0_enc[16];
    memcpy(j0, iv, 12); j0[12]=0; j0[13]=0; j0[14]=0; j0[15]=1;
    aes_block_encrypt(&ctx, j0, j0_enc);

    uint8_t raw_tag[16];
    ghash(h, aad, aad_len, ciphertext, len, raw_tag);
    for (int i = 0; i < 16; ++i) tag[i] = raw_tag[i] ^ j0_enc[i];

    memset(&ctx, 0, sizeof ctx);
    return 0;
}

AIR_EXPORT
bool air_aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                          const uint8_t  iv[12],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *ciphertext, size_t len,
                          const uint8_t  tag[AES_GCM_TAG_LEN],
                          uint8_t       *plaintext)
{
    REQUIRE(key != nullptr && iv != nullptr && tag != nullptr);
    REQUIRE(ciphertext != nullptr || len == 0u);
    REQUIRE(plaintext  != nullptr || len == 0u);

    struct Air_AES_CTX ctx;
    aes_key_expand(&ctx, key, key_len);

    uint8_t h[16] = {0};
    aes_block_encrypt(&ctx, h, h);

    uint8_t j0[16], j0_enc[16];
    memcpy(j0, iv, 12); j0[12]=0; j0[13]=0; j0[14]=0; j0[15]=1;
    aes_block_encrypt(&ctx, j0, j0_enc);

    uint8_t expected[16];
    ghash(h, aad, aad_len, ciphertext, len, expected);
    for (int i = 0; i < 16; ++i) expected[i] ^= j0_enc[i];

    /* Constant-time tag comparison */
    volatile uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= expected[i] ^ tag[i];

    memset(&ctx, 0, sizeof ctx);

    if (diff != 0) return false;

    if (len > 0u) {
        memcpy(plaintext, ciphertext, len);
        air_aes_ctr_xcrypt(key, key_len, iv, 1u, plaintext, len);
    }
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * §7 — AES Key Wrap / Unwrap (RFC 3394)
 *       out size = key_len + 8  (wrap) / key_len - 8  (unwrap)
 * ══════════════════════════════════════════════════════════════════════ */

static const uint8_t k_wrap_iv[8] = {
    0xa6,0xa6,0xa6,0xa6,0xa6,0xa6,0xa6,0xa6,
};

AIR_EXPORT
int air_aes_key_wrap(const uint8_t *kek, size_t kek_len,
                      const uint8_t *key, size_t key_len,
                      uint8_t       *out)
{
    REQUIRE(kek != nullptr && key != nullptr && out != nullptr);
    REQUIRE(key_len % 8u == 0u && key_len >= 16u);

    struct Air_AES_CTX ctx;
    aes_key_expand(&ctx, kek, kek_len);

    int n = (int)(key_len / 8);
    uint8_t a[8];
    memcpy(a, k_wrap_iv, 8);
    memcpy(out + 8, key, key_len);

    for (int j = 0; j < 6; ++j) {
        for (int i = 1; i <= n; ++i) {
            uint8_t b[16];
            memcpy(b, a, 8); memcpy(b + 8, out + 8*i, 8);
            aes_block_encrypt(&ctx, b, b);

            uint64_t t = (uint64_t)(6 * j + i);
            for (int k = 0; k < 8; ++k)
                a[k] = b[k] ^ (uint8_t)(t >> (56 - 8*k));
            memcpy(out + 8*i, b + 8, 8);
        }
    }
    memcpy(out, a, 8);
    memset(&ctx, 0, sizeof ctx);
    return 0;
}

AIR_EXPORT
int air_aes_key_unwrap(const uint8_t *kek, size_t kek_len,
                        const uint8_t *wrapped, size_t wrapped_len,
                        uint8_t       *out)
{
    REQUIRE(kek != nullptr && wrapped != nullptr && out != nullptr);
    REQUIRE(wrapped_len % 8u == 0u && wrapped_len >= 24u);

    /* RFC 3394 §2.2.2 unwrap needs AES block DECRYPT (InvCipher).
     * A portable InvCipher requires InvMixColumns tables (~1 KB each).
     * TODO(rust): delegate to `aes` crate which has full InvCipher.
     * For now, the OpenSSL/gcrypt back-ends handle real unwrap;
     * this stub returns -1 to force callers to use a proper back-end. */
    (void)kek; (void)kek_len; (void)wrapped; (void)wrapped_len; (void)out;
    return -1;
}
