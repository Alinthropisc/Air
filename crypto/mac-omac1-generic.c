/*
 * OMAC1/CMAC-AES — generic back-end (no OpenSSL/gcrypt).
 *
 * Implements NIST SP 800-38B (CMAC) on top of the generic AES-ECB
 * primitives from aes-128-cbc-generic.c.
 *
 * Design patterns:
 *   - Opaque Handle / Pimpl  : Air_OMAC_CTX defined only here
 *   - Template Method        : _generate_subkeys() used by all API variants
 *   - Adapter                : same stable MAC interface as gcrypt/OpenSSL backends
 *
 * SPDX-License-Identifier: BSD-3-CLAUSE
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "../defs.h"
#include "aes.h"
#include "mac.h"

/* ── Rb constant for 128-bit block (NIST SP 800-38B §5.3) ─────────── */
#define CMAC_RB_128  UINT8_C(0x87)

/* ── Opaque streaming context ──────────────────────────────────────── */

struct Air_OMAC_CTX {
    Cipher_AES_CTX *aes_ctx;   /* AES-ECB encrypt context               */
    uint8_t         K1[16];    /* subkey 1 (complete last block)         */
    uint8_t         K2[16];    /* subkey 2 (incomplete last block)       */
    uint8_t         X[16];     /* running CBC-MAC accumulator            */
    uint8_t         buf[16];   /* buffered pending block                 */
    size_t          buf_len;   /* bytes currently in buf                 */
};

/* ── Internal helpers ──────────────────────────────────────────────── */

/* left-shift 128-bit block by 1 bit (big-endian) */
static void block_shift_left1(const uint8_t in[static 16],
                               uint8_t       out[static 16])
{
    uint8_t carry = 0;
    for (int i = 15; i >= 0; --i) {
        out[i] = (uint8_t)((in[i] << 1) | carry);
        carry   = in[i] >> 7;
    }
}

/* XOR two 16-byte blocks: dst ^= src */
static void block_xor(uint8_t dst[static 16],
                       const uint8_t src[static 16])
{
    for (size_t i = 0; i < 16; ++i) dst[i] ^= src[i];
}

/* Generate K1 and K2 from the AES key (NIST SP 800-38B §6.1). */
static int _generate_subkeys(Cipher_AES_CTX *aes_ctx,
                              uint8_t K1[static 16],
                              uint8_t K2[static 16])
{
    uint8_t L[16] = {0};

    /* L = AES(K, 0^128) */
    if (Cipher_AES_Encrypt(aes_ctx, L, L) != 0) return -1;

    /* K1 = double(L) */
    block_shift_left1(L, K1);
    if (L[0] & 0x80) K1[15] ^= CMAC_RB_128;

    /* K2 = double(K1) */
    block_shift_left1(K1, K2);
    if (K1[0] & 0x80) K2[15] ^= CMAC_RB_128;

    return 0;
}

/* Encrypt one 16-byte block through the CBC-MAC accumulator. */
static int _process_block(Air_OMAC_CTX *ctx,
                           const uint8_t blk[static 16])
{
    block_xor(ctx->X, blk);
    return Cipher_AES_Encrypt(ctx->aes_ctx, ctx->X, ctx->X);
}

/* ── Streaming API ─────────────────────────────────────────────────── */

AIR_EXPORT
MAC_OMAC_CTX *MAC_OMAC1_AES_Create(const uint8_t *key, size_t key_len)
{
    REQUIRE(key     != nullptr);
    REQUIRE(key_len == 16u || key_len == 32u);

    Air_OMAC_CTX *ctx = (Air_OMAC_CTX *)malloc(sizeof *ctx);
    if (!ctx) return nullptr;

    ctx->aes_ctx = Cipher_AES_Encrypt_Init(key_len, key);
    if (!ctx->aes_ctx) { free(ctx); return nullptr; }

    if (_generate_subkeys(ctx->aes_ctx, ctx->K1, ctx->K2) != 0) {
        Cipher_AES_Encrypt_Deinit(ctx->aes_ctx);
        free(ctx);
        return nullptr;
    }

    memset(ctx->X,   0, 16);
    memset(ctx->buf, 0, 16);
    ctx->buf_len = 0;
    return ctx;
}

AIR_EXPORT
int MAC_OMAC1_AES_Update(MAC_OMAC_CTX *ctx, const uint8_t *data, size_t len)
{
    REQUIRE(ctx  != nullptr);
    REQUIRE(data != nullptr || len == 0);

    const uint8_t *p   = data;
    size_t         rem = len;

    while (rem > 0) {
        size_t space = 16u - ctx->buf_len;
        size_t take  = rem < space ? rem : space;

        memcpy(ctx->buf + ctx->buf_len, p, take);
        ctx->buf_len += take;
        p            += take;
        rem          -= take;

        /* Only flush a full block when more data follows.
         * The last block (possibly incomplete) is handled in Finish. */
        if (ctx->buf_len == 16u && rem > 0) {
            if (_process_block(ctx, ctx->buf) != 0) return -1;
            ctx->buf_len = 0;
        }
    }

    return 0;
}

AIR_EXPORT
int MAC_OMAC1_AES_Finish(MAC_OMAC_CTX *ctx,
                          uint8_t       mac[static MAC_CMAC_AES_128_LEN])
{
    REQUIRE(ctx != nullptr);
    REQUIRE(mac != nullptr);

    uint8_t M_last[16];

    if (ctx->buf_len == 16u) {
        /* Complete last block: M_last = buf XOR K1 */
        memcpy(M_last, ctx->buf, 16);
        block_xor(M_last, ctx->K1);
    } else {
        /* Incomplete last block: pad with 10*…0, then XOR K2 */
        memset(M_last, 0, 16);
        memcpy(M_last, ctx->buf, ctx->buf_len);
        M_last[ctx->buf_len] = 0x80;   /* 10* padding */
        block_xor(M_last, ctx->K2);
    }

    if (_process_block(ctx, M_last) != 0) return -1;
    memcpy(mac, ctx->X, 16);
    return 0;
}

AIR_EXPORT
void MAC_OMAC1_AES_Destroy(MAC_OMAC_CTX *ctx)
{
    if (!ctx) return;
    Cipher_AES_Encrypt_Deinit(ctx->aes_ctx);
    /* Wipe sensitive material before free */
    memset(ctx, 0, sizeof *ctx);
    free(ctx);
}

/* ── One-shot vector API ───────────────────────────────────────────── */

AIR_EXPORT
int MAC_OMAC1_AES_Vector(size_t         key_len,
                          const uint8_t  key[static key_len],
                          size_t         count,
                          const uint8_t *addr[],
                          const size_t  *len,
                          uint8_t       *mac)
{
    REQUIRE(key  != nullptr);
    REQUIRE(addr != nullptr);
    REQUIRE(len  != nullptr);
    REQUIRE(mac  != nullptr);

    MAC_OMAC_CTX *ctx = MAC_OMAC1_AES_Create(key, key_len);
    if (!ctx) return -1;

    int rc = 0;
    for (size_t i = 0; i < count && rc == 0; ++i)
        rc = MAC_OMAC1_AES_Update(ctx, addr[i], len[i]);

    if (rc == 0)
        rc = MAC_OMAC1_AES_Finish(ctx, mac);

    MAC_OMAC1_AES_Destroy(ctx);
    return rc;
}

/* ── Convenience one-shots ─────────────────────────────────────────── */

AIR_EXPORT
int MAC_OMAC1_AES(size_t         key_len,
                  const uint8_t *key,
                  const uint8_t *data,
                  size_t         data_len,
                  uint8_t       *mac)
{
    const uint8_t *addrs[1] = { data };
    const size_t   lens[1]  = { data_len };
    return MAC_OMAC1_AES_Vector(key_len, key, 1, addrs, lens, mac);
}

AIR_EXPORT
int MAC_OMAC1_AES_128(const uint8_t  key[static MAC_CMAC_AES_128_LEN],
                       const uint8_t *data,
                       size_t         data_len,
                       uint8_t        mac[static MAC_CMAC_AES_128_LEN])
{
    return MAC_OMAC1_AES(MAC_CMAC_AES_128_LEN, key, data, data_len, mac);
}
