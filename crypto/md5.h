/*
 * MD5 message-digest algorithm.
 *
 * WARNING: MD5 is cryptographically broken. Retained only for WPA-TKIP
 * MIC verification (HMAC-MD5, keyver == 1) as mandated by IEEE 802.11i.
 * Do NOT use for new code.
 *
 * Original: Joseph Benden <joe@benden.us>
 * C23 modernisation: Air Project 2026.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Design pattern — Adapter:
 *   gcrypt / OpenSSL / generic back-ends behind one stable interface.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "../defs.h"

/* ── Back-end selection ────────────────────────────────────────────── */

#ifdef GCRYPT_WITH_MD5
#  include <gcrypt.h>
#  define Digest_MD5_CTX gcry_md_hd_t
#elif defined(OPENSSL_WITH_MD5)
#  include <openssl/evp.h>
#  define Digest_MD5_CTX EVP_MD_CTX
#else
typedef struct Air_MD5_CTX {
    uint32_t total[2];
    uint32_t state[4];
    uint8_t  buffer[64];
} Digest_MD5_CTX;
#endif

/* ── Constants ─────────────────────────────────────────────────────── */

enum : size_t {
    DIGEST_MD5_MAC_LEN = 16u,
    DIGEST_MD5_BLK_LEN = 64u,
};

/* ── Low-level context API ─────────────────────────────────────────── */

[[nodiscard]] AIR_EXPORT Digest_MD5_CTX *Digest_MD5_Create(void);
AIR_EXPORT void Digest_MD5_Destroy(Digest_MD5_CTX *ctx);

[[nodiscard]] AIR_EXPORT int Digest_MD5_Init(Digest_MD5_CTX *ctx);
[[nodiscard]] AIR_EXPORT int Digest_MD5_Update(Digest_MD5_CTX *ctx,
                                                const uint8_t  *input,
                                                size_t          ilen);
[[nodiscard]] AIR_EXPORT int Digest_MD5_Finish(Digest_MD5_CTX *ctx,
                                                uint8_t        *output);
[[nodiscard]] AIR_EXPORT int Digest_Internal_MD5_Process(Digest_MD5_CTX *ctx,
                                                          const uint8_t  *data);

/* ── One-shot and vector ───────────────────────────────────────────── */

[[nodiscard]] AIR_EXPORT
int Digest_MD5(const uint8_t *input, size_t ilen, uint8_t *output);

[[nodiscard]] AIR_EXPORT
int Digest_MD5_Vector(size_t         num_elem,
                      const uint8_t *addrs[],
                      const size_t   lengths[],
                      uint8_t       *output);

/* ── HMAC-MD5 (RFC 2104) ───────────────────────────────────────────── */

[[nodiscard]] AIR_EXPORT
int MAC_HMAC_MD5_Vector(size_t         key_len,
                         const uint8_t *key,
                         size_t         num_elem,
                         const uint8_t *addr[],
                         const size_t  *len,
                         uint8_t       *mac);

[[nodiscard]] AIR_EXPORT
int MAC_HMAC_MD5(size_t        key_len,
                 const uint8_t *key,
                 size_t        data_len,
                 const uint8_t *data,
                 uint8_t       *output);
