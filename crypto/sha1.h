/*
 * SHA-1 cryptographic hash function.
 *
 * Defined in FIPS 180-4: Secure Hash Standard (SHS).
 *
 * Original authors: Joseph Benden <joe@benden.us>, Jouni Malinen <j@w1.fi>
 * C23 modernisation: Air Project 2026.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * WARNING: SHA-1 is cryptographically weak. It is retained here solely
 * because WPA-PSK (PBKDF2-HMAC-SHA1) and IEEE 802.11i PTK derivation
 * mandate it. Do NOT use for new protocol work.
 *
 * Design pattern — Adapter:
 *   Three build-time back-ends (gcrypt / OpenSSL / generic) all satisfy
 *   the same interface declared here. Callers never see back-end details.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../defs.h"

/* wpapsk needs a concrete, stack-allocatable, cheaply-cloneable context */
#include "sha1-git.h"

#define wpapsk_SHA1_CTX    blk_SHA_CTX
#define wpapsk_SHA1_Init   blk_SHA1_Init
#define wpapsk_SHA1_Update blk_SHA1_Update
#define wpapsk_SHA1_Final  blk_SHA1_Final
#define wpapsk_SHA1_Clone(d, s) \
    do { memmove((d), (s), sizeof(blk_SHA_CTX)); } while (0)

/* ── Back-end selection (Adapter pattern) ──────────────────────────── */

#ifdef GCRYPT_WITH_SHA1
#  include <gcrypt.h>
#  define Digest_SHA1_CTX gcry_md_hd_t
#elif defined(OPENSSL_WITH_SHA1)
#  include <openssl/evp.h>
#  define Digest_SHA1_CTX EVP_MD_CTX
#else
/* Generic back-end: plain struct, no heap needed for context storage. */
typedef struct Air_SHA1_CTX {
    uint32_t total[2];
    uint32_t state[5];
    uint8_t  buffer[64];
} Digest_SHA1_CTX;
#endif

/* ── Constants ─────────────────────────────────────────────────────── */

enum : size_t {
    DIGEST_SHA1_MAC_LEN = 20u,
    DIGEST_SHA1_BLK_LEN = 64u,
};

/* ── Low-level context API ─────────────────────────────────────────── */

[[nodiscard]] AIR_EXPORT Digest_SHA1_CTX *Digest_SHA1_Create(void);
AIR_EXPORT void Digest_SHA1_Destroy(Digest_SHA1_CTX *ctx);
AIR_EXPORT void Digest_SHA1_Clone(Digest_SHA1_CTX **dst, const Digest_SHA1_CTX *src);

[[nodiscard]] AIR_EXPORT int Digest_SHA1_Init(Digest_SHA1_CTX *ctx);
[[nodiscard]] AIR_EXPORT int Digest_SHA1_Update(Digest_SHA1_CTX *ctx,
                                                 const uint8_t   *input,
                                                 size_t           ilen);
[[nodiscard]] AIR_EXPORT int Digest_SHA1_Finish(Digest_SHA1_CTX *ctx,
                                                 uint8_t output[static DIGEST_SHA1_MAC_LEN]);
[[nodiscard]] AIR_EXPORT int Digest_Internal_SHA1_Process(
    Digest_SHA1_CTX *ctx,
    const uint8_t    data[static DIGEST_SHA1_BLK_LEN]);

/* ── One-shot and vector APIs ──────────────────────────────────────── */

[[nodiscard]] AIR_EXPORT
int Digest_SHA1(const uint8_t *input, size_t ilen,
                uint8_t output[static DIGEST_SHA1_MAC_LEN]);

[[nodiscard]] AIR_EXPORT
int Digest_SHA1_Vector(size_t         num_elem,
                       const uint8_t *addrs[static num_elem],
                       const size_t   lengths[static num_elem],
                       uint8_t        output[static DIGEST_SHA1_MAC_LEN]);

/* ── HMAC-SHA-1 (RFC 2104) ─────────────────────────────────────────── */

[[nodiscard]] AIR_EXPORT
int MAC_HMAC_SHA1_Vector(size_t         key_len,
                         const uint8_t  key[static key_len],
                         size_t         num_elem,
                         const uint8_t *addr[],
                         const size_t  *len,
                         uint8_t        mac[static DIGEST_SHA1_MAC_LEN]);

[[nodiscard]] AIR_EXPORT
int MAC_HMAC_SHA1(size_t        key_len,
                  const uint8_t key[static key_len],
                  size_t        data_len,
                  const uint8_t data[static data_len],
                  uint8_t       output[static DIGEST_SHA1_MAC_LEN]);

/* ── Key derivation ────────────────────────────────────────────────── */

/* PBKDF2-HMAC-SHA1 — IEEE 802.11i WPA-PSK PMK derivation (4096 iters) */
[[nodiscard]] AIR_EXPORT
int KDF_PBKDF2_SHA1(const uint8_t *passphrase,
                    const uint8_t *ssid,
                    size_t         ssid_len,
                    size_t         iterations,
                    uint8_t       *buf,
                    size_t         buflen);

/* SHA1-PRF — IEEE 802.11i §8.5.1.1, PTK expansion */
[[nodiscard]] AIR_EXPORT
int SHA1_PRF(const uint8_t *key, size_t key_len,
             const uint8_t *label,
             const uint8_t *data, size_t data_len,
             uint8_t *buf, size_t buf_len);
