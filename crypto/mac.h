/*
 * Message Authentication Code (MAC) algorithms.
 *
 * Covers OMAC1/CMAC-AES and convenience wrappers used in IEEE 802.11i.
 *
 * Original: Jouni Malinen <j@w1.fi>
 * C23 modernisation + new API: Air Project 2026.
 *
 * SPDX-License-Identifier: BSD-3-CLAUSE
 *
 * Design pattern — Adapter:
 *   gcrypt / OpenSSL / generic OMAC1 implementations behind one stable
 *   interface. Callers never see back-end context types.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "../defs.h"

/* ── Back-end context ──────────────────────────────────────────────── */

#ifdef GCRYPT_WITH_CMAC
#  include <gcrypt.h>
#  define MAC_OMAC_CTX gcry_cipher_hd_t
#elif defined(OPENSSL_WITH_CMAC)
#  include <openssl/cmac.h>
#  define MAC_OMAC_CTX CMAC_CTX
#else
/* Generic back-end uses the AES ECB primitives from aes.h internally. */
typedef struct Air_OMAC_CTX Air_OMAC_CTX;
#  define MAC_OMAC_CTX Air_OMAC_CTX
#endif

/* ── Constants ─────────────────────────────────────────────────────── */

enum : size_t {
    MAC_CMAC_AES_128_LEN = 16u,   /* AES-128-CMAC tag length */
    MAC_CMAC_AES_256_LEN = 16u,   /* AES-256-CMAC tag length (same width) */
    MAC_MIC_LEN_TKIP     =  8u,   /* TKIP MIC (HMAC-MD5 truncated, keyver 1) */
    MAC_MIC_LEN_CCMP     =  8u,   /* CCMP MIC (AES-CMAC truncated, keyver 2) */
    MAC_MIC_LEN_GCMP     = 16u,   /* GCMP MIC (AES-GCM tag, keyver 3) */
};

/* ── OMAC1 / CMAC-AES vector API ───────────────────────────────────── */

/* MAC_OMAC1_AES_Vector - One-Key CBC MAC (OMAC1 == CMAC, NIST SP 800-38B).
 * key_len: 16 (AES-128) or 32 (AES-256).
 * addr/len: scatter-gather input; mac receives 16-byte tag.
 */
[[nodiscard]] AIR_EXPORT
int MAC_OMAC1_AES_Vector(size_t         key_len,
                          const uint8_t  key[static key_len],
                          size_t         count,
                          const uint8_t *addr[],
                          const size_t  *len,
                          uint8_t       *mac);

/* ── Convenience one-shot functions ────────────────────────────────── */

/* MAC_OMAC1_AES - One-shot OMAC1 over a single buffer. */
[[nodiscard]] AIR_EXPORT
int MAC_OMAC1_AES(size_t        key_len,
                  const uint8_t *key,
                  const uint8_t *data,
                  size_t         data_len,
                  uint8_t       *mac);

/* MAC_OMAC1_AES_128 - Convenience wrapper fixed at 16-byte (128-bit) key. */
[[nodiscard]] AIR_EXPORT
int MAC_OMAC1_AES_128(const uint8_t  key[static MAC_CMAC_AES_128_LEN],
                       const uint8_t *data,
                       size_t         data_len,
                       uint8_t        mac[static MAC_CMAC_AES_128_LEN]);

/* ── Streaming context API (for incremental MIC computation) ────────── */

/* Streaming OMAC1 used by CCMP/GCMP frame processors that feed data in chunks. */
[[nodiscard]] AIR_EXPORT
MAC_OMAC_CTX *MAC_OMAC1_AES_Create(const uint8_t *key, size_t key_len);

[[nodiscard]] AIR_EXPORT
int MAC_OMAC1_AES_Update(MAC_OMAC_CTX *ctx, const uint8_t *data, size_t len);

[[nodiscard]] AIR_EXPORT
int MAC_OMAC1_AES_Finish(MAC_OMAC_CTX *ctx,
                          uint8_t       mac[static MAC_CMAC_AES_128_LEN]);

AIR_EXPORT
void MAC_OMAC1_AES_Destroy(MAC_OMAC_CTX *ctx);

/* ── HMAC-SHA1-AES PRF (IEEE 802.11i §8.5.1.1) ─────────────────────── */

/* Derives key material via HMAC-SHA1 over label||data.
 * Shared header so all MAC consumers have a single include.
 * Implementation lives in mac-hmac-sha1-generic.c.
 */
[[nodiscard]] AIR_EXPORT
int MAC_HMAC_SHA1_AES_PRF(const uint8_t *key, size_t key_len,
                            const uint8_t *label,
                            const uint8_t *data, size_t data_len,
                            uint8_t       *output, size_t output_len);
