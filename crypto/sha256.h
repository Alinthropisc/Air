/*
 * SHA-256 cryptographic hash function and PRF.
 *
 * Defined in FIPS 180-4. Used in IEEE 802.11r/ac/ax and WPA3-SAE.
 *
 * Original: Jouni Malinen <j@w1.fi>
 * C23 modernisation: Air Project 2026.
 *
 * SPDX-License-Identifier: BSD-3-CLAUSE
 *
 * Design pattern — Adapter:
 *   Three back-ends (gcrypt / OpenSSL / generic) behind one stable interface.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "../defs.h"

/* ── Back-end selection ────────────────────────────────────────────── */

#ifdef GCRYPT_WITH_SHA256
#  include <gcrypt.h>
#  define Digest_SHA256_CTX gcry_md_hd_t
#elif defined(OPENSSL_WITH_SHA256)
#  include <openssl/evp.h>
#  define Digest_SHA256_CTX EVP_MD_CTX
#else
typedef struct Air_SHA256_CTX {
    uint32_t total[2];
    uint32_t state[8];
    uint8_t  buffer[64];
} Digest_SHA256_CTX;
#endif

/* ── Constants ─────────────────────────────────────────────────────── */

enum : size_t {
    DIGEST_SHA256_MAC_LEN = 32u,
    DIGEST_SHA256_BLK_LEN = 64u,
};

/* ── Low-level context API ─────────────────────────────────────────── */

[[nodiscard]] AIR_EXPORT Digest_SHA256_CTX *Digest_SHA256_Create(void);
AIR_EXPORT void Digest_SHA256_Destroy(Digest_SHA256_CTX *ctx);
AIR_EXPORT void Digest_SHA256_Clone(Digest_SHA256_CTX **dst,
                                     const Digest_SHA256_CTX *src);
[[nodiscard]] AIR_EXPORT int Digest_SHA256_Init(Digest_SHA256_CTX *ctx);
[[nodiscard]] AIR_EXPORT int Digest_SHA256_Update(Digest_SHA256_CTX *ctx,
                                                   const uint8_t     *input,
                                                   size_t             ilen);
[[nodiscard]] AIR_EXPORT int Digest_SHA256_Finish(
    Digest_SHA256_CTX *ctx,
    uint8_t           *output);  /* must be DIGEST_SHA256_MAC_LEN bytes */

/* ── One-shot and vector ───────────────────────────────────────────── */

[[nodiscard]] AIR_EXPORT
int Digest_SHA256(const uint8_t *input, size_t ilen, uint8_t *output);

[[nodiscard]] AIR_EXPORT
int Digest_SHA256_Vector(size_t         num_elem,
                         const uint8_t *addrs[],
                         const size_t   lengths[],
                         uint8_t       *output);

/* ── HMAC-SHA-256 ──────────────────────────────────────────────────── */

[[nodiscard]] AIR_EXPORT
int MAC_HMAC_SHA256_Vector(size_t         key_len,
                            const uint8_t *key,
                            size_t         num_elem,
                            const uint8_t *addr[],
                            const size_t  *len,
                            uint8_t       *mac);

[[nodiscard]] AIR_EXPORT
int MAC_HMAC_SHA256(size_t        key_len,
                    const uint8_t *key,
                    size_t        data_len,
                    const uint8_t *data,
                    uint8_t       *output);

/* ── Key derivation ────────────────────────────────────────────────── */

/* IEEE 802.11-2012 §11.6.1.7.2 KDF — bit-addressed PRF-256 */
AIR_EXPORT
void Digest_SHA256_PRF_Bits(const uint8_t *key, size_t key_len,
                             const uint8_t *label,
                             const uint8_t *data, size_t data_len,
                             uint8_t *buf, size_t buf_len_bits);

/* PBKDF2-HMAC-SHA256 — WPA3-Enterprise and custom key stretching */
[[nodiscard]] AIR_EXPORT
int KDF_PBKDF2_SHA256(const uint8_t *passphrase,
                      const uint8_t *ssid, size_t ssid_len,
                      size_t         iterations,
                      uint8_t       *buf, size_t buflen);

/* SHA256-PRF — IEEE 802.11r FT key hierarchy */
[[nodiscard]] AIR_EXPORT
int SHA256_PRF(const uint8_t *key, size_t key_len,
               const uint8_t *label,
               const uint8_t *data, size_t data_len,
               uint8_t *buf, size_t buf_len);
