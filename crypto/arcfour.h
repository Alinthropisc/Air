/*
 * ARC4 (RC4) stream cipher.
 *
 * WARNING: RC4 is cryptographically broken. Retained only because WEP
 * and WPA-TKIP mandate it. Do NOT use for new protocol work.
 *
 * Original: The Mbed TLS Contributors
 * C23 modernisation: Air Project 2026.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Design pattern — Adapter:
 *   gcrypt / OpenSSL ≥3 / OpenSSL <3 / generic back-ends behind
 *   one stable interface. Callers see only Cipher_RC4_KEY.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "../defs.h"

/* ── Back-end selection ────────────────────────────────────────────── */

#ifdef GCRYPT_WITH_ARCFOUR
#  include <gcrypt.h>
#  define Cipher_RC4_KEY gcry_cipher_hd_t

#elif defined(OPENSSL_WITH_ARCFOUR)
#  include <openssl/opensslv.h>
#  if OPENSSL_VERSION_NUMBER < 0x30000000L
#    include <openssl/rc4.h>
#    define Cipher_RC4_KEY     RC4_KEY
#    define Cipher_RC4_set_key RC4_set_key
#    define Cipher_RC4         RC4
#  else
#    include <openssl/evp.h>
#    define Cipher_RC4_KEY EVP_CIPHER_CTX
#  endif

#else
/* Generic back-end: pure-C KSA, no external deps. */
typedef struct Air_RC4_KEY {
    uint32_t x;
    uint32_t y;
    uint8_t  m[256];
} Cipher_RC4_KEY;
#endif

/* ── API ─────────────────────────────────────────────────────────────── */

/* Cipher_RC4_set_key - RC4 key schedule (KSA).
 * Must be called before any Cipher_RC4 call on a context.
 */
AIR_EXPORT
void Cipher_RC4_set_key(Cipher_RC4_KEY *ctx,
                         size_t          keylen,
                         const uint8_t  *key);

/* Cipher_RC4 - Encrypt or decrypt @length bytes in-place or copy.
 * RC4 is self-inverse: same function encrypts and decrypts.
 * input and output may point to the same buffer (in-place).
 */
[[nodiscard]] AIR_EXPORT
int Cipher_RC4(Cipher_RC4_KEY *ctx,
               size_t          length,
               const uint8_t  *input,
               uint8_t        *output);
