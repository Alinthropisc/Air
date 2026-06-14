/*
 * AES cipher — ECB, CTR, GCM, and key-wrap.
 *
 * Original: Jouni Malinen <j@w1.fi>
 * C23 modernisation + new CTR/GCM/key-wrap API: Air Project 2026.
 *
 * SPDX-License-Identifier: BSD-3-CLAUSE
 *
 * Design pattern — Adapter:
 *   gcrypt / OpenSSL / generic back-ends behind one stable interface.
 *
 * New in 2026:
 *   - AES-CTR  : for GCMP cipher-suite processing
 *   - AES-GCM  : WPA3-GCMP-256 authenticated encryption
 *   - Key wrap : RFC 3394, used in WPA3-SAE key transport
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "../defs.h"

/* ── Back-end context type ─────────────────────────────────────────── */

#ifdef GCRYPT_WITH_AES
#  include <gcrypt.h>
#  define Cipher_AES_CTX gcry_cipher_hd_t
#elif defined(OPENSSL_WITH_AES)
#  include <openssl/evp.h>
#  define Cipher_AES_CTX EVP_CIPHER_CTX
#else
typedef struct Air_AES_CTX Air_AES_CTX;
#  define Cipher_AES_CTX Air_AES_CTX
#endif

/* ── Constants ─────────────────────────────────────────────────────── */

enum : size_t {
    AES_BLOCK_LEN   = 16u,
    AES_KEY_LEN_128 = 16u,
    AES_KEY_LEN_192 = 24u,
    AES_KEY_LEN_256 = 32u,
    AES_GCM_TAG_LEN = 16u,
    AES_CCM_TAG_LEN =  8u,   /* CCM MIC used in CCMP (802.11i) */
};

/* ── AES-ECB single-block — internal building block for CCM/CTR ───── */

[[nodiscard]]
AIR_EXPORT Cipher_AES_CTX *Cipher_AES_Encrypt_Init(size_t key_len, const uint8_t *key);

[[nodiscard]]
AIR_EXPORT int Cipher_AES_Encrypt(Cipher_AES_CTX *ctx, const uint8_t *plain,uint8_t *crypt);

AIR_EXPORT void Cipher_AES_Encrypt_Deinit(Cipher_AES_CTX *ctx);

/* ── AES-CTR — in-place encrypt/decrypt ───────────────────────────── */

/* CTR mode is self-inverse: same function encrypts and decrypts.
 * nonce   : 12 bytes (96-bit)
 * counter : 32-bit block counter (starts at 1 per RFC 3686, or 0 for GCMP)
 */
[[nodiscard]]
AIR_EXPORT int air_aes_ctr_xcrypt(const uint8_t *key, size_t key_len,const uint8_t  nonce[12],uint32_t counter,uint8_t *data, size_t len);

/* ── AES-GCM — authenticated encryption for WPA3/GCMP-256 ─────────── */

[[nodiscard]]
AIR_EXPORT int air_aes_gcm_encrypt(const uint8_t *key, size_t key_len,const uint8_t iv[12],const uint8_t *aad, size_t aad_len,const uint8_t *plaintext, size_t len,uint8_t *ciphertext,uint8_t tag[AES_GCM_TAG_LEN]);

/* Returns true on authenticated success; MUST discard output on false. */
[[nodiscard]]
AIR_EXPORT bool air_aes_gcm_decrypt(const uint8_t *key, size_t key_len,const uint8_t  iv[12],const uint8_t *aad, size_t aad_len,const uint8_t *ciphertext, size_t len,const uint8_t tag[AES_GCM_TAG_LEN],uint8_t *plaintext);

/* ── AES Key Wrap (RFC 3394) — WPA3-SAE key transport ─────────────── */

/* Output = key_len + 8 bytes */
[[nodiscard]]
AIR_EXPORT int air_aes_key_wrap(const uint8_t *kek, size_t kek_len,const uint8_t *key, size_t key_len,uint8_t *out);

/* Returns 0 on success, -1 on integrity failure. */
[[nodiscard]]
AIR_EXPORT int air_aes_key_unwrap(const uint8_t *kek, size_t kek_len,const uint8_t *wrapped, size_t wrapped_len,uint8_t *out);
