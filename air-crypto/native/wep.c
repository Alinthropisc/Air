/* air-crypto — WEP RC4 stream cipher + key verification. C23.
 * Pattern: Strategy — rc4_keystream is the pluggable primitive;
 *           wep_verify is the policy layer on top.            */
#include "wep.h"
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* RC4 KSA + PRGA — self-contained, no external deps */

typedef struct { uint8_t s[256]; uint32_t i, j; } Rc4Ctx;

static void rc4_init(Rc4Ctx *ctx, const uint8_t *key, size_t key_len) {
    for (uint32_t i = 0; i < 256; i++) ctx->s[i] = (uint8_t)i;
    uint32_t j = 0;
    for (uint32_t i = 0; i < 256; i++) {
        j = (j + ctx->s[i] + key[i % key_len]) & 0xFF;
        uint8_t tmp = ctx->s[i]; ctx->s[i] = ctx->s[j]; ctx->s[j] = tmp;
    }
    ctx->i = ctx->j = 0;
}

static uint8_t rc4_byte(Rc4Ctx *ctx) {
    ctx->i = (ctx->i + 1) & 0xFF;
    ctx->j = (ctx->j + ctx->s[ctx->i]) & 0xFF;
    uint8_t tmp = ctx->s[ctx->i]; ctx->s[ctx->i] = ctx->s[ctx->j]; ctx->s[ctx->j] = tmp;
    return ctx->s[(ctx->s[ctx->i] + ctx->s[ctx->j]) & 0xFF];
}

/* air_rc4_xcrypt — XOR data in-place with RC4 keystream */
int air_rc4_xcrypt(const uint8_t *key, size_t key_len,
                   uint8_t *data, size_t data_len) {
    if (!key || !data || key_len == 0) return -1;
    Rc4Ctx ctx;
    rc4_init(&ctx, key, key_len);
    for (size_t i = 0; i < data_len; i++) data[i] ^= rc4_byte(&ctx);
    return 0;
}

/* air_wep_decrypt — decrypt WEP payload: prepend 3-byte IV to key,
 * decrypt, verify ICV (last 4 bytes = CRC32 of plaintext).
 *
 * key     : WEP key bytes (5 or 13 bytes for WEP-40/WEP-104)
 * key_len : 5 or 13
 * iv      : 3-byte IV from the frame
 * cipher  : ciphertext (payload + ICV)
 * plain   : output buffer (same length as cipher)
 * Returns 0 if ICV matches, -1 on error, -2 on ICV mismatch.
 */
int air_wep_decrypt(const uint8_t *key,    size_t key_len,
                    const uint8_t  iv[3],
                    const uint8_t *cipher, size_t cipher_len,
                    uint8_t       *plain) {
    if (!key || !iv || !cipher || !plain || key_len == 0 || cipher_len < 4) return -1;

    /* Combined IV+key for RC4 seed */
    uint8_t seed[16];
    seed[0] = iv[0]; seed[1] = iv[1]; seed[2] = iv[2];
    if (key_len > 13) key_len = 13;
    memcpy(seed + 3, key, key_len);
    size_t seed_len = 3 + key_len;

    memcpy(plain, cipher, cipher_len);
    Rc4Ctx ctx;
    rc4_init(&ctx, seed, seed_len);
    for (size_t i = 0; i < cipher_len; i++) plain[i] ^= rc4_byte(&ctx);

    /* CRC32 ICV check (IEEE 802.11 uses CRC32 with poly 0xEDB88320) */
    uint32_t crc = 0xFFFFFFFFu;
    size_t data_len = cipher_len - 4;
    for (size_t i = 0; i < data_len; i++) {
        crc ^= plain[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1u));
    }
    crc ^= 0xFFFFFFFFu;

    uint32_t icv = (uint32_t)plain[data_len]
                 | ((uint32_t)plain[data_len+1] << 8)
                 | ((uint32_t)plain[data_len+2] << 16)
                 | ((uint32_t)plain[data_len+3] << 24);
    return (crc == icv) ? 0 : -2;
}
