/* air-crypto — WEP/RC4 public API. C23. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define AIR_WEP40_KEY_LEN   5u
#define AIR_WEP104_KEY_LEN  13u

#ifdef __cplusplus
extern "C" {
#endif

/* In-place RC4 XOR. Returns 0 on success. */
int air_rc4_xcrypt(const uint8_t *key, size_t key_len,
                   uint8_t *data, size_t data_len);

/* Decrypt + ICV-verify a WEP frame payload.
 * Returns 0 = OK, -1 = bad args, -2 = ICV mismatch (wrong key). */
int air_wep_decrypt(const uint8_t *key,    size_t key_len,
                    const uint8_t  iv[3],
                    const uint8_t *cipher, size_t cipher_len,
                    uint8_t       *plain);

#ifdef __cplusplus
}
#endif
