/*
 * air-crypto — C23 MIC / PRF public API.
 *
 * HMAC-MD5, HMAC-SHA1, and IEEE 802.11 PRF-512 — the primitives needed
 * to verify WPA/WPA2 handshake MICs and derive PTKs.
 */
#ifndef AIR_MIC_H
#define AIR_MIC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Output length constants */
#define AIR_MD5_LEN    16u  /* HMAC-MD5 output     */
#define AIR_SHA1_LEN   20u  /* HMAC-SHA1 output    */
#define AIR_PRF512_LEN 64u  /* IEEE 802.11 PRF-512 */

/*
 * HMAC-SHA1 (RFC 2104).
 * Used for: WPA2/CCMP MIC verification, PRF-512 building block.
 * Returns 0 on success, non-zero on invalid arguments.
 */
int air_hmac_sha1(const uint8_t *key,  size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t out[static AIR_SHA1_LEN]);

/*
 * HMAC-MD5 (RFC 2104).
 * Used for: WPA1/TKIP MIC verification (key version 1).
 * Returns 0 on success, non-zero on invalid arguments.
 */
int air_hmac_md5(const uint8_t *key,  size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[static AIR_MD5_LEN]);

/*
 * IEEE 802.11 PRF-512 (section 12.7.1.2).
 * Derives 64 bytes of Pairwise Transient Key material.
 *
 *   key       — PMK (32 bytes for WPA2)
 *   label     — ASCII label, e.g. "Pairwise key expansion"
 *   data      — ordered MACs + nonces (76 bytes for WPA2)
 *   out[64]   — PTK output buffer
 *
 * Returns 0 on success, non-zero on invalid arguments.
 */
int air_prf512(const uint8_t *key,   size_t key_len,
               const uint8_t *label, size_t label_len,
               const uint8_t *data,  size_t data_len,
               uint8_t out[static AIR_PRF512_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* AIR_MIC_H */
