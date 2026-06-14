/*
 * air-crypto — C23 cryptographic core.
 *
 * First vertical slice: WPA PMK derivation via PBKDF2-HMAC-SHA1.
 * Self-contained (no OpenSSL/gcrypt), modern C23, designed to be driven
 * from an async Rust front-end through a thin FFI.
 */
#ifndef AIR_PBKDF2_SHA1_H
#define AIR_PBKDF2_SHA1_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* WPA Pairwise Master Key length, in bytes. */
#define AIR_PMK_LEN 32u

/*
 * Generic PBKDF2-HMAC-SHA1 (RFC 2898 / PKCS #5).
 *
 * Writes `out_len` derived bytes into `out`.
 * Returns 0 on success, non-zero on invalid arguments.
 */
int air_pbkdf2_sha1(const uint8_t *passphrase, size_t passphrase_len,
                    const uint8_t *salt, size_t salt_len,
                    uint32_t iterations,
                    uint8_t *out, size_t out_len);

/*
 * Convenience wrapper: derive a 32-byte WPA PMK from an ASCII passphrase
 * and ESSID using the WPA parameters (4096 iterations, ESSID as salt).
 * Returns 0 on success, non-zero on invalid arguments.
 */
int air_calc_pmk(const char *passphrase, const char *essid,
                 uint8_t out[static AIR_PMK_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* AIR_PBKDF2_SHA1_H */
