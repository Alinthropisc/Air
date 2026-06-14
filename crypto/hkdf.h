/*
 * HKDF — HMAC-based Key Derivation Function (RFC 5869).
 *
 * Used in WPA3-SAE (Simultaneous Authentication of Equals) for PMK
 * derivation and in the 802.11ax security handshake.
 *
 * Two-phase design:
 *   1. HKDF-Extract(salt, ikm)   → PRK  (pseudo-random key, 32 bytes)
 *   2. HKDF-Expand(PRK, info, L) → OKM  (output key material, up to 255×32 B)
 *
 * Both SHA-256 and SHA-384 variants are provided because WPA3-SAE-ECC
 * uses H-256 while WPA3-SAE-FFC may use H-384.
 *
 * Air Project 2026.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Design pattern — Template Method:
 *   air_hkdf_sha256_* / air_hkdf_sha384_* share the same algorithmic
 *   skeleton; only the underlying HMAC primitive differs.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "../defs.h"

/* ── Constants ─────────────────────────────────────────────────────── */

enum : size_t {
    HKDF_SHA256_PRK_LEN    = 32u,
    HKDF_SHA384_PRK_LEN    = 48u,
    HKDF_MAX_OUTPUT_SHA256 = 255u * 32u,   /* RFC 5869 §2.3 upper bound */
    HKDF_MAX_OUTPUT_SHA384 = 255u * 48u,
};

/* ── SHA-256 variant ────────────────────────────────────────────────── */

/* air_hkdf_sha256_extract - RFC 5869 §2.2 Extract.
 * salt may be NULL (replaced by 32 zero bytes per spec).
 */
[[nodiscard]] AIR_EXPORT
int air_hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                              const uint8_t *ikm,  size_t ikm_len,
                              uint8_t        prk[static HKDF_SHA256_PRK_LEN]);

/* air_hkdf_sha256_expand - RFC 5869 §2.3 Expand.
 * okm_len must be ≤ HKDF_MAX_OUTPUT_SHA256.
 */
[[nodiscard]] AIR_EXPORT
int air_hkdf_sha256_expand(const uint8_t prk[static HKDF_SHA256_PRK_LEN],
                             const uint8_t *info, size_t info_len,
                             uint8_t       *okm,  size_t okm_len);

/* air_hkdf_sha256 - Combined one-shot Extract+Expand. */
[[nodiscard]] AIR_EXPORT
int air_hkdf_sha256(const uint8_t *salt,  size_t salt_len,
                     const uint8_t *ikm,   size_t ikm_len,
                     const uint8_t *info,  size_t info_len,
                     uint8_t       *okm,   size_t okm_len);

/* ── SHA-384 variant (WPA3-SAE-FFC, 192-bit security level) ─────────── */

[[nodiscard]] AIR_EXPORT
int air_hkdf_sha384_extract(const uint8_t *salt, size_t salt_len,
                              const uint8_t *ikm,  size_t ikm_len,
                              uint8_t        prk[static HKDF_SHA384_PRK_LEN]);

[[nodiscard]] AIR_EXPORT
int air_hkdf_sha384_expand(const uint8_t prk[static HKDF_SHA384_PRK_LEN],
                             const uint8_t *info, size_t info_len,
                             uint8_t       *okm,  size_t okm_len);

[[nodiscard]] AIR_EXPORT
int air_hkdf_sha384(const uint8_t *salt,  size_t salt_len,
                     const uint8_t *ikm,   size_t ikm_len,
                     const uint8_t *info,  size_t info_len,
                     uint8_t       *okm,   size_t okm_len);

/* ── WPA3-SAE convenience wrappers ─────────────────────────────────── */

/* air_wpa3_sae_kck_pmk - Derive KCK and PMK from SAE session data.
 *
 * Implements IEEE 802.11-2020 §12.4.5.4:
 *   PMK = HKDF-SHA256-Expand(PRK, "SAE PMK", 32)
 *   KCK = HKDF-SHA256-Expand(PRK, "SAE KCK", 32)
 *
 * pwe_xy : elliptic-curve point (X||Y coordinates) from Rust SAE layer
 * rand   : random scalar from this side
 *
 * TODO(rust): scalar multiplication to produce pwe_xy belongs in Rust
 * (curve25519-dalek or p256 crate). Pass already-derived coordinates here.
 */
[[nodiscard]] AIR_EXPORT
int air_wpa3_sae_kck_pmk(const uint8_t *pwe_xy, size_t pwe_len,
                           const uint8_t *rand,   size_t rand_len,
                           uint8_t        pmk[static 32u],
                           uint8_t        kck[static 32u]);
