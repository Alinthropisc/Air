/*
 * HKDF — HMAC-based Key Derivation Function (RFC 5869).
 *
 * Air Project 2026.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "../defs.h"
#include "hkdf.h"
#include "sha256.h"

/* ── SHA-256 backend ──────────────────────────────────────────────── */

AIR_EXPORT
int air_hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                              const uint8_t *ikm,  size_t ikm_len,
                              uint8_t        prk[static HKDF_SHA256_PRK_LEN])
{
    REQUIRE(ikm != nullptr && ikm_len > 0u);
    REQUIRE(prk != nullptr);

    /* If salt is omitted, use 32 zero bytes (RFC 5869 §2.2) */
    static const uint8_t k_zero_salt[HKDF_SHA256_PRK_LEN] = {0};
    if (salt == nullptr || salt_len == 0u) {
        salt     = k_zero_salt;
        salt_len = HKDF_SHA256_PRK_LEN;
    }

    return MAC_HMAC_SHA256(salt_len, salt, ikm_len, ikm, prk);
}

AIR_EXPORT
int air_hkdf_sha256_expand(const uint8_t prk[static HKDF_SHA256_PRK_LEN],
                             const uint8_t *info, size_t info_len,
                             uint8_t       *okm,  size_t okm_len)
{
    REQUIRE(prk != nullptr);
    REQUIRE(okm != nullptr && okm_len > 0u);
    REQUIRE(okm_len <= HKDF_MAX_OUTPUT_SHA256);

    uint8_t  t[HKDF_SHA256_PRK_LEN]; /* T(i) block */
    uint8_t  counter;
    size_t   done = 0u;
    size_t   tlen = 0u; /* T(0) = empty */

    /* RFC 5869 §2.3: T(i) = HMAC-Hash(PRK, T(i-1) || info || i) */
    for (counter = 1u; done < okm_len; ++counter) {
        const uint8_t *addr[3] = { t, info, &counter };
        size_t         lens[3] = { tlen, info_len, 1u };

        if (MAC_HMAC_SHA256_Vector(HKDF_SHA256_PRK_LEN, prk,
                                   3u, addr, lens, t) != 0)
            return -1;
        tlen = HKDF_SHA256_PRK_LEN;

        size_t copy = okm_len - done;
        if (copy > HKDF_SHA256_PRK_LEN) copy = HKDF_SHA256_PRK_LEN;
        memcpy(okm + done, t, copy);
        done += copy;
    }
    return 0;
}

AIR_EXPORT
int air_hkdf_sha256(const uint8_t *salt,  size_t salt_len,
                     const uint8_t *ikm,   size_t ikm_len,
                     const uint8_t *info,  size_t info_len,
                     uint8_t       *okm,   size_t okm_len)
{
    uint8_t prk[HKDF_SHA256_PRK_LEN];
    if (air_hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk) != 0)
        return -1;
    return air_hkdf_sha256_expand(prk, info, info_len, okm, okm_len);
}

/* ── SHA-384 backend ──────────────────────────────────────────────── */
/* TODO(rust): SHA-384 HMAC is not in the C crypto layer yet.
 * Stubs return -1 until the sha384 backend is added or Rust provides it.
 * WPA3-SAE-FFC (192-bit security) needs this path. */

AIR_EXPORT
int air_hkdf_sha384_extract(const uint8_t *salt, size_t salt_len,
                              const uint8_t *ikm,  size_t ikm_len,
                              uint8_t        prk[static HKDF_SHA384_PRK_LEN])
{
    (void)salt; (void)salt_len; (void)ikm; (void)ikm_len; (void)prk;
    return -1;
}

AIR_EXPORT
int air_hkdf_sha384_expand(const uint8_t prk[static HKDF_SHA384_PRK_LEN],
                             const uint8_t *info, size_t info_len,
                             uint8_t       *okm,  size_t okm_len)
{
    (void)prk; (void)info; (void)info_len; (void)okm; (void)okm_len;
    return -1;
}

AIR_EXPORT
int air_hkdf_sha384(const uint8_t *salt,  size_t salt_len,
                     const uint8_t *ikm,   size_t ikm_len,
                     const uint8_t *info,  size_t info_len,
                     uint8_t       *okm,   size_t okm_len)
{
    (void)salt; (void)salt_len; (void)ikm; (void)ikm_len;
    (void)info; (void)info_len; (void)okm; (void)okm_len;
    return -1;
}

/* ── WPA3-SAE convenience wrapper ─────────────────────────────────── */

AIR_EXPORT
int air_wpa3_sae_kck_pmk(const uint8_t *pwe_xy, size_t pwe_len,
                           const uint8_t *rand,   size_t rand_len,
                           uint8_t        pmk[static 32u],
                           uint8_t        kck[static 32u])
{
    REQUIRE(pwe_xy != nullptr && pwe_len > 0u);
    REQUIRE(rand   != nullptr && rand_len > 0u);
    REQUIRE(pmk    != nullptr);
    REQUIRE(kck    != nullptr);

    /* PRK = HKDF-SHA256-Extract(salt=0, IKM=pwe_xy || rand) */
    uint8_t ikm[512]; /* enough for any ECC curve point + scalar */
    if (pwe_len + rand_len > sizeof(ikm)) return -1;
    memcpy(ikm,           pwe_xy, pwe_len);
    memcpy(ikm + pwe_len, rand,   rand_len);

    uint8_t prk[HKDF_SHA256_PRK_LEN];
    if (air_hkdf_sha256_extract(nullptr, 0u, ikm, pwe_len + rand_len, prk) != 0)
        return -1;

    static const uint8_t k_pmk_label[] = "SAE PMK";
    if (air_hkdf_sha256_expand(prk, k_pmk_label, sizeof(k_pmk_label) - 1u,
                                pmk, 32u) != 0)
        return -1;

    static const uint8_t k_kck_label[] = "SAE KCK";
    if (air_hkdf_sha256_expand(prk, k_kck_label, sizeof(k_kck_label) - 1u,
                                kck, 32u) != 0)
        return -1;

    return 0;
}
