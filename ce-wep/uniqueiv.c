/*
 * IV uniqueness tracking and WEP cloaking detection.
 *
 * C23 rewrite of the original aircrack-ng uniqueiv module.
 * Copyright (C) 2004-2008 Stanislaw Pusep (original algorithm)
 * Copyright (C) 2026 Air Project (C23 rewrite)
 *
 * Two-level lazy bitmap:
 *   Level 0: air_uiv_s.level_1[256]  — indexed by iv[0]
 *   Level 1: 8192-byte leaf bitmap    — indexed by iv[1]<<8|iv[2]
 *
 * Total worst-case RAM: 256 × 8192 B = 2 MiB (same as a flat bitmap),
 * but leaves are only allocated the first time their iv[0] is seen.
 */

#include <stdlib.h>
#include <string.h>

#include "../defs.h"
#include "uniqueiv.h"

/* 65536 (iv[1]<<8|iv[2]) combinations stored as bits: 65536/8 = 8192 */
#define LEVEL2_BYTES 8192u

/* Per-IV layout for cloaking detection: seen-flag (1 B) + payload (2 B) */
#define IV_DATA_STRIDE 3u

/* ── opaque struct definitions ─────────────────────────────────────── */

struct air_uiv_s {
    uint8_t  *level_1[256]; /* lazy 8192-byte bitmaps, one per iv[0]   */
    uint32_t  count;        /* unique IVs marked so far                 */
};

struct air_iv_data_s {
    uint8_t *slots;         /* AIR_IV_SPACE × IV_DATA_STRIDE flat array */
};

/* ── air_uiv_t ─────────────────────────────────────────────────────── */

[[nodiscard]]
air_uiv_t *air_uiv_create(void)
{
    return calloc(1, sizeof(air_uiv_t));
}

[[nodiscard]]
AirIvStatus air_uiv_mark(air_uiv_t *uiv, const uint8_t iv[AIR_IV_SIZE])
{
    REQUIRE(uiv != nullptr);
    REQUIRE(iv  != nullptr);

    if (uiv->level_1[iv[0]] == nullptr) {
        uiv->level_1[iv[0]] = calloc(LEVEL2_BYTES, 1);
        if (uiv->level_1[iv[0]] == nullptr) return AIR_IV_ERR;
    }

    uint32_t idx  = ((uint32_t)iv[1] << 8u) | (uint32_t)iv[2];
    uint32_t byte = idx >> 3u;
    uint8_t  bit  = (uint8_t)(1u << (idx & 7u));

    if (uiv->level_1[iv[0]][byte] & bit) return AIR_IV_SEEN;

    uiv->level_1[iv[0]][byte] |= bit;
    uiv->count++;
    return AIR_IV_NOT_SED;
}

[[nodiscard]]
AirIvStatus air_uiv_check(const air_uiv_t *uiv, const uint8_t iv[AIR_IV_SIZE])
{
    REQUIRE(uiv != nullptr);
    REQUIRE(iv  != nullptr);

    if (uiv->level_1[iv[0]] == nullptr) return AIR_IV_NOT_SED;

    uint32_t idx  = ((uint32_t)iv[1] << 8u) | (uint32_t)iv[2];
    uint32_t byte = idx >> 3u;
    uint8_t  bit  = (uint8_t)(1u << (idx & 7u));

    return (uiv->level_1[iv[0]][byte] & bit) ? AIR_IV_SEEN : AIR_IV_NOT_SED;
}

[[nodiscard]]
uint32_t air_uiv_count(const air_uiv_t *uiv)
{
    REQUIRE(uiv != nullptr);
    return uiv->count;
}

void air_uiv_destroy(air_uiv_t *uiv)
{
    if (uiv == nullptr) return;

    for (size_t i = 0; i < 256; i++) {
        if (uiv->level_1[i] != nullptr) {
            free(uiv->level_1[i]);
        }
    }
    free(uiv);
}

/* ── air_iv_data_t (WEP cloaking detection) ───────────────────────── */

[[nodiscard]]
air_iv_data_t *air_iv_data_create(void)
{
    air_iv_data_t *d = calloc(1, sizeof(air_iv_data_t));
    if (d == nullptr) return nullptr;

    /* AIR_IV_SPACE IVs × 3 bytes: seen-flag + 2 payload bytes (~48 MiB) */
    d->slots = calloc(AIR_IV_SPACE, IV_DATA_STRIDE);
    if (d->slots == nullptr) {
        free(d);
        return nullptr;
    }
    return d;
}

[[nodiscard]]
AirCloakStatus air_iv_data_check(air_iv_data_t  *data,
                                  const uint8_t   iv[AIR_IV_SIZE],
                                  const uint8_t   payload[2])
{
    REQUIRE(data    != nullptr);
    REQUIRE(iv      != nullptr);
    REQUIRE(payload != nullptr);

    uint32_t pos = air_iv_to_index(iv) * IV_DATA_STRIDE;

    if (data->slots[pos] == 0) {
        data->slots[pos]     = 1;
        data->slots[pos + 1] = payload[0];
        data->slots[pos + 2] = payload[1];
        return AIR_CLOAK_NONE;
    }

    return (data->slots[pos + 1] != payload[0] || data->slots[pos + 2] != payload[1])
           ? AIR_CLOAK_PRESENT
           : AIR_CLOAK_NONE;
}

void air_iv_data_destroy(air_iv_data_t *data)
{
    if (data == nullptr) return;
    free(data->slots);
    free(data);
}
