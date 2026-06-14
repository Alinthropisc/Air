/* air-ptw-lib — PTW WEP key recovery. C23. Renamed from aircrack-ptw-lib. */
/*
 * PTW (Tews-Weinmann-Pychkine) WEP key-recovery attack.
 *
 * Copyright (c) 2007-2009 Erik Tews, Andrei Pychkine, Ralf-Philipp Weinmann.
 * Copyright (c) 2013 Ramiro Polla.
 * Copyright (c) 2026 Air Project — C23 modernisation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Design patterns applied:
 *  - Strategy  : rc4_test_fn is a replaceable algorithm slot (fast AMD64 asm
 *                vs. portable C; the implementation selects at init time).
 *  - Opaque handle : PTW_attack_ctx is forward-declared; callers only see
 *                    the API below (information hiding / encapsulation).
 *  - Named constants: all magic numbers replaced by typed enum constants.
 *  - Compat shims : thin inline wrappers preserve the legacy call-sites.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "../defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── compile-time constants ─────────────────────────────────────────── */

enum : uint32_t {
    PTW_IV_TABLE_BYTES   = 2097152u,  /* (2^24)/8 — seen-IV bitmap size     */
    PTW_CONTROL_SESSIONS = 10000u,    /* sessions used to verify a key guess */
    PTW_KEY_HS_BYTES     = 29u,       /* max main-key length (104-bit = 13 B)*/
    PTW_IV_BYTES         = 3u,        /* IV length for WEP                   */
    PTW_KS_BYTES         = 32u,       /* keystream bytes collected per packet */
    PTW_ALPHABET         = 256u,      /* RC4 state size (n)                  */
};

/* Flags for PTW_compute_key — which sub-attacks to enable/skip */
enum PtwAttackFlags : uint32_t {
    PTW_SKIP_KLEIN = 0x01u,
    PTW_SKIP_PTW   = 0x02u,
};

/* Legacy flag aliases so old callers still compile */
#define NO_KLEIN  PTW_SKIP_KLEIN
#define NO_PTW    PTW_SKIP_PTW

/* ── data types ─────────────────────────────────────────────────────── */

/* Strategy interface — RC4 key-stream verification.
 * Returns 1 if key+iv reproduces the expected keystream prefix. */
typedef int (*rc4_test_fn)(uint8_t *key, int keylen,
                            uint8_t *iv,  uint8_t *keystream);

/* Vote entry for one key-byte candidate */
typedef struct PtwTableEntry {
    int32_t  votes;
    uint8_t  b;
    uint8_t  _pad[3];
} PtwTableEntry;

/* One recovered WEP session */
typedef struct PtwSession {
    uint8_t iv[PTW_IV_BYTES];
    uint8_t keystream[PTW_KS_BYTES];
    int32_t weight;
} PtwSession;

/* Opaque attack context — allocated/freed via PTW_attack_create/destroy */
typedef struct PTW_attack_ctx PTW_attack_ctx;

/* ── primary API ─────────────────────────────────────────────────────── */

/**
 * PTW_attack_create - Allocate a fresh attack context.
 *
 * Selects the best available RC4 implementation automatically
 * (AMD64 SSE2 assembly when the CPU supports it, portable C otherwise).
 *
 * @return new context, or nullptr on OOM.
 */
[[nodiscard]]
AIR_EXPORT PTW_attack_ctx *PTW_attack_create(void);

/**
 * PTW_attack_destroy - Release an attack context.
 * Safe to call with nullptr.
 */
AIR_EXPORT void PTW_attack_destroy(PTW_attack_ctx *ctx);

/**
 * PTW_add_session - Feed one captured IV+keystream pair.
 *
 * @param ctx        attack context
 * @param iv         3-byte WEP IV
 * @param keystream  recovered keystream bytes (at least PTW_KS_BYTES)
 * @param weight     per-byte confidence weights, or nullptr
 * @param weight_len number of entries in weight[]
 *
 * @return true  — session accepted (unique IV, space available)
 * @return false — duplicate IV or context full
 */
[[nodiscard]]
AIR_EXPORT bool PTW_add_session(PTW_attack_ctx *ctx,
                                 uint8_t        *iv,
                                 uint8_t        *keystream,
                                 int32_t        *weight,
                                 int32_t         weight_len);

/**
 * PTW_compute_key - Attempt to recover the WEP key.
 *
 * @param ctx         attack context
 * @param key         output buffer for recovered key bytes
 * @param key_bytes   key length to recover (5 for WEP-40, 13 for WEP-104)
 * @param max_tries   candidate limit before giving up
 * @param starts      per-position depth hints, or nullptr
 * @param vote_table  accumulated per-position vote table
 * @param flags       bitmask of PtwAttackFlags
 *
 * @return true  — key found (written to *key)
 * @return false — not enough data / key not found
 */
[[nodiscard]]
AIR_EXPORT bool PTW_compute_key(PTW_attack_ctx *ctx,
                                 uint8_t        *key,
                                 int32_t         key_bytes,
                                 int32_t         max_tries,
                                 int32_t        *starts,
                                 int32_t         vote_table[][PTW_ALPHABET],
                                 uint32_t        flags);

/* ── legacy shims (keep old callers compiling without changes) ──────── */

static inline PTW_attack_ctx *PTW_newattackstate(void)
{
    return PTW_attack_create();
}

static inline void PTW_freeattackstate(PTW_attack_ctx *ctx)
{
    PTW_attack_destroy(ctx);
}

static inline int PTW_addsession(PTW_attack_ctx *ctx,
                                  uint8_t *iv, uint8_t *ks,
                                  int *weight, int wlen)
{
    return PTW_add_session(ctx, iv, ks, (int32_t *)weight, (int32_t)wlen) ? 1 : 0;
}

static inline int PTW_computeKey(PTW_attack_ctx *ctx,
                                  uint8_t *key, int kb, int tries,
                                  int *starts,
                                  int vote_table[][PTW_ALPHABET],
                                  int attacks)
{
    return PTW_compute_key(ctx, key, (int32_t)kb, (int32_t)tries,
                           starts, vote_table, (uint32_t)attacks) ? 1 : 0;
}

#ifdef __cplusplus
}
#endif
