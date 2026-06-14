/*
 * PMKID computation — WPA2 key recovery without a 4-way handshake.
 *
 * Discovered by Jens Steube (@hashcat), August 2018.
 * Specification: IEEE 802.11-2016 §12.7.1.3
 *
 * Formula:
 *   PMKID = HMAC-SHA1-128( PMK, "PMK Name" || AP_MAC || STA_MAC )
 *
 * Only the first 16 bytes (128 bits) of the HMAC-SHA1 digest are used.
 * This allows offline brute-force against captured RSN IEs without waiting
 * for a client to associate.
 *
 * Air Project 2026.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "../defs.h"
#include "sha1.h"

/* ── Constants ─────────────────────────────────────────────────────── */

enum : size_t {
    PMKID_LEN     = 16u,   /* 128 bits — truncated HMAC-SHA1 */
    PMKID_PMK_LEN = 32u,   /* 256-bit PMK (output of PBKDF2-HMAC-SHA1) */
    PMKID_MAC_LEN =  6u,   /* IEEE 802 MAC address length */
};

/* ── Core computation ──────────────────────────────────────────────── */

/* air_pmkid_compute - Derive the PMKID from a candidate PMK.
 *
 * pmk    : 32-byte Pairwise Master Key (from PBKDF2-HMAC-SHA1)
 * ap_mac : 6-byte BSSID of the access point
 * sta_mac: 6-byte MAC of the station (client)
 * out    : 16-byte PMKID output buffer
 *
 * Returns 0 on success, -1 on underlying HMAC failure.
 */
[[nodiscard]] AIR_EXPORT
int air_pmkid_compute(const uint8_t pmk[static PMKID_PMK_LEN],
                       const uint8_t ap_mac[static PMKID_MAC_LEN],
                       const uint8_t sta_mac[static PMKID_MAC_LEN],
                       uint8_t       out[static PMKID_LEN]);

/* air_pmkid_verify - Constant-time compare of computed vs captured PMKID.
 *
 * Returns true if the candidate PMK matches the captured PMKID.
 * Constant-time to avoid timing oracles in dictionary attacks.
 */
[[nodiscard]] AIR_EXPORT
bool air_pmkid_verify(const uint8_t pmk[static PMKID_PMK_LEN],
                       const uint8_t ap_mac[static PMKID_MAC_LEN],
                       const uint8_t sta_mac[static PMKID_MAC_LEN],
                       const uint8_t captured_pmkid[static PMKID_LEN]);

/* ── Dictionary-attack helper ──────────────────────────────────────── */

/* air_pmkid_from_passphrase - Full pipeline: passphrase → PMK → PMKID.
 *
 * Derives PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32) then
 * calls air_pmkid_compute. Convenience for single-threaded dictionary
 * attacks; the Rust layer parallelises this via rayon.
 *
 * passphrase: null-terminated UTF-8 passphrase (8–63 printable ASCII bytes)
 * ssid      : raw SSID bytes (not null-terminated)
 * ssid_len  : 1–32 bytes
 *
 * Returns 0 on success, -1 on failure.
 */
[[nodiscard]] AIR_EXPORT
int air_pmkid_from_passphrase(const char    *passphrase,
                               const uint8_t *ssid, size_t ssid_len,
                               const uint8_t  ap_mac[static PMKID_MAC_LEN],
                               const uint8_t  sta_mac[static PMKID_MAC_LEN],
                               uint8_t        out[static PMKID_LEN]);
