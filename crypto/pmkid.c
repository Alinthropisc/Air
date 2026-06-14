/*
 * PMKID computation — WPA2 key recovery without a 4-way handshake.
 *
 * Jens Steube (@hashcat), August 2018.
 * Air Project 2026.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "../defs.h"
#include "pmkid.h"
#include "sha1.h"

/* "PMK Name" label — fixed string mandated by IEEE 802.11-2016 §12.7.1.3 */
static const uint8_t k_pmk_name_label[] = "PMK Name";
enum : size_t { PMK_NAME_LABEL_LEN = 8u };

AIR_EXPORT
int air_pmkid_compute(const uint8_t pmk[static PMKID_PMK_LEN],
                       const uint8_t ap_mac[static PMKID_MAC_LEN],
                       const uint8_t sta_mac[static PMKID_MAC_LEN],
                       uint8_t       out[static PMKID_LEN])
{
    REQUIRE(pmk     != nullptr);
    REQUIRE(ap_mac  != nullptr);
    REQUIRE(sta_mac != nullptr);
    REQUIRE(out     != nullptr);

    /* data = "PMK Name" || AP_MAC || STA_MAC  (20 bytes total) */
    uint8_t data[PMK_NAME_LABEL_LEN + PMKID_MAC_LEN + PMKID_MAC_LEN];
    memcpy(data,                                       k_pmk_name_label, PMK_NAME_LABEL_LEN);
    memcpy(data + PMK_NAME_LABEL_LEN,                  ap_mac,           PMKID_MAC_LEN);
    memcpy(data + PMK_NAME_LABEL_LEN + PMKID_MAC_LEN,  sta_mac,          PMKID_MAC_LEN);

    uint8_t hmac[DIGEST_SHA1_MAC_LEN]; /* 20 bytes; PMKID uses first 16 */
    if (MAC_HMAC_SHA1(PMKID_PMK_LEN, pmk, sizeof(data), data, hmac) != 0)
        return -1;

    memcpy(out, hmac, PMKID_LEN);
    return 0;
}

AIR_EXPORT
bool air_pmkid_verify(const uint8_t pmk[static PMKID_PMK_LEN],
                       const uint8_t ap_mac[static PMKID_MAC_LEN],
                       const uint8_t sta_mac[static PMKID_MAC_LEN],
                       const uint8_t captured[static PMKID_LEN])
{
    uint8_t computed[PMKID_LEN];
    if (air_pmkid_compute(pmk, ap_mac, sta_mac, computed) != 0)
        return false;

    /* Constant-time compare — no early exit to avoid timing oracles */
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < PMKID_LEN; ++i)
        diff |= computed[i] ^ captured[i];

    return diff == 0;
}

AIR_EXPORT
int air_pmkid_from_passphrase(const char    *passphrase,
                               const uint8_t *ssid, size_t ssid_len,
                               const uint8_t  ap_mac[static PMKID_MAC_LEN],
                               const uint8_t  sta_mac[static PMKID_MAC_LEN],
                               uint8_t        out[static PMKID_LEN])
{
    REQUIRE(passphrase != nullptr);
    REQUIRE(ssid       != nullptr);
    REQUIRE(ssid_len   >= 1u && ssid_len <= 32u);

    uint8_t pmk[PMKID_PMK_LEN];
    if (KDF_PBKDF2_SHA1((const uint8_t *) passphrase, ssid, ssid_len,
                         4096u, pmk, PMKID_PMK_LEN) != 0)
        return -1;

    return air_pmkid_compute(pmk, ap_mac, sta_mac, out);
}
