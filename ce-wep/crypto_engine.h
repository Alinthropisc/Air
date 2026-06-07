#pragma once


#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "../defs.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef enum AirSimdSupport : uint32_t {
    AIR_SIMD_NONE = 0u,
    AIR_SIMD_SSE2 = 1u << 0u,
    AIR_SIMD_AVX = 1u << 1u,
    AIR_SIMD_AVX2 = 1u << 2u,
    AIR_SIMD_AVX512F = 1u << 3u,
    AIR_SIMD_NEON = 1u << 4u,   /* ARM          */
    AIR_SIMD_ASIMD = 1u << 5u,   /* ARM64        */
    AIR_SIMD_POWER8 = 1u << 6u,   /* POWER8       */
    AIR_SIMD_ALTIVEC = 1u << 7u,   /* PowerPC      */
} AirSimdSupport;

enum : uint32_t {
    AIR_PMK_LEN = 32u,   /* WPA PMK length              */
    AIR_PTK_LEN = 64u,   /* WPA PTK length              */
    AIR_MIC_LEN = 16u,   /* MIC length                  */
    AIR_ESSID_MAX_LEN_CE = 32u,   /* ESSID max             */
    AIR_BSSID_LEN_CE = 6u,    /* BSSID length                */
    AIR_NONCE_LEN = 32u,   /* ANonce/SNonce length        */
    AIR_EAPOL_MAX = 256u,  /* EAPOL buffer max       */
    AIR_MAX_KEYS_BATCH = 8u, /* Keys in one batch       */
    AIR_PKE_LEN = 100u,  /* PKE Buffer                  */
};

typedef enum AirKeyVersion : uint8_t {
    AIR_KEYVER_WPA1_TKIP = 1u,   /* HMAC-MD5  MIC              */
    AIR_KEYVER_WPA2_CCMP = 2u,   /* HMAC-SHA1 MIC              */
    AIR_KEYVER_WPA2_AES = 3u,   /* AES-128-CMAC MIC           */
} AirKeyVersion;

typedef struct AirPassword {
    uint8_t data[64]; /* Password details              */
    uint32_t length; /* Password length                 */
} AirPassword;

static_assert(sizeof(AirPassword) == 68u, "AirPassword size mismatch");

typedef struct air_engine_thread_s air_engine_thread_t;

typedef struct AirCryptoEngine {
    uint8_t *essid; /* ESSID aligned buffer  */
    uint32_t essid_length; /* ESSID length             */
    uint32_t _pad;
    air_engine_thread_t *thread_data[256u]; /* Per-thread (MAX 256)  */
} AirCryptoEngine;

typedef struct AirCrackResult {
    bool found; /* Key found?               */
    char _pad[3];
    int32_t batch_index; /* Index in batch (-1 if none)*/
    char key[64]; /* The key found             */
    uint32_t key_length; /* Key length                */
} AirCrackResult;

typedef enum AirEngineStatus : int32_t {
    AIR_ENGINE_OK = 0,
    AIR_ENGINE_ERR = -1,
    AIR_ENGINE_NOT_FOUND = -2,
    AIR_ENGINE_BAD_KEYVER = -3,
    AIR_ENGINE_NULL_ARG = -4,
} AirEngineStatus;


/**
 * air_engine_simd_support - SIMD flags of the current CPU
 */
[[nodiscard]]
AIR_EXPORT AirSimdSupport air_engine_simd_support(void);

/**
 * air_engine_simd_width - SIMD width in uint32 words
 * SSE2=4, AVX=8, AVX2=8, AVX512=16
 */
[[nodiscard]]
AIR_EXPORT uint32_t air_engine_simd_width(void);


/**
* air_engine_init - Initialize the engine
*
* @param engine - Pointer to the engine (stack or heap)
* @return AIR_ENGINE_OK or an error code
*/
[[nodiscard]]
AIR_EXPORT AirEngineStatus air_engine_init(AirCryptoEngine *engine);

/**
 * air_engine_destroy - Free up engine resources
 */
AIR_EXPORT void air_engine_destroy(AirCryptoEngine *engine);

/**
* air_engine_set_essid - Set the target ESSID
*
* @param engine Engine
* ​​@param essid ESSID string (max 32 bytes)
*/
AIR_EXPORT void air_engine_set_essid(AirCryptoEngine *engine,const uint8_t *essid);


/**
* air_engine_thread_init - Thread data init
*
* Call from each worker thread before cracking.
*
* @param engine Engine
* ​​@param thread_id Thread ID [0, MAX_THREADS)
*/
[[nodiscard]]
AIR_EXPORT AirEngineStatus air_engine_thread_init(AirCryptoEngine *engine,uint32_t thread_id);

/**
 * air_engine_thread_destroy - Release stream data
 */
AIR_EXPORT void air_engine_thread_destroy(AirCryptoEngine *engine,uint32_t thread_id);


/**
* air_engine_calc_pke - Calculate PKE buffer
*
* Pre-calculates the key expansion buffer.
* Call once per target change.
*
* @param engine Engine
* ​​@param bssid Access point BSSID (6 bytes)
* @param stmac Station MAC (6 bytes)
* @param anonce EAPOL ANonce (32 bytes)
* @param snonce EAPOL SNonce (32 bytes)
* @param thread_id Thread ID
*/
AIR_EXPORT void air_engine_calc_pke(AirCryptoEngine *engine,const uint8_t bssid[AIR_BSSID_LEN_CE],const uint8_t stmac[AIR_BSSID_LEN_CE],const uint8_t anonce[AIR_NONCE_LEN],const uint8_t snonce[AIR_NONCE_LEN],uint32_t thread_id);

/**
* air_engine_calc_pmk_single - PMK for a single password
*
* PBKDF2-SHA1(password, essid, 4096, 32)
*
* @param password Password
* @param pass_len Password length
* @param essid ESSID
* @param essid_len ESSID length
* @param out_pmk Buffer for PMK (32 bytes)
*/
AIR_EXPORT void air_engine_calc_pmk_single(const uint8_t *password,uint32_t pass_len,const uint8_t *essid,uint32_t essid_len,uint8_t out_pmk[AIR_PMK_LEN]);

/**
* air_engine_calc_pmk_batch - PMK batch (SIMD acceleration)
*
* @param engine Engine
* ​​@param passwords Password array
* @param count Number of passwords in the batch
* @param thread_id Thread ID
*/
AIR_EXPORT void air_engine_calc_pmk_batch(AirCryptoEngine *engine,const AirPassword passwords[AIR_MAX_KEYS_BATCH],uint32_t count,uint32_t thread_id);

/**
* air_engine_calc_ptk - Calculate PTK from PMK
*
* @param engine Engine
* ​​@param keyver Key version (AirKeyVersion)
* @param vec_idx Batch index
* @param thread_id Thread ID
*/
AIR_EXPORT void air_engine_calc_ptk(AirCryptoEngine *engine,AirKeyVersion keyver,uint32_t vec_idx,uint32_t thread_id);

/**
* air_engine_calc_mic - Calculate MIC
*
* @param engine Engine
* ​​@param eapol EAPOL data
* @param eapol_size EAPOL size
* @param out_mic MIC buffer [batch][20]
* @param keyver Key version
* @param vec_idx Batch index
* @param thread_id Thread ID
*/
AIR_EXPORT void air_engine_calc_mic(AirCryptoEngine *engine,const uint8_t eapol[AIR_EAPOL_MAX],uint32_t eapol_size,uint8_t out_mic[AIR_MAX_KEYS_BATCH][20u],AirKeyVersion keyver,uint32_t vec_idx,uint32_t thread_id);


/**
* air_engine_crack_wpa - Attempt to crack a WPA handshake
*
* Performs a full cycle: PMK → PTK → MIC → compare
*
* @param engine Engine
* ​​@param passwords Batch of passwords
* @param count Number in batch
* @param eapol EAPOL packet
* @param eapol_size EAPOL size
* @param keyver Key version
* @param target_mic MIC from captured handshake
* @param thread_id Thread ID
*
* @return Index of found password in batch
* @return -1 if not found
*/
[[nodiscard]]
AIR_EXPORT int32_t air_engine_crack_wpa(AirCryptoEngine *engine,const AirPassword passwords[AIR_MAX_KEYS_BATCH],uint32_t count,const uint8_t eapol[AIR_EAPOL_MAX],uint32_t eapol_size,AirKeyVersion keyver,const uint8_t target_mic[AIR_MIC_LEN],uint32_t thread_id);

/**
* air_engine_crack_pmkid - PMKID cracking (PMKID attack)
*
* No handshake required! Only PMKID from Beacon/Probe.
* WPA3 attack - newer than the original aircrack.
*
* @param engine Engine
* ​​@param passwords Batch of passwords
* @param count Number in batch
* @param target_pmkid PMKID from captured packet (16 bytes)
* @param thread_id Thread ID
*
* @return Index of found or -1
*/
[[nodiscard]]
AIR_EXPORT int32_t air_engine_crack_pmkid(AirCryptoEngine *engine,const AirPassword passwords[AIR_MAX_KEYS_BATCH],uint32_t count,const uint8_t target_pmkid[AIR_MIC_LEN],uint32_t thread_id);

/**
* air_engine_set_pmkid_salt - Set salt for PMKID
*
* @param engine Engine
* ​​@param bssid BSSID (6 bytes)
* @param stmac Station MAC (6 bytes)
* @param thread_id Thread ID
*/
AIR_EXPORT void air_engine_set_pmkid_salt(AirCryptoEngine *engine,const uint8_t bssid[AIR_BSSID_LEN_CE],const uint8_t stmac[AIR_BSSID_LEN_CE],uint32_t thread_id);


/**
 * air_engine_get_pmk - Get PMK for batch index
 */
[[nodiscard]]
AIR_EXPORT const uint8_t *air_engine_get_pmk(const AirCryptoEngine *engine,uint32_t thread_id,uint32_t batch_idx);

/**
 * air_engine_get_ptk - Get PTK for the batch index
 */
[[nodiscard]]
AIR_EXPORT const uint8_t *air_engine_get_ptk(const AirCryptoEngine *engine,uint32_t thread_id,uint32_t batch_idx);



#ifdef __cplusplus
}
#endif









