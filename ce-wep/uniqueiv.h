#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "../defs.h"


#ifdef __cplusplus
extern "C" {
#endif


typedef enum AirIvStatus:int32_t {
    AIR_IV_NOT_SED = 0,
    AIR_IV_SEEN = 1,
    AIR_IV_ERR = -1,
} AirIvStatus;


typedef enum AirCloakStatus:int32_t {
    AIR_CLOAK_NONE = 0,
    AIR_CLOAK_PRESENT = 1,
} AirCloakStatus;


enum : uint32_t {
    AIR_IV_SIZE = 3u,
    AIR_IV_SPACE = 1u << 24u,
    AIR_IV_MAP_BYTES = AIR_IV_SPACE / 8u,
    AIR_IV_DATA_SIZE = AIR_IV_SPACE * 2u,
};


/**
* AirUniqueIv - two-level IV bitmap
*
* Level 1: 256 pointers (by the high-order byte of the IV)
* Level 2: 65536 bits per pointer
*
* Lazy memory allocation - level 2 only
* when really needed (saving RAM)
*/
typedef struct air_uiv_s air_uiv_t;

/**
* AirIvData - a map for cloaking detection
* Stores the last 2 bytes of data for each IV
*/
typedef struct air_iv_data_s air_iv_data_t;



/**
* air_iv_to_index - IV bytes → 24-bit index
*/
static inline uint32_t air_iv_to_index(const uint8_t iv[AIR_IV_SIZE])
{
    REQUIRE(iv != nullptr);
    return ((uint32_t)iv[0] << 16u) | ((uint32_t)iv[1] <<  8u) |  (uint32_t)iv[2];
}



/**
* The byte in which the bit for this IV lives
* Original: BITWISE_OFFT(x) = x >> 3
*/
static inline uint32_t air_iv_byte_offset(uint32_t iv_idx)
{
    return iv_idx >> 3u;
}


/**
* Bit extraction mask
* Original: BITWISE_MASK(x) = 1 << (x & 7)
*/
static inline uint8_t air_iv_bit_mask(uint32_t iv_idx)
{
    return (uint8_t)(1u << (iv_idx & 7u));
}



/**
* air_uiv_create - Create a map of unique IVs
*
* @return the map or nullptr on memory error
*
* Allocates only the top level (256 pointers).
* Lower levels are allocated lazily with the first IV.
*/
[[nodiscard]]
AIR_EXPORT air_uiv_t *air_uiv_create(void);



/**
* air_uiv_mark - Mark IV as seen
*
* @param uiv IV map
* @param iv 3-byte IV
*
* @return AIR_IV_NOT_SEEN - IV was new (marked for the first time)
* @return AIR_IV_SEEN - IV has been seen before
* @return AIR_IV_ERR - memory error
*/
[[nodiscard]]
AIR_EXPORT AirIvStatus air_uiv_mark(air_uiv_t *uiv, const uint8_t iv[AIR_IV_SIZE]);


/**
 * air_uiv_check - Check IV without marking
 *
 * @param uiv map IV
 * @param iv 3-byte IV
 *
 * @return AIR_IV_NOT_SEEN - IV new
 * @return AIR_IV_SEEN - IV already seen
 */
[[nodiscard]]
AIR_EXPORT AirIvStatus air_uiv_check(const air_uiv_t *uiv, const uint8_t iv[AIR_IV_SIZE]);


/**
 * air_uiv_count - Number of unique IVs
 */
[[nodiscard]]
AIR_EXPORT uint32_t air_uiv_count(const air_uiv_t *uiv);


/**
* air_uiv_destroy - Destroy the IV card
*
* @param uiv Card to destroy (may be nullptr)
*/
AIR_EXPORT void air_uiv_destroy(air_uiv_t *uiv);


/**
 * air_iv_data_create - Create Data Map IV
 */
[[nodiscard]]
AIR_EXPORT air_iv_data_t *air_iv_data_create(void);

/**
* air_iv_data_check - Check IV data (cloaking)
*
* @param data Data map
* @param iv 3-byte IV
* @param payload 2 bytes of packet data
*
* @return AIR_CLOAK_NONE - no cloaking
* @return AIR_CLOAK_PRESENT - cloaking detected
*/
[[nodiscard]]
AIR_EXPORT AirCloakStatus air_iv_data_check(air_iv_data_t *data,const uint8_t iv[AIR_IV_SIZE], const uint8_t payload[2]);

/**
 * air_iv_data_destroy - Free up data card
 */
AIR_EXPORT void air_iv_data_destroy(air_iv_data_t *data);



#ifdef __cplusplus
}


#endif




