#pragma once


#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "../defs.h"
#include "../ce-wep/crypto_engine.h"



#ifdef __cplusplus
extern "C" {
#endif


/**
* air_init_atoi - Initialize conversion tables
* Call once before using the engine
*/
AIR_EXPORT void air_init_atoi(void);


/**
* air_init_wpapsk - Calculate batch PMK using SIMD
*
* @param engine Crypto engine
* ​​@param passwords Array of passwords for batch processing
* @param nparallel Number of parallel passwords
* (≤ MAX_KEYS_PER_CRYPT_SUPPORTED)
* @param thread_id Worker thread ID
*
* @return 0 on success, < 0 on error
*
* Internally uses SIMD (AVX2/AVX512/NEON)
* for parallel PBKDF2-SHA1.
*/
[[nodiscard]]
AIR_EXPORT int air_init_wpapsk(AirCryptoEngine *engine,const AirPassword passwords[AIR_MAX_KEYS_BATCH],uint32_t nparallel,uint32_t thread_id);

#ifdef __cplusplus
}
#endif



















































