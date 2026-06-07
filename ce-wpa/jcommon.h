#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "arch.h"
#include "aligned.h"

#include "../defs.h"

typedef uint32_t air_u32_t;
typedef uint64_t air_u64_t;


#if defined(__GNUC__) || defined(__clang__)
#define AIR_FORCE_INLINE __attribute__((always_inline)) inline
#else
#define AIR_FORCE_INLINE inline
#endif

#define AIR_CACHE_ALIGN alignas(AIR_ALIGN_CACHE)


#ifdef __cplusplus
extern "C" {
#endif

extern const char air_itoa64[64];
extern       char air_atoi64[256];

extern const char air_itoa16[16];    /* lowercase: 0-9a-f */
extern const char air_itoa16u[16];   /* uppercase: 0-9A-F */
extern       char air_atoi16[256];

/**
* air_common_init - Initialize conversion tables
* Call once at startup
*/
AIR_EXPORT void air_common_init(void);

#ifdef __cplusplus
}
#endif









































