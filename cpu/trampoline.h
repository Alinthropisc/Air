#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "../defs.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef enum AirSimdFeature : uint32_t {
    AIR_SIMD_FEAT_NONE = 1u << 0u,
    AIR_SIMD_FEAT_MMX = 1u << 1u,
    AIR_SIMD_FEAT_SSE2 = 1u << 2u,
    AIR_SIMD_FEAT_AVX = 1u << 3u,
    AIR_SIMD_FEAT_AVX2 = 1u << 4u,
    AIR_SIMD_FEAT_NEON = 1u << 5u,
    AIR_SIMD_FEAT_ASIMD = 1u << 6u,
    AIR_SIMD_FEAT_ALTIVEC = 1u << 7u,
    AIR_SIMD_FEAT_POWER8 = 1u << 8u,
    AIR_SIMD_FEAT_AVX512F = 1u << 9u,
} AirSimdFeature;


AIR_EXPORT void air_simd_init(void);


AIR_EXPORT void air_simd_destroy(void);


[[nodiscard]]
AIR_EXPORT uint32_t air_simd_features(void);


[[nodiscard]]
static inline bool air_simd_has(AirSimdFeature feature)
{
    return (air_simd_features() & (uint32_t)feature) != 0u;
}


[[nodiscard]]
AIR_EXPORT const char *air_simd_name(void);


[[nodiscard]]
AIR_EXPORT AirSimdFeature air_simd_best_feature(void);

#ifdef __cplusplus
}
#endif
