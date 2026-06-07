#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "air/defs.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct AirCpuSimdInfo {
    uint32_t  simd_width;     // SIMD register width in uint32 */
    uint32_t  simd_width64;   // SIMD register width in uint64 */
} AirCpuSimdInfo;

typedef struct AirCpuCoreInfo {
    uint32_t  physical_cores;
    uint32_t  logical_cores;
    uint32_t  cores_per_id; 
    bool      has_htt;      
    bool      has_hypervisor; 
    char      _pad[2];
} AirCpuCoreInfo;

typedef struct AirCpuFreqInfo {
    uint32_t  current_mhz;  
    uint32_t  max_mhz;      
    float     temperature;
    char      _pad[4];
} AirCpuFreqInfo;

typedef struct AirCpuInfo {
    char model[128];   // String model CPU
    char flags[512];   // str flags (like /proc/cpuinfo)
    AirCpuSimdInfo simd;
    AirCpuCoreInfo cores;
    AirCpuFreqInfo freq;
} AirCpuInfo;

extern AirCpuInfo air_cpuinfo;


/**
* air_cpuid_init - Determine CPU capabilities
*
* Populates air_cpuinfo.
* Call once at program startup.
*
* @return 0 on success, -1 on error
*/
[[nodiscard]]
AIR_EXPORT int air_cpuid_init(void);

/**
* air_cpuid_simd_width - SIMD width in uint32 words
*
* Original: cpuid_simdsize(int)
*
* @return 16 (AVX512) | 8 (AVX2) | 4 (SSE2) | 1 (scalar)
*/
[[nodiscard]]
AIR_EXPORT uint32_t air_cpuid_simd_width(void);

/**
 * air_cpuid_print - Display CPU information

 */
AIR_EXPORT void air_cpuid_print(void);

#ifdef __cplusplus
}
#endif

















































