#pragma once

#include <stdint.h>




typedef enum AirSimdFlags : uint32_t {
    // Input data format
    AIR_SIMD_MIXED_IN = 0x0000u, // Ready interleaved array
    AIR_SIMD_FLAT_IN = 0x0001u, // Flat byte array
    AIR_SIMD_FLAT_OUT = 0x0004u, // Flat outlet (not interleaved)
    // State Reboot Mode 
    AIR_SIMD_RELOAD = 0x0008u, // Continue from previous state
    AIR_SIMD_RELOAD_INP_FMT = 0x0018u, // Reload в INPUT format
    AIR_SIMD_OUTPUT_AS_INP = 0x0020u, // Output in INPUT format
    // optimize 
    AIR_SIMD_REVERSE_STEPS = 0x0040u, // Reverse the steps
    // Input buffer size
    AIR_SIMD_2BUF_INPUT = 0x0080u, // 2x buffer (up to 119 bytes)
    AIR_SIMD_2BUF_FIRST = 0x0180u, // 2x buffer, first block
    AIR_SIMD_4BUF_INPUT = 0x0200u, // Buffer 4x (up to 256 bytes)
    AIR_SIMD_4BUF_FIRST = 0x0600u, // 4x buffer, first block
    // Other 
    AIR_SIMD_FLAT_RELOAD_SWAP = 0x0800u, // Swap при flat reload
    // SHA options
    AIR_SIMD_SHA224 = 0x1000u, // SHA-224 IV
    AIR_SIMD_SHA384 = 0x1000u, // SHA-384 IV
    AIR_SIMD_OUTPUT_AS_2BUF = 0x2020u, // 2buf OUTPUT format
} AirSimdFlags;

/* ─────────────────────────────────────────────
 * SIMD ширина в битах (для логирования)
 * ───────────────────────────────────────────── */
#if AIR_SIMD_COEF32 == 16
#  define AIR_SIMD_BITS_STR "512"
#elif AIR_SIMD_COEF32 == 8
#  define AIR_SIMD_BITS_STR "256"
#elif AIR_SIMD_COEF32 == 4
#  define AIR_SIMD_BITS_STR "128"
#else
#  define AIR_SIMD_BITS_STR "scalar"
#endif














































