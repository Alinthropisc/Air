#pragma once

#include <stdalign.h>
#include <stdint.h>
#include <cstddef>



#if __STDC_VERSION__ < 202311L
#error "Air requires C23"
#endif


// For backward compatibility within the project
#define AIR_ALIGN(n) alignas(n)


enum:uint32_t {
    AIR_ALIGN_NONE = 1u,
    AIR_ALIGN_WORD = alignof(void *),
    AIR_ALIGN_CACHE = 64u, /* L1 cache line          */
    AIR_ALIGN_PAGE = 4096u, /* Memory page       */
    /* SIMD leveling */
    AIR_ALIGN_SSE2 = 16u, /* 128-bit SSE2           */
    AIR_ALIGN_AVX = 32u, /* 256-bit AVX/AVX2       */
    AIR_ALIGN_AVX512 = 64u, /* 512-bit AVX-512        */
    AIR_ALIGN_NEON = 16u, /* ARM NEON               */
};



// Determining optimal SIMD alignment
// for the current platform
#if defined(__AVX512F__)
#define AIR_ALIGN_SIMD AIR_ALIGN_AVX512
#define AIR_SIMD_COEF32 16u
#define AIR_SIMD_COEF64  8u
#elif defined(__AVX2__) || defined(__AVX__)
#define AIR_ALIGN_SIMD AIR_ALIGN_AVX
#define AIR_SIMD_COEF32  8u
#define AIR_SIMD_COEF64  4u
#elif defined(__SSE2__)
#define AIR_ALIGN_SIMD AIR_ALIGN_SSE2
#define AIR_SIMD_COEF32  4u
#define AIR_SIMD_COEF64  2u
#elif defined(__ARM_NEON__) || defined(__aarch64__)
#define AIR_ALIGN_SIMD AIR_ALIGN_NEON
#define AIR_SIMD_COEF32  4u
#define AIR_SIMD_COEF64  2u
#else
#define AIR_ALIGN_SIMD AIR_ALIGN_SSE2  /* min 16 byte */
#define AIR_SIMD_COEF32  1u
#define AIR_SIMD_COEF64  1u
#endif


// air_is_aligned - Check pointer alignment
// align must be a power of two!
static inline bool air_is_aligned(const void *ptr, size_t align)
{
    return ((uintptr_t)ptr & (align - 1u)) == 0u;
}



#define AIR_STACK_ALIGN(n) alignas(n)


#define AIR_CACHELINE_PAD(name) alignas(AIR_ALIGN_CACHE) uint8_t name[AIR_ALIGN_CACHE]































