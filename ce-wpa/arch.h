#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <limits.h>


#if __STDC_VERSION__ < 202311L
#error "Air requires C23"
#endif

#if defined(__LP64__) || defined(_LP64) || defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__)
#define AIR_ARCH_BITS 64u
#define AIR_ARCH_SIZE 8u
#define AIR_ARCH_64 1
#else
#define AIR_ARCH_BITS 32u
#define AIR_ARCH_SIZE 4u
#define AIR_ARCH_32 1
#endif

// C23 use intptr_t instead of custom types
typedef uintptr_t  air_arch_word_t;

// original ARCH_WORD_32 / ARCH_WORD_64
typedef uint32_t air_word32_t;

typedef uint64_t air_word64_t;


// Endianness
#if defined(__BYTE_ORDER__)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define AIR_LITTLE_ENDIAN 1
#define AIR_BIG_ENDIAN    0
#else
#define AIR_LITTLE_ENDIAN 0
#define AIR_BIG_ENDIAN    1
#endif
#elif defined(_WIN32)
#define AIR_LITTLE_ENDIAN 1
#define AIR_BIG_ENDIAN    0
#else
#error "Cannot determine byte order"
#endif


#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64)   || defined(_M_IX86)
#define AIR_ALLOWS_UNALIGNED 1
#else
#define AIR_ALLOWS_UNALIGNED 0
#endif


#if defined(__x86_64__) || defined(_M_X64)
#define AIR_ARCH_NAME "x86_64"
#elif defined(__i386__) || defined(_M_IX86)
#define AIR_ARCH_NAME "x86"
#elif defined(__aarch64__)
#define AIR_ARCH_NAME "aarch64"
#elif defined(__arm__)
#define AIR_ARCH_NAME "arm"
#elif defined(__powerpc64__)
#define AIR_ARCH_NAME "ppc64"
#else
#define AIR_ARCH_NAME "unknown"
#endif


static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");
static_assert(sizeof(uint64_t) == 8, "uint64_t must be 8 bytes");
static_assert(sizeof(uintptr_t) == AIR_ARCH_SIZE,"pointer size mismatch");





























