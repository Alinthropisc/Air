#pragma once


#include <stdint.h>
#include <stdbit.h>

#include "arch.h"




[[nodiscard]]
static inline uint32_t air_bswap32(uint32_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(x);
#elif defined(_MSC_VER)
    return _byteswap_ulong(x);
#else
    /* C23 portable fallback */
    return ((x & 0xFF000000u) >> 24u) | ((x & 0x00FF0000u) >>  8u) | ((x & 0x0000FF00u) <<  8u) | ((x & 0x000000FFu) << 24u);
#endif
}




[[nodiscard]]
static inline uint64_t air_bswap64(uint64_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap64(x);
#elif defined(_MSC_VER)
    return _byteswap_uint64(x);
#else
    return ((uint64_t)air_bswap32((uint32_t)(x & 0xFFFFFFFFu)) << 32u) | ((uint64_t)air_bswap32((uint32_t)(x >> 32u)));
#endif
}


[[nodiscard]]
static inline uint32_t air_rotl32(uint32_t x, uint32_t n)
{
    /* C23: stdbit.h имеет stdc_rotate_left */
    return (x << n) | (x >> (32u - n));
}

[[nodiscard]]
static inline uint32_t air_rotr32(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32u - n));
}

[[nodiscard]]
static inline uint64_t air_rotl64(uint64_t x, uint32_t n)
{
    return (x << n) | (x >> (64u - n));
}

[[nodiscard]]
static inline uint64_t air_rotr64(uint64_t x, uint32_t n)
{
    return (x >> n) | (x << (64u - n));
}


static inline void air_bswap32_buf(uint32_t *buf, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        buf[i] = air_bswap32(buf[i]);
    }
}

/**
 * air_bswap64_buf - Поменять endian в массиве uint64
 */
static inline void air_bswap64_buf(uint64_t *buf, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        buf[i] = air_bswap64(buf[i]);
    }
}


static inline void air_to_big_endian32(uint32_t *buf, size_t count)
{
#if AIR_LITTLE_ENDIAN
    air_bswap32_buf(buf, count);
#else
    (void)buf; (void)count;
#endif
}

static inline void air_to_little_endian32(uint32_t *buf, size_t count)
{
#if AIR_BIG_ENDIAN
    air_bswap32_buf(buf, count);
#else
    (void)buf; (void)count; /* уже LE */
#endif
}

static inline void air_to_big_endian64(uint64_t *buf, size_t count)
{
#if AIR_LITTLE_ENDIAN
    air_bswap64_buf(buf, count);
#else
    (void)buf; (void)count;
#endif
}

static inline void air_to_little_endian64(uint64_t *buf, size_t count)
{
#if AIR_BIG_ENDIAN
    air_bswap64_buf(buf, count);
#else
    (void)buf; (void)count;
#endif
}





































