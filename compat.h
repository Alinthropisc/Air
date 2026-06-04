#pragma once


#include <stddef.h>
#include <stdint.h>
#include <string.h>


#if __STDC_VERSION__ < 202311L
#error "Air requires C23 or later"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__MidnightBSD__)
#include <string.h>
#else


[[nodiscard]]
static inline size_t air_strlcpy(char *restrict dst,const char *restrict src,size_t dsize)
{
    if (dst == nullptr || dsize == 0) 
    {
        return (src != nullptr) ? strlen(src) : 0;
    }
    size_t src_len = strlen(src);
    size_t copy = (src_len < dsize - 1) ? src_len : dsize - 1;
    memcpy(dst, src, copy);
    dst[copy] = '\0';
    return src_len; /* Всегда strlen(src) */
}


[[nodiscard]]
static inline size_t air_strlcat(char *restrict dst,const char *restrict src,size_t dsize)
{
    if (dst == nullptr || dsize == 0)
    {
        return 0;
    }
    size_t dst_len = strnlen(dst, dsize);

    if (dst_len >= dsize)
    {
        return dst_len + strlen(src);
    }
    size_t remaining = dsize - dst_len - 1;
    size_t src_len = strlen(src);
    size_t copy = (src_len < remaining) ? src_len : remaining;
    memcpy(dst + dst_len, src, copy);
    dst[dst_len + copy] = '\0';
    return dst_len + src_len;
}


#define strlcpy air_strlcpy
#define strlcat air_strlcat

#endif 

#ifdef __cplusplus
}
#endif
















































































