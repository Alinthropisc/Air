#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "../defs.h"



#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

/* Original: LLu, LLd, Zu - platform-specific */
/* C23: standard macros from inttypes.h */
#define AIR_PRIu64 PRIu64   /* "%" PRIu64 */
#define AIR_PRId64 PRId64
#define AIR_PRIx64 PRIx64
#define AIR_PRIzu  "zu"     /* size_t     */
#define AIR_PRIzd  "zd"


/**
* air_fatal - Terminate with an error
*
* Original: real_error() + error() macro
*/
[[noreturn]]
AIR_EXPORT void air_fatal(const char *file,int line,const char *msg);

/**
* air_fatal_errno - Terminate with an errno message
*
* Original: real_pexit() + pexit() macro
*/
[[noreturn]]
AIR_EXPORT void air_fatal_errno(const char *file,int line,const char *fmt, ...);

/* Convenient macros */
#define AIR_FATAL(msg) air_fatal(__FILE__, __LINE__, (msg))

#define AIR_FATAL_ERRNO(fmt, ...) air_fatal_errno(__FILE__, __LINE__, (fmt), ##__VA_ARGS__)


/**
* air_strnzcpy - Copy a string with a guaranteed NUL
* Returns the length of the copied string
*/
[[nodiscard]]
static inline size_t air_strnzcpy(char *dst,const char *src,size_t size)
{
    if (size == 0)
    {
         return 0;
    }
    size_t len = strnlen(src, size - 1);
    memcpy(dst, src, len);
    dst[len] = '\0';
    return len;
}

/**
 * air_strnzcat -Concatenation with NUL guarantee
 */
static inline void air_strnzcat(char *dst,const char *src,size_t size)
{
    size_t dst_len = strnlen(dst, size);

    if (dst_len >= size - 1)
    {
         return;
    }
    air_strnzcpy(dst + dst_len, src, size - dst_len);
}

/**
* air_write_loop - Write to fd with repeat on EINTR
*
* Original: write_loop()
*/
[[nodiscard]]
AIR_EXPORT ssize_t air_write_loop(int fd,const void *buf,size_t count);

/**
* air_fgetl - fgets without the trailing '\n'
*
* Original: fgetl()
* Handles Unix and DOS (\r\n) line breaks
*/
[[nodiscard]]
AIR_EXPORT char *air_fgetl(char *buf,size_t size,FILE *stream);

/**
* air_atou - atoi for unsigned (safe)
*
* Original: atou()
*/
[[nodiscard]]
static inline uint32_t air_atou(const char *s)
{
    if (s == nullptr || *s == '\0')
    {
        return 0u;
    }
    return (uint32_t)strtoul(s, nullptr, 10);
}

/**
* air_strtokm - strtok with empty tokens
*
* Original: strtokm()
* Unlike strtok, it doesn't skip adjacent delimiters
*/
[[nodiscard]]
AIR_EXPORT char *air_strtokm(char *str,const char *delim);

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define AIR_WITH_ASAN 1
#endif
#endif

#if defined(__SANITIZE_ADDRESS__)
#define AIR_WITH_ASAN 1
#endif

#ifdef AIR_WITH_ASAN
#define AIR_NO_ASAN __attribute__((no_address_safety_analysis)) __attribute__((noinline))
#else
#define AIR_NO_ASAN
#endif

#ifdef __cplusplus
}
#endif



















































