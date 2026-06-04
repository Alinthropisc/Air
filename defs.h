#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <error.h>
#include <assert.h>


#if __STDC_VERSION__ < 202311L
#error "Air requires C23 or later"
#endif


#if defined(_MSC_VER)
#define AIR_EXPORT __declspec(dllexport)
#define AIR_IMPORT __declspec(dllimport)
#elif defined(__GNUC__) || defined(__clang__)
#define AIR_EXPORT __attribute__((visibility("default")))
#define AIR_IMPORT 
#else
#define AIR_EXPORT
#define AIR_IMPORT
#endif


[[noreturn]]
static inline void air_contract_fail(const char *restrict kind, const char *restrict expr,const char *restrict file, int line)
{
    fprintf(stderr, "[ ETA ]: Air %s failed at %s:%d -> %s\n", kind, file, line, expr);
    abort();
}



#define ALLEGE(cond)                                          \
    do {                                                      \
        if (!(cond)) {                                        \
            air_contract_fail("ALLEGE", #cond,                \
                              __FILE__, __LINE__);            \
        }                                                     \
    } while (0)

#define REQUIRE(cond)                                         \
    do {                                                      \
        if (!(cond)) {                                        \
            air_contract_fail("Pre-condition", #cond,         \
                              __FILE__, __LINE__);            \
        }                                                     \
    } while (0)

#define ENSURE(cond)                                          \
    do {                                                      \
        if (!(cond)) {                                        \
            air_contract_fail("Post-condition", #cond,        \
                              __FILE__, __LINE__);            \
        }                                                     \
    } while (0)

#define INVARIANT(cond)                                       \
    do {                                                      \
        if (!(cond)) {                                        \
            air_contract_fail("Invariant", #cond,             \
                              __FILE__, __LINE__);            \
        }                                                     \
    } while (0)


#ifdef NDEBUG
#undef REQUIRE
#define REQUIRE(c) ((void)0)
#undef ENSURE
#define ENSURE(c) ((void)0)
#undef INVARIANT
#define INVARIANT(c) ((void)0)
#endif


#define AIR_STATIC_ASSERT(cond, msg) static_assert((cond), msg)

#if defined(__GNUC__) || defined(__clang__)
#define air_likely(x) __builtin_expect(!!(x), 1)
#define air_unlikely(x) __builtin_expect(!!(x), 0)
#else
#define air_likely(x) (x)
#define air_unlikely(x) (x)
#endif

#define AIR_ARRAY_COUNT(arr) (sizeof(arr) / sizeof(typeof((arr)[0])))
#define AIR_UNUSED(x) ((void)(x))
#define AIR_THREAD_ENTRY(fn) void* __attribute__((noinline)) fn(void *arg)

#define AIR_WARN_LTZ(expr)                                    \
    do {                                                      \
        int _rc = (expr);                                     \
        if (air_unlikely(_rc < 0)) {                          \
            fprintf(stderr,                                   \
                "[Air] Warning %s:%d → %s failed"             \
                " (ret=%d, errno=%d)\n",                      \
                __FILE__, __LINE__, #expr, _rc, errno);       \
        }                                                     \
    } while (0)

#define AIR_WARN_NZ(expr)                                     \
    do {                                                      \
        int _rc = (expr);                                     \
        if (air_unlikely(_rc != 0)) {                         \
            fprintf(stderr,                                   \
                "[Air] Warning %s:%d → %s failed"             \
                " (ret=%d, errno=%d)\n",                      \
                __FILE__, __LINE__, #expr, _rc, errno);       \
        }                                                     \
    } while (0)

#define AIR_WARN_ZERO(expr)                                   \
    do {                                                      \
        if (air_unlikely((expr) == 0)) {                      \
            fprintf(stderr,                                   \
                "[Air] Warning %s:%d → %s returned zero"      \
                " (errno=%d)\n",                              \
                __FILE__, __LINE__, #expr, errno);            \
        }                                                     \
    } while (0)


#define AIR_DO_PRAGMA(x) _Pragma(#x)

#if defined(__clang__) && __clang_major__ >= 4
#  define AIR_UNROLL(n) AIR_DO_PRAGMA(clang loop unroll_count(n))
#elif defined(__GNUC__) && __GNUC__ >= 8
#  define AIR_UNROLL(n) AIR_DO_PRAGMA(GCC unroll n)
#else
#  define AIR_UNROLL(n)
#endif


#define air_destroy(ptr, free_fn)                             \
    do {                                                      \
        if ((ptr) != nullptr) {                               \
            free_fn((typeof(ptr))(ptr));                      \
            (ptr) = nullptr;                                  \
        }                                                     \
    } while (0)


#ifdef __cplusplus
extern "C" {
#endif

[[nodiscard]]
static inline size_t air_ustrlen(const uint8_t *s)
{
    REQUIRE(s != nullptr);
    return strlen((const char *)s);
}

#ifdef __cplusplus
}
#endif


AIR_STATIC_ASSERT(sizeof(uint8_t)  == 1, "uint8_t must be 1 byte");
AIR_STATIC_ASSERT(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");
AIR_STATIC_ASSERT(sizeof(uint64_t) == 8, "uint64_t must be 8 bytes");










