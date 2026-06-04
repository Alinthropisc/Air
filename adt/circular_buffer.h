#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "../defs.h"

#ifdef __cplusplus
extern "C" {
#endif


/// The internal structure is hidden from the consumer API.
typedef struct air_cbuf_s air_cbuf_t;

/// Ring buffer handle
typedef air_cbuf_t *air_cbuf_handle_t;

typedef enum AirCbufStatus : int32_t {
    AIR_CBUF_OK = 0,
    AIR_CBUF_FULL = -1,
    AIR_CBUF_EMPTY = -2,
    AIR_CBUF_NULL_ARG = -3,
    AIR_CBUF_BAD_SIZE = -4,
} AirCbufStatus;


/**
 * air_cbuf_init - Create a circular buffer
 *
 * @param storage External storage for elements
 * @param storage_size Size of storage in bytes
 * @param elem_size Size of one element in bytes
 *
 * @return Buffer handle or nullptr on error
 *
 * IMPORTANT: storage must outlive the buffer!
 * The consumer frees storage itself.
 */
[[nodiscard]]
AIR_EXPORT air_cbuf_handle_t air_cbuf_init(uint8_t *storage,size_t storage_size,size_t elem_size);

/**
 * air_cbuf_free - Free the buffer
 *
 * @param cbuf Buffer handle
 *
 * IMPORTANT: storage is NOT freed!
 */
AIR_EXPORT void air_cbuf_free(air_cbuf_handle_t cbuf);

/**
 * air_cbuf_reset - Reset the buffer to its initial state
 *
 * @param cbuf Buffer handle
 */
AIR_EXPORT void air_cbuf_reset(air_cbuf_handle_t cbuf);

/**
 * air_cbuf_put - Write an element to the buffer
 *
 * @param cbuf Buffer handle
 * @param data Data to copy
 * @param size Data size (≤ elem_size)
 * If less than elem_size → the remainder is set to zero
 *
 * @return AIR_CBUF_OK - success
 * @return AIR_CBUF_FULL - the buffer is full (the old element is overwritten!)
 *
 * IMPORTANT: data and storage must NOT overlap in memory!
 */
[[nodiscard]]
AIR_EXPORT AirCbufStatus air_cbuf_put(air_cbuf_handle_t cbuf,const void *data,size_t size);

/**
 * air_cbuf_get - Read an element from the buffer
 *
 * @param cbuf Buffer handle
 * @param data Where to copy the data
 * @param size Size of the data buffer (≤ elem_size)
 *
 * @return AIR_CBUF_OK - success
 * @return AIR_CBUF_EMPTY - the buffer is empty
 *
 * IMPORTANT: data and storage must NOT overlap in memory!
 */
[[nodiscard]]
AIR_EXPORT AirCbufStatus air_cbuf_get(air_cbuf_handle_t cbuf,void *data,size_t size);


/**
 * air_cbuf_is_empty - Is the buffer empty?
 */
[[nodiscard]]
AIR_EXPORT bool air_cbuf_is_empty(air_cbuf_handle_t cbuf);

/**
 * air_cbuf_is_full - Is the buffer full?
 */
[[nodiscard]]
AIR_EXPORT bool air_cbuf_is_full(air_cbuf_handle_t cbuf);

/**
 * air_cbuf_capacity - Maximum number of elements
 */
[[nodiscard]]
AIR_EXPORT size_t air_cbuf_capacity(air_cbuf_handle_t cbuf);

/**
 * air_cbuf_size - Current number of elements
 */
[[nodiscard]]
AIR_EXPORT size_t air_cbuf_size(air_cbuf_handle_t cbuf);

/**
 * air_cbuf_free_space - Free slots
 */
[[nodiscard]]
static inline size_t air_cbuf_free_space(air_cbuf_handle_t cbuf)
{
    return air_cbuf_capacity(cbuf) - air_cbuf_size(cbuf);
}

#ifdef __cplusplus
}
#endif
































































