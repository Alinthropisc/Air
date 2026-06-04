#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "../defs.h"

#ifdef __cplusplus
extern "C" {
#endif


/// The internal structure is hidden from consumers.
typedef struct air_cqueue_s air_cqueue_t;

/// Blocking queue handle
typedef air_cqueue_t *air_cqueue_handle_t;

typedef enum AirCqueueStatus : int32_t {
    AIR_CQUEUE_OK = 0,
    AIR_CQUEUE_FULL = -1,
    AIR_CQUEUE_EMPTY = -2,
    AIR_CQUEUE_NULL_ARG = -3,
    AIR_CQUEUE_SHUTDOWN = -4,
    AIR_CQUEUE_TIMEOUT = -5,
} AirCqueueStatus;


/**
 * air_cqueue_init - Create a blocking queue
 *
 * @param storage External storage for elements
 * @param storage_size Storage size in bytes
 * @param elem_size Size of one element in bytes
 *
 * @return Queue handle or nullptr on error
 */
[[nodiscard]]
AIR_EXPORT air_cqueue_handle_t air_cqueue_init(uint8_t *storage,size_t storage_size,size_t elem_size);

/**
 * air_cqueue_free - Free the queue
 *
 * @param cq Queue handle
 *
 * IMPORTANT: storage is NOT freed!
 */
AIR_EXPORT void air_cqueue_free(air_cqueue_handle_t cq);

/**
 * air_cqueue_reset - Reset the queue
 *
 * @param cq Queue handle
 */
AIR_EXPORT void air_cqueue_reset(air_cqueue_handle_t cq);

/**
 * air_cqueue_shutdown - Shutdown signal
 *
 * All blocked threads are unblocked.
 * Subsequent pushes/pops will return AIR_CQUEUE_SHUTDOWN.
 *
 * @param cq Queue handle
 */
AIR_EXPORT void air_cqueue_shutdown(air_cqueue_handle_t cq);

/**
 * air_cqueue_push - Blocking write of an element
 *
 * Blocks the thread until the queue is full.
 * Unblocks when there is room or shutdown occurs.
 *
 * @param cq Queue handle
 * @param data Data to write
 * @param size Data size (≤ elem_size)
 *
 * @return AIR_CQUEUE_OK - success
 * @return AIR_CQUEUE_SHUTDOWN - the queue is shutting down
 */
[[nodiscard]]
AIR_EXPORT AirCqueueStatus air_cqueue_push(air_cqueue_handle_t cq,const void *data,size_t size);

/**
 * air_cqueue_try_push - Non-blocking write
 *
 * Returns the result immediately.
 *
 * @return AIR_CQUEUE_OK - success
 * @return AIR_CQUEUE_FULL - the queue is full
 * @return AIR_CQUEUE_SHUTDOWN - the queue is shutting down
 */
[[nodiscard]]
AIR_EXPORT AirCqueueStatus air_cqueue_try_push(air_cqueue_handle_t cq,const void *data,size_t size);

/**
 * air_cqueue_pop - Blocking read of an element
 *
 * Blocks the thread until the queue is empty.
 *
 * @param cq Queue handle
 * @param data Where to copy the data
 * @param size Buffer size (≤ elem_size)
 *
 * @return AIR_CQUEUE_OK - success
 * @return AIR_CQUEUE_SHUTDOWN - the queue is shutting down
 */
[[nodiscard]]
AIR_EXPORT AirCqueueStatus air_cqueue_pop(air_cqueue_handle_t cq,void *data,size_t size);

/**
 * air_cqueue_try_pop - Non-blocking read
 *
 * @return AIR_CQUEUE_OK - success
 * @return AIR_CQUEUE_EMPTY - the queue is empty
 * @return AIR_CQUEUE_SHUTDOWN - the queue is shutting down
 */
[[nodiscard]]
AIR_EXPORT AirCqueueStatus air_cqueue_try_pop(air_cqueue_handle_t cq,void *data,size_t size);

/**
 * air_cqueue_is_empty - Is the queue empty?
 */
[[nodiscard]]
AIR_EXPORT bool air_cqueue_is_empty(air_cqueue_handle_t cq);

/**
 * air_cqueue_is_full - Is the queue full?
 */
[[nodiscard]]
AIR_EXPORT bool air_cqueue_is_full(air_cqueue_handle_t cq);

/* ─────────────────────────────────────────────
 * Usage pattern (Producer/Consumer)
 *
 * Producer flow:
 *   while (there are_passwords) {
 *       AirCqueueStatus s = air_cqueue_push(cq, pwd, len);
 *       if (s == AIR_CQUEUE_SHUTDOWN) break;
 *   }
 *   air_cqueue_shutdown(cq);
 *
 * Consumer flow:
 *   char buf[64];
 *   while (true) {
 *       AirCqueueStatus s = air_cqueue_pop(cq, buf, sizeof(buf));
 *       if (s == AIR_CQUEUE_SHUTDOWN) break;
 *       // checking the password...
 *   }
 * ───────────────────────────────────────────── */

#ifdef __cplusplus
}
#endif































































