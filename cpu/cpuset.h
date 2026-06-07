#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#include "../defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct air_cpuset_s air_cpuset_t;

typedef enum AirCpusetStatus : int32_t {
    AIR_CPUSET_OK =  0,
    AIR_CPUSET_ERR_ALLOC = -1, // No memory
    AIR_CPUSET_ERR_INIT = -2, // Initialization error
    AIR_CPUSET_ERR_BIND = -3, // Thread binding error
    AIR_CPUSET_ERR_ARG = -4, // Invalid argument
    AIR_CPUSET_NOT_SUPPORT = -5, // The platform does not support
} AirCpusetStatus;


typedef struct AirCpuTopology {
    uint32_t physical_cores;  // Physical cores
    uint32_t logical_cores; // Logical (with HT)
    uint32_t numa_nodes; // NUMA Nodes      
    bool     has_htt; // Hyper-Threading true
    char     _pad[3];
} AirCpuTopology;


/**
* air_cpuset_new - Create a new cpuset
*
* @return cpuset or nullptr on memory error
*/
[[nodiscard]]
AIR_EXPORT air_cpuset_t *air_cpuset_new(void);

/**
* air_cpuset_free - Free the cpuset
*
* @param cset cpuset (can be nullptr)
*/
AIR_EXPORT void air_cpuset_free(air_cpuset_t *cset);

/**
* air_cpuset_init - Initialize cpuset
*
* Determines the available CPUs on the current system.
*
* @param cset cpuset
* @return AIR_CPUSET_OK or an error code
*/
[[nodiscard]]
AIR_EXPORT AirCpusetStatus air_cpuset_init(air_cpuset_t *cset);

/**
* air_cpuset_destroy - Free cpuset resources
*
* @param cset cpuset
*/
AIR_EXPORT void air_cpuset_destroy(air_cpuset_t *cset);


/**
* air_cpuset_distribute - Distribute threads across CPUs
*
* Evenly distributes the thread count
* across available physical cores.
* With HT, only uses physical cores
* for crypto workloads (better performance).
*
* @param cset cpuset
* @param count Number of worker threads
*/
AIR_EXPORT void air_cpuset_distribute(air_cpuset_t *cset,size_t count);

/**
* air_cpuset_bind_thread - Bind a thread to a CPU
*
* @param cset cpuset
* @param tid POSIX thread ID
* @param idx Thread index (0..count-1)
*
* @return AIR_CPUSET_OK or an error code
*/
[[nodiscard]]
AIR_EXPORT AirCpusetStatus air_cpuset_bind_thread(air_cpuset_t *cset,pthread_t tid,size_t idx);


/**
* air_cpuset_topology - Get CPU topology
*
* @param cset Initialized CPU set
* @param topo Where to write the information
*/
AIR_EXPORT void air_cpuset_topology(const air_cpuset_t *cset,AirCpuTopology *topo);

/**
* air_cpuset_optimal_threads - Optimal number of threads
*
* For crypto workloads = physical cores.
* Does not use HT threads (they interfere with AES-NI).
*
* @param cset Initialized cpuset
* @return Recommended number of threads
*/
[[nodiscard]]
AIR_EXPORT uint32_t air_cpuset_optimal_threads(const air_cpuset_t *cset);

#ifdef __cplusplus
}
#endif
























































