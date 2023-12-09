/*
 * Default remote memory settings
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "asm/atomic.h"
#include "base/assert.h"
#include "base/log.h"
#include "base/mem.h"

/* Default configs */
#define TRACK_DIRTY             /* not available for kernels v < 5.7 */
#define NO_DYNAMIC_REGIONS      /* regions added/deleted only at startup/exit */

/* memory backend */
typedef enum {
    RMEM_BACKEND_LOCAL = 0,
} rmem_backend_t;
#define RMEM_BACKEND_DEFAULT    RMEM_BACKEND_LOCAL
#define RMEM_SLAB_SIZE          (128 * 1024L)
#define RMEM_MAX_CHANNELS       32
#define RMEM_MAX_CHUNKS_PER_OP  64
#define RMEM_MAX_COMP_PER_OP    16
#define RMEM_MAX_LOCAL_MEM      (64 * 1024L * 1024 * 1024)

/* Chunk size for remote memory handling (must be a power of 2 (KB)). */
#define PAGE_SIZE   PGSIZE_4KB
#define CHUNK_SHIFT PGSHIFT_4KB
#define CHUNK_SIZE  PGSIZE_4KB
#define CHUNK_MASK  PGMASK_4KB
BUILD_ASSERT(CHUNK_SIZE >= PGSIZE_4KB);

/* Eviction core settings */
#define LOCAL_MEMORY_SIZE           (4 * 1024 * 1024 * 1024L)
#define EVICTION_THRESHOLD          0.95
#define EVICTION_MAX_BATCH_SIZE     64
#define EVICTION_REGION_SWITCH_THR  1000
#define EVICTION_MAX_GENS           8
#define EVICTION_MAX_PRIO           2
#define EVICTION_EPOCH_LEN_MUS      100
#define EVICTION_TLB_FLUSH_MIN      2       /* TODO: must be 32 or something */
#define EVICTION_MAX_BUMPS_PER_OP   (5*EVICTION_MAX_BATCH_SIZE)
#define OS_MEM_PROBE_INTERVAL       1e6
BUILD_ASSERT(EVICTION_MAX_BATCH_SIZE <= RMEM_MAX_CHUNKS_PER_OP);

/* eviction policy (default is none) */
// #define SC_EVICTION     /* second-chance eviction */
// #define LRU_EVICTION    /* LRU eviction */
#if (defined(SC_EVICTION) && defined(LRU_EVICTION))
#pragma GCC error "Only one policy (SC_EVICTION/LRU_EVICTION) can be defined"
#endif

/* fault handling */
#define MAX_HANDLER_CORES               8
#define RUNTIME_MAX_FAULTS              2048
#define FAULT_TCACHE_MAG_SIZE           64
#define FAULT_MAX_RDAHEAD_SIZE          63
#define HANDLER_WAIT_BEFORE_STEAL_US    100
BUILD_ASSERT((1 + FAULT_MAX_RDAHEAD_SIZE) <= RMEM_MAX_CHUNKS_PER_OP);

/* fault sampling */
#define MAX_FAULT_SAMPLERS          (MAX_HANDLER_CORES)
#define FAULT_TRACE_STEPS           50

/* Region settings  */
#define RMEM_MAX_REGIONS            1

/* Do-not-evict region defaults (per priority level) */
#define RMEM_DNE_SIZE_MB            100
#define RMEM_DNE_MAX_PAGES          (RMEM_DNE_SIZE_MB * 1024 * 1024 / PAGE_SIZE)
BUILD_ASSERT(RMEM_DNE_MAX_PAGES >= RMEM_MAX_CHUNKS_PER_OP);

#endif  // __CONFIG_H__