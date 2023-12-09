/*
 * stats.h - remote memory stat counters
 */

#ifndef __RMEM_STATS_H__
#define __RMEM_STATS_H__

/*
 * Remote memory stat counters. 
 * Don't use these enums directly. Instead, use the RSTAT() macro in defs.h
 */
enum {
    /* fault stats */
    RSTAT_FAULTS = 0,
    RSTAT_FAULTS_R,
    RSTAT_FAULTS_W,
    RSTAT_FAULTS_WP,
    RSTAT_FAULTS_ZP,
    RSTAT_FAULTS_P0,
    RSTAT_FAULTS_DONE,
    RSTAT_WP_UPGRADES,
    RSTAT_UFFD_NOTIF,
    RSTAT_UFFD_RETRIES,
    RSTAT_RDAHEADS,
    RSTAT_RDAHEAD_PAGES,

    /* eviction stats */
    RSTAT_EVICTS,
    RSTAT_EVICT_POPPED,
    RSTAT_EVICT_NONE,           /* found no eviction candidates */
    RSTAT_EVICT_SUBOPTIMAL,     /* couldn't fill the entire batch size */
    RSTAT_EVICT_WBACK,
    RSTAT_EVICT_WP_RETRIES,
    RSTAT_EVICT_MADV,
    RSTAT_EVICT_DONE,
    RSTAT_EVICT_PAGES_DONE,

    /* network read/writes */
    RSTAT_NET_READ,
    RSTAT_NET_WRITE,

    /* work stealing */
    RSTAT_READY_STEALS,
    RSTAT_WAIT_STEALS,
    RSTAT_WAIT_RETRIES,         /* time wasted checking on concurrent faults */

    /* memory accounting */
    RSTAT_MALLOC_SIZE,
    RSTAT_MUNMAP_SIZE,
    RSTAT_MADV_SIZE,

    /* time accounting */
    RSTAT_TOTAL_CYCLES,
    RSTAT_WORK_CYCLES,
    RSTAT_BACKEND_WAIT_CYCLES,  /* time wasted because backend is busy  */

    /* rmem hints */
    RSTAT_ANNOT_HITS,

    RSTAT_NR,   /* total number of counters */
};

/**
 * RSTAT - gets an remote memory stat counter
 * (this can be used from both shenango & handler threads but make 
 * sure to initialize the ptr to the thread-local stats)
 */
extern __thread uint64_t* rstats_ptr;
static inline uint64_t* rstats_ptr_safe()
{
   	assert(rstats_ptr);
    return rstats_ptr;
}
#define RSTAT(counter) (rstats_ptr_safe()[RSTAT_ ## counter])

/* stat counter names */
extern const char *rstat_names[];

#endif  // __RMEM_STATS_H__