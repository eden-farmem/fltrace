/*
 * stats.c - remote memory stat counters
 */

#include "base/stddef.h"
#include "rmem/stats.h"

/* stat counter names */
const char *rstat_names[] = {
	/* fault stats */
    "faults",
    "faults_r",
    "faults_w",
    "faults_wp",
    "faults_zp",
	"faults_p0",
    "faults_done",
    "wp_upgrades",
    "uffd_notif",
    "uffd_retries",
    "rdahead_ops",
    "rdahead_pages",

    /* eviction stats */
    "evict_ops",
    "evict_pages_popped",
	"evict_no_candidates",
	"evict_incomplete_batch",
    "evict_writes",
    "evict_wp_retries",
    "evict_madv",
    "evict_ops_done",
    "evict_pages_done",

    /* network read/writes */
    "net_reads",
    "net_writes",

    /* work stealing */
    "steals_ready",
    "steals_wait",
    "wait_retries",

    /* memory accounting */
    "rmalloc_size",
    "rmunmap_size",
    "rmadv_size",

    /* time accounting */
    "total_cycles",		/* only valid for handler cores */
    "work_cycles",		/* only valid for handler cores */
	"backend_wait_cycles",

	/* rmem hints */
	"annot_hits",
};
BUILD_ASSERT(ARRAY_SIZE(rstat_names) == RSTAT_NR);
