/*
 * cpu.h - detection for CPU topology
 */

#pragma once

#include <pthread.h>
#include <unistd.h>

#include <base/stddef.h>
#include <base/limits.h>
#include <base/bitmap.h>

/* Ideally should be runtime settings */
#ifndef NUMA_NODE
#define NUMA_NODE 0		
#endif
#ifndef EXCLUDE_CORES
#define EXCLUDE_CORES		// comma-separated list of numbers
#endif

extern int cpu_count; /* the number of available CPUs */
extern int numa_count; /* the number of NUMA nodes */

struct cpu_info {
	DEFINE_BITMAP(thread_siblings_mask, NCPU);
	DEFINE_BITMAP(core_siblings_mask, NCPU);
	int package;
};

extern struct cpu_info cpu_info_tbl[NCPU];
int cpu_pin_thread(pthread_t tid, int core);
