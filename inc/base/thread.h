/*
 * thread.h - perthread data and other utilities
 */

#pragma once

#include <sys/syscall.h>
#include <unistd.h>

#include <base/stddef.h>
#include <base/limits.h>
#include <base/cpu.h>

/* used to define perthread variables */
#ifndef KEEP_PERTHREAD_DATA
#define DEFINE_PERTHREAD(type, name) \
	__typeof__(type) __perthread_##name __perthread \
	__attribute__((section(".perthread,\"\",@nobits#")))
#else
#define DEFINE_PERTHREAD(type, name) \
	__thread __typeof__(type) __perthread_##name
#endif

/* used to make perthread variables externally available */
#define DECLARE_PERTHREAD(type, name) \
	extern DEFINE_PERTHREAD(type, name)

extern void *perthread_offsets[NTHREAD];
extern bool perthread_inited[NTHREAD];
extern __thread void *perthread_ptr;
extern unsigned int thread_count;
int thread_init_perthread(void);

/**
 * perthread_get_remote - get a perthread variable on a specific thread
 * @var: the perthread variable
 * @thread: the thread id
 *
 * Returns a perthread variable.
 */
#define perthread_get_remote(var, thread)			\
	(*((__force __typeof__(__perthread_##var) *)		\
	 ((uintptr_t)&__perthread_##var + (uintptr_t)perthread_offsets[thread])))

static inline void *__perthread_get(void __perthread *key)
{
	return (__force void *)((uintptr_t)key + (uintptr_t)perthread_ptr);
}

/**
 * perthread_get - get the local perthread variable
 * @var: the perthread variable
 *
 * Returns a perthread variable.
 */
#define perthread_get(var)					\
	(*((__typeof__(__perthread_##var) *)(__perthread_get(&__perthread_##var))))

/* returns the next initalized thread */
static inline int __thread_next_active(int thread)
{
	while (thread < thread_count) {
		if (perthread_inited[++thread])
			return thread;
	}

	return thread;
}

/**
 * for_each_thread - iterates over each thread
 * @thread: the thread id
 */
#define for_each_thread(thread)						\
	for ((thread) = -1; (thread) = __thread_next_active(thread),	\
			    (thread) < thread_count;)

extern __thread unsigned int thread_id;
extern __thread unsigned int thread_numa_node;

extern pid_t thread_gettid(void);
