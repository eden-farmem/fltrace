/*
 * eviction.h - eviction helpers
 */

#ifndef __EVICTION_H__
#define __EVICTION_H__

#include "base/sampler.h"
#include "rmem/backend.h"
#include "rmem/region.h"

/**
 * Eviction main
 */
int do_eviction(int chan_id, struct bkend_completion_cbs* cbs, int max_batch_size);
int owner_write_back_completed(struct region_t* mr, unsigned long addr, size_t size);
int stealer_write_back_completed(struct region_t* mr, unsigned long addr, size_t size);

/**
 * Page LRU lists support
 */

struct page_list {
    struct list_head pages[EVICTION_MAX_PRIO];
    size_t npages;
    spinlock_t lock;
};
struct page_list_per_prio {
    struct list_head pages[EVICTION_MAX_PRIO];
    size_t npages[EVICTION_MAX_PRIO];
    spinlock_t locks[EVICTION_MAX_PRIO];
};
extern struct page_list evict_gens[EVICTION_MAX_GENS];
struct page_list_per_prio dne_pages;
extern int evict_gen_mask;
extern int evict_gen_now;
extern unsigned long evict_epoch_now;
extern struct sampler epoch_sampler;

int eviction_init(void);
int eviction_init_thread(void);
void eviction_exit(void);

#endif  // __EVICTION_H__