
/*
 * backend.c - common remote memory backend functions
 */

#include <stdatomic.h>
#include "rmem/backend.h"

#define BACKEND_BUF_PTR_SIZE    (BACKEND_BUF_SIZE / sizeof(uintptr_t))
BUILD_ASSERT(BACKEND_BUF_SIZE % sizeof(uintptr_t) == 0);

/* common state */
atomic_int nchans_bkend = ATOMIC_VAR_INIT(0);
static struct tcache *bkend_buf_tcache;
DEFINE_PERTHREAD(struct tcache_perthread, bkend_buf_pt);
static DEFINE_SPINLOCK(bkend_buf_lock);
static int bkend_buf_count = 0, free_bkend_buf_count = 0;
static void* free_bkend_bufs[MAX_BACKEND_BUFS];
static void* backend_buf_region = NULL;
static size_t backend_region_size = 0;

/**
 * Returns the next available channel (id) for datapath communication
 **/
int backend_get_data_channel()
{
    int chan_id;
    do {
        chan_id = atomic_load(&nchans_bkend);
        BUG_ON(chan_id > RMEM_MAX_CHANNELS);
        if (chan_id == RMEM_MAX_CHANNELS) {
            log_warn("out of backend channels!");
            return -1;
        }
    } while(!atomic_compare_exchange_weak(&nchans_bkend, &chan_id, chan_id+1));
    log_debug("channel %d taken, num channels: %d", chan_id, nchans_bkend);
    return chan_id;
}

/**
 * Tcache for allocating backend data bufs (exchanged with backend and between
 * threads)
 */
static void bkend_buf_tcache_free(struct tcache *tc, int nr, void **items)
{
	/* save for reallocation */
	int i;
	spin_lock(&bkend_buf_lock);
	for (i = 0; i < nr; i++) {
		/* make sure the items returned are proper */
		BUG_ON(free_bkend_buf_count >= MAX_BACKEND_BUFS);
		assert(bkend_is_buf_valid(items[i]));
		free_bkend_bufs[free_bkend_buf_count++] = items[i];
	}
	spin_unlock(&bkend_buf_lock);
}

static int bkend_buf_tcache_alloc(struct tcache *tc, int nr, void **items)
{
	int i = 0;

	spin_lock(&bkend_buf_lock);
	while (free_bkend_buf_count && i < nr) {
		items[i++] = free_bkend_bufs[--free_bkend_buf_count];
	}

	for (; i < nr; i++) {
        /* allocate new */
		log_debug("allocing new bkend buf: %d", bkend_buf_count);
        if(bkend_buf_count >= MAX_BACKEND_BUFS){
    		log_err_ratelimited("too many bkend_bufs, cannot allocate more");
			goto fail;
		}
		items[i] = (void*)((unsigned long) backend_buf_region + 
            bkend_buf_count * BACKEND_BUF_SIZE);
		bkend_buf_count++;
	}
	spin_unlock(&bkend_buf_lock);
	return 0;
fail:
	spin_unlock(&bkend_buf_lock);
	bkend_buf_tcache_free(tc, i, items);
	return -ENOMEM;
}

static const struct tcache_ops bkend_buf_tcache_ops = {
	.alloc	= bkend_buf_tcache_alloc,
	.free	= bkend_buf_tcache_free,
};

/**
 * bkend_buf_get_backing_region - gets the backing region for the pool
 */
void bkend_buf_get_backing_region(void** start, size_t* len)
{
    assert(backend_buf_region && backend_region_size);  /* check inited */
	*start = backend_buf_region;
    *len = backend_region_size;
}

/**
 * bkend_is_buf_valid - checks if a given address points to a valid buffer
 */
bool bkend_is_buf_valid(void* buf)
{
	unsigned long region_end;
    assert(backend_buf_region && backend_region_size);  /* check inited */
	region_end = (unsigned long) backend_buf_region + backend_region_size;
	return buf >= backend_buf_region 
		&& buf < (void*) region_end 
		&& (unsigned long) (buf - backend_buf_region) % BACKEND_BUF_SIZE == 0;
}

/**
 * bkend_buf_init_thread - inits per-thread tcache for fault objects
 * Returns 0 (always successful).
 */
void bkend_buf_tcache_init_thread(void)
{
	tcache_init_perthread(bkend_buf_tcache, &perthread_get(bkend_buf_pt));
}

/**
 * bkend_buf_tcache_init - initializes the global backend buf pool
 * Returns 0 if successful, or -ENOMEM if out of memory.
 */
int bkend_buf_tcache_init(void)
{
	int pgsize;

    /* create backing region */
    backend_region_size = MAX_BACKEND_BUFS * BACKEND_BUF_SIZE;
	BUILD_ASSERT(is_power_of_two(BACKEND_BUF_SIZE));

	/* determine page size */
    pgsize = PGSIZE_4KB;

	backend_buf_region = 
		mem_map_anom(NULL, backend_region_size, pgsize, NUMA_NODE);
	if (backend_buf_region == MAP_FAILED) {
        log_err("out of huge pages for backend_buf_region");
        return -ENOMEM;
	}
	BUG_ON((unsigned long) backend_buf_region % pgsize != 0);

    /* create pool */
	bkend_buf_tcache = tcache_create("bkend_bufs_tcache", &bkend_buf_tcache_ops, 
		BACKEND_BUF_MAG_SIZE, BACKEND_BUF_SIZE);
	if (!bkend_buf_tcache)
		return -ENOMEM;

	log_info("inited backend buffer pool - start %p, size %lu",
		backend_buf_region, backend_region_size);
	return 0;
}
