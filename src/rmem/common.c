/*
 * init.c - remote memory init
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>

#include "rmem/backend.h"
#include "rmem/common.h"
#include "rmem/config.h"
#include "rmem/fault.h"
#include "rmem/fsampler.h"
#include "rmem/handler.h"
#include "rmem/pgnode.h"
#include "rmem/region.h"
#include "rmem/uffd.h"

/* externed global settings */
bool rmem_enabled = false;
bool rmem_hints_enabled = false;
rmem_backend_t rmbackend_type = RMEM_BACKEND_DEFAULT;
uint64_t local_memory = LOCAL_MEMORY_SIZE;
double eviction_threshold = EVICTION_THRESHOLD;
int evict_batch_size = 1;
int fsampler_samples_per_sec = -1;  /* dump every record by default */

/* common global state for remote memory */
struct rmem_backend_ops* rmbackend = NULL;
int userfault_fd = -1;
hthread_t** handlers = NULL;
int nhandlers = 1;
atomic64_t memory_used = ATOMIC_INIT(0);
atomic64_t max_memory_used = ATOMIC_INIT(0);
atomic64_t memory_allocd = ATOMIC_INIT(0);
atomic64_t memory_freed = ATOMIC_INIT(0);
bool rmem_inited = false;

/* variable to track whether we are in the runtime or application at 
 * any point in time; this is used to track internal vs external 
 * memory allocations when interposing on memory calls */
__thread bool __from_runtime = 
/* default when running without shenango = */ false;

/* common thread-local state for remote memory */
__thread uint64_t* rstats_ptr = NULL;
__thread pgthread_t current_kthread_id = 0;

/**
 * rmem_common_init - initializes remote memory
 */
int rmem_common_init(
    unsigned long nslabs,
    int pin_handlers_start_core,
    int pin_handlers_end_core,
    int fsampler_samples_per_sec)
{
    int i, ret, coreid;
    log_info("rmem_init with: ");
    log_info("local memory - %lu B", local_memory);
    log_info("(initial) backing memory - %lu B", nslabs * RMEM_SLAB_SIZE);
    log_info("evict thr %.2lf, batch %d", eviction_threshold, evict_batch_size);
    BUG_ON(!rmem_enabled);

    /* init global data structures */
    CIRCLEQ_INIT(&region_list);

    /* init userfaultfd */
    userfault_fd = uffd_init();
    BUG_ON(userfault_fd < 0);

    /* initialize backend buf pool (used by backend) */
    ret = bkend_buf_tcache_init();
    assertz(ret);

    /* initialize backend */
    switch(rmbackend_type) {
        case RMEM_BACKEND_LOCAL:
            rmbackend = &local_backend_ops;
            break;
        default:
            BUG();  /* unhandled backend */
    }
    ret = rmbackend->init();
    assertz(ret);

    /* add some memory to start with */
    ret = rmbackend->add_memory(NULL, nslabs);
    assert(ret > 0);

    /* assign tcaches for faults */
    ret = fault_tcache_init();
    assertz(ret);

    /* tcaches for pages */
    ret = rmpage_node_tcache_init();
    assertz(ret);

    /* init lru lists and other eviction state */
    eviction_init();

#ifdef FAULT_SAMPLER
    /* init fault samplers */
    fsampler_init(fsampler_samples_per_sec);
#endif

    /* kick off rmem handlers - need at least one for kernel faults */
    BUG_ON(nhandlers <= 0);
    BUG_ON(nhandlers > MAX_HANDLER_CORES);

    coreid = -1;
    if (pin_handlers_start_core >= 0) {
        BUG_ON(pin_handlers_start_core > pin_handlers_end_core);
        BUG_ON(nhandlers > (pin_handlers_end_core - pin_handlers_start_core + 1));
        coreid = pin_handlers_end_core;  /* start high */
    }
    handlers = malloc(nhandlers*sizeof(hthread_t*));
    for (i = 0; i < nhandlers; i++) {
        handlers[i] = new_rmem_handler_thread(coreid);
        if (coreid >= 0)
            coreid--;
    }

    return 0;
}

/**
 * rmem_common_init_thread - initializes per-thread remote memory support for
 * either shenango or handler threads. Also creates a new backend channel and 
 * passes it back to the caller if asked for.
 */
int rmem_common_init_thread(int* new_chan_id, uint64_t* stats_ptr, 
    pgthread_t kthr_id)
{
    /* save rstats ptr as a first thing */
    assert(stats_ptr);
    BUG_ON(rstats_ptr); /* can't set twice */
    rstats_ptr = stats_ptr;

    /* save kthread id. 0 means current thread is not a shenango kthread */
    current_kthread_id = kthr_id;

    /* init per-thread data */
    fault_tcache_init_thread();
    bkend_buf_tcache_init_thread();
    rmpage_node_tcache_init_thread();
    zero_page_init_thread();
    eviction_init_thread();

    /* get a dedicated backend channel */
    assert(new_chan_id);
    *new_chan_id = rmbackend->get_new_data_channel();
    assert(*new_chan_id >= 0);
    return 0;
}

/**
 * rmem_common_destroy_thread - destroy per-thread remote memory support
 */
int rmem_common_destroy_thread()
{
    zero_page_free_thread();
    return 0;
}

/**
 * rmem_common_destroy - remote memory clean-up
 * (in reverse order of rmem_common_init)
 */
int rmem_common_destroy()
{
    int i, ret;
    struct region_t *mr;

    /* stop and destroy handlers */
    for (i = 0; i < nhandlers; i++) {
        ret = stop_rmem_handler_thread(handlers[i]);
        assertz(ret);
    }
    free(handlers);

    /* eviction free */
    eviction_exit();

    /* free rmmem page node pool */
    rmpage_node_tcache_destroy();

    /* destroy fault tcache pool */
    fault_tcache_destroy();

#ifdef FAULT_SAMPLER
    /* free fault sampler resources */
    fsampler_destroy();
#endif

    /* ensure all regions freed and removed */
    while(!CIRCLEQ_EMPTY(&region_list)) {
        mr = CIRCLEQ_FIRST(&region_list);
        remove_memory_region(mr);
    }

    /* destroy backend */
    if (rmbackend != NULL) {
        rmbackend->destroy();
        rmbackend = NULL;
    }

    return 0;
}