/*
 * rmem_api.c - externally-visible remote memory allocation functions
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>

#include "base/atomic.h"
#include "base/log.h"
#include "base/mem.h"
#include "base/realmem.h"
#include "rmem/api.h"
#include "rmem/common.h"
#include "rmem/eviction.h"
#include "rmem/page.h"
#include "rmem/pgnode.h"
#include "rmem/region.h"

/**
 * When using interposition, make sure the API calls in 
 * this file are only called from the runtime
 */
#define ASSERT_IN_RUNTIME() BUG_ON(!IN_RUNTIME())

/**
 * Internal methods
 */

static inline void* __alloc_new(struct region_t *mr, size_t size)
{
    bool booked = false;
    unsigned long long offset;
    void *retptr = NULL;

    do {
        offset = atomic_load(&mr->current_offset);
        BUG_ON(offset + size > mr->size);	/* out of memory */
        booked = atomic_compare_exchange_weak(&mr->current_offset, &offset, 
            offset + size);
    } while(!booked);

    /* found */
    log_debug("rmalloc allocation: addr: %llx, end=%llx, length=%ld",
        mr->addr + offset, mr->addr + offset + size, size);
    retptr = (void *)(mr->addr + offset);

    /* account memory added */
    atomic64_add_and_fetch(&memory_allocd, size);

    return retptr;
}

static inline void __lock_page_range(struct region_t *mr,
    void* start, size_t length)
{
    unsigned long offset, page;
    pgflags_t oldflags;
    bool locked;

    for (offset = 0; offset < length; offset += CHUNK_SIZE) {
        page = (unsigned long) start + offset;
        do {
            set_page_flags(mr, page, PFLAG_WORK_ONGOING, &oldflags);
            locked = !(oldflags & PFLAG_WORK_ONGOING);
            cpu_relax();
        } while(!locked);
    }
}

static inline void __unlock_page_range(struct region_t *mr,
    void* start, size_t length)
{
    unsigned long offset, page;
    pgflags_t oldflags;

    for (offset = 0; offset < length; offset += CHUNK_SIZE) {
        page = (unsigned long) start + offset;
        clear_page_flags(mr, page, PFLAG_WORK_ONGOING, &oldflags);
        assert(!!(oldflags & PFLAG_WORK_ONGOING));
    }
}

static inline void __remove_and_unlock_page_range(struct region_t *mr,
    void* start, size_t length, bool unregister)
{
    int evicted, i;
    unsigned long offset, page;
    pgflags_t clrflags, flags;
    pgidx_t pgidx;
    pginfo_t pginfo, oldinfo;
    struct rmpage_node *pgnode;
    unsigned long pressure;

    /* unlock all pages while also setting them unregistered and freeing the 
     * page nodes for pages that were locally present (if munmap worked) */
    evicted = 0;
    for (offset = 0; offset < length; offset += CHUNK_SIZE)
    {
        page = (unsigned long) start + offset;

        /* unlock the page */
        clrflags = PFLAG_WORK_ONGOING;

        /* unregister the page if needed */
        if (unregister)
            clrflags |= (PFLAG_REGISTERED | PFLAG_PRESENT_ZERO_PAGED);

        /* if the page was present, drop it and release the page node */
        pginfo = get_page_info(mr, page);
        flags = get_flags_from_pginfo(pginfo);
        assert(!!(flags & PFLAG_WORK_ONGOING));
        if (!!(flags & PFLAG_PRESENT)) {
            pgidx = get_index_from_pginfo(pginfo);
            pgnode = rmpage_get_node_by_id(pgidx);
            assert(pgnode->addr == page);

            /* remove the node from eviction lists. we need a lock on the 
             * list before removing but can't get the list information from
             * the node. So I lock all the gens and remove the node without 
             * using the list_head; this can be costly so just supporting 
             * for 2 gens that SC_EVICTION, our most common use-case, needs. */
            BUG_ON(evict_ngens > 2);
            for (i = 0; i < evict_ngens; i++) spin_lock(&evict_gens[i].lock);
            list_del(&pgnode->link);
            for (i = 0; i < evict_ngens; i++) spin_unlock(&evict_gens[i].lock);

            /* free the page node */
            /* if running without shenango, application threads
             * calling unmap(), etc. will not have the local tcache
             * initialized, so we can't free the page nodes directly.
             * Instead, we save them to the "to-be-freed" list from
             * where the nodes are released back into the pool by
             * the handler threads  */
            rmpage_node_tbf_add(pgnode);

            evicted++;
            clrflags |= (PFLAG_PRESENT | PFLAG_DIRTY);
        }

        /* unlock the page */
        __clear_page_info(mr, page, clrflags, true, true, &oldinfo);
        log_debug("unlocked page for unmap %lx", page);
    }

    /* update local memory usage */
    if (evicted) {
        pressure = atomic64_sub_and_fetch(&memory_used, evicted * CHUNK_SIZE);
        log_debug("freed %d page(s), memory used=%ld", evicted, pressure);
    }

    /* accounting */
    if (unregister)
        atomic64_add_and_fetch(&memory_freed, length);
}

/**
 * Support for malloc
 */
void *rmalloc(size_t size)
{
    struct region_t *mr;
    void* retptr = NULL;

    ASSERT_IN_RUNTIME();

    log_debug("rmalloc with size %ld", size);
    if (size <= 0)
        goto OUT;
    size = align_up(size, CHUNK_SIZE);

    /* find available region and atomically grab memory */
    mr = get_available_region(size);
    if (mr == NULL) {
        log_err("ERROR! out of remote memory for alloc; add more");
        BUG();
    }

    retptr = __alloc_new(mr, size);

    put_mr(mr);
OUT:
    log_debug("rmalloc done, ptr %p", retptr);
    return retptr;
}

/**
 * Support for realloc
 */
void *rmrealloc(void *ptr, size_t size, size_t oldsize)
{
    void *retptr;
    struct region_t *mr;
    unsigned long long ptr_offset, offset;
    bool resized;

    if (ptr == NULL || oldsize <= 0)
        return rmalloc(size);

    ASSERT_IN_RUNTIME();

    log_debug("rmrealloc at %p with size %ld", ptr, size);
    retptr = ptr;
    if (size <= 0)
        goto OUT;
    size = align_up(size, CHUNK_SIZE);

    /* find associated region and atomically grab memory */
    mr = get_region_by_addr_safe((unsigned long) ptr);
    if (mr == NULL) {
        log_err("realloc: cannot find the region with ptr");
        BUG();
    }

    /* not handling size decrements in the proper way for now - we just return 
     * the same region with a hole in it (doing it the proper way would also
     * make eviction more complicated as current_offset is not expected to go 
     * down) */
    if (size < oldsize) {
        retptr = ptr;
        goto OUT_MR;
    }

    /* try resizing in-place */
    offset = atomic_load_explicit(&mr->current_offset, memory_order_acquire);
    ptr_offset = (unsigned long)ptr - mr->addr;
    resized = false;
    if (offset == ptr_offset + oldsize) {
        /* can resize in place */
        BUG_ON(ptr_offset + size > mr->size);	/* out of memory */
        resized = atomic_compare_exchange_strong(&mr->current_offset,
            &offset, ptr_offset + size);
    }

    if (resized) {
        /* resized in place */
        retptr = ptr;
        atomic64_add_and_fetch(&memory_allocd, (size - oldsize));
        goto OUT_MR;
    }
    else {
        /* cannot resize in-place, alloc new space and move */
        retptr = __alloc_new(mr, size);
        assert(retptr);
        memmove(retptr, ptr, oldsize);

        /* let go of old space */
        assert(oldsize % CHUNK_SIZE == 0);
        __lock_page_range(mr, ptr, oldsize);
        __remove_and_unlock_page_range(mr, ptr, oldsize, true);

        goto OUT_MR;
    }

OUT_MR:
    put_mr(mr);
OUT:
    log_debug("rmrealloc done at %p, newptr %p", ptr, retptr);
    return retptr;
}

/**
 * Support for munmap
 */
int rmunmap(void *addr, size_t length)
{
    struct region_t *mr;
    unsigned long max_addr;
    int ret = 0;

    ASSERT_IN_RUNTIME();

    log_debug("rmunmap at %p", addr);
    if (!addr) 
        goto OUT;

    /* find associated region */
    mr = get_region_by_addr_safe((unsigned long) addr);
    if (mr == NULL) {
        log_warn("rmunmap: cannot find the region with ptr");
        ret = -1;
        goto OUT;
    }

    max_addr = mr->addr + atomic_load(&mr->current_offset);
    BUG_ON((unsigned long) addr + length > max_addr);

    /* lock pages */
    __lock_page_range(mr, addr, length);

    /* Now we can do munmap (if UFFD_REGISTER_MUNMAP is defined, this will
     * result in a notif to the handler but I don't see why that would help 
     * except add perf overhead as we lock all the pages anyway */
    ret = real_munmap(addr, length);

    /* remove pages and unlock */
    if (ret == 0) __remove_and_unlock_page_range(mr, addr, length, true);
    else __unlock_page_range(mr, addr, length);

    put_mr(mr);
OUT:
    log_debug("rmunmap done at %p, retcode %d", addr, ret);
    return ret;
}

/**
 * Support for madvise
 */
int rmadvise(void *addr, size_t length, int advice)
{
    struct region_t *mr;
    unsigned long max_addr;
    int ret = 0;

    ASSERT_IN_RUNTIME();

    log_debug("rmadvise at %p size %ld advice %d", addr, length, advice);
    if (!addr) 
        goto OUT;

    /* we don't know how to deal with other advices yet */
    if (advice != MADV_FREE && advice != MADV_DONTNEED) {
        log_warn("rmadvise: advice %d not supported", advice);
        goto OUT;
    }

    /* find associated region */
    mr = get_region_by_addr_safe((unsigned long) addr);
    if (mr == NULL) {
        log_warn("rmadvise: cannot find the region with ptr");
        ret = -1;
        goto OUT;
    }

    max_addr = mr->addr + atomic_load(&mr->current_offset);
    BUG_ON((unsigned long) addr + length > max_addr);

    /* lock pages */
    __lock_page_range(mr, addr, length);

    /* Now we can do madvise (if UFFD_REGISTER_MADVISE is defined, this will
     * result in a notif to the handler but I don't see why that would help 
     * except add perf overhead as we lock all the pages anyway */
    ret = real_madvise((void *)addr, length, advice);

    /* remove pages and/or unlock */
    if (ret == 0) __remove_and_unlock_page_range(mr, addr, length, true);
    else __unlock_page_range(mr, addr, length);

    put_mr(mr);
OUT:
    log_debug("rmadvise done at %p, retcode %d", addr, ret);
    return ret;
}

/*** Unsupported (but potentially required or useful) functions ***/

/**
 * Free a region
 * (using jemalloc interpostion hopefully avoids this)
 */
int rmfree(void *ptr)
{
    ASSERT_IN_RUNTIME();
    log_debug("rfree");
    /* TODO */
    return 0;
}

/**
 * Pins pages for a while in local memory
 */
int rmpin(void *addr, size_t size)
{
    ASSERT_IN_RUNTIME();
    log_debug("rmpin for %p size %ld", addr, size);
    BUG();  /* not supported, should work with eviction */
    return 0;
}

/**
 * Flushes pages to remote memory
 */
int rmflush(void *addr, size_t size, bool evict)
{
    ASSERT_IN_RUNTIME();
    log_debug("rflush for %p size %ld", addr, size);
    BUG();  /* not supported, should work with eviction */
    return 0;
}