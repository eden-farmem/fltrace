/*
 * page.h - remote memory page metadata and page nodes
 */

#ifndef __RMEM_PAGE_H__
#define __RMEM_PAGE_H__

#include <stdatomic.h>
#include "base/list.h"
#include "base/tcache.h"
#include "rmem/eviction.h"
#include "rmem/region.h"

/**
 * Page metadata
 * 64-bits for each page - saves the following in the order of least to 
 * most significant bits:
 * 1. Page flags
 * 2. Page thread id
 * 3. Page node index
 */

/* 1. Page flags (mask) */
enum {
    PSHIFT_REGISTERED = 0,      /* first fault (zero-page) was served */
    PSHIFT_PRESENT,             /* page currently mapped in local memory */
    PSHIFT_DIRTY,               /* page was mapped as writable */
    PSHIFT_WORK_ONGOING,        /* page is currently locked for work */
    PSHIFT_EVICT_ONGOING,       /* page is being evicted */
    PSHIFT_ACCESSED,            /* page was accessed again after the fault */
    PSHIFT_PRESENT_ZERO_PAGED,  /* page currently mapped due to first access */
    PAGE_FLAGS_NUM
};
BUILD_ASSERT(PAGE_FLAGS_NUM <= sizeof(pgflags_t) * 8);
#define PFLAG_REGISTERED            (1u << PSHIFT_REGISTERED)
#define PFLAG_PRESENT               (1u << PSHIFT_PRESENT)
#define PFLAG_DIRTY                 (1u << PSHIFT_DIRTY)
#define PFLAG_WORK_ONGOING          (1u << PSHIFT_WORK_ONGOING)
#define PFLAG_EVICT_ONGOING         (1u << PSHIFT_EVICT_ONGOING)
#define PFLAG_ACCESSED              (1u << PSHIFT_ACCESSED)
#define PFLAG_PRESENT_ZERO_PAGED    (1u << PSHIFT_PRESENT_ZERO_PAGED)
#define PAGE_FLAGS_MASK             ((1u << PAGE_FLAGS_NUM) - 1)

/* 2. Page thread id (offset and mask) */
#define PAGE_THREAD_SHIFT    (sizeof(pgflags_t) * 8)
#define PAGE_THREAD_LEN      (sizeof(pgthread_t) * 8)
#define PAGE_THREAD_MAX      ((1ULL << PAGE_THREAD_LEN) - 1)
#define PAGE_THREAD_MASK     (PAGE_THREAD_MAX << PAGE_THREAD_SHIFT)
BUILD_ASSERT(PAGE_THREAD_MASK > 0);

/* 3. Page node id (offset and mask) */
#define PAGE_INDEX_SHIFT    ((sizeof(pgflags_t) + (sizeof(pgthread_t))) * 8)
#define PAGE_INDEX_LEN      (sizeof(pgidx_t) * 8)
#define PAGE_INDEX_MAX      ((1ULL << PAGE_INDEX_LEN) - 1)
#define PAGE_INDEX_MASK     (PAGE_INDEX_MAX << PAGE_INDEX_SHIFT)
BUILD_ASSERT(PAGE_INDEX_MASK > 0);

/**
 * Gets page metadata pointer
 */
static inline atomic_pginfo_t *page_ptr(struct region_t *mr, unsigned long addr)
{
    int offset = ((addr - mr->addr) >> CHUNK_SHIFT);
    return &mr->page_info[offset];
}

/**
 * Gets page metadata
 */
static inline pginfo_t get_page_info(struct region_t *mr, unsigned long addr)
{
    atomic_pginfo_t *ptr = page_ptr(mr, addr);
    return *ptr;
}

/**
 * Sets page info (flags, thread id, node index) optionally in one 
 * atomic operation (only recommended for internal usage). This fn only supports 
 * updating thread/page id from zero to non-zero values, and fails if old 
 * values are non-zero.
 */
static inline pginfo_t __set_page_info(struct region_t *mr, unsigned long addr,
    pgflags_t flags_to_set, bool set_thread, pgthread_t thread_id, 
    bool set_pgidx, pgidx_t page_idx, pginfo_t* oldinfo_out)
{
    pginfo_t oldinfo, setbits, newinfo;
    atomic_pginfo_t *ptr;
    
    ptr = page_ptr(mr, addr);
    setbits = flags_to_set;
    if (set_thread) setbits |= (((pginfo_t) thread_id) << PAGE_THREAD_SHIFT);
    if (set_pgidx)  setbits |= (((pginfo_t) page_idx) << PAGE_INDEX_SHIFT);
    oldinfo = atomic_fetch_or(ptr, setbits);
    if (oldinfo_out)
        *oldinfo_out = oldinfo;
    assert(!set_thread || (oldinfo & PAGE_THREAD_MASK) == 0);
    assert(!set_pgidx || (oldinfo & PAGE_INDEX_MASK) == 0);
    newinfo = oldinfo | setbits;
    return newinfo;
}

/**
 * Clears page info (flags, thread id, node index) optionally in one 
 * atomic operation (only recommended for internal usage). Returns new page 
 * flags and old info in ptr
 */
static inline pgflags_t __clear_page_info(struct region_t *mr, 
    unsigned long addr, pgflags_t flags_to_clear, bool clear_thread, 
    bool clear_idx, pginfo_t* oldinfo_out)
{
    pginfo_t oldinfo, clrmask, newinfo;
    atomic_pginfo_t *ptr;
    
    ptr = page_ptr(mr, addr);
    clrmask = ~flags_to_clear;
    if (clear_thread)   clrmask &= (~PAGE_THREAD_MASK);
    if (clear_idx)      clrmask &= (~PAGE_INDEX_MASK);
    oldinfo = atomic_fetch_and(ptr, clrmask);
    if (oldinfo_out)
        *oldinfo_out = oldinfo;
    newinfo = oldinfo & clrmask;
    return newinfo;
}

/* ***********************************************************
 * Page flags - definition and helpers
 */

/**
 * Gets page flags from pginfo
 */
static inline pgflags_t get_flags_from_pginfo(pginfo_t pginfo)
{
    return (pgflags_t) (pginfo & PAGE_FLAGS_MASK);
}

/**
 * Gets page flags
 */
static inline pgflags_t get_page_flags(struct region_t *mr, unsigned long addr)
{
    return get_flags_from_pginfo(get_page_info(mr, addr));
}

/**
 * Sets flags on a page and returns new flags (and oldflags in ptr)
 */
static inline pgflags_t set_page_flags(struct region_t *mr, unsigned long addr, 
    pgflags_t flags, pgflags_t* oldflags_out)
{
    pginfo_t oldinfo;
    pgflags_t oldflags, newflags;
    atomic_pginfo_t *ptr;

    ptr = page_ptr(mr, addr);
    oldinfo = atomic_fetch_or(ptr, flags);
    oldflags = get_flags_from_pginfo(oldinfo);
    if (oldflags_out)
        *oldflags_out = oldflags;
    newflags = oldflags | flags;
    log_debug("set flags 0x%x on page 0x%lx; old: 0x%x, new: 0x%x", 
        flags, addr, oldflags, newflags);
    return newflags;
}

/**
 * Clears flags on a page and returns new flags (and oldflags in ptr)
 */
static inline pgflags_t clear_page_flags(struct region_t *mr, unsigned long addr, 
    pgflags_t flags, pgflags_t* oldflags_out)
{
    pginfo_t oldinfo;
    pgflags_t oldflags, new_flags;
    atomic_pginfo_t *ptr;
    
    ptr = page_ptr(mr, addr);
    oldinfo = atomic_fetch_and(ptr, ~flags);
    oldflags = get_flags_from_pginfo(oldinfo);
    if (oldflags_out)
        *oldflags_out = oldflags;
    new_flags = oldflags & (~flags);
    log_debug("cleared flags 0x%x on page 0x%lx; old: 0x%x, new: 0x%x", 
        flags, addr, oldflags, new_flags);
    return new_flags;
}

/**
 * Sets page flags on each page in the range
 */
static inline int set_page_flags_range(struct region_t *mr, unsigned long addr,
    size_t size, pgflags_t flags)
{
    unsigned long offset;
    pgflags_t oldflags;
    int nupdated = 0;

    for (offset = 0; offset < size; offset += CHUNK_SIZE) {
        set_page_flags(mr, addr + offset, flags, &oldflags);
        if (!(oldflags & flags))
            nupdated++;
    }
    /* return number of pages were actually set */
    return nupdated;
}

/**
 * Clears page flags on each page in the range
 */
static inline int clear_page_flags_range(struct region_t *mr, 
    unsigned long addr, size_t size, pgflags_t flags)
{
    unsigned long offset;
    int nupdated = 0;
    pgflags_t oldflags;

    for (offset = 0; offset < size; offset += CHUNK_SIZE) {
        clear_page_flags(mr, addr + offset, flags, &oldflags);
        if (!!(oldflags & flags))
            nupdated++;
    }
    /* return number of pages that were actually reset */
    return nupdated;
}

/* ***********************************************************
 * Page thread index in metadata - definition and helpers
 * This is used to store the current shenango thread that is currently working 
 * on the page (and as such is only valid when the page is locked).
 * 
 * We try and set or clear this field along with other page flags as much as 
 * possible to avoid a dedicated atomic operation.
 */

/**
 * Gets page thread index from pginfo
 */
static inline pgthread_t get_thread_from_pginfo(pginfo_t pginfo)
{
    return (pgthread_t) ((pginfo & PAGE_THREAD_MASK) >> PAGE_THREAD_SHIFT);
}

/**
 * Gets page thread index
 */
static inline pgthread_t get_page_thread(struct region_t *mr,
    unsigned long addr)
{
    return get_thread_from_pginfo(get_page_info(mr, addr));
}

/**
 * Sets page thread index on a page and returns old thread index. Note that 
 * this requires that the old thread value to be 0 since we do the 
 * atomic_or, not atomic_cmpxcg - but that is good enough for now.
 */
static inline pgthread_t set_page_thread(struct region_t *mr,
    unsigned long addr, pgthread_t threadid)
{
    pginfo_t oldinfo, setbits;
    atomic_pginfo_t *ptr;

    ptr = page_ptr(mr, addr);
    setbits = ((pginfo_t) threadid) << PAGE_THREAD_SHIFT;
    oldinfo = atomic_fetch_or(ptr, setbits);
    assertz(get_thread_from_pginfo(oldinfo)); /*must be zero before*/
    log_debug("set thread 0x%x on page 0x%lx; old: 0x%x, new: 0x%x", 
        threadid, addr, get_thread_from_pginfo(oldinfo), threadid);
    return get_thread_from_pginfo(oldinfo);
}

/**
 * Sets page thread id on each page in the range
 */
static inline int set_page_thread_range(struct region_t *mr, unsigned long addr,
    size_t size, pgthread_t threadid)
{
    unsigned long offset;
    int nupdated = 0;

    for (offset = 0; offset < size; offset += CHUNK_SIZE) {
        set_page_thread(mr, addr + offset, threadid);
        nupdated++;
    }

    /* return number of pages were updated */
    return nupdated;
}

/**
 * Sets page flags along with thread index on a page and returns the new flags
 * and oldflags and old thread in ptr). This fn only works if the old thread 
 * index is 0 as it uses atomic_or, not atomic_cmpxcg.
 */
static inline pgflags_t set_page_flags_and_thread(struct region_t *mr,
    unsigned long addr, pgflags_t flags, pgthread_t threadid, 
    pgflags_t* oldflags_out, pgthread_t* oldthread_out)
{
    pginfo_t oldinfo;
    pgflags_t newflags;

    newflags = __set_page_info(mr, addr, flags, true, threadid,
        false, 0, &oldinfo);
    if (oldflags_out)   *oldflags_out = get_flags_from_pginfo(oldinfo);
    if (oldthread_out)  *oldthread_out = get_thread_from_pginfo(oldinfo);
    log_debug("set flags 0x%x and thread id %d on page 0x%lx; result: 0x%x, "
        "old flags: 0x%x, old thr: %d", flags, threadid, addr, newflags,
        get_flags_from_pginfo(oldinfo), get_thread_from_pginfo(oldinfo));
    return newflags;
}

/**
 * Clears given set of flags and the thread id on a page and returns 
 * new flags (also includes oldflags and old thread id in ptrs)
 */
static inline pgflags_t clear_page_flags_and_thread(struct region_t *mr, 
    unsigned long addr, pgflags_t flags, pgflags_t* oldflags_out, 
    pgflags_t* oldthread_out)
{
    pginfo_t oldinfo;
    pgflags_t newflags;

    newflags = __clear_page_info(mr, addr, flags, true, false, &oldinfo);
    if (oldflags_out)   *oldflags_out = get_flags_from_pginfo(oldinfo);
    if (oldthread_out)  *oldthread_out = get_thread_from_pginfo(oldinfo);
    log_debug("cleared flags 0x%x and thread id on page 0x%lx; result: 0x%x, "
        "old flags: 0x%x, old thr: %d", flags, addr, newflags,
        get_flags_from_pginfo(oldinfo), get_thread_from_pginfo(oldinfo));
    return newflags;
}

/**
 * Clears given set of flags and the thread id on each page in the range
 * Returns the number of pages for which (some or all of) the flags were 
 * actually cleared by us (does not care about the thread id updates).
 */
static inline pgflags_t clear_page_flags_and_thread_range(struct region_t *mr, 
    unsigned long addr, size_t size, pgflags_t flags)
{
    unsigned long offset;
    int nupdated = 0;
    pgflags_t oldflags;
    pgthread_t oldthread;

    for (offset = 0; offset < size; offset += CHUNK_SIZE) {
        clear_page_flags_and_thread(mr, addr + offset, 
            flags, &oldflags, &oldthread);
        if (!!(oldflags & flags))
            nupdated++;
    }
    /* return number of pages whose flags were actually reset */
    return nupdated;
}

/* ***********************************************************
 * Page node index in metadata - definition and helpers
 */

/**
 * Gets page node index from pginfo (doesn't check that page is locked, which 
 * means the page node pointed to by the index may not exist, so use it with 
 * extreme care)
 */
static inline pgidx_t get_index_from_pginfo_unsafe(pginfo_t pginfo)
{
    return (pgidx_t) ((pginfo & PAGE_INDEX_MASK) >> PAGE_INDEX_SHIFT);
}

/**
 * Gets page node index from pginfo (checks that page is locked)
 */
static inline pgidx_t get_index_from_pginfo(pginfo_t pginfo)
{
    /* requires that page be locked to read index */
    assert(!!(pginfo & PFLAG_WORK_ONGOING));
    return get_index_from_pginfo_unsafe(pginfo);
}

/**
 * Gets page node index
 */
static inline pgidx_t get_page_index(struct region_t *mr, unsigned long addr)
{
    return get_index_from_pginfo(get_page_info(mr, addr));
}

/**
 * Sets page node index on a page and returns the old index
 */
static inline pgidx_t set_page_index(struct region_t *mr,
    unsigned long addr, pgidx_t index)
{
    pginfo_t pginfo, newinfo;
    atomic_pginfo_t *ptr;
    bool swapped;

    /* compare-and-swap to not affect other flags */
    ptr = page_ptr(mr, addr);
    do {
        pginfo = atomic_load(ptr);
        assert(!!(pginfo & PFLAG_WORK_ONGOING)); /*require a page lock to set*/
        newinfo = (pginfo & ~PAGE_INDEX_MASK);   /*keep non-index bits*/
        newinfo |= (((pginfo_t) index) << PAGE_INDEX_SHIFT);
        swapped = atomic_compare_exchange_weak(ptr, &pginfo, newinfo);
    } while(!swapped);
    log_debug("set index %d on page 0x%lx; old index: %d", index, addr, 
        get_index_from_pginfo_unsafe(pginfo));

    /* old index */
    return get_index_from_pginfo_unsafe(pginfo);
}

/**
 * Clears page node index on a page and returns the old index
 */
static inline pgidx_t clear_page_index(struct region_t *mr, unsigned long addr)
{
    return set_page_index(mr, addr, 0);
}

#endif    // __RMEM_PAGE_H_