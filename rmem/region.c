/*
 * region.h - Remote memory region management helpers
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>

#include "base/stddef.h"
#include "rmem/backend.h"
#include "rmem/page.h"
#include "rmem/region.h"
#include "rmem/uffd.h"

/* region data */
struct region_listhead region_list;
struct region_t* last_evicted = NULL;
int nregions = 0;
DEFINE_SPINLOCK(regions_lock);

void deregister_memory_region(struct region_t *mr)
{
    int r;
    size_t pginfo_size, npages;

    log_debug("deregistering region %p", mr);
    if (mr->addr != 0) {
        uffd_unregister(userfault_fd, mr->addr, mr->size);
        r = munmap((void *)mr->addr, mr->size);
        if (r < 0) log_warn("munmap failed");

        npages = (mr->size >> CHUNK_SHIFT);
        pginfo_size = align_up(npages, 8) * sizeof(atomic_pginfo_t);
        r = munmap(mr->page_info, pginfo_size);
        if (r < 0) log_warn("munmap page_flags failed");
    }
    mr->addr = 0;
}

int register_memory_region(struct region_t *mr, int writeable)
{
    void *ptr = NULL;
    size_t pginfo_size, npages;
    int r;

    log_debug("registering region %p", mr);

    /* mmap virt addr space*/
    int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
    int prot = PROT_READ;
    if (writeable)  prot |= PROT_WRITE;
    ptr = mmap(NULL, mr->size, prot, mmap_flags, -1, 0);
    if (ptr == MAP_FAILED) {
        log_err("mmap failed");
        goto error;
    }
    mr->addr = (unsigned long)ptr;
    log_info("mmap ptr %p mr %p, size %ld", ptr, (void*)mr->addr, mr->size);

    /* register it with userfaultfd */
    assert(userfault_fd >= 0);
    r = uffd_register(userfault_fd, mr->addr, mr->size, writeable);
    if (r < 0) goto error;

    /* initalize metadata */
    npages = (mr->size >> CHUNK_SHIFT);
    pginfo_size = align_up(npages, 8) * sizeof(atomic_pginfo_t);
    mr->page_info = (atomic_pginfo_t*) mmap(NULL, pginfo_size, 
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mr->page_info == NULL) 
        goto error;
    mr->ref_cnt = ATOMIC_VAR_INIT(0);
    mr->current_offset = ATOMIC_VAR_INIT(0);

    /* add it to the list. TODO: this should be done in rmem.c after adding 
     * a region */
    acquire_region_lock();
    CIRCLEQ_INSERT_HEAD(&region_list, mr, link);
    nregions++;
    BUG_ON(nregions > RMEM_MAX_REGIONS);
    release_region_lock();
    return 0;
error:
    deregister_memory_region(mr);
    return 1;
}

void remove_memory_region(struct region_t *mr) {
    int ret;
    log_debug("deleting region %p", mr);
    BUG_ON(atomic_load(&mr->ref_cnt) > 0);
    
    acquire_region_lock();
    CIRCLEQ_REMOVE(&region_list, mr, link);
    nregions--;
    last_evicted = CIRCLEQ_FIRST(&region_list); /* reset */
    release_region_lock();

    /* deregister */
    deregister_memory_region(mr);

    /* notify backed memory */
    assert(rmbackend != NULL);
    ret = rmbackend->remove_region(mr);
    assertz(ret);
    
    munmap(mr, sizeof(struct region_t));
}
