/*
 * rmem_local.c - Local memory-based remote memory backend
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <sys/mman.h>

#include "base/time.h"
#include "rmem/backend.h"
#include "rmem/fault.h"
#include "rmem/stats.h"

#define LOCAL_BACKEND_DELAY_MUS 0
#define PAGE_LOCKS_SHIFT    16
#define PAGE_LOCKS_SIZE     (1 << PAGE_LOCKS_SHIFT)
#define PAGE_LOCKS_MASK     (PAGE_LOCKS_SIZE-1)
BUILD_ASSERT(PAGE_LOCKS_SIZE > MAX_REQS_TOTAL); /* to avoid contention */

/**
 * Local definitions for requests/completions
 */
struct local_request {
    volatile int busy;
    int index;
    int chan_id;
    struct fault* fault;
    struct region_t* mr;
    unsigned long orig_local_addr;
    unsigned long local_addr;
    unsigned long remote_addr;
    unsigned long size;
};

enum req_mode_t {
    WRITE,
    READ,
};

struct local_completion {
    volatile int busy;
    int req_idx;
    enum req_mode_t rwmode;
    unsigned long posted_tsc;
};

struct local_channel {
    volatile int read_req_idx;
    volatile int write_req_idx;
    volatile int cq_post_idx;
    volatile int cq_read_idx;
    spinlock_t cq_read_lock;
    struct local_request read_reqs[MAX_R_REQS_PER_CHAN];
    struct local_request write_reqs[MAX_W_REQS_PER_CHAN];
    struct local_completion cq[MAX_REQS_PER_CHAN];
};

/* state */
static struct local_channel* channels[RMEM_MAX_CHANNELS] = {0};
static spinlock_t pglocks[PAGE_LOCKS_SIZE];
static unsigned long pglock_holders[PAGE_LOCKS_SIZE] = {0};
static __thread struct local_completion wc[RMEM_MAX_COMP_PER_OP];

/**
 * Page lock helpers to avoid concurrent page reads/writes. rmem shouldn't 
 * be sending concurrent ops on the same page so we just do this to 
 * check for that case 
 * */
static inline void page_lock_acquire(unsigned long remote_addr)
{
#if !defined(DEBUG) && !defined(SAFEMODE)
    return;
#endif
    int lock_id;
    bool locked;

    lock_id = (unsigned long) remote_addr & PAGE_LOCKS_MASK;
    locked = spin_try_lock(&pglocks[lock_id]);
    if (!locked) {
        /* can't have concurrent ops on the same addr */ 
        BUG_ON(pglock_holders[lock_id] == remote_addr);

        /* lock collision with some other page, wait for the lock */
        spin_lock(&pglocks[lock_id]);
    }

    assert_spin_lock_held(&pglocks[lock_id]);
    pglock_holders[lock_id] = remote_addr;
}

static inline void page_lock_release(unsigned long remote_addr)
{
#if !defined(DEBUG) && !defined(SAFEMODE)
    return;
#endif
    int lock_id;
    lock_id = (unsigned long) remote_addr & PAGE_LOCKS_MASK;
    pglock_holders[lock_id] = 0;
    spin_unlock(&pglocks[lock_id]);
}

/* backend init */
int local_init()
{
    int i;

    log_info("setting up local backend for remote memory");
    for (i = 0; i < PAGE_LOCKS_SIZE; i++)
        spin_lock_init(&pglocks[i]);
    return 0;
}

/* returns the next available channel (id) for datapath */
int local_get_data_channel()
{
    int id;
    id = backend_get_data_channel();
    assert(id >= 0 && id < RMEM_MAX_CHANNELS);
    channels[id] = aligned_alloc(CACHE_LINE_SIZE, sizeof(struct local_channel));
    memset(channels[id], 0, sizeof(struct local_channel));
    return id;
}

/* backend destroy */
int local_destroy()
{
    int i;
    for(i = 0; i < nchans_bkend; i++) {
        assert(channels[i]);
        free(channels[i]);
    }
    return 0;
}

/* add more backend memory (in slabs) and return new regions */
int local_add_regions(struct region_t **regions, int nslabs)
{
    struct region_t *reg;
    void* ptr;
    size_t size;
    int r;

    /* alloc backing memory */
    size = nslabs * RMEM_SLAB_SIZE;
    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, 
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        log_err("memory alloc failed for local backend - %s", strerror(errno));
        BUG();
    }

    /* init & register region */
    reg = (struct region_t *)mmap(NULL, sizeof(struct region_t), 
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    reg->size = 0;
    reg->remote_addr = (unsigned long) ptr; /* remote from client perspective */
    reg->size = size;
    r = register_memory_region(reg, 1);
    assertz(r);
    assert(reg->addr);
    log_debug("%s: local region added at address %p", __func__, ptr);

    /* TODO: return the region in **regions */
    return 1;
}

/* remove a memory region from backend */
int local_free_region(struct region_t *reg)
{
    assert(reg->remote_addr);
    munmap((void*) reg->remote_addr, reg->size);
    return 0;
}

/* post read on a channel */
int local_post_read(int chan_id, fault_t* f)
{
    struct local_channel* chan;
    unsigned long remote_addr, offset;
    void* local_addr;
    size_t size;
    int req_id, cq_id;
    
    /* get channel */
    log_debug("%s - posting read", FSTR(f));
    assert(chan_id >= 0 && chan_id < nchans_bkend);
    chan = channels[chan_id];

    /* do we have a free slot? */
    req_id = chan->read_req_idx;
    assert(req_id >= 0 && req_id < MAX_R_REQS_PER_CHAN);
    if (load_acquire(&chan->read_reqs[req_id].busy))
        /* all slots busy, try again */
        return EAGAIN;

    /* infer remote addr */
    offset = f->page - f->mr->addr;
    remote_addr = f->mr->remote_addr + offset;
    size = CHUNK_SIZE * (1 + f->rdahead);
    assert(offset + size <= f->mr->size);

    /* alloc data buf */
    local_addr = bkend_buf_alloc();
    BUG_ON(local_addr == NULL);     /* not enough bufs */
    f->bkend_buf = local_addr;
    assert(size <= BACKEND_BUF_SIZE);

    /* take this slot */
    log_debug("%s - taking read slot %d on chan %d", FSTR(f), req_id, chan_id);
    chan->read_reqs[req_id].busy = 1;
    chan->read_reqs[req_id].index = req_id;
    chan->read_reqs[req_id].local_addr = (unsigned long) local_addr;
    chan->read_reqs[req_id].orig_local_addr = f->page;
    chan->read_reqs[req_id].remote_addr = remote_addr;
    chan->read_reqs[req_id].size = size;
    chan->read_reqs[req_id].mr = f->mr;
    chan->read_reqs[req_id].fault = f;

    /*** post read - which in case of local backend is just copying the 
     * data to the buffer and post a completion ***/

    /* take a page lock to avoid concurrent page reads/writes */
    page_lock_acquire(remote_addr);

    /* copy from remote */
    log_debug("%s - READ remote_addr %lx into local_addr %p, size %lu", FSTR(f), 
        remote_addr, local_addr, size);
    memcpy(local_addr, (void*) remote_addr, size);

    /* post completion */
    cq_id = chan->cq_post_idx;
    assert(cq_id >= 0 && cq_id < MAX_REQS_PER_CHAN);
    assert(!chan->cq[cq_id].busy);  /* cq should have enough free entries */
    chan->cq[cq_id].req_idx = req_id;
    chan->cq[cq_id].rwmode = READ;
    chan->cq[cq_id].posted_tsc = rdtsc();
    store_release(&chan->cq[cq_id].busy, 1);
    log_debug("%s - posted cq %d on chan %d", FSTR(f), cq_id, chan_id);

    /* release after completion to maintain order */
    page_lock_release(remote_addr);

    /* increment queue ids */
    chan->read_req_idx++;
    assert(req_id + 1 == chan->read_req_idx); /*no unexpected concurrent reads*/
    if (chan->read_req_idx >= MAX_R_REQS_PER_CHAN) 
        chan->read_req_idx = 0;

    chan->cq_post_idx++;
    assert(cq_id + 1 == chan->cq_post_idx); /*no unexpected concurrent posts */
    if (chan->cq_post_idx >= MAX_REQS_PER_CHAN) 
        chan->cq_post_idx = 0;

    /* success */
    return 0;
}

/* post write on a channel */
int local_post_write(int chan_id, struct region_t* mr, unsigned long addr, 
    size_t size) 
{
    struct local_channel* chan;
    unsigned long remote_addr, offset;
    void* local_addr;
    int req_id, cq_id;
    
    /* get channel */
    log_debug("posting write for %lx, size %ld", addr, size);
    assert(chan_id >= 0 && chan_id < nchans_bkend);
    chan = channels[chan_id];

    /* do we have a free slot? */
    req_id = chan->write_req_idx;
    assert(req_id >= 0 && req_id < MAX_W_REQS_PER_CHAN);
    if (load_acquire(&chan->write_reqs[req_id].busy))
        /* all slots busy, try again */
        return EAGAIN;

    /* infer remote addr */
    offset = addr - mr->addr;
    remote_addr = mr->remote_addr + offset;
    assert(offset + size <= mr->size);

    /* alloc data buf */
    local_addr = bkend_buf_alloc();
    BUG_ON(local_addr == NULL);     /* not enough bufs */
    assert(size <= BACKEND_BUF_SIZE);

    /* take this slot */
    log_debug("taking write slot %d for %lx on chan %d", req_id, addr, chan_id);
    chan->write_reqs[req_id].busy = 1;
    chan->write_reqs[req_id].index = req_id;
    chan->write_reqs[req_id].local_addr = (unsigned long) local_addr;
    chan->write_reqs[req_id].orig_local_addr = addr;
    chan->write_reqs[req_id].remote_addr = remote_addr;
    chan->write_reqs[req_id].size = size;
    chan->write_reqs[req_id].mr = mr;

    /* copy page into temporary local buf
     * NOTE: we don't need this extra copy for local backend as we can copy 
     * the buffer to the "remote" region directly, but for the sake of 
     * consistency with backend semantics, let's do the same thing as any 
     * other non-local backend would do. */
    assert(size <= BACKEND_BUF_SIZE);
    memcpy(local_addr, (void *)addr, size);

    /* post write - which in case of local backend is just copying the 
     * data from the buffer and post a completion */

    /* take a page lock to avoid concurrent page reads/writes. rmem shouldn't 
     * be sending concurrent ops on the same page so we just do this to 
     * check for that case */
    page_lock_acquire(remote_addr);

    /* copy to remote */
    log_debug("WRITE remote_addr %lx from local_addr %p, size %lu", 
        remote_addr, local_addr, size);
    memcpy((void*) remote_addr, local_addr, size);

    /* post completion */
    cq_id = chan->cq_post_idx;
    assert(cq_id >= 0 && cq_id < MAX_REQS_PER_CHAN);
    assert(!chan->cq[cq_id].busy);  /* cq should have enough free entries */
    chan->cq[cq_id].req_idx = req_id;
    chan->cq[cq_id].rwmode = WRITE;
    chan->cq[cq_id].posted_tsc = rdtsc();
    store_release(&chan->cq[cq_id].busy, 1);
    log_debug("posted cq %d for %lx on chan %d", cq_id, addr, chan_id);

    /* release after completion to maintain order */
    page_lock_release(remote_addr);

    /* increment queue ids */
    chan->write_req_idx++;
    assert(req_id + 1 == chan->write_req_idx); /*no unexpected concurrent reads*/
    if (chan->write_req_idx >= MAX_W_REQS_PER_CHAN) 
        chan->write_req_idx = 0;

    chan->cq_post_idx++;
    assert(cq_id + 1 == chan->cq_post_idx); /*no unexpected concurrent posts */
    if (chan->cq_post_idx >= MAX_REQS_PER_CHAN) 
        chan->cq_post_idx = 0;

    /* success */
    return 0;
}

/* backend check for read & write completions on a channel */
int local_check_cq(int chan_id, struct bkend_completion_cbs* cbs, int max_cqe, 
    int* nread, int* nwrite)
{
    struct local_request* req;
    struct local_completion *cq;
    struct local_channel* chan;
    int ncqe, r, i, cq_id, req_id;
    spinlock_t* cq_lock;
    unsigned long long duration_tsc;
    
    ncqe = 0;
    if(nread)   *nread = 0;
    if(nwrite)  *nwrite = 0;
    assert(max_cqe > 0 && max_cqe <= RMEM_MAX_COMP_PER_OP);
    assert(chan_id >= 0 && chan_id < nchans_bkend);
    chan = channels[chan_id];

    /* get CQ to poll */
    cq = chan->cq;
    cq_lock = &chan->cq_read_lock;

    /* get completions out of the queue (this function is expected to be thread-
     * safe) so we pull them out quickly under a lock and handle them later */
    spin_lock(cq_lock);
    for (i = 0; i < max_cqe; i++)
    {
        /* check current slot */
        cq_id = chan->cq_read_idx;
        assert(cq_id >= 0 && cq_id < MAX_REQS_PER_CHAN);
        if (!load_acquire(&cq[cq_id].busy))
            /* no completions */
            break;

        /* found one */
        log_debug("found completion on chan %d idx %d", chan_id, cq_id);

        /* check artificial delay: is it time yet? */
        duration_tsc = rdtscp(NULL) - cq[cq_id].posted_tsc;
        if (duration_tsc < cycles_per_us * LOCAL_BACKEND_DELAY_MUS)
            break;

        /* copy completion to local buf. NOTE: mind the shallow copy */
        wc[i] = cq[cq_id];

        /* go to next cq */
        store_release(&cq[cq_id].busy, 0);
        chan->cq_read_idx++;
        assert(cq_id + 1 == chan->cq_read_idx); /*no unexpected concur reads */
        if (chan->cq_read_idx >= MAX_REQS_PER_CHAN) 
            chan->cq_read_idx = 0;
        ncqe++;
    }
    spin_unlock(cq_lock);

    /* handle completions */
    for (i = 0; i < ncqe; i++)
    {
        req_id = wc[i].req_idx;
        assert(req_id >= 0);
        if (wc[i].rwmode == READ) {
            /* handle read completion */
            assert(req_id < MAX_R_REQS_PER_CHAN);
            req = &(channels[chan_id]->read_reqs[req_id]);
            assert(req->busy);
            assert(req->fault && req->fault->bkend_buf);
            assert(req->size == (1 + req->fault->rdahead) * CHUNK_SIZE);
            log_debug("%s - READ done, qid: %d", FSTR(req->fault), req_id);
           
            /* call completion hook */
            r = cbs->read_completion(req->fault);
            assertz(r);

            /* release request slot */
            store_release(&req->busy, 0);
            RSTAT(NET_READ)++;
            if (nread)  (*nread)++;
        }
        else {
            /* handle write completion */
            assert(wc[i].rwmode == WRITE);
            assert(req_id < MAX_W_REQS_PER_CHAN);
            req = &(channels[chan_id]->write_reqs[req_id]);
            assert(req->busy);
            assert(req->mr);
            log_debug("WRITE completed on chan %d, addr=%lx", 
                chan_id, req->orig_local_addr);

            /* call completion hook */
            r = cbs->write_completion(req->mr, req->orig_local_addr, req->size);
            assertz(r);

            /* release data buffer */
            bkend_buf_free((void*)req->local_addr);

            /* release request slot */
            store_release(&req->busy, 0);
            RSTAT(NET_WRITE)++;
            if (nwrite)  (*nwrite)++;
        }
    }

    assert(!(nread && nwrite) || (*nread + *nwrite == ncqe));
    return ncqe;
}

/* ops for local DRAM backend */
struct rmem_backend_ops local_backend_ops = {
    .init = local_init,
    .get_new_data_channel = local_get_data_channel,
    .destroy = local_destroy,
    .add_memory = local_add_regions,
    .remove_region = local_free_region,
    .post_read = local_post_read,
    .post_write = local_post_write,
    .check_for_completions = local_check_cq,
};