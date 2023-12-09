/*
 * backend.h - abstract remote memory backend
 */

#ifndef __BACKEND_H__
#define __BACKEND_H__

#include "base/thread.h"
#include "rmem/config.h"
#include "rmem/fault.h"
#include "rmem/region.h"

/* accounting for resource allocation limits */
#define MAX_CONNECTIONS         RMEM_MAX_REGIONS         
#define MAX_R_REQS_PER_CONN_CHAN 32
#define MAX_W_REQS_PER_CONN_CHAN 32

#define MAX_R_REQS_PER_CHAN     (MAX_R_REQS_PER_CONN_CHAN * MAX_CONNECTIONS)
#define MAX_W_REQS_PER_CHAN     (MAX_W_REQS_PER_CONN_CHAN * MAX_CONNECTIONS)
#define MAX_REQS_PER_CHAN       (MAX_R_REQS_PER_CHAN + MAX_W_REQS_PER_CHAN)

#define MAX_R_REQS_TOTAL        (RMEM_MAX_CHANNELS * MAX_R_REQS_PER_CHAN)
#define MAX_W_REQS_TOTAL        (RMEM_MAX_CHANNELS * MAX_W_REQS_PER_CHAN)
#define MAX_REQS_TOTAL          (MAX_R_REQS_TOTAL + MAX_W_REQS_PER_CHAN)

#define MAX_BACKEND_BUFS        MAX_REQS_TOTAL
#define BACKEND_BUF_SIZE        (CHUNK_SIZE * RMEM_MAX_CHUNKS_PER_OP)
#define BACKEND_BUF_MAG_SIZE    MAX_R_REQS_PER_CONN_CHAN
BUILD_ASSERT(BACKEND_BUF_MAG_SIZE <= TCACHE_MAX_MAG_SIZE);

/* forward declarations */
struct region_t;    
struct fault;
struct bkend_completion_cbs;

/**
 * Backend suppported ops
 * Provides read/write page ops on multiple channels, each of which can be
 * used independently (e.g., by each core). Note that none of the backend 
 * operations are expected to be thread-safe as cores work with independent 
 * channels EXCEPT check_for_completions() which is expected to be thread-safe
 * as multiple cores can call it on a single channel during work stealing.
 */
struct rmem_backend_ops {
    /**
     * init - global backend init
     * returns 0 if success, 1 otherwise
     */
    int (*init)();

    /**
     * get_new_data_channel - next available channel for read/write pages
     * returns channel id if available, -1 otherwise
     */
    int (*get_new_data_channel)();

    /**
     * destroy - backend destroy
     * returns 0 if success, 1 otherwise
     */
    int (*destroy)();

    /**
     * add_memory - request more memory (in slabs) from the backend. New regions 
     * (there may be more than one e.g., from multiple remote servers) are 
     * added to `reg` and the count is returned.
     */
    int (*add_memory)(struct region_t **reg, int nslabs);

    /**
     * remove_region - inform the backend to remove/free a memory region
     * returns 0 if success, 1 otherwise
     */
    int (*remove_region)(struct region_t *reg);
    
    /**
     * post_read - post read request for the pages needed by the fault from 
     * the backend. returns 0 if posted, EAGAIN if busy
     */
    int (*post_read)(int chan_id, struct fault* f);

    /**
     * post_write - post write request for the page range pointed by addr and 
     * size to the backend. returns 0 if posted, EAGAIN if busy
     */
    int (*post_write)(int chan_id, struct region_t* mr, unsigned long addr, 
        size_t size);

    /**
     * check_for_completions - check with backend for read/write completions
     * for the posted ones. One can also specify max events it is allowed to
     * check before. Returns the number of events addressed (including the 
     * read/write split if required) or -1 on error.
     * NOTE: This function is expected to be thread-safe for each channel to 
     * allow completion stealing. Naturally, the thread-safety expectations 
     * extend to the callbacks too.
     */
    int (*check_for_completions)(int chan_id, struct bkend_completion_cbs* cbs,
        int max_cqe, int* nread, int* nwrite);
};

/* available backends */
extern struct rmem_backend_ops local_backend_ops;
extern struct rmem_backend_ops rdma_backend_ops;
/* current backend */
extern struct rmem_backend_ops* rmbackend;

/**
 * Completion Callbacks
 **/
struct bkend_completion_cbs {
    /**
     * read_completion - executed after a read fetches the page(s). The fault 
     * that initiated the read is passed over to the callback, whose bkend_buf
     * is set to the backend buffer containing the read content. The callback 
     * is responsible for freeing them both after use.
     */
    int (*read_completion)(struct fault* fault);

    /**
     * write_completion - executed after a posted write finished writing back.
     * The local identifier of written pages (region and address) are 
     * passed to the callback to mark any completions. 
     */
    int (*write_completion)(struct region_t* mr, unsigned long page, size_t size);
};

/**
 * Common backend functions 
 **/
extern atomic_int nchans_bkend;
int backend_get_data_channel();

/**
 * Backend data buffer pool (tcache) support
 */
DECLARE_PERTHREAD(struct tcache_perthread, bkend_buf_pt);

int bkend_buf_tcache_init(void);
void bkend_buf_tcache_init_thread(void);
void bkend_buf_get_backing_region(void** start, size_t* len);
bool bkend_is_buf_valid(void* buf);

/* bkend_buf_alloc - allocates a buf from pool */
static inline void *bkend_buf_alloc(void)
{
    return tcache_alloc(&perthread_get(bkend_buf_pt));
}

/* bkend_buf_free - frees a fault */
static inline void bkend_buf_free(void *buf)
{
    assert(bkend_is_buf_valid(buf));
    tcache_free(&perthread_get(bkend_buf_pt), buf);
}

#endif    // __BACKEND_H__