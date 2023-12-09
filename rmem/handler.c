/*
 * handler.h - dedicated handler core for remote memory
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <linux/userfaultfd.h>
#include <unistd.h>

#include "base/cpu.h"
#include "base/mem.h"
#include "base/sampler.h"
#include "rmem/backend.h"
#include "rmem/common.h"
#include "rmem/config.h"
#include "rmem/dump.h"
#include "rmem/eviction.h"
#include "rmem/fault.h"
#include "rmem/fsampler.h"
#include "rmem/handler.h"
#include "rmem/page.h"
#include "rmem/pgnode.h"
#include "rmem/region.h"
#include "rmem/uffd.h"

/* handler state */
__thread struct hthread *my_hthr = NULL;
__thread int current_stealing_kthr_id = -1;
__thread unsigned long current_blocking_page = 0;
__thread bool current_page_unblocked = false;

/* check if a fault already exists in the wait queue */
bool does_fault_exist_in_wait_q(struct fault *fault)
{
    struct fault *f;
    list_for_each(&my_hthr->fault_wait_q, f, link) {
        if (f->page == fault->page)
            return true;
    }
    return false;
}

/* called after fetched pages are ready on handler read completions */
int hthr_fault_read_done(fault_t* f)
{
    int r;
    r = fault_read_done(f);
    assertz(r);

    /* release fault */
    fault_done(f);
    return 0;
}

/* poll for faults/other notifications coming from UFFD */
static inline fault_t* read_uffd_fault()
{
    ssize_t read_size;
    struct uffd_msg message;
    struct fault* fault;
    unsigned long long addr, flags;
    struct region_t* mr;

    struct pollfd evt = { .fd = userfault_fd, .events = POLLIN };
    if (poll(&evt, 1, 0) > 0) {
        /* we have something pending on ths fd */
        if ((evt.revents & POLLERR) || (evt.revents & POLLHUP)) {
            log_warn_ratelimited("unexpected wrong poll event from uffd");
            return NULL;
        }

        /* read uffd event data into message */
        read_size = read(evt.fd, &message, sizeof(struct uffd_msg));
        if (unlikely(read_size != sizeof(struct uffd_msg))) {
            /* EAGAIN is fine; another handler may have gotten to it first */
            if (errno != EAGAIN) {
                log_err("unexpected read size %ld, errno %d on uffd", 
                    read_size, errno);
                BUG();
            }
            return NULL;
        }

        /* only need page fault events */
        if (unlikely(message.event != UFFD_EVENT_PAGEFAULT)) {
            /* we don't need other events right now; a lot of them are 
             * for reporting changes to memory layout to the handler, but 
             * we hope to handle them with memory lib interposition (see 
             * fltrace.c) or provide explicit calls (see rmem_api.c) */
            log_err("uffd event %d not supported", message.event);
            BUG();
        }

        /* new fault */
        addr = message.arg.pagefault.address;
        flags = message.arg.pagefault.flags;
        log_debug("uffd pagefault event %d: addr=%llx, flags=0x%llx",
            message.event, addr, flags);

        /* create new fault object */
        fault = fault_alloc();
        if (unlikely(!fault)) {
            log_debug("couldn't get a fault object");
            return NULL;    /* we'll try again later */
        }
    
        /* populate it */
        memset(fault, 0, sizeof(fault_t));
        fault->page = addr & ~CHUNK_MASK;
        fault->is_wrprotect = !!(flags & UFFD_PAGEFAULT_FLAG_WP);
        fault->is_write = !!(flags & UFFD_PAGEFAULT_FLAG_WRITE);
        fault->is_read = !(fault->is_write || fault->is_wrprotect);
        fault->from_kernel = true;
        fault->rdahead_max = 0;   /*no readaheads for kernel faults*/
        fault->rdahead  = 0;
        fault->evict_prio = evict_nprio - 1;

        /* find associated region */
        mr = get_region_by_addr_safe(fault->page);
        BUG_ON(!mr);  /* we dont do region deletions yet so it must exist */
        assert(mr->addr);
        fault->mr = mr;

#ifdef FAULT_SAMPLER
        /* check if this is the first fault on the page; there may be many 
         * concurrent "first" faults to a page but only one of them can be 
         * captured as zero-page fault if we just use PFLAG_REGISTERED. So we
         * use PFLAG_PRESENT_ZERO_PAGED to indicate if a page is currently 
         * exists in local memory before its first-ever eviction and any faults
         * to such locally-present page must be a concurrent zero-page faults */
        pgflags_t pflags = get_page_flags(mr, addr);
        if (!(pflags & PFLAG_REGISTERED) || (pflags & PFLAG_PRESENT_ZERO_PAGED))
            flags |= FSAMPLER_FAULT_FLAG_ZERO;

        /* record if sampling faults */
        fsampler_add_fault_sample(my_hthr->fsampler_id, addr, flags,
            message.arg.pagefault.feat.ptid);
#endif

        return fault;
    }
    return NULL;
}

/**
 * Main handler thread function
 */
static void* rmem_handler(void *arg) 
{
    /* handler threads run entirely in runtime */
    RUNTIME_ENTER();

    bool need_eviction, work_done;
    unsigned long long pressure;
    fault_t *fault, *next;
    int nevicts, nevicts_needed, batch, r;
    enum fault_status fstatus;
    assert(arg != NULL);        /* expecting a hthread_t */
    my_hthr = (hthread_t*) arg; /* save our hthread_t */
    unsigned long now_tsc, last_tsc;

    /* init per-thread resources */
    r = thread_init_perthread(); assertz(r); /* for tcache support */
    rmem_common_init_thread(&my_hthr->bkend_chan_id, my_hthr->rstats, 0);
    list_head_init(&my_hthr->fault_wait_q);
    my_hthr->n_wait_q = 0;
#ifdef FAULT_SAMPLER
    my_hthr->fsampler_id = fsampler_get_sampler();
#endif

    /* do work */
    last_tsc = 0;
    while(!my_hthr->stop)
    {
        /* account time spent in last iteration */
        now_tsc = rdtsc();
        if (last_tsc) {
            RSTAT(TOTAL_CYCLES) += now_tsc - last_tsc;
            if (work_done)
                RSTAT(WORK_CYCLES) += now_tsc - last_tsc;
        }
        last_tsc = now_tsc;

        /* reset every iteration */
        need_eviction = false;
        work_done = false;
        nevicts = nevicts_needed = 0;

        /* pick faults from the backlog (wait queue) first */
        fault = list_top(&my_hthr->fault_wait_q, fault_t, link);
        while (fault != NULL) {
            next = list_next(&my_hthr->fault_wait_q, fault, link);
            fstatus = handle_page_fault(my_hthr->bkend_chan_id, fault, 
                &nevicts_needed, &hthr_cbs);
            switch (fstatus) {
                case FAULT_DONE:
                    log_debug("%s - done, released from wait", FSTR(fault));
                    list_del_from(&my_hthr->fault_wait_q, &fault->link);
                    assert(my_hthr->n_wait_q > 0);
                    my_hthr->n_wait_q--;
                    fault_done(fault);
                    work_done = true;
                    break;
                case FAULT_READ_POSTED:
                    log_debug("%s - done, released from wait", FSTR(fault));
                    list_del_from(&my_hthr->fault_wait_q, &fault->link);
                    assert(my_hthr->n_wait_q > 0);
                    my_hthr->n_wait_q--;
                    work_done = true;
                    if (nevicts_needed > 0)
                        goto eviction;
                    break;
                case FAULT_IN_PROGRESS:
                    log_debug("%s - not released from wait", FSTR(fault));
                    RSTAT(WAIT_RETRIES)++;
                    break;
            }

            /* go to next fault */
            fault = next;
        }

        /* check for incoming uffd faults */
        fault = read_uffd_fault();
        if (fault) {
            /* accounting */
            RSTAT(FAULTS)++;
            if (fault->is_read)         RSTAT(FAULTS_R)++;
            if (fault->is_write)        RSTAT(FAULTS_W)++;
            if (fault->is_wrprotect)    RSTAT(FAULTS_WP)++;
            if (fault->evict_prio == 0) RSTAT(FAULTS_P0)++;
            work_done = true;

            /* start handling fault */
            fstatus = handle_page_fault(my_hthr->bkend_chan_id, fault, 
                &nevicts_needed, &hthr_cbs);
            switch (fstatus) {
                case FAULT_DONE:
                    fault_done(fault);
                    break;
                case FAULT_IN_PROGRESS:
                    /* handler thread should not see duplicate faults as we 
                     * don't expect kernel to send the same fault twice; 
                     * although duplicate faults seems to occur when debugging 
                     * with GDB after a previously faulting thread is let go 
                     * from a breakpoint, so comment it out when debugging */
                    // assert(!does_fault_exist_in_wait_q(fault));

                    /* add to wait, with a timestamp */
                    assertz(fault->tstamp_tsc);
                    fault->tstamp_tsc = rdtsc();
                    list_add_tail(&my_hthr->fault_wait_q, &fault->link);
                    my_hthr->n_wait_q++;
                    log_debug("%s - added to wait", FSTR(fault));
                    break;
                case FAULT_READ_POSTED:
                    /* nothing to do here, we check for completions later*/
                    break;
            }
        }

eviction:
        /*  do eviction if needed */
        need_eviction = (nevicts_needed > 0);
        if (!need_eviction) {
            /* if eviction wasn't already signaled by the earlier fault, 
             * see if we need one in general (since this is the handler thread)*/
            pressure = atomic64_read(&memory_used);
            need_eviction = (pressure > local_memory * eviction_threshold);
        }

        /* start eviction */
        if (need_eviction) {
            nevicts = 0;
            do {
                /* can use bigger batches in handler threads if idling */
                batch = evict_batch_size;
                if (nevicts_needed > 0) 
                    batch = EVICTION_MAX_BATCH_SIZE;
                nevicts += do_eviction(my_hthr->bkend_chan_id, &hthr_cbs, batch);
            } while(nevicts < nevicts_needed);
            work_done = true;
        }

        /* handle read/write completions from the backend */
        r = rmbackend->check_for_completions(my_hthr->bkend_chan_id, &hthr_cbs, 
            RMEM_MAX_COMP_PER_OP, NULL, NULL);
        if (r > 0)
            work_done = true;

        /* check for remote memory dump */
        if (unlikely(dump_rmem_state_and_exit)) {
            dump_rmem_state();
            unreachable();
        }

        /* check for any sampler dumps */
#ifdef EPOCH_SAMPLER
        sampler_dump_provide_tsc(&epoch_sampler, 32, now_tsc);
#endif
#ifdef FAULT_SAMPLER
        fsampler_dump(my_hthr->fsampler_id);
#endif
    }

    /* destroy state */
    rmem_common_destroy_thread();
    assert(list_empty(&my_hthr->fault_wait_q));
    return NULL;
}

/* create a new fault handler thread */
hthread_t* new_rmem_handler_thread(int pincore_id)
{
    int r;
    hthread_t* hthr = aligned_alloc(CACHE_LINE_SIZE, sizeof(hthread_t));
    assert(hthr);
    memset(hthr, 0, sizeof(hthread_t));

    /* create thread */
    hthr->stop = false;
    hthr->fsampler_id = -1;
    r = pthread_create(&hthr->thread, NULL, rmem_handler, (void*)hthr);
    if (r < 0) {
        log_err("pthread_create for rmem handler failed: %d", errno);
        return NULL;
    }

    /* pin thread */
    if (pincore_id >= 0) {
        r = cpu_pin_thread(hthr->thread, pincore_id);
        assertz(r);
    }

    return hthr;
}

/* stop and deallocate a fault handler thread */
int stop_rmem_handler_thread(hthread_t* hthr)
{
    /* signal and wait for thread to stop */
    assert(!hthr->stop);
    hthr->stop = true;
	pthread_join(hthr->thread, NULL);

    /* deallocate */
    free(hthr);
    return 0;
}

/* handler thread backend read/write completion ops for own cq */
struct bkend_completion_cbs hthr_cbs = {
    .read_completion = hthr_fault_read_done,
    .write_completion = owner_write_back_completed
};
