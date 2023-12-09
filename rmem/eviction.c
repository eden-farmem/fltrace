/*
 * eviction.h - eviction helpers
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include "base/cpu.h"
#include "base/log.h"
#include "base/sampler.h"
#include "base/qestimator.h"

#include "rmem/backend.h"
#include "rmem/common.h"
#include "rmem/config.h"
#include "rmem/fault.h"
#include "rmem/handler.h"
#include "rmem/page.h"
#include "rmem/pgnode.h"
#include "rmem/region.h"
#include "rmem/uffd.h"

/* eviction state */
__thread uint64_t last_seen_faults = 0;
__thread struct region_t *eviction_region_safe = NULL;
__thread uint64_t last_evict_try_count = 0;
__thread struct iovec madv_iov[EVICTION_MAX_BATCH_SIZE];
__thread struct page_list tmp_evict_gens[EVICTION_MAX_GENS];
__thread struct iovec mprotect_iov[EVICTION_MAX_BATCH_SIZE];
__thread struct region_t* mprotect_mr[EVICTION_MAX_BATCH_SIZE];
int madv_pidfd = -1;

/* lru state */
struct page_list evict_gens[EVICTION_MAX_GENS];
struct page_list_per_prio dne_pages;
int evict_ngens = 1;
int evict_gen_mask = 0;
int evict_nprio = 1;
unsigned long epoch_start_tsc;
int epoch_tsc_shift;
struct sampler epoch_sampler;
struct sampler_ops epoch_sampler_ops;
struct mov_p2estimator epoch_p2estimator;

/**
 * All these are write-protected by the lock of the current LRU generation 
 * the pages are being evicted out of i.e., evict_gens[evict_gen_now].lock
 * Place variables in a different cache line to avoid false sharing with 
 * constants.
 */
unsigned long evict_epoch_now __aligned(CACHE_LINE_SIZE) = 0;
int evict_gen_now = 0;
int evict_prio_now = 0;
int evict_prio_quota_left = 1;

/* get process memory from OS */
unsigned long long get_process_mem()
{
    FILE *file = fopen("/proc/self/status", "r");
    if (!file)
        return 0;

    const int line_size = 512;
    char line[line_size];
    unsigned long long vmrss = 0;

    while (fgets(line, line_size, file) != NULL) {
        int i = strlen(line);
        assert(i > 6);
        if (strncmp(line, "VmRSS:", 6) == 0) {
            // This assumes that a digit will be found and the line ends in " Kb".
            const char *p = line;
            while (*p < '0' || *p > '9') p++;
            line[i - 3] = '\0';
            vmrss = atoi(p);
            break;
        }
    }
    fclose(file);

    // Convert to bytes
    vmrss *= 1024;
    return vmrss;
}

/* checks if OS memory stats match our local memory accounting */
void verify_eviction()
{
    double over_allocated;

    /* Note that this does not work for the local backend as the backing memory
     * for the backend also comes from process memory (and allocated on demand), 
     * so the OS memory stat in this case does not reflect the 
     * true resident-set size of the process running on Eden */
    if (rmbackend_type == RMEM_BACKEND_LOCAL)
        return;

    /* check every 1 million page faults served? */
    if (RSTAT(FAULTS) - last_seen_faults > OS_MEM_PROBE_INTERVAL) {
        last_seen_faults = RSTAT(FAULTS);

        /* read the current memory from OS periodically */
        uint64_t current_mem = get_process_mem();
        if (current_mem > 0) {
            over_allocated = (current_mem - local_memory) * 100 / local_memory;
            if (over_allocated > 1) {
                /* just warn for now */
                log_warn("OS memory probing found usage %.0lf%% (>1%%) "
                    "over limit. memory overflow: %lu MB", over_allocated, 
                    (current_mem - local_memory) / 1024 / 1024);
            }
        }
    }
}

/**
 * Return the number of pages that must be popped off at each 
 * priority level before moving to the next one
 */
static __always_inline int get_evict_prio_quota(int prio)
{
    assert(prio >= 0 && prio < evict_nprio);
#if EVPRIORITY_LINEAR
    /* pop off one extra page at each step */
    return prio + 1;
#elif EVPRIORITY_EXPONENITAL
   /* FIXME: should be (1 << prio) instead */
    return (prio == 0 ? 2 : 3); 
#endif
    /* absolute priority by default i.e., each prio level must 
     * be fully exhausted before moving to the next one */
    return -1;
}

/**
 * Update evict_epoch_now based on the current timer
 */
static __always_inline void update_evict_epoch_now(void)
{
#ifdef LRU_EVICTION
    unsigned long tmp_evict_epoch_now;
    tmp_evict_epoch_now = (rdtsc() - epoch_start_tsc) >> epoch_tsc_shift;
    assert(tmp_evict_epoch_now >= evict_epoch_now);
    evict_epoch_now = tmp_evict_epoch_now;
    log_debug("evict_epoch_now updated to %lu", evict_epoch_now);
#endif
}

/* Destiny of a page with LRU eviction */
static __always_inline int get_page_next_gen_lru(struct rmpage_node* page)
{
    long int next_gen_id, slope;
    unsigned long pgepoch, pgepoch_gap;
    unsigned long pgepoch_quantile;

    /* check and sort pages */
    assert(evict_gen_mask);

    /* get page's epoch; may get updated concurrently so just read it once */
    pgepoch = ACCESS_ONCE(page->epoch);
    assert(pgepoch == 0 || pgepoch <= evict_epoch_now);
    pgepoch_gap = evict_epoch_now - pgepoch;

    /* reset the page's access epoch. we're either gonna evict it or 
     * bump it to higher list, either of which require resetting it */
    page->epoch = 0;

    next_gen_id = 0;
    if (pgepoch)
    {
        /* page epoch was set by a hint, indicating a more recent access 
         * after the page fault. figure out the next gen for this page 
         * depending on how recent the access was */

        /* add the gap to epoch to the quantile estimator */
        mov_p2estimator_add(&epoch_p2estimator, pgepoch_gap);

        pgepoch_quantile = mov_p2estimator_get_quantile(&epoch_p2estimator);
        assert(pgepoch_quantile >= 0);
        if (pgepoch_gap < pgepoch_quantile) {
            slope = pgepoch_gap * (evict_ngens - 1) / pgepoch_quantile;
            assert(slope >= 0 && slope <= evict_ngens - 1);
            next_gen_id = (evict_ngens - (1 + slope));
        }
    }

#ifdef EPOCH_SAMPLER
    /* record the page epoch gap and 
     * no need to bump lists when sampling */
    if (pgepoch)
        sampler_add(&epoch_sampler, &next_gen_id);
        // sampler_add(&epoch_sampler, &pgepoch_quantile);
        // sampler_add(&epoch_sampler, &pgepoch_gap);
    return 0;
#endif

    log_debug("page %lx had epoch %lu, epoch now: %lu, next gen: %ld", 
        page->addr, pgepoch, evict_epoch_now, next_gen_id);
    return next_gen_id;
}

/* Destiny of a page with SC (second-chance) eviction */
static int __always_inline get_page_next_gen_sc(struct rmpage_node* page)
{
    pgflags_t flags;

    /* check page accessed bit */
    flags = get_page_flags(page->mr, page->addr);
    if (!!(flags & PFLAG_ACCESSED)) {
        /* reset the access bit. we're either gonna evict it or bump it
         * to higher list, either of which require resetting it */
        clear_page_flags(page->mr, page->addr, PFLAG_ACCESSED, NULL);

        /* bump it to the next list 
         * (we only maintain two lists in second-chance eviction) */
        log_debug("page %lx had accessed bit set, bumping up", page->addr);
        return 1;
    }

    log_debug("page %lx had accessed bit clear, evicting", page->addr);
    return 0;
}

/**
 * Figure out the eviction destiny of a page. If the page was recently accessed
 * and needs to be bumped up to a higher list according to the eviction policy,
 * return the the number of the new generation. Or returns 0 if the page can 
 * be evicted
 **/
static int __always_inline get_page_next_gen(struct rmpage_node* page)
{
#ifdef LRU_EVICTION
    return get_page_next_gen_lru(page);
#endif
#ifdef SC_EVICTION
    return get_page_next_gen_sc(page);
#endif
    return 0;
}

/* drain some of the pages reserved for bumping to higher lists into the 
 * the eviction lists (because we ran out of pages in the original lists) */
int drain_tmp_lists(struct list_head* evict_list, int max_drain,
    bitmap_ptr tmplist_nonzero)
{
    int npages, gen_id, prio;
    struct rmpage_node* page;

    assert(evict_ngens > 0);
    /* we don't use tmplist 0 */
    for (prio = 0; prio < evict_nprio; prio++)
        assert(list_empty(&tmp_evict_gens[0].pages[prio]));

    /* drain from the bottom gen, lowest priority */
    log_debug("draining tmp lists");
    npages = 0;
    for (gen_id = 1; gen_id < evict_ngens; gen_id++) {
        if (tmp_evict_gens[gen_id].npages == 0)
            continue;

        if (npages >= max_drain)
            break;

        assert(bitmap_test(tmplist_nonzero, gen_id));
        if (tmp_evict_gens[gen_id].npages <= (max_drain - npages)) {
            /* move all pages in one go */
            for (prio = evict_nprio - 1; prio >= 0; prio--) {
                list_append_list(evict_list, &tmp_evict_gens[gen_id].pages[prio]);
                assert(list_empty(&tmp_evict_gens[gen_id].pages[prio]));
            }
            npages += tmp_evict_gens[gen_id].npages;
            tmp_evict_gens[gen_id].npages = 0;
            bitmap_clear(tmplist_nonzero, gen_id);
        }
        else {
            /* move as many as needed one-by-one */
            for (prio = evict_nprio - 1; prio && npages < max_drain; prio--) {
                while(npages < max_drain) {
                    page = list_pop(&tmp_evict_gens[gen_id].pages[prio], 
                        rmpage_node_t, link);
                    if (!page)
                        break;
                    list_add_tail(evict_list, &page->link);
                    npages++;
                    assert(tmp_evict_gens[gen_id].npages > 0);
                    tmp_evict_gens[gen_id].npages--;
                }
            }
        }
    }
    assert(npages <= max_drain);
    return npages;
}

/* finds eviction candidates - returns the number of candidates found and 
 * sends out the list of page nodes */
static inline int find_candidate_pages(struct list_head* evict_list,
    int batch_size)
{
    int npages, npopped, prio, prio_quota_left;
    int start_gen, gen_id, pg_next_gen;;
    pgflags_t flags, oldflags;
    struct rmpage_node *page, *next;
    struct page_list *evict_gen;
    bool out_of_gens = false;
    DEFINE_BITMAP(tmplist_used, evict_ngens);

    /* quickly pop the first few pages off current lru list */
    gen_id = start_gen = -1;
    npages = npopped = 0;
    bitmap_init(tmplist_used, evict_ngens, 0);
    do {

        /* get current lru gen */
        gen_id = evict_gen_now;
        assert(gen_id >= 0 && gen_id < evict_ngens);

        /* circled back to the started list */
        if (start_gen == gen_id) {
            out_of_gens = true;
            break;
        }
        
        if (start_gen < 0)
            start_gen = gen_id;

        /* lock current gen (make sure things move fast until we unlock) */
        evict_gen = &evict_gens[gen_id];
        spin_lock(&evict_gen->lock);

        /* update epoch */
        update_evict_epoch_now();

        /* figure out where to begin popping pages */
        prio = evict_prio_now;
        prio_quota_left = evict_prio_quota_left;

        do {
            /* break if we are out of pages, or found/popped enough pages */
            if (npages >= batch_size
                    || npopped >= EVICTION_MAX_BUMPS_PER_OP
                    || evict_gen->npages == 0)
                break;

            /* try popping a page from current prio */
            page = list_pop(&evict_gen->pages[prio], rmpage_node_t, link);
            if (unlikely(page == NULL)) {
                /* if out of prio, move to next gen */
                if (unlikely(prio == 0))
                    break;
                prio--;
                continue;
            }

            /* popped a page */
            log_debug("popped page %lx from gen %d prio %d", 
                page->addr, gen_id, prio);
            assert(evict_gen->npages > 0);
            evict_gen->npages--;
            npopped++;

            /* check page's destiny */
            pg_next_gen = get_page_next_gen(page);

            if (pg_next_gen == 0) {
                /* page good for eviction */
                /* save prio in case we need to add the page back */
                assertz(page->evict_prio);
                page->evict_prio = prio;

                /* add it to evict list */
                list_add_tail(evict_list, &page->link);
                npages++;
            }
            else {
                /* page selected to bumping to a higher list */
                assert(pg_next_gen < evict_ngens);
                assert(bitmap_test(tmplist_used, pg_next_gen)
                    || tmp_evict_gens[pg_next_gen].npages == 0);

                list_add_tail(&tmp_evict_gens[pg_next_gen].pages[prio],
                    &page->link);
                tmp_evict_gens[pg_next_gen].npages++;
                bitmap_set(tmplist_used, pg_next_gen);
            }

            /* decrement prio quota TODO: should we do this only for 
             * pages that are good for eviction instead of pages popped? */
            if (prio_quota_left > 0)
                prio_quota_left--;

            /* if out of quota, move to next prio and reset quota */
            if (prio_quota_left == 0) {
                prio--;
                if (prio < 0)
                    prio = evict_nprio - 1;
                prio_quota_left = get_evict_prio_quota(prio);
            }
        } while(true);

        /* got enough pages */
        if (npages == batch_size)
            goto found_enough;
        
        /* enough searching for candidates */
        if (npopped == EVICTION_MAX_BUMPS_PER_OP)
            goto found_enough;

        /* not enough candidates in this list, move to next list */
        assert(list_empty(&evict_gen->pages[0]) && !evict_gen->npages);
        evict_gen_now = (gen_id + 1) % evict_ngens;
        evict_prio_now = evict_nprio - 1;
        evict_prio_quota_left = get_evict_prio_quota(prio);
        spin_unlock(&evict_gen->lock);
        continue;

found_enough:
        /* specify where the next reclaim shoud begin: either from where the
         * previousreclaim left off (if we're doing relative priorities) or 
         * start at the lowest prio again (for absolute reclaim); */
        if (prio_quota_left == -1) {
            evict_prio_now = evict_nprio - 1;
            evict_prio_quota_left = get_evict_prio_quota(prio);
        }
        else {
            evict_prio_now = prio;
            evict_prio_quota_left = prio_quota_left;
        }
        spin_unlock(&evict_gen->lock);
        break;

    } while(1);

    /* record pages popped to find candidates in each turn */
    RSTAT(EVICT_POPPED) += npopped;

    /* if we didn't get enough for a batch, introspect */
    if (npages < batch_size)
    {
        /* if the reason is that we were completely out of pages, 
         * get the remaining from the bump lists if they have any */
        if (unlikely(out_of_gens)) {
            npages += drain_tmp_lists(evict_list, 
                batch_size - npages, tmplist_used);

            /* couldn't find anything anywhere; local memory must have been
             * extremely low for this to happen */
            BUG_ON(npages == 0);
        }
        
        /* if the reason is that we had to give up the hunt after a while as 
         * most pages were non-evictible, then we need to make more pages 
         * evictible; how this is done depends on the eviction policy (such as 
         * increasing the epoch interval or decreasing the number of generations
         * for LRU). For now, we won't take any self-correcting 
         * measures here and let this overhead reflect in the EVICT_SUBOPTIMAL 
         * and evict effective batch size (EVICT_PAGES/EVICTS) metrics. 
         * We'll leave it to the developer to judge if this eviction overhead 
         * is worthwhile and tune the afforementioned parameters. */
        else if (npopped == EVICTION_MAX_BUMPS_PER_OP)
            RSTAT(EVICT_SUBOPTIMAL)++;

        /* expecting no other reason */
        else
            BUG();
    }

    /* add bumped pages back to the higher lists. note that evict_gen_now may 
     * be updated by other evictors in this process but adding pages in the 
     * wrong lists doesn't affect correctness, just performance. we will get 
     * to these pages sooner or later. */
    bitmap_for_each_set(tmplist_used, evict_ngens, gen_id) {
        assert(tmp_evict_gens[gen_id].npages > 0);
        assert(gen_id != 0);
        evict_gen = &evict_gens[(evict_gen_now + gen_id) & evict_gen_mask];
        spin_lock(&evict_gen->lock);
        for (prio = 0; prio < evict_nprio; prio++)
            list_append_list(&evict_gen->pages[prio], 
                &tmp_evict_gens[gen_id].pages[prio]);
        evict_gen->npages += tmp_evict_gens[gen_id].npages;
        spin_unlock(&evict_gen->lock);
        tmp_evict_gens[gen_id].npages = 0;
    }

#if defined(DEBUG) || defined(SAFEMODE)
    /* check that we didn't leak any pages */
    bitmap_for_each_cleared(tmplist_used, evict_ngens, gen_id) {
        for (prio = 0; prio < evict_nprio; prio++)
            assert(list_empty(&tmp_evict_gens[gen_id].pages[prio]));
        assert(tmp_evict_gens[gen_id].npages == 0);
    }
#endif

    /* couldn't find anything evictible this time around */
    if (npages == 0)
        return 0;

    /* found some candidates, lock them for eviction. Keep pages we can't lock
     * aside to add them back to the evict lists - we reuse tmp_evict_gens[0] 
     * as the temporary holding buffer */
    assert(tmp_evict_gens[0].npages == 0);
    list_for_each_safe(evict_list, page, next, link)
    {
        flags = set_page_flags(page->mr, page->addr,
            PFLAG_WORK_ONGOING, &oldflags);
        if (unlikely(!!(oldflags & PFLAG_WORK_ONGOING))) {
            /* page was locked by someone (presumbly for write-protect fault 
             * handling), add it the locked list so we can put it back */
            list_del_from(evict_list, &page->link);
            assert(page->evict_prio >= 0 && page->evict_prio < evict_nprio);
            list_add_tail(&tmp_evict_gens[0].pages[page->evict_prio], &page->link);
            tmp_evict_gens[0].npages++;
            page->evict_prio = 0;   /* reset prio */
            npages--;
        }
        else {
            /* page is evictable (i.e., present and not hot) */
            assert(!!(flags & PFLAG_PRESENT));
            assert(!!(flags & PFLAG_REGISTERED));
            assert(!(flags & PFLAG_EVICT_ONGOING));
            assert(is_in_memory_region_unsafe(page->mr, page->addr));
            assertz(get_page_thread(page->mr, page->addr));
        }
    }

    /* put back the locked pages into lru lists; adding them to the farthest 
     * lru list is fine as these pages are currently being worked on and 
     * they deserve to be on the latest list anyway */
    if (tmp_evict_gens[0].npages > 0) {
        gen_id = (evict_gen_now + evict_ngens - 1) & evict_gen_mask;
        evict_gen = &evict_gens[gen_id];
        spin_lock(&evict_gen->lock);
        for (prio = 0; prio < evict_nprio; prio++) {
            list_append_list(&evict_gen->pages[prio], 
                &tmp_evict_gens[0].pages[prio]);
            assert(list_empty(&tmp_evict_gens[0].pages[prio]));
        }
        evict_gen->npages += tmp_evict_gens[0].npages;
        spin_unlock(&evict_gen->lock);
        tmp_evict_gens[0].npages = 0;
    }

    return npages;
}

/* remove pages from virtual memory using madvise */
static inline int remove_pages(struct list_head* pglist, int npages,
    bool wrprotected) 
{
    int r, i;
    ssize_t ret;
    struct rmpage_node *page;
    bool vectored_madv = false;

#ifdef REGISTER_MADVISE_REMOVE
    /* we don't support receiving madvise notifications for page 
     * deletions (which will lead to deadlocks as the notifications 
     * will need to be handled before we move on from here - something we 
     * cannot do if we expect to support a single handler core. I don't 
     * see a reason why we should use them if pages are being locked, as we do,
     * and only release them when the job is done */
    BUILD_ASSERT(0);
#endif
#ifdef VECTORED_MADVISE
    /* process_madvise supported. This always flushes the TLB so we may only 
     * want to use it on very big batches. Although, UFFD_WRITEPROTECT currently
     * flushes TLB on every op so if we write-protected pages before getting 
     * here, we don't have to think twice about flushing again */
    vectored_madv = wrprotected || npages >= EVICTION_TLB_FLUSH_MIN;
#endif

    i = 0;
    log_debug("removing %d pages (vectored: %d)", npages, vectored_madv);
    list_for_each(pglist, page, link)
    {
        if (vectored_madv) {
            /* prepare the io vector */
            log_debug("adding page %p to iovec", (void*) page->addr);
            madv_iov[i].iov_base = (void*) page->addr;
            madv_iov[i].iov_len = CHUNK_SIZE;
        }
        else {
            /* or issue madvise once per page */
            log_debug("madvise dont_need on page %p", (void*) page->addr);
            r = madvise((void*)page->addr, CHUNK_SIZE, MADV_DONTNEED);
            if (r != 0) {
                log_err("madvise for chunk %d failed: %s", i, strerror(errno));
                BUG();
            }
        }
        i++;
    }
    assert(i == npages);

    if (vectored_madv) {
        /* issue one madvise for all pages */
        assert(madv_pidfd >= 0);
        ret = syscall(440, madv_pidfd, madv_iov, npages, MADV_DONTNEED, 0);
        if(ret != npages * CHUNK_SIZE) {
            log_err("process_madvise returned %ld expected %d, errno %d", 
                ret, npages * CHUNK_SIZE, errno);
            BUG();
        }
    }

    RSTAT(EVICT_MADV) += npages;
    return 0;
}

/* checks if a page needs write-back */
static inline bool needs_write_back(pgflags_t flags) 
{
    /* page must be present at this point */
    assert(!!(flags & PFLAG_PRESENT));
    /* if the page was unmapped, no need to write-back */
    if (!(flags & PFLAG_REGISTERED))
        return false;
#ifdef TRACK_DIRTY
    /* DIRTY bit is only valid when dirty tracking is enabled */
    return !!(flags & PFLAG_DIRTY);
#endif
    return true;
}

/* write-back a region to the backend */
static unsigned int write_region_to_backend(int chan_id, struct region_t *mr, 
    unsigned long addr, size_t size, struct bkend_completion_cbs* cbs) 
{
    int r;
    int ncompletions, nwrites_done;
    uint64_t start_tsc, duration;
    log_debug("writing back contiguous region at [%lx, %lu)", addr, size);

    /* post the write-back */
    start_tsc = 0;
    ncompletions = 0;
    nwrites_done = -1;
    do {
        r = rmbackend->post_write(chan_id, mr, addr, size);
        if (r == EAGAIN) {
            /* start the timer the first time we are here */
            if (!start_tsc)
                start_tsc = rdtsc();

            /* write queue is full, nothing to do but repeat and keep 
             * checking for completions to free request slots; raising error
             * if we handled some write completions but still cannot post */
            assert(nwrites_done != 0);
            ncompletions += rmbackend->check_for_completions(chan_id, cbs, 
                RMEM_MAX_COMP_PER_OP, NULL, &nwrites_done);
        }
    } while(r == EAGAIN);
    assertz(r);

    /* save wait time if any */
    if (start_tsc) {
        duration = rdtscp(NULL) - start_tsc;
        RSTAT(BACKEND_WAIT_CYCLES) += duration;
    }

    return 0;
}

/* flush pages (with write-back if necessary). 
 * Returns whether any of the pages were written to backend and should be 
 * monitored for completions */
static bool flush_pages(int chan_id, struct list_head* pglist, int npages,
    pgflags_t* pflags, bitmap_ptr write_map, struct bkend_completion_cbs* cbs)
{
    int i, r, niov;
    int nretries;
    struct rmpage_node *page;
    bool vectored_mprotect = false;
    size_t wpbytes;

#ifdef VECTORED_MPROTECT
    /* process_mprotect supported. mprotect operations flush the TLB always 
     * so batching multiple mprotects is always a strict win */
    vectored_mprotect = (npages > 1);
#endif

    log_debug("flushing %d pages", npages);

    /* write back pages that are dirty */
    i = 0;
    niov = 0;
    bitmap_init(write_map, npages, false);
    list_for_each(pglist, page, link)
    {
        /* check dirty */
        if (!needs_write_back(pflags[i])) {
            i++;
            continue;
        }

        /* prepare the io vector */
        mprotect_mr[niov] = page->mr;
        mprotect_iov[niov].iov_base = (void*) page->addr;
        mprotect_iov[niov].iov_len = CHUNK_SIZE;
        niov++;
        assert(niov <= EVICTION_MAX_BATCH_SIZE);

        bitmap_set(write_map, i);
        i++;
    }
    assert(i == npages);

    /* protect and write-back dirty pages */
    if (niov > 0)
    {
        if (vectored_mprotect) {
            /* if batch mprotect is available, use it to mprotect all at once */
            nretries = 0;
            r = uffd_wp_add_vec(userfault_fd, mprotect_iov, niov, 
                false, true, &nretries, &wpbytes);
            assertz(r);
            assert(wpbytes == niov * CHUNK_SIZE);
            RSTAT(EVICT_WP_RETRIES) += nretries;
        }
       
        /* for each page */
        for (i = 0; i < niov; i++) {
            if (!vectored_mprotect && uffd_is_wp_supported(userfault_fd)) {
                /* batch mprotect is not available, mprotect individually */
                nretries = 0;
                r = uffd_wp_add(userfault_fd, 
                    (unsigned long) mprotect_iov[i].iov_base, 
                    mprotect_iov[i].iov_len, false, true, &nretries);
                assertz(r);
                RSTAT(EVICT_WP_RETRIES) += nretries;
            }

            /* write-back. TODO: there is an optimization here we can do 
             * using backend scatter-gather op to write all at once */
            write_region_to_backend(chan_id, mprotect_mr[i], 
                (unsigned long) mprotect_iov[i].iov_base, 
                mprotect_iov[i].iov_len, cbs);
            RSTAT(EVICT_WBACK)++;
        }
    }

    /* remove pages from UFFD */
    r = remove_pages(pglist, npages, niov > 0);
    assertz(r);
    return npages;
}

/**
 * Eviction done for a page
 */
static inline void evict_page_done(struct region_t* mr, unsigned long pgaddr, 
    bool discarded, bool stolen)
{
    pgflags_t clrbits, oldflags;
    pgthread_t owner_kthr = 0;

    /* assert locked */
    assert(!!(get_page_flags(mr, pgaddr) & PFLAG_WORK_ONGOING));

    /* bits to clear */
    clrbits = 0;
    clrbits |= PFLAG_EVICT_ONGOING;
    clrbits |= PFLAG_PRESENT;
    clrbits |= PFLAG_DIRTY;
    clrbits |= PFLAG_ACCESSED;
    clrbits |= PFLAG_PRESENT_ZERO_PAGED;

    if (discarded) {
        /* for pages that were discarded and not written-back, we can just 
         * clear most bits, including the lock, and let them go */
        log_debug("evict done, unlocking page %lx", pgaddr);
        clear_page_flags_and_thread(mr, pgaddr, 
            clrbits | PFLAG_WORK_ONGOING, &oldflags, &owner_kthr);
        assert(!!(oldflags & PFLAG_PRESENT));
        goto evict_done;
    }
    else {
        /* For pages that were written-back, the story is more complicated. 
         * We can set them non-present at this point but cannot release 
         * those that are waiting for writes to complete. Because we don't 
         * want another fault to go on reading from remote memory while the
         * dirtied changes are waiting in the write queue. At the same time,
         * we cannot release after write completion because that might happen
         * before the madvise (due to completion stealing). So we try
         * and determine who went later than the other using the 
         * PFLAG_EVICT_ONGOING flag and clear the lock then */
        clear_page_flags(mr, pgaddr, clrbits, &oldflags);
        if (!!(oldflags & PFLAG_EVICT_ONGOING)) {
            /* first to get here, do not release */
            assert(!!(oldflags & PFLAG_PRESENT));
            log_debug("evict one step done for page %lx", pgaddr);
            return;
        }
        else {
            /* last one to get here, clear the lock as well */
            log_debug("evict done, unlocking page %lx", pgaddr);
            clear_page_flags_and_thread(mr, pgaddr, PFLAG_WORK_ONGOING, 
                &oldflags, &owner_kthr);
            goto evict_done;
        }
    }

evict_done:
    /* check that the page was locked and that the saved kthread thread id
     * (if this fault was originally from a kthread) is same or different 
     * the from current kthread id depending on if the fault was stolen */
    assert(!!(oldflags & PFLAG_WORK_ONGOING));
    if (owner_kthr) {
        assert(stolen || owner_kthr == current_kthread_id);
        assert(!stolen || owner_kthr != current_kthread_id);
    }
    RSTAT(EVICT_PAGES_DONE)++;
    put_mr(mr);
}

/**
 * backend write has completed - release the page
 */
static inline int write_back_completed(struct region_t* mr, unsigned long addr,
    size_t size, bool stolen)
{
    unsigned long page;
    size_t covered;
    assert(addr % CHUNK_SIZE == 0 && size % CHUNK_SIZE == 0);
    
    covered = 0;
    while(covered < size) {
        page = addr + covered;
        evict_page_done(mr, page, false, stolen);
        covered += CHUNK_SIZE;
    }
    return 0;
}

/**
 * Called after backend write has completed
 */
int owner_write_back_completed(struct region_t* mr, unsigned long addr, 
    size_t size)
{
    return write_back_completed(mr, addr, size, false);
}

/**
 * Called after backend write has completed but on a stolen completion
 */
int stealer_write_back_completed(struct region_t* mr, unsigned long addr,
    size_t size)
{
    return write_back_completed(mr, addr, size, true);
}

/**
 * Main function for eviction. Returns number of pages evicted.
 */
int do_eviction(int chan_id, struct bkend_completion_cbs* cbs,
    int batch_size)
{
    size_t size;
    pgflags_t oldflags;
    pgidx_t pgidx;
    pgthread_t oldthread;
    int npages, i, flushed;
    pgflags_t flags[batch_size];
    DEFINE_BITMAP(write_map, batch_size);
    unsigned long long pressure;
    struct rmpage_node *page;
    struct list_head evict_list;
    bool discarded;
    struct region_t* mr;
    unsigned long addr;

    /* record eviction calls */
    RSTAT(EVICTS)++;

    /* get eviction candidates */
    npages = 0;
    list_head_init(&evict_list);
    assert(batch_size > 0 && batch_size <= EVICTION_MAX_BATCH_SIZE);
    do {
        /* TODO: error out if we are stuck here */
        npages = find_candidate_pages(&evict_list, batch_size);
        if (npages)
            break;
        RSTAT(EVICT_NONE)++;
    } while(!npages);

    /* found page(s) */
    assert(list_empty(&evict_list) || (npages > 0));

    /* flag them as evicting */
    assert(npages <= EVICTION_MAX_BATCH_SIZE);
    i = 0;
    list_for_each(&evict_list, page, link) {
        flags[i] = set_page_flags_and_thread(page->mr, page->addr, 
            PFLAG_EVICT_ONGOING, current_kthread_id, &oldflags, &oldthread);
        assert(!(oldflags & PFLAG_EVICT_ONGOING));
        assertz(oldthread);
        log_debug("evicting page %lx from mr start %lx", 
            page->addr, page->mr->addr);
        i++;
    }
    assert(i == npages);

    /* once we get a lock, we're gonna evict them no matter what. decrease the 
     * memory used now so others don't overwork for the same memory that we 
     * are about to release */
    size = npages * CHUNK_SIZE;
    pressure = atomic64_sub_and_fetch(&memory_used, size);
    log_debug("Freed %d page(s), new pressure %lld", npages, pressure);

    /* flush pages */
    flushed = flush_pages(chan_id, &evict_list, npages, flags, write_map, cbs);
    assert(npages == flushed);

    /* release page nodes and clear flags */
    if (flushed > 0)
    {
        /* work for each removed page */
        i = 0;
        list_for_each(&evict_list, page, link)
        {
            /* clear the page index and release the page node */
            mr = page->mr;
            addr = page->addr;
            pgidx = clear_page_index(page->mr, page->addr);
            assert(pgidx == rmpage_get_node_id(page));
            rmpage_node_free(page); /* don't use page after this point */
            log_debug("cleared index bits and page node for %lx", page->addr);

            /* eviction done */
            discarded = !bitmap_test(write_map, i);
            evict_page_done(mr, addr, discarded, false);
            i++;
        }
        assert(i == flushed);
        RSTAT(EVICT_DONE)++;
        log_debug("evict done for %d pages", flushed);
    }

#ifdef SAFEMODE
    /* see if eviction was going as expected*/
    verify_eviction();
#endif
    return flushed;
}

/**
 * Init functions
 */

/**
 * eviction_init - initializes eviction global state
 */
int eviction_init(void)
{
    int i, j;
    unsigned long interval_tsc;
    char* policy;

    /* get eviction policy */
    policy = NULL;
#if defined(SC_EVICTION)
    policy = "second-chance";
    if (evict_ngens != 2)
        log_warn("second-chance eviction policy only supports two gens;"
            " ignoring %d", evict_ngens);
    evict_ngens = 2;
#elif defined(LRU_EVICTION)
    policy = "lru";
    if (evict_ngens == 1)
        log_warn("lru eviction policy useless with one gen");
#else
    policy = "default";
    if (evict_ngens != 1)
        log_warn("default eviction policy only supports one gen;"
            " ignoring %d", evict_ngens);
    evict_ngens = 1;
#endif
    assert(policy);

    /* eviction priority levels */
    log_info("available eviction priority levels: %d", evict_nprio);
    BUG_ON(evict_nprio <= 0 || evict_nprio > EVICTION_MAX_PRIO);

    /* init page lists for all generations and the gen mask */
    BUG_ON(evict_ngens <= 0 || evict_ngens > EVICTION_MAX_GENS);
    BUG_ON(evict_ngens & (evict_ngens - 1));  /* power of 2 */
    evict_gen_mask = evict_ngens - 1;
    for(i = 0; i < evict_ngens; i++) {
        for (j = 0; j < evict_nprio; j++)
            list_head_init(&evict_gens[i].pages[j]);
        evict_gens[i].npages = 0;
        spin_lock_init(&evict_gens[i].lock);
    }
    log_info("inited %s eviction with %d gens. gen mask: %x", 
        policy, evict_ngens, evict_gen_mask);

#ifdef EVICTION_DNE_ON
    /* init do-not-evict list */
    log_info("do-not-evict size per prio: %d MB", RMEM_DNE_SIZE_MB);
    for (j = 0; j < evict_nprio; j++) {
        list_head_init(&dne_pages.pages[j]);
        dne_pages.npages[j] = 0;
        spin_lock_init(&dne_pages.locks[j]);
    }
    BUG_ON(local_memory <= RMEM_DNE_SIZE_MB * evict_nprio * 1024 * 1024);
    if (local_memory <= RMEM_DNE_SIZE_MB * evict_nprio * 1024 * 1024 * 1.1)
        log_warn("WARN! do-not-evict size is too close to max local memory!");
#endif

    /* init epoch */
    epoch_start_tsc = rdtsc();
    interval_tsc = EVICTION_EPOCH_LEN_MUS * cycles_per_us;
    epoch_tsc_shift = 1;
    while(interval_tsc > 0) {
        epoch_tsc_shift++;
        interval_tsc >>= 1;
    }
    log_info("evict epoch: %d mus, closest bit-shift: %d, real epoch: %d mus",
        EVICTION_EPOCH_LEN_MUS, epoch_tsc_shift, 
        (1 << epoch_tsc_shift) / cycles_per_us);

    /* pid fd required for process madvise */
#ifdef VECTORED_MADVISE
    log_info("eviction using vectored madvise");
    madv_pidfd = syscall(SYS_pidfd_open, getpid(), 0);
    assert(madv_pidfd >= 0);
#endif

#ifdef EPOCH_SAMPLER
    /* init epoch sampler */
    sampler_init(&epoch_sampler, "epoch_distance_samples", /* header= */ NULL,
        SAMPLER_TYPE_POISSON, &epoch_sampler_ops, sizeof(unsigned long),
        1000, 1000, 1, false);
#endif

#ifdef LRU_EVICTION
    /* init LRU epoch distance estimator */
    mov_p2estimator_init(&epoch_p2estimator, LRU_EVICTION_BUMP_THR, 10000);
    log_info("inited LRU epoch distance with thr: %lf", LRU_EVICTION_BUMP_THR);
#endif

    /* check if write-protect is supported */
    if (!uffd_is_wp_supported(userfault_fd))
        log_warn("!!WARNING!! uffd write-protect not supported on this machine,"
            " eviction may corrupt the data. Proceed at your own risk!");

    /* set initial eviction state */
    evict_gen_now = 0;
    evict_prio_now = evict_nprio - 1;
    evict_prio_quota_left = get_evict_prio_quota(evict_prio_now);

    return 0;
}

/**
 * eviction_thread_init - initializes per-thread eviction state
 */
int eviction_init_thread(void)
{
    int i, j;

    for(i = 0; i < evict_ngens; i++) {
        for (j = 0; j < evict_nprio; j++)
            list_head_init(&tmp_evict_gens[i].pages[j]);
        tmp_evict_gens[i].npages = 0;
        spin_lock_init(&tmp_evict_gens[i].lock);
    }

    return 0;
}

/**
 * eviction_exit - frees eviction global state
 */
void eviction_exit(void)
{
#ifdef EPOCH_SAMPLER
    /* free epoch sampler */
    sampler_destroy(&epoch_sampler);
#endif
}

/**
 * Epoch sampling functions
 */

void epoch_add_sample(void* buffer, void* sample)
{
    assert(buffer && sample);
    *(long*)buffer = *(long*)sample;
}

void epoch_sample_to_str(void* sample, char* sbuf, int max_len)
{
    int n;
    assert(sbuf && sample);
    n = snprintf(sbuf, max_len, "%ld", *(long*)sample);
    BUG_ON(n >= max_len);   /* truncated */
}

/* epoch sampler ops */
struct sampler_ops epoch_sampler_ops = {
    .add_sample = epoch_add_sample,
    .sample_to_str = epoch_sample_to_str,
};
