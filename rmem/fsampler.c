/*
 * fsampler.c - fault sampling support for the handler threads
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <execinfo.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "base/map.h"
#include "base/sampler.h"
#include "base/thread.h"
#include "rmem/common.h"
#include "rmem/config.h"
#include "rmem/handler.h"

#define FAULT_TRACE_BUF_SIZE    (FAULT_TRACE_STEPS*15)
#define MAX_FAULT_SAMPLE_LEN    1000
#define FSAMPLER_MAX_BUFS       10000

/* defs */
struct fsample {
    volatile int busy;                  /* sample buf slot is being used */
    volatile int trace_in_progress;     /* backtrace in progress */
    int fsid;
    unsigned long tstamp_tsc;
    unsigned long ip;
    unsigned long addr;
    int flags;
    int tid;
    void* bktrace[FAULT_TRACE_STEPS];
    int trace_size;
    int npages;
} __aligned(CACHE_LINE_SIZE);

struct fsampler {
    struct sampler base;
    /* TODO: allocate the below bufs dynamically */
    struct fsample fsample_bufs[FSAMPLER_MAX_BUFS];
    struct hashmap thread_buf_map;
    int nbufs_used;
};

/* sampler global state */
struct fsampler fsamplers[MAX_FAULT_SAMPLERS];
atomic_t nsamplers;
int sigid;
unsigned long sampler_start_tsc;
unsigned long sampler_start_unix_time;
int fsamples_per_sec = -1;

/**
 * Ops for base sampler support
 */
void fault_add_sample(void* buffer, void* sample)
{
    /* note: the shallow copy */
    assert(buffer && sample);
    memcpy(buffer, sample, sizeof(struct fsample));
}

void fault_sample_to_str(void* sample, char* sbuf, int max_len)
{
    int n, i;
    struct fsample* fs;
    char trace[FAULT_TRACE_BUF_SIZE] = {'\0'};

    assert(sbuf && sample);
    fs = (struct fsample*) sample;

    /* convert the backtrace to text */
    for(i = 0; i < fs->trace_size && 
        strlen(trace) < (FAULT_TRACE_BUF_SIZE-1); i++)
            snprintf(&trace[strlen(trace)], 
                (FAULT_TRACE_BUF_SIZE - 1 - strlen(trace)),
                "%p|", fs->bktrace[i]);

    /* write to string buf */
    n = snprintf(sbuf, max_len, "%lf,%lx,%lx,%d,%d,%d,%s", 
            sampler_start_unix_time + 
            (fs->tstamp_tsc - sampler_start_tsc) / (1000000.0 * cycles_per_us),
            fs->ip, fs->addr, fs->npages, fs->flags, fs->tid, trace);
    BUG_ON(n >= max_len);   /* truncated */
}

/* base sampler ops */
struct sampler_ops fault_sampler_ops = {
    .add_sample = fault_add_sample,
    .sample_to_str = fault_sample_to_str,
};

/**
 * Record the fault sample with a backtrace of the faulting thread
 * @fsid: the id of the sampler to use for recording
 * @addr: the faulting address
 * @flags: the flags associated with the fault (see FSAMPLER_FAULT_FLAG_*)
 * @tid: the faulting thread id
 */
void fsampler_add_fault_sample(int fsid, unsigned long addr, int flags, pid_t tid)
{
    int ret, bufid;
    struct sampler* sampler;
    struct fsample* sample;
    unsigned long now_tsc;
    siginfo_t sginfo;
    bool found;

    log_debug("sampler %d got fault %lx for thr %d", fsid, addr, tid);
    assert(fsid >= 0 && fsid < MAX_FAULT_SAMPLERS);
    sampler = &fsamplers[fsid].base;

    /* ignore if it is not time yet */
    now_tsc = rdtsc();
    if (!sampler_is_time(sampler, now_tsc)) {
        log_debug("not time for the next sample yet, ignore");
        return;
    }

    /* see if the current thread already has a buffer */
    bufid = map_get(&fsamplers[fsid].thread_buf_map, tid);
    found = bufid >= 0;
    if (!found) {
        /* no buffer for this thread, get a new one */
        BUG_ON(fsamplers[fsid].nbufs_used >= FSAMPLER_MAX_BUFS);
        bufid = fsamplers[fsid].nbufs_used++;
        map_put(&fsamplers[fsid].thread_buf_map, tid, bufid);
    }
    assert(bufid >= 0 && bufid < fsamplers[fsid].nbufs_used);

    /* retrieve the buffer */
    sample = &fsamplers[fsid].fsample_bufs[bufid];
    assert(!found || sample->tid == tid);

    /* if a sample in progress, wait for finish and record it */
    if (sample->busy) {
        if (load_acquire(&sample->trace_in_progress)) {
            /* another fault came from the same thread before it handled 
             * the signal sent for the previous fault: there is only one 
             * known scenario for this right now, which is that the kernel is
             * sending back-to-back faults on an address range without ever
             * unblocking the thread; counting all these faults towards the 
             * original fault as the app remains faulted at the same location 
             * during all of these repeat faults */
            if (addr == sample->addr + sample->npages * PAGE_SIZE) {
                log_debug("repeat range fault at fsid %d tid %d", fsid, tid);
                sample->npages++;
                return;
            }

            /* not sure what this case is, warn and ignore */
            log_debug("unknown repeat fault at fsid %d tid %d", fsid, tid);
            log_warn_ratelimited("WARN: fsample missed during sig handling");
            return;
        }

        /* record it */
        sampler_add_provide_tsc(sampler, sample, sample->tstamp_tsc);
        sample->busy = 0;
    }

    /* prepare for next sample */
    assert(!sample->busy);
    sample->fsid = fsid;
    sample->tstamp_tsc = now_tsc;
    sample->flags = flags;
    sample->addr = addr;
    sample->tid = tid;
    sample->trace_size = 0;
    sample->busy = 1;
    sample->npages = 1;
    store_release(&sample->trace_in_progress, 1);

    /* send a signal to the thread to get the new backtrace */
    log_debug("sampler %d sending sig %d to tid %d using buf %d at time %lu",
        fsid, sigid, tid, bufid, now_tsc);
    assert(tid);
    sginfo.si_signo = sigid;
    sginfo.si_code = SI_QUEUE;
    sginfo.si_value.sival_ptr = sample;
    ret = syscall(SYS_rt_tgsigqueueinfo, getpid(), tid, sigid, &sginfo);
    if (ret)
        log_warn("failed to send signal to tid: %d, errno: %d", tid, errno);
    assertz(ret);
}

/**
 * Dump any recorded samples of a sampler
 * @fsid: the sampler id
 */
void fsampler_dump(int fsid)
{
    assert(fsid >= 0 && fsid < MAX_FAULT_SAMPLERS);
    sampler_dump(&fsamplers[fsid].base, MAX_FAULT_SAMPLE_LEN);
}

/* signal handler for saving stacktrace */
void save_stacktrace(int signum, siginfo_t *siginfo, void *context)
{
    int fsid;
    bool from_runtime;
    struct fsample* sample;

    /* this handler is only triggered on the application threads during 
     * a page fault but faults can happen both in application or runtime 
     * code (e.g., in interposed malloc). Make sure that we are in 
     * runtime during this fn to avoid remote memory interpostion but 
     * keep track of the original state and revert to it when exiting */
    from_runtime = IN_RUNTIME();
    RUNTIME_ENTER();

    /* retrieve and check sample to write to */
    sample = (struct fsample*) siginfo->si_value.sival_ptr;
    fsid = sample->fsid;
    assert(fsid >= 0 && fsid < MAX_FAULT_SAMPLERS);
    assert(sample->busy);
    assert(sample->trace_in_progress);
    assert(sample->tid == thread_gettid());
    log_debug("thr %d received sig %d from sampler %d at addr %lx, time %lu",
        thread_gettid(), signum, fsid, sample->addr, sample->tstamp_tsc);

    /* backtrace */
    sample->trace_size = backtrace(sample->bktrace, FAULT_TRACE_STEPS);

    /* set done */
    store_release(&sample->trace_in_progress, 0);
    log_debug("thr %d backtrace done for sampler %d", thread_gettid(), fsid);

    /* exit runtime if necessary */
    if (!from_runtime)
        RUNTIME_EXIT();
}

/**
 * Returns the next available sampler (id)
 */
int fsampler_get_sampler()
{
    int fsid;
    char fsname[100];

    /* atomically g et a sampler id */
    do {
        fsid = atomic_read(&nsamplers);
        BUG_ON(fsid > MAX_FAULT_SAMPLERS);
        if (fsid == MAX_FAULT_SAMPLERS) {
            log_warn("out of fault samplers!");
            return -1;
        }
    } while(!atomic_cmpxchg(&nsamplers, fsid, fsid + 1));
    log_debug("sampler %d taken, num samplers: %d",
        fsid, atomic_read(&nsamplers));

    /* initialize base sampler */
    sprintf(fsname, "fault-samples-%d-%d.out", getpid(), 1 + fsid);
    sampler_init(&fsamplers[fsid].base, fsname,
        /* header= */ "tstamp,ip,addr,pages,flags,tid,trace",
        fsamples_per_sec > 0 ? SAMPLER_TYPE_POISSON : SAMPLER_TYPE_NONE,
        &fault_sampler_ops, sizeof(struct fsample), 
        /* queue size = */ 1000, /* sampling rate = */ fsamples_per_sec,
        /* dumps per sec = */ 1, /* dump on full = */ true);

    /* init hashmap */
    map_init(&fsamplers[fsid].thread_buf_map, FSAMPLER_MAX_BUFS);
    fsamplers[fsid].nbufs_used = 0;
    log_info("initialized fault sampler %d", 1 + fsid);
    return fsid;
}

/**
 * sampler_init - initializes samplers for handler threads
 */
int fsampler_init(int samples_per_sec)
{
    int i, ret;
    struct sigaction act, oldact;

    /* save sampling rate; <= 0 means record everything */
    fsamples_per_sec = samples_per_sec;

    /* find a signal that hasn't been registered */
    for (i = SIGRTMIN; i < SIGRTMAX; i++) {
        ret = sigaction(i, NULL, &oldact);
        BUG_ON(ret);
        if (oldact.sa_sigaction == NULL && oldact.sa_handler == NULL)
            break;
    }
    if (i == SIGRTMAX) {
        log_err("no free signal for fault sampler");
        return 1;
    }

    /* register a signal handler that saves stack-trace of the 
     * handling thread */
    sigid = i;
    act.sa_sigaction = save_stacktrace;
    act.sa_flags = SA_SIGINFO;
    sigemptyset(&act.sa_mask);
    ret = sigaction(sigid, &act, NULL);
    assertz(ret);
    log_info("registered signal %d for fault sampler", sigid);

    /* start timestamp */
    sampler_start_tsc = rdtsc();
    sampler_start_unix_time = time(NULL);
    return 0;
}


/**
 * fsampler_destroy - destroys samplers
 */
int fsampler_destroy(void)
{
    int i;
    for (i = 0; i < MAX_FAULT_SAMPLERS; i++) {
        sampler_destroy(&fsamplers[i].base);
        map_destroy(&fsamplers[i].thread_buf_map);
    }
    return 0;
}