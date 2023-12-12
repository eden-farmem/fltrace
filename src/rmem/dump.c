/*
 * dump.c - remote memory state dump
 * 
 * dumps remote memory state into a file and exits the program (becauses it 
 * makes irreversible changes to the state).
 * Only use it in deadlock/buggy situations where you need the program to 
 * dump a snapshot of remote memory state and exit; this can be done by
 * setting the "dump_rmem_state_and_exit" global variable (in the buggy code 
 * path or through GDB). While dumping the state is best done in the stats
 * thread which is least likely to be affected by bugs than the handler threads,
 * only handler threads have the required thread local state 
 * (rmem_init_thread()) that is needed to walk the remote memory structures 
 * like the completion queues for all threads. 
 */

#include "rmem/dump.h"
#include "rmem/page.h"

/* state */
bool dump_rmem_state_and_exit = false;
const char* dumpfile = "rmem-dump.out";
FILE* dumpfp = NULL;
static DEFINE_SPINLOCK(dump_lock);

/* write backend read completion to dump file */
int rmem_dump_read_comp(fault_t* f)
{
    assert(dumpfp);
    fprintf(dumpfp, "read completion for %s - page flags: %x, kthread: %d\n", 
        FSTR(f), get_page_flags(f->mr, f->page),
        get_page_thread(f->mr, f->page));
    return 0;
}

/* write backend write completion to dump file */
int rmem_dump_write_comp(struct region_t* mr, unsigned long addr, size_t size)
{
    assert(dumpfp);
    fprintf(dumpfp, "write completion for [%lx,%lu) - page flags: %x, "
        "kthread: %d\n", addr, size, get_page_flags(mr, addr),
        get_page_thread(mr, addr));
    return 0;
}

/* dummy callbacks to dump completion queue contents */
struct bkend_completion_cbs bkend_dump_cbs = {
    .read_completion = rmem_dump_read_comp,
    .write_completion = rmem_dump_write_comp
};

/* collect remote memory state and dump into a file */
void dump_rmem_state()
{
    int i;
    hthread_t* h;
    struct fault* f;

    /* only one handler should attend to this */
    spin_lock(&dump_lock);
    dumpfp = fopen(dumpfile, "w");

    /* dump handlers */
    assert(nhandlers > 0);
    for (i = 0; i < nhandlers; i++) {
        h = handlers[i];
        assert(h);

        fprintf(dumpfp, "hthread %d -\n", i);

        /* dump waiting faults. NOTE: no lock! */
        fprintf(dumpfp, "wait queue - count: %d\n", h->n_wait_q);
        list_for_each(&h->fault_wait_q, f, link)
            fprintf(dumpfp, "found fault %s - page flags: %x, kthread: %d\n", 
                FSTR(f), get_page_flags(f->mr, f->page), 
                get_page_thread(f->mr, f->page));

        /* dump completions */
        fprintf(dumpfp, "completion queue:\n");
        rmbackend->check_for_completions(h->bkend_chan_id, 
            &bkend_dump_cbs, RMEM_MAX_COMP_PER_OP, NULL, NULL);
    }

    /* exit the program */
    fflush(dumpfp);
    fclose(dumpfp);
    spin_unlock(&dump_lock);
    
    log_warn("dumped remote memory state to %s. exiting!", dumpfile);
    fflush(stdout);
    exit(1);
}