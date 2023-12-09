/*
 * stat.c - statistics thread for tracing tool
 */

#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>

#include <base/atomic.h>
#include <base/stddef.h>
#include <base/log.h>
#include <base/time.h>
#include <rmem/common.h>

#define STAT_INTERVAL_SECS  1
#define MAX_STAT_STR_LEN    2048

static inline int append_stat(char *pos, size_t len, 
    const char *name, uint64_t val)
{
    return snprintf(pos, len, "%s:%ld,", name, val);
}

/* get value of the process virt mem counter from /proc/self/status file */
unsigned long long get_process_vm_counter(const char* name)
{
    const int line_size = 512;
    char line[line_size];
    unsigned long long value;
    FILE *file;
    bool found;
    
    file = fopen("/proc/self/status", "r");
    if (!file)
        return 0;

    found = false;
    while (fgets(line, line_size, file) != NULL) {
        int i = strlen(line);
        assert(i > 6);
        if (strncmp(line, name, strlen(name)) == 0) {
            /* assumes that a digit will be found and the line ends in " Kb" */
            const char *p = line;
            while (*p < '0' || *p > '9') p++;
            line[i - 3] = '\0';
            value = atoi(p);
            found = true;
            break;
        }
    }
    fclose(file);
    BUG_ON(!found);

    value *= 1024;  /* to bytes */
    return value;
}

/* save latest process memory map information to a local file */
void save_process_maps()
{
    char ch, fname[25];
    FILE *source, *target;

    /* we could use system("cp") to copy the file but it creates a new 
     * process and causes issues with inherited LD_PRELOAD */
    sprintf(fname, "procmaps-%d", getpid());
    source = fopen("/proc/self/maps", "r");
    target = fopen(fname, "w");
    while ((ch = fgetc(source)) != EOF)
        fputc(ch, target);
    fclose(source);
    fclose(target);
}

/* gather all rmem stats and write to the buffer */
static inline int rstat_write_buf(char *buf, size_t len)
{
    uint64_t rstats[RSTAT_NR];
    char *pos, *end;
    int i, j, ret;

    memset(rstats, 0, sizeof(rstats));

    /* gather also from each rmem handler thread */
    assert(nhandlers > 0);
    for (i = 0; i < nhandlers; i++) {
        assert(handlers[i]);
        /* ensure 64bit-alignment as gcc O3 is going to vectorize these loops 
         * and non-alignment results in segfaults (see gcc -ftree-vectorize) */
        assert(((unsigned long) handlers[i]->rstats & 7) == 0);
        for (j = 0; j < RSTAT_NR; j++) {
            rstats[j] += handlers[i]->rstats[j];
        }
    }

#define APPEND_STAT(name,val)   \
    ret = append_stat(pos, end - pos, name, val); \
    if (ret < 0) { \
        return -EINVAL; \
    } else if (ret >= end - pos) { \
        return -E2BIG; \
    } \
    pos += ret;

    /* write out all thr stats to the buffer */
    pos = buf;
    end = buf + len;
    for (j = 0; j < RSTAT_NR; j++) {
        APPEND_STAT(rstat_names[j], rstats[j]);
    }

    /* report local memory usage stats */
    APPEND_STAT("memory_used", atomic64_read(&max_memory_used));
    APPEND_STAT("memory_allocd", atomic64_read(&memory_allocd));
    APPEND_STAT("memory_freed", atomic64_read(&memory_freed));

    /* report process vm stats from the status file */
    APPEND_STAT("vm_peak", get_process_vm_counter("VmPeak"));
    APPEND_STAT("vm_size", get_process_vm_counter("VmSize"));
    APPEND_STAT("vm_lock", get_process_vm_counter("VmLck"));
    APPEND_STAT("vm_pin", get_process_vm_counter("VmPin"));
    APPEND_STAT("vm_hwm", get_process_vm_counter("VmHWM"));
    APPEND_STAT("vm_rss", get_process_vm_counter("VmRSS"));
    APPEND_STAT("vm_data", get_process_vm_counter("VmData"));
    APPEND_STAT("vm_stk", get_process_vm_counter("VmStk"));
    APPEND_STAT("vm_exe", get_process_vm_counter("VmExe"));
    APPEND_STAT("vm_lib", get_process_vm_counter("VmLib"));
    APPEND_STAT("vm_pte", get_process_vm_counter("VmPTE"));
    APPEND_STAT("vm_swap", get_process_vm_counter("VmSwap"));

    pos[-1] = '\0'; /* clip off last ',' */
    return 0;
}

static void* stats_worker(void *arg)
{
    /* stats thread always part of runtime */
    RUNTIME_ENTER();

    char buf[MAX_STAT_STR_LEN];
    char fname[100];
    unsigned long now;
    FILE* fp;
    int ret;
    
    sprintf(fname, "fault-stats-%d.out", getpid());
    fp = fopen(fname, "w");
    assert(fp);

    while (true)
    {
        sleep(STAT_INTERVAL_SECS);
        now = time(NULL);

        /* print remote memory stats */
        ret = rstat_write_buf(buf, MAX_STAT_STR_LEN);
        if (ret < 0) {
            log_err("rstat err %d: couldn't generate stat buffer", ret);
            continue;
        }
        fprintf(fp, "%lu %s\n", now, buf);
        fflush(fp);

        /* save latest process maps */
        save_process_maps();
    }

    fclose(fp);
    RUNTIME_EXIT();
    return NULL;
}

/**
 * start_stats_thread - starts the stats thread
 */
int start_stats_thread(int pincore_id)
{
    pthread_t stats_thread;
    int ret;

    /* start stats thread */
    ret = pthread_create(&stats_thread, NULL, stats_worker, NULL);
    assertz(ret);

    /* pin thread */
    if (pincore_id >= 0) {
        ret = cpu_pin_thread(stats_thread, pincore_id);
        assertz(ret);
    }

    return 0;
}
