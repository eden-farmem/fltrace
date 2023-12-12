/**
 * realmem.c - pointers to the standard "real" memory allocation functions
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "base/realmem.h"

/* thread-local pointers */
__thread size_t (*__libc_malloc_usable_size)(void * ptr) = NULL;
__thread void *(*__libc6_mmap)(void *, size_t, int, int, int, off_t) = NULL;
__thread int (*__libc6_madvise)(void *, size_t, int) = NULL;
__thread int (*__libc6_munmap)(void *, size_t) = NULL;
__thread void *libc6 = NULL;

/**
 * Lib C Alloc Functions
 */

void *libc_malloc(size_t size)
{
    extern void *__libc_malloc(size_t);
    void *ptr = __libc_malloc(size);
    return ptr;
}

void *libc_realloc(void *ptr, size_t size)
{
    extern void *__libc_realloc(void *, size_t);
    void *newptr = __libc_realloc(ptr, size);
    return newptr;
}

void *libc_calloc(size_t nitems, size_t size)
{
    extern void *__libc_calloc(size_t, size_t);
    void *newptr = __libc_calloc(nitems, size);
    return newptr;
}

void *libc_memalign(size_t alignment, size_t size)
{
    extern void *__libc_memalign(size_t, size_t);
    void *ptr = __libc_memalign(alignment, size);
    return ptr;
}

size_t libc_malloc_usable_size(void * ptr)
{
    char *error;
    if (!__libc_malloc_usable_size) {
        dlerror();
        /* TODO: not sure which of the lines below is correct. I suspect that 
         * RTLD_NEXT will lead to bugs as we lookup once per thread. Also not 
         * not sure if libc6 has the function. Do not have a use-case now to 
         * test so raising BUG() here to test it when we actually hit it. */
        // __libc_malloc_usable_size = dlsym(RTLD_NEXT, "malloc_usable_size");
        // __libc_malloc_usable_size = dlsym(libc6, "malloc_usable_size");
        fprintf(stderr, "fix the TODO!!\n");
        exit(1);
        if ((error = dlerror()) != NULL) {
            fprintf(stderr, "Error in dlopen: %s\n", error);
            exit(1);
        }
    }
    return __libc_malloc_usable_size(ptr);
}

void libc_free(void *ptr)
{
    extern void __libc_free(void *);
    __libc_free(ptr);
}

/**
 * Other Alloc Functions in glibc
 */

static inline void init_libc6(void)
{
    char *error;
    if (!libc6) {
        dlerror();
        libc6 = dlopen("libc.so.6", RTLD_LAZY | RTLD_GLOBAL);
        if ((error = dlerror()) != NULL) {
            fprintf(stderr, "Error in dlopen: %s\n", error);
            exit(1);
        }
    }
}

void* libc6_mmap(void *addr, size_t length, int prot, int flags,
    int fd, off_t offset)
{
    char *error;

    if (!__libc6_mmap) {
        init_libc6();
        dlerror();
        __libc6_mmap = dlsym(libc6, "mmap");
        if ((error = dlerror()) != NULL) {
            fprintf(stderr, "Error in `dlsym`: %s\n", error);
            exit(1);
        }
    }
    return __libc6_mmap(addr, length, prot, flags, fd, offset);
}

int libc6_madvise(void *addr, size_t length, int advice)
{
    char *error;

    if (!__libc6_madvise) {
        init_libc6();
        dlerror();
        __libc6_madvise = dlsym(libc6, "madvise");
        if ((error = dlerror()) != NULL) {
            fprintf(stderr, "Error in `dlsym`: %s\n", error);
            exit(1);
        }
    }
    return __libc6_madvise(addr, length, advice);
}

int libc6_munmap(void *ptr, size_t length)
{
    char *error;

    if (!__libc6_munmap) {
        init_libc6();
        dlerror();
        __libc6_munmap = dlsym(libc6, "munmap");
        if ((error = dlerror()) != NULL) {
            fprintf(stderr, "Error in `dlsym`: %s\n", error);
            exit(1);
        }
    }
    return __libc6_munmap(ptr, length);
}
