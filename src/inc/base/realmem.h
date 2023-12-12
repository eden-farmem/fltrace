/**
 * realmem.h - pointers to the standard "real" memory allocation functions
 */

#ifndef __REAL_MEM_H__
#define __REAL_MEM_H__

#include <stddef.h>

/* wrappers for libc functions */
void *libc_malloc(size_t size);
void *libc_realloc(void *ptr, size_t size);
void *libc_calloc(size_t nitems, size_t size);
void *libc_memalign(size_t alignment, size_t size);
size_t libc_malloc_usable_size(void* ptr);
void libc_free(void *ptr);
void* libc6_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int libc6_madvise(void *addr, size_t length, int advice);
int libc6_munmap(void *ptr, size_t length);

/* pointers to the wrapper functions */
#define real_malloc     libc_malloc
#define real_realloc    libc_realloc
#define real_calloc     libc_calloc
#define real_memalign   libc_memalign
#define real_malloc_usable_size   libc_malloc_usable_size
#define real_free       libc_free
#define real_mmap       libc6_mmap
#define real_madvise    libc6_madvise
#define real_munmap     libc6_munmap

#endif  // __REAL_MEM_H__