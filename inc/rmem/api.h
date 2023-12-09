/*
 * api.h - remote memory custom allocation API
 */

#ifndef __RMEM_API_H__
#define __RMEM_API_H__

#include <stddef.h>
#include "base/types.h"

/*** Supported ***/
void *rmalloc(size_t size);
void *rmrealloc(void *ptr, size_t size, size_t old_size);
int rmunmap(void *addr, size_t length);
int rmadvise(void *addr, size_t length, int advice);

/*** Unsupported ***/
int rmfree(void *ptr);
int rmpin(void *addr, size_t size);
int rmflush(void *addr, size_t size, bool evict);


#endif  // __RMEM_API_H__