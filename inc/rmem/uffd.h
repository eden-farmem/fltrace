/*
 * uffd.h - uffd helper methods
 */

#ifndef __UFFD_H__
#define __UFFD_H__

#include <sys/uio.h>

/**
 * Control Ops 
 */
int userfaultfd(int flags);
int uffd_init(void);
int uffd_register(int fd, unsigned long addr, size_t size, int writeable);
int uffd_unregister(int fd, unsigned long addr, size_t size);

/**
 * Page mapping ops
 */
int uffd_copy(int fd, unsigned long dst, unsigned long src, size_t size, 
    bool wrprotect, bool no_wake, bool retry, int *n_retries);
int uffd_zero(int fd, unsigned long addr, size_t size, bool no_wake, 
    bool retry, int *n_retries);

/**
 * Change Write Protection
 */
bool uffd_is_wp_supported(int fd);
int uffd_wp(int fd, unsigned long addr, size_t size, bool wrprotect, 
    bool no_wake, bool retry, int *n_retries);
int uffd_wp_add(int fd, unsigned long fault_addr, size_t size, bool no_wake, 
    bool retry, int *n_retries);
int uffd_wp_remove(int fd, unsigned long fault_addr, size_t size, bool no_wake, 
    bool retry, int *n_retries);

/**
 * Change Write Protection Vectored ops
 */
int uffd_wp_vec(int fd, struct iovec* iov, int iov_len, bool wrprorect,
    bool no_wake, bool retry, int *n_retries, size_t* wp_bytes);
int uffd_wp_add_vec(int fd, struct iovec* iov, int iov_len, bool no_wake, 
    bool retry, int *n_retries, size_t* wp_bytes);
int uffd_wp_remove_vec(int fd, struct iovec* iov, int iov_len, bool no_wake, 
    bool retry, int *n_retries, size_t* wp_bytes);

/**
 * Explicit wake-up notification
 */
int uffd_wake(int fd, unsigned long addr, size_t size);

/* uffd state */
extern int userfault_fd;

#endif  // __UFFD_H__