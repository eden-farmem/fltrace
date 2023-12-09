/*
 * uffd.c - uffd helper methods
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "rmem/uffd.h"
#include "rmem/config.h"
#include "rmem/dump.h"
#include "base/log.h"
#include "base/assert.h"

/**
 * Check uffd features required for certain configurations at compile time
 */

/* UFFD feature for dirty-page tracking */
#ifdef TRACK_DIRTY
#if !defined(UFFD_FEATURE_PAGEFAULT_FLAG_WP) || !defined(UFFDIO_WRITEPROTECT)
#error "UFFD WP features not available to support write-protection on read"
#endif
#endif

/* UFFD features for batched write-protect */
#ifdef VECTORED_MPROTECT
#ifndef UFFDIO_WRITEPROTECT
#error "UFFDIO_WRITEPROTECT not available for vectored mprotect"
#endif
#ifndef UFFDIO_WRITEPROTECTV
#error "UFFDIO_WRITEPROTECTV not available to support vectored mprotect"
#endif
#endif

/* UFFD Thread Id is required for fault sampling */
#ifdef FAULT_SAMPLER
#ifndef UFFD_FEATURE_THREAD_ID
#error "Fault sampling not supported without uffd thread id feature"
#endif
#endif

/* state */
static int saved_fd = -1;
static uint64_t saved_ioctls;

/**
 * UFFD wrappers
 */

static inline int uffd_not_supported_error()
{
    log_err("uffd feature not supported");
    BUG();
}

int uffd_init(void)
{
    int r, fd;
    unsigned long features;
    unsigned long ioctl_mask;

    /* create fd */
    fd = syscall(SYS_userfaultfd, O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        log_err("userfaultfd failed");
        return -1;
    }

    /* enabling required features */
    features = 0;
#ifdef TRACK_DIRTY
    features |= UFFD_FEATURE_PAGEFAULT_FLAG_WP;
#endif
#ifdef UFFD_FEATURE_THREAD_ID
    features |= UFFD_FEATURE_THREAD_ID;
#endif

    struct uffdio_api api = {
        .api = UFFD_API,
        .features = features
    };
    r = ioctl(fd, UFFDIO_API, &api);
    if (r < 0) {
        log_err("ioctl(fd, UFFDIO_API, ...) failed");
        return -1;
    }

    /* check required ioctls supported */
    ioctl_mask = (1ull << _UFFDIO_REGISTER) | (1ull << _UFFDIO_UNREGISTER);
    if ((api.ioctls & ioctl_mask) != ioctl_mask) {
        log_err("uffd unsupported features. features: %llx ioctls %llx",
            api.features, api.ioctls);
        return -1;
    }

    /* save uffd info */
    saved_fd = fd;
    saved_ioctls = api.ioctls;

    return fd;
}

int uffd_register(int fd, unsigned long addr, size_t size, int writeable)
{
    int r, mode;
    uint64_t ioctls_mask;

    mode = UFFDIO_REGISTER_MODE_MISSING;
#ifdef TRACK_DIRTY
    if (writeable)
        mode |= UFFDIO_REGISTER_MODE_WP;
#endif

    struct uffdio_register reg = {
        .mode = mode, 
        .range = {.start = addr, .len = size}
    };

    r = ioctl(fd, UFFDIO_REGISTER, &reg);
    if (r < 0) {
        log_err("UFFDIO_REGISTER failed: size %ld addr %lx", size, addr);
        goto out;
    }

    ioctls_mask = (1ull << _UFFDIO_COPY);
#ifdef TRACK_DIRTY
    if (writeable)
        ioctls_mask |= (1ull << _UFFDIO_WRITEPROTECT);
#endif
    if ((reg.ioctls & ioctls_mask) != ioctls_mask) {
        log_err("unexpected UFFD register ioctls %llx, expected %lx",
            reg.ioctls, ioctls_mask);
        r = -1;
        goto out;
    }
    log_debug("UFFDIO_REGISTER succeeded: size %ld addr %lx", size, addr);

out:
    return r;
}

int uffd_unregister(int fd, unsigned long addr, size_t size)
{
    int r;
    struct uffdio_range range = {.start = addr, .len = size};
    r = ioctl(fd, UFFDIO_UNREGISTER, &range);
    if (r < 0) log_err("ioctl(fd, UFFDIO_UNREGISTER, ...) failed");
    return r;
}

int uffd_copy(int fd, unsigned long dst, unsigned long src, size_t size, 
    bool wrprotect, bool no_wake, bool retry, int *n_retries) 
{
    int r;
    int mode;

    assert(n_retries);
    *n_retries = 0;

    mode = 0;
#ifdef UFFDIO_COPY_MODE_WP
    if (wrprotect)  
        mode |= UFFDIO_COPY_MODE_WP;
#endif
    if (no_wake)    
        mode |= UFFDIO_COPY_MODE_DONTWAKE;
    struct uffdio_copy copy = {
        .dst = dst, 
        .src = src, 
        .len = size, 
        .mode = mode
    };

    do {
        log_debug("uffd_copy from src %lx, size %lu to dst %lx wpmode %d "
            "nowake %d", src, size, dst, wrprotect, no_wake);
        errno = 0;

        /* TODO: Use UFFD_USE_PWRITE (see kona)? */
        r = ioctl(fd, UFFDIO_COPY, &copy);
        if (r < 0) {
            log_debug("uffd_copy copied %lld bytes, addr=%lx, errno=%d", 
                copy.copy, dst, errno);

            if (errno == ENOSPC) {
                // The child process has exited.
                // We should drop this request.
                r = 0;
                break;

            } else if (errno == EEXIST) {
                /* something wrong with our page locking */
                log_err("uffd_copy err EEXIST on %lx", dst);
                BUG();
            } else if (errno == EAGAIN) {
                /* layout change in progress; try again */
                if (retry == false) {
                    /* do not retry, let the caller handle it */
                    r = EAGAIN;
                    break;
                }
                (*n_retries)++;
            } else {
                log_info("uffd_copy errno=%d: unhandled error", errno);
                BUG();
            }
        }
    } while (r && errno == EAGAIN);
    return r;
}

/* check if write-protection is supported on the current kernel */
bool uffd_is_wp_supported(int fd)
{
#ifdef UFFDIO_WRITEPROTECT
    return true;
#else
    return false;
#endif
}

#ifdef UFFDIO_WRITEPROTECT
int uffd_wp(int fd, unsigned long addr, size_t size, bool wrprotect, 
    bool no_wake, bool retry, int *n_retries) 
{
    int r;
    int mode = 0;

    assert(n_retries);
    *n_retries = 0;

    if (wrprotect)  
        mode |= UFFDIO_WRITEPROTECT_MODE_WP;
    if (no_wake)    
        mode |= UFFDIO_WRITEPROTECT_MODE_DONTWAKE;
    struct uffdio_writeprotect wp = {
        .mode = mode,
        .range = {.start = addr, .len = size}
    };

    do {
        log_debug("uffd_wp start %p size %lx mode %d nowake %d", 
            (void *)addr, size, wrprotect, no_wake);
        errno = 0;
        r = ioctl(fd, UFFDIO_WRITEPROTECT, &wp);
        if (r < 0) {
            log_debug("uffd_wp errno=%d", errno);
            if (errno == EEXIST || errno == ENOSPC) {
                /* This page is already write-protected OR the child process 
                    has exited. We should drop this request. */
                r = 0;
                break;
            } else if (errno == EAGAIN) {
                /* layout change in progress; try again */
                if (retry == false) {
                    /* do not retry, let the caller handle it */
                    r = EAGAIN;
                    break;
                }
                (*n_retries)++;
            } else {
                log_info("uffd_wp errno=%d: unhandled error", errno);
                BUG();
            }
        }
    } while (r && errno == EAGAIN);
    return r;
}
#else
int uffd_wp(int fd, unsigned long addr, size_t size, bool wrprotect, 
    bool no_wake, bool retry, int *n_retries)
{
    return uffd_not_supported_error();
}
#endif


int uffd_wp_add(int fd, unsigned long fault_addr, size_t size, bool nowake, 
    bool retry, int *n_retries) 
{
    return uffd_wp(fd, fault_addr, size, true, nowake, retry, n_retries);
}

/* NOTE: make sure that page exists before issuing this */
int uffd_wp_remove(int fd, unsigned long fault_addr, size_t size, bool nowake, 
    bool retry, int *n_retries) 
{
    return uffd_wp(fd, fault_addr, size, false, nowake, retry, n_retries);
}

#ifdef VECTORED_MPROTECT
int uffd_wp_vec(int fd, struct iovec* iov, int iov_len, bool wrprotect, 
    bool no_wake, bool retry, int *n_retries, size_t* wp_bytes) 
{
    int r;
    int mode = 0;

    assert(n_retries);
    *n_retries = 0;

    if (wrprotect)  
        mode |= UFFDIO_WRITEPROTECT_MODE_WP;
    if (no_wake)    
        mode |= UFFDIO_WRITEPROTECT_MODE_DONTWAKE;
    struct uffdio_writeprotectv wpv = {
        .mode = mode,
        .iovec = iov,
        .vlen = iov_len,
    };

    do {
        log_debug("uffd_wp_vec %d items mode %d nowake %d", 
            iov_len, wrprotect, no_wake);
        errno = 0;
        r = ioctl(fd, UFFDIO_WRITEPROTECTV, &wpv);
        log_debug("uffd_wp_vec returned %d handled=%llu bytes errno=%d", 
          r, wpv.writeprotected, errno);
        if (r < 0) {
            if (errno == EEXIST || errno == ENOSPC) {
                /* This page is already write-protected OR the child process 
                    has exited. We should drop this request. */
                r = 0;
                break;
            } else if (errno == EAGAIN) {
                /* layout change in progress; try again */
                if (retry == false) {
                    /* do not retry, let the caller handle it */
                    r = EAGAIN;
                    break;
                }
                (*n_retries)++;
            } else {
                log_err("uffd_wp errno=%d: unhandled error", errno);
                BUG();
            }
        }
    } while (r && errno == EAGAIN);

    /* currently we get the bytes in the return value which is a bug that 
     * we're fixing here */
    if (r > 0) {
      *wp_bytes = r;
      r = 0;
    }
    return r;
}
#else
int uffd_wp_vec(int fd, struct iovec* iov, int iov_len, bool wrprotect, 
    bool no_wake, bool retry, int *n_retries, size_t* wp_bytes)
{
    return uffd_not_supported_error();
}
#endif

int uffd_wp_add_vec(int fd, struct iovec* iov, int iov_len, bool no_wake, 
    bool retry, int *n_retries, size_t* wp_bytes)
{
    return uffd_wp_vec(fd, iov, iov_len, true, no_wake, retry, n_retries, 
        wp_bytes);
}

int uffd_wp_remove_vec(int fd, struct iovec* iov, int iov_len, bool no_wake, 
    bool retry, int *n_retries, size_t* wp_bytes)
{
    return uffd_wp_vec(fd, iov, iov_len, false, no_wake, retry, n_retries, 
        wp_bytes);
}

int uffd_zero(int fd, unsigned long addr, size_t size, bool no_wake, 
    bool retry, int *n_retries) 
{
    int r;
    int mode = 0;

    assert(n_retries);
    *n_retries = 0;

    if (no_wake)    
        mode |= UFFDIO_ZEROPAGE_MODE_DONTWAKE;
    struct uffdio_zeropage zero = {
        .mode = mode,
        .range = {.start = addr, .len = size}
    };

    do {
        log_debug("uffd_zero to addr %lx size=%lu nowake=%d", addr, size, no_wake);
        errno = 0;
        r = ioctl(fd, UFFDIO_ZEROPAGE, &zero);
        if (r < 0) {
            log_debug("uffd_zero copied %lld bytes, errno=%d", 
                zero.zeropage, errno);

            if (errno == ENOSPC) {
                // The child process has exited.
                // We should drop this request.
                r = 0;
                break;

            } else if (errno == EAGAIN || errno == EEXIST) {
                // layout change in progress; try again
                errno = EAGAIN;
                if (retry == false) {
                    /* do not retry, let the caller handle it */
                    r = EAGAIN;
                    break;
                }
                (*n_retries)++;
            } else {
                log_info("uffd_zero errno=%d: unhandled error", errno);
                BUG();
            }
        }
    } while (r && errno == EAGAIN);
    return r;
}

int uffd_wake(int fd, unsigned long addr, size_t size)
{
    // This will wake all threads waiting on this range:
    // From https://lore.kernel.org/lkml/5661B62B.2020409@gmail.com/T/
    //
    // userfaults won't wait in "pending" state to be read anymore and any
    // UFFDIO_WAKE or similar operations that has the objective of waking
    // userfaults after their resolution, will wake all blocked userfaults
    // for the resolved range, including those that haven't been read() by
    // userland yet.

    struct uffdio_range range = {.start = addr, .len = size};
    int r;
    r = ioctl(fd, UFFDIO_WAKE, &range);
    if (r < 0) log_err("UFFDIO_WAKE");
    return r;
}
