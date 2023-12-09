/*
 * rdma_common.h - RDMA common for client and servers
 */

#ifndef __RDMA_COMMON_H__
#define __RDMA_COMMON_H__

#include <infiniband/verbs.h>
#include <netdb.h>
#include <rdma/rdma_cma.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

enum __rw_mode_t {
    M_WRITE,
    M_READ,
};

typedef enum __rw_mode_t rw_mode_t;
enum { DISCONNECTED, CONNECTED };

/**
 * Control message
 */
struct message {
    enum {
        MSG_SERVER_ADD,
        MSG_SERVER_REM,
        MSG_SLAB_ADD,
        MSG_SLAB_REM,

        MSG_DONE,
        MSG_SLAB_ADD_PARTIAL,
        MSG_DONE_SLAB_ADD,

        NUM_MSG_TYPE
    } type;

    struct {
        struct ibv_mr mr;
        void *addr;
        size_t size;
        char ip[200];
        int port;
        int id;
        unsigned int rdmakey;
        int nslabs;
    } data;
};

#endif    // __RDMA_COMMON_H__
