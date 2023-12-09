/*
 * rdma.h - RDMA helper for remote memory (client-side)
 */

#ifndef __RDMA_H__
#define __RDMA_H__

#include <infiniband/verbs.h>
#include <netdb.h>
#include <rdma/rdma_cma.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include "rmem/config.h"
#include "rmem/rdma_common.h"
#include "rmem/region.h"

/* forward declarations */
struct server_conn_t;
struct request;

/**
 * Common context
 */
struct context {
    struct ibv_context *ctx;
    struct ibv_pd *pd;
    struct ibv_mr *bkend_buf_pool_mr;
    struct ibv_cq *cq_recv;
    struct ibv_cq *cq_send;
    struct ibv_comp_channel *cc;
    struct ibv_cq *dp_cq[RMEM_MAX_CHANNELS];
    struct ibv_comp_channel *dp_cc[RMEM_MAX_CHANNELS];
};

/**
 * State for a single connection
 */
struct connection {
    /* metadata */
    struct server_conn_t* server;
    uint8_t datapath;
    uint8_t dp_chan_id;
    uint8_t use_global_cq;
    uint8_t one_send_recv_cq;

    /* status */
    volatile int connected;
    
    /* rdma connection state */
    struct rdma_cm_id *id;
    struct rdma_event_channel *chan;
    struct ibv_qp *qp;

    /* completion queue state */
    struct ibv_cq *cq_recv;
    struct ibv_cq *cq_send;
    struct ibv_comp_channel *cc;

    /* memory buf for send/recv */
    struct ibv_mr *recv_mr;
    struct ibv_mr *send_mr;
    struct message *recv_msg;
    struct message *send_msg;

    /* requests for read/write (only for datapath qps) */
    struct request *read_reqs;
    struct request *write_reqs;
    volatile int read_req_idx;
    volatile int write_req_idx;

    /* placeholder for region association during region add/remove 
     * vestige of bad design from kona. TODO: fix it */
    struct region_t* reg;
} __aligned(CACHE_LINE_SIZE);
BUILD_ASSERT(RMEM_MAX_CHANNELS < UINT8_MAX);    /* due to dp_chan_id */

/**
 * A server connection that is also currently tied to a single
 * region. TODO: we should decouple them later.
 */
struct server_conn_t {
    char ip[36];
    int port;
    int id;
    int status;
    uint64_t rdmakey;
    uint64_t size;

    int num_dp;
    struct connection cp;   /* control path */
    struct connection dp[RMEM_MAX_CHANNELS];   /* data path */

    struct region_t* reg;   /* backref to region */
    SLIST_ENTRY(server_conn_t) link;
};

/* RDMA request */
struct request {
    volatile int busy;
    int index;
    struct connection *conn;
    struct fault* fault;
    unsigned long orig_local_addr;
    unsigned long local_addr;
    unsigned long remote_addr;
    unsigned int lkey;
    unsigned int rkey;
    unsigned long size;
    rw_mode_t mode;
};
typedef struct request request_t;

void build_params(struct rdma_conn_param *params);
void destroy_connection(struct connection *conn);
void post_receives(struct connection *conn);
void send_message(struct connection *conn);
void do_rdma_op(request_t *req, bool signal_completion);
void do_rdma_op_linked(request_t *reqs, unsigned n_reqs, bool signal_completion);

#endif    // __RDMA_H__
