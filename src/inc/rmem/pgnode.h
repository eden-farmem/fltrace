/*
 * pgnode.h - Page node support (for locally present pages)
 * These nodes are juggled around LRU lists until the pages get kicked out to 
 * remote memory, after which they are reused for other pages
 */

#ifndef __RMEM_PAGE_NODE_H__
#define __RMEM_PAGE_NODE_H__

#include "base/list.h"
#include "base/tcache.h"
#include "rmem/eviction.h"
#include "rmem/page.h"
#include "rmem/region.h"

/**
 * Page node definition
 */
struct rmpage_node {
    struct region_t *mr;
    unsigned long addr;
    struct list_node link;
    uint8_t evict_prio;

    /* time epoch when page was last accessed. this is set by hints and consumed 
     * by the eviction routines to make smarter eviction choices. we treat it 
     * merely as a performance hint that can be inaccurate to avoid the overhead
     * of locking the page node or ensuring the node is valid. that means, in 
     * rare cases, this field can be set when the page node does not exist for 
     * a page or is associated with a different page. */
    unsigned long epoch;
};
typedef struct rmpage_node rmpage_node_t;
BUILD_ASSERT(EVICTION_MAX_PRIO <= UINT8_MAX);   /* due to evict_prio */

/* Page node pool (tcache) support */
DECLARE_PERTHREAD(struct tcache_perthread, rmpage_node_pt);
extern rmpage_node_t* rmpage_nodes;
extern size_t rmpage_node_count;

/* pgnode tcache API */
int rmpage_node_tcache_init(void);
void rmpage_node_tcache_init_thread(void);
bool rmpage_is_node_valid(rmpage_node_t* pgnode);
int rmpage_node_tcache_destroy(void);

/* rmpage_node_alloc - allocates a page node from pool */
static inline rmpage_node_t* rmpage_node_alloc(void)
{
    rmpage_node_t* pgnode;
    pgnode = (rmpage_node_t*) tcache_alloc(&perthread_get(rmpage_node_pt));
    if (unlikely(!pgnode)) {
        log_err("out of page nodes!");
        BUG();
    }
    memset(pgnode, 0, sizeof(rmpage_node_t));
    return pgnode;
}

/* rmpage_node_free - frees a page node */
static inline void rmpage_node_free(rmpage_node_t* node)
{
    assert(rmpage_is_node_valid(node));
    tcache_free(&perthread_get(rmpage_node_pt), node);
}

/* rmpage_get_node_id - gets a shortened index to a page node that can be saved 
 * in page metadata and used to retrieve the node later */
static inline pgidx_t rmpage_get_node_id(rmpage_node_t* node)
{
    assert(rmpage_is_node_valid(node));
    return (pgidx_t)(node - rmpage_nodes);
}

static inline rmpage_node_t* rmpage_get_node_by_id(pgidx_t id)
{
    assert(id >= 0 && id < rmpage_node_count);
    return &rmpage_nodes[id];
}

/**
 * To-be-freed page nodes support - for properly releasing page nodes from
 * threads that do not have the tcache support, and hence cannot use
 * rmpage_node_free(). An example is the page nodes released by
 * munmap() on the application threads (when using standalone remote
 * memory). We collect these page nodes in a global list (protected by a 
 * lock) and release them regularly in the handler threads - this is 
 * naturally inefficient than freeing into thread-local tcaches but 
 * hopefully will only be used in non-critical paths.
 */
void rmpage_node_tbf_init();
void rmpage_node_tbf_add(rmpage_node_t* node);
void rmpage_node_tbf_try_release();

#endif    // __RMEM_PAGE_NODE_H_