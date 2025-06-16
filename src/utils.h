#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <string.h>
#include <rte_log.h>
#include <rte_malloc.h>

#define MALLOC(sz) (xmalloc(sz))
#define FREE(p) (xfree(p))
#define REALLOC(p, sz) (xrealloc((p), (sz)))
#define FREE_PTR(p) if((p)) FREE((p))

static inline void* xmalloc(uint32_t sz)
{
    void *mem = rte_zmalloc("cfgfile", sz, RTE_CACHE_LINE_SIZE);
    if (mem)
        memset(mem, 0, sz);

    return mem;
}

static inline void* xrealloc(void *p, uint32_t sz)
{
    return rte_realloc(p, sz, RTE_CACHE_LINE_SIZE);
}

static inline void xfree(void *p)
{
    rte_free(p);
    p = NULL;
}

#endif