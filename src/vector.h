#ifndef __VECTOR_H__
#define __VECTOR_H__
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "utils.h"

struct vector {
    uint32_t allocated;
    void **slot;
};
typedef struct vector* vector_t;

#define VECTOR_SLOT(V, E) ((V)->slot[(E)])
#define VECTOR_SIZE(V) ((V)->allocated)

#define vector_foreach_slot(v, p, i) \
    for (i = 0; i < (v)->allocated && ((p) = (v)->slot[i]; i++))

static inline vector_t vector_alloc(void)
{
    return (vector_t) MALLOC(sizeof(struct vector));
}

static inline void vector_alloc_slot(vector_t v)
{
    assert(v);

    v->allocated += 1;
    if (v->slot)
        v->slot = REALLOC(v->slot, sizeof(void *) * v->allocated);
    else
        v->slot = MALLOC(sizeof(void *) * v->allocated);
}

static inline void vector_set_slot(vector_t v, void *value)
{
    assert(v);

    v->slot[v->allocated - 1] = value;
}

static inline void vector_insert_slot(vector_t v, uint32_t slot, void *value)
{
    assert(v && value);
    uint32_t i;

    for (i = v->allocated - 2; i >= slot; i--)
        v->slot[i + 1] = v->slot[i];

    v->slot[slot] = value;
}

static inline void vector_free(vector_t v)
{
    assert(v);

    FREE(v->slot);
    FREE(v);
}

static inline void vector_str_free(vector_t v)
{
    assert(v);
    uint32_t i;
    char *str;

    for (i = 0; i < VECTOR_SIZE(v); i++)
        if ((str = VECTOR_SLOT(v, i)) != NULL)
            FREE(str);

    vector_free(v);
}
#endif