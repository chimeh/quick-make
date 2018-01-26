/****************************************************************************
 * ctc_vti_vec.c :         header
 *
 * Copyright (C) 2010 Centec Networks Inc.  All rights reserved.
 *
 * Modify History :
 * Revision       :         V1.0
 * Date           :         2010-7-28
 * Reason         :         First Create
 ****************************************************************************/

#include "sal/core/libc.h"
#include "sal/core/alloc.h"
#include "ctc_types.h"
#include "ctc_sal.h"
#include "ctc_vti_vec.h"

extern void *sal_realloc(void *ptr, size_t size);
/* Initialize vector : allocate memory and return vector. */
vector
ctc_vti_vec_init(uint32 size)
{
    vector v = sal_alloc(sizeof(struct _vector),"kcli");

    if (!v)
    {
        return NULL;
    }
    sal_memset(v, 0, sizeof(struct _vector));

    /* allocate at least one slot */
    if (size == 0)
    {
        size = 1;
    }

    v->alloced = size;
    v->max = 0;
    v->index = sal_alloc(sizeof(void*) * size, "kcli");
    if (!v->index)
    {
        sal_free(v);
        return NULL;
    }

    sal_memset(v->index, 0, sizeof(void*) * size);
    v->direction = 0;
    v->is_desc = 0;
    v->is_multiple = 0;

    return v;
}

void
ctc_vti_vec_only_wrapper_free(vector v)
{
    sal_free(v);
}

void
ctc_vti_vec_only_index_free(void* index)
{
    sal_free(index);
}

void
ctc_vti_vec_free(vector v)
{
    sal_free(v->index);
    sal_free(v);
}

vector
ctc_vti_vec_copy(vector v)
{
    uint32 size;
    vector new_v = sal_alloc(sizeof(struct _vector), "kcli");

    if (!new_v)
    {
        return NULL;
    }
    sal_memset(new_v, 0, sizeof(struct _vector));

    new_v->max = v->max;
    new_v->alloced = v->alloced;
    new_v->direction = v->direction;
    new_v->is_desc = v->is_desc;
    new_v->is_multiple = v->is_multiple;

    size = sizeof(void*) * (v->alloced);
    new_v->index = (void**)sal_alloc(size, "kcli");
    if (!new_v->index)
    {
        sal_free(new_v);
        return NULL;
    }

    sal_memcpy(new_v->index, v->index, size);

    return new_v;
}

/* Check assigned index, and if it runs short double index pointer */
void
ctc_vti_vec_ensure(vector v, uint32 num)
{
    if (v->alloced > num)
    {
        return;
    }

    v->index = sal_realloc(v->index, sizeof(void*) * (v->alloced * 2));
    sal_memset(&v->index[v->alloced], 0, sizeof(void*) * v->alloced);
    v->alloced *= 2;

    if (v->alloced <= num)
    {
        ctc_vti_vec_ensure(v, num);
    }
}

/* This function only returns next empty slot index.  It dose not mean
   the slot's index memory is assigned, please call ctc_vti_vec_ensure()
   after calling this function. */
int
ctc_vti_vec_empty_slot(vector v)
{
    uint32 i;

    if (v->max == 0)
    {
        return 0;
    }

    for (i = 0; i < v->max; i++)
    {
        if (v->index[i] == 0)
        {
            return i;
        }
    }

    return i;
}

/* Set value to the smallest empty slot. */
int
ctc_vti_vec_set(vector v, void* val)
{
    uint32 i;

    i = ctc_vti_vec_empty_slot(v);
    ctc_vti_vec_ensure(v, i);

    v->index[i] = val;

    if (v->max <= i)
    {
        v->max = i + 1;
    }

    return i;
}

/* Set value to specified index slot. */
int
ctc_vti_vec_set_index(vector v, uint32 i, void* val)
{
    ctc_vti_vec_ensure(v, i);

    v->index[i] = val;

    if (v->max <= i)
    {
        v->max = i + 1;
    }

    return i;
}

/* Look up vector.  */
void*
ctc_vti_vec_lookup(vector v, uint32 i)
{
    if (i >= v->max)
    {
        return NULL;
    }

    return v->index[i];
}

/* Lookup vector, ensure it. */
void*
ctc_vti_vec_lookup_ensure(vector v, uint32 i)
{
    ctc_vti_vec_ensure(v, i);
    return v->index[i];
}

/* Unset value at specified index slot. */
void
ctc_vti_vec_unset(vector v, uint32 i)
{
    if (i >= v->alloced)
    {
        return;
    }

    v->index[i] = NULL;

    if (i + 1 == v->max)
    {
        v->max--;

        while (i && v->index[--i] == NULL && v->max--)
        {
            ;   /* Is this ugly ? */
        }
    }
}

/* Count the number of not emplty slot. */
uint32
ctc_vti_vec_count(vector v)
{
    uint32 i;
    uint32 count = 0;

    for (i = 0; i < v->max; i++)
    {
        if (v->index[i] != NULL)
        {
            count++;
        }
    }

    return count;
}

/* Add ctc_vector src items to ctc_vector dest.  */
void
ctc_vti_vec_add(vector dest, vector src)
{
    int i;
    void* val;

    for (i = 0; i < vector_max(src); i++)
    {
        if ((val = vector_slot(src, i)))
        {
            ctc_vti_vec_set(dest, val);
        }
    }
}

/* Reset dest before vector add.  */
void
ctc_vti_vec_dup(vector dest, vector src)
{
    vector_reset(dest);
    ctc_vti_vec_add(dest, src);
}

