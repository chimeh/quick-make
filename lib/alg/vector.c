/* Copyright (C) 2001-2011 IP Infusion, Inc. All Rights Reserved. */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/semaphore.h>
#include <linux/ctype.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/types.h>
#include "alg_config.h"
#include "memory.h"
#include "vector.h"

/* Initialize vector : allocate memory and return vector. */
vector
vector_init (u_int32_t size)
{
  vector v = XMALLOC (MTYPE_VECTOR, sizeof (struct _vector));
  if (v == NULL)
    return NULL;

  /* allocate at least 64 slot */
  if (size < 64)
    size = 64;
  
  v->index = XMALLOC (MTYPE_VECTOR_INDEX, sizeof (void *) * size);
  if (v->index == NULL)
    {
      XFREE (MTYPE_VECTOR, v);
      return NULL;
    }

  v->alloced = size;
  v->max = 0;
  v->count = 0;

  memset (v->index, 0, sizeof (void *) * size);
  return v;
}

void
vector_only_wrapper_free (vector v)
{
  XFREE (MTYPE_VECTOR, v);
}

void
vector_free (vector v)
{
  XFREE (MTYPE_VECTOR_INDEX, v->index);
  XFREE (MTYPE_VECTOR, v);
}

vector
vector_copy (vector v)
{
  u_int32_t size;
  vector new = XMALLOC (MTYPE_VECTOR, sizeof (struct _vector));

  if (new == NULL)
    return NULL;

  size = sizeof (void *) * (v->alloced);
  new->index = XMALLOC (MTYPE_VECTOR_INDEX, size);
  if (new->index == NULL)
    {
      XFREE (MTYPE_VECTOR, new);
      return NULL;
    }

  new->max = v->max;
  new->alloced = v->alloced;
  new->count = v->count;
  memcpy (new->index, v->index, size);

  return new;
}

/* Check assigned index, and if it runs short double index pointer */
int
vector_ensure (vector v, u_int32_t num)
{  
  if (v->alloced > num)
    return TRUE;
  
  num <<= 1;    
  v->index = XREALLOC (MTYPE_VECTOR_INDEX, v->index,
                       sizeof (void*) * num);
  if (v->index == NULL)
    {
      v->alloced = 0;
      v->max = 0;
      v->count = 0;
      return FALSE;
    }

  memset (&v->index[v->alloced], 0, sizeof (void *) * (num - v->alloced));
  v->alloced = num;

  return TRUE;
}

/* This function only returns next empty slot index.  It dose not mean
   the slot's index memory is assigned, please call vector_ensure()
   after calling this function. */
u_int32_t
vector_empty_slot (vector v)
{
  u_int32_t i;

  if (v->max == 0)
    return 0;

  if (v->index == NULL)
    return VECTOR_MEM_ALLOC_ERROR;

  /* 如果v->count和v->max相同，则表示向量slot偏移小于max的都已使用 */
  if (v->count == v->max)
    return v->max;

  for (i = 0; i < v->max; i++)
    if (v->index[i] == 0)
      return i;

  return i;
}

/* Set value to the smallest empty slot. */
u_int32_t
vector_set (vector v, void *val)
{
  u_int32_t i;

  if (val == NULL)
    return VECTOR_INVALID_VALUE;

  i = vector_empty_slot (v);
  if (i == VECTOR_MEM_ALLOC_ERROR)
    return i;

  if (! vector_ensure (v, i))
    return VECTOR_MEM_ALLOC_ERROR;

  v->index[i] = val;
  v->count++;

  if (v->max <= i)
    v->max = i + 1;

  return i;
}

/* Set value to specified index slot. */
u_int32_t
vector_set_index (vector v, u_int32_t i, void *val)
{
  if (val == NULL)
    return VECTOR_INVALID_VALUE;

  if (! vector_ensure (v, i))
    return VECTOR_MEM_ALLOC_ERROR;

  /* 如果指定的位置未使用才对count加1 */
  if (v->index[i] == NULL)
    v->count++;

  v->index[i] = val;

  if (v->max <= i)
    v->max = i + 1;

  return i;
}

/* Lookup vector, ensure it. */
void *
vector_lookup_index (vector v, u_int32_t i)
{
  if (! vector_ensure (v, i))
    return NULL;

  return v->index[i];
}

/* Unset value at specified index slot. */
void
vector_unset (vector v, u_int32_t i)
{
  if ((i >= v->alloced) || (v->index[i] == NULL))
    return;

  v->count--;
  if (v->count < 0)
    {
      printk("vector used error，v->count is minus。\n");
      ZASSERT(0);
    }
  
  v->index[i] = NULL;

  if (i + 1 == v->max)
    {
      v->max--;
      while (i && v->index[--i] == NULL && v->max--)
        ;
    }
}

/* 将向量恢复未使用状态 */
void vector_reset (vector v)
{
  memset (v->index, 0, sizeof (void *) * v->alloced);
  v->max = 0;
  v->count = 0;
}

/* Add vector src items to vector dest.  */
void
vector_add (vector dest, vector src)
{
  int i;
  void *val;

  for (i = 0; i < vector_max (src); i++)
    if ((val = vector_slot (src, i)))
        if (vector_set (dest, val) == VECTOR_MEM_ALLOC_ERROR)
          return;
}

/* Reset dest before vector add.  */
void
vector_dup (vector dest, vector src)
{
  vector_reset (dest);
  vector_add (dest, src);
}

u_int32_t
vector_cmp(vector v1, vector v2)
{
  int i;

  if ((v1->count != v2->count) || (v1->max != v2->max))
    return 1;
  else
    for (i = 0; i < vector_max (v1); i++)
      if (vector_slot (v1, i) != vector_slot (v2, i))
        return 1;

  return 0;
}

int
vector_walk(vector v, VECTOR_WALK_CB user_cb, void *user_ref)
{
  int i;
  void *val;

  if (user_cb)
    for (i = 0; i < vector_max (v); i++)
      if ((val = vector_slot (v, i))!= NULL)
        user_cb(val, user_ref);

  return ZRES_OK;
}

