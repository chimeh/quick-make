/* Hash routine.
* Copyright (C) 1998 Kunihiro Ishiguro
*
* This file is part of GNU Zebra.
*
* GNU Zebra is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published
* by the Free Software Foundation; either version 2, or (at your
* option) any later version.
*
* GNU Zebra is distributed in the hope that it will be useful, but
* WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with GNU Zebra; see the file COPYING.  If not, write to the
* Free Software Foundation, Inc., 59 Temple Place - Suite 330,
* Boston, MA 02111-1307, USA.
*/

/* 
	$Log: hash.c,v $
	Revision 1.4  2006/06/27 08:10:22  fky
	fix bug1724
	
	Revision 1.3  2005/05/16 08:43:03  fky
	nRose3 commit
	
	Revision 1.1  2004/12/29 07:26:56  chenshiwei
	Move from bgpd/bgp_lib
	
	Revision 1.3  2004/09/27 07:09:39  fky
	New BGP First commit
	
*/
#include "hsl_os.h"
#include "hsl_types.h"
#include "hsl_oss.h"
#include "hsl_hash.h"

/* Allocate a new hash.  */
struct hash* hash_create_size(unsigned int size, unsigned int (*hash_key) (),
	int (*hash_cmp) ())
{
	struct hash* hash;

	hash = XMALLOC(MTYPE_HASH, sizeof(struct hash));
	if (NULL == hash)
		return NULL;
	hash->index = XMALLOC(MTYPE_HASH_INDEX,
					sizeof(struct hash_backet *) * size);
	if (NULL == hash->index)
	{
		XFREE(MTYPE_HASH, hash);
		return NULL;
	}
	memset(hash->index, 0, sizeof(struct hash_backet *) * size);
	hash->size = size;
	hash->hash_key = hash_key;
	hash->hash_cmp = hash_cmp;
	hash->count = 0;

	return hash;
}

/* Allocate a new hash with default hash size.  */
struct hash* hash_create(unsigned int (*hash_key) (), int (*hash_cmp) ())
{
	return hash_create_size(HASHTABSIZE, hash_key, hash_cmp);
}

/* Utility function for hash_get().  When this function is specified
   as alloc_func, return arugment as it is.  This function is used for
   intern already allocated value.  */
void* hash_alloc_intern(void* arg)
{
	return arg;
}

/* Lookup and return hash backet in hash.  If there is no
   corresponding hash backet and alloc_func is specified, create new
   hash backet.  */
void* hash_get(struct hash* hash, void* data, void * (*alloc_func) ())
{
	unsigned int key;
	unsigned int index;
	void* newdata;
	struct hash_backet* backet;

	key = (*hash->hash_key) (data);
	index = key % hash->size;

	for (backet = hash->index[index]; backet != NULL; backet = backet->next)
		if (backet->key == key && (*hash->hash_cmp) (backet->data, data))
			return backet->data;

	if (alloc_func)
	{
		newdata = (*alloc_func) (data);
		if (newdata == NULL)
			return NULL;

		backet = XMALLOC(MTYPE_HASH_BACKET, sizeof(struct hash_backet));
		if (NULL == backet)
			return NULL;
		backet->data = newdata;
		backet->key = key;
		backet->next = hash->index[index];
		hash->index[index] = backet;
		hash->count++;
		return backet->data;
	}
	return NULL;
}

/* Hash lookup.  */
void* hash_lookup(struct hash* hash, void* data)
{
	return hash_get(hash, data, NULL);
}

/* This function release registered value from specified hash.  When
   release is successfully finished, return the data pointer in the
   hash backet.  */
void* hash_release(struct hash* hash, void* data)
{
	void* ret;
	unsigned int key;
	unsigned int index;
	struct hash_backet* backet;
	struct hash_backet* pp;

	key = (*hash->hash_key) (data);
	index = key % hash->size;

	for (backet = pp = hash->index[index]; backet; backet = backet->next)
	{
		if (backet->key == key && (*hash->hash_cmp) (backet->data, data))
		{
			if (backet == pp)
				hash->index[index] = backet->next;
			else
				pp->next = backet->next;

			ret = backet->data;
			XFREE(MTYPE_HASH_BACKET, backet);
			hash->count--;
			return ret;
		}
		pp = backet;
	}
	return NULL;
}

/* Iterator function for hash.  */
void hash_iterate(struct hash* hash,
	void (*func) (struct hash_backet *, void*), void* arg)
{
	int i;
	struct hash_backet* hb;

	for (i = 0; i < hash->size; i++)
		for (hb = hash->index[i]; hb; hb = hb->next)
			(*func) (hb, arg);
}

/* Clean up hash.  */
void hash_clean(struct hash* hash, void (*free_func) (void*))
{
	int i;
	struct hash_backet* hb;
	struct hash_backet* next;

	for (i = 0; i < hash->size; i++)
	{
		for (hb = hash->index[i]; hb; hb = next)
		{
			next = hb->next;

			if (free_func)
				(*free_func) (hb->data);

			XFREE(MTYPE_HASH_BACKET, hb);
			hash->count--;
		}
		hash->index[i] = NULL;
	}
}

/* Free hash memory.  You may call hash_clean before call this
   function.  */
void hash_free(struct hash* hash)
{
	XFREE(MTYPE_HASH_INDEX, hash->index);
	XFREE(MTYPE_HASH, hash);
}

/*
 * condition iterator
 * iterate over the hash, do action over element if the element meet the condition
 * @hash, the hash table
 * @cond, int (*cond)(void *element, void* cond_arg), condition checker, if meet return nonzero, else return 0;
 * @cond_arg, the arg to cond
 * @action, void (*action)(void *element, void* action_arg), do action if meet cond and action !=NULL
 * @action_arg, the arg to cond
 * author: huangjimin
 */

void hash_iterate_cond(struct hash* hash,
                int (*cond)(void*, void*),
                void *cond_arg,
                void (*action) (void*, void*),
                void *action_arg) 
{
    unsigned int i;
    struct hash_backet* hb;
    //struct hash_backet* next;
    for (i = 0; i < hash->size; i++)
    {
        for (hb = hash->index[i]; hb; hb = hb->next)
        {
            if (cond && (*cond)(hb->data, cond_arg)) {
                if (action) {
                    (*action)(hb->data, action_arg);
                }
            }
        }
    }
}


/*
 * condition cleanup, free bucket and data in bucket from hash if bucket's data meet condition.
 * iterate over the hash, free bucket and data if the data meet the condition
 * @hash, the hash table
 * @data_cond, int (*data_cond)(void *element, void* data_cond_arg), condition checker, if meet return nonzero, else return 0.NULL treat no meet
 * @cond_arg, the arg to cond
 * @free_func, assert(NONULL), void (*free_func) (void*), the free method of data in bucket.
 * author: huangjimin
 */

void hash_clean_cond(struct hash* hash, int (*data_cond)(void*, void*), void* data_cond_arg, void (*free_func) (void*))
{
    unsigned int i;
    struct hash_backet* *p;
    struct hash_backet* hb;
    struct hash_backet* next;
    //assert free_func;
    for (i = 0; i < hash->size; i++)
    {
        if (hash->index[i] == NULL) {
            ;
        } else {
            p = &hash->index[i];
            hb = hash->index[i];
            for (; hb; hb = next) {
                if(data_cond && (*data_cond)(hb->data, data_cond_arg)) {
                    *p = hb->next;
                    if (free_func) {
                        hb->next = NULL;
                        (*free_func) (hb->data);
                    }
                    XFREE(MTYPE_HASH_BACKET, hb);
                    hash->count--;
                }
                p = &hb->next;
                next = hb->next;
            }
        }
    }
}

