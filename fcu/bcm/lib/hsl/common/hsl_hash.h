/* Hash routine.
   Copyright (C) 1998 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published
by the Free Software Foundation; either version 2, or (at your
option) any later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

/* 
	$Log: hash.h,v $
	Revision 1.3  2005/05/16 08:43:03  fky
	nRose3 commit
	
	Revision 1.1  2004/12/29 07:26:56  chenshiwei
	Move from bgpd/bgp_lib
	
	Revision 1.3  2004/09/27 07:09:39  fky
	New BGP First commit
	
*/

#ifndef _PUBLIB_HASH_H_
#define _PUBLIB_HASH_H_

/* Default hash table size.  */ 
#define HASHTABSIZE     1024

#define XMALLOC(T, SZ) oss_malloc((SZ), OSS_MEM_HEAP)
#define XFREE(T, PTR)  oss_free((PTR), OSS_MEM_HEAP)
struct hash_backet
{
  /* Linked list.  */
  struct hash_backet *next;

  /* Hash key. */
  unsigned int key;

  /* Data.  */
  void *data;
};

struct hash
{
  /* Hash backet. */
  struct hash_backet **index;

  /* Hash table size. */
  unsigned int size;

  /* Key make function. */
  unsigned int (*hash_key) ();

  /* Data compare function. */
  int (*hash_cmp) ();

  /* Backet alloc. */
  unsigned long count;
};

struct hash *hash_create (unsigned int (*) (), int (*) ());
struct hash *hash_create_size (unsigned int, unsigned int (*) (), int (*) ());

void *hash_get (struct hash *, void *, void * (*) ());
void *hash_alloc_intern (void *);
void *hash_lookup (struct hash *, void *);
void *hash_release (struct hash *, void *);

void hash_iterate (struct hash *, 
		   void (*) (struct hash_backet *, void *), void *);

void hash_clean (struct hash *, void (*) (void *));
void hash_free (struct hash *);
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
                void *action_arg);

/*
 * condition cleanup, free bucket and data in bucket from hash if bucket's data meet condition.
 * iterate over the hash, free bucket and data if the data meet the condition
 * @hash, the hash table
 * @data_cond, int (*data_cond)(void *element, void* data_cond_arg), condition checker, if meet return nonzero, else return 0.NULL treat no meet
 * @cond_arg, the arg to cond
 * @free_func, assert(NONULL), void (*free_func) (void*), the free method of data in bucket.
 * author: huangjimin
 */

void hash_clean_cond(struct hash* hash,
                    int (*data_cond)(void*, void*),
                    void* data_cond_arg,
                    void (*free_func) (void*));
#endif /* _PUBLIB_HASH_H_ */
