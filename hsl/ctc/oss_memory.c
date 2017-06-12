/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"

#include "hsl_types.h"
//#include "sal/appl/sal.h"
//#include "sal/core/alloc.h"
#include "hsl_oss.h"

//by chentao add
#define sal_alloc(p,q) kmalloc(p, GFP_KERNEL)
#define sal_free(p) kfree(p)

/************************************************************************************
 * Function: oss_malloc  - Service routine to allocate memory                       *
 * Parameters:                                                                      *
 *   IN  size     - required size in bytes.                                         *
 *   IN  mem_type - type of memory required heap/dma.                               *
 * Return value:                                                                    *
 *   void *ptr - pointer to allocated memory buffer                                 *
 *   NULL - if memory allocation failed                                             *
 ************************************************************************************/

void *
oss_malloc(unsigned long size,oss_mem_type_t mem_type)
{
   void *p;
   switch(mem_type)
   {
      case OSS_MEM_HEAP:
        {
          p = sal_alloc (size, "ipi allocated");

          if (p)
            memset (p, 0, size);
          return p;
        }

      default:
          return NULL;
   }
   return NULL;
}

/************************************************************************************
 * Function: oss_free - Service routine to free allocated memory                    *
 * Parameters:                                                                      *
 *   IN  ptr - pointer to freed memory.                                             *
 *   IN  mem_type - type of memory freed heap/dma.                                  *
 * Return value:                                                                    *
 *   void                                                                           * 
 ************************************************************************************/
void 
oss_free(void *ptr, oss_mem_type_t mem_type)
{
   switch(mem_type)
   {
      case OSS_MEM_HEAP:
        sal_free(ptr);
        break;

      default:
        break;
   }
}
