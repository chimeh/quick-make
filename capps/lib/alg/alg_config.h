/* Copyright (C) 2002-2011 IP Infusion, Inc.  All Rights Reserved.  */

#ifndef _ALG_CONFIG_H_
#define _ALG_CONFIG_H_


#ifdef FALSE
#undef FALSE
#endif
#define FALSE                           (1 == 0)

#ifdef TRUE
#undef TRUE
#endif
#define TRUE                            (1 == 1)

/* Flag manipulation macros. */
#undef CHECK_FLAG
#undef SET_FLAG
#undef UNSET_FLAG
#undef FLAG_ISSET
#define CHECK_FLAG(V,F)      ((V) & (F))
#define SET_FLAG(V,F)        (V) = (V) | (F)
#define UNSET_FLAG(V,F)      (V) = (V) & ~(F)
#define FLAG_ISSET(V,F)      (((V) & (F)) == (F))
typedef enum ZRESULT
{
  ZRES_ERR     = -1,
  ZRES_OK      =  0,
  ZRES_MORE    =  1,
  ZRES_NO_MORE =  2,
  ZRES_FAIL    =  3,
  ZRES_LAST
} ZRESULT;

#ifdef CONFIG_KERNEL_ASSERTS
/* kgdb stuff */
#define ZASSERT(p) KERNEL_ASSERT(#p, p)
#else
#define ZASSERT(p) do {  \
        if (!(p)) {     \
                printk(KERN_CRIT "BUG at %s:%d assert(%s)\n",   \
                       __FILE__, __LINE__, #p);                 \
                BUG();  \
        }               \
} while (0)
#endif /* CONFIG_KERNEL_ASSERTS */
#endif /* _ALG_CONFIG_H_ */
