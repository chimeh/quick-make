/* Copyright (C) 2004-2011 IP Infusion, Inc. All Rights Reserved. */


#include <stdio.h>
#include "hal_types.h"
#include "hal.h"


/* Libglobals. */
void *hal_zg;

struct hal_ops hal_ops_G = {0};


//extern int hal_fwd_init(void *hal_zg, struct hal_ops * ) __attribute__((weak));
//int hal_fwd_init(void *hal_zg, struct hal_ops *hal_ops)
//{
//    printf("Warning, tail_init, use default(null) hal_fwd %s %s()\n", __FILE__, __func__);
//    return 0;
//}
//
//extern int hal_fwd_deinit (void *, struct hal_ops *) __attribute__((weak));
//int hal_fwd_deinit(void *hal_zg, struct hal_ops *hal_ops )
//{
//    printf("Warning, tail_deinit, use default(null) hal_fwd  %s %s()\n", __FILE__, __func__);
//    return 0;
//}
/*
   Name: hal_init

   Description:
   Initialize the HAL component.

   Parameters:
   None

   Returns:
   < 0 on error
   0
*/
int
hal_init (void *zg)
{
    hal_fwd_init(zg, &hal_ops_G);
    return 0;
}

/*
   Name: hal_deinit

   Description:
   Deinitialize the HAL component.

   Parameters:
   None

   Returns:
   < 0 on error
   0
*/
int
hal_deinit (void *zg)
{
    hal_fwd_init(zg, &hal_ops_G);
    return 0;
}

