/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */
#include "hal_netlink.h"
#include "hal_comm.h"




/* Libglobals. */
void *hal_zg;


/* 
   Name: hal_init

   Description: 
   Initialize the HAL component. 

   Parameters:
   None

   Returns:
   < 0 on error 
   HAL_SUCCESS
*/
int
hal_init (void *zg)
{
  int ret;
  /* Set ZG. */
  hal_zg = zg;
  
  /* Initialize HAL-HSL transport. */
  hal_comm_init (zg);

  return 0;

 CLEANUP:
 	printf("hal_init fail\r\n");
  hal_deinit (zg);

  return -1;
}

/* 
   Name: hal_deinit

   Description:
   Deinitialize the HAL component.

   Parameters:
   None

   Returns:
   < 0 on error
   HAL_SUCCESS
*/
int
hal_deinit (struct lib_globals *zg)
{
  /* Deinitialize HAL-HSL transport. */
  hal_comm_deinit (zg);

  return 0;
}

