/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_LINKCMD_H_
#define _HAL_LINKCMD_H_

/* 
   Command channel. 
*/
extern struct halsock hal_linkcmd;

/*
   Function prototypes.
*/

int hal_comm_init(void *zg);
int hal_comm_deinit(void *zg);

#endif  /* _HAL_LINKCMD_H */
