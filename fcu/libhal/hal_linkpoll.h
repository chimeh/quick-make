/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HAL_LINKPOLL_H_
#define _HAL_LINKPOLL_H_

/* 
   Command channel. 
*/
extern struct halsock hal_linkcmd;

/*
   Function prototypes.
*/

int hal_linkcmd_init(void *zg);
int hal_linkcmd_deinit(void *zg);

#endif  /* _HAL_LINKPOLL_H_ */
