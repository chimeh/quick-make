/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _NETL_LINKPOLL_H_
#define _NETL_LINKPOLL_H_

/* 
   Command channel. 
*/
extern struct netlsock netl_linkcmd;

/*
   Function prototypes.
*/

int netl_linkcmd_init(void *zg);
int netl_linkcmd_deinit(void *zg);

#endif  /* _NETL_LINKPOLL_H_ */
