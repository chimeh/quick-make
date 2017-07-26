/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _NETL_LINKCMD_H_
#define _NETL_LINKCMD_H_

/* 
   Command channel. 
*/
struct netlsock netl_linkcmd;

/*
   Function prototypes.
*/

int netl_linkcmd_init(void *zg);
int netl_linkcmd_deinit(void *zg);

#endif  /* _NETL_LINKCMD_H */
