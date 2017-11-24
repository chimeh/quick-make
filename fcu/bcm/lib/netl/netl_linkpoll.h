/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _NETL_LINKPOLL_H_
#define _NETL_LINKPOLL_H_

/*
   Function prototypes.
*/

int netl_linkcmd_init(struct netlsock *link_desc);
int netl_linkcmd_deinit(struct netlsock *link_desc);

#endif  /* _NETL_LINKPOLL_H_ */
