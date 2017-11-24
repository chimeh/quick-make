/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _NETL_NPAS_TBL_LINK_H_
#define _NETL_NPAS_TBL_LINK_H_

#include "netl_netlink.h"
#include "netl_comm.h"

/*
   Function prototypes.
*/

int npas_tbl_link_init(struct netlsock *ns);
int npas_tbl_link_deinit(struct netlsock *ns);

#endif  /* _NETL_NPAS_TBL_LINK_H_ */
