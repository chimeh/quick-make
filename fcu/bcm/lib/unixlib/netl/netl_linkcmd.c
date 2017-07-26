/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include <stdio.h>
#include <sys/types.h>          /* socket */
#include <sys/socket.h>
#include <unistd.h>             /* close */
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "netl_netlink.h"
#include "netl_comm.h"
#include "netl_log.h"
#include "netl_linkcmd.h"

/* 
   Command channel. 
*/
struct netlsock netl_linkcmd = { -1, 0, {0}, "netl_linkcmd", (void *)0};


static int netl_cmd_initialized = 0;


/* 
   Initialize NETL-NETL transport.
*/
int netl_cmd_init(void *zg)
{

    /* Open sockets to NETL. */
    netl_socket(&netl_linkcmd, 0, 0);

    netl_cmd_initialized = 1;
    return 0;
}

/* 
   Deinitialize NETL-NETL transport.
*/
int netl_cmd_deinit(void *zg)
{
    /* Close sockets to NETL. */
    netl_close(&netl_linkcmd);

    netl_cmd_initialized = 0;
    return 0;
}
