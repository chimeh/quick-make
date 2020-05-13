/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include <stdio.h>
#include <sys/types.h>          /* socket */
#include <sys/socket.h>
#include <unistd.h>             /* close */
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "hal_netlink.h"
#include "hal_comm.h"
#include "hal_log.h"
#include "hal_linkcmd.h"

/* 
   Command channel. 
*/
struct halsock hal_linkcmd = { -1, 0, {0}, "hal_linkcmd", (void *)0};


static int hal_cmd_initialized = 0;


/* 
   Initialize HAL-HSL transport.
*/
int hal_cmd_init(void *zg)
{

    /* Open sockets to HSL. */
    hal_socket(&hal_linkcmd, 0, 0);

    hal_cmd_initialized = 1;
    return 0;
}

/* 
   Deinitialize HAL-HSL transport.
*/
int hal_cmd_deinit(void *zg)
{
    /* Close sockets to HSL. */
    hal_close(&hal_linkcmd);

    hal_cmd_initialized = 0;
    return 0;
}
