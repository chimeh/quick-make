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
   Initialize NETL-NETL transport.
*/
int netl_cmd_init(struct netlsock *link_desc)
{

    /* Open sockets to NETL. */
    netl_socket(link_desc, 0, 0);
    link_desc->initialized = 1;
    return 0;
}

/* 
   Deinitialize NETL-NETL transport.
*/
int netl_cmd_deinit(struct netlsock *link_desc)
{
    /* Close sockets to NETL. */
    netl_close(link_desc);
    link_desc->initialized = 0;
    return 0;
}
