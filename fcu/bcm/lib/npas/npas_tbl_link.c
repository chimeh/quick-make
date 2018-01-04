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
#include "npas_tbl_link.h"



/* 
   Initialize NETL-NETL transport.
*/
int npas_tbl_link_init(struct netlsock *ns)
{
    int ret;

    /* Open sockets to NETL. */
    ret = netl_socket(ns, 0, 0);

    ns->initialized = 1;
    return 0;
}

/* 
   Deinitialize NETL-NETL transport.
*/
int npas_tbl_link_deinit(struct netlsock *ns)
{
    /* Close sockets to NETL. */
    netl_close(ns);

    ns->initialized = 0;
    return 0;
}
