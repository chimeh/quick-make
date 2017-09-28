/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include <stdio.h>
#include <sys/types.h>          /* socket */
#include <sys/socket.h>
#include <unistd.h>             /* close */
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "netl_netlink.h"
#include "netl_log.h"
#include "netl_comm.h"
#include "netl_linkpoll.h"
#ifdef HAVE_QUAGGA_LIB
#include "thread.h"
#endif /* HAVE_QUAGGA_LIB */


/* 
   Command channel. 
*/
struct netlsock netl_linkpoll = { -1, 0, {0}, "netl_linkpoll" };

int netl_poll_initialized = 0;


int netl_cb(struct netl_nlmsghdr *h, void *cbdata)
{
    switch (h->nlmsg_type) {
        default:
        printf("rcv nlmsg_type %d\n", h->nlmsg_type);
    }
    return 0;
}

/*
  Read thread for async messages.
*/
int netl_read_parser_invokecb_thread(void *quagga_thread)
{
    int ret = 0;
    int sock;
    void *zg;
#ifdef HAVE_QUAGGA_LIB
    struct thread *thread = (struct thread *)quagga_thread;
    sock = THREAD_FD(thread);
    zg = THREAD_ARG(thread);
    netl_linkpoll.t_read = NULL;

    netl_read_parser_invokecb(&netl_linkpoll, netl_match_always, NULL, netl_cb,
                             NULL);
    netl_linkpoll.t_read =
        thread_add_read(zg, netl_read_parser_invokecb_thread, zg, sock);
#endif
    return ret;
}

/* 
   Initialize NETL-NETL transport.
*/
int netl_poll_init(void *zg)
{
    unsigned long groups;

    groups = NETL_GROUP_LINK;

    /* Open sockets to NETL. */
    netl_socket(&netl_linkpoll, 0, 0);

    /* Register NETL socket. */
    if (netl_linkpoll.sock > 0) {
#ifdef HAVE_QUAGGA_LIB
        netl_linkpoll.t_read =
            thread_add_read(zg, netl_read_parser_invokecb_thread, zg,
                            netl_linkpoll.sock);
#endif
    }

    netl_poll_initialized = 1;
    return 0;
}

/* 
   Deinitialize NETL-NETL transport.
*/
int netl_poll_deinit(void *zg)
{
    /* Close sockets to NETL. */
    netl_close(&netl_linkpoll);

    netl_poll_initialized = 0;
    return 0;
}
