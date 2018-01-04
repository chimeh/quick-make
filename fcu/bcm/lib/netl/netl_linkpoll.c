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
    int sock;
    struct netlsock *nl;
#ifdef HAVE_QUAGGA_LIB
    struct thread *thread = (struct thread *)quagga_thread;
    sock = THREAD_FD(thread);
    nl = THREAD_ARG(thread);
    nl->t_read = NULL;

    netl_read_parser_invokecb(nl, netl_match_always, NULL, netl_cb,
                             NULL);
    nl->t_read =
        thread_add_read(nl->arg_zg,
                netl_read_parser_invokecb_thread,
                nl->arg_zg,
                sock);
#endif
    return 0;
}

/* 
   Initialize NETL-NETL transport.
*/
int netl_poll_init(struct netlsock *link_desc)
{

    /* Open sockets to NETL. */
    netl_socket(link_desc, 0, 0);

    /* Register NETL socket. */
    if (link_desc->sock > 0) {
#ifdef HAVE_QUAGGA_LIB
        link_desc->t_read =
            thread_add_read(link_desc->arg_zg,
                            netl_read_parser_invokecb_thread,
                            link_desc->arg_zg,
                            link_desc->sock);
#endif
    }

    link_desc->initialized = 1;
    return 0;
}

/* 
   Deinitialize NETL-NETL transport.
*/
int netl_poll_deinit(struct netlsock *link_desc)
{
    /* Close sockets to NETL. */
    netl_close(link_desc);

    link_desc->initialized = 0;
    return 0;
}
