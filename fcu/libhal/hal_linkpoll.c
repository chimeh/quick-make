/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include <stdio.h>
#include <sys/types.h>          /* socket */
#include <sys/socket.h>
#include <unistd.h>             /* close */
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "hal_netlink.h"
#include "hal_log.h"
#include "hal_comm.h"
#include "hal_linkpoll.h"
#include "thread.h"


/* 
   Command channel. 
*/
struct halsock hal_linkpoll = { -1, 0, {0}, "hal_linkpoll" };

int hal_poll_initialized = 0;


int hal_cb(struct hal_nlmsghdr *h, void *cbdata)
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
int hal_read_parser_invokecb_thread(struct thread *thread)
{
    int ret = 0;
    int sock;
    void *zg;

    sock = THREAD_FD(thread);
    zg = THREAD_ARG(thread);
    hal_linkpoll.t_read = NULL;

    hal_read_parser_invokecb(&hal_linkpoll, hal_match_always, NULL, hal_cb,
                             NULL);
    hal_linkpoll.t_read =
        thread_add_read(zg, hal_read_parser_invokecb_thread, zg, sock);

    return ret;
}

/* 
   Initialize HAL-HSL transport.
*/
int hal_poll_init(void *zg)
{
    unsigned long groups;

    groups = HAL_GROUP_LINK;

    /* Open sockets to HSL. */
    hal_socket(&hal_linkpoll, 0, 0);

    /* Register HAL socket. */
    if (hal_linkpoll.sock > 0) {
        hal_linkpoll.t_read =
            thread_add_read(zg, hal_read_parser_invokecb_thread, zg,
                            hal_linkpoll.sock);
    }

    hal_poll_initialized = 1;
    return 0;
}

/* 
   Deinitialize HAL-HSL transport.
*/
int hal_poll_deinit(void *zg)
{
    /* Close sockets to HSL. */
    hal_close(&hal_linkpoll);

    hal_poll_initialized = 0;
    return 0;
}
