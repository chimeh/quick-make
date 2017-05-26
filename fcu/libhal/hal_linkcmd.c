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

#define hal_info(zg, ...)
#define hal_warn(zg, ...)
#define hal_err(zg, ...)

void *hal_comm_zg;

/* 
   Asynchronous messages. 
*/
struct halsock hallink = { -1, 0, {0}, "hallink-listen" };

/* 
   Command channel. 
*/
struct halsock hallink_cmd = { -1, 0, {0}, "hallink-cmd" };

/* 
   if-arbiter command channel.
*/
struct halsock hallink_poll = { -1, 0, {0}, "hallink-poll" };

int hal_comm_initialized = 0;

/* 
   Make socket for netlink(RFC 3549) interface. 
*/
int hal_socket(struct halsock *nl, unsigned long groups,
               unsigned char non_block)
{
    int ret;
    struct hal_sockaddr_nl snl;
    int sock;
    socklen_t namelen;

    sock = socket(AF_HSL, SOCK_RAW, 0);
    if (sock < 0) {
        hal_err(hal_zg, "Can't open %s socket: %s", nl->name,
                strerror(errno));
        return -1;
    }

    if (non_block) {
        ret = hal_sock_set_nonblocking(sock, 1 /* non_block */ );
        if (ret < 0) {
            hal_err(hal_zg, "Can't set %s socket flags: %s", nl->name,
                    strerror(errno));
            close(sock);
            return -1;
        }
    }

    memset(&snl, 0, sizeof snl);
    snl.nl_family = AF_HSL;
    snl.nl_groups = groups;

    /* Bind the socket to the netlink(RFC 3549) structure for anything. */
    ret = bind(sock, (struct sockaddr *) &snl, sizeof(snl));
    if (ret < 0) {
        hal_err(hal_zg, "Can't bind %s socket to group 0x%x: %s",
                nl->name, snl.nl_groups, strerror(errno));
        close(sock);
        return -1;
    }

    /* multiple netlink(RFC 3549) sockets will have different nl_pid */
    namelen = sizeof snl;
    ret = getsockname(sock, (struct sockaddr *) &snl, &namelen);
    if (ret < 0 || namelen != sizeof snl) {
        hal_err(hal_zg, "Can't get %s socket name: %s", nl->name,
                strerror(errno));
        close(sock);
        return -1;
    }

    nl->snl = snl;
    nl->sock = sock;
    return ret;
}

/*
  Close HAL socket. 
*/
int hal_close(struct halsock *s)
{
    close(s->sock);

    return 0;
}





static int hal_recv_cb(struct hal_nlmsghdr *h, void *data)
{
    struct hal_nlmsgerr *err = (struct hal_nlmsgerr *) HAL_NLMSG_DATA(h);

    hal_warn(hal_zg, "hal_recv_cb: ignoring message type 0x%04x",
             h->nlmsg_type);

    if (err)
        return err->error;
    else
        return 0;
}

/* 
   sendmsg() to netlink(RFC 3549) socket then recvmsg().
*/
int hal_talk(struct halsock *nl, struct hal_nlmsghdr *n,
             int (*cb) (struct hal_nlmsghdr *, void *), void *data)
{
    int status;
    struct hal_sockaddr_nl snl;
    struct iovec iov = { (void *) n, n->nlmsg_len };
    struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };

    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_HSL;

    /* Request an acknowledgement by setting HAL_NLM_F_ACK */
    n->nlmsg_flags |= HAL_NLM_F_ACK;

    /* Send message to netlink(RFC 3549) interface. */
    status = sendmsg(nl->sock, &msg, 0);
    if (status < 0) {
        hal_err(hal_zg, "hallink_talk sendmsg() error: %s",
                strerror(errno));
        return -1;
    }

    if (cb)
        status = hal_read_parser_invokecb(nl, cb, data);
    else
        status = hal_read_parser_invokecb(nl, hal_recv_cb, data);

    return status;
}

/* 
   Read thread callback. 
*/
static int _hal_callbacks(struct hal_nlmsghdr *h, void *data)
{
    return 0;
}

/*
  Send HAL generic  message to HSL.
*/
int
hal_msg_generic_request(struct halsock *phalsock, int msg,
                        int (*cb) (struct hal_nlmsghdr *, void *),
                        void *data)
{
    int ret;
    struct hal_nlmsghdr *nlh;
    struct {
        struct hal_nlmsghdr nlh;
    } req;
    if (!phalsock) {
        return -1;
    }
    memset(&req.nlh, 0, sizeof(struct hal_nlmsghdr));

    /* Set header. */
    nlh = &req.nlh;
    nlh->nlmsg_len = HAL_NLMSG_LENGTH(0);
    nlh->nlmsg_flags = HAL_NLM_F_CREATE | HAL_NLM_F_REQUEST;
    nlh->nlmsg_type = msg;
    nlh->nlmsg_seq = ++phalsock->seq;

    /* Request list of interfaces. */
    ret = hal_talk(phalsock, nlh, cb, data);
    if (ret < 0)
        return ret;

    return 0;
}

/*
  Send HAL generic poll message to HSL.
*/

/* 
   Receive message from netlink(RFC 3549) interface and pass those information
   to the given function. 
*/
int
hal_read_parser_invokecb(struct halsock *nl,
                         int (*cb) (struct hal_nlmsghdr *, void *),
                         void *data)
{
    int len;
    int ret = 0;
    int error;
    while (1) {
        char buf[4096];
        struct iovec iov = { buf, sizeof(buf) };
        struct hal_sockaddr_nl snl;
        struct msghdr msg =
            { (void *) &snl, sizeof(snl), (void *) &iov, 1, NULL, 0, 0 };
        struct hal_nlmsghdr *h;
        len = recvmsg(nl->sock, &msg, 0);
        if (len < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EWOULDBLOCK)
                break;
            hal_err(hal_zg, "%s recvmsg overrun: %s", nl->name,
                    strerror(errno));
            continue;
        }
        if (len == 0) {
            hal_err(hal_zg, "%s EOF", nl->name);
            return -1;
        }
        for (h = (struct hal_nlmsghdr *) buf; HAL_NLMSG_OK(h, len);
             h = HAL_NLMSG_NEXT(h, len)) {

            /* Finish of reading. */
            if (h->nlmsg_type == HAL_NLMSG_DONE) {
                return ret;
            }

            /* Error handling. */
            if (h->nlmsg_type == HAL_NLMSG_ERROR) {
                struct hal_nlmsgerr *err =
                    (struct hal_nlmsgerr *) HAL_NLMSG_DATA(h);
                if (h->nlmsg_len <
                    HAL_NLMSG_LENGTH(sizeof(struct hal_nlmsgerr))) {
                    hal_err(hal_zg, "%s error: message truncated",
                            nl->name);
                    return -1;
                }
                hal_err(hal_zg,
                        "%s error: %s, type=%u, seq=%u, pid=%d",
                        nl->name, strerror(-err->error),
                        err->msg.nlmsg_type, err->msg.nlmsg_seq,
                        err->msg.nlmsg_pid);
                return err->error;
            }
            if (0) {
                /* OK we got netlink(RFC 3549) message. */
                hal_info(hal_zg,
                         "hal_read_parser_invokecb: %s type %u, seq=%u, pid=%d",
                         nl->name, h->nlmsg_type, h->nlmsg_seq,
                         h->nlmsg_pid);
            }

            /* Skip unsolicited messages originating from command socket. */
            if (nl != &hallink_cmd
                && h->nlmsg_pid == hallink_cmd.snl.nl_pid) {
                hal_info(hal_zg,
                         "hallink_parse_info: %s packet comes from %s",
                         nl->name, hallink_cmd.name);

                continue;
            }
            error = (*cb) (h, data);
            if (error < 0) {
                hal_err(hal_zg, "%s cb function error", nl->name);
                ret = error;
            }
        }

        /* After error care. */
        if (msg.msg_flags & MSG_TRUNC) {
            hal_err(hal_zg, "%s error: message truncated", nl->name);
            continue;
        }
        if (len) {
            hal_err(hal_zg, "%s error: data remnant size %d", nl->name,
                    len);
            return -1;
        }
    }
    return ret;
}

/*
  Read thread for async messages.
*/
int hal_read_parser_invokecb_thread(struct thread *thread)
{
    int ret = 0;
    int sock;
    void *zg;

    //sock = THREAD_FD(thread);
    //zg = THREAD_ARG(thread);
    hallink.t_read = NULL;

    ret = hal_read_parser_invokecb(&hallink, _hal_callbacks, NULL);

    hallink.t_read = hal_read_parser_invokecb_thread;

    return ret;
}

/* 
   Initialize HAL-HSL transport.
*/
int hal_comm_init(void *zg)
{
    unsigned long groups;

    groups = HAL_GROUP_LINK;

    /* Open sockets to HSL. */
    //hal_socket (&hallink, groups, 0);
    hal_socket(&hallink_cmd, 0, 0);
    //hal_socket (&hallink_poll, 0, 0);

    /* Register HAL socket. */
    //if (hallink.sock > 0) {
    //  hallink.t_read = thread_add_read (zg, hal_read_parser_invokecb_thread, zg, hallink.sock);
    //}

    hal_comm_initialized = 1;
    return 0;
}

/* 
   Deinitialize HAL-HSL transport.
*/
int hal_comm_deinit(void *zg)
{
    /* Close sockets to HSL. */
    //hal_close (&hallink);
    hal_close(&hallink_cmd);
    //hal_close (&hallink_poll);

    hal_comm_initialized = 0;
    return 0;
}

int hal_sock_set_nonblocking(int sock, int nonblock)
{
    int val;
    int ret;
    val = fcntl(sock, F_GETFL, 0);
    if (-1 != val) {
        ret =
            fcntl(sock, F_SETFL,
                  (nonblock ? val | O_NONBLOCK : val & (~O_NONBLOCK)));
        if (ret < 0)
            return -1;
        return 0;
    } else {
        return errno;
    }
}
