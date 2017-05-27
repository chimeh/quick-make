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


void *hal_comm_zg = NULL;

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
        hal_err(hal_comm_zg, "Can't open %s socket: %s", nl->name,
                strerror(errno));
        return -1;
    }

    if (non_block) {
        ret = hal_sock_set_nonblocking(sock, 1 /* non_block */ );
        if (ret < 0) {
            hal_err(hal_comm_zg, "Can't set %s socket flags: %s", nl->name,
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
        hal_err(hal_comm_zg, "Can't bind %s socket to group 0x%x: %s",
                nl->name, snl.nl_groups, strerror(errno));
        close(sock);
        return -1;
    }

    /* multiple netlink(RFC 3549) sockets will have different nl_pid */
    namelen = sizeof snl;
    ret = getsockname(sock, (struct sockaddr *) &snl, &namelen);
    if (ret < 0 || namelen != sizeof snl) {
        hal_err(hal_comm_zg, "Can't get %s socket name: %s", nl->name,
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

    hal_warn(hal_comm_zg, "hal_recv_cb: ignoring message type 0x%04x",
             h->nlmsg_type);

    if (err)
        return err->error;
    else
        return 0;
}

enum hal_match_cmp hal_match_always(const struct hal_nlmsghdr *msgh,
                                    void *mtdata)
{
    return HAL_NL_CMP_IS_MATCH;
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
        hal_err(hal_comm_zg, "hallink_talk sendmsg() error: %s",
                strerror(errno));
        return -1;
    }

    if (cb)
        status =
            hal_read_parser_invokecb(nl, hal_match_always, NULL, cb, data);
    else
        status =
            hal_read_parser_invokecb(nl, hal_match_always, NULL,
                                     hal_recv_cb, data);

    return status;
}



/*
  Send HAL generic  message to HSL.
*/
int
hal_msg_generic_request(struct halsock *nl, int msg,
                        int (*cb) (struct hal_nlmsghdr *, void *),
                        void *data)
{
    int ret;
    struct hal_nlmsghdr *nlh;
    struct {
        struct hal_nlmsghdr nlh;
    } req;
    if (!nl) {
        return -1;
    }
    memset(&req.nlh, 0, sizeof(struct hal_nlmsghdr));

    /* Set header. */
    nlh = &req.nlh;
    nlh->nlmsg_len = HAL_NLMSG_LENGTH(0);
    nlh->nlmsg_flags = HAL_NLM_F_CREATE | HAL_NLM_F_REQUEST;
    nlh->nlmsg_type = msg;
    nlh->nlmsg_seq = ++nl->seq;

    /* Request list of interfaces. */
    ret = hal_talk(nl, nlh, cb, data);
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
                         enum hal_match_cmp (*match) (const struct
                                                      hal_nlmsghdr * msgh,
                                                      void *mtdata),
                         void *mtdata, int (*cb) (struct hal_nlmsghdr *,
                                                  void *), void *cbdata)
{
    int len;
    int ret = 0;
    int error;
    while (1) {
        enum hal_match_cmp match_cmp;
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
            hal_err(hal_comm_zg, "%s recvmsg overrun: %s", nl->name,
                    strerror(errno));
            continue;
        }
        if (len == 0) {
            hal_err(hal_comm_zg, "%s EOF", nl->name);
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
                    hal_err(hal_comm_zg, "%s error: message truncated",
                            nl->name);
                    return -1;
                }
                hal_err(hal_comm_zg,
                        "%s error: %s, type=%u, seq=%u, pid=%d",
                        nl->name, strerror(-err->error),
                        err->msg.nlmsg_type, err->msg.nlmsg_seq,
                        err->msg.nlmsg_pid);
                return err->error;
            }
            if (0) {
                /* OK we got netlink(RFC 3549) message. */
                hal_info(hal_comm_zg,
                         "hal_read_parser_invokecb: %s type %u, seq=%u, pid=%d",
                         nl->name, h->nlmsg_type, h->nlmsg_seq,
                         h->nlmsg_pid);
            }
            if (match) {
                match_cmp = (*match) ((struct hal_nlmsghdr *) h, mtdata);
                if (match_cmp == HAL_NL_CMP_IS_MATCH) {
                    if (cb) {
                        error = (*cb) (h, cbdata);
                        if (error < 0) {
                            hal_err(hal_comm_zg, "%s cb function error",
                                    nl->name);
                            ret = error;
                        }
                    }
                }

            } else {
                hal_err(hal_comm_zg, "match cmp is NULL", match);
            }
        }

        /* After error care. */
        if (msg.msg_flags & MSG_TRUNC) {
            hal_err(hal_comm_zg, "%s error: message truncated", nl->name);
            continue;
        }
        if (len) {
            hal_err(hal_comm_zg, "%s error: data remnant size %d",
                    nl->name, len);
            return -1;
        }
    }
    return ret;
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
