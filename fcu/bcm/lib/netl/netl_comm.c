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


void *netl_comm_zg = NULL;

/* 
   Make socket for netlink(RFC 3549) interface. 
*/
int netl_socket(struct netlsock *nl, unsigned long groups,
               unsigned char non_block)
{
    int ret;
    struct netl_sockaddr_nl snl;
    int sock;
    socklen_t namelen;

    sock = socket(AF_NETL, SOCK_RAW, 0);
    if (sock < 0) {
        netl_err(netl_comm_zg, "Can't open %s socket: %s", nl->name,
                strerror(errno));
        return -1;
    }

    if (non_block) {
        ret = netl_sock_set_nonblocking(sock, 1 /* non_block */ );
        if (ret < 0) {
            netl_err(netl_comm_zg, "Can't set %s socket flags: %s", nl->name,
                    strerror(errno));
            close(sock);
            return -1;
        }
    }

    memset(&snl, 0, sizeof snl);
    snl.nl_family = AF_NETL;
    snl.nl_groups = groups;

    /* Bind the socket to the netlink(RFC 3549) structure for anything. */
    ret = bind(sock, (struct sockaddr *) &snl, sizeof(snl));
    if (ret < 0) {
        netl_err(netl_comm_zg, "Can't bind %s socket to group 0x%x: %s",
                nl->name, snl.nl_groups, strerror(errno));
        close(sock);
        return -1;
    }

    /* multiple netlink(RFC 3549) sockets will have different nl_pid */
    namelen = sizeof snl;
    ret = getsockname(sock, (struct sockaddr *) &snl, &namelen);
    if (ret < 0 || namelen != sizeof snl) {
        netl_err(netl_comm_zg, "Can't get %s socket name: %s", nl->name,
                strerror(errno));
        close(sock);
        return -1;
    }

    nl->snl = snl;
    nl->sock = sock;
    return ret;
}

/*
  Close NETL socket. 
*/
int netl_close(struct netlsock *s)
{
    close(s->sock);

    return 0;
}





static int netl_recv_cb(struct netl_nlmsghdr *h, void *data)
{
    struct netl_nlmsgerr *err = (struct netl_nlmsgerr *) NETL_NLMSG_DATA(h);

    netl_warn(netl_comm_zg, "netl_recv_cb: ignoring message type 0x%04x",
             h->nlmsg_type);

    if (err)
        return err->error;
    else
        return 0;
}

enum netl_match_cmp netl_match_always(const struct netl_nlmsghdr *msgh,
                                    void *mtdata)
{
    return NETL_NL_CMP_IS_MATCH;
}
/* 
   sendmsg() to netlink(RFC 3549) socket then recvmsg().
*/
int netl_talk(struct netlsock *nl, struct netl_nlmsghdr *n,
             int (*cb) (struct netl_nlmsghdr *, void *), void *data)
{
    int status;
    struct netl_sockaddr_nl snl;
    struct iovec iov = { (void *) n, n->nlmsg_len };
    struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };

    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_NETL;

    /* Request an acknowledgement by setting NETL_NLM_F_ACK */
    n->nlmsg_flags |= NETL_NLM_F_ACK;

    /* Send message to netlink(RFC 3549) interface. */
    status = sendmsg(nl->sock, &msg, 0);
    if (status < 0) {
        netl_err(netl_comm_zg, "netllink_talk sendmsg() error: %s",
                strerror(errno));
        return -1;
    }

    if (cb)
        status =
            netl_read_parser_invokecb(nl, netl_match_always, NULL, cb, data);
    else
        status =
            netl_read_parser_invokecb(nl, netl_match_always, NULL,
                                     netl_recv_cb, data);

    return status;
}



/*
  Send NETL generic  message to NETL.
*/
int
netl_msg_generic_request(struct netlsock *nl, int msg,
                        int (*cb) (struct netl_nlmsghdr *, void *),
                        void *data)
{
    int ret;
    struct netl_nlmsghdr *nlh;
    struct {
        struct netl_nlmsghdr nlh;
    } req;
    if (!nl) {
        return -1;
    }
    memset(&req.nlh, 0, sizeof(struct netl_nlmsghdr));

    /* Set header. */
    nlh = &req.nlh;
    nlh->nlmsg_len = NETL_NLMSG_LENGTH(0);
    nlh->nlmsg_flags = NETL_NLM_F_CREATE | NETL_NLM_F_REQUEST;
    nlh->nlmsg_type = msg;
    nlh->nlmsg_seq = ++nl->seq;

    /* Request list of interfaces. */
    ret = netl_talk(nl, nlh, cb, data);
    if (ret < 0)
        return ret;

    return 0;
}



/*
  Send NETL generic poll message to NETL.
*/

/* 
   Receive message from netlink(RFC 3549) interface and pass those information
   to the given function. 
*/
int
netl_read_parser_invokecb(struct netlsock *nl,
                         enum netl_match_cmp (*match) (const struct
                                                      netl_nlmsghdr * msgh,
                                                      void *mtdata),
                         void *mtdata, int (*cb) (struct netl_nlmsghdr *,
                                                  void *), void *cbdata)
{
    int len;
    int ret = 0;
    int error;
    while (1) {
        enum netl_match_cmp match_cmp;
        char buf[4096];
        struct iovec iov = { buf, sizeof(buf) };
        struct netl_sockaddr_nl snl;
        struct msghdr msg =
            { (void *) &snl, sizeof(snl), (void *) &iov, 1, NULL, 0, 0 };
        struct netl_nlmsghdr *h;
        len = recvmsg(nl->sock, &msg, 0);
        if (len < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EWOULDBLOCK)
                break;
            netl_err(netl_comm_zg, "%s recvmsg overrun: %s", nl->name,
                    strerror(errno));
            continue;
        }
        if (len == 0) {
            netl_err(netl_comm_zg, "%s EOF", nl->name);
            return -1;
        }
        for (h = (struct netl_nlmsghdr *) buf; NETL_NLMSG_OK(h, len);
             h = NETL_NLMSG_NEXT(h, len)) {

            /* Finish of reading. */
            if (h->nlmsg_type == NETL_NLMSG_DONE) {
                return ret;
            }

            /* Error handling. */
            if (h->nlmsg_type == NETL_NLMSG_ERROR) {
                struct netl_nlmsgerr *err =
                    (struct netl_nlmsgerr *) NETL_NLMSG_DATA(h);
                if (h->nlmsg_len <
                    NETL_NLMSG_LENGTH(sizeof(struct netl_nlmsgerr))) {
                    netl_err(netl_comm_zg, "%s error: message truncated",
                            nl->name);
                    return -1;
                }
                netl_err(netl_comm_zg,
                        "%s error: %s, type=%u, seq=%u, pid=%d",
                        nl->name, strerror(-err->error),
                        err->msg.nlmsg_type, err->msg.nlmsg_seq,
                        err->msg.nlmsg_pid);
                return err->error;
            }
            if (0) {
                /* OK we got netlink(RFC 3549) message. */
                netl_info(netl_comm_zg,
                         "netl_read_parser_invokecb: %s type %u, seq=%u, pid=%d",
                         nl->name, h->nlmsg_type, h->nlmsg_seq,
                         h->nlmsg_pid);
            }
            if (match) {
                match_cmp = (*match) ((struct netl_nlmsghdr *) h, mtdata);
                if (match_cmp == NETL_NL_CMP_IS_MATCH) {
                    if (cb) {
                        error = (*cb) (h, cbdata);
                        if (error < 0) {
                            netl_err(netl_comm_zg, "%s cb function error",
                                    nl->name);
                            ret = error;
                        }
                    }
                }

            } else {
                netl_err(netl_comm_zg, "match cmp is NULL", match);
            }
        }

        /* After error care. */
        if (msg.msg_flags & MSG_TRUNC) {
            netl_err(netl_comm_zg, "%s error: message truncated", nl->name);
            continue;
        }
        if (len) {
            netl_err(netl_comm_zg, "%s error: data remnant size %d",
                    nl->name, len);
            return -1;
        }
    }
    return ret;
}



int netl_sock_set_nonblocking(int sock, int nonblock)
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
