/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */


#include "hal_netlink.h"
#include "hal_comm.h"


extern struct lib_globals *hal_zg;
extern int hal_if_newlink(struct hal_nlmsghdr *h, void *data);
extern int hal_if_dellink(struct hal_nlmsghdr *h, void *data);
#ifdef HAVE_L2
extern int hal_if_stp_refresh(struct hal_nlmsghdr *h, void *data);
#endif                          /* HAVE_L2 */
#ifdef HAVE_L3
extern int hal_rx_max_multipath(struct hal_nlmsghdr *h, void *data);
#endif
extern int hal_if_ipv4_addr(struct hal_nlmsghdr *h, void *data);
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
int hal_socket(struct halsock *nl, unsigned long groups, u_char non_block)
{
    int ret;
    struct hal_sockaddr_nl snl;
    int sock;
    int namelen;

    sock = pal_sock(hal_zg, AF_HSL, SOCK_RAW, 0);
    if (sock < 0) {
        if (IS_HAL_DEBUG_EVENT)
            zlog_err(hal_zg, "Can't open %s socket: %s", nl->name,
                     strerror(errno));
        return -1;
    }

    if (non_block) {
        ret = pal_sock_set_nonblocking(sock, PAL_TRUE);
        if (ret < 0) {
            if (IS_HAL_DEBUG_EVENT)
                zlog_err(hal_zg, "Can't set %s socket flags: %s", nl->name,
                         strerror(errno));
            close(sock);
            return -1;
        }
    }

    memset(&snl, 0, sizeof snl);
    snl.nl_family = AF_HSL;
    snl.nl_groups = groups;

    /* Bind the socket to the netlink(RFC 3549) structure for anything. */
    ret = pal_sock_bind(sock, (struct pal_sockaddr *) &snl, sizeof snl);
    if (ret < 0) {
        if (IS_HAL_DEBUG_EVENT)
            zlog_err(hal_zg, "Can't bind %s socket to group 0x%x: %s",
                     nl->name, snl.nl_groups, strerror(errno));
        close(sock);
        return -1;
    }

    /* multiple netlink(RFC 3549) sockets will have different nl_pid */
    namelen = sizeof snl;
    ret = pal_sock_getname(sock, (struct pal_sockaddr *) &snl, &namelen);
    if (ret < 0 || namelen != sizeof snl) {
        if (IS_HAL_DEBUG_EVENT)
            zlog_err(hal_zg, "Can't get %s socket name: %s", nl->name,
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

#if 0
/*
  Get type specified information from netlink(RFC 3549). 
*/
int
hal_request(void *req, int size, int type, struct halsock *nl,
            int ack_required)
{
    int ret;
    struct hal_sockaddr_nl snl;
    struct hal_nlmsghdr *nlh = (struct hal_nlmsghdr *) req->nlh;

    /* Check netlink(RFC 3549) socket. */
    if (nl->sock < 0) {
        if (IS_HAL_DEBUG_EVENT)
            zlog_err(hal_zg, "%s socket isn't active.", nl->name);
        return -1;
    }

    memset(&snl, 0, sizeof snl);
    snl.nl_family = AF_HSL;

    nlh->nlmsg_len = size;
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags =
        HAL_NLM_F_ROOT | HAL_NLM_F_MATCH | HAL_NLM_F_REQUEST;
    if (ack_required)
        nlh->nlmsg_flags |= HAL_NLM_F_ACK;
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_seq = ++nl->seq;

    ret = pal_sock_sendto(nl->sock, (void *) &req, size, 0,
                          (struct sockaddr *) &snl, sizeof snl);
    if (ret < 0) {
        if (IS_HAL_DEBUG_EVENT)
            zlog_err(hal_zg, "%s sendto failed: %s", nl->name,
                     strerror(errno));
        return -1;
    }
    return 0;
}
#endif

/* 
   Receive message from netlink(RFC 3549) interface and pass those information
   to the given function. 
*/
int
hal_parse_info(struct halsock *nl,
               int (*filter) (struct hal_nlmsghdr *, void *), void *data)
{
    int status;
    int ret = 0;
    int error;

    while (1) {
        char buf[4096];
        struct iovec iov = { buf, sizeof buf };
        struct hal_sockaddr_nl snl;
        struct msghdr msg =
            { (void *) &snl, sizeof snl, (void *) &iov, 1, NULL, 0, 0 };
        struct hal_nlmsghdr *h;

        status = pal_sock_recvmsg(nl->sock, &msg, 0);

        if (status < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EWOULDBLOCK)
                break;
            if (IS_HAL_DEBUG_EVENT)
                zlog_err(hal_zg, "%s recvmsg overrun: %s", nl->name,
                         strerror(errno));
            continue;
        }

        if (status == 0) {
            if (IS_HAL_DEBUG_EVENT)
                zlog_err(hal_zg, "%s EOF", nl->name);
            return -1;
        }

        for (h = (struct hal_nlmsghdr *) buf; HAL_NLMSG_OK(h, status);
             h = HAL_NLMSG_NEXT(h, status)) {
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
                    if (IS_HAL_DEBUG_EVENT)
                        zlog_err(hal_zg, "%s error: message truncated",
                                 nl->name);
                    return -1;
                }

                if (IS_HAL_DEBUG_EVENT)
                    zlog_err(hal_zg,
                             "%s error: %s, type=%u, seq=%u, pid=%d",
                             nl->name, strerror(-err->error),
                             err->msg.nlmsg_type, err->msg.nlmsg_seq,
                             err->msg.nlmsg_pid);
                return err->error;
            }
#if 0                           /* changed by cdy, 2016/07/06 */
            /* OK we got netlink(RFC 3549) message. */
            if (IS_HAL_DEBUG_EVENT)
                zlog_info(hal_zg,
                          "hal_parse_info: %s type %u, seq=%u, pid=%d",
                          nl->name, h->nlmsg_type,
                          h->nlmsg_seq, h->nlmsg_pid);
#endif

            /* Skip unsolicited messages originating from command socket. */
            if (nl != &hallink_cmd
                && h->nlmsg_pid == hallink_cmd.snl.nl_pid) {
                if (IS_HAL_DEBUG_EVENT)
                    zlog_info(hal_zg,
                              "hallink_parse_info: %s packet comes from %s",
                              nl->name, hallink_cmd.name);
                //continue;
            }

            error = (*filter) (h, data);
            if (error < 0) {
                if (IS_HAL_DEBUG_EVENT)
                    zlog_err(hal_zg, "%s filter function error", nl->name);
                ret = error;
            }
        }

        /* After error care. */
        if (msg.msg_flags & MSG_TRUNC) {
            if (IS_HAL_DEBUG_EVENT)
                zlog_err(hal_zg, "%s error: message truncated", nl->name);
            continue;
        }
        if (status) {
            if (IS_HAL_DEBUG_EVENT)
                zlog_err(hal_zg, "%s error: data remnant size %d",
                         nl->name, status);
            return -1;
        }
    }
    return ret;
}

static int hal_recv_cb(struct hal_nlmsghdr *h, void *data)
{
    struct hal_nlmsgerr *err = (struct hal_nlmsgerr *) HAL_NLMSG_DATA(h);

    if (IS_HAL_DEBUG_EVENT)
        zlog_warn(hal_zg, "hal_recv_cb: ignoring message type 0x%04x",
                  h->nlmsg_type);

    if (err)
        return err->error;
    else
        return 0;
}

/* 
   sendmsg() to netlink(RFC 3549) socket then recvmsg().
*/
int
hal_talk(struct halsock *nl, struct hal_nlmsghdr *n,
         int (*filter) (struct hal_nlmsghdr *, void *), void *data)
{
    int status;
    struct hal_sockaddr_nl snl;
    struct iovec iov = { (void *) n, n->nlmsg_len };
    struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };

    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_HSL;

    /* Request an acknowledgement by setting HAL_NLM_F_ACK */
    n->nlmsg_flags |= HAL_NLM_F_ACK;

#if 0
    if (IS_HAL_DEBUG_EVENT)
        zlog_info(hal_zg, "hallink_talk: %s type %u, seq=%u",
                  hallink_cmd.name, n->nlmsg_type, n->nlmsg_seq);
#endif

    /* Send message to netlink(RFC 3549) interface. */
    status = pal_sock_sendmsg(nl->sock, &msg, 0);
    if (status < 0) {
        if (IS_HAL_DEBUG_EVENT)
            zlog_err(hal_zg, "hallink_talk sendmsg() error: %s",
                     strerror(errno));
        return -1;
    }

    if (filter)
        status = hal_parse_info(nl, filter, data);
    else
        status = hal_parse_info(nl, hal_recv_cb, data);

    return status;
}

/* 
   Read thread callback. 
*/
static int _hal_callbacks(struct hal_nlmsghdr *h, void *data)
{
    switch (h->nlmsg_type) {
    case HAL_MSG_IF_NEWLINK:
    case HAL_MSG_IF_UPDATE:
    case HAL_MSG_IF_DELLINK:
#ifdef HAVE_L2
    case HAL_MSG_IF_STP_REFRESH:
#endif                          /* HAVE_L2 */
#ifdef HAVE_L3
    case HAL_MSG_IF_IPV4_NEWADDR:
    case HAL_MSG_IF_IPV4_DELADDR:
    case HAL_MSG_GET_MAX_MULTIPATH:
#ifdef HAVE_IPV6
    case HAL_MSG_IF_IPV6_NEWADDR:
    case HAL_MSG_IF_IPV6_DELADDR:
#endif                          /* HAVE_IPV6 */
#endif                          /* HAVE_L3   */
        break;
    }
    return 0;
}

/*
  Send HAL generic  message to HSL.
*/
int
hal_msg_generic_request(int msg,
                        int (*filter) (struct hal_nlmsghdr *, void *),
                        void *data)
{
    int ret;
    struct hal_nlmsghdr *nlh;
    struct {
        struct hal_nlmsghdr nlh;
    } req;

    memset(&req.nlh, 0, sizeof(struct hal_nlmsghdr));

    /* Set header. */
    nlh = &req.nlh;
    nlh->nlmsg_len = HAL_NLMSG_LENGTH(0);
    nlh->nlmsg_flags = HAL_NLM_F_CREATE | HAL_NLM_F_REQUEST;
    nlh->nlmsg_type = msg;
    nlh->nlmsg_seq = ++hallink_cmd.seq;

    /* Request list of interfaces. */
    ret = hal_talk(&hallink_cmd, nlh, filter, data);
    if (ret < 0)
        return ret;

    return HAL_SUCCESS;
}

/*
  Send HAL generic poll message to HSL.
*/
int
hal_msg_generic_poll_request(int msg,
                             int (*filter) (struct hal_nlmsghdr *, void *),
                             void *data)
{
    int ret;
    struct hal_nlmsghdr *nlh;
    struct {
        struct hal_nlmsghdr nlh;
    } req;

    memset(&req.nlh, 0, sizeof(struct hal_nlmsghdr));

    /* Set header. */
    nlh = &req.nlh;
    nlh->nlmsg_len = HAL_NLMSG_LENGTH(0);
    nlh->nlmsg_flags = HAL_NLM_F_CREATE | HAL_NLM_F_REQUEST;
    nlh->nlmsg_type = msg;
    nlh->nlmsg_seq = ++hallink_poll.seq;

    /* Request list of interfaces. */
    ret = hal_talk(&hallink_poll, nlh, filter, data);
    if (ret < 0)
        return ret;

    return HAL_SUCCESS;
}

/*
  Read thread for async messages.
*/
int _hal_read(struct thread *thread)
{
    int ret = 0;
    int sock;
    struct lib_globals *zg;

    sock = THREAD_FD(thread);
    zg = THREAD_ARG(thread);
    hallink.t_read = NULL;

    ret = hal_parse_info(&hallink, _hal_callbacks, NULL);

    hallink.t_read = thread_add_read(zg, _hal_read, zg, hallink.sock);

    return ret;
}

/* 
   Initialize HAL-HSL transport.
*/
int hal_comm_init(struct lib_globals *zg)
{
    unsigned long groups;

    groups = HAL_GROUP_LINK;

    /* Open sockets to HSL. */
    //hal_socket (&hallink, groups, 0);
    hal_socket(&hallink_cmd, 0, 0);
    //hal_socket (&hallink_poll, 0, 0);

    /* Register HAL socket. */
    //if (hallink.sock > 0)
    //  hallink.t_read = thread_add_read (zg, _hal_read, zg, hallink.sock);

    hal_comm_initialized = 1;
    return 0;
}

/* 
   Deinitialize HAL-HSL transport.
*/
int hal_comm_deinit(struct lib_globals *zg)
{
    /* Close sockets to HSL. */
    //hal_close (&hallink);
    hal_close(&hallink_cmd);
    //hal_close (&hallink_poll);

    hal_comm_initialized = 0;
    return 0;
}
