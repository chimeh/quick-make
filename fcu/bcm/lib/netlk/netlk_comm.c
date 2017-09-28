/* Copyright 2003 IP Infusion, Inc. All Rights Reserved.  */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/ip_fib.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <net/ip_fib.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/igmp.h>
#include <linux/mroute.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/addrconf.h>
#include <linux/ctype.h>

#include "netl_netlink.h"
#include "netlk_comm.h"


/* Forward declarations. */
int netlk_sock_if_event (int cmd, void *param1, void *param2);

/* List of all HSL backend sockets. */
static struct netlk_sock *netlk_socklist = 0;
static rwlock_t netlk_socklist_lock = __RW_LOCK_UNLOCKED(netlk_socklist_lock);//RW_LOCK_UNLOCKED;

/* Forward declarations for static calls only. */
static void _netlk_sock_destruct (struct sock *sk);
static int _netlk_sock_create (struct net *net, struct socket *sock, int protocol, int kern);
#if 0   /* EWAN 0921 linux2.4 */
static int _netlk_sock_sendmsg (struct socket *sock, struct msghdr *msg, int len, struct scm_cookie *scm);
static int _netlk_sock_recvmsg (struct socket *sock, struct msghdr *msg, int len, int flags, struct scm_cookie *scm);
#else	/* EWAN 0921 linux2.6 */
static int _netlk_sock_sendmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len);
static int _netlk_sock_recvmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);
#endif
static int _netlk_sock_bind (struct socket *sock, struct sockaddr *sockaddr, int sockaddr_len);
static int _netlk_sock_getname (struct socket *sock, struct sockaddr *saddr, int *len, int peer);


static struct proto_ops netlk_ops = {
family:
    AF_NETL,

release:
    netlk_sock_release,
bind:
    _netlk_sock_bind,
connect:
    sock_no_connect,
socketpair:
    sock_no_socketpair,
accept:
    sock_no_accept,
getname:
    _netlk_sock_getname,
poll:
    datagram_poll,
ioctl:
    sock_no_ioctl,
listen:
    sock_no_listen,
shutdown:
    sock_no_shutdown,
setsockopt:
    sock_no_setsockopt,
getsockopt:
    sock_no_getsockopt,
sendmsg:
    _netlk_sock_sendmsg,
recvmsg:
    _netlk_sock_recvmsg,
mmap:
    sock_no_mmap,
sendpage:
    sock_no_sendpage,
};

static struct net_proto_family netlk_family_ops = {
family:
    AF_NETL,
create:
    _netlk_sock_create,
};

/* Destruct socket. */
static void
_netlk_sock_destruct (struct sock *sk) {
    struct netlk_sock *hsk, *phsk;

    if (!sk)
        return;

    /* Write lock. */
    write_lock_bh (&netlk_socklist_lock);

    phsk = NULL;
    for (hsk = netlk_socklist; hsk; hsk = hsk->next) {
        if (hsk->sk == sk) {
            if (phsk)
                phsk->next = hsk->next;
            else
                netlk_socklist = hsk->next;
            /* Free hsk. */
            kfree (hsk);
            break;
        }
        phsk = hsk;
    }

    /* Write unlock. */
    write_unlock_bh (&netlk_socklist_lock);

    /* Now the socket is dead. No more input will appear.*/
    sock_orphan (sk);

    /* Purge queues */
#if 0   /* NETFORD-linux_2.6 */
    skb_queue_purge (&sk->receive_queue);
#else
    skb_queue_purge (&sk->sk_receive_queue);
#endif

    sock_put (sk);
}

/* Release socket. */
int
netlk_sock_release (struct socket *sock) {
    struct sock *sk = sock->sk;

    /* Destruct socket. */
    _netlk_sock_destruct (sk);
    sock->sk = NULL;
    return 0;
}

static struct proto netlk_proto = {
    .name     = "HSL",
    .owner    = THIS_MODULE,
    .obj_size = sizeof(struct sock),
};

/* Create socket. */
static int
_netlk_sock_create (struct net *net, struct socket *sock, int protocol, int kern) {
    struct sock *sk = NULL;
    struct netlk_sock *hsk = NULL;
    sock->state = SS_UNCONNECTED;

#if 0   /* NETFORD-linux_2.6 */
    sk = sk_alloc (AF_NETL, GFP_KERNEL, 1);
#else
    sk = sk_alloc (net, AF_NETL, GFP_KERNEL, &netlk_proto);
#endif
    if (sk == NULL) {
        return(-ENOBUFS);
    }
    sock->ops = &netlk_ops;
    sock_init_data (sock,sk);
    sock_hold (sk);
    /* Write lock. */
    write_lock_bh (&netlk_socklist_lock);
    hsk = kmalloc (sizeof (struct netlk_sock), GFP_KERNEL);
    if (! hsk) {
        write_unlock_bh (&netlk_socklist_lock);
        goto ERR;
    }
    hsk->next = netlk_socklist;
    netlk_socklist = hsk;
    /* Set sk. */
    hsk->sk = sk;
    /* Reset multicast group and PID. */
    hsk->groups = 0;
    hsk->pid = 0;
    /* Write unlock. */
    write_unlock_bh (&netlk_socklist_lock);
    return(0);
ERR:
    if (sk)
        sk_free (sk);
    return(-ENOMEM);
}

/*
  HSL socket getname.
*/
static int
_netlk_sock_getname (struct socket *sock, struct sockaddr *saddr,
                   int *len, int peer) {
    struct netlk_sock *hsk;
    struct netl_sockaddr_nl *snl = (struct netl_sockaddr_nl *) saddr;
    struct sock *sk;

    sk = sock->sk;
    if (! sk)
        return -EINVAL;

    /* Read lock. */
    read_lock_bh (&netlk_socklist_lock);
    for (hsk = netlk_socklist; hsk; hsk = hsk->next) {
        if (hsk->sk == sk) {
            /* Set multicast group. */
            snl->nl_pid    = hsk->pid;
            snl->nl_groups = hsk->groups;
            break;
        }
    }

    /* Read unlock. */
    read_unlock_bh (&netlk_socklist_lock);
    if (len)
        *len = sizeof (struct netl_sockaddr_nl);

    return 0;
}


/*
   HSL process message from client.
*/
int
netlk_sock_process_msg (struct socket *sock, char *buf, int buflen) {
    struct netl_nlmsghdr *hdr;
    char *msgbuf;

    hdr = (struct netl_nlmsghdr *)buf;
    msgbuf = buf + sizeof (struct netl_nlmsghdr);
    if (hdr->nlmsg_type < 300)
        printk("netlk_sock_process_msg() type %d =\n", hdr->nlmsg_type);
    switch (hdr->nlmsg_type) {


    default:
        NETL_MSG_PROCESS_RETURN (sock, hdr, -ENOTSUPP);
        return 0;
    }


    return 0;
}

/* Sendmsg. */
static int
#if	0	/* NETFORD-linux_2.6 */
_netlk_sock_sendmsg (struct socket *sock, struct msghdr *msg, int len,
                   struct scm_cookie *scm)
#else
_netlk_sock_sendmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
#endif
{
    u_char *buf = NULL;
    int err;

    /* Allocate work memory. */
    buf = (u_char *) kmalloc (len, GFP_KERNEL);
    if (! buf)
        goto ERR;

    /* Returns -EFAULT on error */
    err = memcpy_fromiovec ((unsigned char *)buf, msg->msg_iov, len);
    if (err)
        goto ERR;

    /* Process message. */
    netlk_sock_process_msg (sock, (char *)buf, len);


    /* Free buf. */
    if (buf)
        kfree (buf);

    return len;

ERR:
    if (buf)
        kfree (buf);

    return -1;
}

/* Recvmsg. */
static int
#if	0	/* NETFORD-linux_2.6 */
_netlk_sock_recvmsg (struct socket *sock, struct msghdr *msg, int len,
                   int flags, struct scm_cookie *scm)
#else
_netlk_sock_recvmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags)
#endif
{
    struct sock *sk;
    struct sk_buff *skb;
    struct netl_sockaddr_nl snl;
    int copied;
    struct netlk_sock *hsk;
    int socklen;
    int err;

    sk = sock->sk;
    if (! sk)
        return -EINVAL;

    /* Read lock. */
    read_lock_bh (&netlk_socklist_lock);

    for (hsk = netlk_socklist; hsk; hsk = hsk->next) {
        if (hsk->sk == sk) {
            /* Set multicast group. */
            snl.nl_pid    = hsk->pid;
            snl.nl_groups = hsk->groups;
            break;
        }
    }

    /* Read unlock. */
    read_unlock_bh (&netlk_socklist_lock);

    /* Copy netl_sockaddr_nl. */
    socklen = sizeof (struct netl_sockaddr_nl);
    if (msg->msg_name)
        memcpy (msg->msg_name, &snl, socklen);
    msg->msg_namelen = socklen;

    /* Receive one msg from the queue. */
    skb = skb_recv_datagram (sk, flags, flags & MSG_DONTWAIT, &err);
    if (! skb) {
        return -EINVAL;
    }

    /* Did user send lesser buffer? */
    copied = skb->len;
    if (copied > len) {
        copied = len;
        msg->msg_flags |= MSG_TRUNC;
    }

    /* Copy message. */
    /*skb->h.raw = skb->data;*/
    err = skb_copy_datagram_iovec (skb, 0, msg->msg_iov, copied);
    if (err < 0) {
        skb_free_datagram (sk, skb);
        release_sock (sk);
        return err;
    }

    sock_recv_timestamp (msg, sk, skb);

    /* Free. */
    skb_free_datagram (sk, skb);

    return copied;
}

/* Bind. */
static int
_netlk_sock_bind (struct socket *sock, struct sockaddr *sockaddr, int sockaddr_len) {
    struct sock *sk = sock->sk;
    struct netlk_sock *hsk;
    struct netl_sockaddr_nl *nl_sockaddr = (struct netl_sockaddr_nl *) sockaddr;

    if (! sk)
        return -EINVAL;

    /* Write lock. */
    write_lock_bh (&netlk_socklist_lock);

    for (hsk = netlk_socklist; hsk; hsk = hsk->next) {
        if (hsk->sk == sk) {
            /* Set multicast group. */
            hsk->groups = nl_sockaddr->nl_groups;
            hsk->pid = (u_int32_t)((long)sk);
            break;
        }
    }

    /* Write unlock. */
    write_unlock_bh (&netlk_socklist_lock);

    return 0;
}

/* Post skb to the socket. */
static int
_netlk_sock_post_skb (struct socket *sock, struct sk_buff *skb) {
    struct sock *sk = sock->sk;
    int ret = 0;

#if 0   /* NETFORD-linux_2.6 */
    if (atomic_read (&sk->rmem_alloc) + skb->truesize < (unsigned)sk->rcvbuf)
#else
    if (atomic_read (&sk->sk_rmem_alloc) + skb->truesize < (unsigned)sk->sk_rcvbuf)
#endif
    {
        skb_set_owner_r (skb, sk);
        skb->dev = NULL;
#if 0   /* NETFORD-linux_2.6 */
        spin_lock (&sk->receive_queue.lock);
        __skb_queue_tail (&sk->receive_queue, skb);
        spin_unlock (&sk->receive_queue.lock);
        sk->data_ready (sk, skb->len);
#else
        spin_lock (&sk->sk_receive_queue.lock);
        __skb_queue_tail (&sk->sk_receive_queue, skb);
        spin_unlock (&sk->sk_receive_queue.lock);
        sk->sk_data_ready (sk, skb->len);
#endif
    } else
        ret = -1;

//    printk("[%s]: ret = %d\r\n", __func__, ret);

    return ret;
}

/* Post buffer to socket. */
int
netlk_sock_post_buffer (struct socket *sock, char *buf, int size) {
    struct sk_buff *skb = NULL;
    int ret;

    skb = alloc_skb (size, GFP_KERNEL);
    if (! skb)
        return -1;

    /* Copy data. */
    memcpy (skb->data, buf, size);
    skb->len = size;
    skb->truesize = size;

    ret = _netlk_sock_post_skb (sock, skb);
    if (ret < 0)
        kfree_skb (skb);

    return ret;
}

/*
  Post the (non-multi) message buffer to the socket.
*/
int
netlk_sock_post_msg (struct socket *sock, int cmd, int flags, int seqno, char *buf, int size) {
    int totsize;
    struct netl_nlmsghdr *nlh;
    int offset;
    struct sk_buff *skb = NULL;

    /* Total size. */
    totsize = 2 * NETL_NLMSG_ALIGN(NETL_NLMSGHDR_SIZE) + NETL_NLMSG_ALIGN(size);

    skb = alloc_skb (totsize, GFP_KERNEL);
    if (! skb)
        return -1;
    skb->len = totsize;
    skb->truesize = totsize;

    nlh = (struct netl_nlmsghdr *) skb->data;
    nlh->nlmsg_len = NETL_NLMSG_LENGTH (size);
    nlh->nlmsg_type = cmd;
    nlh->nlmsg_seq = seqno;

    /* Total message size. */
    offset = NETL_NLMSG_ALIGN(NETL_NLMSGHDR_SIZE);
    memcpy (skb->data + offset, buf, size);

    /* End message with done. */
    offset = NETL_NLMSG_ALIGN(nlh->nlmsg_len);
    nlh = (struct netl_nlmsghdr *) (skb->data + offset);
    nlh->nlmsg_len = NETL_NLMSG_LENGTH(0);
    nlh->nlmsg_type = NETL_NLMSG_DONE;

    return _netlk_sock_post_skb (sock, skb);
}

/* Post ACK. */
int
netlk_sock_post_ack (struct socket *sock, struct netl_nlmsghdr *hdr, int flags, int error) {
    int acksz = 2 * NETL_NLMSG_ALIGN(NETL_NLMSGHDR_SIZE) + NETL_NLMSG_ALIGN(4);
    struct netl_nlmsghdr *nlh;
    int *err;
    struct sk_buff *skb;
    u_char *sp;

    skb = alloc_skb (acksz, GFP_KERNEL);
    if (! skb)
        return -1;
    skb->len = acksz;
    skb->truesize = acksz;

    nlh = (struct netl_nlmsghdr *) skb->data;
    nlh->nlmsg_type = NETL_NLMSG_ERROR;
    nlh->nlmsg_len = NETL_NLMSG_LENGTH(4 + NETL_NLMSGHDR_SIZE);
    nlh->nlmsg_flags = flags;

    sp = skb->data + NETL_NLMSG_ALIGN(NETL_NLMSGHDR_SIZE);
    err = (int *) sp;
    *err = error;

    sp += NETL_NLMSG_ALIGN(4);

    nlh = (struct netl_nlmsghdr *) sp;
    memcpy (nlh, hdr, NETL_NLMSGHDR_SIZE);

    return _netlk_sock_post_skb (sock, skb);
}

/* HSL socket initialization. */
int
netlk_sock_init (void) {
    int ret;
    ret = sock_register (&netlk_family_ops);
    return 0;
}

/* HSL socket deinitialization. */
int
netlk_sock_deinit (void) {
    sock_unregister (AF_NETL);
    return 0;
}

/*
  HSL Socket Interface event function.
*/
int
netlk_sock_if_event (int cmd, void *param1, void *param2) {
    return 0;
}


