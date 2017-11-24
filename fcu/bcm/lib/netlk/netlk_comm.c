/* Copyright 2003 IP Infusion, Inc. All Rights Reserved.  */

#include <linux/module.h>
#include <linux/capability.h>
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

static netlk_sock_process_msg_func_t netlk_sock_process_msg_hook = NULL;

/* List of all HSL backend sockets. */
//static struct netlk_sock *netlk_socklist = 0;
//static rwlock_t netlk_socklist_lock = __RW_LOCK_UNLOCKED(netlk_socklist_lock);//RW_LOCK_UNLOCKED;

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
    .family = AF_NETL,
    .owner = THIS_MODULE,
    .release = netlk_sock_release,
    .bind = _netlk_sock_bind,
    .connect = sock_no_connect,
    .socketpair = sock_no_socketpair,
    .accept = sock_no_accept,
    .getname = _netlk_sock_getname,
    .poll = datagram_poll,
    .ioctl = sock_no_ioctl,
    .listen = sock_no_listen,
    .shutdown = sock_no_shutdown,
    .setsockopt = sock_no_setsockopt,
    .getsockopt = sock_no_getsockopt,
    .sendmsg = _netlk_sock_sendmsg,
    .recvmsg = _netlk_sock_recvmsg,
    .mmap = sock_no_mmap,
    .sendpage = sock_no_sendpage,
};

static struct net_proto_family netlk_family_ops = {
    .family = AF_NETL,
    .create = _netlk_sock_create,
    .owner = THIS_MODULE,
};

static struct proto netlk_proto = {
    .name     = "HSL",
    .owner    = THIS_MODULE,
    .obj_size = sizeof(struct netlk_sock),
};
static inline struct netlk_sock *netlk_sk(struct sock *sk)
{
    return container_of(sk, struct netlk_sock, sk);
}

/* Destruct socket. */
static void
_netlk_sock_destruct (struct sock *sk) {
    struct netlk_sock *hsk;

    if (!sk)
        return;

    /* Write lock. */
    //write_lock_bh (&netlk_socklist_lock);

    hsk = netlk_sk(sk);

    /* Write unlock. */
    //write_unlock_bh (&netlk_socklist_lock);

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
    //printk("#%s() %d module ref %d\n",__func__, __LINE__, module_refcount(THIS_MODULE));
    //printk(KERN_ALERT "#%s\n", __func__);
    /* Destruct socket. */
    _netlk_sock_destruct (sk);
    sock->sk = NULL;
    
    module_put(netlk_family_ops.owner);
    //printk("#%s() %d module ref %d\n",__func__, __LINE__, module_refcount(THIS_MODULE));
    return 0;
}


/* Create socket. */
static int
_netlk_sock_create (struct net *net, struct socket *sock, int protocol, int kern) {
    struct sock *sk = NULL;
    struct netlk_sock *hsk = NULL;
    sock->state = SS_UNCONNECTED;
    
    //printk("#%s() %d module ref %d\n",__func__, __LINE__, module_refcount(THIS_MODULE));
    //printk(KERN_ALERT "#%s\n", __func__);
#if 0   /* NETFORD-linux_2.6 */
    sk = sk_alloc (AF_NETL, GFP_KERNEL, 1);
#else
    sk = sk_alloc (net, AF_NETL, GFP_KERNEL, &netlk_proto);
#endif
    if (sk == NULL) {
        return(-ENOBUFS);
    }
    //printk("#%s() %d module ref %d\n",__func__, __LINE__, module_refcount(THIS_MODULE));
    sock_init_data (sock, sk);
    sock->ops = &netlk_ops;
    sk->sk_protocol = protocol;
    sock_hold (sk);
    /* Write lock. */
    //write_lock_bh (&netlk_socklist_lock);
    
    hsk = netlk_sk(sk);
    //mutex_init(hsk->cb_mutex);
    /* Set sk. */
    //hsk->sk = sk;
    /* Reset multicast group and PID. */
    hsk->groups = 0;
    hsk->pid = 0;
    /* Write unlock. */
    //write_unlock_bh (&netlk_socklist_lock);
    return(0);
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

    //printk(KERN_ALERT "#%s\n", __func__);
    sk = sock->sk;
    if (! sk)
        return -EINVAL;

    /* Read lock. */
    //read_lock_bh (&netlk_socklist_lock);
    hsk = netlk_sk(sk);
    /* Set multicast group. */
    snl->nl_pid    = hsk->pid;
    snl->nl_groups = hsk->groups;


    /* Read unlock. */
    //read_unlock_bh (&netlk_socklist_lock);
    if (len)
        *len = sizeof (struct netl_sockaddr_nl);

    return 0;
}


/*
   HSL process message from client.
*/
int
netlk_sock_process_msg_default (struct socket *sock, char *buf, int buflen) {
    struct netl_nlmsghdr *hdr;
    char *msgbuf;
    u_char *pnt; 
    u_int32_t size;
    
    hdr = (struct netl_nlmsghdr *)buf;
    msgbuf = buf + sizeof (struct netl_nlmsghdr);
    pnt = (u_char *)msgbuf;
    size = hdr->nlmsg_len - NETL_NLMSG_ALIGN(NETL_NLMSGHDR_SIZE);
    
    //printk("netlk_sock_process_msg() type %d \n", hdr->nlmsg_type);
    switch (hdr->nlmsg_type) {


    default:
        NETLK_MSG_PROCESS_RETURN_WITH_VALUE (sock, hdr, 0);
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
    //printk(KERN_ALERT "#%s\n", __func__);
    /* Allocate work memory. */
    buf = (u_char *) kmalloc (len, GFP_KERNEL);
    if (! buf)
        goto ERR;

    /* Returns -EFAULT on error */
    err = memcpy_fromiovec ((unsigned char *)buf, msg->msg_iov, len);
    if (err)
        goto ERR;

    /* Process message. */
    if(netlk_sock_process_msg_hook) {
        (*netlk_sock_process_msg_hook)(sock, (char *)buf, len);
    }

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
    
    //printk(KERN_ALERT "#%s\n", __func__);
    sk = sock->sk;
    if (! sk)
        return -EINVAL;

    /* Read lock. */
    //read_lock_bh (&netlk_socklist_lock);
    hsk = netlk_sk(sk);
    /* Set multicast group. */
    snl.nl_pid    = hsk->pid;
    snl.nl_groups = hsk->groups;


    /* Read unlock. */
    //read_unlock_bh (&netlk_socklist_lock);

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
    
    //printk(KERN_ALERT "#%s\n", __func__);
    if (! sk)
        return -EINVAL;

    /* Write lock. */
    //write_lock_bh (&netlk_socklist_lock);

    hsk = netlk_sk(sk);
    /* Set multicast group. */
    hsk->groups = nl_sockaddr->nl_groups;
    hsk->pid = (u_int32_t)((long)sk);

    /* Write unlock. */
    //write_unlock_bh (&netlk_socklist_lock);

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
netlk_sock_init (netlk_sock_process_msg_func_t cb) {
    int ret;
    if(cb) {
        netlk_sock_process_msg_hook = cb;
    } else {
        netlk_sock_process_msg_hook = netlk_sock_process_msg_default;
    }
    ret = sock_register (&netlk_family_ops);
    //printk("#%s() %d module ref %d\n",__func__, __LINE__, module_refcount(THIS_MODULE));
    return ret;
}

/* HSL socket deinitialization. */
int
netlk_sock_deinit (void) {
    //printk("#%s() %d module ref %d\n",__func__, __LINE__, module_refcount(THIS_MODULE));
    sock_unregister (AF_NETL);
    //printk("#%s() %d module ref %d\n",__func__, __LINE__, module_refcount(THIS_MODULE));
    netlk_sock_process_msg_hook = NULL;
    return 0;
}

/*
  HSL Socket Interface event function.
*/
int
netlk_sock_if_event (int cmd, void *param1, void *param2) {
    return 0;
}

/* struct module *owner = sock->ops->owner; module_put(owner); */

