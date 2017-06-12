/* Copyright 2003 IP Infusion, Inc. All Rights Reserved.  */

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"

/*
   Broadcom includes.
*/
//#include "bcm_incl.h"

/*
   HAL includes.
*/
#include "hal_types.h"
#include "hal_l2.h"
#include "hal_msg.h"

/* HSL includes.*/
#include "hsl_types.h"
#include "hsl_logger.h"
#include "hsl_ether.h"
#include "hsl.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_if_os.h"
#include "hsl_ctc_if.h"
#include "hsl_l2_sock.h"

#include "hal_netlink.h"
#include "hal_socket.h"
#include "hal_msg.h"

#include "hsl_ctc_pkt.h"

/* List of all HSL backend sockets. */
#if 0   /* EWAN linux2.4 */
static struct sock *_stp_socklist = 0;
#else   /* EWAN linux2.6 */
static HLIST_HEAD(_stp_socklist);
#endif
static rwlock_t _stp_socklist_lock = __RW_LOCK_UNLOCKED(_stp_socklist_lock);//RW_LOCK_UNLOCKED;

int stp_sock_create (struct socket *sock, int protocol);
/* Private packet socket structures. */

/* Forward declarations. */
static int _stp_sock_release (struct socket *sock);
static int _stp_sock_create (struct net *net, struct socket *sock, int protocol, int kern);
#if 0   /* EWAN 0921 linux2.4 */
static int _stp_sock_sendmsg (struct socket *sock, struct msghdr *msg, int len,
struct scm_cookie *scm);
static int _stp_sock_recvmsg (struct socket *sock, struct msghdr *msg, int len,
int flags, struct scm_cookie *scm);
#else   /* EWAN 0921 linux2.6 */
static int _stp_sock_sendmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len);
static int _stp_sock_recvmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);
#endif

static struct proto_ops stp_ops = {
  family:	AF_STP,
#if 1   /* EWAN linux2.6 */
  .owner    =   THIS_MODULE,
#endif

  release:	_stp_sock_release,
  bind:		sock_no_bind,
  connect:	sock_no_connect,
  socketpair:	sock_no_socketpair,
  accept:	sock_no_accept,
  getname:	sock_no_getname,
  poll:		datagram_poll,
  ioctl:	sock_no_ioctl,
  listen:	sock_no_listen,
  shutdown:	sock_no_shutdown,
  setsockopt:	sock_no_setsockopt,
  getsockopt:	sock_no_getsockopt,
  sendmsg:	_stp_sock_sendmsg,
  recvmsg:	_stp_sock_recvmsg,
  mmap:		sock_no_mmap,
  sendpage:	sock_no_sendpage,
};

static struct net_proto_family stp_family_ops = {
  family:		AF_STP,
  create:		_stp_sock_create,
#if 1   /* EWAN linux2.6 */
  .owner    =   THIS_MODULE,
#endif
};


/* Destruct socket. */
static void 
_stp_sock_destruct (struct sock *sk)
{
  //struct sock **skp;
#if 1   /* EWAN linux2.6 */
    struct sock *s;
    struct hlist_node *node;
#endif

  if (!sk)
    return;

  write_lock_bh (&_stp_socklist_lock);
#if 0   /* EWAN linux2.4 */
  for (skp = &_stp_socklist; *skp; skp = &(*skp)->next)
    {
      if (*skp == sk)
        {
          *skp = sk->next;
          break;
        }
    }
#else   /* EWAN linux2.6 */

	//by chentao
   // sk_for_each(s, node, &_stp_socklist) {
   	  sk_for_each(s, &_stp_socklist) {
        if (s == sk) {
            sk_del_node_init(s);
            break;
        }
    }
#endif
  write_unlock_bh (&_stp_socklist_lock);

  /*
   *	Now the socket is dead. No more input will appear.
   */
  sock_orphan (sk);

  /* Purge queues */
#if 0   /* EWAN  linux2.4 */
  skb_queue_purge (&sk->receive_queue);
#else   /* EWAN  linux2.6 */
  skb_queue_purge (&sk->sk_receive_queue);
#endif

  sock_put (sk);
}

/* Release socket. */
static int 
_stp_sock_release (struct socket *sock)
{
  struct sock *sk = sock->sk;
  //struct sock **skp;
#if 1   /* EWAN linux2.6 */
    struct sock *s;
    struct hlist_node *node;
#endif

  if (!sk)
    return 0;

  write_lock_bh (&_stp_socklist_lock);
#if 0   /* EWAN linux2.4 */
  for (skp = &_stp_socklist; *skp; skp = &(*skp)->next)
    {
      if (*skp == sk)
        {
          *skp = sk->next;
          break;
        }
    }
#else   /* EWAN linux2.4 */
    //by chentao
   // sk_for_each(s, node, &_stp_socklist) {
   	  sk_for_each(s, &_stp_socklist) {
        if (s == sk) {
            sk_del_node_init(s);
            break;
        }
    }
#endif
  write_unlock_bh (&_stp_socklist_lock);

  /*
   *	Now the socket is dead. No more input will appear.
   */

  sock_orphan (sk);
  sock->sk = NULL;

  /* Purge queues */
#if 0   /* EWAN linux2.4 */
  skb_queue_purge (&sk->receive_queue);
#else   /* EWAN linux2.6 */
  skb_queue_purge (&sk->sk_receive_queue);
#endif

  sock_put (sk);

  return 0;
}

static struct proto stp_proto = {
        .name     = "STP",
        .owner    = THIS_MODULE,
        .obj_size = sizeof(struct sock),
};

/* Create socket. */
static int 
_stp_sock_create (struct net *net, struct socket *sock, int protocol, int kern)
{
  struct sock *sk;

  if (!capable (CAP_NET_RAW))
    return -EPERM;
  if (sock->type  != SOCK_RAW)
    return -ESOCKTNOSUPPORT;

  sock->state = SS_UNCONNECTED;

#if 0   /* EWAN linux2.4 */
  sk = sk_alloc (AF_STP, GFP_KERNEL, 1);
#else   /* EWAN linux2.6 */
  sk = sk_alloc (net, AF_STP, GFP_KERNEL, &stp_proto);
#endif
  if (sk == NULL)
    {
      return -ENOBUFS;
    }

  sock->ops = &stp_ops;
  sock_init_data (sock,sk);
#if 1   /* EWAN linux2.6 */
  //sk_set_owner(sk, THIS_MODULE);
#endif

#if 0   /* EWAN linux2.4 */
  sk->family = AF_STP;
  sk->num = protocol;
  sk->destruct = _stp_sock_destruct;
#else   /* EWAN linux2.6 */
  sk->sk_family = AF_STP;
  sk->sk_protocol = protocol;
  sk->sk_destruct = _stp_sock_destruct;
#endif

  sock_hold (sk);

  write_lock_bh (&_stp_socklist_lock);
#if 0   /* EWAN linux2.4 */
  sk->next = _stp_socklist;
  _stp_socklist = sk;
#else   /* EWAN linux2.6 */
  sk_add_node(sk, &_stp_socklist);
#endif
  write_unlock_bh (&_stp_socklist_lock);
  return 0;
}

/* Sendmsg. */
static int 
#if	0	/* NETFORD-linux_2.6 */
_stp_sock_sendmsg (struct socket *sock, struct msghdr *msg, int len,
		   struct scm_cookie *scm)
#else
_stp_sock_sendmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
#endif
{
	int ret = 0;
	u_char *buf = NULL;
	u_char *send_buf = NULL;
	uint32 send_len = 0;
	struct sockaddr_l2 *s = NULL;
	struct hsl_if *ifp = NULL;
	struct hsl_bcm_if *sifp = NULL;
	struct hsl_eth_header *eth = NULL;
	uint16 port = 0;
	
	s = (struct sockaddr_l2 *)msg->msg_name;

	
	ifp = hsl_ifmgr_lookup_by_index (s->port);
	if (!ifp) {
		ret = -EINVAL;
		goto RET;
	}
	
	if (ifp->type == HSL_IF_TYPE_L2_ETHERNET) {
		sifp = ifp->system_info;
		if (!sifp) {
			HSL_IFMGR_IF_REF_DEC (ifp);
			ret = -EINVAL;
			goto RET;
		}
		if (sifp->trunk_id >= 0) {
			/* Get first member port. */
			if (ifp->children_list 
				&& ifp->children_list->ifp) {
				sifp = ifp->children_list->ifp->system_info;
			} else {
				HSL_IFMGR_IF_REF_DEC (ifp);
				ret = -EINVAL;
				goto RET;
			}		
		}
		port = sifp->u.l2.lport;	
	} else {
		HSL_IFMGR_IF_REF_DEC (ifp);
		ret = -EINVAL;
		goto RET;
	}
	HSL_IFMGR_IF_REF_DEC (ifp);

	//分配PM传递下来的数据BUFF
	buf = kmalloc (len, GFP_KERNEL);
	if (! buf) {
		ret = -ENOMEM;
		goto RET;
	}
	
	//分配最后组好的包BUFF
	send_buf = kmalloc (len + ENET_UNTAGGED_HDR_LEN, GFP_KERNEL);
	if (!send_buf) {
		ret = -ENOMEM;
		goto RET;
	}	
	
	/* Copy from iov's */
	ret = memcpy_fromiovec (buf, msg->msg_iov, len);
	if (ret < 0) {
	  ret = -ENOMEM;
	  goto RET;
	}
	
	/*build l2 header*/
	eth = (struct hsl_eth_header *) send_buf;
	memcpy (eth->dmac, s->dest_mac, 6);
	memcpy (eth->smac, s->src_mac, 6);	
	eth->d.type = htons (len);
	memcpy (send_buf+ENET_UNTAGGED_HDR_LEN, buf, len);
	send_len = len + ENET_UNTAGGED_HDR_LEN;
	#if 0
	ret = hsl_packet_tx_generic (send_buf, send_len, CTC_PKT_MODE_DMA, 1, 0,
								port, 0, 0, 1, 0, 0, 0, 0, 0, 0);
    #else
    //ret = hsl_ctc_pkt_send (send_buf, send_len, port, 0, FALSE);
    ret = 0;
    #endif
	if (ret < 0) {
		printk ("ctc send packet failed! ret=%d\n", ret);
		goto RET;
	}
    
	
	
RET:
	if (buf) {
		kfree (buf);
        buf = NULL;
	}
	if (send_buf) {
		kfree (send_buf);
        send_buf = NULL;
	}
 return ret;

}


/* Recvmsg. */
static int 
#if	0	/* NETFORD-linux_2.6 */
_stp_sock_recvmsg (struct socket *sock, struct msghdr *msg, int len,
		   int flags, struct scm_cookie *scm)
#else
_stp_sock_recvmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags)
#endif
{
  int size = sizeof (struct sockaddr_l2);
  struct sk_buff *skb;
  struct sock *sk = sock->sk;
  int copied;
  int ret;

  if (! sk)
    return -EINVAL;

  /* Receive one msg from the queue. */
  skb = skb_recv_datagram (sk, flags, flags & MSG_DONTWAIT, &ret);
  if (! skb)
    return -EINVAL;

  /* Copy sockaddr_l2. */
  if (msg->msg_name)
    memcpy (msg->msg_name, (struct sockaddr_l2 *) skb->data, size);
  msg->msg_namelen = size;

  /* Pull data of sockaddr_l2 from skb. */
  skb_pull (skb, size);

    /* Did user send lesser buffer? */
  copied = skb->len;
  if (copied > len)
    {
      copied = len;
      msg->msg_flags |= MSG_TRUNC;
    }

  /* Copy message. */
  ret = skb_copy_datagram_iovec (skb, 0, msg->msg_iov, copied);
  if (ret < 0)
    {
      skb_free_datagram (sk, skb);
      return ret;
    }

  sock_recv_timestamp (msg, sk, skb);
  
  /* Free. */
  skb_free_datagram (sk, skb);

  return copied;
}

/* Post packet. */
int 
hsl_af_stp_post_packet (struct sk_buff *skb)
{
  struct sock * sk; 
  struct sk_buff *skbc;
#if 1   /* EWAN linux2.6 */
    struct hlist_node *node;
#endif

  /* Read lock. */
  read_lock_bh (&_stp_socklist_lock);

  /* Is there room to schedule the packet */
#if 0   /* EWAN linux2.4 */
  for (sk = _stp_socklist; sk; sk = sk->next)
#else   /* EWAN linux2.6 */
//by chentao change
 // sk_for_each(sk, node, &_stp_socklist)
    sk_for_each(sk, &_stp_socklist)
#endif
    {
      /* Skip dead sockets. */
#if 0   /* EWAN linux2.4 */
      if (sk->dead)
#else   /* EWAN linux2.6 */
      if (sock_flag (sk, SOCK_DEAD))
#endif
        {
          continue;
        }

      /* Check if there is space. */
#if 0   /* EWAN linux2.4 */
      if (atomic_read (&sk->rmem_alloc) + skb->truesize > (unsigned)sk->rcvbuf)
#else   /* EWAN linux2.6 */
      if (atomic_read (&sk->sk_rmem_alloc) + skb->truesize > (unsigned)sk->sk_rcvbuf)
#endif
        {
          continue;
        }

      /* Clone the skb. */
      skbc = skb_clone (skb, GFP_ATOMIC);
      if (! skbc)
	{
	  /* Continue with next. */
	  continue;
	}

      /* Post this skb. */
      hsl_sock_post_skb (sk, skbc);
    }

  /* Read unlock. */
  read_unlock_bh (&_stp_socklist_lock);

  return 0;
}

/* HSL socket initialization. */
int
hsl_af_stp_sock_init (void)
{
  
  int ret;
  ret = sock_register (&stp_family_ops);
  printk("stp sk = %d\r\n", ret);
  return 0;
}

/* HSL socket deinitialization. */
int
hsl_af_stp_sock_deinit (void)
{
  sock_unregister (AF_STP);
  return 0;
}

