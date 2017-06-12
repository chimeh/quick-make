/* Copyright 2015 galaxywind Inc. All Rights Reserved.  */

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"

/*
   Broadcom includes.
*/
#include "bcm_incl.h"

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
#include "hsl_bcm_if.h"
#include "hsl_bcm_pkt.h"
#include "hsl_l2_sock.h"

#include "hal_netlink.h"
#include "hal_socket.h"
#include "hal_msg.h"

static HLIST_HEAD(_of_socklist);
static rwlock_t _of_socklist_lock = __RW_LOCK_UNLOCKED(_of_socklist_lock);//RW_LOCK_UNLOCKED;

struct of_sock {
	struct sock sk;
    int non_arp_packet_in_count;
};

#define OFP_SOCK(sk) ((struct of_sock*)sk)

int of_sock_create (struct socket *sock, int protocol);
/* Private packet socket structures. */

/* Forward declarations. */
static int _of_sock_release (struct socket *sock);
static int _of_sock_create (struct net *net, struct socket *sock, int protocol);

static int _of_sock_sendmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len);
static int _of_sock_recvmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);

static struct proto_ops of_ops = {
  family:	AF_OF,
  .owner    =   THIS_MODULE,

  release:	_of_sock_release,
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
  sendmsg:	_of_sock_sendmsg,
  recvmsg:	_of_sock_recvmsg,
  mmap:		sock_no_mmap,
  sendpage:	sock_no_sendpage,
};

static struct net_proto_family of_family_ops = {
  family:		AF_OF,
  create:		_of_sock_create,
  .owner    =   THIS_MODULE,
};


/* Destruct socket. */
static void 
_of_sock_destruct (struct sock *sk)
{
    //struct sock **skp;
    struct sock *s;
    struct hlist_node *node;

    if (!sk) {
        return;
    }

    write_lock_bh (&_of_socklist_lock);


    sk_for_each(s, node, &_of_socklist) {
        if (s == sk) {
            sk_del_node_init(s);
            break;
        }
    }
    write_unlock_bh (&_of_socklist_lock);

    /*
    *	Now the socket is dead. No more input will appear.
    */
    sock_orphan (sk);

    skb_queue_purge (&sk->sk_receive_queue);

    sock_put (sk);
}

/* Release socket. */
static int 
_of_sock_release (struct socket *sock)
{
    struct sock *sk = sock->sk;
    //struct sock **skp;
    struct sock *s;
    struct hlist_node *node;

    if (!sk) {
        return 0;
    }

    write_lock_bh (&_of_socklist_lock);

    sk_for_each(s, node, &_of_socklist) {
        if (s == sk) {
            sk_del_node_init(s);
            break;
        }
    }
    write_unlock_bh (&_of_socklist_lock);

    /*
    *	Now the socket is dead. No more input will appear.
    */

    sock_orphan (sk);
    sock->sk = NULL;

    /* Purge queues */

    skb_queue_purge (&sk->sk_receive_queue);

    sock_put (sk);

    return 0;
}

static struct proto of_proto = {
        .name     = "OPENFLOW",
        .owner    = THIS_MODULE,
        .obj_size = sizeof(struct of_sock),
};


/* Create socket. */
static int 
_of_sock_create (struct net *net, struct socket *sock, int protocol)
{
    struct sock *sk;

    if (!capable (CAP_NET_RAW)) {
        return -EPERM;
    }
    
    if (sock->type  != SOCK_RAW) {
        return -ESOCKTNOSUPPORT;
    }

    sock->state = SS_UNCONNECTED;

    sk = sk_alloc (net, AF_OF, GFP_KERNEL, &of_proto);
    if (sk == NULL){
        return -ENOBUFS;
    }

    sock->ops = &of_ops;
    sock_init_data (sock,sk);


    sk->sk_family = AF_OF;
    sk->sk_protocol = protocol;
    sk->sk_destruct = _of_sock_destruct;
    OFP_SOCK(sk)->non_arp_packet_in_count = 0;
    sock_hold (sk);

    write_lock_bh (&_of_socklist_lock);
    sk_add_node(sk, &_of_socklist);
    write_unlock_bh (&_of_socklist_lock);

    return 0;
}

/* Sendmsg. */
static int 
_of_sock_sendmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
{
  bcm_pkt_t *pkt = NULL;
  int ret = 0;
  u_char *hdr = NULL;
  u_char *buf = NULL;
  struct sockaddr_of *s;
  struct hsl_if *ifp, *ifp2;
  struct hsl_bcm_if *sifp;
  bcmx_lport_t dport;
  struct hsl_eth_header *eth;
  

  s = (struct sockaddr_of *)msg->msg_name;
  ifp = hsl_ifmgr_lookup_by_index (s->port);
  if (! ifp)
    {
      ret = -EINVAL;
      goto RET;
    }

  if (ifp->type == HSL_IF_TYPE_L2_ETHERNET)
    {
      sifp = ifp->system_info;
      if (! sifp)
	{
	  HSL_IFMGR_IF_REF_DEC (ifp);
	  ret = -EINVAL;
	  goto RET;
	}
      dport = sifp->u.l2.lport;
    }
  else if (ifp->type == HSL_IF_TYPE_IP)
    {
      ifp2 = hsl_ifmgr_get_first_L2_port (ifp);
      if (! ifp2)
        {
          HSL_IFMGR_IF_REF_DEC (ifp);
          goto RET;
        }
      sifp = ifp2->system_info;
      if (! sifp)
        {
          HSL_IFMGR_IF_REF_DEC (ifp);
          HSL_IFMGR_IF_REF_DEC (ifp2);
          goto RET;
        }
      dport = sifp->u.l2.lport;
    }
  else
    {
      HSL_IFMGR_IF_REF_DEC (ifp);
      ret = -EINVAL;
      goto RET; 
    }

  HSL_IFMGR_IF_REF_DEC (ifp);

  /* Allocate pkt info structure. One for the header and one for the body. */
  pkt = hsl_bcm_tx_pkt_alloc (1);
  if (! pkt)
    {
      ret = -ENOMEM;
      goto RET;
    }
    
    /* Set packet flags. */
  SET_FLAG (pkt->flags, BCM_TX_CRC_APPEND);

  /* Set COS to highest. */
  pkt->cos = 1;


    /* Allocate buffer for body. */
  buf = kmalloc (len, GFP_KERNEL);
  if (! buf)
    {
      ret = -ENOMEM;
      goto RET;
    }

  /* Set body. */
  pkt->pkt_data[0].data = buf;
  pkt->pkt_data[0].len = len;
  
  /* Copy from iov's */
  ret = memcpy_fromiovec (buf, msg->msg_iov, len);
  if (ret < 0)
    {
      ret = -ENOMEM;
      goto RET;
    }

  if (*(unsigned short*)(buf+12) != htons (0x8100)) {
      SET_FLAG (pkt->flags, BCM_PKT_F_NO_VTAG);
  }
  

  /* Send packet. */
  ret = hsl_bcm_pkt_send (pkt, dport, 0);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_ERROR, "Error sending openflow frame out on dport(%d)\n", dport);
      ret = -EINVAL;
      goto RET;
    }

  ret = len;

 RET:
  if (pkt)
    hsl_bcm_tx_pkt_free (pkt);

  if (buf)
    kfree (buf);

  return ret;
}


/* Recvmsg. */
static int 
#if 0   /* EWAN linux2.6 */
_lacp_sock_recvmsg (struct socket *sock, struct msghdr *msg, int len,
		    int flags, struct scm_cookie *scm)
#else
_of_sock_recvmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags)
#endif
{
  int size = sizeof (struct sockaddr_of);
  struct sockaddr_l2 *s = NULL;
  struct hsl_if *ifp = NULL;
  struct hsl_if *ifpl3 = NULL;
  struct hsl_if_list *node = NULL;
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
  if (msg->msg_name){
        memcpy (msg->msg_name, (struct sockaddr_of *) skb->data, size);
    }
  msg->msg_namelen = size;

    if (((struct sockaddr_of *) skb->data)->pkt_type != 0x0806) {
        if (OFP_SOCK(sk)->non_arp_packet_in_count > 0) {
            OFP_SOCK(sk)->non_arp_packet_in_count--;
        }
    }

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

ERR:
  if (sk && skb)
    skb_free_datagram(sk, skb);
  return -1;
}

/* Post packet. */
int 
hsl_af_of_post_packet (struct sk_buff *skb, int pkt_type)
{
  struct sock * sk; 
  struct sk_buff *skbc;
#if 1   /* EWAN linux2.6 */
    struct hlist_node *node;
#endif

  /* Read lock. */
  read_lock_bh (&_of_socklist_lock);

  /* Is there room to schedule the packet */
#if 0   /* EWAN linux2.4 */
  for (sk = _lacp_socklist; sk; sk = sk->next)
#else   /* EWAN linux2.6 */
  sk_for_each(sk, node, &_of_socklist)
#endif
    {
      /* Skip dead sockets. */
#if 0   /* EWAN linux2.4 */
      if (sk->dead)
#else   /* EWAN linux2.6 */
      if (sock_flag (sk, SOCK_DEAD))
#endif
        {
          HSL_LOG (HSL_LOG_PKTDRV,HSL_LEVEL_INFO,"sk is dead.\n");
          continue;
        }
      
      /* Check if there is space. */
#if 0   /* EWAN linux2.4 */
      if (atomic_read (&sk->rmem_alloc) + skb->truesize > (unsigned)sk->rcvbuf)
#else   /* EWAN linux2.6 */
      if (atomic_read (&sk->sk_rmem_alloc) + skb->truesize > (unsigned)sk->sk_rcvbuf)
#endif
        {
          HSL_LOG (HSL_LOG_PKTDRV,HSL_LEVEL_INFO,"sk buffer is full.\n");
          continue;
        }

        if (pkt_type != 0x0806) {
            if (OFP_SOCK(sk)->non_arp_packet_in_count > 1024) {
                HSL_LOG (HSL_LOG_PKTDRV,HSL_LEVEL_INFO,"no arp packet is too more.\n");
                continue;
            }
            OFP_SOCK(sk)->non_arp_packet_in_count++;
        }

      /* Clone the skb. */
      skbc = skb_clone (skb, GFP_ATOMIC);
      if (! skbc)
	{
      HSL_LOG (HSL_LOG_PKTDRV,HSL_LEVEL_INFO,"skb clone is fail.\n");
	  /* Continue with next. */
	  continue;
	}
      /* Post this skb. */
      hsl_sock_post_skb (sk, skbc);
    }

  /* Read unlock. */
  read_unlock_bh (&_of_socklist_lock);

  return 0;
}

/* HSL socket initialization. */
int
hsl_af_of_sock_init (void)
{
  
  int ret;
  ret = sock_register (&of_family_ops);
  printk("openflow sk = %d\r\n", ret);
  return 0;
}

/* HSL socket deinitialization. */
int
hsl_af_of_sock_deinit (void)
{
  sock_unregister (AF_OF);
  return 0;
}


