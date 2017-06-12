/* Copyright 2003 IP Infusion, Inc. All Rights Reserved.  */

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
#include "hsl_vlan.h"

/* List of all HSL backend sockets. */
#if 0   /* EWAN linux2.4 */
static struct sock *_garp_socklist = 0;
#else   /* EWAN linux2.6 */
static HLIST_HEAD(_garp_socklist);
#endif
static rwlock_t _garp_socklist_lock = __RW_LOCK_UNLOCKED(_garp_socklist_lock);//RW_LOCK_UNLOCKED;

int garp_sock_create (struct socket *sock, int protocol);
/* Private packet socket structures. */

/* Forward declarations. */
static int _garp_sock_release (struct socket *sock);
static int _garp_sock_create (struct net *net, struct socket *sock, int protocol);
#if	0	/* NETFORD-linux_2.6 */
static int _garp_sock_sendmsg (struct socket *sock, struct msghdr *msg, int len, struct scm_cookie *scm);
static int _garp_sock_recvmsg (struct socket *sock, struct msghdr *msg, int len, int flags, struct scm_cookie *scm);
#else
static int _garp_sock_sendmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len);
static int _garp_sock_recvmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);
#endif

static struct proto_ops garp_ops = {
  family:	AF_GARP,
#if 1   /* EWAN linux2.6 */
  .owner    =   THIS_MODULE,
#endif

  release:	_garp_sock_release,
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
  sendmsg:	_garp_sock_sendmsg,
  recvmsg:	_garp_sock_recvmsg,
  mmap:		sock_no_mmap,
  sendpage:	sock_no_sendpage,
};

static struct net_proto_family garp_family_ops = {
  family:		AF_GARP,
  create:		_garp_sock_create,
#if 1   /* EWAN linux2.6 */
  .owner    =   THIS_MODULE,
#endif
};


/* Destruct socket. */
static void 
_garp_sock_destruct (struct sock *sk)
{
  //struct sock **skp;
#if 1   /* EWAN linux2.6 */
    struct sock *s;
    struct hlist_node *node;
#endif

  if (!sk)
    return;

  write_lock_bh (&_garp_socklist_lock);
#if 0   /* EWAN linux2.4 */
  for (skp = &_garp_socklist; *skp; skp = &(*skp)->next)
    {
      if (*skp == sk)
        {
          *skp = sk->next;
          break;
        }
    }
#else   /* EWAN linux2.6 */
    sk_for_each(s, node, &_garp_socklist) {
        if (s == sk) {
            sk_del_node_init(s);
            break;
        }
    }
#endif
  write_unlock_bh (&_garp_socklist_lock);

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
_garp_sock_release (struct socket *sock)
{
  struct sock *sk = sock->sk;
  //struct sock **skp;
#if 1   /* EWAN linux2.6 */
    struct sock *s;
    struct hlist_node *node;
#endif

  if (!sk)
    return 0;

  write_lock_bh (&_garp_socklist_lock);
#if 0   /* EWAN linux2.4 */
  for (skp = &_garp_socklist; *skp; skp = &(*skp)->next)
    {
      if (*skp == sk)
        {
          *skp = sk->next;
          break;
        }
    }
#else   /* EWAN linux2.6 */
    sk_for_each(s, node, &_garp_socklist) {
        if (s == sk) {
            sk_del_node_init(s);
            break;
        }
    }
#endif
  write_unlock_bh (&_garp_socklist_lock);

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


static struct proto garp_proto = {
        .name     = "GARP",
        .owner    = THIS_MODULE,
        .obj_size = sizeof(struct sock),
};


/* Create socket. */
static int 
_garp_sock_create (struct net *net, struct socket *sock, int protocol)
{
  struct sock *sk;

  if (!capable (CAP_NET_RAW))
    return -EPERM;
  if (sock->type  != SOCK_RAW)
    return -ESOCKTNOSUPPORT;

  sock->state = SS_UNCONNECTED;

#if 0   /* EWAN linux2.4 */
  sk = sk_alloc (AF_GARP, GFP_KERNEL, 1);
#else   /* EWAN linux2.6 */
  sk = sk_alloc (net, AF_GARP, GFP_KERNEL, &garp_proto);
#endif
  if (sk == NULL)
    {
      return -ENOBUFS;
    }

  sock->ops = &garp_ops;
  sock_init_data (sock,sk);
#if 1   /* EWAN linux2.6 */
  //sk_set_owner(sk, THIS_MODULE);
#endif

#if 0   /* EWAN linux2.4 */
  sk->family = AF_GARP;
  sk->num = protocol;
  sk->destruct = _garp_sock_destruct;
#else   /* EWAN linux2.6 */
  sk->sk_family = AF_GARP;
  sk->sk_protocol = protocol;
  sk->sk_destruct = _garp_sock_destruct;
#endif

  sock_hold (sk);

  write_lock_bh (&_garp_socklist_lock);
#if 0   /* EWAN linux2.4 */
  sk->next = _garp_socklist;
  _garp_socklist = sk;
#else   /* EWAN linux2.6 */
  sk_add_node(sk, &_garp_socklist);
#endif
  write_unlock_bh (&_garp_socklist_lock);
  return 0;
}

/* Sendmsg. */
static int 
#if	0	/* NETFORD-linux_2.6 */
_garp_sock_sendmsg (struct socket *sock, struct msghdr *msg, int len,
		    struct scm_cookie *scm)
#else
_garp_sock_sendmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
#endif
{
  bcm_pkt_t *pkt = NULL;
  int ret = 0;
  u_char *hdr = NULL;
  u_char *buf = NULL;
  struct sockaddr_vlan *s;
  struct hsl_if *ifp;
  struct hsl_bcm_if *sifp;
  bcmx_lport_t dport;
  struct hsl_eth_header *eth;
  int tagged = 0;

  s = (struct sockaddr_vlan *)msg->msg_name;

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

      if (sifp->trunk_id >= 0)
        {
          /* Get first member port. */
          if (ifp->children_list
              && ifp->children_list->ifp)
            {
              sifp = ifp->children_list->ifp->system_info;
            }
          else
            {
              HSL_IFMGR_IF_REF_DEC (ifp);
              ret = -EINVAL;
              goto RET;
            }
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
  pkt = hsl_bcm_tx_pkt_alloc (2);
  if (! pkt)
    {
      ret = -ENOMEM;
      goto RET;
    }

  /* Set packet flags. */
  SET_FLAG (pkt->flags, BCM_TX_CRC_APPEND);

  /* Set COS to highest. */
  pkt->cos = 1;

  /* Allocate buffer for header. */
  hdr = kmalloc (ENET_TAGGED_HDR_LEN, GFP_KERNEL);
  if (! hdr)
    {
      ret = -ENOMEM;
      goto RET;
    }

  /* Set header. */
  pkt->pkt_data[0].data = hdr;
  pkt->pkt_data[0].len = ENET_TAGGED_HDR_LEN;

  /* Allocate buffer for body. */
  buf = kmalloc (len, GFP_KERNEL);
  if (! buf)
    {
      ret = -ENOMEM;
      goto RET;
    }

  /* Copy from iov's */
  ret = memcpy_fromiovec (buf, msg->msg_iov, len);
  if (ret < 0)
    {
      ret = -ENOMEM;
      goto RET;
    }

  /* Set body. */
  pkt->pkt_data[1].data = buf;
  pkt->pkt_data[1].len = len;

  /* Set ETH header. */
  eth = (struct hsl_eth_header *) hdr;
  memset (eth, 0, sizeof (struct hsl_eth_header));
  memcpy (eth->dmac, s->dest_mac, 6);
  memcpy (eth->smac, s->src_mac, 6);
  eth->d.vlan.tag_type = htons (0x8100);
 
  if (!s->vlanid)
    {
      tagged = 0;
  HSL_ETH_VLAN_SET_VID (eth->d.vlan.pri_cif_vid, 1);
    }
  else
    {
      tagged = hsl_vlan_get_egress_type (ifp, s->vlanid);
      HSL_ETH_VLAN_SET_VID (eth->d.vlan.pri_cif_vid, s->vlanid);
    }
  eth->d.vlan.type = htons (len);
  
  /* Send packet. */
  if (tagged)
    ret = hsl_bcm_pkt_send (pkt, dport, 1);
  else
  ret = hsl_bcm_pkt_send (pkt, dport, 0);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_ERROR, "Error sending GARP frame out on dport(%d)\n", dport);
      ret = -EINVAL;
      goto RET;
    }

  ret = 0;

 RET:
  if (pkt)
    hsl_bcm_tx_pkt_free (pkt);
  if (hdr)
    kfree (hdr);
  if (buf)
    kfree (buf);

  return ret;
}


/* Recvmsg. */
static int 
#if	0	/* NETFORD-linux_2.6 */
_garp_sock_recvmsg (struct socket *sock, struct msghdr *msg, int len,
		    int flags, struct scm_cookie *scm)
#else
_garp_sock_recvmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags)
#endif
{
  int size = sizeof (struct sockaddr_vlan);
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

  /* Copy sockaddr_vlan. */
  if (msg->msg_name)
    memcpy (msg->msg_name, (struct sockaddr_vlan *) skb->data, size);
  msg->msg_namelen = size;

  /* Pull data of sockaddr_vlan from skb. */
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
hsl_af_garp_post_packet (struct sk_buff *skb)
{
  struct sock * sk; 
  struct sk_buff *skbc;
#if 1   /* EWAN linux2.6 */
    struct hlist_node *node;
#endif

  /* Read lock. */
  read_lock_bh (&_garp_socklist_lock);

  /* Is there room to schedule the packet */
#if 0   /* EWAN linux2.4 */
  for (sk = _garp_socklist; sk; sk = sk->next)
#else   /* EWAN linux2.6 */
  sk_for_each(sk, node, &_garp_socklist)
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
  read_unlock_bh (&_garp_socklist_lock);

  return 0;
}

/* HSL socket initialization. */
int
hsl_af_garp_sock_init (void)
{
  
  int ret;
  ret = sock_register (&garp_family_ops);
  printk("garp sk = %d\r\n", ret);
  return 0;
}

/* HSL socket deinitialization. */
int
hsl_af_garp_sock_deinit (void)
{
  sock_unregister (AF_GARP);
  return 0;
}

