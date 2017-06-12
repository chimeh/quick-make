/* Copyright (C) 2004-2005 IP Infusion, Inc.  All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"

#include "hsl_types.h"
                                                                                
//#include "bcm_incl.h"
                                                                                
/* HAL includes. */
#include "hal_netlink.h"
#include "hal_msg.h"

#include "hsl_avl.h"
#include "hsl.h"
#include "hsl_oss.h"
#include "hsl_comm.h"
#include "hsl_logger.h"
#include "hsl_ifmgr.h"
#include "hsl_msg.h"
#include "hsl_tlv.h"
#include "hsl_ether.h"

//by chentao add
#include "hsl_mac_tbl.h"
#include "hsl_ctc_ipmc.h"


#ifdef HAVE_L2
#include "hsl_vlan.h"
#include "hsl_bridge.h"
//#include "bcm_incl.h"
//#include "hsl_bcm_vlanclassifier.h"
//#include "hsl_bcm_l2.h"
//#include "hsl_bcm_lacp.h"
#endif /* HAVE_L2 */
#include "fwdu_hal_id_uc.h"
#include "fwdu_hal_id_nbr.h"
#ifdef HAVE_L3
#include "hsl_table.h"
#include "hsl_fib.h"
#endif /* HAVE_L3 */
#if defined HAVE_MCAST_IPV4 || defined HAVE_MCAST_IPV6 || defined HAVE_IGMP_SNOOP
#include "hsl_mcast_fib.h"
#endif /* HAVE_MCAST_IPV4 || HAVE_MCAST_IPV6 || HAVE_IGMP_SNOOP */


#include "hsl_ctc_if.h"
#include "hsl_ctc_ifmap.h"
#include "hsl_ctc.h"
#include "ctc_if_portmap.h"
#include "vsc8512.h"

#ifdef HAVE_AUTHD
//#include "hsl_bcm_auth.h"
#endif /* HAVE_AUTHD */

#ifdef HAVE_QOS
#include "hsl_bcm_qos.h"
#endif /* HAVE_QOS */

#ifdef HAVE_L2
#ifdef HAVE_VLAN_CLASS
extern int hsl_vlan_classifier_add (struct hal_msg_vlan_classifier_rule *msg);
extern int hsl_vlan_classifier_delete (struct hal_msg_vlan_classifier_rule *msg);
#endif /* HAVE_VLAN_CLASS */
#endif /* HAVE_L2 */

//by chentao add
int 
hsl_ifmgr_clear_if_counters(hsl_ifIndex_t ifindex);
int
hsl_if_mac_learning_set (hsl_ifIndex_t ifindex, int disable);


//-------------------------------------------//
#if 0

extern int
hsl_bcm_set_ip_access_group
                 (struct hal_msg_ip_set_access_grp *msg);
extern int
hsl_bcm_unset_ip_access_group
                 (struct hal_msg_ip_set_access_grp *msg);

extern int
hsl_bcm_set_ip_access_group_interface
                 (struct hal_msg_ip_set_access_grp_interface *msg);
extern int
hsl_bcm_unset_ip_access_group_interface
                 (struct hal_msg_ip_set_access_grp_interface *msg);
#endif

#ifdef HAVE_MPLS
#include "hal_mpls_types.h"
//#include "hsl_mpls.h"
#endif /* HAVE_MPLS */
#if 0
#ifdef HAVE_L2LERN
extern int hsl_bcm_mac_set_access_grp (struct hal_msg_mac_set_access_grp *msg);
extern int hsl_bcm_vlan_set_access_map (struct hal_msg_vlan_set_access_map *msg);
#endif

extern int _bcm_esw_gport_resolve(int unit, bcm_gport_t gport,
                                  bcm_module_t *modid, bcm_port_t *port, 
                                  bcm_trunk_t *trunk_id, int *id);
#endif

extern int hsl_shape_mem_get(char *buffer, int offset, int length);

//by chentao delete
//extern int read_optical_module_register(int ifindex, struct hal_optical_module_info *info);

/* 
   Encode the interface information.
*/
static void
_hsl_map_if (struct hsl_if *ifp, struct hal_msg_if *msg, u_int32_t cindex)
{
  struct hsl_if *ifp2;

  memset (msg, 0, sizeof (struct hal_msg_if));

  msg->cindex = cindex;

  memcpy (msg->name, ifp->name, HAL_IFNAME_LEN + 1);
  msg->ifindex = ifp->ifindex;

  /* MTU */
  if (CHECK_CINDEX (cindex, HAL_MSG_CINDEX_IF_MTU))
    {
      if (ifp->type == HSL_IF_TYPE_IP)
        msg->mtu = ifp->u.ip.ipv4.mtu;
      else if (ifp->type == HSL_IF_TYPE_L2_ETHERNET)
	msg->mtu = ifp->u.l2_ethernet.mtu;
    }

  /* ARP AGEING TIMEOUT */
  if (CHECK_CINDEX (cindex, HAL_MSG_CINDEX_IF_ARP_AGEING_TIMEOUT))
    {
      if (ifp->type == HSL_IF_TYPE_IP)
        msg->arp_ageing_timeout = HSL_ARP_ALIVE_COUNTER_TO_TIMEOUT(ifp->u.ip.arpTimeout);
      else if (ifp->type == HSL_IF_TYPE_L2_ETHERNET)
        msg->arp_ageing_timeout = 0;
    }
  
  /* Flags. */
  if (CHECK_CINDEX (cindex, HAL_MSG_CINDEX_IF_FLAGS))
    msg->flags = ifp->flags;

  /* Metric. */
  if (CHECK_CINDEX (cindex, HAL_MSG_CINDEX_IF_METRIC))
    {
      /* XXX Metric is currently set to 1. */
      msg->metric = 1;
    }

  switch (ifp->type)
    {
    case HSL_IF_TYPE_IP:
      {
        msg->type = HAL_IF_ROUTER_PORT;

	/* Hardware type, address. */
	if (CHECK_CINDEX (cindex, HAL_MSG_CINDEX_IF_HW))
	  { 
	    msg->hw_addr_len = ETHER_ADDR_LEN;
	    memcpy (msg->hw_addr, ifp->u.ip.mac, ETHER_ADDR_LEN);
	    msg->hw_type = HAL_IF_TYPE_ETHERNET;
	  }

	/* Get the first L2 interface to get the speed etc. */
        ifp2 = hsl_ifmgr_get_first_L2_port (ifp);	      

	/* Bandwidth */
	if (CHECK_CINDEX (cindex, HAL_MSG_CINDEX_IF_BANDWIDTH))
	  { 
	    if (ifp2)
	      msg->bandwidth = (ifp2->u.l2_ethernet.speed * 1000) / 8;
	    else
	      msg->bandwidth = 0;
	  }
        /* Duplex */
	if (CHECK_CINDEX (cindex, HAL_MSG_CINDEX_IF_DUPLEX))
	  { 
	    if (ifp2)
	      msg->duplex = ifp2->u.l2_ethernet.duplex;
	    else
	      msg->duplex = 0;
	  }
        /* Autoneg. */ 
        if (CHECK_CINDEX (cindex, HAL_MSG_CINDEX_IF_AUTONEGO))
	  {  
	    if(ifp2)
	      msg->autonego = ifp2->u.l2_ethernet.autonego;
	    else  
	      msg->autonego = 0;
	  }

        if (ifp2)
          HSL_IFMGR_IF_REF_DEC (ifp2);
      }
      break;
    case HSL_IF_TYPE_L2_ETHERNET:
      {
        msg->type = HAL_IF_SWITCH_PORT;

	/* Hardware type, address. */
	if (CHECK_CINDEX (cindex, HAL_MSG_CINDEX_IF_HW))
	  {
	    msg->hw_addr_len = ETHER_ADDR_LEN;
	    memcpy (msg->hw_addr, ifp->u.l2_ethernet.mac, ETHER_ADDR_LEN);
	    msg->hw_type = HAL_IF_TYPE_ETHERNET;
	  }

	/* Bandwidth. */
	if (CHECK_CINDEX (cindex, HAL_MSG_CINDEX_IF_BANDWIDTH))
	  {	
	    msg->bandwidth = (ifp->u.l2_ethernet.speed * 1000) /  8;
	    SET_CINDEX (msg->cindex, HAL_MSG_CINDEX_IF_BANDWIDTH);
	  }
        /* Duplex */
  	if (CHECK_CINDEX (cindex, HAL_MSG_CINDEX_IF_DUPLEX))
          { 
	    msg->duplex = ifp->u.l2_ethernet.duplex;
	    SET_CINDEX (msg->cindex, HAL_MSG_CINDEX_IF_DUPLEX);
          }
        /* Autoneg. */ 
        if (CHECK_CINDEX (cindex, HAL_MSG_CINDEX_IF_AUTONEGO))
          {  
	    msg->autonego = ifp->u.l2_ethernet.autonego;
	    SET_CINDEX (msg->cindex, HAL_MSG_CINDEX_IF_AUTONEGO);
          }
      }
      break;
    case HSL_IF_TYPE_LOOPBACK:
      msg->type = HAL_IF_ROUTER_PORT;

      if (CHECK_CINDEX (cindex, HAL_MSG_CINDEX_IF_HW))
	{
	  msg->hw_type = HAL_IF_TYPE_LOOPBACK;
	}
    default:
      break;
    }
     
  return;
}
#ifdef HAVE_L3
/* 
   Common function for interface address updates. 
*/
static int
_hsl_msg_addr_event (struct socket *sock, struct hsl_if *ifp, hsl_prefix_t *prefix, int cmd)
{
  u_char tbuf[256], *tpnt;
  int tsize, nbytes = -1;
  struct hal_msg_if_ipv4_addr msg_v4;
#ifdef HAVE_IPV6
  struct hal_msg_if_ipv6_addr msg_v6;
#endif /* HAVE_IPV6 */

  HSL_FN_ENTER(); 

  tpnt = tbuf;
  tsize = 256;

  /* Encode interface. */
  switch(cmd)
    {
    case HAL_MSG_IF_IPV4_DELADDR:   
    case HAL_MSG_IF_IPV4_NEWADDR:
      memset (&msg_v4, 0, sizeof (msg_v4));
      memcpy(msg_v4.name,ifp->name,hsl_strlen(ifp->name));     
      msg_v4.ifindex = ifp->ifindex;
      msg_v4.addr.s_addr = prefix->u.prefix4;
      msg_v4.ipmask = prefix->prefixlen;
      nbytes = hsl_msg_encode_ipv4_addr(&tpnt,(u_int32_t *)&tsize,&msg_v4);
      break; 
#ifdef HAVE_IPV6
    case HAL_MSG_IF_IPV6_DELADDR:   
    case HAL_MSG_IF_IPV6_NEWADDR:
      memset (&msg_v6, 0, sizeof (msg_v6));
      memcpy(msg_v6.name,ifp->name,hsl_strlen(ifp->name));     
      msg_v6.ifindex = ifp->ifindex;
      IPV6_ADDR_COPY(msg_v6.addr.in6_u.u6_addr32,prefix->u.prefix6.word);
      msg_v6.ipmask = prefix->prefixlen;
      nbytes = hsl_msg_encode_ipv6_addr(&tpnt,&tsize,&msg_v6);
      break; 
#endif /* HAVE_IPV6 */
    default: 
      HSL_FN_EXIT(-1);  
    }
  if (nbytes < 0)
    HSL_FN_EXIT(STATUS_ERROR);

  /* Post the message. */
  hsl_sock_post_msg (sock, cmd, 0, 0, (char *)tbuf, nbytes);

  HSL_FN_EXIT(0);
}


/* 
   Address addition message.
*/
int
hsl_msg_ifnewaddr(struct socket *sock, void *param1, void *param2)
{
  int ret;
  int cmd;
  struct hsl_if *ifp = (struct hsl_if *) param1;
  hsl_prefix_t *prefix = (hsl_prefix_t *) param2; 

  HSL_FN_ENTER(); 

  if((!ifp) || !(prefix))
    HSL_FN_EXIT(-1);

  if(AF_INET == prefix->family) 
    cmd = HAL_MSG_IF_IPV4_NEWADDR;
#ifdef HAVE_IPV6
  else if(AF_INET6 == prefix->family) 
    cmd = HAL_MSG_IF_IPV6_NEWADDR;
#endif 
  else
    HSL_FN_EXIT(-1);

  ret = _hsl_msg_addr_event (sock, ifp, prefix ,cmd);
  if (ret < 0)
    goto ERR;

  HSL_FN_EXIT(STATUS_OK);

 ERR:  
  /* Close socket. */
  hsl_sock_release (sock);
  return -1;
}

/* 
   Address deletion message.
*/
int
hsl_msg_ifdeladdr(struct socket *sock, void *param1, void *param2)
{
  int ret;
  int cmd;
  struct hsl_if *ifp = (struct hsl_if *) param1;
  hsl_prefix_t *prefix = (hsl_prefix_t *) param2; 

  HSL_FN_ENTER(); 

  if((!ifp) || !(prefix))
    HSL_FN_EXIT(-1);

  if(AF_INET == prefix->family) 
    cmd = HAL_MSG_IF_IPV4_DELADDR;
#ifdef HAVE_IPV6
  else if(AF_INET6 == prefix->family) 
    cmd = HAL_MSG_IF_IPV6_DELADDR;
#endif 
  else
    HSL_FN_EXIT(-1);


  ret = _hsl_msg_addr_event (sock, ifp, prefix ,cmd);
  if (ret < 0)
    goto ERR;

  HSL_FN_EXIT(STATUS_OK);

 ERR:  
  /* Close socket. */
  hsl_sock_release (sock);
  return -1;
}
#endif /* HAVE_L3 */
/* 
   Common function for IFNEW, IFDEL or IFFLAGS.
*/
static int
_hsl_msg_if_event (struct socket *sock, struct hsl_if *ifp, u_int32_t cindex, int cmd)
{
  u_char tbuf[256], *tpnt;
  int tsize, nbytes;
  struct hal_msg_if msg;

  /* Interface mapping. */
  _hsl_map_if (ifp, &msg, cindex);

  tpnt = tbuf;
  tsize = 256;

  /* Encode interface. */
  nbytes = hsl_msg_encode_if (&tpnt, (u_int32_t *)&tsize, &msg); 
  if (nbytes < 0)
    return -1;

  /* Post the message. */
  hsl_sock_post_msg (sock, cmd, 0, 0, (char *)tbuf, nbytes);

  return 0;
}

/*
  IFNEW message multicast.
*/
int
hsl_msg_ifnew (struct socket *sock, void *param1, void *unused)
{
  u_int32_t cindex = 0;
  int ret;
  struct hsl_if *ifp = (struct hsl_if *) param1;

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_FLAGS);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_METRIC);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_MTU);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_DUPLEX);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_ARP_AGEING_TIMEOUT);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_AUTONEGO);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_HW);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_BANDWIDTH);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_HW);

  ret = _hsl_msg_if_event (sock, ifp, cindex, HAL_MSG_IF_NEWLINK);
  if (ret < 0)
    goto ERR;

  return 0;

 ERR:  
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}
/*
  IFAUTONEGO message multicast.
*/
int
hsl_msg_ifautonego(struct socket *sock, void *param1, void *unused)
{
  u_int32_t cindex = 0;
  int ret;
  struct hsl_if *ifp = (struct hsl_if *) param1;

  HSL_FN_ENTER(); 

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_AUTONEGO);
  ret = _hsl_msg_if_event (sock, ifp, cindex, HAL_MSG_IF_UPDATE);
  if (ret < 0)
    goto ERR;

  HSL_FN_EXIT(STATUS_OK);

 ERR:  
  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT(STATUS_ERROR);
}

/*
  IFHWADDR message multicast.
*/
int
hsl_msg_ifhwaddr(struct socket *sock, void *param1, void *unused)
{
  u_int32_t cindex = 0;
  int ret;
  struct hsl_if *ifp = (struct hsl_if *) param1;

  HSL_FN_ENTER(); 

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_HW);
  ret = _hsl_msg_if_event (sock, ifp, cindex, HAL_MSG_IF_UPDATE);
  if (ret < 0)
    goto ERR;

  HSL_FN_EXIT(STATUS_OK);

 ERR:  
  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT(STATUS_ERROR);
}

/*
  IFMTU message multicast.
*/
int
hsl_msg_ifmtu(struct socket *sock, void *param1, void *unused)
{
  u_int32_t cindex = 0;
  int ret;
  struct hsl_if *ifp = (struct hsl_if *) param1;

  HSL_FN_ENTER(); 

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_MTU);
  ret = _hsl_msg_if_event (sock, ifp, cindex, HAL_MSG_IF_UPDATE);
  if (ret < 0)
    goto ERR;

  HSL_FN_EXIT(STATUS_OK);

 ERR:  
  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT(STATUS_ERROR);
}

/*
  IFDUPLEX message multicast.
*/
int
hsl_msg_ifduplex(struct socket *sock, void *param1, void *unused)
{
  u_int32_t cindex = 0;
  int ret;
  struct hsl_if *ifp = (struct hsl_if *) param1;

  HSL_FN_ENTER(); 

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_DUPLEX);
  ret = _hsl_msg_if_event (sock, ifp, cindex, HAL_MSG_IF_UPDATE);
  if (ret < 0)
    goto ERR;

  HSL_FN_EXIT(STATUS_OK);

 ERR:  
  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT(STATUS_ERROR);
}

/* 
   IFDELETE message multicast. 
*/
int
hsl_msg_ifdelete (struct socket *sock, void *param1, void *param2)
{
  u_int32_t cindex = 0;
  int ret;
  struct hsl_if *ifp = (struct hsl_if *) param1;

  ret = _hsl_msg_if_event (sock, ifp, cindex, HAL_MSG_IF_DELLINK);
  if (ret < 0)
    goto ERR;

  return 0;

 ERR:  
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}

/*
  IFFLAGS message multicast.
*/
int
hsl_msg_ifflags (struct socket *sock, void *param1, void *param2)
{
  u_int32_t cindex = 0;
  int ret;
  struct hsl_if *ifp = (struct hsl_if *) param1;

  HSL_FN_ENTER ();

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_FLAGS);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_BANDWIDTH);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_DUPLEX);

  ret = _hsl_msg_if_event (sock, ifp, cindex, HAL_MSG_IF_UPDATE);
  if (ret < 0)
    goto ERR;

  HSL_FN_EXIT (0);

 ERR:  
  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT (-1);
}

/*
  HAL initialization.
*/
int
hsl_msg_recv_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL initialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/* 
   HAL deinitialization.
*/
int
hsl_msg_recv_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL deinitialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/* 
   HAL HSL debug.
*/
int
hsl_msg_recv_debug_hsl (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)

{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_debug_hsl_req msg;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Set interface list\n");

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  ret = hsl_msg_decode_debug_hsl(&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;
 
  ret = hsl_log_conf(msg.module_str, msg.enable, msg.level);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}


/* HAL_MSG_IF_CLEANUP_DONE message. */
int
hsl_msg_recv_if_delete_done (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_if msg;
  int ret;

  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Interfece Cleanup done\n");

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  ret = hsl_msg_decode_if (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_clean_up_complete(msg.ifindex);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT (-1);
}

#ifdef HAVE_L3
/*
  HAL_MSG_IF_L3_INIT message.
*/
int
hsl_msg_recv_if_init_l3(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{

#if 1
  struct hsl_bcm_if   *bcm_ifp;                   /* Broadcom interface info.    */
  struct hsl_if       **ifp_arr;                  /* Array of all L2 interfaces. */
  struct hsl_if       *ifp;                       /* Inteface information.       */
  struct hsl_if       *ifpp;                      /* New Inteface information.   */
  int ret;                                        /* General operation status.   */
  u_int16_t index;                                /* Index for iteration.        */
  u_int16_t count = 0;                            /* Interface size.             */  
  u_int8_t policy;
 
  HSL_FN_ENTER();
  
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: Set interface init l3 mode\n"); 

  /* Get current interface manager policy. */
  policy = hsl_ifmgr_get_policy ();

  if (policy == HSL_IFMGR_IF_INIT_POLICY_L3)
    {
      HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
      HSL_FN_EXIT (0);
    }
  

  /* Lock interface manager. */
  HSL_IFMGR_LOCK;
  

  /* Create a snapshot of all L2 interfaces (ports). */
  ret = hsl_ifmgr_get_L2_array(&ifp_arr, &count);

  if (ret < 0 )
    {
      HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Failed to read l2 interface array.\n");
      HSL_IFMGR_UNLOCK;
      HSL_MSG_PROCESS_RETURN (sock, hdr, -1);
      HSL_FN_EXIT(-1);
    }


  /* Create L3 interface for every L2 saved in the snapshot. */
  for (index = 0 ;index < count; index++)
    {
      ifp  = ifp_arr[index];

      bcm_ifp = (struct hsl_bcm_if *) ifp->system_info;
      if (! bcm_ifp) {
    	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Interface %s(%d) doesn't have a corresponding broadcom interface structure\n", ifp->name, ifp->ifindex);
    	  continue;
      }


      /* Enable L3 routing. */
      //by chentao
      //bcmx_port_l3_enable_set (bcm_ifp->u.l2.lport, 1);
       

      /* Create layer 3 interface. */
      ret = hsl_ifmgr_set_router_port (ifp, NULL, &ifpp, HSL_TRUE);
      if (ret < 0 )
	{
	  HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR, "  Interface %s(%d) \n", ifp->name, ifp->ifindex);
	  continue;
	}


      /* Set interface flags. */
      if (ifpp->flags & IFF_UP)
	    hsl_ctc_if_l3_flags_set (ifpp, IFF_UP);

    }


  oss_free(ifp_arr,OSS_MEM_HEAP);

  HSL_IFMGR_UNLOCK;

  /* Set policy. */
  hsl_ifmgr_set_policy (HSL_IFMGR_IF_INIT_POLICY_L3);
#endif
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);

  HSL_FN_EXIT(STATUS_OK);
}
#endif /* HAVE_L3 */
/*
  HAL_MSG_IF_GETLINK message. 
*/
int
hsl_msg_recv_if_getlink (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hsl_avl_node *node;
  struct hsl_if *ifp;
  int size, totsz, nbytes;
  u_char buf[4096], *pnt;
  struct hal_msg_if msg;
  u_int32_t cindex = 0;
  struct hal_nlmsghdr *nlh;
  hsl_prefix_list_t *ucaddr;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Get interface list\n");

  HSL_IFMGR_LOCK;

  for (node = hsl_avl_top (HSL_IFMGR_TREE); node; node = hsl_avl_next(node))
    {
      ifp = HSL_AVL_NODE_INFO (node);
      if (! ifp)
	{
	  continue;
	}

      /* If directly mapped interface, skip this interface. */
      if (CHECK_FLAG (ifp->if_flags, HSL_IFMGR_IF_DIRECTLY_MAPPED))
	continue;

      cindex = 0;
      SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_FLAGS);
      SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_METRIC);
      SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_MTU);
      SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_DUPLEX);
      SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_ARP_AGEING_TIMEOUT);
      SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_AUTONEGO);
      SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_HW);
      SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_BANDWIDTH);

      /* Interface mapping. */
      _hsl_map_if (ifp, &msg, cindex);

      pnt = buf;
      totsz = 0;
      size = 4096;
      nlh = (struct hal_nlmsghdr *) pnt;
      pnt += HAL_NLMSGHDR_SIZE;

      /* Encode interface. */
      nbytes = hsl_msg_encode_if (&pnt, (u_int32_t *)&size, &msg); 
      if (nbytes < 0)
	{
	  goto UNLOCK;
	}
   
      /* Set header. */    
      nlh->nlmsg_len = HAL_NLMSG_LENGTH (nbytes);
      nlh->nlmsg_type = HAL_MSG_IF_NEWLINK;
      nlh->nlmsg_flags = HAL_NLM_F_MULTI;
      totsz += HAL_NLMSG_ALIGN(nlh->nlmsg_len);
      
      /* Post the message. */
      hsl_sock_post_buffer (sock, (char *)buf, totsz);

#ifdef HAVE_L3
      if (ifp->type == HSL_IF_TYPE_L2_ETHERNET)
        continue;

      /* Now send address sync information */
      ucaddr = ifp->u.ip.ipv4.ucAddr;
      while (ucaddr)
        {
          hsl_ifmgr_send_notification (HSL_IF_EVENT_IFNEWADDR, ifp, 
              &ucaddr->prefix);
          ucaddr = ucaddr->next;
        }
#ifdef HAVE_IPV6
      ucaddr = ifp->u.ip.ipv6.ucAddr;
      while (ucaddr)
        {
          hsl_ifmgr_send_notification (HSL_IF_EVENT_IFNEWADDR, ifp, 
              &ucaddr->prefix);
          ucaddr = ucaddr->next;
        }
#endif /* HAVE_IPV6 */
#endif /* HAVE_L3 */
    }

  HSL_IFMGR_UNLOCK;

  /* End the message with HAL_NLMSG_DONE. */
  nlh = (struct hal_nlmsghdr *) buf;
  nlh->nlmsg_len = HAL_NLMSG_LENGTH(0);
  nlh->nlmsg_type = HAL_NLMSG_DONE;
  totsz =  HAL_NLMSG_ALIGN(nlh->nlmsg_len);
  
  /* Post the message. */
  hsl_sock_post_buffer (sock, (char *)buf, totsz);

  return 0;
 UNLOCK:
  HSL_IFMGR_UNLOCK;
  return 0;
}

/* added by cdy, for USDM_HAL to get port link stat and port counter */
static int ngn_get_ifindex_from_hal_msg(u_int8_t *_ifindex)
{
    u_int8_t  linkagg_flag = 0;
    u_int8_t  *ptr    = NULL;
    u_int8_t  slot    = 0;
    u_int8_t  io      = 0;
    u_int8_t  port    = 0;  /* panel port */
    u_int32_t ifindex = 0;

    if(_ifindex == NULL) {
        return -1;
    }

    ptr = _ifindex;
    ifindex = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
    ifindex = ntohl(ifindex);

    linkagg_flag = CTC_GET_LINKAGG_FLAG_FROM_IFINDEX(ifindex);
    slot = CTC_GET_SLOT_FROM_IFINDEX(ifindex);
    io   = CTC_GET_IO_FROM_IFINDEX(ifindex);
    port = CTC_GET_PANEL_PORT_FROM_IFINDEX(ifindex);

    if(slot == 1) {
        ctc_get_gchip_id(0, &slot);
        slot += 1;  /* slot = gchip + 1 */
    }
    ifindex = port_num_to_ifindex(linkagg_flag, slot, io, port);

    return ifindex;
}
extern int32 sys_greatbelt_chip_get_gpio_intput(uint8 gpio_id, uint8* in_value);

int hsl_msg_recv_if_ctc_10ge_los_staus(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret = 0;
	u_int32_t ifindex = *(u_int32_t *)msgbuf;
		
	u_int8_t gpio_id = 0;
	u_int8_t in_value = 0;

	gpio_id = ifindex;
	ret = sys_greatbelt_chip_get_gpio_intput(gpio_id, &in_value);
	if (ret < 0) {
		goto err_out;
	}
	//printk("gpio_id=%d, in_value=%d\n", gpio_id, in_value);
	hsl_sock_post_msg(sock, hdr->nlmsg_type, hdr->nlmsg_seq, 0, (u_int8_t*)&in_value, 1);
	return 0;
	
 err_out:
    printk("[%s]: failed!!!!!!!!!\r\n", __func__);
    hsl_sock_post_ack (sock, hdr, 0, -1);
	return -1;
}

int hsl_msg_recv_if_ctc_get_port_status(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
    struct hsl_avl_node *node = NULL;
    struct hsl_if *ifp = NULL;
    struct hal_msg_if msg;
#if 0
    u_int8_t  linkagg_flag = 0;
    u_int8_t  slot    = 0;
    u_int8_t  io      = 0;
    u_int8_t  port    = 0;  /* panel port */
#endif
    u_int32_t ifindex = 0;
    u_int32_t cindex  = 0;
    u_int32_t tsize   = 0;

    int  nbytes = 0;
    u_char tbuf[256] = { 0 };
    u_char *pnt  = NULL;
    u_char *tpnt = NULL;

//    printk("[%s]: ctc get port \r\n", __func__);

#if 0
    pnt = msgbuf;
    ifindex = (pnt[0] << 24) | (pnt[1] << 16) | (pnt[2] << 8) | pnt[3];

    linkagg_flag = CTC_GET_LINKAGG_FLAG_FROM_IFINDEX(ifindex);
    slot = CTC_GET_SLOT_FROM_IFINDEX(ifindex);
    io   = CTC_GET_IO_FROM_IFINDEX(ifindex);
    port = CTC_GET_PANEL_PORT_FROM_IFINDEX(ifindex);

    if(slot == 0) {
        ctc_get_gchip_id(0, &slot); /* slot == gchip */
    }
    ifindex = port_num_to_ifindex(linkagg_flag, slot, io, port);
#else
    ifindex = ngn_get_ifindex_from_hal_msg(msgbuf);
#endif
    ifp = hsl_ifmgr_lookup_by_index(ifindex);
    if(ifp == NULL) {
       // printk("[%s]: port ifindex<%d> not registered\r\n", __func__, ifindex);
        goto err_out;
    }

    /* If directly mapped interface, skip this interface. */
    if (CHECK_FLAG (ifp->if_flags, HSL_IFMGR_IF_DIRECTLY_MAPPED))
        goto err_out;

    cindex = 0;
    SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_FLAGS);
    SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_METRIC);
    SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_MTU);
    SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_DUPLEX);
    SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_ARP_AGEING_TIMEOUT);
    SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_AUTONEGO);
    SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_HW);
    SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_BANDWIDTH);

    /* get this port infocations */
    _hsl_map_if(ifp, &msg, cindex);
    HSL_IFMGR_IF_REF_DEC(ifp);

    tpnt = tbuf;
    tsize = 256;

    /* Encode interface. */
    nbytes = hsl_msg_encode_if (&tpnt, &tsize, &msg);
    if(nbytes < 0) {
        printk("[%s]: encode port<%d> informations failed: %d\r\n", __func__, ifindex, nbytes);
        goto err_out;
    }

    /* send this port info. to hal */
    hsl_sock_post_msg(sock, hdr->nlmsg_type, hdr->nlmsg_seq, 0, (char *)tbuf, nbytes);
//    printk("[%s]: post port: %s, ifindex: %d, info to hal\r\n", __func__, ifp->name, ifindex);

    return 0;

 err_out:
    //printk("[%s]: failed!!!!!!!!!\r\n", __func__);
    hsl_sock_post_ack (sock, hdr, 0, -1);

    return -1;
}

int hsl_msg_recv_if_ctc_get_port_counter(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
    struct hsl_if *ifp = NULL;
    struct hal_if_counters cntrs;
    u_int32_t ifindex = 0;
    int ret    = 0;
    int respsz = 0;


//    printk("[%s]: ctc get counter \r\n", __func__);
    ifindex = ngn_get_ifindex_from_hal_msg(msgbuf);
    ifp = hsl_ifmgr_lookup_by_index(ifindex);
    if(ifp == NULL) {
        //printk("[%s]: port ifindex<%d> not registered\r\n", __func__, ifindex);
        goto err_out;
    }

    memset(&cntrs, 0, sizeof(cntrs));
    /* Lock interface manager. */
    HSL_IFMGR_LOCK;
    memcpy(&cntrs,&ifp->mac_cntrs,sizeof(struct hal_if_counters));

    HSL_IFMGR_UNLOCK;
    HSL_IFMGR_IF_REF_DEC(ifp);

    /* send counter to usdm_hal */
    respsz = sizeof(struct hal_if_counters);
    ret = hsl_sock_post_msg(sock, hdr->nlmsg_type, 0, hdr->nlmsg_seq, (char *)&cntrs, respsz);

//    printk("[%s]: sz: %d, cnt: %llu, hsl-seq: %u\r\n", __func__, respsz, cntrs.rx_plus.rx_all_pkts, hdr->nlmsg_seq);
//    printk("[%s-counter]: post port: %s, ifindex: %d, info to hal\r\n", __func__, ifp->name, ifindex);

    return 0;

 err_out:
    //printk("[%s]: failed!!!!!!!!!\r\n", __func__);
    hsl_sock_post_ack (sock, hdr, 0, -1);

    return -1;
}


/* For port config */
#define CTC_SW_PORT_SHUTDOWN            0x10
#define CTC_SW_PORT_NO_SHUTDOWN         0x11
#define CTC_SW_PORT_SET_DUPLEX          0x12
#define CTC_SW_PORT_SET_SPEED           0x13
#define CTC_SW_PORT_CLEAN_COUNTER       0x14
#define CTC_SW_PORT_LOOPBACK_ENABLE     0x15
#define CTC_SW_PORT_LOOPBACK_DISABLE    0x16
#define CTC_SW_PORT_SET_L3_ROUTER_MAC   0x17
#define CTC_SW_PORT_SET_NGN_TYPE        0x18

/* shutdown or up port */
static int hsl_msg_recv_if_config_port_link(uint32_t ifindex,   \
                                            uint32_t msg_type,  \
                                            uint32_t value)
{
    int ret = 0;
    struct hsl_if *ifp = NULL;

    ifp = hsl_ifmgr_lookup_by_index(ifindex);
    if(ifp == NULL) {
       // printk("[%s-%d]: port ifindex<%d> not registered\r\n", __func__, __LINE__, ifindex);
        return -1;
    }

    if(msg_type == CTC_SW_PORT_SHUTDOWN) {
        ret = hsl_ifmgr_unset_flags(ifp->name, ifp->ifindex, IFF_UP);
    } else if(msg_type == CTC_SW_PORT_NO_SHUTDOWN) {
        ret = hsl_ifmgr_set_flags(ifp->name, ifp->ifindex, IFF_UP);
    } else {
        ret = -1;
        printk("[%s]: Unknown message type: %#x\r\n", __func__, msg_type);
    }

    return ret;
}

/* set port duplex */
#define HSL_CTC_PORT_CONFIG_DUPLEX_HALF    0
#define HSL_CTC_PORT_CONFIG_DUPLEX_FULL    1
#define HSL_CTC_PORT_CONFIG_DUPLEX_AUTO    2

static int hsl_msg_recv_if_config_port_duplex(uint32_t ifindex,    \
                                              uint32_t msg_type,   \
                                              uint32_t value)
{
    int ret    = 0;
    int duplex = HSL_IF_DUPLEX_AUTO;
    struct hsl_if *ifp = NULL;

    ifp = hsl_ifmgr_lookup_by_index(ifindex);
    if(ifp == NULL) {
        //printk("[%s-%d]: port ifindex<%d> not registered\r\n", __func__, __LINE__, ifindex);
        return -1;
    }

    switch(value) {
        case HSL_CTC_PORT_CONFIG_DUPLEX_HALF:
            duplex = HSL_IF_DUPLEX_HALF;
            break;

        case HSL_CTC_PORT_CONFIG_DUPLEX_FULL:
            duplex = HSL_IF_DUPLEX_HALF;
            break;

        case HSL_CTC_PORT_CONFIG_DUPLEX_AUTO:
            duplex = HSL_IF_DUPLEX_AUTO;
            break;

        default:
            printk("[%s]: Wrong message type: %#x\r\n", __func__, msg_type);
            return -1;
    }
    ret = hsl_ifmgr_set_duplex(ifindex, duplex, HSL_FALSE);

    return ret;
}

static int hsl_msg_recv_if_config_port_speed(uint32_t ifindex,     \
                                             uint32_t msg_type,    \
                                             uint32_t value)
{
    int ret  = 0;
    int speed = 1;
    struct hsl_if *ifp = NULL;

    ifp = hsl_ifmgr_lookup_by_index(ifindex);
    if(ifp == NULL) {
       // printk("[%s]: port ifindex<%d> not registered\r\n", __func__, ifindex);
        return -1;
    }

    if(value >= 10 * 1000) { /*  > 10G */
        printk("[%s-%d]: Not support this port speed: %d\r\n", __func__, __LINE__, value);
        return -1;
    }

    /* @value: 10:  10M,  HSL use 10  * 1000 * 1000 / 8;
    **         100: 100M, HSL use 100 * 1000 * 1000 / 8;
    ** others are the same 
    */
    ret = hsl_ifmgr_set_bandwidth(ifp->ifindex, (value * 1000 * 1000) / 8, HSL_FALSE);

    return ret;
}

static int hsl_msg_recv_if_config_port_clear_counter(uint32_t ifindex,     \
                                                     uint32_t msg_type,    \
                                                     uint32_t value)
{
    int ret  = 0;
    int speed = 1;
    struct hsl_if *ifp = NULL;

    ifp = hsl_ifmgr_lookup_by_index(ifindex);
    if(ifp == NULL) {
        //printk("[%s-%d]: port ifindex<%d> not registered\r\n", __func__, __LINE__, ifindex);
        return -1;
    }

    return hsl_ifmgr_clear_if_counters(ifindex);
}

/* loopback set values: ((dev & 0xf) << 4 ) | (end & 0xf) */
#define CTC_SW_LOOPBACK_FAR_END     0x01
#define CTC_SW_LOOPBACK_NEAR_END    0x02

#define CTC_SW_LOOPBACK_DEV_8512    0x01
#define CTC_SW_LOOPBACK_DEV_5160    0x02

/* set 5160 port to far-end-loopback */
static int ctc_set_5160_loopback(uint16_t gport, int enable_flag)
{
    ctc_port_lbk_param_t port_lbk;

    memset(&port_lbk, 0, sizeof(port_lbk));
    port_lbk.src_gport = gport;
    port_lbk.dst_gport = gport;
    port_lbk.lbk_mode  = 1; /* EFM loopback */

    if(enable_flag) {
        /* enable loopback */
        port_lbk.lbk_type   = CTC_PORT_LBK_TYPE_BYPASS;
        port_lbk.lbk_enable = TRUE;
    } else {
        /* disable loopback */
        port_lbk.lbk_enable = FALSE;
    }

    return ctc_port_set_loopback(&port_lbk);
}

static int set_ctc_8512_loopback(uint16_t pal_port, int end, int enable_flag)
{
    int      ret  = 0;
    uint32_t reg  = 0;
    uint32_t val  = 0;
    uint32_t mask = 0;
    vsc8512_space_t space = VSC8512_MAIN;

    if(end == CTC_SW_LOOPBACK_FAR_END) {
        reg  = 0x17;   /* reg: 23 */
        if(enable_flag) {
            /* enable far-end-loopback */
            mask = 0x01 << 3;
        } else {
            /* diabel far-end-loopback */
            mask = (uint32_t )(~(0x01 << 3));
        }
    } else if(end == CTC_SW_LOOPBACK_NEAR_END) {
        reg = 0x00;
        if(enable_flag) {
            /* enable near-end-loopback */
            mask = 0x01 << 14;
        } else {
            /* disable near-end-loopback */
            mask = (uint32_t )(~0x01 << 14);
        }
    } else {
        printk("[%s-%d]: Wrong loopback end: %#x\r\n", __func__, __LINE__, end);
        return -1;
    }

    ret = vsc8512_read_reg_val(space, pal_port, reg, &val);
    if(ret != 0) {
        printk("[%s-%d]: read reg: %#x, failed: %d\r\n", __func__, __LINE__, reg, val);
        return -1;
    }

    /* set 8512 port loopback */
    if(enable_flag) {
        val |= mask;
    } else {
        val &= mask;
    }
    ret = vsc8512_write_reg_val(space, pal_port, reg, val);
    if(ret != 0) {
        printk("[%s-%d]: write reg: %#x, val: %#x failed: %d\r\n",  \
              __func__, __LINE__, reg, val, ret);
        return -2;
    }

    return 0;
}

/*  @msg_type: enable or disable loopback
**  @value: uint32_t, ((dev & 0x0f) << 4) | (end & 0x0f)
*/
static int hsl_msg_recv_if_config_port_loopback(uint32_t ifindex,     \
                                                uint32_t msg_type,    \
                                                uint32_t value)
{
    int      ret          = 0;
    int      flag_enable  = 0;
    uint8_t  loopback_dev = 0;
    uint8_t  loopback_end = 0;
    uint16_t panel_port   = 0;
    uint16_t ctc_gport    = 0;
    struct hsl_if *ifp    = NULL;

    ifp = hsl_ifmgr_lookup_by_index(ifindex);
    if(ifp == NULL) {
        printk("[%s-%d]: port ifindex<%d> not registered\r\n", __func__, __LINE__, ifindex);
        return -1;
    }

    loopback_end = value & 0x0f;
    loopback_dev = (value >> 4) & 0x0f;

    panel_port = CTC_GET_PANEL_PORT_FROM_IFINDEX(ifp->ifindex);
    ctc_gport  = IFINDEX_TO_GPORT(ifp->ifindex);

    if(msg_type == CTC_SW_PORT_LOOPBACK_ENABLE) {
        flag_enable = 1;
    } else if(msg_type == CTC_SW_PORT_LOOPBACK_DISABLE) {
        flag_enable = 0;
    } else {
        printk("[%s-%d]: Wrong message type: %#x\r\n", __func__, __LINE__, msg_type);
        return -1;
    }

    /* ADS board 
    ** 10G port only can set 5160 loopback(far-end-loopback) 
    **
    ** 1G port will set 8512 registers
    ** reg 0  set bit14 to 1 to enable near-end-loopback
    ** reg 23 set bit3  to 1 to enable far-end-loopback
    */
    switch(loopback_dev) {
        case CTC_SW_LOOPBACK_DEV_5160:
            if(loopback_end == CTC_SW_LOOPBACK_FAR_END) {
                ret = ctc_set_5160_loopback(ctc_gport, flag_enable);
            } else {
                /* not support */
                ret = -1;
            }
            break;

        case CTC_SW_LOOPBACK_DEV_8512:
            ret = set_ctc_8512_loopback(panel_port, loopback_end, flag_enable);
            break;

        default:
            ret = -1;
            printk("[%s-%d]: Wrong loopback dev: %#x, value: %#x\r\n",  \
                   __func__, __LINE__, loopback_dev, value);
            break;
    }

    return ret;
}


static int hsl_msg_recv_if_config_port_set_l3_router_mac(uint32_t ifindex, uint32_t msg_type, void *mac)
{
    int ret = 0;

    ret = ctc_l3if_set_router_mac(mac);

    return ret;
}

static int hsl_msg_recv_if_config_port_ngn_type(uint32_t ifindex, uint32_t msg_type, uint32_t ngn_type)
{
    struct hsl_if *ifp = NULL;

    ifp = hsl_ifmgr_lookup_by_index(ifindex);
    if(ifp == NULL) {
        printk("[%s]: port ifindex<%d> not registered\r\n", __func__, ifindex);
        return -1;
    }

   // printk("[%s]: old ngn_type: flag: %d, type: %#x\r\n", __func__, ifp->ngn_type_enabled, ifp->ngn_type);
    if(ngn_type & (0x01 << 16)) {
        /* enable ngn_type */
        ifp->ngn_type_enabled = 1;  /* enabled */
    } else {
        /* disable ngn_type */
        ifp->ngn_type_enabled = 0;
    }
    ifp->ngn_type = ngn_type & 0xffff;

    return 0;
}

int hsl_msg_recv_if_sync_board_info(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret = 0;
	int32_t *board_type = (int32_t *)msgbuf;
	int slot;
	for (slot=0; slot<8; slot++) {
		//printk("hsl slot %d board_type %d\n", slot, board_type[slot]); 
		hsl_set_board_type(slot, board_type[slot]);
	}
	HSL_MSG_PROCESS_RETURN(sock, hdr, ret);
}

/* USDM config port link statu, speed, duplex, auto-neg */
int hsl_msg_recv_if_ctc_config_port(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
    int  ret     = 0;
    int  respsz  = 0;
    int  msg_len = 0;
    char *ptr    = msgbuf;

    uint32_t ifindex   = 0;
    uint32_t msg_type  = 0;
    uint32_t msg_value = 0;
    struct hsl_if *ifp = NULL;

    msg_len = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
    if(msg_len < 3 * sizeof(uint32_t)) {
        printk("[%s-%d]: Wrong of message length: %d\r\n", __func__, __LINE__, msg_len);
        hsl_sock_post_ack(sock, hdr, 0, -1);
        return -1;
    }

    ifindex = ngn_get_ifindex_from_hal_msg(ptr);
    ptr += sizeof(ifindex);

    /* get command type */
    msg_type = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
    msg_type = ntohl(msg_type);
    ptr += sizeof(msg_type);

    /* get command values */
    msg_value = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
    msg_value = ntohl(msg_value);

    switch(msg_type) {
        case CTC_SW_PORT_SHUTDOWN:
        case CTC_SW_PORT_NO_SHUTDOWN:
            ret = hsl_msg_recv_if_config_port_link(ifindex, msg_type, msg_value);
            break;

        case CTC_SW_PORT_SET_DUPLEX:
            ret = hsl_msg_recv_if_config_port_duplex(ifindex, msg_type, msg_value);
            break;

        case CTC_SW_PORT_SET_SPEED:
            ret = hsl_msg_recv_if_config_port_speed(ifindex, msg_type, msg_value);
            break;

        case CTC_SW_PORT_CLEAN_COUNTER:
            ret = hsl_msg_recv_if_config_port_clear_counter(ifindex, msg_type, msg_value);
            break;

        case CTC_SW_PORT_LOOPBACK_ENABLE:
        case CTC_SW_PORT_LOOPBACK_DISABLE:
            ret = hsl_msg_recv_if_config_port_loopback(ifindex, msg_type, msg_value);
            break;

        case CTC_SW_PORT_SET_L3_ROUTER_MAC:
            if(msg_len < 4 + 4 + 6) {
                printk("[%s-%d]: Wrong of MAC address length: %d\r\n", __func__, __LINE__, msg_len);
                ret = -1;
                break;
            }
            ret = hsl_msg_recv_if_config_port_set_l3_router_mac(ifindex, msg_type, msgbuf + 4 + 4);
            break;

        case CTC_SW_PORT_SET_NGN_TYPE:
            ret = hsl_msg_recv_if_config_port_ngn_type(ifindex, msg_type, msg_value);
            break;

        default:
            ret = -1;
    }

    HSL_MSG_PROCESS_RETURN(sock, hdr, ret);
    return ret;
}


/*
  Generic function to process interface get messages.
*/
static int
_hsl_msg_process_if_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf, u_int32_t cindex)
{
  u_char tbuf[256];
  u_char *pnt, *tpnt;
  u_int32_t size, tsize;
  struct hal_msg_if msg;
  int ret, nbytes;
  struct hsl_if *ifp;

  /* Get requests should have ACK flag set. */
  if (hdr->nlmsg_flags & HAL_NLM_F_ACK)
    {
      pnt = (u_char *)msgbuf;
      size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

      ret = hsl_msg_decode_if (&pnt, &size, &msg);
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_ERROR, "Interface message decode failed\n");
	  goto ERR;
	}

      /* Lookup interface. */
      ifp = hsl_ifmgr_lookup_by_index (msg.ifindex);
      if (! ifp)
	{
	  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_ERROR, "Interface %s(%d) not found in database\n", msg.name, msg.ifindex);
	  /* Send error. */
	  hsl_sock_post_ack (sock, hdr, 0, -1);
	  
	  return -1;
	}
    
      /* Interface mapping. */
      _hsl_map_if (ifp, &msg, cindex);
      HSL_IFMGR_IF_REF_DEC (ifp);

      tpnt = tbuf;
      tsize = 256;

      /* Encode interface. */
      nbytes = hsl_msg_encode_if (&tpnt, &tsize, &msg); 
      if (nbytes < 0)
	{
	  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_ERROR, "Interface message encode failed\n");
	  goto ERR;
	}

      /* Post the message. */
      hsl_sock_post_msg (sock, hdr->nlmsg_type, hdr->nlmsg_seq, 0, (char *)tbuf, nbytes);
    }

  return 0;

 ERR:
  /* Close the socket. */
  hsl_sock_release (sock);

  return -1;
}

/* HAL_MSG_IF_GET_METRIC message. */
int
hsl_msg_recv_if_get_metric (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;
  u_int32_t cindex = 0;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Get interface metric\n");

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_METRIC);
  ret = _hsl_msg_process_if_get (sock, hdr, msgbuf, cindex);

  return ret;
}

/* HAL_MSG_IF_GET_MTU message. */
int
hsl_msg_recv_if_get_mtu (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;
  u_int32_t cindex = 0;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Get interface MTU\n");

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_MTU);
  ret = _hsl_msg_process_if_get (sock, hdr, msgbuf, cindex);

  return ret;
}

/* HAL_MSG_IF_SET_MTU message. */
int
hsl_msg_recv_if_set_mtu (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_if msg;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Set interface list\n");

  /* Get requests should have ACK flag set. */

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_if (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_set_mtu (msg.ifindex, msg.mtu, HSL_FALSE);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}

#ifdef HAVE_L3
/* HAL_MSG_IF_GET_ARP_AGEING_TIMEOUT message. */
int
hsl_msg_recv_if_get_arp_ageing_timeout (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;
  u_int32_t cindex = 0;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Get interface ARP AGEING TIMEOUT\n");

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_ARP_AGEING_TIMEOUT);
  ret = _hsl_msg_process_if_get (sock, hdr, msgbuf, cindex);

  return ret;
}

/* HAL_MSG_IF_SET_ARP_AGEING_TIMEOUT message. */
int
hsl_msg_recv_if_set_arp_ageing_timeout (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_if msg;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Set interface ARP AGEING TIMEOUT\n");

  /* Get requests should have ACK flag set. */

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  ret = hsl_msg_decode_if (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_set_arp_ageing_timeout (msg.ifindex, msg.arp_ageing_timeout);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}
#endif /* HAVE_L3 */

/* HAL_MSG_IF_GET_DUPLEX message. */
int
hsl_msg_recv_if_get_duplex (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;
  u_int32_t cindex = 0;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Get interface DUPLEX\n");

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_DUPLEX);
  ret = _hsl_msg_process_if_get (sock, hdr, msgbuf, cindex);

  return ret;
}

/* HAL_MSG_IF_SET_DUPLEX message. */
int
hsl_msg_recv_if_set_duplex (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_if msg;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Set interface DUPLEX\n");

  /* Get requests should have ACK flag set. */

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  ret = hsl_msg_decode_if (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_set_duplex (msg.ifindex, msg.duplex, HSL_FALSE);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}

/* HAL_MSG_IF_GET_HWADDR message. */
int
hsl_msg_recv_if_get_hwaddr (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;
  u_int32_t cindex = 0;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Get interface hardware address\n");

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_HW);
  ret = _hsl_msg_process_if_get (sock, hdr, msgbuf, cindex);

  return ret;
}


/* HAL_MSG_IF_SET_AUTONEGO message. */
int
hsl_msg_recv_if_set_autonego (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_if msg;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Set interface AUTONEGO\n");

  /* Get requests should have ACK flag set. */

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  ret = hsl_msg_decode_if (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_set_autonego (msg.ifindex, msg.autonego,HSL_FALSE);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}

/* HAL_MSG_IF_SET_HWADDR message. */
int
hsl_msg_recv_if_set_hwaddr (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_if msg;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Set interface hardware address\n");

  /* Get requests should have ACK flag set. */

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_if (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_set_hwaddr (msg.ifindex, msg.hw_addr_len, msg.hw_addr, HSL_FALSE);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}

#ifdef HAVE_L3
static int
_hsl_msg_recv_if_sec_hwaddrs (struct hal_nlmsghdr *hdr, char *msgbuf,
                              int (*func) (hsl_ifIndex_t ifindex, int hwaddrlen, int num, u_char **hwaddr, HSL_BOOL send_notification))
{
  struct hal_msg_if msg;
  u_int32_t size;
  u_char *pnt;
  int ret;
  int i;

  ret = 0;
  
  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  /* Decode interface message. */     
  ret = hsl_msg_decode_if (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = (*func) (msg.ifindex, HSL_ETHER_ADDRLEN, msg.nAddrs, msg.addresses, HSL_FALSE);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_ERROR, "Error setting secondary hardware addresses\n");
    }

 CLEANUP:
  if (msg.addresses)
    {
      for (i = 0; i < msg.nAddrs; i++)
        oss_free (msg.addresses[i], OSS_MEM_HEAP);

      oss_free (msg.addresses, OSS_MEM_HEAP);
    }

  return ret;
}

/* HAL_MSG_IF_SET_SEC_HWADDRS message. */
int
hsl_msg_recv_if_set_sec_hwaddrs (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;
  
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL set interface secondary hardware address\n"); 

  ret = _hsl_msg_recv_if_sec_hwaddrs (hdr, msgbuf, hsl_ifmgr_set_secondary_hwaddrs);

  if (hdr->nlmsg_flags & HAL_NLM_F_ACK)
    {
      HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
    }

  return ret;
}

/* HAL_MSG_IF_ADD_SEC_HWADDRS message. */
int
hsl_msg_recv_if_add_sec_hwaddrs (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL add interface secondary hardware address\n"); 

  ret = _hsl_msg_recv_if_sec_hwaddrs (hdr, msgbuf, hsl_ifmgr_add_secondary_hwaddrs);

  if (hdr->nlmsg_flags & HAL_NLM_F_ACK)
    {
      HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
    }

  return ret;
}

/* HAL_MSG_IF_DELETE_SEC_HWADDRS message. */
int
hsl_msg_recv_if_delete_sec_hwaddrs (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL delete interface secondary hardware address\n"); 

  ret = _hsl_msg_recv_if_sec_hwaddrs (hdr, msgbuf, hsl_ifmgr_delete_secondary_hwaddrs);

  if (hdr->nlmsg_flags & HAL_NLM_F_ACK)
    {
      HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
    }

  return ret;
}
#endif /* HAVE_L3 */

/* HAL_MSG_IF_FLAGS_GET message. */
int
hsl_msg_recv_if_flags_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;
  u_int32_t cindex = 0;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Get interface flags\n");

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_FLAGS);
  ret = _hsl_msg_process_if_get (sock, hdr, msgbuf, cindex);

  return ret;
}

/* HAL_MSG_IF_FLAGS_SET message. */
int
hsl_msg_recv_if_flags_set (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_if msg;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Set interface flags\n");

  /* Get requests should have ACK flag set. */

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_if (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_set_flags (msg.name, msg.ifindex, msg.flags);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;

 CLEANUP:
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Errror Failed: HAL Set interface flags\n");
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}

/* HAL_MSG_IF_FLAGS_UNSET message. */
int
hsl_msg_recv_if_flags_unset (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_if msg;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Unset interface flags\n");

  /* Get requests should have ACK flag set. */

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_if (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_unset_flags (msg.name, msg.ifindex, msg.flags);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}

/* HAL_MSG_IF_GET_BW message. */
int
hsl_msg_recv_if_get_bw (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;
  u_int32_t cindex = 0;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Get interface bandwidth\n");

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_BANDWIDTH);
  ret = _hsl_msg_process_if_get (sock, hdr, msgbuf, cindex);

  return ret;
}


/* HAL_MSG_IF_SET_BW message. */
int
hsl_msg_recv_if_set_bw (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_if msg;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Set interface BANDWIDTH\n");

  /* Get requests should have ACK flag set. */

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  ret = hsl_msg_decode_if (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_set_bandwidth (msg.ifindex,msg.bandwidth, HSL_FALSE);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}

/* HAL_MSG_IF_COUNTERS_GET message. */
int 
hsl_msg_recv_if_get_counters (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_if_stat *req;
  int ret = 0, respsz = 0;
  struct hal_msg_if_stat resp;

  //HSL_FN_ENTER();

  memset (&resp, 0, sizeof (resp));

  req = (struct hal_msg_if_stat*) msgbuf;
  ret =  hsl_ifmgr_get_if_counters(req->ifindex, &resp.cntrs);
  if (ret == 0)
    {
      /* Total response size based on count. */
      respsz = sizeof (struct hal_if_counters);

      /* Post the message. */
      ret = hsl_sock_post_msg (sock, HAL_MSG_IF_COUNTERS_GET, 0, hdr->nlmsg_seq, (char *)&resp, respsz);
    }
  else
    ret = hsl_sock_post_ack (sock, hdr, 0, -1);

  //HSL_FN_EXIT (ret);
  return ret;
}

/* HAL_MSG_IF_COUNTERS_CLEAR message. */
int 
hsl_msg_recv_if_clear_counters (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_if_clear_stat *req;
  int ret = 0, respsz = 0;
  

  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Clear interface counters\r\n");

  //printk("hsl_msg_recv_if_clear_counters, before hsl_ifmgr_clear_if_counters\r\n");

  req = (struct hal_msg_if_clear_stat*) msgbuf;
  ret =  hsl_ifmgr_clear_if_counters(req->ifindex);
  if (ret == 0)
    {
      /* Total response size based on count. */
      respsz = sizeof (struct hal_if_counters);

      ret = hsl_sock_post_ack (sock, hdr, 0, 0);
    }
  else
    ret = hsl_sock_post_ack (sock, hdr, 0, -1);

  //printk("hsl_msg_recv_if_clear_counters return %d\r\n", ret);
  HSL_FN_EXIT (ret);
}
/* HAL_MSG_IF_SET_PORT_TYPE message. */
int
hsl_msg_recv_if_set_port_type (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_if_port_type *msg = (struct hal_msg_if_port_type *) msgbuf;
  struct hsl_if *ifp = NULL, *ifpp = NULL;
  int ret;
  u_int32_t cindex = 0;

  ifp = hsl_ifmgr_lookup_by_index (msg->ifindex);
  if (! ifp)
    goto ERR; 

  HSL_IFMGR_IF_REF_DEC (ifp);
#if defined(HAVE_L2)
  if (msg->type == HAL_MSG_SET_SWITCHPORT)
    {
      HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Set port type to switchport\n");
      /* Lookup interface. It has to be of type IP. */
      ret = hsl_ifmgr_set_switch_port (ifp, &ifpp, HSL_FALSE);
      if (ret < 0)
        {
          HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_ERROR, "Failed: HAL Set switchport\n");
	  goto ERR;
        }
    }
  else 
#endif /* HAVE_L2 */
#if defined(HAVE_L3)
    if (msg->type == HAL_MSG_SET_ROUTERPORT)
      {
        HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Set port type to router port\n");
	/* Lookup interface. It has to be of type L2_ETHERNET. */
	ret = hsl_ifmgr_set_router_port (ifp, NULL, &ifpp, HSL_FALSE);
	if (ret < 0)
          {
            HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_ERROR, "Failed: HAL Set Router port\n");
	    goto ERR;
          }
      }
    else
#endif /* HAVE_L3 */
      goto ERR;

  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_FLAGS);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_METRIC);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_MTU);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_DUPLEX);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_ARP_AGEING_TIMEOUT);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_AUTONEGO);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_HW);
  SET_CINDEX (cindex, HAL_MSG_CINDEX_IF_BANDWIDTH);
  
  ret = _hsl_msg_if_event (sock, ifpp, cindex, HAL_MSG_IF_NEWLINK);
  if (ret < 0)
    goto CLEANUP;

  return 0;  

 ERR:
  HSL_MSG_PROCESS_RETURN (sock, hdr, -1);

  return 0;
 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}

#if defined(HAVE_L2) && defined(HAVE_L3)
/* HAL_MSG_IF_CREATE_SVI message. */
int
hsl_msg_recv_if_create_svi (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_svi *msg = (struct hal_msg_svi *) msgbuf;
  struct hsl_if *ifpp = NULL;
  int br_id, vid;
  int ret = 0;
  char *mac = NULL;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Create SVI\n");
  /* Get MAC for SVI. */
  mac = hsl_bcm_ifmap_svi_mac_get ();

  sscanf (msg->name, "vlan%d.%d", &br_id, &vid);

  /* Register with interface manager. */
  ret = hsl_ifmgr_L3_register (msg->name, (u_char *)mac, 6, NULL, &ifpp);
  if (ret < 0)
    goto ERR;

  /* Link the VLAN port members to this SVI. */
  hsl_vlan_svi_link_port_members (ifpp, vid);
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;

 ERR:
  HSL_MSG_PROCESS_RETURN (sock, hdr, -1);

  return 0;
}

/* HAL_MSG_IF_DELETE_SVI message. */
int
hsl_msg_recv_if_delete_svi (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_svi *msg = (struct hal_msg_svi *) msgbuf;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Delete SVI\n");

  /* Unregister this SVI from the interface manager. */
  ret = hsl_ifmgr_L3_unregister (msg->name, msg->ifindex);
  if (ret < 0)
    {
      HSL_MSG_PROCESS_RETURN (sock, hdr, -1);
      return 0;
    } 

  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);

  return 0;
}
#endif /* HAVE_L2 && HAVE_L3 */

#ifdef HAVE_L3
/*  HAL_MSG_IF_IPV4_NEWADDR message. */
int
hsl_msg_recv_if_ipv4_newaddr (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_if_ipv4_addr *msg = (struct hal_msg_if_ipv4_addr *) msgbuf;
  hsl_prefix_t prefix;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPv4 address add\n");

  memset (&prefix, 0, sizeof (hsl_prefix_t));
  prefix.family = AF_INET;
  prefix.prefixlen = msg->ipmask;
  prefix.u.prefix4 = msg->addr.s_addr;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "ipaddr = %x\n", prefix.u.prefix4);
  
  ret = hsl_ifmgr_ipv4_address_add (msg->name, msg->ifindex, &prefix, 0);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return ret;
}

/*  HAL_MSG_IF_IPV4_DELADDR message. */
int
hsl_msg_recv_if_ipv4_deladdr (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_if_ipv4_addr *msg = (struct hal_msg_if_ipv4_addr *) msgbuf;
  hsl_prefix_t prefix;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPv4 address delete\n");

  memset (&prefix, 0, sizeof (hsl_prefix_t));
  prefix.family = AF_INET;
  prefix.prefixlen = msg->ipmask;
  prefix.u.prefix4 = msg->addr.s_addr;
  
  ret = hsl_ifmgr_ipv4_address_delete (msg->name, msg->ifindex, &prefix);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return ret;
}

/*  HAL_MSG_IPV4_INIT message. */
int
hsl_msg_recv_ipv4_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPv4 initialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);

  return 0;
}

/*  HAL_MSG_IPV4_DEINIT message. */
int
hsl_msg_recv_ipv4_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPv4 deinitialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_GET_MAX_MULTIPATH message. */
int
hsl_msg_recv_get_max_multipath (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_int32_t ecmp;

  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Get maximum number of multipaths.\n");

  hsl_fib_get_max_num_multipath(&ecmp);

  hsl_sock_post_msg (sock, HAL_MSG_GET_MAX_MULTIPATH, 0, hdr->nlmsg_seq, (char *)&ecmp, sizeof (u_int32_t));
  HSL_FN_EXIT(STATUS_OK);
}

/*  HAL_MSG_FIB_CREATE message. */
int
hsl_msg_recv_fib_create (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;
  hsl_fib_id_t *fib_id;

  HSL_FN_ENTER();

  fib_id = (hsl_fib_id_t *)msgbuf;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL FIB %d Create \n", *fib_id);

  ret = hsl_fib_create_tables (*fib_id);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  HSL_FN_EXIT(STATUS_OK);
}

/*  HAL_MSG_FIB_DELETE message. */
int
hsl_msg_recv_fib_delete (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;
  hsl_fib_id_t *fib_id;

  HSL_FN_ENTER();

  fib_id = (hsl_fib_id_t *)msgbuf;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL FIB %d Delete\n", *fib_id);

  ret = hsl_fib_destroy_tables (*fib_id);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  HSL_FN_EXIT(STATUS_OK);
}

/*  HAL_MSG_IPV4_UC_ADD message. */
int
hsl_msg_recv_ipv4_uc_add (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt; 
  u_int32_t size;
  struct hal_msg_ipv4uc_route msg;
  int ret;
  int i, j;
  hsl_prefix_t p;
  
  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
       
  ret =  hsl_msg_decode_ipv4_route (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;
    
  /* Set prefix. */
  p.family = AF_INET;
  p.prefixlen = msg.masklen;
  p.u.prefix4 = msg.addr.s_addr;
  
  for (i = 0; i < msg.num; i++)
    { 
      if (msg.nh[i].nexthopIP.s_addr == 0)
	ret = hsl_fib_add_ipv4uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[i].type, msg.nh[i].egressIfindex,
					 NULL);
      else
	ret = hsl_fib_add_ipv4uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[i].type, msg.nh[i].egressIfindex,
					 &msg.nh[i].nexthopIP.s_addr);
	  printk("%x/%u fib=%u, type=%u, egressIfindex=%u, nh=%x\n",
            msg.addr.s_addr, msg.masklen, 
	        (hsl_fib_id_t)msg.fib_id, msg.nh[i].type, msg.nh[i].egressIfindex,
	        msg.nh[i].nexthopIP.s_addr);
      if (ret < 0)
	goto ERR;
    }

  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
  
 ERR:
  /* Delete previous installed routes. */
  for (j = 0; j < i; j++)
    {
      if (msg.nh[j].nexthopIP.s_addr == 0)
	hsl_fib_delete_ipv4uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[j].type, msg.nh[j].egressIfindex,
				      NULL);
      else
        hsl_fib_delete_ipv4uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[j].type, msg.nh[j].egressIfindex,
				      &msg.nh[j].nexthopIP.s_addr);
    }
  HSL_MSG_PROCESS_RETURN (sock, hdr, -1);
  return 0;

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  
  return -1;
}

/*  HAL_MSG_IPV4_UC_DELETE message. */
int
hsl_msg_recv_ipv4_uc_delete (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_ipv4uc_route msg;
  int ret;
  int i, j;
  hsl_prefix_t p;

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  ret =  hsl_msg_decode_ipv4_route (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  /* Set prefix. */
  p.family = AF_INET;
  p.prefixlen = msg.masklen;
  p.u.prefix4 = msg.addr.s_addr;

  for (i = 0; i < msg.num; i++)
    {
      if (msg.nh[i].nexthopIP.s_addr == 0)
	ret = hsl_fib_delete_ipv4uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[i].type, msg.nh[i].egressIfindex,
					    NULL);
      else
	ret = hsl_fib_delete_ipv4uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[i].type, msg.nh[i].egressIfindex,
					    &msg.nh[i].nexthopIP.s_addr);
      if (ret < 0)
	goto ERR;
    }

  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;

 ERR:
  /* Reinstall the deleted ones to send one response. */
  for (j = 0; j < i; j++)
    {
      if (msg.nh[j].nexthopIP.s_addr == 0)
	ret = hsl_fib_add_ipv4uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[j].type, msg.nh[j].egressIfindex,
					 NULL);
      else
	ret = hsl_fib_add_ipv4uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[j].type, msg.nh[j].egressIfindex,
					 &msg.nh[j].nexthopIP.s_addr);
    }

  HSL_MSG_PROCESS_RETURN (sock, hdr, -1);
  return 0;
 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}

/*  HAL_MSG_IPV4_UC_UPDATE message. */
int
hsl_msg_recv_ipv4_uc_update (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  return 0;
}

#ifdef HAVE_MCAST_IPV4

/* HAL_MSG_IPV4_MC_INIT */
int
hsl_msg_recv_ipv4_mc_init(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL multicast init.\n");

  hsl_ipv4_mc_init();

  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  HSL_FN_EXIT(STATUS_OK);
}

/* HAL_MSG_IPV4_MC_DEINIT */
int
hsl_msg_recv_ipv4_mc_deinit(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL multicast deinit.\n");

  hsl_ipv4_mc_deinit();

  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  HSL_FN_EXIT(STATUS_OK);
}
/* HAL_MSG_IPV4_MC_PIM_INIT */
int
hsl_msg_recv_ipv4_mc_pim_init(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL multicast pim init.\n");
  
  hsl_ipv4_mc_pim_init();
  
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  HSL_FN_EXIT(STATUS_OK);
}

/* HAL_MSG_IPV4_MC_PIM_DEINIT */
int 
hsl_msg_recv_ipv4_mc_pim_deinit(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL multicast pim deinit.\n");

  hsl_ipv4_mc_pim_deinit();
  
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  HSL_FN_EXIT(STATUS_OK);
}

/* HAL_MSG_IPV4_MC_VIF_ADD */
int 
hsl_msg_recv_ipv4_mc_vif_add(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_ipv4mc_vif_add msg;
  int ret;

  HSL_FN_ENTER(); 
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL add mc interface\n");

  /* Get requests should have ACK flag set. */
  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_ipv4_vif_add(&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ipv4_mc_vif_add(msg.vif_index, msg.ifindex, 
                            msg.loc_addr.s_addr,
                            msg.rmt_addr.s_addr,msg.flags);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT(STATUS_ERROR);
}

/* HAL_MSG_IPV4_MC_VIF_DEL */
int
hsl_msg_recv_ipv4_mc_vif_del(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_int32_t vif_index = *((int *)msgbuf);
  int ret;
  
  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL delete mc interface\n");

  ret = hsl_ipv4_mc_vif_del(vif_index);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}

/* HAL_MSG_IPV4_MC_MRT_ADD */
int 
hsl_msg_recv_ipv4_mc_route_add(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_ipv4mc_mrt_add msg;
  int ret;
   
  HSL_FN_ENTER(); 
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL add mc route \n");

  /* Get requests should have ACK flag set. */
  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_ipv4_mrt_add(&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_mc_v4_route_add(msg.src.s_addr, msg.group.s_addr,
                              msg.iif_vif, msg.num_olist, msg.olist_ttls);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT(STATUS_ERROR);
}

/* HAL_MSG_IPV4_MC_MRT_DEL */ 
int
hsl_msg_recv_ipv4_mc_route_del(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_ipv4mc_mrt_del msg;
  int ret;

  HSL_FN_ENTER(); 
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL delete mc route \n");

  /* Get requests should have ACK flag set. */
  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_ipv4_mrt_del(&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_mc_v4_route_del(msg.src.s_addr, msg.group.s_addr);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT(STATUS_ERROR);

}

/* HAL_MSG_IPV4_MC_SG_STAT_REQ */ 
int
hsl_msg_recv_ipv4_mc_stat_get(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_ipv4mc_sg_stat msg;
  int ret; 
  int szsgstat = sizeof (struct hal_msg_ipv4mc_sg_stat);

  HSL_FN_ENTER(); 
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL get mc route statistics\n");

  /* Get requests should have ACK flag set. */
  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_ipv4_sg_stat(&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_mc_v4_sg_stat(msg.src.s_addr, msg.group.s_addr, 
                            msg.iif_vif, &msg.pktcnt, &msg.bytecnt, 
                            &msg.wrong_if);

  /* Post response. */
  hsl_sock_post_msg (sock, HAL_MSG_IPV4_MC_SG_STAT, hdr->nlmsg_seq, 0, (char *) &msg, szsgstat);

  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT(STATUS_ERROR);
}
#endif /* HAVE_MCAST_IPV4 */

#ifdef HAVE_MCAST_IPV6

/* HAL_MSG_IPV6_MC_INIT */
int
hsl_msg_recv_ipv6_mc_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPv6 multicast init.\n");

  hsl_ipv6_mc_init();

  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  HSL_FN_EXIT(STATUS_OK);
}

/* HAL_MSG_IPV6_MC_DEINIT */
int
hsl_msg_recv_ipv6_mc_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPv6 multicast deinit.\n");

  hsl_ipv6_mc_deinit();

  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  HSL_FN_EXIT(STATUS_OK);
}

/* HAL_MSG_IPV6_MC_PIM_INIT */
int
hsl_msg_recv_ipv6_mc_pim_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPv6 multicast pim init.\n");
  
  hsl_ipv6_mc_pim_init();
  
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  HSL_FN_EXIT(STATUS_OK);
}

/* HAL_MSG_IPV6_MC_PIM_DEINIT */
int 
hsl_msg_recv_ipv6_mc_pim_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPv6 multicast pim deinit.\n");

  hsl_ipv6_mc_pim_deinit();
  
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  HSL_FN_EXIT(STATUS_OK);
}

/* HAL_MSG_IPV6_MC_VIF_ADD */
int 
hsl_msg_recv_ipv6_mc_vif_add(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_ipv6mc_vif_add msg;
  int ret;

  HSL_FN_ENTER(); 
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL add IPv6 mc interface\n");

  /* Get requests should have ACK flag set. */
  pnt = msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_ipv6_vif_add (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ipv6_mc_vif_add (msg.vif_index, msg.phy_ifindex, msg.flags);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT(STATUS_ERROR);
}

/* HAL_MSG_IPV6_MC_VIF_DEL */
int
hsl_msg_recv_ipv6_mc_vif_del (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_int32_t vif_index = *((u_int32_t *)msgbuf);
  int ret;
  
  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL delete IPv6 mc interface\n");

  ret = hsl_ipv6_mc_vif_del (vif_index);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}

/* HAL_MSG_IPV6_MC_MRT_ADD */
int 
hsl_msg_recv_ipv6_mc_route_add (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_ipv6mc_mrt_add msg;
  int ret;
   
  HSL_FN_ENTER(); 
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL add IPv6 mc route \n");

  /* Get requests should have ACK flag set. */
  pnt = msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  memset (&msg, 0, sizeof (struct hal_msg_ipv6mc_mrt_add));

  ret = hsl_msg_decode_ipv6_mrt_add (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_mc_v6_route_add((hsl_ipv6Address_t *)&msg.src, 
			      (hsl_ipv6Address_t *)&msg.group, msg.iif_vif, msg.num_olist, 
			      msg.olist);

  /* Free memory allocated by decoding routine */
  if (msg.olist)
    oss_free (msg.olist, OSS_MEM_HEAP);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Free memory allocated by decoding routine */
  oss_free (msg.olist, OSS_MEM_HEAP);

  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT(STATUS_ERROR);
}

/* HAL_MSG_IPV6_MC_MRT_DEL */ 
int
hsl_msg_recv_ipv6_mc_route_del (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_ipv6mc_mrt_del msg;
  int ret;

  HSL_FN_ENTER(); 
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL delete IPv6 mc route \n");

  /* Get requests should have ACK flag set. */
  pnt = msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_ipv6_mrt_del (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_mc_v6_route_del((hsl_ipv6Address_t *)&msg.src, (hsl_ipv6Address_t *)&msg.group);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT(STATUS_ERROR);

}

/* HAL_MSG_IPV6_MC_SG_STAT_REQ */ 
int
hsl_msg_recv_ipv6_mc_stat_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_ipv6mc_sg_stat msg;
  int ret; 
  int szsgstat = sizeof (struct hal_msg_ipv6mc_sg_stat);

  HSL_FN_ENTER(); 
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL get IPv6 mc route statistics\n");

  /* Get requests should have ACK flag set. */
  pnt = msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_ipv6_sg_stat (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_mc_v6_sg_stat  ((hsl_ipv6Address_t *)&msg.src, (hsl_ipv6Address_t *)&msg.group, 
                             msg.iif_vif, &msg.pktcnt, &msg.bytecnt, 
                             &msg.wrong_if);

  /* Post response. */
  hsl_sock_post_msg (sock, HAL_MSG_IPV6_MC_SG_STAT, hdr->nlmsg_seq, 0, (char *) &msg, szsgstat);

  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  HSL_FN_EXIT(STATUS_ERROR);
}
#endif /* HAVE_MCAST_IPV6 */

#ifdef HAVE_IPV6
/*  HAL_MSG_IF_IPV6_ADDRESS_ADD message. */
int
hsl_msg_recv_if_ipv6_newaddr (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_if_ipv6_addr *msg = (struct hal_msg_if_ipv6_addr *) msgbuf;
  hsl_prefix_t prefix;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPv6 address add\n");

  memset (&prefix, 0, sizeof (hsl_prefix_t));
  prefix.family = AF_INET6;
  prefix.prefixlen = msg->ipmask;
  memcpy (&prefix.u.prefix6, &msg->addr, sizeof (struct hal_in6_addr));
  
  ret = hsl_ifmgr_ipv6_address_add (msg->name, msg->ifindex, &prefix, msg->flags);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return ret;
}

/*  HAL_MSG_IF_IPV6_ADDRESS_DELETE message. */
int
hsl_msg_recv_if_ipv6_deladdr (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_if_ipv6_addr *msg = (struct hal_msg_if_ipv6_addr *) msgbuf;
  hsl_prefix_t prefix;
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPv6 address delete\n");

  memset (&prefix, 0, sizeof (hsl_prefix_t));
  prefix.family = AF_INET6;
  prefix.prefixlen = msg->ipmask;
  memcpy (&prefix.u.prefix6, &msg->addr, sizeof (struct hal_in6_addr));
  
  ret = hsl_ifmgr_ipv6_address_delete (msg->name, msg->ifindex, &prefix);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return ret;
}

/*  HAL_MSG_IPV6_INIT message. */
int
hsl_msg_recv_ipv6_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPv6 initialization\n");

#if 0
  /* Initialize L3. */
  bcmx_l3_init ();
#endif 
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  
  return 0;
}

/*  HAL_MSG_IPV6_DEINIT message. */
int
hsl_msg_recv_ipv6_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPv6 deinitialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_IPV6_UC_INIT message. */
int
hsl_msg_recv_ipv6_uc_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  return 0;
}


/*  HAL_MSG_IPV6_UC_DEINIT message. */
int
hsl_msg_recv_ipv6_uc_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  return 0;
}



/*  HAL_MSG_IPV6_UC_ADD message. */
int
hsl_msg_recv_ipv6_uc_add (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt; 
  u_int32_t size;
  struct hal_msg_ipv6uc_route msg;
  int ret;
  int i, j;
  hsl_prefix_t p;
  
  pnt = msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
       
  ret =  hsl_msg_decode_ipv6_route (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;
    
  /* Set prefix. */
  p.family = AF_INET6;
  p.prefixlen = msg.masklen;
  memcpy (&p.u.prefix6, &msg.addr, sizeof (struct hal_in6_addr));
  
  for (i = 0; i < msg.num; i++)
    { 
      if (IPV6_ADDR_ZERO (msg.nh[i].nexthopIP))
	ret = hsl_fib_add_ipv6uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[i].type, msg.nh[i].egressIfindex,
					 NULL);
      else
	ret = hsl_fib_add_ipv6uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[i].type, msg.nh[i].egressIfindex,
					 (hsl_ipv6Address_t *) &msg.nh[i].nexthopIP);
      if (ret < 0)
	goto ERR;
    }

  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
  
 ERR:
  /* Delete previous installed routes. */
  for (j = 0; j < i; j++)
    {
      if (IPV6_ADDR_ZERO (msg.nh[j].nexthopIP))
	hsl_fib_delete_ipv6uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[j].type, msg.nh[j].egressIfindex,
				      NULL);
      else
        hsl_fib_delete_ipv6uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[j].type, msg.nh[j].egressIfindex,
				      (hsl_ipv6Address_t *) &msg.nh[j].nexthopIP);
    }
  HSL_MSG_PROCESS_RETURN (sock, hdr, -1);
  return 0;

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  
  return -1;
}

/*  HAL_MSG_IPV6_UC_DELETE message. */
int
hsl_msg_recv_ipv6_uc_delete (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_ipv6uc_route msg;
  int ret;
  int i, j;
  hsl_prefix_t p;

  pnt = msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  ret =  hsl_msg_decode_ipv6_route (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  /* Set prefix. */
  p.family = AF_INET6;
  p.prefixlen = msg.masklen;
  memcpy (&p.u.prefix6, &msg.addr, sizeof (struct hal_in6_addr));

  for (i = 0; i < msg.num; i++)
    {
      if (IPV6_ADDR_ZERO (msg.nh[i].nexthopIP))
	ret = hsl_fib_delete_ipv6uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[i].type, msg.nh[i].egressIfindex,
					    NULL);
      else
	ret = hsl_fib_delete_ipv6uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[i].type, msg.nh[i].egressIfindex,
					    (hsl_ipv6Address_t *) &msg.nh[i].nexthopIP);
      if (ret < 0)
	goto ERR;
    }

  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;

 ERR:
  /* Reinstall the deleted ones to send one response. */
  for (j = 0; j < i; j++)
    {
      if (IPV6_ADDR_ZERO (msg.nh[j].nexthopIP))
	ret = hsl_fib_add_ipv6uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[j].type, msg.nh[j].egressIfindex,
					 NULL);
      else
	ret = hsl_fib_add_ipv6uc_prefix ((hsl_fib_id_t)msg.fib_id,
            &p, msg.nh[j].type, msg.nh[j].egressIfindex,
					 (hsl_ipv6Address_t *) &msg.nh[j].nexthopIP);
    }

  HSL_MSG_PROCESS_RETURN (sock, hdr, -1);
  return 0;
 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);

  return -1;
}

/*  HAL_MSG_IPV6_UC_UPDATE message. */
int
hsl_msg_recv_ipv6_uc_update (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  return 0;
}
#endif /* HAVE_IPV6 */

/*  HAL_MSG_IF_FIB_BIND message. */
int
hsl_msg_recv_if_bind_fib (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt; 
  u_int32_t size;
  struct hal_msg_if_fib_bind_unbind msg;
  int ret;
  
  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
       
  ret =  hsl_msg_decode_if_fib_bind_unbind (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;
    
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IF %d Bind FIB %d\n",
      msg.ifindex, msg.fib_id);

  ret = hsl_ifmgr_if_bind_fib (msg.ifindex, (hsl_fib_id_t)msg.fib_id);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return 0;

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  
  return -1;
}

/*  HAL_MSG_IF_FIB_UNBIND message. */
int
hsl_msg_recv_if_unbind_fib (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt; 
  u_int32_t size;
  struct hal_msg_if_fib_bind_unbind msg;
  int ret;
  
  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
       
  ret =  hsl_msg_decode_if_fib_bind_unbind (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;
    
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IF %d Unbind FIB %d\n",
      msg.ifindex, msg.fib_id);

  ret = hsl_ifmgr_if_unbind_fib (msg.ifindex, (hsl_fib_id_t)msg.fib_id);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return 0;

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  
  return -1;
}
#endif /* HAVE_L3 */



#ifdef HAVE_L2
/*
  HAL_MSG_IF_L2_INIT message.
*/
int
hsl_msg_recv_if_init_l2(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;   
  ret = hsl_ifmgr_init_policy_l2 ();
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}

/* HAL_MSG_BRIDGE_INIT message. */
int
hsl_msg_recv_bridge_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Bridging initialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_BRIDGE_DEINIT message. */
int
hsl_msg_recv_bridge_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Bridging deinitialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_BRIDGE_ADD message */
int
hsl_msg_recv_bridge_add (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_bridge *msg;
  int ret;

  msg = (struct hal_msg_bridge *) msgbuf;
  
  ret = hsl_bridge_add (msg->name, msg->is_vlan_aware);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return ret;
}

/*  HAL_MSG_BRIDGE_DELETE message. */
int
hsl_msg_recv_bridge_delete (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_bridge *msg;
  int ret;

  msg = (struct hal_msg_bridge *) msgbuf;

  ret = hsl_bridge_delete (msg->name);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/*  HAL_MSG_BRIDGE_SET_AGEING_TIME message. */
int
hsl_msg_recv_set_ageing_time (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_bridge_ageing *msg;
  int ret;

  msg = (struct hal_msg_bridge_ageing *) msgbuf;

  ret = hsl_bridge_age_timer_set (msg->name, msg->ageing_time);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/* HAL_MSG_BRIDGE_SET_LEARNING message. */
int
hsl_msg_recv_set_learning (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_bridge_learn *msg;
  int ret;

  msg = (struct hal_msg_bridge_learn *) msgbuf;

  ret = hsl_bridge_learning_set (msg->name, msg->learn);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

int
hsl_msg_recv_set_if_mac_learning (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_mac_learning *msg;
  int ret;

  msg = (struct hal_msg_mac_learning *) msgbuf;

  ret = hsl_if_mac_learning_set (msg->ifindex, msg->disable);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}


/*  HAL_MSG_BRIDGE_ADD_PORT message. */
int
hsl_msg_recv_bridge_add_port (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_bridge_port *msg;
  int ret;

  msg = (struct hal_msg_bridge_port *) msgbuf;
  
  ret = hsl_bridge_add_port (msg->name, msg->ifindex);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/*  HAL_MSG_BRIDGE_DELETE_PORT message. */
int
hsl_msg_recv_bridge_delete_port (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_bridge_port *msg;
  int ret;

  msg = (struct hal_msg_bridge_port *) msgbuf;
  
  ret = hsl_bridge_delete_port (msg->name, msg->ifindex);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/*  HAL_MSG_BRIDGE_ADD_INSTANCE message. */
int
hsl_msg_recv_bridge_add_instance (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_bridge_instance *msg;
  int ret;

  msg = (struct hal_msg_bridge_instance *) msgbuf;
  
  ret = hsl_bridge_add_instance (msg->name, msg->instance);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/*  HAL_MSG_BRIDGE_DELETE_INSTANCE message. */
int
hsl_msg_recv_bridge_delete_instance (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_bridge_instance *msg;
  int ret;

  msg = (struct hal_msg_bridge_instance *) msgbuf;
  ret = hsl_bridge_delete_instance (msg->name, msg->instance);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/*  HAL_MSG_BRIDGE_ADD_VLAN_TO_INSTANCE message. */
int
hsl_msg_recv_bridge_add_vlan_to_instance (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_bridge_vid_instance *msg;
  int ret;

  msg = (struct hal_msg_bridge_vid_instance *) msgbuf;
  ret = hsl_bridge_add_vlan_to_inst (msg->name, msg->instance, msg->vid);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/*  HAL_MSG_BRIDGE_DELETE_VLAN_FROM_INSTANCE message. */
int
hsl_msg_recv_bridge_delete_vlan_from_instance (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_bridge_vid_instance *msg;
  int ret;

  msg = (struct hal_msg_bridge_vid_instance *) msgbuf;
  ret = hsl_bridge_delete_vlan_from_inst(msg->name, msg->instance, msg->vid);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

#if defined (HAVE_STPD) || defined (HAVE_RSTPD) || defined (HAVE_MSTPD)
int hsl_msg_recv_set_port_state(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;
  struct hal_msg_stp_port_state *msg =
    (struct hal_msg_stp_port_state *)msgbuf;
  
  ret = hsl_bridge_set_stp_port_state(msg->name,msg->port_ifindex,msg->instance,
				      msg->port_state);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}
#endif  /* defined (HAVE_STPD) || defined (HAVE_RSTPD) || defined (HAVE_MSTPD) */

#ifdef HAVE_VLAN

/*  HAL_MSG_VLAN_INIT message. */
int
hsl_msg_recv_vlan_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL VLAN initialization\n");
  printk ("Message: HAL VLAN initialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_VLAN_DEINIT message. */
int
hsl_msg_recv_vlan_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL VLAN deinitialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_VLAN_ADD message. */
int
hsl_msg_recv_vlan_add (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_vlan *msg;
  int ret;

  msg = (struct hal_msg_vlan *) msgbuf;
  ret = hsl_vlan_add (msg->name, msg->vid);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return ret;
}

/*  HAL_MSG_VLAN_DELETE message. */
int
hsl_msg_recv_vlan_delete (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_vlan *msg;
  int ret;

  msg = (struct hal_msg_vlan *) msgbuf;
  ret = hsl_vlan_delete (msg->name, msg->vid);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/*  HAL_MSG_VLAN_SET_PORT_TYPE message. */
int
hsl_msg_recv_vlan_set_port_type (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_vlan_port_type *msg;
  int ret;

  msg = (struct hal_msg_vlan_port_type *) msgbuf;
  ret = hsl_vlan_set_port_type (msg->name, msg->ifindex, msg->port_type, msg->acceptable_frame_type, msg->enable_ingress_filter);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/* HAL_MSG_VLAN_SET_DEFAULT_PVID message. */
int
hsl_msg_recv_vlan_set_default_pvid (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_vlan_port *msg;
  int ret;

  msg = (struct hal_msg_vlan_port *) msgbuf;
  ret = hsl_vlan_set_default_pvid (msg->name, msg->ifindex, msg->vid, msg->egress);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/*  HAL_MSG_VLAN_ADD_VID_TO_PORT message. */
int
hsl_msg_recv_vlan_add_vid_to_port (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_vlan_port *msg;
  int ret;

  msg = (struct hal_msg_vlan_port *) msgbuf;
  ret = hsl_vlan_add_vid_to_port (msg->name, msg->ifindex, msg->vid, msg->egress);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/*  HAL_MSG_DELETE_VID_FROM_PORT message. */
int
hsl_msg_recv_vlan_delete_vid_from_port (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_vlan_port *msg;
  int ret;

  msg = (struct hal_msg_vlan_port *) msgbuf;
  ret = hsl_vlan_delete_vid_from_port(msg->name, msg->ifindex, msg->vid);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

#endif /* HAVE_VLAN */

#ifdef HAVE_PVLAN
/* HAL_MSG_PVLAN_SET_VLAN_TYPE message */
int
hsl_msg_recv_pvlan_set_vlan_type (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_pvlan *msg;
  int ret;

  msg = (struct hal_msg_pvlan *) msgbuf;
  ret = hsl_pvlan_set_vlan_type(msg->name, msg->vid, msg->vlan_type);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/* HAL_MSG_PVLAN_VLAN_ASSOCIATE message */
int
hsl_msg_recv_pvlan_vlan_associate (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_pvlan_association *msg;
  int ret;

  msg = (struct hal_msg_pvlan_association *) msgbuf;
  ret = hsl_pvlan_add_vlan_association (msg->name, msg->pvid, msg->svid);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/* HAL_MSG_PVLAN_VLAN_DISSOCIATE message */
int
hsl_msg_recv_pvlan_vlan_dissociate (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_pvlan_association *msg;
  int ret;

  msg = (struct hal_msg_pvlan_association *) msgbuf;
  ret = hsl_pvlan_remove_vlan_association (msg->name, msg->pvid, msg->svid);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/* HAL_MSG_PVLAN_PORT_ADD message */
int
hsl_msg_recv_pvlan_port_add (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_pvlan_port_set *msg;
  int ret;

  msg = (struct hal_msg_pvlan_port_set *) msgbuf;
  ret = hsl_pvlan_port_add_association (msg->name, msg->ifindex,
                                        msg->pvid, msg->svid);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/* HAL_MSG_PVLAN_PORT_DELETE message */
int
hsl_msg_recv_pvlan_port_delete (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_pvlan_port_set *msg;
  int ret;

  msg = (struct hal_msg_pvlan_port_set *) msgbuf;
  ret = hsl_pvlan_port_delete_association (msg->name, msg->ifindex,
                                           msg->pvid, msg->svid);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/* HAL_MSG_PVLAN_SET_PORT_MODE message */
int
hsl_msg_recv_pvlan_set_port_mode (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_pvlan_port_mode *msg;
  int ret;

  msg = (struct hal_msg_pvlan_port_mode *) msgbuf;
  ret = hsl_pvlan_set_port_mode (msg->name, msg->ifindex, msg->port_mode);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}
#endif /* HAVE_PVLAN */

#ifdef HAVE_VLAN_CLASS
/*  HAL_MSG_VLAN_CLASSIFIER_ADD message. */
int
hsl_msg_recv_vlan_classifier_add (struct socket *sock, struct hal_nlmsghdr *hdr, 
				  char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_vlan_classifier_rule msg;
  int ret;

  HSL_FN_ENTER(); 
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL vlan classifier add\n");

  pnt = msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  ret = hsl_msg_decode_vlan_classifier_rule(&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_vlan_classifier_add (&msg);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
  
 CLEANUP:
  /* Close socket. */
  hsl_sock_release(sock);
  HSL_FN_EXIT(STATUS_ERROR);
}


/*  HAL_MSG_VLAN_CLASSIFIER_DELETE message. */
int
hsl_msg_recv_vlan_classifier_delete (struct socket *sock, struct hal_nlmsghdr *hdr, 
				     char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_vlan_classifier_rule msg;
  int ret;

  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL vlan classifier delete\n");

  pnt = msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  ret = hsl_msg_decode_vlan_classifier_rule(&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_vlan_classifier_delete (&msg);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release(sock);
  HSL_FN_EXIT(STATUS_ERROR);
}
#endif /* HAVE_VLAN_CLASS */

#ifdef HAVE_VLAN_STACK
int 
hsl_msg_recv_vlan_stacking_enable (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{

 // struct hal_msg_vlan_stack *msg = (struct hal_msg_vlan_stack *)msgbuf;
  int ret = -1;
//by chentao delete
//  ret = hsl_bcm_vlan_stacking_enable (msg->ifindex, msg->ethtype,
 //                                     msg->stackmode);
  
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return ret; 
}


int 
hsl_msg_recv_vlan_stacking_disable (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
//  struct hal_msg_vlan_stack *msg = (struct hal_msg_vlan_stack *)msgbuf;
  int ret = -1;

	//by chentao delete
 // ret = hsl_bcm_vlan_stacking_disable (msg->ifindex);
  
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return ret; 
}

int 
hsl_msg_recv_vlan_stacking_ether_set (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
//  struct hal_msg_vlan_stack *msg = (struct hal_msg_vlan_stack *)msgbuf;
  int ret = -1;
//by chentao delete
 // ret = hsl_bcm_vlan_stacking_ether_set (msg->ifindex, msg->ethtype);
  
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return ret; 
}

#endif /* HAVE_VLAN_STACK */

/*  HAL_MSG_FLOW_CONTROL_INIT message. */
int
hsl_msg_recv_flow_control_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret = 0;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Flow Control initialization\n");

//by chentao delete
 // ret = hsl_bcm_flowcontrol_init ();
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return 0;
}

/*  HAL_MSG_FLOW_CONTROL_DEINIT message. */
int
hsl_msg_recv_flow_control_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret = 0;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Flow Control deinitialization\n");

//by chentao delte
 // ret = hsl_bcm_flowcontrol_deinit ();
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return 0;
}

/*  HAL_MSG_FLOW_CONTROL_SET message. */
int
hsl_msg_recv_flow_control_set (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_flow_control *msg;
  int ret;

  msg = (struct hal_msg_flow_control *) msgbuf;
  ret = hsl_bridge_set_flowcontrol(msg->ifindex, msg->direction);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/*  HAL_MSG_FLOW_CONTROL_STATISTICS message. */
int
hsl_msg_recv_flow_control_statistics (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_int32_t *ifindex;
  struct hal_msg_flow_control_stats resp;
  int ret;

  ifindex = (u_int32_t *) msgbuf;
  ret = hsl_bridge_flowcontrol_statistics (*ifindex, &resp.direction, &resp.rxpause, &resp.txpause);
  if (ret < 0)
    {
      HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
    }
  else
    hsl_sock_post_msg (sock, HAL_MSG_FLOW_CONTROL_STATISTICS, 0, hdr->nlmsg_seq, (char *)&resp, sizeof (struct hal_msg_flow_control_stats));

  return ret;
}


/*  HAL_MSG_L2_QOS_INIT message. */
int
hsl_msg_recv_l2_qos_init (struct socket *sock, struct hal_nlmsghdr * hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL L2 QoS initialization\n");

  if (hdr->nlmsg_flags & HAL_NLM_F_ACK)
    hsl_sock_post_ack (sock, hdr, 0, 0);

  return 0;
}

/*  HAL_MSG_L2_QOS_DEINIT message. */
int
hsl_msg_recv_l2_qos_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL L2 QoS initialization\n");

  if (hdr->nlmsg_flags & HAL_NLM_F_ACK)
    hsl_sock_post_ack (sock, hdr, 0, 0);

  return 0;
}

/*  HAL_MSG_L2_QOS_DEFAULT_USER_PRIORITY_SET message. */
int
hsl_msg_recv_l2_qos_default_user_priority_set (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  return 0;
}

/*  HAL_MSG_L2_QOS_DEFAULT_USER_PRIORITY_GET message. */
int
hsl_msg_recv_l2_qos_default_user_priority_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  return 0;
}

/*  HAL_MSG_L2_QOS_REGEN_USER_PRIORITY_SET message. */
int
hsl_msg_recv_l2_qos_regen_user_priority_set (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  return 0;
}

/*  HAL_MSG_L2_QOS_REGEN_USER_PRIORITY_GET message. */
int
hsl_msg_recv_l2_qos_regen_user_priority_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  return 0;
}

/*  HAL_MSG_L2_QOS_TRAFFIC_CLASS_SET message. */
int
hsl_msg_recv_l2_qos_traffic_class_set (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  return 0;
}

/*  HAL_MSG_RATELIMIT_INIT message. */
int
hsl_msg_recv_ratelimit_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Ratelimit initialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_RATELIMIT_DEINIT message. */
int
hsl_msg_recv_ratelimit_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Ratelimit deinitialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_RATELIMIT_BCAST message. */
int
hsl_msg_recv_ratelimit_bcast (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_ratelimit *msg;
  int ret;

  msg = (struct hal_msg_ratelimit *) msgbuf;
  ret = hsl_bridge_ratelimit_bcast (msg->ifindex, msg->level, msg->fraction);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;  
}

/*  HAL_MSG_BCAST_DISCARDS_GET message. */
int
hsl_msg_recv_bcast_discards_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_int32_t *ifindex;
  int discards = 0;
  int ret;

  ifindex = (u_int32_t *) msgbuf;
  ret = hsl_bridge_ratelimit_get_bcast_discards (*ifindex, &discards);
  if (ret < 0)
    {
      HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
    }
  else
    hsl_sock_post_msg (sock, HAL_MSG_RATELIMIT_BCAST_DISCARDS_GET, 0, hdr->nlmsg_seq, (char *)&discards, sizeof (int));

  return 0;
}

/*  HAL_MSG_RATELIMIT_MCAST message. */
int
hsl_msg_recv_ratelimit_mcast (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_ratelimit *msg;
  int ret;

  msg = (struct hal_msg_ratelimit *) msgbuf;
  ret = hsl_bridge_ratelimit_mcast (msg->ifindex, msg->level, msg->fraction);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;  
}

/*  HAL_MSG_MCAST_DISCARDS_GET message. */
int
hsl_msg_recv_mcast_discards_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_int32_t *ifindex;
  int discards = 0;
  int ret;

  ifindex = (u_int32_t *) msgbuf;
  ret = hsl_bridge_ratelimit_get_bcast_discards (*ifindex, &discards);
  if (ret < 0)
    {
      HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
    }
  else
    hsl_sock_post_msg (sock, HAL_MSG_RATELIMIT_MCAST_DISCARDS_GET, 0, hdr->nlmsg_seq, (char *)&discards, sizeof (int));

  return 0;
}

/*  HAL_MSG_RATELIMIT_DLF_BCAST message. */
int
hsl_msg_recv_ratelimit_dlf_bcast (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_ratelimit *msg;
  int ret;

  msg = (struct hal_msg_ratelimit *) msgbuf;
  ret = hsl_bridge_ratelimit_dlf_bcast (msg->ifindex, msg->level, 
                                        msg->fraction);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;  
}

/*  HAL_MSG_RATELIMIT_DLF_BCAST_DISCARDS_GET message. */
int
hsl_msg_recv_dlf_bcast_discards_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_int32_t *ifindex;
  int discards = 0;
  int ret;

  ifindex = (u_int32_t *) msgbuf;
  ret = hsl_bridge_ratelimit_get_dlf_bcast_discards (*ifindex, &discards);
  if (ret < 0)
    {
      HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
    }
  else
    hsl_sock_post_msg (sock, HAL_MSG_RATELIMIT_DLF_BCAST_DISCARDS_GET, 0, hdr->nlmsg_seq, (char *)&discards, sizeof (int));

  return 0;
}

#ifdef HAVE_IGMP_SNOOP
/*  HAL_MSG_IGMP_SNOOPING_INIT message. */
int
hsl_recv_msg_igmp_snooping_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IGMP Snooping initialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_IGMP_SNOOPING_DEINIT message. */
int
hsl_recv_msg_igmp_snooping_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IGMP Snooping deinitialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_IGMP_SNOOPING_ENABLE message. */
int
hsl_msg_recv_igmp_snooping_enable (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_igs_bridge msg;
  int ret;

  HSL_FN_ENTER(); 

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL message igmp snooping enable\n");

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_igs_bridge (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_bridge_enable_igmp_snooping(msg.bridge_name);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  HSL_FN_EXIT(-1);
}

/*  HAL_MSG_IGMP_SNOOPING_DISABLE message. */
int
hsl_msg_igmp_snooping_disable (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_igs_bridge msg;
  int ret;

  HSL_FN_ENTER(); 

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL message igmp snooping disable\n");

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_igs_bridge (&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_bridge_disable_igmp_snooping(msg.bridge_name);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  HSL_FN_EXIT(ret);
}

/*  HAL_MSG_IGMP_SNOOPING_ENTRY_ADD message. */
int
hsl_msg_igmp_snooping_add_entry(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_igmp_snoop_entry msg;
  int ret;

  HSL_FN_ENTER(); 

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL message igmp snooping add entry\n");

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_igs_entry(&pnt, &size, &msg, hsl_malloc);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_mc_v4_igs_add_entry(msg.bridge_name, msg.src.s_addr,
                                msg.group.s_addr, msg.vid, msg.count,
                                msg.ifindexes, msg.is_exclude);

     
  if(msg.ifindexes) oss_free(msg.ifindexes,OSS_MEM_HEAP);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  HSL_FN_EXIT(ret);
}

/*  HAL_MSG_IGMP_SNOOPING_ENTRY_DEL message. */
int
hsl_msg_igmp_snooping_del_entry(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_igmp_snoop_entry msg;
  int ret;

  HSL_FN_ENTER(); 

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL message igmp snooping delete entry\n");

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_igs_entry(&pnt, &size, &msg, hsl_malloc);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_mc_v4_igs_del_entry(msg.bridge_name, msg.src.s_addr, msg.group.s_addr,
                                msg.vid, msg.count, msg.ifindexes, msg.is_exclude);

  if(msg.ifindexes) oss_free(msg.ifindexes,OSS_MEM_HEAP);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  HSL_FN_EXIT(ret);
}
#endif /* HAVE_IGMP_SNOOP */

#ifdef HAVE_MLD_SNOOP

#ifdef HAVE_MLD_SNOOP

/*  HAL_MSG_MLD_SNOOPING_INIT message. */
int
hsl_recv_msg_mld_snooping_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL MLD Snooping initialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_MLD_SNOOPING_DEINIT message. */
int
hsl_recv_msg_mld_snooping_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL MLD Snooping deinitialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_MLD_SNOOPING_ENABLE message. */
int
hsl_msg_recv_mld_snooping_enable (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  char *name;
  int ret;

  name = (char *) msgbuf;
  ret = hsl_bridge_enable_mld_snooping (name);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/*  HAL_MSG_MLD_SNOOPING_DISABLE message. */
int
hsl_msg_mld_snooping_disable (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  char *name;
  int ret;

  name = (char *) msgbuf;
  ret = hsl_bridge_disable_mld_snooping (name);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/*  HAL_MSG_MLD_SNOOPING_ENTRY_ADD message. */
int
hsl_msg_mld_snooping_add_entry(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_mld_snoop_entry msg;
  int ret;

  HSL_FN_ENTER();

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL message MLD snooping add entry\n");

  pnt = msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  ret = hsl_msg_decode_mlds_entry(&pnt, &size, &msg, hsl_malloc);

  if (ret < 0)
    goto CLEANUP;

  ret = hsl_mc_v6_mlds_add_entry (msg.bridge_name, (hsl_ipv6Address_t *) &msg.src,
                                  (hsl_ipv6Address_t *) &msg.group,
                                  msg.vid, msg.count, msg.ifindexes);

  if(msg.ifindexes) oss_free(msg.ifindexes,OSS_MEM_HEAP);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL message MLD CLEANUP \n");
  /* Close socket. */
  hsl_sock_release (sock);
  HSL_FN_EXIT(ret);
}

/*  HAL_MSG_MLD_SNOOPING_ENTRY_DEL message. */
int
hsl_msg_mld_snooping_del_entry (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_mld_snoop_entry msg;
  int ret;

  HSL_FN_ENTER(); 

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL message MLD snooping delete entry\n");

  pnt = msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  ret = hsl_msg_decode_mlds_entry(&pnt, &size, &msg, hsl_malloc);

  if (ret < 0)
    goto CLEANUP;

  ret = hsl_mc_v6_mlds_del_entry (msg.bridge_name, (hsl_ipv6Address_t *) &msg.src,
                                  (hsl_ipv6Address_t *) &msg.group,
                                  msg.vid, msg.count, msg.ifindexes);

  if(msg.ifindexes) oss_free(msg.ifindexes,OSS_MEM_HEAP);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  HSL_FN_EXIT(ret);
}

#endif /* HAVE_MLD_SNOOP */

#endif /* HAVE_MLD_SNOOP */

/*  HAL_MSG_L2_FDB_INIT message. */
int
hsl_msg_recv_l2_fdb_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL L2 FDB initialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_L2_FDB_DEINIT message. */
int
hsl_msg_recv_l2_fdb_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL L2 FDB deinitialization\n");
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_L2_FDB_ADD message. */
int
hsl_msg_recv_l2_fdb_add (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_l2_fdb_entry *msg;
  int ret;

  msg = (struct hal_msg_l2_fdb_entry *) msgbuf;
  ret = hsl_bridge_add_fdb (msg->name, msg->ifindex, (char *)msg->mac, HSL_ETHER_ALEN, msg->vid, msg->flags, msg->is_forward);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return ret;
}

/*  HAL_MSG_L2_FDB_DELETE message. */
int
hsl_msg_recv_l2_fdb_delete (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_l2_fdb_entry *msg;
  int ret;

  msg = (struct hal_msg_l2_fdb_entry *) msgbuf;
  ret = hsl_bridge_delete_fdb (msg->name, msg->ifindex, (char *)msg->mac, HSL_ETHER_ALEN, msg->vid, msg->flags);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return ret;
}


/*  HAL_MSG_L2_FDB_UNICAST_GET message. */
int
hsl_msg_recv_l2_fdb_count_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_l2_fdb_count_resp resp;
  int ret = 0;

  HSL_FN_ENTER();

  /* Prepare response structure. */
  resp.count = hsl_get_fdb_count();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL fdb get count:%d.\n",resp.count);

  /* Post the message. */
  ret = hsl_sock_post_msg (sock, HAL_MSG_L2_FDB_COUNT_GET, 0, hdr->nlmsg_seq, (char *)&resp, sizeof(resp));

  HSL_FN_EXIT(ret);
}

/*  HAL_MSG_L2_FDB_UNICAST_GET message. */
int
hsl_msg_recv_l2_fdb_unicast_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_l2_fdb_entry_req req;
  struct hal_msg_l2_fdb_entry_resp resp;
  int ret = 0, respsz = 0;
  char *buf = NULL;

  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL fdb get unicasts.\n");

  /* Get request. */
  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  /* Decode request message. */
  ret = hsl_msg_decode_l2_fdb_req(&pnt, &size, &req);
  if (ret < 0)
    goto CLEANUP;

  /* Prepare response structure. */
  resp.count = 0;

  /* Get buffer for mac entries. */
  size = HAL_MAX_L2_FDB_ENTRIES * sizeof (struct hal_fdb_entry);
  resp.fdb_entry = (struct hal_fdb_entry *)kmalloc (size, GFP_KERNEL);
  if(!resp.fdb_entry)
    goto CLEANUP;

  /* Zero the buffer. */ 
  memset (resp.fdb_entry, 0, size);

  /* Get unicast dynamic mac fdb. */
  ret = hsl_bridge_unicast_get_fdb (&req, &resp);

  if(ret != 0) 
    resp.count = 0;

  /* Allocate response buffer. */
  size = sizeof (struct hal_msg_l2_fdb_entry_resp) + resp.count * sizeof(struct hal_fdb_entry);
  buf = (char *) kmalloc(size,GFP_KERNEL);
  if (!buf)
    goto CLEANUP;

  pnt = (u_char *)buf;
  /* Encode message response. */
  respsz =  hsl_msg_encode_l2_fdb_resp (&pnt, &size, &resp);

  /* Post the message. */
  ret = hsl_sock_post_msg (sock, HAL_MSG_L2_FDB_UNICAST_GET, 0, hdr->nlmsg_seq, buf, respsz);

  /* Free the buffer. */
  kfree(buf);
  kfree(resp.fdb_entry);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  if(buf)            kfree(buf);
  if(resp.fdb_entry) kfree(resp.fdb_entry);
  HSL_FN_EXIT(STATUS_ERROR);
}

/*  HAL_MSG_L2_FDB_MULTICAST_GET message. */
int
hsl_msg_recv_l2_fdb_multicast_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  return 0;
}

/* HAL_MSG_L2_FDB_FLUSH_PORT message. */
int
hsl_msg_recv_l2_fdb_flush (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_l2_fdb_flush *msg;
  int ret = 0;

  msg = (struct hal_msg_l2_fdb_flush *) msgbuf;
  ret = hsl_bridge_flush_fdb (msg->name, msg->ifindex, msg->vid);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return ret;
}

/* HAL_MSG_L2_FDB_FLUSH_BY_MAC message. */
int
hsl_msg_recv_l2_fdb_flush_by_mac (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_l2_fdb_entry *msg;
  int ret;

  msg = (struct hal_msg_l2_fdb_entry *) msgbuf;
  ret = hsl_bridge_flush_fdb_by_mac (msg->name, (char *)msg->mac, HSL_ETHER_ALEN, msg->flags);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

  return ret;
}
#endif /* HAVE_L2 */

/*  HAL_MSG_PMIRROR_INIT message. */
int
hsl_msg_recv_pmirror_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;

  HSL_FN_ENTER();

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Port Mirroring initialization\n");
  /* Init port mirroring. */
  ret = hsl_ifmgr_init_portmirror ();

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(0);
}

/*  HAL_MSG_PMIRROR_DEINIT message. */
int
hsl_msg_recv_pmirror_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;

  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Port Mirroring deinitialization\n");

  /* Deinit port mirroring. */
  ret = hsl_ifmgr_deinit_portmirror ();

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(0);
}

/*  HAL_MSG_PMIRROR_SET message. */
int
hsl_msg_recv_pmirror_set (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_port_mirror *msg;
  int ret;

  msg = (struct hal_msg_port_mirror *) msgbuf;
  ret = hsl_ifmgr_set_portmirror(msg->to_ifindex, msg->from_ifindex, msg->direction);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

/*  HAL_MSG_PMIRROR_UNSET message. */
int
hsl_msg_recv_pmirror_unset (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_port_mirror *msg;
  int ret;

  msg = (struct hal_msg_port_mirror *) msgbuf;
  ret = hsl_ifmgr_unset_portmirror(msg->to_ifindex, msg->from_ifindex, msg->direction);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return ret;
}

#ifdef HAVE_QOS
/*  HAL_MSG_QOS_INIT message. */
int
hsl_msg_recv_qos_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL QOS initialization\n");

  ret = hsl_bcm_qos_init ();
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

/*  HAL_MSG_QOS_DEINIT message. */
int
hsl_msg_recv_qos_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL QOS uninitialization\n");

  ret = hsl_bcm_qos_deinit ();
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

/*  HAL_MSG_QOS_ENABLE message. */
int
hsl_msg_recv_qos_enable (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_qos_enable *msg = (struct hal_msg_qos_enable *)msgbuf;
  int ret;

  ret = hsl_bcm_qos_enable (&msg->q0[0], &msg->q1[0], &msg->q2[0], &msg->q3[0],
			    &msg->q4[0], &msg->q5[0], &msg->q6[0], &msg->q7[0]);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

/*  HAL_MSG_QOS_DISABLE message. */
int
hsl_msg_recv_qos_disable (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_qos_disable *msg = (struct hal_msg_qos_disable *)msgbuf;
  int ret;

  ret = hsl_bcm_qos_disable (msg->num_queue);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

/*  HAL_MSG_QOS_WRR_QUEUE_LIMIT message. */
int
hsl_msg_recv_qos_wrr_queue_limit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_qos_wrr_queue_limit *msg = (struct hal_msg_qos_wrr_queue_limit *)msgbuf;
  int ret;

  ret = hsl_bcm_qos_wrr_queue_limit (msg->ifindex, &msg->ratio[0]);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

/*  HAL_MSG_QOS_WRR_TAIL_DROP_THRESHOLD message. */
int
hsl_msg_recv_qos_wrr_tail_drop_threshold (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_qos_wrr_tail_drop_threshold *msg = (struct hal_msg_qos_wrr_tail_drop_threshold *)msgbuf;
  int ret;

  ret = hsl_bcm_qos_wrr_tail_drop_threshold (msg->ifindex, msg->qid, msg->thres[0], msg->thres[1]);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

/*  HAL_MSG_QOS_WRR_THRESHOLD_DSCP_MAP message. */
int
hsl_msg_recv_qos_wrr_threshold_dscp_map (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_QOS_WRR_WRED_DROP_THRESHOLD message. */
int
hsl_msg_recv_qos_wrr_wred_drop_threshold (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_qos_wrr_wred_drop_threshold *msg = (struct hal_msg_qos_wrr_wred_drop_threshold *)msgbuf;
  int ret;

  ret = hsl_bcm_qos_wrr_wred_drop_threshold (msg->ifindex, msg->qid, msg->thres[0], msg->thres[1]);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

/*  HAL_MSG_QOS_WRR_SET_BANDWIDTH message. */
int
hsl_msg_recv_qos_wrr_set_bandwidth (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_qos_wrr_set_bandwidth *msg = (struct hal_msg_qos_wrr_set_bandwidth *)msgbuf;
  int ret;

  ret = hsl_bcm_qos_wrr_set_bandwidth (msg->ifindex, &msg->bw[0]);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

/*  HAL_MSG_QOS_WRR_QUEUE_COS_MAP_SET message. */
int
hsl_msg_recv_qos_wrr_queue_cos_map_set (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_QOS_WRR_QUEUE_COS_MAP_UNSET message. */
int
hsl_msg_recv_qos_wrr_queue_cos_map_unset (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}


/*  HAL_MSG_QOS_WRR_QUEUE_MIN_RESERVE message. */
int
hsl_msg_recv_qos_wrr_queue_min_reserve (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_qos_wrr_queue_min_reserve *msg = (struct hal_msg_qos_wrr_queue_min_reserve *)msgbuf;
  int ret;

  ret = hsl_bcm_qos_wrr_queue_min_reserve (msg->ifindex, msg->qid, msg->packets);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

/*  HAL_MSG_QOS_SET_TRUST_STATE message. */
int
hsl_msg_recv_qos_set_trust_state (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_qos_set_trust_state *msg = (struct hal_msg_qos_set_trust_state *)msgbuf;
  int ret;

  ret = hsl_bcm_qos_set_trust_state (msg->ifindex, msg->trust_state);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

/*  HAL_MSG_QOS_SET_DEFAULT_COS message. */
int
hsl_msg_recv_qos_set_default_cos (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_qos_set_default_cos *msg = (struct hal_msg_qos_set_default_cos *)msgbuf;
  int ret;

  ret = hsl_bcm_qos_set_default_cos (msg->ifindex, msg->cos_value);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}


/*  HAL_MSG_QOS_SET_DSCP_MAP_TBL message. */
int
hsl_msg_recv_qos_set_dscp_mapping_tbl (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_qos_set_dscp_map_tbl *msg = (struct hal_msg_qos_set_dscp_map_tbl *)msgbuf;
  int ret;

  ret = hsl_bcm_qos_set_dscp_mapping_tbl (msg->ifindex, msg->flag, msg->map_table, msg->map_count);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}


/*  HAL_MSG_QOS_SET_CLASS_MAP message. */
int
hsl_msg_recv_qos_set_class_map (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_qos_set_class_map *msg = (struct hal_msg_qos_set_class_map *)msgbuf;
  int ret;

  ret = hsl_bcm_qos_set_class_map (msg);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

/*  HAL_MSG_QOS_SET_CMAP_COS_INNER message. */
int
hsl_msg_recv_qos_set_cmap_cos_inner (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_qos_set_class_map *msg = (struct hal_msg_qos_set_class_map *)msgbuf;
  int ret;
                                                                                
  ret = hsl_bcm_qos_set_cmap_cos_inner (msg);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}


/*  HAL_MSG_QOS_SET_POLICY_MAP message. */
int
hsl_msg_recv_qos_set_policy_map (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_qos_set_policy_map *msg = (struct hal_msg_qos_set_policy_map *)msgbuf;
  int ret;

  ret = hsl_bcm_qos_set_policy_map (msg);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}
#endif /* HAVE_QOS */

#ifdef HAVE_LACPD
/*  HAL_MSG_LACP_INIT message. */
int
hsl_msg_recv_lacp_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret = 0;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL LACP initialization\n");

//by chentao delete
 // ret = hsl_bcm_lacp_init ();
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

/*  HAL_MSG_LACP_DEINIT message. */
int
hsl_msg_recv_lacp_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret = 0;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL LACP uninitialization\n");

//by chentao delete
  //ret = hsl_bcm_lacp_deinit ();
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

/*  HAL_MSG_LACP_ADD_AGGREGATOR message. */
int
hsl_msg_recv_lacp_add_aggregator (struct socket *sock, struct hal_nlmsghdr *hdr, 
				  char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_lacp_agg_add msg;
  int ret;

  HSL_FN_ENTER();

    HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL message add aggregator\n");

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_lacp_agg_add(&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_aggregator_add(msg.agg_name,msg.agg_mac,msg.agg_type);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  HSL_FN_EXIT(-1);
}

/*  HAL_MSG_LACP_DELETE_AGGREGATOR message. */
int
hsl_msg_recv_lacp_delete_aggregator (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_lacp_agg_identifier msg;
  int ret;

  HSL_FN_ENTER(); 

    HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL message delete aggregator\n");

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_lacp_id(&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_aggregator_del(msg.agg_name,msg.agg_ifindex);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  HSL_FN_EXIT(-1);
}


/*  HAL_MSG_LACP_ATTACH_MUX_TO_AGGREGATOR message. */
int
hsl_msg_recv_lacp_attach_mux_to_aggregator (struct socket *sock, struct hal_nlmsghdr *hdr,
					    char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_lacp_mux msg;
  int ret;

  HSL_FN_ENTER(); 

    HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL attach port to aggregator\n");

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_lacp_mux(&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_aggregator_port_attach(msg.agg_name,msg.agg_ifindex,msg.port_ifindex);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  HSL_FN_EXIT(-1);
}

/*  HAL_MSG_LACP_DETACH_MUX_TO_AGGREGATOR message. */
int
hsl_msg_recv_lacp_detach_mux_from_aggregator (struct socket *sock, struct hal_nlmsghdr *hdr,
					      char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_lacp_mux msg;
  int ret;

  HSL_FN_ENTER(); 

    HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Detach port from aggregator\n");

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_lacp_mux(&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_aggregator_port_detach(msg.agg_name,msg.agg_ifindex,msg.port_ifindex);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  HSL_FN_EXIT(-1);
}


/*  HAL_MSG_LACP_PSC_SET message. */
int
hsl_msg_recv_lacp_psc_set (struct socket *sock, struct hal_nlmsghdr *hdr, 
			   char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_lacp_psc_set msg;
  int ret;

  HSL_FN_ENTER(); 

    HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Set lacp psc\n");

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
      
  ret = hsl_msg_decode_lacp_psc_set(&pnt, &size, &msg);
  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_lacp_psc_set (msg.ifindex,msg.psc);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  HSL_FN_EXIT(-1);
}

int
hsl_msg_recv_lacp_global_psc_set (struct socket *sock, struct hal_nlmsghdr *hdr, 
			   char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_lacp_global_psc_set msg;
  int ret;

  HSL_FN_ENTER(); 

    HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL Set lacp psc\n");

  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);

  ret = hsl_msg_decode_lacp_global_psc_set(&pnt, &size, &msg);

  if (ret < 0)
    goto CLEANUP;

  ret = hsl_ifmgr_lacp_global_psc_set (msg.psc);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  HSL_FN_EXIT(-1);
}

/*  HAL_MSG_LACP_COLLECTING message. */
int
hsl_msg_recv_lacp_collecting (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_FN_ENTER();
  HSL_FN_EXIT(0);
}

/* HAL_MSG_LACP_DISTRIBUTING message. */
int
hsl_msg_recv_lacp_distributing (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_FN_ENTER();
  HSL_FN_EXIT(0);
}

/*  HAL_MSG_LACP_COLLECTING_DISTRIBUTING message. */
int
hsl_msg_recv_lacp_collecting_distributing (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  HSL_FN_ENTER();
  HSL_FN_EXIT(0);
}
#endif /* HAVE_LACPD */

#ifdef HAVE_AUTHD

/*  HAL_MSG_8021x_INIT message. */
int
hsl_msg_recv_auth_init (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret = 0;
  //by chentao delete
 // ret = hsl_bcm_auth_init ();
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}


/*  HAL_MSG_8021x_DEINIT message. */
int
hsl_msg_recv_auth_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret = 0;

  //by chentao delete
  //ret = hsl_bcm_auth_deinit ();
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}


/*  HAL_MSG_8021x_PORT_STATE message. */
int
hsl_msg_recv_auth_set_port_state (struct socket *sock, struct hal_nlmsghdr *hdr, 
				  char *msgbuf)
{
  int ret = 0;
 // struct hal_msg_auth_port_state *msg = 
 //   (struct hal_msg_auth_port_state *)msgbuf;

  //by chentao delete
  //ret = hsl_bcm_auth_set_port_state (msg->port_ifindex,
//				     msg->port_state);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

#ifdef HAVE_MAC_AUTH
/* Set port auth-mac state */
int
hsl_msg_recv_auth_mac_set_port_state (struct socket *sock,
                                      struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret = 0;
  struct hal_msg_auth_port_state *msg =
    (struct hal_msg_auth_port_state *)msgbuf;

//by chentao delete
 // ret = hsl_bcm_auth_mac_set_port_state (msg->port_ifindex,
   //                                      msg->port_state);
  HSL_MSG_PROCESS_RETURN (fd, hdr, ret);
  return 0;
}
#endif

#endif /* HAVE_AUTHD */

int hsl_msg_recv_fwdu_ufib4_add(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
    fwdu_hal_ufib4_t *msg = (fwdu_hal_ufib4_t *)msgbuf;
    int ret;
    
    HSL_FN_ENTER();
    HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL ufib4 message  \n");
    
    ret = hsl_fib_direct_prefix_add((void*)msg);
    
    HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
    HSL_FN_EXIT(ret);

}

int hsl_msg_recv_fwdu_ufib4_del(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
    fwdu_hal_ufib4_t *msg = (fwdu_hal_ufib4_t *)msgbuf;
    int ret;
    
    HSL_FN_ENTER();
    HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL ufib4 message  \n");
    
    ret = hsl_fib_direct_prefix_del((void*)msg);

    HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
    HSL_FN_EXIT(ret);

}

int hsl_msg_recv_fwdu_nbr_add(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
    fwdu_hal_nbr_data_t *msg = (fwdu_hal_nbr_data_t *)msgbuf;
    int ret;
    
    HSL_FN_ENTER();
    HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL nbr message  \n");
    
    ret = hsl_fib_direct_nh_add((void*)msg);
    
    HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
    HSL_FN_EXIT(ret);

}
int hsl_msg_recv_fwdu_nbr_del(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
    fwdu_hal_nbr_data_t *msg = (fwdu_hal_nbr_data_t *)msgbuf;
    int ret;
    
    HSL_FN_ENTER();
    HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL nbr message  \n");
    
    ret = hsl_fib_direct_nh_del((void*)msg);
     
    HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
    HSL_FN_EXIT(ret);

}


#ifdef HAVE_L3

/* HAL_MSG_ARP_ADD message */
int
hsl_msg_recv_arp_add (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_arp_update *msg = (struct hal_msg_arp_update *)msgbuf;
  int ret;

  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL ARP add message \n");

  if (msg->is_proxy_arp)
    ret = hsl_fib_arp_entry_add ((hsl_ipv4Address_t *)&msg->ip_addr, msg->ifindex,
                                 msg->mac_addr, HSL_NH_ENTRY_STATIC|HSL_NH_ENTRY_VALID|HSL_NH_ENTRY_PROXY);
  else
    ret = hsl_fib_arp_entry_add ((hsl_ipv4Address_t *)&msg->ip_addr, msg->ifindex,
                                 msg->mac_addr, HSL_NH_ENTRY_STATIC|HSL_NH_ENTRY_VALID);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}

/* HAL_MSG_ARP_DEL message */
int
hsl_msg_recv_arp_del (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_arp_update *msg = (struct hal_msg_arp_update *)msgbuf;
  int ret;

  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL ARP del message \n");

  ret = hsl_fib_arp_entry_del((hsl_ipv4Address_t *)&msg->ip_addr,
      msg->ifindex);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}


/* HAL_MSG_ARP_DEL_ALL message */
int
hsl_msg_recv_arp_del_all (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;
  struct hal_msg_arp_del_all *msg = (struct hal_msg_arp_del_all *)msgbuf;

  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL arp del all message \n");

  ret = hsl_fib_arp_del_all ((hsl_fib_id_t)msg->fib_id, msg->clr_flag);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}

/*  HAL_MSG_ARP_CACHE_GET message. */
int
hsl_msg_recv_arp_cache_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_arp_cache_req req;
  struct hal_msg_arp_cache_resp resp;
  int ret = 0, respsz = 0;
  char *buf = NULL; 
  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL ARP cache get message.\n");

  memset (&resp, 0, sizeof (struct hal_msg_arp_cache_resp));

  /* Get requests should have ACK flag set. */
  pnt = (u_char *)msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
  /* Decode request. */
  ret = hsl_msg_decode_arp_cache_req(&pnt, &size, &req);
  if (ret < 0)
    goto CLEANUP;

  /* Get buffer for arp entries. */
  size = HAL_ARP_CACHE_GET_COUNT * sizeof (struct hal_arp_cache_entry);
  resp.cache = (struct hal_arp_cache_entry *)kmalloc (size, GFP_KERNEL);
  if(!resp.cache)
    goto CLEANUP;


  /*  Get Arp entries. */
  ret = hsl_fib_nh_get_bundle((hsl_fib_id_t)req.fib_id, (hsl_ipv4Address_t *)(req.ip_addr.s_addr == 0 ? NULL : &req.ip_addr), req.count, resp.cache);

  /* Allocate buffer to send a response. */
  if((ret < 0) || (ret > HAL_ARP_CACHE_GET_COUNT)) 
    ret = 0;

  size = sizeof (resp) + ret * sizeof(struct hal_arp_cache_entry);
  buf = (char *) kmalloc (size, GFP_KERNEL);
  if (!buf)
    goto CLEANUP;
     
  pnt = (u_char *)buf;
  if (ret > 0)
    resp.count = ret;
  else
    resp.count = 0;

  /* Encode arp-cache response. */
  respsz = hsl_msg_encode_arp_cache_resp (&pnt, &size, &resp);

  /* Post the message. */
  ret = hsl_sock_post_msg (sock, HAL_MSG_ARP_CACHE_GET, 0, hdr->nlmsg_seq, buf, respsz);

  /* Free the buffer. */ 
  kfree (buf);
  kfree (resp.cache);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  if(buf)        kfree (buf);
  if(resp.cache) kfree (resp.cache);
  HSL_FN_EXIT(STATUS_ERROR);
}


#ifdef HAVE_IPV6

/* HAL_MSG_IPV6_NBR_ADD message */
int
hsl_msg_recv_ipv6_nbr_add (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_ipv6_nbr_update *msg = (struct hal_msg_ipv6_nbr_update *)msgbuf;
  int ret;

  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPV6 neighbor add message \n");

  ret = hsl_fib_ipv6_nbr_add ((hsl_ipv6Address_t *)&msg->addr, msg->ifindex,
			      msg->mac_addr, HSL_NH_ENTRY_STATIC|HSL_NH_ENTRY_VALID);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}

/* HAL_MSG_IPV6_NBR_DEL message */
int
hsl_msg_recv_ipv6_nbr_del (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_ipv6_nbr_update *msg = (struct hal_msg_ipv6_nbr_update *)msgbuf;
  int ret;

  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPV6 neighbor del message \n");

  ret = hsl_fib_ipv6_nbr_del ((hsl_ipv6Address_t *)&msg->addr, 1,
      msg->ifindex);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}

/* HAL_MSG_IPV6_NBR_DEL_ALL message */
int
hsl_msg_recv_ipv6_nbr_del_all (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret;
  struct hal_msg_ipv6_nbr_del_all *msg = (struct hal_msg_ipv6_nbr_del_all *)msgbuf;

  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPV6 neighbor del all message \n");

  ret = hsl_fib_ipv6_nbr_del_all ((hsl_fib_id_t)msg->fib_id, 
  msg->clr_flag);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}


/*  HAL_MSG_IPV6_NBR_CACHE_GET message. */
int
hsl_msg_recv_ipv6_nbr_cache_get (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  u_char *pnt;
  u_int32_t size;
  struct hal_msg_ipv6_nbr_cache_req req;
  struct hal_msg_ipv6_nbr_cache_resp resp;
  int ret = 0, respsz = 0;
  char *buf = NULL; 

  HSL_FN_ENTER();
  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL IPV6 neighbor cache get message.\n");

  memset (&resp, 0, sizeof (struct hal_msg_ipv6_nbr_cache_resp));

  /* Get requests should have ACK flag set. */
  pnt = msgbuf;
  size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
  /* Decode request. */
  ret = hsl_msg_decode_ipv6_nbr_cache_req(&pnt, &size, &req);
  if (ret < 0)
    goto CLEANUP;

  /* Get buffer for  entries. */
  size = HAL_IPV6_NBR_CACHE_GET_COUNT * sizeof (struct hal_ipv6_nbr_cache_entry);
  resp.cache = (struct hal_ipv6_nbr_cache_entry *)kmalloc (size, GFP_KERNEL);
  if(! resp.cache)
    goto CLEANUP;

  /*  Get entries. */
  ret = hsl_fib_nh6_get_bundle((hsl_fib_id_t)req.fib_id, (hsl_ipv6Address_t *)(HSL_IPV6_ADDR_ZERO (req.addr) 
						     ? NULL : &req.addr),
			       req.count, resp.cache);

  /* Allocate buffer to send a response. */
  if((ret < 0) || (ret > HAL_IPV6_NBR_CACHE_GET_COUNT)) 
    ret = 0;

  size = sizeof (resp) + ret * sizeof(struct hal_ipv6_nbr_cache_entry);
  buf = (char *) kmalloc (size, GFP_KERNEL);
  if (!buf)
    goto CLEANUP;
     
  pnt = buf;
  if (ret > 0)
    resp.count = ret;
  else
    resp.count = 0;

  /* Encode arp-cache response. */
  respsz = hsl_msg_encode_ipv6_nbr_cache_resp (&pnt, &size, &resp);

  /* Post the message. */
  ret = hsl_sock_post_msg (sock, HAL_MSG_IPV6_NBR_CACHE_GET, 0, hdr->nlmsg_seq, buf, respsz);

  /* Free the buffer. */ 
  kfree (buf);
  kfree (resp.cache);
  HSL_FN_EXIT(ret);

 CLEANUP:
  /* Close socket. */
  hsl_sock_release (sock);
  if(buf)        kfree (buf);
  if(resp.cache) kfree (resp.cache);
  HSL_FN_EXIT(STATUS_ERROR);
}
#endif /* HAVE_IPV6 */

#ifdef HAVE_DEBUG_FIB

/*
 * Function:
 *      hsl_fib_host_snprint
 * Description:
 *	Internal function to print out host entry info
 * Parameters:
 *      unit   - device number.
 *      index  - Traversal index number
 *	info   - Pointer to bcm_l3_host_t data structure.
 *      cookie - user cookie
 */
 //by chentao delete
 #if 0
int hsl_fib_host_snprint(int unit, int index, bcm_l3_host_t *info, void *resp_tmp)
{
    int  tgid=0, port, module, id;
    int  count = 0;
	struct hal_msg_fib_host_resp *resp;

	resp = (struct hal_msg_fib_host_resp *)resp_tmp;
	
    if (BCM_GPORT_IS_SET(info->l3a_port_tgid)) {
        BCM_IF_ERROR_RETURN(_bcm_esw_gport_resolve(unit, info->l3a_port_tgid, &module, 
                               &port, &tgid, &id));
        if (id != -1) {
            return -2;
        }
        
    } else {
        /*get info*/
        if(info->l3a_flags & BCM_L3_IP6){
            return 0;/*do nothing*/
        }
        count = resp->count;
        resp->entry[count].entry_id = index;
        resp->entry[count].vrf_id  =  info->l3a_vrf;
        resp->entry[count].ip_addr.s_addr = info->l3a_ip_addr;
        memcpy(resp->entry[count].mac_addr, info->l3a_nexthop_mac, HAL_HW_LENGTH );
        resp->entry[count].ifindex = info->l3a_intf;
        resp->count ++;

    }
    
    return 0;
}
#endif
int hsl_fib_host_dump_blundle(unsigned int entry_id, unsigned int count, struct hal_msg_fib_host_resp *resp)
{
	//by chentao delete
	#if 0

    int unit = 0;
    int r = 0, free_l3, first_entry, last_entry;
	
    bcm_l3_info_t l3_hw_status;
    BCM_FOREACH_UNIT(unit) {/*目前只获取 unit = 0的信息*/
        if ((r = bcm_l3_info(unit, &l3_hw_status)) < 0) {
             return -1;
        }
        
        free_l3 = l3_hw_status.l3info_max_host - l3_hw_status.l3info_occupied_host;
        
        first_entry = entry_id;
        last_entry = first_entry + count;

        if(last_entry >l3_hw_status.l3info_max_host ){
            last_entry = l3_hw_status.l3info_max_host;
        }

        resp->count = 0;
                
        r= bcm_l3_host_traverse(unit, 0, first_entry, last_entry,
                           hsl_fib_host_snprint, (void *)resp);

        return resp->count;
    }
   #endif 
    return 0;
}


/* 
   Decode fib host request. 
*/
int hsl_msg_decode_fib_host_req (unsigned char  **pnt, u_int32_t *size, struct hal_msg_fib_host_req *msg)
{
    unsigned char *sp = *pnt;

    /* Check size. */
    if (*size < HAL_MSG_FIB_HOST_REQ_SIZE)
    return HAL_MSG_PKT_TOO_SMALL;

    /* entry id. */
    TLV_DECODE_GETL(msg->entry_id);

    /* Entry count. */
    TLV_DECODE_GETL(msg->count);

    return *pnt - sp;
}
/* 
   Encode fib host resp.
*/
int hsl_msg_encode_fib_host_resp (u_char **pnt, u_int32_t *size, struct hal_msg_fib_host_resp *msg)
{
  unsigned char *sp = *pnt;
  u_int16_t i;

  /* Check size. */
  if (*size < HAL_MSG_FIB_HOST_RESP_SIZE)
    return HAL_MSG_PKT_TOO_SMALL;

  /* Entry count. */
  TLV_ENCODE_PUTL (msg->count);
  
  /* arp entries . */
  for (i = 0; i < msg->count; i++)
    {
        /* entry_id */
       TLV_ENCODE_PUTL (msg->entry[i].entry_id);
       /* vrf id */
       TLV_ENCODE_PUTL (msg->entry[i].vrf_id);

       /* host ip address. */
       TLV_ENCODE_PUT_IN4_ADDR (&msg->entry[i].ip_addr);

       /* Mac address. */
       TLV_ENCODE_PUT (msg->entry[i].mac_addr, HAL_HW_LENGTH);
  
       /* If Index */
       TLV_ENCODE_PUTL (msg->entry[i].ifindex);

     }
   return *pnt - sp;
}


/*  HAL_MSG_FIB_HOST_DUMP_MSG message. */
int hsl_msg_recv_fib_host_dump (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
    unsigned char *pnt;
    u_int32_t size;
    struct hal_msg_fib_host_req req;
    struct hal_msg_fib_host_resp resp;
    int ret = 0, respsz = 0;
    char *buf = NULL; 
    HSL_FN_ENTER();
    HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL fib host get message.\n");

    memset (&resp, 0, sizeof (struct hal_msg_fib_host_resp));

    /* Get requests should have ACK flag set. */
    pnt = (unsigned char *)msgbuf;
    size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
    /* Decode request. */
    ret = hsl_msg_decode_fib_host_req(&pnt, &size, &req);
    if (ret < 0)
    goto CLEANUP;

    /* Get buffer for fib host entries. */
    size = HAL_FIB_HOST_GET_COUNT * sizeof (struct fib_host_entry);
    resp.entry = (struct fib_host_entry *)kmalloc (size, GFP_KERNEL);
    memset(resp.entry, 0, size);
    
    if(!resp.entry)
    goto CLEANUP;

    /*  Get FIB host resp . */
    ret = hsl_fib_host_dump_blundle(req.entry_id, req.count, &resp);

    /* Allocate buffer to send a response. */
    if((ret < 0) || (ret > HAL_FIB_HOST_GET_COUNT)) 
    ret = 0;

    size = sizeof (resp) + ret * sizeof(struct fib_host_entry);
    buf = (char *) kmalloc (size, GFP_KERNEL);
    if (!buf)
    goto CLEANUP;
     
    pnt = (unsigned char *)buf;
    

    /* Encode fib host response. */
    respsz = hsl_msg_encode_fib_host_resp (&pnt, &size, &resp);

    /* Post the message. */
    ret = hsl_sock_post_msg (sock, HAL_MSG_FIB_HOST_DUMP_MSG, 0, hdr->nlmsg_seq, buf, respsz);

    /* Free the buffer. */ 
    kfree (buf);
    kfree (resp.entry);
    HSL_FN_EXIT(ret);

    CLEANUP:
    /* Close socket. */
    hsl_sock_release (sock);
    if(buf)        kfree (buf);
    if(resp.entry) kfree (resp.entry);
    HSL_FN_EXIT(STATUS_ERROR);

    }

/*
 * Function:
 *      hsl_fib_route_snprint
 * Description:
 *	Internal function to print out host entry info
 * Parameters:
 *      unit   - device number.
 *      index  - Traversal index number
 *	info   - Pointer to bcm_l3_route_t data structure.
 *      cookie - user cookie
 */
//by chentao 
#if 0
int hsl_fib_route_snprint(int unit, int index, bcm_l3_route_t *info, void *resp_tmp)
{
    int  count = 0;
	struct hal_msg_fib_route_resp *resp;

	resp = (struct hal_msg_fib_route_resp *)resp_tmp;

	//by chentao 
	#if 0
    /*get info*/
    if(info->l3a_flags & BCM_L3_IP6){
        return 0;/*do nothing*/
    }
	#endif
    count = resp->count;
    resp->entry[count].entry_id = index;
    resp->entry[count].vrf_id  =  info->l3a_vrf;
    resp->entry[count].sub_net.s_addr = info->l3a_subnet;
    resp->entry[count].ip_mask.s_addr = info->l3a_ip_mask;
    memcpy(resp->entry[count].nexthop_mac, info->l3a_nexthop_mac, HAL_HW_LENGTH );
    resp->entry[count].ifindex = info->l3a_intf;
    resp->entry[count].flag= info->l3a_flags;
    resp->count ++;
    
    return 0;
}
#endif

int hsl_fib_route_dump_blundle(unsigned int entry_id, unsigned int count, struct hal_msg_fib_route_resp *resp)
{
//by chentao 
#if 0
    int unit = 0;
    int r = 0, free_l3, first_entry, last_entry;
    bcm_l3_info_t l3_hw_status;
    BCM_FOREACH_UNIT(unit) {/*目前只获取 unit = 0的信息*/
        if ((r = bcm_l3_info(unit, &l3_hw_status)) < 0) {
             printk("get bcm l3 info failed\n");
             return -1;
        }
        
        free_l3 = l3_hw_status.l3info_max_route- l3_hw_status.l3info_occupied_route;
        
        first_entry = entry_id;
        last_entry = first_entry + count;

        if(last_entry >l3_hw_status.l3info_max_route){
            last_entry = l3_hw_status.l3info_max_route;
        }

        resp->count = 0;
        
        
        r= bcm_l3_route_traverse(unit, 0, first_entry, last_entry,
                           hsl_fib_route_snprint, (void *)resp);

        return resp->count;
    }
    #endif
    return 0;
}


/* 
   Decode fib host request. 
*/
int hsl_msg_decode_fib_route_req (unsigned char  **pnt, u_int32_t *size, struct hal_msg_fib_route_req *msg)
{
    unsigned char *sp = *pnt;

    /* Check size. */
    if (*size < HAL_MSG_FIB_ROUTE_REQ_SIZE)
    return HAL_MSG_PKT_TOO_SMALL;

    /* entry id. */
    TLV_DECODE_GETL(msg->entry_id);

    /* Entry count. */
    TLV_DECODE_GETL(msg->count);

    return *pnt - sp;
}
/* 
   Encode fib host resp.
*/
int hsl_msg_encode_fib_route_resp (unsigned char  **pnt, u_int32_t *size, struct hal_msg_fib_route_resp *msg)
{
    unsigned char *sp = *pnt;
    u_int16_t i;

    /* Check size. */
    if (*size < HAL_MSG_FIB_ROUTE_RESP_SIZE)
    return HAL_MSG_PKT_TOO_SMALL;

    /* Entry count. */
    TLV_ENCODE_PUTL (msg->count);

    /* arp entries . */
    for (i = 0; i < msg->count; i++)
    {
        /* entry_id */
       TLV_ENCODE_PUTL (msg->entry[i].entry_id);
       /* vrf id */
       TLV_ENCODE_PUTL (msg->entry[i].vrf_id);

       /* route ip subnet address. */
       TLV_ENCODE_PUT_IN4_ADDR (&msg->entry[i].sub_net);

       /* route ip mask address. */
       TLV_ENCODE_PUT_IN4_ADDR (&msg->entry[i].ip_mask);

       /* nexthop Mac address. */
       TLV_ENCODE_PUT (msg->entry[i].nexthop_mac, HAL_HW_LENGTH);

       /* If Index */
       TLV_ENCODE_PUTL (msg->entry[i].ifindex);

        /* l3 flag */
       TLV_ENCODE_PUTL (msg->entry[i].flag);

     }
    
    return *pnt - sp;
}


/*  HAL_MSG_FIB_ROUTE_DUMP_MSG message. */
int hsl_msg_recv_fib_route_dump (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
    unsigned char *pnt;
    u_int32_t size;
    struct hal_msg_fib_route_req req;
    struct hal_msg_fib_route_resp resp;
    int ret = 0, respsz = 0;
    char *buf = NULL; 
    HSL_FN_ENTER();
    HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL fib route get message.\n");

    memset (&resp, 0, sizeof (struct hal_msg_fib_route_resp));

    /* Get requests should have ACK flag set. */
    pnt = (unsigned char *)msgbuf;
    size = hdr->nlmsg_len - HAL_NLMSG_ALIGN(HAL_NLMSGHDR_SIZE);
    /* Decode request. */
    ret = hsl_msg_decode_fib_route_req(&pnt, &size, &req);
    if (ret < 0)
    goto CLEANUP;

    /* Get buffer for fib route entries. */
    size = HAL_FIB_ROUTE_GET_COUNT * sizeof (struct fib_route_entry);
    resp.entry = (struct fib_route_entry *)kmalloc (size, GFP_KERNEL);
    memset(resp.entry, 0, size);
    
    if(!resp.entry)
    goto CLEANUP;

    /*  Get FIB host resp . */
    ret = hsl_fib_route_dump_blundle(req.entry_id, req.count, &resp);

    /* Allocate buffer to send a response. */
    if((ret < 0) || (ret > HAL_FIB_ROUTE_GET_COUNT)) 
    ret = 0;

    size = sizeof (resp) + ret * sizeof(struct fib_route_entry);
    buf = (char *) kmalloc (size, GFP_KERNEL);
    if (!buf)
    goto CLEANUP;
     
    pnt = (unsigned char *)buf;
    

    /* Encode fib host response. */
    respsz = hsl_msg_encode_fib_route_resp (&pnt, &size, &resp);

    /* Post the message. */
    ret = hsl_sock_post_msg (sock, HAL_MSG_FIB_ROUTE_DUMP_MSG, 0, hdr->nlmsg_seq, buf, respsz);

    /* Free the buffer. */ 
    kfree (buf);
    kfree (resp.entry);
    HSL_FN_EXIT(ret);
    
CLEANUP:
    /* Close socket. */
    hsl_sock_release (sock);
    if(buf)        kfree (buf);
    if(resp.entry) kfree (resp.entry);
    HSL_FN_EXIT(STATUS_ERROR);

}

#endif /*HAVE_DEBUG_FIB*/


#endif /* HAVE_L3 */

#ifdef HAVE_MPLS
/*  HAL_MSG_MPLS_INIT message */
int
hsl_msg_recv_mpls_init (struct socket *sock, struct hal_nlmsghdr *hdr, 
                        char *msgbuf)
{
  int ret;

  HSL_LOG (HSL_LOG_MSG, HSL_LEVEL_INFO, "Message: HAL MPLS initialization\n");

  ret = hsl_mpls_init ();
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
  
}

/*  HAL_MSG_MPLS_IF_INIT */
int
hsl_msg_recv_mpls_if_init (struct socket *sock, struct hal_nlmsghdr *hdr, 
                           char *msgbuf)
{
  HSL_MSG_PROCESS_RETURN (sock, hdr, 0);
  return 0;
}

/*  HAL_MSG_MPLS_VRF_INIT */
int
hsl_msg_recv_mpls_vrf_init (struct socket *sock, struct hal_nlmsghdr *hdr, 
                           char *msgbuf)
{
  int ret;
  u_int32_t vrf_id;

  vrf_id = *(u_int32_t *)msgbuf;
  ret = hsl_mpls_vpn_add (vrf_id, HSL_MPLS_VPN_VRF);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}

/*  HAL_MSG_MPLS_VRF_END */
int
hsl_msg_recv_mpls_vrf_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, 
			      char *msgbuf)
{
  int ret;
  u_int32_t vrf_id;

  vrf_id = *(u_int32_t *)msgbuf;
  ret = hsl_mpls_vpn_del (vrf_id, HSL_MPLS_VPN_VRF);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}

/*  HAL_MSG_MPLS_NEWILM */
int
hsl_msg_recv_mpls_ilm_add (struct socket *sock, struct hal_nlmsghdr *hdr, 
                           char *msgbuf)
{
  struct hal_msg_mpls_ilm_add *ia;
  int ret;
  u_char vc_type = HAL_MPLS_VC_TYPE_NONE;

  ia = (struct hal_msg_mpls_ilm_add *)msgbuf;

#ifdef HAVE_MPLS_VC
  if (ia->vc_peer && ia->vpn_id && ia->opcode == HAL_MPLS_POP_FOR_VC)
    vc_type = HAL_MPLS_VC_TYPE_MARTINI;
#endif /* HAVE_MPLS_VC */
  ret = hsl_mpls_ilm_add (ia, ia->vpn_id, vc_type);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}

/*  HAL_MSG_MPLS_DELILM */
int
hsl_msg_recv_mpls_ilm_del (struct socket *sock, struct hal_nlmsghdr *hdr, 
                           char *msgbuf)
{
  struct hal_msg_mpls_ilm_del *id;
  int ret;

  id = (struct hal_msg_mpls_ilm_del *)msgbuf;

  ret = hsl_mpls_ilm_del (id);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}


/*  HAL_MSG_MPLS_NEWFTN */
int
hsl_msg_recv_mpls_ftn_add (struct socket *sock, struct hal_nlmsghdr *hdr, 
                           char *msgbuf)
{
  struct hal_msg_mpls_ftn_add fa;
  int ret;
  int *size, len;
  u_char **pnt = (u_char **) &msgbuf;

  len = sizeof (struct hal_msg_mpls_ftn_add);
  size = &len;

  TLV_DECODE_GETC (fa.family);
  TLV_DECODE_GETL (fa.vrf);
  TLV_DECODE_GETL (fa.fec_addr);
  TLV_DECODE_GETC (fa.fec_prefixlen);
  TLV_DECODE_GETC (fa.dscp_in);
  TLV_DECODE_GETL (fa.tunnel_label);
  TLV_DECODE_GETL (fa.tunnel_nhop);
  TLV_DECODE_GETL (fa.tunnel_oif_ix);
  TLV_DECODE_GET (fa.tunnel_oif_name, HAL_IFNAME_LEN + 1);
  TLV_DECODE_GETC (fa.opcode);
  TLV_DECODE_GETL (fa.nhlfe_ix);
  TLV_DECODE_GETL (fa.ftn_ix);
  TLV_DECODE_GETC (fa.ftn_type);
  TLV_DECODE_GETL (fa.tunnel_id);
  TLV_DECODE_GETL (fa.qos_resource_id);
  TLV_DECODE_GETL (fa.bypass_ftn_ix);
  TLV_DECODE_GETC (fa.bypass_flag);
  TLV_DECODE_GETL (fa.vpn_label);
  TLV_DECODE_GETL (fa.vpn_nhop);
  TLV_DECODE_GETL (fa.vpn_oif_ix);
  TLV_DECODE_GET (fa.tunnel_oif_name, HAL_IFNAME_LEN + 1);

  ret = hsl_mpls_ftn_add (&fa);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}


/*  HAL_MSG_MPLS_DELFTN */
int
hsl_msg_recv_mpls_ftn_del (struct socket *sock, struct hal_nlmsghdr *hdr, 
                           char *msgbuf)
{
  struct hal_msg_mpls_ftn_del *fd;
  int ret;

  fd = (struct hal_msg_mpls_ftn_del *)msgbuf;
  
  ret = hsl_mpls_ftn_del (fd);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}


#ifdef HAVE_MPLS_VC
/*  HAL_MSG_MPLS_VC_INIT */
int
hsl_msg_recv_mpls_vc_init (struct socket *sock, struct hal_nlmsghdr *hdr, 
                           char *msgbuf)
{
  int ret;
  struct hal_msg_mpls_vpn_if *vif_msg;

  vif_msg = (struct hal_msg_mpls_vpn_if *)msgbuf;
  ret = hsl_mpls_vpn_add (vif_msg->vpn_id, HSL_MPLS_VPN_MARTINI);
  if (ret < 0)
    {
      HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
      HSL_FN_EXIT(ret);
    }

  ret = hsl_mpls_vpn_if_bind (vif_msg->vpn_id, vif_msg->ifindex, 
			      vif_msg->vlan_id, HSL_MPLS_VPN_MARTINI);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
  
  return 0;
}

/*  HAL_MSG_MPLS_VC_END */
int
hsl_msg_recv_mpls_vc_deinit (struct socket *sock, struct hal_nlmsghdr *hdr, 
                             char *msgbuf)
{
  int ret;
  struct hal_msg_mpls_vpn_if *vif_msg;

  vif_msg = (struct hal_msg_mpls_vpn_if *)msgbuf;
  hsl_mpls_vpn_if_unbind (vif_msg->vpn_id, vif_msg->ifindex, 
			  vif_msg->vlan_id, HSL_MPLS_VPN_MARTINI);

  ret = hsl_mpls_vpn_del (vif_msg->vpn_id, HSL_MPLS_VPN_MARTINI);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}



/*  HAL_MSG_MPLS_NEW_VC_FTN */
int
hsl_msg_recv_mpls_vc_ftn_add (struct socket *sock, struct hal_nlmsghdr *hdr, 
                              char *msgbuf)
{
  int ret;
  struct hal_msg_mpls_vc_ftn_add *vfa;

  vfa = (struct hal_msg_mpls_vc_ftn_add *)msgbuf;

  ret = hsl_mpls_vc_ftn_add (vfa->vc_id, vfa, HAL_MPLS_VC_TYPE_MARTINI);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}


/*  HAL_MSG_MPLS_DEL_VC_FTN */
int
hsl_msg_recv_mpls_vc_ftn_del (struct socket *sock, struct hal_nlmsghdr *hdr, 
                              char *msgbuf)
{
  int ret;
  struct hal_msg_mpls_vc_ftn_del *vfd;

  vfd = (struct hal_msg_mpls_vc_ftn_del *)msgbuf;

  ret = hsl_mpls_vc_ftn_del (vfd->vc_id, vfd->vc_id, vfd->vc_peer, HAL_MPLS_VC_TYPE_MARTINI);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}
#endif /* HAVE_MPLS_VC */

#ifdef HAVE_VPLS
/* HAL_MSG_MPLS_VPLS_ADD */
int
hsl_msg_recv_mpls_vpls_add (struct socket *sock, struct hal_nlmsghdr *hdr,
			    char *msgbuf)
{
  int ret;
  u_int32_t vpls_id;

  vpls_id = *(u_int32_t *)msgbuf;
  ret = hsl_mpls_vpn_add (vpls_id, HSL_MPLS_VPN_VPLS);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}

/* HAL_MSG_MPLS_VPLS_DEL */
int
hsl_msg_recv_mpls_vpls_del (struct socket *sock, struct hal_nlmsghdr *hdr,
			    char *msgbuf)
{
  int ret;
  u_int32_t vpls_id;

  vpls_id = *(u_int32_t *)msgbuf;
  ret = hsl_mpls_vpn_del (vpls_id, HSL_MPLS_VPN_VPLS);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}

/* HAL_MSG_MPLS_VPLS_IF_BIND */
int
hsl_msg_recv_mpls_vpls_if_bind (struct socket *sock, struct hal_nlmsghdr *hdr,
				char *msgbuf)
{
  int ret;
  struct hal_msg_mpls_vpn_if *vif_msg;

  vif_msg = (struct hal_msg_mpls_vpn_if *)msgbuf;

  ret = hsl_mpls_vpn_if_bind (vif_msg->vpn_id, vif_msg->ifindex, 
			      vif_msg->vlan_id, HSL_MPLS_VPN_VPLS);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}


/* HAL_MSG_MPLS_VPLS_IF_UNBIND */
int
hsl_msg_recv_mpls_vpls_if_unbind (struct socket *sock, struct hal_nlmsghdr *hdr,
				  char *msgbuf)
{
  int ret;
  struct hal_msg_mpls_vpn_if *vif_msg;

  vif_msg = (struct hal_msg_mpls_vpn_if *)msgbuf;

  ret = hsl_mpls_vpn_if_unbind (vif_msg->vpn_id, vif_msg->ifindex, 
				vif_msg->vlan_id, HSL_MPLS_VPN_VPLS);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}


/* HAL_MSG_MPLS_VPLS_FIB_ADD */
int
hsl_msg_recv_mpls_vpls_fib_add (struct socket *sock, struct hal_nlmsghdr *hdr,
				  char *msgbuf)
{
  int ret;
  struct hal_msg_mpls_vpls_fib_add *vfib_msg;

  vfib_msg = (struct hal_msg_mpls_vpls_fib_add *)msgbuf;

  ret = hsl_mpls_vpls_fib_add (vfib_msg);

  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}


/* HAL_MSG_MPLS_VPLS_FIB_DEL */
int
hsl_msg_recv_mpls_vpls_fib_del (struct socket *sock, struct hal_nlmsghdr *hdr,
				  char *msgbuf)
{
  int ret;
  struct hal_msg_mpls_vpls_fib_del *vfib_msg;

  vfib_msg = (struct hal_msg_mpls_vpls_fib_del *)msgbuf;

  ret = hsl_mpls_vpls_fib_del (vfib_msg);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  HSL_FN_EXIT(ret);
}
#endif /* HAVE_VPLS */
#endif /* HAVE_MPLS */

#ifdef HAVE_L2LERN
int
hsl_msg_recv_mac_access_grp_set (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_mac_set_access_grp *msg = (struct hal_msg_mac_set_access_grp *)msgbuf;
  int ret;

  ret = hsl_bcm_mac_set_access_grp (msg);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;

}

int
hsl_msg_recv_vlan_access_map_set (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  struct hal_msg_vlan_set_access_map *msg = (struct hal_msg_vlan_set_access_map *)msgbuf;
  int ret;

  ret = hsl_bcm_vlan_set_access_map (msg);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}
#endif /* HAVE_L2LERN */

int
hsl_msg_recv_ip_set_acl_filter (struct socket *sock,
                                struct hal_nlmsghdr *hdr, char *msgbuf)
{
//  struct hal_msg_ip_set_access_grp *msg =
 //                                  (struct hal_msg_ip_set_access_grp *) msgbuf;
  int ret = 0;
//by chentoa delete
//  ret = hsl_bcm_set_ip_access_group (msg);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

int
hsl_msg_recv_ip_unset_acl_filter (struct socket *sock,
                                  struct hal_nlmsghdr *hdr, char *msgbuf)
{
//  struct hal_msg_ip_set_access_grp *msg = (struct
//                                       hal_msg_ip_set_access_grp *) msgbuf;
  int ret = 0;
//by chentao 
//  ret = hsl_bcm_unset_ip_access_group (msg);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

int
hsl_msg_recv_ip_set_acl_filter_interface (struct socket *sock,
                                          struct hal_nlmsghdr *hdr,
                                          char *msgbuf)
{
 // struct hal_msg_ip_set_access_grp_interface *msg =
  //                       (struct hal_msg_ip_set_access_grp_interface *) msgbuf;
  int ret = 0;

//by chentao
 // ret = hsl_bcm_set_ip_access_group_interface (msg);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}

int
hsl_msg_recv_ip_unset_acl_filter_interface (struct socket *sock,
                                            struct hal_nlmsghdr *hdr,
                                            char *msgbuf)
{
  //struct hal_msg_ip_set_access_grp_interface *msg =
  //                       (struct hal_msg_ip_set_access_grp_interface *) msgbuf;
  int ret = 0;
//by chentao 
 // ret = hsl_bcm_unset_ip_access_group_interface (msg);
  HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  return 0;
}
#if 1
/* CPU related HSL API's */
int
hsl_msg_recv_cpu_set_master (struct socket *sock, struct hal_nlmsghdr *hdr, 
                             char *msgbuf)
{
  int ret = 0;
  unsigned char *msg = (unsigned char *) msgbuf;

//by chentao 
 // ret = hsl_bcm_set_master_cpu (msg);
  if (ret < 0)
  {
     HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  }
  else
  {
      hsl_sock_post_msg (sock, HAL_MSG_CPU_SET_MASTER, hdr->nlmsg_seq, 0,
         (char *)msg, sizeof (u_int32_t));
  }

  return 0;
}

int
hsl_msg_recv_cpu_get_info_index (struct socket *sock, struct hal_nlmsghdr *hdr, 
                                 char *msgbuf)
{
  int ret = 0;
  unsigned int num;
  struct hal_cpu_info_entry cpu_info;

  memcpy(&num, msgbuf, sizeof(int)) ;
//by chentao 
 // ret = hsl_bcm_get_cpu_index (num, (char *)&cpu_info.mac_addr);
  if (ret < 0)
  {
      HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  }
  else
  {
      hsl_sock_post_msg (sock, HAL_MSG_CPU_GETDB_INDEX, 0, hdr->nlmsg_seq, 
       (char *)&cpu_info, sizeof (struct hal_cpu_info_entry));
  }
  return 0;
}

int
hsl_msg_recv_cpu_get_dump_index (struct socket *sock, struct hal_nlmsghdr *hdr, 
                                 char *msgbuf)
{
  int ret = 0;
  unsigned int num;
  struct hal_cpu_dump_entry cpu_info;

  memcpy(&num, msgbuf, sizeof(int)) ;
  //by chentao 
//  ret = hsl_bcm_get_dump_cpu_index (num, (char *)&cpu_info);
  if (ret < 0)
  {
      HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  }
  else
  {
     hsl_sock_post_msg (sock, hdr->nlmsg_type, hdr->nlmsg_seq, 0,
              (char *)&cpu_info, sizeof (struct hal_cpu_dump_entry));
  }
  return 0;
}

int
hsl_msg_recv_cpu_get_num (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  int ret = 0;
  unsigned int num;
//by chentao 
 // ret = hsl_bcm_get_num_cpu (&num);
  if (ret < 0)
  {
      HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  }
  else
  {
     hsl_sock_post_msg (sock, hdr->nlmsg_type, hdr->nlmsg_seq, 0,
              (char *)&num, sizeof (u_int32_t)); 
  }

  return 0;
}

int
hsl_msg_recv_cpu_getdb_info (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
  return 0;
}


int
hsl_msg_recv_cpu_get_master (struct socket *sock, struct hal_nlmsghdr *hdr, 
                             char *msgbuf)
{
  int ret = 0;
  struct hal_cpu_info_entry cpu_info;
//by chentao
 // ret = hsl_bcm_get_master_cpu ((char *)&cpu_info.mac_addr);
  if (ret < 0)
  {
     HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  }
  else
  {
      hsl_sock_post_msg (sock, HAL_MSG_CPU_GET_MASTER, 0, hdr->nlmsg_seq,
          (char *)&cpu_info, sizeof (struct hal_cpu_info_entry));
  }
  
  return 0;
}


int
hsl_msg_recv_cpu_get_local (struct socket *sock, struct hal_nlmsghdr *hdr, 
                            char *msgbuf)
{
  int ret= 0;
  struct hal_cpu_info_entry cpu_info;
	//by chentao delete
 // ret = hsl_bcm_get_local_cpu ((char *)&cpu_info.mac_addr);
  if (ret < 0)
  {
     HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  }
  else
  {
      hsl_sock_post_msg (sock, HAL_MSG_CPU_GET_LOCAL, 0, hdr->nlmsg_seq,
          (char *)&cpu_info, sizeof (struct hal_cpu_info_entry));
  }

  return 0;
}
#endif
// #ifdef HAVE_NETFORD_SHAPE
int
hsl_msg_recv_shape_get_mse_mem (struct socket *sock, struct hal_nlmsghdr *hdr,
                            char *msgbuf)
{
  int ret;
  struct hal_shape_mem *mse_mem;

  mse_mem = (struct hal_shape_mem *)msgbuf;

  ret = hsl_shape_mem_get ((char *)mse_mem->mem_buffer, (int)mse_mem->offset, (int)mse_mem->length);

  if (ret < 0)
  {
     HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  }
  else
  {
      hsl_sock_post_msg (sock, HAL_MSG_SHAPE_GET_MSE_MEM, 0, hdr->nlmsg_seq,
          (char *)&mse_mem, sizeof (struct hal_shape_mem));
  }

  return 0;
}

// #endif

int
hsl_msg_recv_get_optical_module_info (struct socket *sock, struct hal_nlmsghdr *hdr,
                            char *msgbuf)
{
  int ret = 0;
  struct hal_msg_optical_module_req *msg;
  struct hal_optical_module_info optical_module_info;
  

  msg = (struct hal_msg_optical_module_req *)msgbuf;

  memset(&optical_module_info, 0, sizeof(struct hal_optical_module_info));
  //by chentao delete
 // ret = read_optical_module_register(msg->ifindex, &optical_module_info);
  if (ret < 0)
  {
     HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
  }
  else
  {
	 hsl_sock_post_msg(sock, HAL_MSG_GET_OPTICAL_MODULE_INFO, hdr->nlmsg_seq, 0, (char *)&optical_module_info, sizeof(struct hal_optical_module_info));
  }
  return 0;
}

int
hsl_msg_recv_storm_ctl_set (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret = 0;
	struct hal_msg_storm_ctl *storm_ctl;

	storm_ctl = (struct hal_msg_storm_ctl *)msgbuf;

	//printk("msg recv: ifindex_or_vlan=%d, enable=%d, type=%d,mode=%d, threshold_num=%d", storm_ctl->ifindex_or_vlan,
	//	storm_ctl->enable, storm_ctl->type, storm_ctl->mode, storm_ctl->threshold_num);
	
	ret = hsl_bridge_storm_ctl(storm_ctl->ifindex_or_vlan, storm_ctl->iv.ifindex, storm_ctl->iv.vlan_id, storm_ctl->enable,
		storm_ctl->type, storm_ctl->mode, storm_ctl->threshold_num, storm_ctl->is_discard_to_cpu);
	
	HSL_MSG_PROCESS_RETURN_WITH_VALUE(sock, hdr, ret);
}

int hsl_msg_recv_zw_ipmc_add (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret =0;

	hal_ipmc_group_info_t *ipmc_group_info = (struct hal_ipmc_group_info_t *)msgbuf;

	ret = hsl_ipv4_mc_add_mfc (ipmc_group_info);
	

	HSL_MSG_PROCESS_RETURN_WITH_VALUE(sock, hdr, ret);
}


int hsl_msg_recv_zw_ipmc_del (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret =0;
	hal_ipmc_group_info_t *ipmc_group_info = (struct hal_ipmc_group_info_t *)msgbuf;
	ret = hsl_ipv4_mc_del_mfc(ipmc_group_info);
	HSL_MSG_PROCESS_RETURN_WITH_VALUE(sock, hdr, ret);
}


