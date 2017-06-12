/* Copyright (C) 2004 IP Infusion, Inc.  All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"
                                                                                
/* Broadcom includes. */
//#include "bcm_incl.h"

#include "hsl_types.h"
                                                                               
/* HAL includes. */
#include "hal_netlink.h"
#include "hal_msg.h"

#include "hsl_avl.h"
#include "hsl.h"
#include "hsl_oss.h"
#include "hsl_comm.h"
#include "hsl_logger.h"
#include "hsl_ifmgr.h"
#include "hsl_ether.h"

#include "hsl_vlan.h"

#include "ctc_api.h"


//#include "hsl_bcm_ifmap.h"
#include "hsl_l2_sock.h"

#ifdef HAVE_LACPD
extern int hsl_af_lacp_sock_init (void);
extern int hsl_af_lacp_sock_deinit (void);
#endif /* HAVE_LACPD */
#if defined(HAVE_STPD) || defined(HAVE_RSTPD) || defined(HAVE_MSTPD)
extern int hsl_af_stp_sock_init (void);
extern int hsl_af_stp_sock_deinit (void);
#endif /* defined(HAVE_STPD) || defined(HAVE_RSTPD) || defined(HAVE_MSTPD) */
#ifdef HAVE_AUTHD
extern int hsl_af_eapol_sock_init (void);
extern int hsl_af_eapol_sock_deinit (void);
#endif /* HAVE_AUTHD */
#if defined(HAVE_GVRP) || defined(HAVE_GMRP)
extern int hsl_af_garp_sock_init (void);
extern int hsl_af_garp_sock_deinit (void);
#endif /* defined(HAVE_GVRP) || defined (HAVE_GMRP) */
#ifdef HAVE_IGMP_SNOOP
extern int hsl_af_igs_sock_init (void);
extern int hsl_af_igs_sock_deinit (void);
#endif /* HAVE_IGMP_SNOOP. */
#ifdef HAVE_MLD_SNOOP
extern int hsl_af_mlds_sock_init (void);
extern int hsl_af_mlds_sock_deinit (void);
#endif /* HAVE_MLD_SNOOP. */


/* Post a packet to the socket backend. */
int
hsl_sock_post_skb (struct sock *sk, struct sk_buff *skb)
{
  skb_set_owner_r (skb, sk);
  skb->dev = NULL;
#if 0   /* EWAN linux2.4 */
  spin_lock (&sk->receive_queue.lock);
  __skb_queue_tail (&sk->receive_queue, skb);
  spin_unlock (&sk->receive_queue.lock);
  sk->data_ready (sk, skb->len);
#else   /* EWAN linux2.6 */
  spin_lock (&sk->sk_receive_queue.lock);
  __skb_queue_tail (&sk->sk_receive_queue, skb);
  spin_unlock (&sk->sk_receive_queue.lock);
  sk->sk_data_ready (sk, skb->len);
#endif

  return 0;
}



static struct sk_buff *_hsl_ctc_rx_handle_untagged (struct hsl_if *ifp, ctc_pkt_buf_t *pkt_buf)
{
	struct sockaddr_l2 sockaddr;
	int sockaddrlen = sizeof (struct sockaddr_l2);
	int totlen;
	struct sk_buff *skb = NULL;
	u_char *p = NULL;
	struct hsl_eth_header *eth = NULL;
	int payloadlen = 0;
	int len = 0;
	
	p = pkt_buf->data;
	eth = (struct hsl_eth_header *)p;
	if (htons(eth->d.type) == 0x8100) {
		len = ENET_TAGGED_HDR_LEN;
	} else {
		len = ENET_UNTAGGED_HDR_LEN;
	}

	payloadlen = pkt_buf->len - len - 4;
	
	/* Packet length - len - 4(for CRC) + sizeof (struct sockaddr_l2) */
	totlen = sockaddrlen + payloadlen;
	
	skb = dev_alloc_skb (totlen);
	if (! skb) {
		return NULL;
	}

	/* Set length. */
	skb->len = totlen;
	skb->truesize = totlen;	
	
	/* Fill sockaddr. */
	memcpy (sockaddr.dest_mac, eth->dmac, 6);
	memcpy (sockaddr.src_mac, eth->smac, 6);
	sockaddr.port = ifp->ifindex;	

	/* Copy sockaddr. */
	memcpy (skb->data, &sockaddr, sockaddrlen);
	p += len;

	/* Copy packet. */
	memcpy (skb->data + sockaddrlen, p, payloadlen);
	
	return skb;
}


int hsl_ctc_rx_handle_bpdu (struct hsl_if *ifp, ctc_pkt_buf_t *pkt_buf)
{
	struct sk_buff *skb = NULL;
	skb = _hsl_ctc_rx_handle_untagged (ifp, pkt_buf);
	if (!skb) {
		return -1;
	}
	
	/* Post this skb to the socket backend. */
	hsl_af_stp_post_packet (skb);
	
	/* Free skb. */
	kfree_skb (skb);
	
	return 0;	
}


/* add by suk */
int
hsl_ctc_rx_handle_lacp (struct hsl_if *ifp, ctc_pkt_buf_t *pkt_buf)
{
  //printk("[%s - %d]: into %s\n", __FUNCTION__, __LINE__, __FUNCTION__);
  struct sk_buff *skb;

  skb = _hsl_ctc_rx_handle_untagged (ifp, pkt_buf);
  if (! skb)
    return -1;
  
#if 0
  int i = 0;
  for(i = 0; i < skb->len; i++)
	  printk("%02x ", skb->data[i]);
  printk("\n");  
#endif

  /* Post this skb to the socket backend. */
  hsl_af_lacp_post_packet (skb);

  /* Free skb. */
  kfree_skb (skb);

  return 0;
}






#if  0
/* Returns a skb with untagged control frame. */
static struct sk_buff *
_hsl_bcm_rx_handle_untagged (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct sockaddr_l2 sockaddr;
  int sockaddrlen = sizeof (struct sockaddr_l2);
  int totlen;
  struct sk_buff *skb = NULL;
  u_char *p = NULL;
  struct hsl_eth_header *eth = NULL;
  int payloadlen;
  int len;

  p = BCM_PKT_DMAC (pkt);
  eth = (struct hsl_eth_header *) p;
  if (htons(eth->d.type) == 0x8100)
    {
      len = ENET_TAGGED_HDR_LEN;
    }
  else
    {
      len = ENET_UNTAGGED_HDR_LEN;
    }

  payloadlen = pkt->pkt_len - len - 4;

  /* Packet length - len - 4(for CRC) + sizeof (struct sockaddr_l2) */
  totlen = sockaddrlen + payloadlen;

  skb = dev_alloc_skb (totlen);
  if (! skb)
    return NULL;

  /* Set length. */
  skb->len = totlen;
  skb->truesize = totlen;

  /* Fill sockaddr. */
  memcpy (sockaddr.dest_mac, eth->dmac, 6);
  memcpy (sockaddr.src_mac, eth->smac, 6);
  sockaddr.port = ifp->ifindex;

  /* Copy sockaddr. */
  memcpy (skb->data, &sockaddr, sockaddrlen);
  p += len;

  /* Copy packet. */
  memcpy (skb->data + sockaddrlen, p, payloadlen);

  return skb;
}

/* Returns a skb with tagged control frame. */
static struct sk_buff *
_hsl_bcm_rx_handle_tagged (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct sockaddr_vlan sockaddr;
  int sockaddrlen = sizeof (struct sockaddr_vlan);
  int totlen;
  struct sk_buff *skb;
  u_char *p;
  struct hsl_eth_header *eth;
  int payloadlen;

  p = BCM_PKT_DMAC (pkt);
  eth = (struct hsl_eth_header *) p;

  /* Actual payload length. */
  payloadlen = pkt->pkt_len - ENET_TAGGED_HDR_LEN - 4;

  /* Packet length - ENET_TAGGED_HDR_LEN - 4(for CRC) + sizeof (struct sockaddr_vlan). */
  totlen = sockaddrlen + payloadlen;

  skb = dev_alloc_skb (totlen);
  if (! skb)
    return NULL;

  /* Set length. */
  skb->len = totlen;
  skb->truesize = totlen;

  /* Fill sockaddr. */
  memcpy (sockaddr.dest_mac, eth->dmac, 6);
  memcpy (sockaddr.src_mac, eth->smac, 6);
  sockaddr.port = ifp->ifindex;
  sockaddr.vlanid = HSL_ETH_VLAN_GET_VID (eth->d.vlan.pri_cif_vid);

  /* Copy sockaddr. */
  memcpy (skb->data, &sockaddr, sockaddrlen);
  p += ENET_TAGGED_HDR_LEN;

  /* Copy packet. */
  memcpy (skb->data + sockaddrlen, p, payloadlen);

  return skb;
}

#if defined (HAVE_STPD) || defined(HAVE_RSTPD) || defined(HAVE_MSTPD)
/*
  Handle BPDU. 
  Substract CRC length.
  pkt -> mblk copy
*/
int
hsl_bcm_rx_handle_bpdu (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct sk_buff *skb;

  skb = _hsl_bcm_rx_handle_untagged (ifp, pkt);
  if (! skb)
    return -1;

  /* Post this skb to the socket backend. */
  hsl_af_stp_post_packet (skb);

  /* Free skb. */
  kfree_skb (skb);

  return 0;
}
#endif /* defined (HAVE_STPD) || defined(HAVE_RSTPD) || defined(HAVE_MSTPD) */

#ifdef HAVE_AUTHD

/* Returns a skb with eapol control frame. */
static struct sk_buff *
_hsl_bcm_rx_handle_eapol (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct sockaddr_l2 sockaddr;
  int sockaddrlen = sizeof (struct sockaddr_l2);
  int totlen;
  struct sk_buff *skb = NULL;
  u_char *p = NULL;
  u_int32_t recv_untagged;
  struct hsl_eth_header *eth = NULL;
  int payloadlen;
  int hw_pktlen;
  int len;
  hsl_vid_t pvid;

  p = BCM_PKT_DMAC (pkt);
  eth = (struct hsl_eth_header *) p;
  recv_untagged = pkt->rx_untagged;
  
  if (eth->d.type == 0x8100)
    {
      if (!(recv_untagged)) 
        {
          pvid = hsl_get_pvid (ifp);

          if (pvid == 0)
            return NULL;
          
          if (pvid != HSL_ETH_VLAN_GET_VID (eth->d.vlan.pri_cif_vid))
            {
              /* Discarding tagged EAPOL frame. ANVL TC 3.2 */
              HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_ERROR," Discarding tagged frame \n");
              return NULL;
            }
        }
      /* Priority-tagged frame vlan id is NULL */
      len = ENET_TAGGED_HDR_LEN;
    }
  else
    {
      len = ENET_UNTAGGED_HDR_LEN;
    }
  
  p += len;
  payloadlen = ((p[2] << 8) | p[3]) + HSL_L2_AUTH_HDR_LEN;
  hw_pktlen = BCM_PKT_IEEE_LEN(pkt) - len - 4;

  /* Junk packet */
  if (payloadlen > hw_pktlen)
    return NULL;

  /* Packet length - len - 4(for CRC) + sizeof (struct sockaddr_l2) */
  totlen = sockaddrlen + payloadlen;

  skb = dev_alloc_skb (totlen);
  if (! skb)
    return NULL;

  /* Set length. */
  skb->len = totlen;
  skb->truesize = totlen;

  /* Fill sockaddr. */
  memcpy (sockaddr.dest_mac, eth->dmac, 6);
  memcpy (sockaddr.src_mac, eth->smac, 6);
  sockaddr.port = ifp->ifindex;

  /* Copy sockaddr. */
  memcpy (skb->data, &sockaddr, sockaddrlen);

  /* Copy packet. */
  memcpy (skb->data + sockaddrlen, p, payloadlen);

  return skb;
}

/*
  Handle EAPOL.
  Substract CRC length.
  pkt -> mblk copy
*/
int
hsl_bcm_rx_handle_eapol (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct sk_buff *skb;

  skb = _hsl_bcm_rx_handle_eapol (ifp, pkt);
  if (! skb)
    return -1;

  /* Post this skb to the socket backend. */
  hsl_af_eapol_post_packet (skb);

  /* Free skb. */
  kfree_skb (skb);

  return 0;
}
#endif /* HAVE_AUTHD */

#ifdef HAVE_LACPD
/*
  Handle LACP.
  Substract CRC length.
  pkt -> mblk copy
*/
int
hsl_bcm_rx_handle_lacp (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct sk_buff *skb;

  skb = _hsl_bcm_rx_handle_untagged (ifp, pkt);
  if (! skb)
    return -1;

  /* Post this skb to the socket backend. */
  hsl_af_lacp_post_packet (skb);

  /* Free skb. */
  kfree_skb (skb);

  return 0;
}
#endif /* HAVE_LACPD */
#ifdef HAVE_OPENFLOW

u_int16_t hsl_bcm_get_pkt_type(struct hsl_eth_header *eth) 
{
    u_int16_t type;
    
    if (eth == NULL) {
        return HSL_FALSE;
    }

    if (eth->d.type == HSL_ENET_8021Q_VLAN) {
        type = eth->d.vlan.type;

    } else {
        type = eth->d.type;
    }

    return ntohs(type);
}
HSL_BOOL hsl_bcm_is_arp(struct hsl_eth_header *eth)
{
    u_int16_t type;
    
    if (eth == NULL) {
        return HSL_FALSE;
    }

    type = hsl_bcm_get_pkt_type(eth);

    if ((type == HSL_ETHER_TYPE_ARP) || (type == HSL_ETHER_TYPE_RARP)) {
        return HSL_TRUE;
    } else {
        return HSL_FALSE;
    }
    
}

HSL_BOOL hsl_bcm_is_dhcp(struct hsl_eth_header *eth)
{
    int type;
    struct hsl_ip *ip_header;
    struct udp_hdr{
      unsigned short uh_sport;
      unsigned short uh_dport;
      unsigned short uh_ulen;
      unsigned short uh_sum;
    } *udp;
    
    if (eth == NULL) {
        return HSL_FALSE;
    }

    if (eth->d.type == HSL_ENET_8021Q_VLAN) {
        type = eth->d.vlan.type;

    } else {
        type = eth->d.type;
    }

    if (type != HSL_ETHER_TYPE_IP){
        return HSL_FALSE;
    }

    ip_header = (struct hsl_ip*)&eth[1];
    if (ip_header->ip_p != HSL_PROTO_UDP) {
        return HSL_FALSE;
    }

    udp = (struct udp_hdr*)&ip_header[1];
    if (udp->uh_dport != htons(67)) {
        return HSL_FALSE;
    }
    
    return HSL_TRUE;   
    
}

HSL_BOOL hsl_bcm_is_packet_in( bcm_pkt_t *pkt)
{
    return hsl_ofp_is_packet_in(pkt->rx_matched);
}

#if 1
static struct sk_buff *
_hsl_bcm_rx_openflow (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct sockaddr_of sockaddr;
  int sockaddrlen = sizeof (struct sockaddr_of);
  int totlen;
  struct sk_buff *skb;
  u_char *p;
  struct hsl_eth_header *eth;
  int payloadlen;

  p = BCM_PKT_DMAC (pkt);
  eth = (struct hsl_eth_header *) p;

  /* Actual payload length. */
  payloadlen = pkt->pkt_len - 4;

  /* Packet length - 4(for CRC) + sizeof (struct sockaddr_vlan). */
  totlen = sockaddrlen + payloadlen;

  skb = dev_alloc_skb (totlen);
  if (! skb)
    return NULL;

  /* Set length. */
  skb->len = totlen;
  skb->truesize = totlen;

  /* Fill sockaddr. */
  memcpy (sockaddr.dest_mac, eth->dmac, 6);
  memcpy (sockaddr.src_mac, eth->smac, 6);
  sockaddr.port = ifp->ifindex;
  sockaddr.vlanid = HSL_ETH_VLAN_GET_VID (eth->d.vlan.pri_cif_vid);
  sockaddr.reason = hsl_ofp_get_packet_in_reason(pkt->rx_matched);
  sockaddr.pkt_type = hsl_bcm_get_pkt_type(eth);
  
  /* Copy sockaddr. */
  memcpy (skb->data, &sockaddr, sockaddrlen);

  /* Copy packet. */
  memcpy (skb->data + sockaddrlen, p, payloadlen);

  return skb;
}
#else

static struct sk_buff *
_hsl_bcm_rx_openflow (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct sockaddr_vlan sockaddr;
  int sockaddrlen = sizeof (struct sockaddr_vlan);
  int totlen;
  struct sk_buff *skb;
  u_char *p;
  struct hsl_eth_header *eth;
  int payloadlen;
  int len;
  int vlan_len;

  p = BCM_PKT_DMAC (pkt);
  eth = (struct hsl_eth_header *) p;
    if (htons(eth->d.type) == 0x8100)
    {
      len = ENET_TAGGED_HDR_LEN;
      vlan_len = 4;
    }
    else
    {
      len = ENET_UNTAGGED_HDR_LEN;
      vlan_len = 0;
    }

  /* Actual payload length. */
  payloadlen = pkt->pkt_len - 4;

  /* Packet length - 4(for CRC) + sizeof (struct sockaddr_vlan) - vlan tag len. */
  totlen = sockaddrlen + payloadlen - vlan_len;

  skb = dev_alloc_skb (totlen);
  if (! skb)
    return NULL;

  /* Set length. */
  skb->len = totlen;
  skb->truesize = totlen;

  /* Fill sockaddr. */
  memcpy (sockaddr.dest_mac, eth->dmac, 6);
  memcpy (sockaddr.src_mac, eth->smac, 6);
  sockaddr.port = ifp->ifindex;
  sockaddr.vlanid = HSL_ETH_VLAN_GET_VID (eth->d.vlan.pri_cif_vid);

  /* Copy sockaddr. */
  memcpy (skb->data, &sockaddr, sockaddrlen);

  /* Copy packet. */
  memcpy (skb->data + sockaddrlen, p, 12);
  memcpy (skb->data + sockaddrlen + 12, p + 12 + vlan_len, payloadlen - 12 - vlan_len);

  return skb;
}
#endif

/*返回-1继续处理，返回0，不再处理*/
int hsl_bcm_rx_openflow_packet_in(struct hsl_if *ifp, bcm_pkt_t *pkt)
{
    struct hsl_if *ifpl3;
    struct sk_buff *skb;
    struct hsl_eth_header *eth = NULL;
    hsl_vid_t vid;
    HSL_BOOL    dmac_is_my;
    HSL_BOOL    dmac_is_bc;
    char bc_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    int i;

    /*不是fp抓的包，继续处理*/
    HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_INFO, "rx_reason:%x\n", pkt->rx_reason);
    for (i = 0; i < _SHR_BITDCLSIZE(_SHR_RX_REASON_COUNT);i++) {
        HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_INFO, "rx_reasons %x:%x\n", i,pkt->rx_reasons.pbits[i]);
    }
    if (!BCM_RX_REASON_GET(pkt->rx_reasons ,bcmRxReasonFilterMatch)) {
        return -1;
    }

    if (BCM_RX_REASON_GET(pkt->rx_reasons ,bcmRxReasonControl)) {
        return -1;
    }

    if (BCM_RX_REASON_GET(pkt->rx_reasons ,bcmRxReasonDhcp)) {
        return -1;
    }

    eth = (struct hsl_eth_header *) BCM_PKT_DMAC (pkt);

    if (BCM_RX_REASON_GET(pkt->rx_reasons ,bcmRxReasonBpdu)) {
        /*LLDP仍然由控制处理*/
        if (eth->dmac[5] != 0xe) {
            return -1;
        }
    }

    if (eth->d.type == HSL_ENET_8021Q_VLAN)
    {
        vid = HSL_ETH_VLAN_GET_VID (eth->d.vlan.pri_cif_vid);
    }
    else
        vid = HSL_DEFAULT_VID;

    /* Get matching L3 port. */
    ifpl3 = hsl_ifmgr_get_matching_L3_port (ifp, vid);
    if (ifpl3 != NULL) {
        dmac_is_my = (memcmp(eth->dmac, ifpl3->u.ip.mac, 6) == 0) ? HSL_TRUE : HSL_FALSE; 
    } else {
        dmac_is_my = FALSE;
    }
    dmac_is_bc = (memcmp(eth->dmac, bc_mac, 6) == 0) ? HSL_TRUE : HSL_FALSE; 

    if (dmac_is_my) {
        return -1;
    }

    if (dmac_is_bc) {
        if (hsl_bcm_is_arp(eth)) {
            struct hsl_arp *arp;
            arp = (struct hsl_arp*)&eth[1];
            if (ifpl3 && hsl_ifmgr_is_have_ip_addr(ifpl3, ntohl(*(int*)arp->ip_dstp))) {
                return -1;
            }
        }

        if (hsl_bcm_is_dhcp(eth)) {
            return -1;
        }

    }

    if (!hsl_bcm_is_packet_in(pkt)) {
        return -1;
    }

    skb = _hsl_bcm_rx_openflow (ifp, pkt);
    if (! skb)
        return 0;

    /* Post this skb to the socket backend. */
    hsl_af_of_post_packet (skb, hsl_bcm_get_pkt_type(eth));

    /* Free skb. */
    kfree_skb (skb);

    return 0;
    
}
#endif

#ifdef HAVE_GMRP
/*
  Handle GMRP.
  Substract CRC length
  pkt -> mblk copy
*/
int
hsl_bcm_rx_handle_gmrp (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct sk_buff *skb;

  skb = _hsl_bcm_rx_handle_tagged (ifp, pkt);
  if (! skb)
    return -1;

  /* Post this skb to the socket backend. */
  hsl_af_garp_post_packet (skb);

  /* Free skb. */
  kfree_skb (skb);

  return 0;
}
#endif /* HAVE_GMRP */

#ifdef HAVE_GVRP
/*
  Handle GVRP.
  Substract CRC length
  pkt -> mblk copy
*/
int
hsl_bcm_rx_handle_gvrp (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct sk_buff *skb;

  skb = _hsl_bcm_rx_handle_tagged (ifp, pkt);
  if (! skb)
    return -1;

  /* Post this skb to the socket backend. */
  hsl_af_garp_post_packet (skb);

  /* Free skb. */
  kfree_skb (skb);

  return 0;
}

#endif /* HAVE_GVRP */

#ifdef HAVE_IGMP_SNOOP
/*
  Handle IGMP Snooping packet.
  Substract CRC length.
  pkt -> mblk copy
*/
int
hsl_bcm_rx_handle_igs (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct sk_buff *skb;

  skb = _hsl_bcm_rx_handle_tagged (ifp, pkt);
  if (! skb)
    return -1;

  /* Post this skb to the socket backend. */
  hsl_af_igs_post_packet (skb);

  /* Free skb. */
  kfree_skb (skb);

  return 0;
}
#endif /* HAVE_IGMP_SNOOP */

#ifdef HAVE_MLD_SNOOP
/*
  Handle MLD Snooping packet.
  Substract CRC length.
  pkt -> mblk copy
*/
int
hsl_bcm_rx_handle_mlds (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct sk_buff *skb;

  skb = _hsl_bcm_rx_handle_tagged (ifp, pkt);
  if (! skb)
    return -1;

  /* Post this skb to the socket backend. */
  hsl_af_mlds_post_packet (skb);

  /* Free skb. */
  kfree_skb (skb);

  return 0;
}
#endif /* HAVE_MLD_SNOOP */
#endif
/*
  Initialize L2 socket backends.
*/
int
hsl_l2_sock_init (void)
{
#ifdef HAVE_LACPD
  /* LACP. */
  hsl_af_lacp_sock_init ();
#endif /* HAVE_LACPD. */

#if defined (HAVE_STPD) || defined (HAVE_RSTPD) || defined (HAVE_MSTPD)
  /* STP. */
  hsl_af_stp_sock_init ();
#endif /* defined (HAVE_STPD) || defined (HAVE_RSTPD) || defined (HAVE_MSTPD) */
#if 0
#ifdef HAVE_AUTHD
  /* EAPOL. */
  hsl_af_eapol_sock_init ();
#endif /* HAVE_AUTHD */

#if defined(HAVE_GVRP) || defined(HAVE_GMRP)
  /* GARP. */
  hsl_af_garp_sock_init ();
#endif /* HAVE_GMRP */

#ifdef HAVE_IGMP_SNOOP
  /* IGS. */
  hsl_af_igs_sock_init ();
#endif /* HAVE_IGMP_SNOOP */

#ifdef HAVE_MLD_SNOOP
 /* MLDS. */
 hsl_af_mlds_sock_init ();
#endif /* HAVE_MLD_SNOOP */

#ifdef HAVE_OPENFLOW
  hsl_af_of_sock_init();
#endif

#endif
  return 0;
}

/*
  Deinitialize L2 socket backends.
*/
int
hsl_l2_sock_deinit ()
{
#ifdef HAVE_LACPD
  /* LACP. */
  hsl_af_lacp_sock_deinit ();
#endif /* HAVE_LACD */

#if defined (HAVE_STPD) || defined(HAVE_RSTPD) || defined(HAVE_MSTPD)
  /* STP. */
  hsl_af_stp_sock_deinit ();
#endif /* defined (HAVE_STPD) || defined(HAVE_RSTPD) || defined(HAVE_MSTPD) */
#if 0
#ifdef HAVE_AUTHD
  /* EAPOL. */
  hsl_af_eapol_sock_deinit ();
#endif /* HAVE_AUTHD */

#if defined(HAVE_GMRP) || defined(HAVE_GVRP)
  /* GARP. */
  hsl_af_garp_sock_deinit ();
#endif /* defined(HAVE_GMRP) || defined(HAVE_GVRP) */

#ifdef HAVE_IGMP_SNOOP
  /* IGS. */
  hsl_af_igs_sock_deinit ();
#endif /* HAVE_IGMP_SNOOP. */

#ifdef HAVE_MLD_SNOOP
  /* MLDS. */
  hsl_af_mlds_sock_deinit ();
#endif /* HAVE_MLD_SNOOP. */
#endif
  return 0;
}
