/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HSL_ETH_DRV_H
#define _HSL_ETH_DRV_H

#define ENET_TAG_SIZE				4
#define		ENET_UNTAGGED_HDR_LEN		14
#define		ENET_TAGGED_HDR_LEN		18



#define VLAN_CTRL(prio, cfi, id)        (((prio) & 0x007) << 13 | \
                                         ((cfi ) & 0x001) << 12 | \
                                         ((id  ) & 0xfff) << 0)

#define VLAN_CTRL_PRIO(c)               ((c) >> 13 & 0x007)
#define VLAN_CTRL_CFI(c)                ((c) >> 12 & 0x001)
#define VLAN_CTRL_ID(c)                 ((c) >>  0 & 0xfff)


#define _CTC_HTONS_CVT_SET(pkt, val, posn)  \
    do { \
         uint16 _tmp; \
         _tmp = htons(val); \
         sal_memcpy((pkt) + (posn), &_tmp, 2); \
    } while (0) 


#define CTC_PKT_HDR_DMAC_SET(pkt, mac)  \
    sal_memcpy((pkt), (mac), 6) 
	
#define CTC_PKT_HDR_SMAC_SET(pkt, mac)  \
    sal_memcpy((pkt) + 6, (mac), 6)
	
#define CTC_PKT_HDR_TPID_SET(pkt, tpid)  \
    _CTC_HTONS_CVT_SET(pkt, tpid, 12) 
	
#define CTC_PKT_HDR_UNTAGGED_LEN_SET(pkt, len)  \
    _CTC_HTONS_CVT_SET(pkt, len, 12) 

#define CTC_PKT_HDR_VTAG_CONTROL_SET(pkt, vtag)  \
    _CTC_HTONS_CVT_SET(pkt, vtag, 14) 
	
#define CTC_PKT_HDR_TAGGED_LEN_SET(pkt, len)  \
    _CTC_HTONS_CVT_SET(pkt, len, 16) 



#define HSL_ETH_PKT_SIZE             1520

int hsl_eth_drv_init (void);
int hsl_eth_drv_deinit (void);
//by chentao delete
//int hsl_eth_drv_post_l3_pkt (struct hsl_if *ifpl3, bcm_pkt_t *pkt);
int hsl_eth_dev_xmit (struct sk_buff * skb, struct net_device * dev);
int hsl_eth_dev_open (struct net_device * dev);
int hsl_eth_dev_close (struct net_device * dev);
struct net_device_stats *hsl_eth_dev_get_stats(struct net_device *dev);
void hsl_eth_dev_set_mc_list (struct net_device *dev);
int hsl_eth_dev_set_mac_addr (struct net_device *dev, void *p);
struct net_device *hsl_eth_drv_create_netdevice (struct hsl_if *ifp,  u_char *hwaddr, int hwaddrlen, int usr_ifindex);
int hsl_eth_drv_destroy_netdevice (struct net_device *dev);

#endif /* _HSL_ETH_DRV_H */
