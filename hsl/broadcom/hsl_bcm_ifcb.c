/* Copyright (C) 2004 IP Infusion, Inc.  All Rights Reserved. */

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

#ifdef HAVE_L2
#include "hal_l2.h"
#endif /* HAVE_L2 */

#include "hal_msg.h"

#include "hsl_types.h"
#include "hsl_logger.h"
#include "hsl_ether.h"
#include "hsl_ifmgr.h"
#include "hsl_if_os.h"
#include "hsl_if_hw.h"
#include "hsl_ifmgr.h"

#include "hsl_bcm_if.h"
#include "hsl_bcm_ifmap.h"
#include "hsl_bcm_pkt.h"

#define FIBER_PORTS_MIN 25
static int cnt_ext_ports = 0;

#if 0
int
hsl_bcm_port_medium_set(int gport, int unit, int lport)
{
	bcm_phy_config_t cfg;
	
	int ret;
	
	if (lport > FIBER_PORTS_MIN) {
		memset(&cfg, 0, sizeof(bcm_phy_config_t));
		cfg.enable = 0;
		cfg.preferred = 0;
		bcmx_port_medium_config_set(lport, BCM_PORT_MEDIUM_COPPER, &cfg);
		
		memset(&cfg, 0, sizeof(bcm_phy_config_t));	
		cfg.enable = 1;
		cfg.preferred = 1;
		ret = bcmx_port_medium_config_set(lport, BCM_PORT_MEDIUM_FIBER, &cfg);
		//printk("hsl_bcm_port_medium_set port %d BCM_PORT_MEDIUM_FIBER ret %d\r\n", port, ret);
		
	}
}
#else 
int hsl_ctc_port_medium_set(int gport, int unit, int lport)
{
    return 0;
}
#endif

/* 
   Port callback handling for 
   * Port attachment
   * Port detachment
   * Link Scan
*/

/* 
   Process port attachment message. 
*/
int
hsl_bcm_ifcb_port_attach (int gport, int unit, uint8_t lport,
			  uint32 flags)
{
    char ifname[HSL_IFNAM_SIZE + 1];
    u_char mac[HSL_ETHER_ALEN];
    int ret, stat;
    unsigned long ifflags = 0;
    int speed, mtu;
    u_int32_t  duplex;
    struct hsl_if *ifp;
    struct hsl_bcm_if *bcmifp;
//  bcm_stg_t stg;
//  bcmx_lplist_t t, u;

    /* for vs8512 to get phy link status */
    int  ret         = 0;
    bool phy_link    = FALSE;
    bool qsgmii_link = FALSE;
    bool vsc_an      = FALSE;
    bool vsc_duplex  = FALSE;
    ctc_port_speed_t vsc_speed; 

    memset (ifname, 0, sizeof (ifname));
    /* Register with ifmap and get name and mac address for this port. */
  
    ret = hsl_bcm_ifmap_lport_register (gport, flags, ifname, mac);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Can't register lport(%d) in Broadcom interface map\n", lport);
        return -1;
    }  
  
    hsl_ctc_port_medium_set(gport, unit, lport);

    /* Multicast flag. */
    ifflags |= IFF_MULTICAST;

    /* Broadcast flag. */
    ifflags |= IFF_BROADCAST;

    /* get phy link satus form vs8512 */
    ret = get_vsc8512_status(gport, &phy_link, &qsgmii_link, &vsc_an, &vsc_speed, &vsc_duplex);
    if(ret < 0) {
        printk("[%s]: get_vsc8512_status failed: %d \r\n", __func__, ret);
    }
    
    ret = ctc_port_set_port_en(gport, 1);
    if (ret != 0) {
        printk("ctc_port_set_port_en fail, ret %d\r\n", ret);
    }

    /* Administrative status. */
    ret = ctc_port_get_port_en(gport, &stat);
    if (ret == 0) {
        if (stat)
            ifflags |= IFF_RUNNING;
        else
            ifflags &= ~IFF_UP;
    } else {
        ifflags &= ~IFF_UP;
    }

#if 0
  /* Operational status. */
  ret = bcmx_port_link_status_get (gport, &stat);
  if (ret == BCM_E_NONE)
    {
      if (stat)
	ifflags |= IFF_RUNNING;
      else
	ifflags &= ~IFF_RUNNING;
    }
  else
    ifflags &= ~IFF_RUNNING;
#else
    if(phy_link) {
        ifflags |= IFF_RUNNING;
    } else {
        ifflags &= ~IFF_RUNNING;
    }

#endif

#if 0
	/*flowctrl*/
	ret = bcmx_port_pause_set (gport, 0, 0);
	if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_WARN, "Can't unset flowcontrol for port %d\r\n", port);
	}
#endif

#if 0
    /* Speed. */
  ret = bcmx_port_speed_get (gport, &speed);
  if (ret == BCM_E_NONE)
    {
      /* Change it to kbits/sec. */
      speed *= 1000;
    }
  else
    speed = 0;
#else
    switch(vsc_speed) {
    /* in bytes/sec */
    case CTC_PORT_SPEED_10M:
        speed *= 10;
        break;

    case CTC_PORT_SPEED_100M:
        speed *= 100;
        break;

    case CTC_PORT_SPEED_1G:
    default:
        speed *= 1000;
        break;
    }
    speed *= 1000;  /* change to kbits/s */
#endif

 	//printk("hsl_bcm_ifcb_port_attach: lport %d, port %d, speed %d\r\n", lport, port, speed);

  /* Duplex */
//  hsl_bcm_get_port_duplex(gport, &duplex);
    if(duplex) {    /* full duplex */
        duplex = NSM_IF_FULL_DUPLEX;
    } else {
        duplex = NSM_IF_HALF_DUPLEX;
    }

  /* MTU. */
  //hsl_bcm_get_port_mtu (lport, &mtu);
  /* Set HW port MTU to account for 8021Q tagged frames */
//  ret = hsl_bcm_set_port_mtu (gport, HSL_8021Q_MAX_LEN);
    /* ctc no mtu settings, so we set ctc max frame size to 8192 */
    ret = ctc_port_set_max_frame(gport, 8192);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_WARN, "Interface %s hardware mtu %d set failed\n", ifname, HSL_8021Q_MAX_LEN);
    }
//  hsl_bcm_get_port_mtu(gport, &mtu);
    ctc_port_get_max_frame(gport, &mtu);    /* at there, mtu is max frame size, maybe it's wrong */
  
  bcmifp = hsl_bcm_if_alloc ();
  if (! bcmifp)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Memory allocation failed for Broadcom interface\n");
      return -1;
    }

  bcmifp->u.l2.gport = gport;
  bcmifp->type = HSL_BCM_IF_TYPE_L2_ETHERNET;
  bcmifp->trunk_id = -1;

  if (unit)
    cnt_ext_ports++;

  /* Register this interface with the interface manager. */
  ret = hsl_ifmgr_L2_ethernet_register (ifname, mac, mtu, speed, duplex, ifflags, 
					(void *) bcmifp, &ifp);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Interface %s registration failed with HSL Interface Manager\n", ifname);
      return -1;
    }
  
#if 0
    /* Set this port to disable by default. */
  bcmx_stg_default_get (&stg);

  bcmx_stg_stp_set (stg, lport, BCM_STG_STP_BLOCK);

  /* Add this port to the default VLAN. */
  bcmx_lplist_init (&t, 1, 0);
  bcmx_lplist_init (&u, 1, 0);

  bcmx_lplist_add (&t, lport);
  bcmx_lplist_add (&u, lport);

  bcmx_vlan_port_add (HSL_DEFAULT_VID, t, u);

  bcmx_lplist_free (&t);
  bcmx_lplist_free (&u);

  /* Set port filtering mode for multicast packets. */
  bcmx_port_pfm_set (lport, BCM_PORT_MCAST_FLOOD_UNKNOWN);
#endif

  /* Set packet types to accept from this port. */
  hsl_ifmgr_unset_acceptable_packet_types (ifp, HSL_IF_PKT_ALL);

  /* Set the uport for the lport. */
  hsl_bcm_ifmap_if_set (lport, ifp);

#ifdef HAVE_L3
#if defined HAVE_MCAST_IPV4 || defined HAVE_MCAST_IPV6

  bcmx_ipmc_egress_port_set (lport, ifp->u.l2_ethernet.mac, HSL_FALSE,
                             HSL_DEFAULT_VID, 0);

#endif /* HAVE_MCAST_IPV4 || HAVE_MCAST_IPV6 */
#endif /* HAVE_L3 */

  return 0;
}

/* 
   Process port detachment message. 
*/
int
hsl_bcm_ifcb_port_detach (bcmx_lport_t lport, bcmx_uport_t uport)
{
  struct hsl_if *ifp;

  /* Get ifindex for the lport. */
  ifp = hsl_bcm_ifmap_if_get (lport);
  if (! ifp)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Lport (%d) not found in Interface Map\n", lport);
      return -1;
    }

#if 0
  if (unit)
    cnt_ext_ports--;
#endif

  HSL_IFMGR_IF_REF_DEC (ifp);

  /* Unregister from interface manager. */
  hsl_ifmgr_L2_ethernet_unregister (ifp);

  return 0;
}

void delay_1s(void){

  unsigned long j = jiffies + HZ;

  while(time_before(jiffies, j))

     schedule();

}


/*
  Process link scan message. 
*/
int
hsl_bcm_ifcb_link_scan (bcmx_lport_t lport, bcm_port_info_t *info)
{
  unsigned long speed;
  unsigned long duplex;
  struct hsl_if *ifp = NULL;
  struct hsl_if *ifp2 = NULL;
  struct hsl_if_list *node = NULL;



  if(lport == 0xFFFF0001) {
  	struct net_device *dev;
  	dev = dev_get_by_name (&init_net, "eth0");

    if(dev)
  	  ifp2 = (struct hsl_if *)dev->ml_priv;

	if(ifp2)
  		node = ifp2->children_list;
	
  	if (node)
      ifp = node->ifp;

	if (ifp) {
		delay_1s();
	   if (netif_carrier_ok(dev)){
			info->linkstatus = 1;
	    } else {
	    	info->linkstatus = 0;
	    }
	}
  	info->speed = 100;
	info->duplex = 1;

  } else {

	  /* Get ifindex for the lport. */
	  ifp = hsl_bcm_ifmap_if_get (lport);
	  if (! ifp)
	    {
	      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "LinkScanning notification for a port(lport) for which map doesn't exist\n");
	      return -1;
	    }
  }

  /* Speed. */
  speed = info->speed * 1000;

  /* Duplex. */
  duplex = info->duplex;

  if (info->linkstatus == BCM_PORT_LINK_STATUS_UP)
    {
      /* Oper status. */
      hsl_ifmgr_L2_link_up (ifp, speed, duplex);
    }
  else 
    {
      /* Oper status. */
      hsl_ifmgr_L2_link_down (ifp, speed, duplex);
    }

  return 0;
}
