/* Copyright (C) 2004 IP Infusion, Inc.  All Rights Reserved. */

#include <linux/types.h>

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
#include "sal_types.h"

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

#include "hsl_ctc_if.h"
#include "hsl_ctc_ifmap.h"
#include "hsl_ctc_micro.h"
#include "ctc_if_portmap.h"
#include "ctc_adapter_hsl_port.h"
#include "ctc_board_macros.h"

//#include "hsl_ctc_pkt.h"

#include "ctc_api.h"
#include "vsc8512.h"

#define FIBER_PORTS_MIN 25
static int cnt_ext_ports = 0;

/* those micros defined in zebos/lib/if.h */
/* Duplex-specific defines */
#define NSM_IF_HALF_DUPLEX      0
#define NSM_IF_FULL_DUPLEX      1
#define NSM_IF_AUTO_NEGO        2
#define NSM_IF_DUPLEX_UNKNOWN   3

#define NSM_IF_AUTONEGO_DISABLE 1
#define NSM_IF_AUTONEGO_ENABLE  0

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
hsl_bcm_ifcb_port_attach (int gport, int unit, uint8_t lport, uint32_t flags)
{
    char ifname[HSL_IFNAM_SIZE + 1];
    u_char mac[HSL_ETHER_ALEN];
    int      ret          = 0;
    int      mtu          = 0;
    int      stat         = 0;
    int      speed        = 1;
    int      panel_port   = 0;
    bool     phy_link_stu = 0;
    uint32_t duplex       = 0;
    unsigned long ifflags = 0;
    struct hsl_if *ifp    = NULL;
    struct hsl_bcm_if *bcmifp = NULL;

    /* for vs8512 to get phy link status */
    int phy_link    = FALSE;
    int qsgmii_link = FALSE;
    int vsc_an      = FALSE;
    int vsc_duplex  = FALSE;
    ctc_port_speed_t vsc_speed; 

   // printk("[%s]: will registe port: gport: %d, unit: %d, lport: %d, flags: %#x\r\n", __func__, gport, unit, lport, flags);
    
    memset (ifname, 0, sizeof (ifname));
    /* Register with ifmap and get name and mac address for this port. */
  
    ret = hsl_bcm_ifmap_lport_register (gport, flags, ifname, mac);
    if (ret < 0) {
        //HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Can't register lport(%d) in Broadcom interface map\n", lport);
        return -1;
    }
  
    hsl_ctc_port_medium_set(gport, unit, lport);

    /* Multicast flag. */
    ifflags |= IFF_MULTICAST;

    /* Broadcast flag. */
    ifflags |= IFF_BROADCAST;

    ret = ctc_port_get_mac_link_up(gport, &phy_link_stu);
    if(ret < 0) {
        printk("[%s]: get gport: %#x, mac link failed: %d\r\n", __func__, gport, ret);
        return -10;
    }

    panel_port = CTC_PORT_LPORT_TO_PANEL(CTC_MAP_GPORT_TO_LPORT(gport));
    if(panel_port < 0) {
        printk("[%s]: Wrong of gport: %#x\r\n", __func__, gport);
        return -11;
    }

    if((board_id == BOARD_PLATFORM_ID_XGS)  \
    || ((board_id == BOARD_PLATFORM_ID_FS5352) && panel_port >= CTC_FS5352_10G_MIN_LPORT)) {
        ret = ctc_port_get_speed(gport, &vsc_speed);
        if(ret < 0) {
            printk("[%s]: get xgs gport: %#x speed failed: %d\r\n", __func__, gport, ret);
            return -12;
        }

        if(phy_link_stu == TRUE) {
            phy_link = 1;
            qsgmii_link = 1;
        } else {
            phy_link = 0;
            qsgmii_link = 0;
        }

        vsc_an      = 1;
        vsc_duplex  = 1;
    } else if((board_id == BOARD_PLATFORM_ID_GES) 
      || ((board_id == BOARD_PLATFORM_ID_FS5352) && panel_port < CTC_FS5352_10G_MIN_LPORT)) {
        ret = get_vsc8512_status(panel_port, &phy_link, &qsgmii_link, &vsc_an, &vsc_speed, &vsc_duplex);
        if(ret < 0) {
            sal_printf("[%s]: get ges gport: %#x, 8512 status failed\r\n", __func__, panel_port);
            return -13;
        }
    } else {
        printk("[%s]: Unknow board_id: %d\r\n", __func__, board_id);
        return -14;
    }   /* end of if(board_id) */

    ret = ctc_port_set_port_en(gport, 1);
    if (ret != 0) {
        printk("ctc_port_set_port_en fail, ret %d\r\n", ret);
        return -15;
    }

    /* Administrative status. */
    ret = ctc_port_get_port_en(gport, &stat);
    if (ret == 0) {
        if (stat)
            ifflags |= IFF_RUNNING;
        else
            ifflags &= ~IFF_RUNNING;
    } else {
        ifflags &= ~IFF_RUNNING;
    }

    if(phy_link & qsgmii_link) {
        ifflags |= IFF_UP;
    } else {
        ifflags &= ~(IFF_UP | IFF_RUNNING);
    }

    switch(vsc_speed) {
    /* in bytes/sec */
    case CTC_PORT_SPEED_10M:
        speed *= 10;
        break;

    case CTC_PORT_SPEED_100M:
        speed *= 100;
        break;

    case CTC_PORT_SPEED_1G:
        speed *= 1000;
        break;

    case CTC_PORT_SPEED_10G:
        speed *= (10 * 1000);
        break;

    default:    /* default is 1g */
        speed *= 1000;
        break;
    }
    speed *= 1000;  /* change to kbits/s */

 	//printk("hsl_bcm_ifcb_port_attach: lport %d, port %d, speed %d\r\n", lport, port, speed);

    /* Duplex */
    if(vsc_duplex) {    /* full duplex */
        duplex = NSM_IF_FULL_DUPLEX;
    } else {
        duplex = NSM_IF_HALF_DUPLEX;
    }

    /* ctc no mtu settings, so we set ctc max frame size to 8192 */
    ret = ctc_port_set_max_frame(gport, 8192);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_WARN, "Interface %s hardware mtu %d set failed\n", ifname, HSL_8021Q_MAX_LEN);
    }
    ctc_port_get_max_frame(gport, &mtu);    /* at there, mtu is max frame size, maybe it's wrong */
  
    bcmifp = hsl_ctc_if_alloc ();
    if (! bcmifp) {
        HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Memory allocation failed for Broadcom interface\n");
        return -1;
    }

    bcmifp->u.l2.lport = gport;
    bcmifp->type = HSL_BCM_IF_TYPE_L2_ETHERNET;
    bcmifp->trunk_id = -1;

    if (unit)
        cnt_ext_ports++;

    /* Register this interface with the interface manager. */
    ret = hsl_ifmgr_L2_ethernet_register (ifname, mac, mtu, speed, duplex, ifflags, (void *) bcmifp, &ifp);
    if (ret < 0) {
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
  hsl_ctc_ifmap_if_set (gport, ifp);

#if 0
#ifdef HAVE_L3
#if defined HAVE_MCAST_IPV4 || defined HAVE_MCAST_IPV6

  bcmx_ipmc_egress_port_set (lport, ifp->u.l2_ethernet.mac, HSL_FALSE,
                             HSL_DEFAULT_VID, 0);

#endif /* HAVE_MCAST_IPV4 || HAVE_MCAST_IPV6 */
#endif /* HAVE_L3 */
#endif

  return 0;
}

/* 
   Process port detachment message. 
*/
int
hsl_bcm_ifcb_port_detach (int gport, int uport)
{
  struct hsl_if *ifp;

  /* Get ifindex for the lport. */
  ifp = hsl_bcm_ifmap_if_get (gport);
  if (! ifp)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Lport (%d) not found in Interface Map\n", gport);
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
int hsl_bcm_ifcb_link_scan (int gport, void *info)
{
    unsigned long speed;
    unsigned long duplex;
    struct hsl_if *ifp = NULL;
    struct hsl_if *ifp2 = NULL;
    struct hsl_if_list *node = NULL;

    int ret           = 0;
    int vsc_an        = 0;
    int vsc_duplex    = 0;
    int phy_link      = 0;
    int qsgmii_link   = 0;
    int panel_port    = 0;
    bool phy_link_stu = 0;

    ctc_port_speed_t vsc_speed = CTC_PORT_SPEED_MAX;

    if(gport == 0xFFFF0001) {
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
                phy_link = TRUE;
                qsgmii_link = TRUE;
            } else {
                phy_link = FALSE;
                qsgmii_link = FALSE;
            }
        }
        speed = 100;
        duplex = NSM_IF_FULL_DUPLEX;
    } else {
        /* Get ifindex for the lport. */
        ifp = hsl_bcm_ifmap_if_get(gport);
        if (! ifp) {
            //HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "LinkScanning notification for a port(lport) for which map doesn't exist\n");
            return -1;
        }

        ret = ctc_port_get_mac_link_up(gport, &phy_link_stu);
        if(ret < 0) {
            printk("[%s]: get gport: %#x, mac link failed: %d\r\n", __func__, gport, ret);
            return -10;
        }

        panel_port = CTC_PORT_LPORT_TO_PANEL(CTC_MAP_GPORT_TO_LPORT(gport));
        if(panel_port < 0) {
            printk("[%s]: Unknow gport(%#x) to panel port\r\n", __func__, gport);
            return -11;
        }
        if((board_id == BOARD_PLATFORM_ID_XGS)  \
        || ((board_id == BOARD_PLATFORM_ID_FS5352) && panel_port >= CTC_FS5352_10G_MIN_LPORT)) {
            ret = ctc_port_get_speed(gport, &speed);
            if(ret < 0) {
                printk("[%s]: get xgs gport: %#x speed failed: %d\r\n", __func__, gport, ret);
                return -12;
            }

            if(phy_link_stu == TRUE) {
                phy_link = 1;
                qsgmii_link = 1;
            } else {
                phy_link = 0;
                qsgmii_link = 0;
            }

            vsc_an      = 1;
            vsc_duplex  = 1;
        } else if((board_id == BOARD_PLATFORM_ID_GES) 
          || ((board_id == BOARD_PLATFORM_ID_FS5352) && panel_port < CTC_FS5352_10G_MIN_LPORT)) {
            ret = get_vsc8512_status(panel_port, &phy_link, &qsgmii_link, &vsc_an, &speed, &vsc_duplex);
            if(ret < 0) {
                sal_printf("[%s]: get ges gport: %#x, 8512 status failed\r\n", __func__, panel_port);
                return -13;
            }
        } else {
            printk("[%s]: Unknow board_id: %d\r\n", __func__, board_id);
            return -14;
        }   /* end of if(board_id) */
    }   /* end of if(gport) */

    switch(vsc_speed) {
    case CTC_PORT_SPEED_1G:
        speed = 1000;
        break;
        
    case CTC_PORT_SPEED_100M:
        speed = 100;
        break;
        
    case CTC_PORT_SPEED_10M:
        speed = 10;
        break;
        
    case CTC_PORT_SPEED_2G5:
        speed = 2500;
        break;

    case CTC_PORT_SPEED_10G:
        speed = 10000;
        break;
        
    default:
        break;
    }
    /* Speed. */
    speed *= 1000;

    /* Duplex. */
    if(vsc_duplex) {    /* full duplex */
        duplex = NSM_IF_FULL_DUPLEX;
    } else {
        duplex = NSM_IF_HALF_DUPLEX;
    }

    if((vsc_duplex == 0) && (vsc_an== 1)) {
        duplex = NSM_IF_AUTO_NEGO;
    }

    if ((phy_link == TRUE) && (qsgmii_link == TRUE)) {
        /* Oper status. */
        ifp->flags |= IFF_UP;
        hsl_ifmgr_L2_link_up (ifp, speed, duplex);
    } else {
        /* Oper status. */
        ifp->flags &= ~IFF_UP;
        hsl_ifmgr_L2_link_down (ifp, speed, duplex);
    }

    return 0;
}



