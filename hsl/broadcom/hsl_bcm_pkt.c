/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"
#include "hsl_avl.h"

/* 
   Broadcom includes. 
*/
#include "bcm_incl.h"
#ifdef VXWORKS
#include "selectLib.h"
#endif /* VXWORKS */
/* 
   HAL includes.
*/
#include "hal_types.h"

#ifdef HAVE_L2
#include "hal_l2.h"
#endif /* HAVE_L2 */

#include "hal_msg.h"

/*
  HSL includes.
*/
#include "hsl_types.h"
#include "hsl_logger.h"
#include "hsl_error.h"
#include "hsl_ether.h"
#include "hsl_table.h"
#include "hsl.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_if_os.h"

/* HAL includes. */
#ifdef HAVE_L2
#include "hal_types.h"
#include "hal_l2.h"
#endif /* HAVE_L2 */

#ifdef HAVE_L2
#include "hsl_l2_sock.h"
#include "hsl_vlan.h"
#include "hsl_bridge.h"
#ifdef HAVE_AUTHD
#include "hsl_bcm_auth.h"
#endif /* HAVE_AUTHD */
#endif /* HAVE_L2 */

#ifdef HAVE_L3
#include "hsl_fib.h"
#endif /* HAVE_L3 */

#include "hsl_bcm_ifmap.h"
#include "hsl_bcm_if.h"
#include "hsl_bcm_pkt.h"
#if defined(HAVE_MCAST_IPV4) || defined(HAVE_MCAST_IPV6) || defined(HAVE_MLD_SNOOP) || defined (HAVE_IGMP_SNOOP)
#include "hsl_mcast_fib.h"
#endif /* HAVE_MCAST_IPV4 || HAVE_MCAST_IPV6 || HAVE_MLD_SNOOP || defined HAVE_IGMP_SNOOP */

#if 1 /** Inserted by alfred, 2007-01-12 **/
#include "bcmx/lport.h"
#endif
#include "hsl_bcm.h"


/* 
   Master packet driver structure.
*/
static struct hsl_bcm_pkt_master *p_hsl_bcm_pkt_master = NULL;
static int aligned_sizeof_bcm_pkt_t;

/*
  L2 Control Frame DMACs.
*/

/* Multicast MAC. */
mac_addr_t multicast_addr    = {0x1, 0x00, 0x5e, 0x00, 0x00, 0x00};

/* Bridge BPDUs. */
mac_addr_t bpdu_addr         = {0x1, 0x80, 0xc2, 0x00, 0x00, 0x00};

/* GMRP BPDUs. */
mac_addr_t gmrp_addr         = {0x1, 0x80, 0xc2, 0x00, 0x00, 0x20};

/* GVRP BPDUs. */
mac_addr_t gvrp_addr         = {0x1, 0x80, 0xc2, 0x00, 0x00, 0x21};

/* LACP. */
mac_addr_t lacp_addr         = {0x1, 0x80, 0xc2, 0x00, 0x00, 0x02};

/* EAPOL. */
mac_addr_t eapol_addr        = {0x1, 0x80, 0xc2, 0x00, 0x00, 0x03};

/* 
   Forward declarations.
*/
int hsl_eth_drv_post_l3_pkt (struct hsl_if *ifpl3, bcm_pkt_t *pkt);
static void _hsl_bcm_rx_handler_thread (void *param);

/*
  Deinitialize master structure. 
*/
static int
_hsl_bcm_pkt_master_deinit (void)
{
  if (p_hsl_bcm_pkt_master)
    {
      if (p_hsl_bcm_pkt_master)
	oss_free (p_hsl_bcm_pkt_master, OSS_MEM_HEAP);
      p_hsl_bcm_pkt_master = NULL;
    }
  return 0;
}

/* 
   Initialize master structure. 
*/
static int
_hsl_bcm_pkt_master_init (void)
{
  HSL_FN_ENTER ();

  p_hsl_bcm_pkt_master = oss_malloc (sizeof (struct hsl_bcm_pkt_master), OSS_MEM_HEAP);
  if (! p_hsl_bcm_pkt_master)
    {
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_FATAL, "Failed allocating memory for packet driver master structure\n");     
      return -1;
    }

  HSL_FN_EXIT (0);
}

/* 
   Deinitialize BCMX Rx.
*/
static int
_hsl_bcm_rx_deinit (void)
{
  HSL_FN_ENTER ();

  if (bcmx_rx_running())
    bcmx_rx_stop ();

  if(p_hsl_bcm_pkt_master)
    HSL_FN_EXIT (0);

  if (p_hsl_bcm_pkt_master->rx.pkt_queue)
    oss_free (p_hsl_bcm_pkt_master->rx.pkt_queue, OSS_MEM_HEAP);

  if (p_hsl_bcm_pkt_master->rx.pkt_sem)
    oss_sem_delete (OSS_SEM_BINARY, p_hsl_bcm_pkt_master->rx.pkt_sem);

  if (p_hsl_bcm_pkt_master->rx.pkt_thread)
    sal_thread_destroy (p_hsl_bcm_pkt_master->rx.pkt_thread);

  HSL_FN_EXIT (0);
}

/*
  Initialize BCMX Rx.
*/
static int
_hsl_bcm_rx_init (void)
{
  int ret;
  int total;

  HSL_FN_ENTER ();
  /* Set up Rx pool. */
  total =  aligned_sizeof_bcm_pkt_t * HSL_BCM_PKT_RX_QUEUE_SIZE;
  if ((p_hsl_bcm_pkt_master->rx.pkt_queue = oss_malloc (total, OSS_MEM_HEAP)) == NULL)
    {
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_FATAL, "Failed allocating memory for packet driver queue\n");     
      goto ERR;
    }

  memset (p_hsl_bcm_pkt_master->rx.pkt_queue, 0, total);
  p_hsl_bcm_pkt_master->rx.total = (HSL_BCM_PKT_RX_QUEUE_SIZE - 1);
  p_hsl_bcm_pkt_master->rx.count = 0;
  p_hsl_bcm_pkt_master->rx.head = 0;
  p_hsl_bcm_pkt_master->rx.tail = 0;
  p_hsl_bcm_pkt_master->rx.drop = 0;

  /* Initialize semaphore. */
  ret = oss_sem_new ("pkt_engine_rx_queue_sem",
		     OSS_SEM_BINARY,
		     0,
		     NULL,
		     &p_hsl_bcm_pkt_master->rx.pkt_sem);


  if (ret < 0)
    {
      goto ERR;
    }


    ret = oss_sem_new ("pkt_engine_rx_queue_mutex",
		     OSS_SEM_BINARY,
		     1,
		     NULL,
		     &p_hsl_bcm_pkt_master->rx.pkt_mutex);

  if (ret < 0)
    {
      goto ERR;
    }
  
  p_hsl_bcm_pkt_master->rx.thread_exit = 0;

  /* Create packet dispather thread. */
  if ((p_hsl_bcm_pkt_master->rx.pkt_thread = 
       sal_thread_create ("zPKTDRV", 
			  SAL_THREAD_STKSZ, 
			  150,
			  _hsl_bcm_rx_handler_thread,
			  0)) == SAL_THREAD_ERROR)
    {
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_FATAL, "Cannot start packet dispatcher thread\n");
      goto ERR;
    }

  /* 
     bcm_rx_burst_set
     bcm_rx_cos_rate_set
     bcm_rx_cos_burst_set
     bcm_rx_cos_max_len_set
  */

  /* Start BCMX RX. */
  if (! bcmx_rx_running ())
    {
      ret = bcmx_rx_start ();
      if (ret < 0)
	{
	  HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_FATAL, "Error starting RX on CPU(%s)\n", bcm_errmsg(ret));
	  goto ERR;
	}
    }

  /* Register RX. */
  ret = bcmx_rx_register ("packet_driver_rx", 
			  hsl_bcm_rx_cb,
			  HSL_BCM_RX_PRIO,
			  NULL,
			  BCM_RCO_F_ALL_COS);

  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_FATAL, "Error registering callback for Rx\n");
      goto ERR;
    }

  HSL_FN_EXIT (0);

 ERR:
  _hsl_bcm_rx_deinit ();

  HSL_FN_EXIT (-1);
}

/* 
   Deinitialize BCMX Tx. 
*/
static int
_hsl_bcm_tx_deinit (void)
{
  if (p_hsl_bcm_pkt_master == NULL)
      return -1;

  if (p_hsl_bcm_pkt_master->tx.pkt_sem)
    oss_sem_delete (OSS_SEM_BINARY, p_hsl_bcm_pkt_master->tx.pkt_sem);
  
  if (p_hsl_bcm_pkt_master->tx.pkt_list)
    oss_free (p_hsl_bcm_pkt_master->tx.pkt_list, OSS_MEM_HEAP);

  return 0;
}

/*
  Initialize BCMX Tx.
*/
static int
_hsl_bcm_tx_init (void)
{
  int ret;
  int total;
  int i;
  bcm_pkt_t *pkt, *pkt_next;

  /* Set up Tx pool. */
  total = aligned_sizeof_bcm_pkt_t * HSL_BCM_PKT_TX_LIST_LENGTH;
  if ((p_hsl_bcm_pkt_master->tx.pkt_list = oss_malloc (total, OSS_MEM_HEAP)) == NULL)
    {
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_FATAL, "Failed allocating memory for packet driver Tx queue\n");     
      goto ERR;
    }

  memset (p_hsl_bcm_pkt_master->tx.pkt_list, 0, total);
  p_hsl_bcm_pkt_master->tx.total = HSL_BCM_PKT_TX_LIST_LENGTH;
  p_hsl_bcm_pkt_master->tx.count = 0;

  /* Link them into a list. */
  for (i = 0; i < HSL_BCM_PKT_TX_LIST_LENGTH; i++)
    {
      pkt      = (bcm_pkt_t *) &p_hsl_bcm_pkt_master->tx.pkt_list[i * aligned_sizeof_bcm_pkt_t];
      pkt_next = (bcm_pkt_t *) &p_hsl_bcm_pkt_master->tx.pkt_list[(i + 1) * aligned_sizeof_bcm_pkt_t];

      /* Link them. */
      pkt->next = pkt_next;
    }

  /* Last packet. */
  pkt = (bcm_pkt_t *) &p_hsl_bcm_pkt_master->tx.pkt_list[(i - 1) * aligned_sizeof_bcm_pkt_t];
  pkt->next = NULL;

  /* Set free list. */
  p_hsl_bcm_pkt_master->tx.free_pkt_list = p_hsl_bcm_pkt_master->tx.pkt_list;

  /* Initialize semaphore. */
  ret = oss_sem_new ("pkt_engine_rx_queue_sem",
		     OSS_SEM_MUTEX,
		     0,
		     NULL,
		     &p_hsl_bcm_pkt_master->tx.pkt_sem);
  if (ret < 0)
    {
      goto ERR;
    }

  return 0;

 ERR:
  _hsl_bcm_tx_deinit ();

  return -1;
}

/*
  Alloc a Tx bcm_pkt_t structure.
*/
bcm_pkt_t *
hsl_bcm_tx_pkt_alloc (int num)
{
  bcm_pkt_t *pkt;
  void *pkt_data;

  /* Currently only one pkt block supported. Ignoring num argument. */
  
  HSL_BCM_TX_SEM_LOCK(OSS_WAIT_FOREVER);

  pkt = (bcm_pkt_t *) p_hsl_bcm_pkt_master->tx.free_pkt_list;
  if (pkt)
    {
    p_hsl_bcm_pkt_master->tx.free_pkt_list = pkt->next;
    }
  else
    {
      HSL_BCM_TX_SEM_UNLOCK;
	  HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_ERROR, "hsl_bcm_tx_pkt_alloc, err1.\n");
      return NULL;
    }

  p_hsl_bcm_pkt_master->tx.count++;
  
  HSL_BCM_TX_SEM_UNLOCK;

  memset (pkt, 0, sizeof (bcm_pkt_t));
  
  if (num == 1)
    {
      /* Set data blocks. */
      pkt->pkt_data = &pkt->_pkt_data;
    }
  else
    {
      /* Allocate number of data blocks. */
      pkt_data = oss_malloc (sizeof (bcm_pkt_blk_t) * num, OSS_MEM_HEAP);
      if (! pkt_data)
        {
          hsl_bcm_tx_pkt_free (pkt);
		  HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_ERROR, "hsl_bcm_tx_pkt_alloc, err2.\n");
	  return NULL;
        }

      /* Set data blocks. */
      pkt->pkt_data = pkt_data;
    }

  pkt->blk_count = num;

  return pkt;
}

/*
  Free a Tx bcm_pkt_t structure.
*/
void
hsl_bcm_tx_pkt_free (bcm_pkt_t *pkt)
{
  if (pkt->blk_count > 1)
    {
      oss_free (pkt->pkt_data, OSS_MEM_HEAP);
    }

  /* zero out the pkt memory from the callers junk. */
  memset (pkt, 0, sizeof (bcm_pkt_t));

  HSL_BCM_TX_SEM_LOCK(OSS_WAIT_FOREVER);

  pkt->next = p_hsl_bcm_pkt_master->tx.free_pkt_list;
  p_hsl_bcm_pkt_master->tx.free_pkt_list = (u_char *) pkt;

  p_hsl_bcm_pkt_master->tx.count--;

  HSL_BCM_TX_SEM_UNLOCK;

  return;
}

/*
  Send a packet.
  pkt->pkt_data[0].data will contain the header.
*/
int
hsl_bcm_pkt_send (bcm_pkt_t *pkt, bcmx_lport_t dport, int tagged)
{
  int ret = 0;
  bcmx_lplist_t ports;
#ifdef HAVE_AUTHD
  u_char *p;
  struct hsl_eth_header *eth;
  u_int32_t mode;
#endif /* HAVE_AUTHD */
	//int i;

#ifdef HAVE_AUTHD
  p = BCM_PKT_DMAC (pkt);
  eth = (struct hsl_eth_header *) p;

  if (eth && (eth->d.vlan.type != HSL_L2_ETH_P_PAE))
    {
      if ((bcmx_auth_mode_get (dport, &mode) == BCM_E_NONE))
        {
          if (mode & BCM_AUTH_BLOCK_INOUT)
            {
              return ret;
            }
        }
     }
#endif /* HAVE_AUTHD */
     
  bcmx_lplist_init (&ports, 0, 0);

  bcmx_lplist_add (&ports, dport);
#if 0
  printk(">>>>>>>>>>1tx %d\r\n", pkt->pkt_len);
for(i = 0; i < pkt->pkt_len; i++){
        printk("%02x ", pkt->pkt_data->data[i]);
}
printk("\r\n");
#endif
  if (! tagged)
    ret = bcmx_tx_lplist (pkt, NULL, &ports, 0);
  else
    ret = bcmx_tx_lplist (pkt, &ports, NULL, 0);


  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_ERROR, "Failed sending packet\n");
    }

  bcmx_lplist_free (&ports);

  return ret;

}

/*
  Flood a packet from the vlan interface.
  pkt->pkt_data[0].data will contain the header.
*/
int
hsl_bcm_pkt_vlan_flood (bcm_pkt_t *pkt, int vid, struct hsl_if *vlanifp)
{
  int ret;
  bcmx_lplist_t tagged_ports;
  bcmx_lplist_t untagged_ports;
  struct hsl_if *ifpc = NULL;
  struct hsl_bcm_if *bcmifp = NULL;
  struct hsl_if_list *node = NULL;
  struct hsl_if_list *nodel2 = NULL;
  int tagged = -1;
  //int i;
   
  if (!vlanifp)
    return -1;
  
  if (vlanifp->u.ip.vid != vid)
    return -1;
  
  bcmx_lplist_init (&tagged_ports, 0, 0);
  bcmx_lplist_init (&untagged_ports, 0, 0);
  node = vlanifp->children_list;
  if (!node)
    return -1;
  
  for (; node; node = node->next)
    {
      ifpc = node->ifp;
      if (!ifpc)
	continue;
    
      /* Skip the port if it is DOWN and not RUNNING. */
      if (! HSL_IFP_ADMIN_UP(ifpc) || ! HSL_IFP_OPER_UP(ifpc))
	continue;
    
      bcmifp = (struct hsl_bcm_if *)ifpc->system_info;
      if (!bcmifp)
	continue;
    
      if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK)
	{
	  nodel2 = ifpc->parent_list;
	  if (!nodel2)
	    continue;
        
	  ifpc = nodel2->ifp;
	  if (!ifpc)
	    continue;
	}
      bcmifp = (struct hsl_bcm_if *)ifpc->system_info;
      if (!bcmifp)
	continue;
   
#ifdef HAVE_VLAN
      tagged = hsl_vlan_get_egress_type (ifpc, vid);
      if (tagged < 0)
	continue;
#else /* HAVE_VLAN */
      tagged = 0;
#endif /* HAVE_VLAN */
    
      if (!tagged) 
	bcmx_lplist_add (&untagged_ports, bcmifp->u.l2.lport);
      else
	bcmx_lplist_add (&tagged_ports, bcmifp->u.l2.lport);
    } 

#if 0
printk(">>>>>>>>>>tx %d\r\n", pkt->pkt_len);
for(i = 0; i < pkt->pkt_len; i++){
        printk("%02x ", pkt->pkt_data->data[i]);
}
printk("\r\n");
  
#endif

  ret = bcmx_tx_lplist (pkt, &tagged_ports, &untagged_ports, 0);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_ERROR, "Failed sending packet\n");
    }

  bcmx_lplist_free (&tagged_ports);
  bcmx_lplist_free (&untagged_ports);
  return 0;
}
  
#ifdef HAVE_L3
/*
  Handling based on rx reason.
*/
int
hsl_bcm_pkt_reason_handling (struct hsl_if *ifp, struct hsl_if *l2_ifp,
                             bcm_pkt_t *pkt)
{
  u_int32_t reason;
  u_char *p;
  struct hsl_eth_header *eth;
  struct hsl_arp *arp;
  int ret;
  u_int16_t pkt_type;
  u_int8_t len = 0;
#ifdef HAVE_IPV6
  int ipv6_pkt_type = 0;
#endif /* HAVE_IPV6 */

  HSL_FN_ENTER ();

  p = BCM_PKT_DMAC (pkt);
  eth = (struct hsl_eth_header *) p;

  pkt_type = (eth->d.type == HSL_ENET_8021Q_VLAN) ? eth->d.vlan.type : eth->d.type;

  len = (eth->d.type == HSL_ENET_8021Q_VLAN) ?  ENET_TAGGED_HDR_LEN: ENET_UNTAGGED_HDR_LEN;

  reason = pkt->rx_reason;

  if(reason)
  	HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_INFO, "rx_reason = %x, resons=%x\r\n", reason, pkt->rx_reasons);
  
  /*
   * The following may occur only on Strata XGS devices, and happen to
   * match the hardware values for the CPU opcode in the DCB.
   */

  /* L3 SIP Miss OR L3 station movement. */
  /* Check for ARP packets. */
  if (pkt_type == HSL_ETHER_TYPE_ARP)
    {
      arp = (struct hsl_arp *) (p + len);
      
      /* Add the NH. */
      ret = hsl_fib_handle_arp (ifp, eth, arp);
      if (ret == HSL_FIB_ERR_INVALID_ARP_SRC)
        HSL_FN_EXIT (ret);

    } else {
    	if (reason & 0x100)
	    {
	      /* L3 DIP Miss */
	      /* Handle the exception packet. */
	      if ((pkt_type == HSL_ETHER_TYPE_IP)
#ifdef HAVE_IPV6
		  || ((pkt_type == HSL_ETHER_TYPE_IPV6) && (ipv6_pkt_type != IPV6_ND_NEIGHBOR_ADVERT))
#endif /* HAVE_IPV6 */
		  )
		hsl_fib_handle_exception (ifp->fib_id, p + len, pkt_type);
	    }
    }
#ifdef HAVE_MCAST_IPV4
  if (pkt_type == HSL_ETHER_TYPE_IP)
    {
      hsl_mc_v4_fib_register_iif_l2_port (p + len, ifp, l2_ifp);
    }
#endif /* HAVE_MCAST_IPV4 */
#ifdef HAVE_IPV6
  if(HSL_ETHER_TYPE_IPV6 == pkt_type) 
    {
#ifdef HAVE_MCAST_IPV6
      hsl_mc_v6_fib_register_iif_l2_port (p + len, ifp, l2_ifp);
#endif /* HAVE_MCAST_IPV6 */

      ret = hsl_fib_handle_neigbor_discovery (ifp, p + len, &ipv6_pkt_type);
      if (ret == HSL_FIB_ERR_INVALID_ND_SRC)
        HSL_FN_EXIT (ret);
    }
#endif /* HAVE_IPV6 */

  /* Post message to the TCP/IP stack through the driver. */
  ret = hsl_eth_drv_post_l3_pkt (ifp, pkt);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_INFO, "Error posting packet to the TCP/IP stack\n");
      HSL_FN_EXIT (-1);
    }

  HSL_FN_EXIT (0);
}

/*
  Top level handler for L3 packets.
*/
int
hsl_bcm_rx_handle_l3 (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct hsl_eth_header *eth = NULL;
  u_char *p = NULL;
  hsl_vid_t vid;
  struct hsl_if *ifpl3 = NULL;

  HSL_FN_ENTER ();
  
  p = BCM_PKT_DMAC (pkt);
  eth = (struct hsl_eth_header *) p;

  if (eth->d.type == HSL_ENET_8021Q_VLAN)
    {
      vid = HSL_ETH_VLAN_GET_VID (eth->d.vlan.pri_cif_vid);
    }
  else
    vid = HSL_DEFAULT_VID;

  /* Get matching L3 port. */
  ifpl3 = hsl_ifmgr_get_matching_L3_port (ifp, vid);
  if (! ifpl3)
    {
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_INFO, "L3 interface not found\n");

      HSL_FN_EXIT (-1);
    }
  
  /* If interface is up only then process the packets. */
  if (HSL_IFP_ADMIN_UP (ifpl3) && HSL_IFP_OPER_UP (ifpl3))
    {
      /* 
	 Hardware BCM specific handling for pkt based on rx_reason.
      */
      hsl_bcm_pkt_reason_handling (ifpl3, ifp, pkt);

    }
  else
    {
      /* Interface is down. */
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_INFO, "L3 interface down, dropping...\n");
    }
  
  HSL_IFMGR_IF_REF_DEC (ifpl3);
  
  return 0;
}
#endif /* HAVE_L3 */

#ifdef HAVE_L2LERN

int
hsl_bcm_rx_l2lern (struct hsl_if *ifp, bcm_pkt_t *pkt)
{
  struct hsl_if *p_ifp;
  struct hsl_eth_header *eth;
  struct hsl_bcm_if *bcmifp, *p_bcmifp; 
  struct hsl_bridge_port *bridge_port;
  u_int32_t recv_untagged;
  bcmx_l2_addr_t l2addr;
  bcmx_lport_t lport;
  hsl_vid_t pvid;
  hsl_vid_t vid;
  u_char *p;
  s_int32_t ret;
  struct hsl_if_list *node = NULL;
  int is_trunk = 0;

  HSL_FN_ENTER ();

  if (!ifp)
    {
       HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_INFO, " ifp is null \n");
       return 0;
    }

  bcmifp = ifp->system_info;

  if (!bcmifp)
    {
       HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_INFO, " bcmifp is null \n");
       return 0;
    }

  lport = bcmifp->u.l2.lport;

  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_INFO, " Recvd lport = %d \n", lport);

  p = BCM_PKT_DMAC (pkt);
  eth = (struct hsl_eth_header *) p;
  recv_untagged = pkt->rx_untagged;

  /* Source address is multicast */
  if (eth->smac[0] & 1)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, " source mac is multicast, discarding \n");
      HSL_FN_EXIT (-1);
    }

  pvid = hsl_get_pvid (ifp);

  vid = HSL_ETH_VLAN_GET_VID (eth->d.vlan.pri_cif_vid);

  bridge_port = ifp->u.l2_ethernet.port;

  /* Pure L3  mapped ports do not have a bridge port */
  if ((! bridge_port) || 
      (bridge_port && 
       ((bridge_port->stp_port_state == HAL_BR_PORT_STATE_LEARNING) ||
     (bridge_port->stp_port_state == HAL_BR_PORT_STATE_FORWARDING))))
    {
      /* Learn the src mac on the port for vlan */
      if ((vid == HSL_VLAN_DEFAULT_VID) && (pvid ==0))
        {
          HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_INFO, " Not vlan aware \n");
          bcmx_l2_addr_init (&l2addr, eth->smac, pvid);
        }
      else
        {
          bcmx_l2_addr_init (&l2addr, eth->smac, vid);
        }

      /* Determine if port is a part of trunk */
      do
        {
          /* Its a aggregate, should have only one parent. */
          node = ifp->parent_list;	  
          if (! node)
            break;

          p_ifp = node->ifp;
          if (! p_ifp)
            break;

          p_bcmifp = p_ifp->system_info;
          if (!p_bcmifp)
            break;

          if (p_bcmifp->type == HSL_BCM_IF_TYPE_TRUNK)
            {
              is_trunk = 1;
              l2addr.tgid = p_bcmifp->trunk_id;
              l2addr.flags |= BCM_L2_TRUNK_MEMBER;
            }
        }
      while (0);

      if (!is_trunk)
        l2addr.lport = lport;

      ret = bcmx_l2_addr_add (&l2addr, NULL);
      if (ret < 0)
        {
          HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, " Can't add learnt fdb entry \n");
          HSL_FN_EXIT (-1);
        }
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_INFO, "MAC added successfully \n");
    }
  else
    {
       HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_ERROR," Port state is not in learning \n");
       HSL_FN_EXIT (-1);
    }

  HSL_FN_EXIT (0);
}
#endif /* HAVE_L2LERN */

/*
  Main packet/frame demux function.
  Please note the packet will be sent with the CRC. The CRC length must be substracted from the total
  length of the packet. 
*/
void
hsl_bcm_pkt_process (bcm_pkt_t *pkt)
{
  struct hsl_eth_header *eth = NULL;
  u_char *p = NULL;
  struct hsl_if *ifp, *ifp2;
#ifdef HAVE_IGMP_SNOOP
  struct hsl_ip *ip = NULL;
#endif /* HAVE_IGMP_SNOOP */

#ifdef HAVE_MLD_SNOOP
  struct hsl_ip6_hdr *ipv6_hdr = NULL;
#endif /* HAVE_MLD_SNOOP */

#ifdef HAVE_AUTHD
  u_int32_t mode;
#ifdef HAVE_MAC_AUTH
  s_int32_t ret;
  u_int32_t auth_mode;
#endif
#endif /* HAVE_AUTHD */
  bcmx_lport_t lport;

#if 0
	int i;

	for(i = 0;i < 64; i++)
	{
		printk("%02X ", (unsigned char)pkt->pkt_data->data[i]);

		if((i+1) % 16 == 0)
			printk("\n");
	}
#endif

  HSL_FN_ENTER ();

  ifp = NULL;
  ifp2 = NULL;

  p = BCM_PKT_DMAC (pkt);
  eth = (struct hsl_eth_header *) p;

	{
		int i;
		char buf[64] = {0};

		for (i = 0; i < 20; i++){
			sprintf(buf + 3*i, "%02x,", p[i]);
		}
		HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_INFO, "%s\n", buf);
	}

  lport = bcmx_unit_port_to_lport (pkt->rx_unit, pkt->rx_port); /* WORKS */
  if (lport < 0)
    goto FREE;

  /* Get interface map. */
  ifp = hsl_bcm_ifmap_if_get (lport);
  if (! ifp)
    goto FREE;

#ifdef HAVE_L2
#ifdef HAVE_AUTHD
#ifdef HAVE_MAC_AUTH
  ret = bcmx_auth_mode_get (lport, &auth_mode);
  if (auth_mode & BCM_AUTH_MODE_UNAUTH)
    {
      ret = bcmx_auth_mode_set (lport, BCM_AUTH_MODE_AUTH);
      if (ret != BCM_E_NONE)
        {
          HSL_LOG (HSL_LOG_IFMGR, HSL_LEVEL_ERROR,
                   "Failed to set port mode to authorozed after recv unknown"
                   "src %d, bcm error = %d %d\n", ifp->ifindex, ret);
          HSL_IFMGR_IF_REF_DEC (ifp);
          goto FREE;
        }
      hsl_bcm_rx_handle_auth_mac (ifp, pkt);
      goto FREE;
    }
#endif
  /* EAPOL. */
  if (! memcmp (eth->dmac, eapol_addr, 6))
    {
      if (HSL_IF_PKT_CHECK_EAPOL (ifp))
        hsl_bcm_rx_handle_eapol (ifp, pkt);
      goto FREE;
    }

  /* If interface is unauthorized do not process pkt */
  if (bcmx_auth_mode_get (lport, &mode)== BCM_E_NONE)
    {
      if (mode & BCM_AUTH_MODE_UNAUTH)
        {
          /* Discard the packet */
          goto FREE;
        }
    }
#endif /* HAVE_AUTHD */
#endif /* HAVE_L2 */

#ifdef HAVE_L2LERN
  hsl_bcm_rx_l2lern (ifp, pkt);
#endif /* HAVE_L2LERN */

#ifdef HAVE_L2
#if defined (HAVE_STPD) || defined (HAVE_RSTPD) || defined (HAVE_MSTPD)
  /* BPDUs. */
  if (! memcmp (eth->dmac, bpdu_addr, 6))
    {
      if (HSL_IF_PKT_CHECK_BPDU (ifp))
        {
          ifp2 = hsl_ifmgr_get_L2_parent (ifp);
          if (ifp2)
	    hsl_bcm_rx_handle_bpdu (ifp2, pkt);
        }
      goto FREE;
    }
#endif /* defined (HAVE_STPD) || defined (HAVE_RSTPD) || defined (HAVE_MSTPD) */

#ifdef HAVE_GVRP
  /* GVRP. */
  if (! memcmp (eth->dmac, gvrp_addr, 6))
    {
      if (HSL_IF_PKT_CHECK_GVRP (ifp))
        {
          ifp2 = hsl_ifmgr_get_L2_parent (ifp);
          if (ifp2)
	    hsl_bcm_rx_handle_gvrp (ifp2, pkt);
        }
      goto FREE;
    }
#endif /* HAVE_GVRP */

#ifdef HAVE_GMRP
  /* GMRP. */
  if (! memcmp (eth->dmac, gmrp_addr, 6))
    {
      if (HSL_IF_PKT_CHECK_GMRP (ifp))
        {
          ifp2 = hsl_ifmgr_get_L2_parent (ifp);
          if (ifp2)
	    hsl_bcm_rx_handle_gmrp (ifp2, pkt);
        }
      goto FREE;
    }
#endif /* HAVE_GMRP */

#ifdef HAVE_LACPD
  /* LACP. */
  if (! memcmp (eth->dmac, lacp_addr, 6))
    {
      if (HSL_IF_PKT_CHECK_LACP (ifp)) {
	  	if(((eth->d.type == HSL_ENET_8021Q_VLAN)&& eth->d.vlan.type == HSL_ETHER_TYPE_LACP)
			||(eth->d.type == HSL_ETHER_TYPE_LACP) ) {
			hsl_bcm_rx_handle_lacp (ifp, pkt);
	  	}
      }
      goto FREE;
    }
#endif /* HAVE_LACPD */
#endif /* HAVE_L2 */

#ifdef HAVE_IGMP_SNOOP
  if ((eth->d.type == HSL_ENET_8021Q_VLAN) && (eth->d.vlan.type == HSL_ETHER_TYPE_IP))
    {
      ip = (struct hsl_ip *) (p + ENET_TAGGED_HDR_LEN);
    }
  else if (eth->d.type == HSL_ETHER_TYPE_IP)
    {
      ip = (struct hsl_ip *) (p + ENET_UNTAGGED_HDR_LEN);
    }
  if (ip && ip->ip_p == HSL_PROTO_IGMP)
    {
      if (HSL_IF_PKT_CHECK_IGMP_SNOOP (ifp))
        {
          ifp2 = hsl_ifmgr_get_L2_parent (ifp);
          if (ifp2)
	    hsl_bcm_rx_handle_igs (ifp2, pkt);
        }

      /* Please note there is no goto FREE here as we want to pass this IGMP packet
	 to the stack if L3 is enabled otherwise it is going to free the packet
	 anyways. */
    }
#endif /* HAVE_IGMP_SNOOP. */

#ifdef HAVE_MLD_SNOOP
  if ((eth->d.type == HSL_ENET_8021Q_VLAN) && (eth->d.vlan.type == HSL_ETHER_TYPE_IPV6))
    {
      ipv6_hdr = (struct hsl_ip6_hdr *) (p + ENET_TAGGED_HDR_LEN);
    }
  else if (eth->d.type == HSL_ETHER_TYPE_IPV6)
    {
      ipv6_hdr = (struct hsl_ip6_hdr *) (p + ENET_UNTAGGED_HDR_LEN);
    }
  if (ipv6_hdr && IPV6_IS_ADDR_MULTICAST (&ipv6_hdr->ip_dst))
    {
      if (HSL_IF_PKT_CHECK_MLD_SNOOP (ifp))
        {
          ifp2 = hsl_ifmgr_get_L2_parent (ifp);
          if (ifp2)
            hsl_bcm_rx_handle_mlds (ifp2, pkt);
        }

      /* Please note there is no goto FREE here as we want to pass this IGMP packet
         to the stack if L3 is enabled otherwise it is going to free the packet
         anyways. */
    }
#endif /* HAVE_MLD_SNOOP. */

#ifdef HAVE_L3
  if (eth->d.type == HSL_ENET_8021Q_VLAN)
    {
      if ((eth->d.vlan.type == HSL_ETHER_TYPE_IP && HSL_IF_PKT_CHECK_IP(ifp))
#ifdef HAVE_IPV6
	  || (eth->d.vlan.type == HSL_ETHER_TYPE_IPV6 && HSL_IF_PKT_CHECK_IP(ifp))
#endif /* HAVE_IPV6 */
	  || (eth->d.vlan.type == HSL_ETHER_TYPE_ARP && HSL_IF_PKT_CHECK_ARP(ifp))
	  || (eth->d.vlan.type == HSL_ETHER_TYPE_RARP && HSL_IF_PKT_CHECK_RARP(ifp)))
	hsl_bcm_rx_handle_l3 (ifp, pkt);
    }
  else if (eth->d.type == HSL_ETHER_TYPE_IP && HSL_IF_PKT_CHECK_IP(ifp))
    hsl_bcm_rx_handle_l3 (ifp, pkt);
  else if (eth->d.type == HSL_ETHER_TYPE_ARP && HSL_IF_PKT_CHECK_ARP(ifp))
    hsl_bcm_rx_handle_l3 (ifp, pkt);
  else if (eth->d.type == HSL_ETHER_TYPE_RARP && HSL_IF_PKT_CHECK_RARP(ifp))
    hsl_bcm_rx_handle_l3 (ifp, pkt);
#ifdef HAVE_IPV6
  else if (eth->d.type == HSL_ETHER_TYPE_IPV6 && HSL_IF_PKT_CHECK_IP(ifp))
    hsl_bcm_rx_handle_l3 (ifp, pkt);
#endif /* HAVE_IPV6 */
  else
    {
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_INFO, "Unknown packet type\n");
    }
#endif /* HAVE_L3 */

 FREE:

  /* Free the Rx memory. */
  bcm_rx_free (pkt->rx_unit, pkt->pkt_data[0].data);

  HSL_FN_EXIT();
}

/*
  Packet dispatcher thread.
*/
static void
_hsl_bcm_rx_handler_thread (void *param)
{
  bcm_pkt_t *pkt;
  int spl;

  while (! p_hsl_bcm_pkt_master->rx.thread_exit)
    {
      /* Service packets. */
      while (1)
	{


	oss_sem_lock (OSS_SEM_BINARY, p_hsl_bcm_pkt_master->rx.pkt_mutex, OSS_WAIT_FOREVER);

	if(HSL_BCM_PKT_RX_QUEUE_EMPTY){
		oss_sem_unlock (OSS_SEM_BINARY, p_hsl_bcm_pkt_master->rx.pkt_mutex);
		break;
	}
          /* Set interrupt level to high. */
 //         spl = sal_splhi ();

	  /* Get head packet. */
	  pkt = (bcm_pkt_t *)&p_hsl_bcm_pkt_master->rx.pkt_queue[p_hsl_bcm_pkt_master->rx.head * aligned_sizeof_bcm_pkt_t];

	  /* Increment head. */
	  p_hsl_bcm_pkt_master->rx.head = HSL_BCM_PKT_RX_QUEUE_NEXT (p_hsl_bcm_pkt_master->rx.head);

	  /* Decrement count. */
//	  p_hsl_bcm_pkt_master->rx.count--;

          /* Unlock interrupt level. */
//          sal_spl (spl);

	  /* Main demux routine for the packets coming to the CPU. */
	  hsl_bcm_pkt_process (pkt);

		smp_mb();
	  /* Decrement count. */
	  p_hsl_bcm_pkt_master->rx.count--;
	   smp_mb();

	   oss_sem_unlock (OSS_SEM_BINARY, p_hsl_bcm_pkt_master->rx.pkt_mutex);
	}

      oss_sem_lock (OSS_SEM_BINARY, p_hsl_bcm_pkt_master->rx.pkt_sem, OSS_WAIT_FOREVER);

    }

  /* Exit packet thread. */
  oss_sem_delete (OSS_SEM_BINARY, p_hsl_bcm_pkt_master->rx.pkt_sem);
}

/*
  Callback from BCM Rx. */
bcm_rx_t
hsl_bcm_rx_cb (int unit, bcm_pkt_t *pkt, void *cookie)
{
  bcm_pkt_t *entry;

  oss_sem_lock (OSS_SEM_BINARY, p_hsl_bcm_pkt_master->rx.pkt_mutex, OSS_WAIT_FOREVER);

  /* Queue the packet. */
  if (HSL_BCM_PKT_RX_QUEUE_FULL)
    {
      /* Queue is full. */
      p_hsl_bcm_pkt_master->rx.drop++;

	  oss_sem_unlock (OSS_SEM_BINARY, p_hsl_bcm_pkt_master->rx.pkt_mutex);

      return BCM_RX_NOT_HANDLED;
    }
  else
    {
 
      /* Get entry. */
      entry = (bcm_pkt_t *)&p_hsl_bcm_pkt_master->rx.pkt_queue[p_hsl_bcm_pkt_master->rx.tail * aligned_sizeof_bcm_pkt_t];

      /* Copy the header contents. */
      memcpy (entry, pkt, sizeof (bcm_pkt_t));

      /* Fix internal packet pointer. */
      entry->pkt_data = &entry->_pkt_data;
      entry->pkt_data[0].data = pkt->pkt_data[0].data;
      entry->pkt_data[0].len = pkt->pkt_data[0].len;

      /* Increment count. */
	  smp_mb();
      p_hsl_bcm_pkt_master->rx.count++;
	  smp_mb();

      /* Adjust tail. */
      p_hsl_bcm_pkt_master->rx.tail = HSL_BCM_PKT_RX_QUEUE_NEXT (p_hsl_bcm_pkt_master->rx.tail);

	  oss_sem_unlock (OSS_SEM_BINARY, p_hsl_bcm_pkt_master->rx.pkt_mutex);

      /* Give semaphore. */
      oss_sem_unlock (OSS_SEM_BINARY, p_hsl_bcm_pkt_master->rx.pkt_sem);
	  

      return BCM_RX_HANDLED_OWNED;
    }

  oss_sem_unlock (OSS_SEM_BINARY, p_hsl_bcm_pkt_master->rx.pkt_mutex);
  
  return BCM_RX_NOT_HANDLED;
}

/*
  Initialize packet driver.
*/
int
hsl_bcm_pkt_init ()
{
  int ret;

  HSL_FN_ENTER ();
  /* Set the aligned size of struct bcm_pkt_t so that we don;t calculate everytime. */
  aligned_sizeof_bcm_pkt_t = (sizeof (bcm_pkt_t) + ALIGN_TO - 1) & (-ALIGN_TO);

  /* Initialize master. */
  _hsl_bcm_pkt_master_init ();

  /* Initialize Rx. */
  ret = _hsl_bcm_rx_init ();
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Error initializing CPU Rx interface\n");
      goto ERR;
    }

  /* Initialize Tx. */
  ret = _hsl_bcm_tx_init ();
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Error initializing CPU Tx interface\n");
      goto ERR;
    }

  HSL_FN_EXIT (0);

 ERR:
  hsl_bcm_pkt_deinit ();
  HSL_FN_EXIT (-1);
}

/*
  Deinitialize packet driver.
*/
int
hsl_bcm_pkt_deinit ()
{
  int ret;

  HSL_FN_ENTER ();

  /* Deinitialize Rx. */
  ret = _hsl_bcm_rx_deinit ();
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Error denitializing CPU Rx interface\n");
    }

  /* Deinitialize Tx. */
  ret = _hsl_bcm_tx_deinit ();
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Error deinitializing CPU Tx interface\n");
    }

  /* Deinitialize master. */
  _hsl_bcm_pkt_master_deinit ();

  HSL_FN_EXIT (0);
}

/* 
   Dump.
*/
void
hsl_bcm_pkt_dump (void)
{
  HSL_LOG (HSL_LOG_PLATFORM, HSL_LEVEL_INFO, "Rx Total %d Drop %d Count %d\n",
           p_hsl_bcm_pkt_master->rx.total, p_hsl_bcm_pkt_master->rx.drop,
           p_hsl_bcm_pkt_master->rx.count);
}


