/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"

/* 
   Broadcom includes. 
*/
//#include "bcm_incl.h"

/*
	CTC includes
*/
#include "ctc_api.h"
#include "sal.h"

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
#include "hsl_oss.h"
#include "hsl_ifmgr.h"
#include "hsl_if_os.h"
#include "hsl_ifmgr.h"
#include "hsl_logger.h"
#include "hsl_ether.h"

/* 
   Broadcom L3 interface driver. 
*/
#include "hsl_eth_drv.h"
#include "hsl_ctc_pkt.h"
#include "hsl_ctc_if.h"
#include "hsl_ctc_ifmap.h"

#ifdef HAVE_L2
#include "hsl_vlan.h"
#endif /* HAVE_L2 */

#define ALLOC_FLAGS (in_interrupt () ? GFP_ATOMIC : GFP_KERNEL)

#define HSL_ETH_DRV_TX_THREAD
#ifdef HSL_ETH_DRV_TX_THREAD
/* Tx thread. */

//by chentao change
//static struct sal_thread_s *hsl_eth_drv_tx_thread = NULL;
static sal_task_t *hsl_eth_drv_tx_thread = NULL;

static struct sk_buff_head hsl_eth_tx_queue;
static ipi_sem_id hsl_eth_tx_sem = NULL;
static volatile int hsl_eth_tx_thread_running;

/* Forward declarations. */
static void _hsl_eth_tx_handler (void *notused);

static struct net_device_stats *bcm_stats;

#endif /* HSL_ETH_DRV_TX_THREAD */

/* Initiailization. */
int
hsl_eth_drv_init (void)
{
  int ret = 0;

  HSL_FN_ENTER();

#ifdef HSL_ETH_DRV_TX_THREAD
  ret = oss_sem_new ("Eth Tx sem",
                     OSS_SEM_BINARY,
                     0,
                     NULL,
                     &hsl_eth_tx_sem);
  if (ret < 0)
    {
      HSL_LOG (HSL_LOG_DEVDRV, HSL_LEVEL_ERROR, "Cannot create ethernet driver Tx synchronization semaphore\n");
      goto ERR;
    }

  hsl_eth_tx_thread_running = 1;
  skb_queue_head_init (&hsl_eth_tx_queue);
 
  /* Create thread for processing Tx. */
  //by chentao change
  /*******************start****************/
  #if 0
  hsl_eth_drv_tx_thread = sal_thread_create ("zEthTx",
                                             SAL_THREAD_STKSZ,
                                             200,
                                             _hsl_eth_tx_handler,
                                             0);
    
  if (hsl_eth_drv_tx_thread == SAL_THREAD_ERROR)
    {
      HSL_LOG (HSL_LOG_DEVDRV, HSL_LEVEL_ERROR, "Cannot create Tx thread\n");
      goto ERR;
    }
   #else
   ret = sal_task_create (&hsl_eth_drv_tx_thread, 
  							  "zEthTx",
  							  SAL_DEF_TASK_STACK_SIZE,
  							  200,
  							  _hsl_eth_tx_handler,
  							  NULL);
  #endif
  /***********************end***************************/
  
#else
  if (ret < 0) /* to avoid compile warnings. */
    goto ERR;

#endif /* HSL_ETH_DRV_TX_THREAD */

	bcm_stats = kmalloc(sizeof(struct net_device_stats), GFP_KERNEL);

	if(!bcm_stats)
	{
		HSL_LOG (HSL_LOG_DEVDRV, HSL_LEVEL_ERROR, "Cannot allocate memory for net_device_stats.\n");                         
   		/* goto ERR; */ 
	}
    memset(bcm_stats, 0, sizeof(struct net_device_stats));

  HSL_FN_EXIT (0);

ERR:
  hsl_eth_drv_deinit ();
  HSL_FN_EXIT (-1);
}

/* Deinitialization. */
int
hsl_eth_drv_deinit (void)
{
#ifdef HSL_ETH_DRV_TX_THREAD
  struct sk_buff *skb;


	if(bcm_stats)
	{
		kfree(bcm_stats);
		bcm_stats = NULL;
	}

  /* Cancel Tx thread. */
  if (hsl_eth_drv_tx_thread)
    {
    /**************by chentao change********************/
	#if 0
      sal_thread_destroy (hsl_eth_drv_tx_thread);
	#else
	  sal_task_destroy(hsl_eth_drv_tx_thread);
	#endif
      hsl_eth_drv_tx_thread = NULL;
    }

  /* Cancel Tx semaphore. */
  if (hsl_eth_tx_sem)
    {
      oss_sem_delete (OSS_SEM_BINARY, hsl_eth_tx_sem);
      hsl_eth_tx_sem = NULL;
    }

  hsl_eth_tx_thread_running = 0;
  while ((skb = skb_dequeue (&hsl_eth_tx_queue)) != NULL)
    kfree_skb (skb);
#endif /* HSL_ETH_DRV_TX_THREAD */
  printk("%s ...ok\n", __func__);

  return 0;
}



/* Callback for deferred xmit. */
#if 0

static void
_hsl_eth_xmit_done (int ignored, bcm_pkt_t *pkt, void *cookie)
{
//by chentao delete

	if (pkt)
    {
#if 0 /** Modified by alfred, 2007-02-03 **/
		/* Free buffer. */
		kfree ((u_char *)pkt->cookie2);
#else
		/* Free allocated DMA Area  **/
		soc_cm_sfree(0, (u_char *)pkt->cookie2);
#endif

		/* Free pkt. */
		hsl_bcm_tx_pkt_free (pkt);
    }

return;
}
#endif

/* Tx routine for pure L3 ports. */
static int
_hsl_eth_drv_l3_tx (struct hsl_if *ifp, struct sk_buff *skb)
{
	int len = 0;
	uint8 *buf = NULL;
	uint8 *pkt = NULL;
	struct hsl_if *ifpc = NULL;
	struct hsl_bcm_if *sifp = NULL;
	int ret = 0, offset = 0;
    
    if (skb->len > HSL_ETH_PKT_SIZE) {
        return -1;
    }

	buf  = kmalloc (HSL_ETH_PKT_SIZE, GFP_KERNEL);
	if (!buf) {
		goto ERR;
	}
    
	#if 0
	memcpy (buf + ENET_TAG_SIZE, skb->data, length);
	len = (skb->len - ENET_UNTAGGED_HDR_LEN) + ENET_TAGGED_HDR_LEN;
	
	offset = ENET_TAG_SIZE;
	CTC_PKT_HDR_DMAC_SET (buf, skb->data + offset);
	offset += 6;
	CTC_PKT_HDR_SMAC_SET (buf, skb->data + offset);
	CTC_PKT_HDR_TPID_SET (buf, 0x8100);
	CTC_PKT_HDR_VTAG_CONTROL_SET (buf, VLAN_CTRL (0, 0, 1));
    #else
    memcpy (buf, skb->data, skb->len);
    len = skb->len;
    #endif
	
	ifpc = hsl_ifmgr_get_first_L2_port (ifp);
	if (!ifp) {
		goto ERR;
	}
	
	sifp = ifpc->system_info;
	if (!sifp) {
		HSL_IFMGR_IF_REF_DEC (ifpc);
		goto ERR;
	}
	HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_DEBUG, "_hsl_eth_drv_l3_tx\n");
    printk("_hsl_eth_drv_l3_tx\n");
	
	  /* Send packet. */
	//ret = hsl_ctc_pkt_send (buf, len, sifp->u.l2.lport, 1, TRUE);
	//ret = hsl_ctc_pkt_send (buf, len, sifp->u.l2.lport, 1, FALSE);
	if (ret < 0) {
      HSL_LOG (HSL_LOG_DEVDRV, HSL_LEVEL_ERROR, "Failure sending packet\n");
	  HSL_IFMGR_IF_REF_DEC (ifpc);
      goto ERR;
    }
	HSL_IFMGR_IF_REF_DEC (ifpc);
ERR:
	
	if (buf) {
		kfree (buf);
		buf = NULL;
	}
	return 0;    
}

/* Tx routine for SVI ports. */
static int
_hsl_eth_drv_svi_tx (struct hsl_if *ifp, struct sk_buff *skb)
{
    int ret = 0;
    int len;
    u_char *buf = NULL;
    struct hsl_if *ifpc = NULL;
    struct hsl_if_list *nodel2;
    struct hsl_bcm_if *bcmifp = NULL;
    struct hsl_eth_header *eth;
    int tagged = -1;
    bool is_drop_tag = FALSE;
    ctc_l2_fdb_query_t  fdb_que;
    ctc_l2_fdb_query_rst_t fdb_que_rst;
    ctc_l2_addr_t querybuf[10];
    int brid, vid;
    int offset = 0;

    
    if (skb->len > HSL_ETH_PKT_SIZE) {
        return -1;
    }
    
    memset (&fdb_que, 0, sizeof(ctc_l2_fdb_query_t));
    memset (&fdb_que_rst, 0, sizeof(ctc_l2_fdb_query_rst_t));
    fdb_que_rst.buffer_len = sizeof(querybuf);
    fdb_que_rst.buffer = querybuf;
    memset (fdb_que_rst.buffer, 0, fdb_que_rst.buffer_len);
    
    buf = kmalloc (HSL_ETH_PKT_SIZE, GFP_ATOMIC);
    if (! buf) {
      HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_ERROR, "soc_cm_salloc, err.\n");
      goto ERR;
    }
    #if 0
    /* Copy entire packet. */      
    memcpy (buf + ENET_TAG_SIZE, skb->data, skb->len);
    
    /* Correct length. */
    len = (skb->len - ENET_UNTAGGED_HDR_LEN) + ENET_TAGGED_HDR_LEN;
    
    /* Get vid. */
    sscanf (ifp->name, "vlan%d.%d", &brid, &vid);
    
    /* Fill header. */
    offset = 0;
    
    CTC_PKT_HDR_DMAC_SET (buf, skb->data + offset);   
    offset += 6;
    CTC_PKT_HDR_SMAC_SET (buf, skb->data + offset);
    CTC_PKT_HDR_TPID_SET (buf, 0x8100);
    CTC_PKT_HDR_VTAG_CONTROL_SET (buf, VLAN_CTRL (0, 0, vid));
    #else
    memcpy (buf, skb->data, skb->len);
    len = skb->len;

        /* Get vid. */
    sscanf (ifp->name, "vlan%d.%d", &brid, &vid);
        
    #endif

    if ((buf[0] & 0x1) == 0 ) {    //unicast
        fdb_que.query_type = CTC_L2_FDB_ENTRY_OP_BY_MAC_VLAN;
        fdb_que.query_flag = CTC_L2_FDB_ENTRY_ALL;
        memcpy (fdb_que.mac, buf, 6);
        fdb_que.fid = vid;
        //printk ("[%s,%d], mac[5]:%02x, vid=%d\n", __func__, __LINE__, buf[5], vid);
        ret = ctc_l2_get_fdb_entry(&fdb_que, &fdb_que_rst);
        if (ret == CTC_E_NONE && fdb_que.count > 0) {
            ifpc = hsl_bcm_ifmap_if_get (fdb_que_rst.buffer[0].gport);
            if (ifpc) {
                bcmifp = (struct hsl_bcm_if *)ifpc->system_info;
                if (!bcmifp) {
                    printk ("error [%s,%d]\n", __func__, __LINE__);
                    goto ERR;
                }
                
                if (bcmifp->type == HSL_BCM_IF_TYPE_TRUNK) {
                    nodel2 = ifpc->children_list;
                    if (!nodel2) {
                        printk ("error [%s,%d]\n", __func__, __LINE__);
                        goto ERR;
                    }
                    
                    ifpc = nodel2->ifp;
                    if (!ifpc) {
                        printk ("error [%s,%d]\n", __func__, __LINE__);
                        goto ERR;
                    }
                }
                bcmifp = (struct hsl_bcm_if *)ifpc->system_info;
                if (!bcmifp) {
                    printk ("error [%s,%d]\n", __func__, __LINE__);
                    goto ERR;
                }

#ifdef HAVE_L2
                tagged = hsl_vlan_get_egress_type (ifpc, vid);
                if (is_drop_tag < 0) {
                    printk ("error [%s,%d]\n", __func__, __LINE__);
                    goto ERR;
                }
#else /* HAVE_L2 */
                tagged  = 0;
#endif /* HAVE_L2 */
                #if 0
                if (tagged) {
                    is_drop_tag = FALSE;
                } else {
                    is_drop_tag = TRUE;
                }
                #endif
                
                HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_DEBUG, "_hsl_eth_drv_svi_tx\n");
                //hsl_bcm_pkt_send (pkt, bcmifp->u.l2.lport, tagged);
                //hsl_ctc_pkt_send (buf,len,  bcmifp->u.l2.lport, vid, tagged);
            }
        } else {
            //hsl_ctc_pkt_vlan_flood(buf, len, vid, ifp);
        }
    } else {
        /*Broadcast, multicast flooded.*/
        HSL_LOG (HSL_LOG_PKTDRV, HSL_LEVEL_DEBUG, "_hsl_eth_drv_svi_tx flood\n");
        //hsl_bcm_pkt_vlan_flood (pkt, vid, ifp);
        //hsl_ctc_pkt_vlan_flood(buf, len, vid, ifp);
    }   
    
ERR:
    if (buf) {
        kfree (buf);
        buf = NULL;
    }
    
    return 0;

} 

/* Tx a skb out on a interface. */
static int
_hsl_eth_drv_tx (struct sk_buff *skb)
{

  struct net_device * dev;
  struct hsl_if *ifp;

  HSL_LOG (HSL_LOG_PKTDRV, HSL_LOG_PKTDRV, "_hsl_eth_drv_tx\n");

  if (!skb) {
    return -1;
  }
  
  dev = skb->dev;
  if (! dev) {
    printk ("[%s,%d]\n", __func__, __LINE__);
	kfree_skb (skb);
    return -1;
  }

  ifp = dev->ml_priv;
  if (! ifp) {
    printk ("[%s,%d]\n", __func__, __LINE__);
	kfree_skb (skb);
    return -EINVAL;
  }

  /* Check for a SVI or pure L3 port transmit. */
  if (memcmp (ifp->name, "vlan", 4) == 0)
    _hsl_eth_drv_svi_tx (ifp, skb);
  else
    _hsl_eth_drv_l3_tx (ifp, skb);

  /* Free skb. */
  kfree_skb (skb);
  return 0;
}

#ifdef HSL_ETH_DRV_TX_THREAD
/* Tx thread. */
static void
_hsl_eth_tx_handler (void *notused)
{
     int ret = 0;

  struct sk_buff *skb;
#if 0  /** Inserted by alfred for debugging, 2007-01-25 **/
	printk("[%s:%d] %s thread was running \n", __FILE__, __LINE__, __FUNCTION__);
#endif

  while (hsl_eth_tx_thread_running) {
      while ((skb = skb_dequeue (&hsl_eth_tx_queue)) != NULL) {
    	  ret = _hsl_eth_drv_tx (skb);
          if (ret < 0) {
                printk("_hsl_eth_drv_tx failed,ret=%d\n", ret);
          }
	 }
     oss_sem_lock (OSS_SEM_BINARY, hsl_eth_tx_sem, OSS_WAIT_FOREVER);
 }
 return;
}
#endif /* HSL_ETH_DRV_TX_THREAD */

//by chentao
#if 1

/* Function to post L3 message. */
int
hsl_eth_drv_post_l3_pkt (struct hsl_if *ifpl3, ctc_pkt_buf_t *pkt)
{

  int len;
  int offset = 0;
  struct hsl_eth_header *eth;
  u_char *p;
  struct net_device *dev;
  struct sk_buff *skb = NULL;
  int i;
  unsigned char *pktu = (unsigned char*) pkt->data;

  HSL_FN_ENTER ();

  dev = ifpl3->os_info;
  if (! dev) {
    printk("=============error dev=NULL!===========\n");
    HSL_FN_EXIT (-1);
  }

  len = pkt->len;
  p = pkt->data;
  eth = (struct hsl_eth_header *) p;
    
  if (htons(eth->d.type) == 0x8100) {
		offset = 4;
   } else {
		offset = 0;
   }

  //È¥µôtag
  len -= offset;
  
  /* Substract CRC from length. */
  len -= 4;

  /* Allocate skb. */

  skb = dev_alloc_skb (len + 2);
  if (! skb)
    goto DROP;

  skb->dev = dev;
  skb_reserve (skb, 2); /* 16 byte align the IP fields. */ 
  memcpy(skb->data, pktu, 12);
  memcpy(skb->data+12, pktu+12+offset, len-12);
  skb_put (skb, len);

  skb->protocol = eth_type_trans (skb, dev);

#if 0
  {
      printk("netif_rx<3>:data_len=%d\n", skb->data_len);
      int i;
      for (i =0; i<len; i++)
        {
            printk("%02x,", (skb->data)[i]);
        }
      printk ("\n");
  }
#endif

  /* Pass it up. */

  netif_rx (skb);
  dev->last_rx = jiffies;

  HSL_FN_EXIT (0);

 DROP:
  if (skb)
    kfree_skb (skb);

  HSL_FN_EXIT (-1);

}
#endif

/* Transmit a packet. */
int
hsl_eth_dev_xmit (struct sk_buff * skb, struct net_device * dev)
{
  skb->dev = dev;


   HSL_LOG (HSL_LOG_GENERAL, HSL_LOG_PKTDRV, "hsl_eth_dev_xmit\n");

#ifdef HSL_ETH_DRV_TX_THREAD

  /* Post to tail. */
  skb_queue_tail (&hsl_eth_tx_queue, skb);

  /* Release semaphore. */
  oss_sem_unlock (OSS_SEM_BINARY, hsl_eth_tx_sem);
#else
  /* Stop queue. */
  netif_stop_queue (dev);

  /* Xmit pkt. */
  _hsl_eth_drv_tx (skb);

  /* Wakeup queue. */
  netif_wake_queue (dev);
#endif /* ! HSL_ETH_DRV_TX_THREAD */
  return 0;
}

/* Open. */
int
hsl_eth_dev_open (struct net_device * dev)
{
  /* Start queue. */
  netif_start_queue (dev);

  return 0;
}

/* Close. */
int
hsl_eth_dev_close (struct net_device * dev)
{
  /* Stop queue. */
  netif_stop_queue (dev);

  return 0;
}

/* Get interface statistics. */
struct net_device_stats *
hsl_eth_dev_get_stats(struct net_device *dev)
{
  return bcm_stats;
}

/* Set MC list. */
void
hsl_eth_dev_set_mc_list (struct net_device *dev)
{
  return;
}

/* Set multicast address. */
int
hsl_eth_dev_set_mac_addr (struct net_device *dev, void *p)
{
  struct sockaddr *addr = (struct sockaddr *) p;

  if (netif_running (dev))
    return -EBUSY;

  /* Set address. */
  memcpy (dev->dev_addr, addr->sa_data, dev->addr_len);

  return 0;
}

/*
1¡¢
* int (*ndo_open)(struct net_device *dev);
*     This function is called when network device transistions to the up
*     state.
2¡¢ 
* int (*ndo_stop)(struct net_device *dev);
*     This function is called when network device transistions to the down
*     state.
3¡¢
* struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);
*  Called when a user wants to get the network device usage
*  statistics. Drivers must do one of the following:
*  1. Define @ndo_get_stats64 to fill in a zero-initialised
*     rtnl_link_stats64 structure passed by the caller.
*  2. Define @ndo_get_stats to update a net_device_stats structure
*     (which should normally be dev->stats) and return a pointer to
*     it. The structure may be changed asynchronously only if each
*     field is written atomically.
*  3. Update dev->stats asynchronously and atomically, and define
*     neither operation.
*
4¡¢
* int (*ndo_set_mac_address)(struct net_device *dev, void *addr);
*  This function  is called when the Media Access Control address
*  needs to be changed. If this interface is not defined, the
*  mac address can not be changed.

5¡¢
* netdev_tx_t (*ndo_start_xmit)(struct sk_buff *skb,
*                               struct net_device *dev);
*  Called when a packet needs to be transmitted.
*  Must return NETDEV_TX_OK , NETDEV_TX_BUSY.
*        (can also return NETDEV_TX_LOCKED iff NETIF_F_LLTX)
*  Required can not be NULL.
*/

const struct net_device_ops hsl_netdev_ops = {
	.ndo_open               = hsl_eth_dev_open,
	.ndo_stop               = hsl_eth_dev_close,
	.ndo_get_stats          = hsl_eth_dev_get_stats,
	//.ndo_set_multicast_list = hsl_eth_dev_set_mc_list,
	/* Overwrite the default eth_mac_addr () */
	.ndo_set_mac_address    = hsl_eth_dev_set_mac_addr,
	.ndo_start_xmit         = hsl_eth_dev_xmit,
};

/* Setup netdevice functions/parameters. */
static void
hsl_eth_dev_setup (struct net_device *dev)
{
  dev->netdev_ops = &hsl_netdev_ops;

  memset (dev->dev_addr, 0, ETH_ALEN);

  dev->tx_queue_len = 0;

  return;
}

/* Function to create a L3 netdevice. */
struct net_device *
hsl_eth_drv_create_netdevice (struct hsl_if *ifp,  u_char *hwaddr, int hwaddrlen, int usr_ifindex)
{
	struct net_device *dev;
	struct sockaddr addr;
	int ret, _dev_put = 0;
	char ifname[IFNAMSIZ+1];
	char *chr;

#if 0 /** Inserted by alfred for debugging, 2007-02-05 **/
	printk("[%s:%d] ALFRED......... \n", __FUNCTION__, __LINE__);
#endif
	memset(ifname, 0, IFNAMSIZ);
	snprintf (ifname, IFNAMSIZ, "%s", ifp->name);
	chr = strchr(ifname,'/');
	if (chr != NULL) {
		*chr = '-';
	}

	dev = dev_get_by_name (&init_net, ifname);
	if (! dev)
    {
#if 0 /* EWAN 20061220 for 2.6 :NOTICE: dev_alloc is removed in 2.6 */
		dev = dev_alloc(ifname, &ret);
#else
		dev = alloc_netdev(0,ifname,ether_setup);
#endif
		if (dev == NULL)
		{
			return NULL;
		}
	}
	else
		_dev_put = 1;


  /* Ethernet type setup */
#if 0  /* EWAN 20061220 for 2.6 :NOTICE: dev_alloc is removed in 2.6 */
	ether_setup (dev);
#endif
  
	hsl_eth_dev_setup (dev);

	/* Set the callback for xmit. */
	//dev->hard_start_xmit = hsl_eth_dev_xmit;
  
	//SET_MODULE_OWNER (dev);
  
	/* Set ifp. */
	dev->ml_priv = ifp;

	/* Set flags. */
	ifp->flags = IFF_UP | IFF_BROADCAST | IFF_MULTICAST;
  
	/* Set mac. */
	if (hwaddrlen <= 14)
    {
		memset (&addr, 0, sizeof (struct sockaddr));
		memcpy (addr.sa_data, hwaddr, hwaddrlen);
      
		hsl_eth_dev_set_mac_addr (dev, (void *) &addr);
    }

	if (_dev_put)
		dev_put (dev);
	else
    {
        if(usr_ifindex > 0) {
            dev->ifindex = usr_ifindex;
        }
        
		/* Register netdevice. */
		ret = register_netdev (dev);
		if (ret)
		{
			return NULL;
		}
    }

	return dev;
}

/* Destroy netdevice. */
int
hsl_eth_drv_destroy_netdevice (struct net_device *dev)
{
  /* Unregister netdevice. */
  unregister_netdev (dev);

  return 0;
}

