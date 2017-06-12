/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#include "config.h"
#include "hsl_os.h"
#include "hsl_types.h"
#include "hsl_avl.h"

/* 
   Broadcom includes. 
*/
//#include "ctc_incl.h"
#ifdef VXWORKS
#include "selectLib.h"
#endif                          /* VXWORKS */
/* 
   HAL includes.
*/
#include "hal_types.h"
#include <linux/kfifo.h>
#include <linux/vnetdev.h>

#ifdef HAVE_L2
#include "hal_l2.h"
#endif                          /* HAVE_L2 */

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
#endif                          /* HAVE_L2 */

#ifdef HAVE_L2
#include "hsl_l2_sock.h"
#include "hsl_vlan.h"
#include "hsl_bridge.h"
#include "hsl_mac_tbl.h"
#ifdef HAVE_AUTHD
//#include "hsl_ctc_auth.h"
#endif                          /* HAVE_AUTHD */
#endif                          /* HAVE_L2 */

#ifdef HAVE_L3
#include "hsl_fib.h"
#endif                          /* HAVE_L3 */

#include "hsl_ctc_ifmap.h"
#include "hsl_ctc_if.h"
#include "hsl_ctc_pkt.h"
#if defined(HAVE_MCAST_IPV4) || defined(HAVE_MCAST_IPV6) || defined(HAVE_MLD_SNOOP) || defined (HAVE_IGMP_SNOOP)
#include "hsl_mcast_fib.h"
#endif                          /* HAVE_MCAST_IPV4 || HAVE_MCAST_IPV6 || HAVE_MLD_SNOOP || defined HAVE_IGMP_SNOOP */

//#include "hsl_ctc.h"
#include "ctc_api.h"
#include "ctc_packet.h"
#include "sal.h"

#include "ctc_if_portmap.h"
#include "ctc_board_macros.h"

#define HSL_CTC_TRY_TRY_UNICAST_FAIL -1
#define HSL_CTC_TRY_TRY_UNICAST_OK   0

#define MACADDR_IS_MULTICAST(mac) (mac[0] & 0x1)

#define HSL_ETH_TAG_SIZE           4
#define HSL_ETH_UNTAGGED_HDR_LEN   14
#define HSL_ETH_TAGGED_HDR_LEN     18

#define HSL_ETH_VLAN_CTRL(prio, cfi, vid)   (((prio) & 0x007) << 13 | \
                                            ((cfi ) & 0x001) << 12 | \
                                            ((vid  ) & 0xfff) << 0)

#define HSL_ETH_VLAN_CTRL_PRIO(c)               ((c) >> 13 & 0x007)
#define HSL_ETH_VLAN_CTRL_CFI(c)                ((c) >> 12 & 0x001)
#define HSL_ETH_VLAN_CTRL_ID(c)                 ((c) >>  0 & 0xfff)

typedef struct vendor_rx_chippkt_s {
    unsigned int seq;
    ctc_pkt_rx_t v_pkt;
    u_char data[0];
} vendor_rx_chippkt_t;

#define VENDOR_RX_CHIPPKT_PKT(pkt) (pkt->_pkt)
#define VENDOR_RX_CHIPPKT_DATA(pkt) (pkt->data)
#define VENDOR_RX_CHIPPKT_DATALEN(pkt) (pkt->v_pkt.pkt_len)


/* 
   Rx queue length.
*/
#define HSL_CTC_PKT_CHIP2CP_QUEUE_SIZE      (0x100)
#define ALIGN_TO                            4

/* HSL_CTC_RX_PRIO need be less than ATP_RX_PRIORITY for stacking */
#define ATP_RX_PRIORITY         20
#define HSL_CTC_RX_PRIO			ATP_RX_PRIORITY - 10

#define hsl_ctc_vid2ifindex(vid)   (VND_INDEX_VLAN_BASE + (vid))
#define hsl_ctc_ifindex2vid(ifindex) ( ifindex >= VND_INDEX_VLAN_BASE ? (ifindex-VND_INDEX_VLAN_BASE): 0)
/*
  Rx queue. Queue of HANDLE_OWNED packets. To be processed by
  pkt_thread outside the context of RX thread.
*/
struct hsl_ctc_rx_queue
{
  DECLARE_KFIFO_PTR(pkt_queue, vendor_rx_chippkt_t *);/* CTC Packet queue of aligned ctc_pkt_t. */
  //int total;                          /* Total queue size. */
  //volatile int head;                           /* Head of queue. */
  //volatile int tail;                           /* Tail of queue. */
  oss_atomic_t count;                          /* Number of packets in queue. */
  oss_atomic_t drop;                           /* Number of dropped packets. */
  void *pkt_thread;                   /* Packet execution thread. */
  ipi_sem_id pkt_sem;                 /* Packet semaphore. */
  int thread_exit;                    /* If 1, exit packet processing. */
  //ipi_sem_id pkt_mutex;               /* Packet queue muxtex. */
};

/* 
   Rx queue helper macros. 
*/

/*
  Packet driver master structure. 
*/
struct hsl_ctc_pkt_master
{
  /* Rx. */
  struct hsl_ctc_rx_queue rx;
};




extern void ctc_cfg_rx_callback_register(CTC_PKT_RX_CALLBACK cfg_rx_cb);
extern int32 _ctc_app_packet_sample_build_raw_pkt(uint8* p_pkt, ctc_pkt_rx_t* p_pkt_rx);
static int hsl_ctc_rx_chippkt(ctc_pkt_rx_t * pkt);


/* 
   Master packet driver structure.
*/
static struct hsl_ctc_pkt_master *p_hsl_ctc_pkt_master = NULL;
static int aligned_sizeof_vendor_rx_chippkt_t;

/*
  L2 Control Frame DMACs.
*/

/* Multicast MAC. */
mac_addr_t multicast_addr = { 0x1, 0x00, 0x5e, 0x00, 0x00, 0x00 };

/* Bridge BPDUs. */
mac_addr_t bpdu_addr = { 0x1, 0x80, 0xc2, 0x00, 0x00, 0x00 };

/* GMRP BPDUs. */
mac_addr_t gmrp_addr = { 0x1, 0x80, 0xc2, 0x00, 0x00, 0x20 };

/* GVRP BPDUs. */
mac_addr_t gvrp_addr = { 0x1, 0x80, 0xc2, 0x00, 0x00, 0x21 };

/* LACP. */
mac_addr_t lacp_addr = { 0x1, 0x80, 0xc2, 0x00, 0x00, 0x02 };

/* EAPOL. */
mac_addr_t eapol_addr = { 0x1, 0x80, 0xc2, 0x00, 0x00, 0x03 };

/* 
   Forward declarations.
*/
static void hsl_ctc_chip2cp_handler_thread(void *param);

/*
  Deinitialize master structure. 
*/
static int hsl_ctc_pkt_master_deinit(void)
{
    if (p_hsl_ctc_pkt_master) {
        if (p_hsl_ctc_pkt_master)
            oss_free(p_hsl_ctc_pkt_master, OSS_MEM_HEAP);
        p_hsl_ctc_pkt_master = NULL;
    }
    return 0;
}

/* 
   Initialize master structure. 
*/
static int hsl_ctc_pkt_master_init(void)
{
    HSL_FN_ENTER();

    p_hsl_ctc_pkt_master = oss_malloc(sizeof(struct hsl_ctc_pkt_master), OSS_MEM_HEAP);
    if (!p_hsl_ctc_pkt_master) {
        HSL_LOG(HSL_LOG_PKTDRV, HSL_LEVEL_FATAL,
                "Failed allocating memory for packet driver master structure\n");
        return -1;
    }
    memset(p_hsl_ctc_pkt_master, 0, sizeof(struct hsl_ctc_pkt_master));
    HSL_FN_EXIT(0);
}
void hsl_ctc_dump_hex8(unsigned char *data, unsigned int len);

int hsl_ctc_chip2cp_data_skb_func(struct sk_buff *skb, struct net_device *dev,
            struct packet_type *ptype, struct net_device *orig_dev)
{

    int pkt_size;
    struct net_device *tx_dev;

    pkt_size = skb->len + ETH_HLEN;
    if (pkt_size <= LC2CP_DATA_HDR_SIZE){
        goto no_dev;
    }
    
    tx_dev = dev_get_by_name (&init_net, "eth7");
    if (!tx_dev)
        goto drop_skb;

    skb->dev = tx_dev;
    skb_push (skb, ETH_HLEN);
    dev_queue_xmit(skb);
    return NET_RX_SUCCESS;

drop_skb:
    //vnd_dev->stats.rx_dropped++;
    //dev_put(vnd_dev);
no_dev:
    kfree_skb(skb);
    return NET_RX_DROP;

}

static struct packet_type hsl_chip2cp_data_pkt_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_LC2CP_DATA), /*0x8987*/
	.func = hsl_ctc_chip2cp_data_skb_func, /* LC2CP redir data packet receive method */
};

/* 
   Deinitialize CTCX Rx.
*/
static int hsl_ctc_chip2cp_deinit(void)
{
    HSL_FN_ENTER();

#if 0
    if (ctcx_rx_running())
        ctcx_rx_stop();
#endif
    if ((board_id == BOARD_PLATFORM_ID_XGS) || (board_id == BOARD_PLATFORM_ID_GES)) {
        dev_remove_pack(&hsl_chip2cp_data_pkt_type);
        printk("deregister hsl_chip2cp_data_pkt_type\n");
    }
    if (p_hsl_ctc_pkt_master)
        HSL_FN_EXIT(0);

    if (&p_hsl_ctc_pkt_master->rx.pkt_queue)
        kfifo_free(&p_hsl_ctc_pkt_master->rx.pkt_queue);

    if (p_hsl_ctc_pkt_master->rx.pkt_sem)
        oss_sem_delete(OSS_SEM_BINARY, p_hsl_ctc_pkt_master->rx.pkt_sem);

    if (p_hsl_ctc_pkt_master->rx.pkt_thread)
        sal_task_destroy(p_hsl_ctc_pkt_master->rx.pkt_thread);

    HSL_FN_EXIT(0);
}

/*
  Initialize CTC Rx.
*/
static int hsl_ctc_chip2cp_init(void)
{
    int ret;
    int total;

    HSL_FN_ENTER();
    /* Set up Rx pool. */
    //total = aligned_sizeof_vendor_rx_chippkt_t * HSL_CTC_PKT_CHIP2CP_QUEUE_SIZE;
    ret = kfifo_alloc(&p_hsl_ctc_pkt_master->rx.pkt_queue, HSL_CTC_PKT_CHIP2CP_QUEUE_SIZE, GFP_KERNEL);
    if (ret) {
        HSL_LOG(HSL_LOG_PKTDRV, HSL_LEVEL_FATAL,
                "Failed allocating memory for packet driver queue\n");
        goto ERR;

    }
    //if ((p_hsl_ctc_pkt_master->rx.pkt_queue = oss_malloc(total, OSS_MEM_HEAP)) == NULL) {
    //    HSL_LOG(HSL_LOG_PKTDRV, HSL_LEVEL_FATAL,
    //            "Failed allocating memory for packet driver queue\n");
    //    goto ERR;
    //}
    
    /* Initialize semaphore. */
    ret = oss_sem_new("chip2cp SEM",
                      OSS_SEM_BINARY, 0, NULL, &p_hsl_ctc_pkt_master->rx.pkt_sem);

    if (ret < 0) {
        goto ERR;
    }
    

    p_hsl_ctc_pkt_master->rx.thread_exit = 0;

    /* Create packet dispather thread. */
    ret = sal_task_create((sal_task_t **)&p_hsl_ctc_pkt_master->rx.pkt_thread,
                      "zPktchip2cp",
                      SAL_DEF_TASK_STACK_SIZE,
                      150, hsl_ctc_chip2cp_handler_thread, 0);

    if (!p_hsl_ctc_pkt_master->rx.pkt_thread) {
        HSL_LOG(HSL_LOG_PKTDRV, HSL_LEVEL_FATAL, "Cannot start packet dispatcher thread\n");
        goto ERR;
    }

    if ((board_id == BOARD_PLATFORM_ID_XGS) || (board_id == BOARD_PLATFORM_ID_GES)) {
        dev_add_pack(&hsl_chip2cp_data_pkt_type);
        printk("register hsl_chip2cp_data_pkt_type\n");
    }
    /* Register RX. */
    ctc_cfg_rx_callback_register(hsl_ctc_rx_chippkt);

    if (ret < 0) {
        HSL_LOG(HSL_LOG_PKTDRV, HSL_LEVEL_FATAL, "Error registering Chip Rx callback\n");
        goto ERR;
    }
#if 0
    /* Start CTCX RX. */
    if (1) {
        ret = ctc_rx_start();
        if (ret < 0) {
            HSL_LOG(HSL_LOG_PKTDRV, HSL_LEVEL_FATAL, "Error starting RX on CHIP\n");
            goto ERR;
        }
    }
#endif

    HSL_FN_EXIT(0);

  ERR:
    hsl_ctc_chip2cp_deinit();
    HSL_FN_EXIT(-1);
}


static const unsigned char * hsl_ctc_get_cp_mac()
{
      static const unsigned char cp_eth7mac_lelft[6] = { 0x00, 0x40, 0x00, 0x00, 0x00, 0x00 };
      static const unsigned char cp_eth7mac_right[6] = { 0x00, 0x40, 0x00, 0x00, 0x00, 0x01 };

     return cp_eth7mac_lelft;
}

/*
 * LC's Function send packet to cp
 * 
 */

static int hsl_ctc_tx2cp(vendor_rx_chippkt_t *pkt)
{
    struct net_device *tx_dev;
    struct sk_buff *skb = NULL;
    
    unsigned char *frame;
    unsigned int frame_len;
    struct hsl_eth_header *eth;
    
    lc2cp_data_hdr_t *lc2cp_h;
    const ctc_pkt_info_t *rx_info;
    const unsigned char *lc2cp_dmac = hsl_ctc_get_cp_mac();
    unsigned char lc2cp_smac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; 
    
    unsigned int vid;
    int drop_vlan_tag;
    
    
    rx_info = &pkt->v_pkt.rx_info;
    frame = pkt->data + CTC_PKT_TOTAL_HDR_LEN(&pkt->v_pkt);
    frame_len = pkt->v_pkt.pkt_len - 4/* strip tail crc */ - CTC_PKT_TOTAL_HDR_LEN(&pkt->v_pkt);

    if (frame_len < (64 - 4/* min eth payload */)) {
        goto DROP; 
    }
    
    eth = (struct hsl_eth_header *) frame;
    if (eth->d.type == HSL_ENET_8021Q_VLAN) {
        vid = HSL_ETH_VLAN_GET_VID (eth->d.vlan.pri_cif_vid);
        drop_vlan_tag = 1;
    } else {
        vid = 1 /* default vlan1 */;
        drop_vlan_tag = 0;
    }

    /* Allocate skb. */
    skb = dev_alloc_skb(32/*LC2CP_DATA_HDR_SIZE*/ + frame_len);
    if (!skb)
        goto DROP;
    
    tx_dev = dev_get_by_name (&init_net, "lo");
    if (!tx_dev)
        goto DROP;

    skb->dev = tx_dev;
    skb_reserve(skb, 10);        /* 16 byte align the IP fields. */
    /* encap lc2cp hdr */
    memset(skb->data, 0, LC2CP_DATA_HDR_SIZE);
    lc2cp_h = (lc2cp_data_hdr_t *)skb->data;
    lc2cp_h->ifindex = htons(hsl_ctc_vid2ifindex(vid));
    if ((board_id == BOARD_PLATFORM_ID_XGS) || (board_id == BOARD_PLATFORM_ID_GES)) {
        memcpy(lc2cp_h->dmac, lc2cp_dmac, 6);
        lc2cp_smac[2]= 1<<rx_info->src_chip;
        memcpy(lc2cp_h->smac, lc2cp_smac, 6); 
    }
    lc2cp_h->proto =  htons(0x8987); /* LC2CP */
    lc2cp_h->redir_code = REDIR_ALL;
    lc2cp_h->pad_len = 0;
    
   {
        /* |dmac 6 | smac 6 | vlantag 4 | type 2 | ... */
        /* drop vlan_tag */
        if (drop_vlan_tag) {
            /* orig raw packet data */
            memcpy(skb->data + LC2CP_DATA_HDR_SIZE, frame, HSL_ETHER_ADDRLEN + HSL_ETHER_ADDRLEN);
            memcpy(skb->data + LC2CP_DATA_HDR_SIZE + HSL_ETHER_ADDRLEN + HSL_ETHER_ADDRLEN,
                frame + HSL_ETHER_ADDRLEN + HSL_ETHER_ADDRLEN + HSL_ETH_TAG_SIZE /* vlantag */,
                frame_len - HSL_ETHER_ADDRLEN - HSL_ETHER_ADDRLEN - HSL_ETH_TAG_SIZE);
            skb_put(skb, LC2CP_DATA_HDR_SIZE + frame_len - HSL_ETH_TAG_SIZE);
            c2cp_h->length = (frame_len - HSL_ETH_TAG_SIZE);
    
        } else {
            /* orig raw packet data */
            memcpy(skb->data + LC2CP_DATA_HDR_SIZE, frame, frame_len);
            skb_put(skb, LC2CP_DATA_HDR_SIZE + frame_len);
        }
    }
    
    skb->protocol = eth_type_trans(skb, tx_dev);
    
    netif_rx (skb);
    tx_dev->last_rx = jiffies;
    
    HSL_FN_EXIT(0);
DROP:
    if (skb)
        kfree_skb(skb);
    
    HSL_FN_EXIT(-1);
}


#define NGN_HEADER_OFFSET_TAG   (18+20)
#define NGN_HEADER_OFFSET_UNTAG  (14+20)
#define  NGN_TYPE  0x8871

struct ngnhdr {
#if defined (__LITTLE_ENDIAN_BITFIELD)
	__u8 	len:4,
			version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8 	version:4,
			len:4;
#else
#error	"Please fix byteorder"
#endif
	__u8   next_head;
};

int hsl_ctc_ipv4_to_id(vendor_rx_chippkt_t * pkt)
{
	int ngn_head_offset = 0;
	struct hsl_eth_header *eth = NULL;
	struct ngnhdr  *ngnhdr = NULL;
	u_int16_t *l2_type = NULL;
	unsigned char *frame;

	frame = pkt->data + CTC_PKT_TOTAL_HDR_LEN(&pkt->v_pkt);
    
	eth = (struct hsl_eth_header *)(frame);
	if (htons(eth->d.type) == 0x8100 || htons(eth->d.type) == 0x9100
	|| htons(eth->d.type) == 0x9300) {
		ngn_head_offset = NGN_HEADER_OFFSET_TAG;
		l2_type = (u_int16_t *)(frame + 16);
	} else {
		ngn_head_offset = NGN_HEADER_OFFSET_UNTAG;
		l2_type = (u_int16_t *)(frame + 12);
	}
	
	ngnhdr = (struct ngnhdr *)(frame + ngn_head_offset);

	//printk("ngnhdr->version=%d, ngnhdr->len=%d, ngnhdr->next_head=%d, l2_type=%#x\n",
	//    ngnhdr->version,ngnhdr->len,ngnhdr->next_head, ntohs(*l2_type));
	
	if (ntohs(*l2_type) == 0x0800  && ngnhdr->version == 1 
		&& ngnhdr->len == 3 && ngnhdr->next_head == 0)  {
		*l2_type = htons(NGN_TYPE);
	}
	return 0;	
	
}

static void hsl_ctc_dump_pktfromchip(vendor_rx_chippkt_t *);
static void hsl_ctc_chip2cp_process(vendor_rx_chippkt_t * pkt)
{
  hsl_ctc_dump_pktfromchip(pkt);
//    hsl_ctc_ipv4_to_id(pkt);
    hsl_ctc_tx2cp(pkt);
    HSL_FN_EXIT();
}

/*
  Packet dispatcher thread.
*/
static void hsl_ctc_chip2cp_handler_thread(void *param)
{
    vendor_rx_chippkt_t *pkt;
    int rv;
//    printk(" hsl_ctc_chip2cp_handler_thread\n"); 
    while (!p_hsl_ctc_pkt_master->rx.thread_exit) {
        /* Service packets. */
        while (!kfifo_is_empty(&p_hsl_ctc_pkt_master->rx.pkt_queue)) {
            
            /* Get head packet. */
            rv = kfifo_get(&p_hsl_ctc_pkt_master->rx.pkt_queue, &pkt);     
            if (!rv) {
                return;
            }
//            printk(" handle %u packet\n", pkt->seq);
            
            /* Main demux routine for the packets coming to the CPU. */
            hsl_ctc_chip2cp_process(pkt);
            
            /* Free the Rx data. */
            if(pkt->data)
                sal_free(pkt);
            
        }
        oss_sem_lock(OSS_SEM_BINARY, p_hsl_ctc_pkt_master->rx.pkt_sem, OSS_WAIT_FOREVER);

    }
    printk(" hsl_ctc_chip2cp_handler_thread exit!!! \n");

    /* Exit packet thread. */
    oss_sem_delete(OSS_SEM_BINARY, p_hsl_ctc_pkt_master->rx.pkt_sem);
}


static int32
_ctc_app_packet_sample_dump_info_xx(ctc_pkt_info_t* p_info, uint32 is_tx);

/*
  Callback from CTC Rx. */
static int hsl_ctc_rx_chippkt(ctc_pkt_rx_t * pkt)
{
    static unsigned int count;
    vendor_rx_chippkt_t *entry;
    u_char *data;
    int rv;
    
    count++;
//    printk(">>>%u pkt\n", count);
    if (!pkt) {
       return 0; 
    }
    /* Queue the packet. */
    if (kfifo_is_full(&p_hsl_ctc_pkt_master->rx.pkt_queue)) {
        /* Queue is full. */
        oss_atomic_inc(&p_hsl_ctc_pkt_master->rx.drop);
        printk(">>>  queue full\n");
        return -1;
    } else {
        /* | seq | ctc_pkt_rx_t | data ....  */
         entry = (vendor_rx_chippkt_t *)sal_malloc(sizeof(vendor_rx_chippkt_t) + pkt->pkt_len);
         if (!entry) {
            return -1;
         }
        /* debug purpose */
        entry->seq = count;
        
        /* Copy the header contents. */
        memcpy(&entry->v_pkt, pkt, sizeof(ctc_pkt_rx_t));
        /* Not use */
        entry->v_pkt.pkt_buf = 0;
        
        /* assembling a packet from rcv buf */
        _ctc_app_packet_sample_build_raw_pkt(entry->data, pkt);
        
        /* Increment count. */
        rv = kfifo_put(&p_hsl_ctc_pkt_master->rx.pkt_queue, entry);
        if(rv) {
            oss_atomic_inc(&p_hsl_ctc_pkt_master->rx.count);
        } else {
            oss_atomic_inc(&p_hsl_ctc_pkt_master->rx.drop);
        }
        
//        printk(">>>  enqueue\n");
        /* Give semaphore. */
        oss_sem_unlock(OSS_SEM_BINARY, p_hsl_ctc_pkt_master->rx.pkt_sem);
    }
    
    return 0;
}



#define HSL_DBG_PKT_LEVEL 0
#define HSL_DBG_PKT_OUT(L, FMT,...) printk(FMT, ##__VA_ARGS__)

static void hsl_ctc_dump_pktfromchip_info(ctc_pkt_info_t * p_info, unsigned int is_tx)
{
    if (is_tx) {
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "\nTx Information\n");
    } else {
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "\nRx Information\n");
    }

    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "flags              :   0x%08X\n", p_info->flags);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "oper_type          :   %d\n", p_info->oper_type);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "priority           :   %d\n", p_info->priority);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "color              :   %d\n", p_info->color);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "src_cos            :   %d\n", p_info->src_cos);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "TTL                :   %d\n", p_info->ttl);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "is_critical        :   %d\n", p_info->is_critical);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "dest_gport         :   %d\n", p_info->dest_gport);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "dest_group_id      :   %d\n", p_info->dest_group_id);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "src_svid           :   %d\n", p_info->src_svid);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "src_cvid           :   %d\n", p_info->src_cvid);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "src_port           :   %d\n", p_info->src_port);

    if (CTC_PKT_OPER_OAM == p_info->oper_type) {
        /* OAM */
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "oam.type           :   %d\n", p_info->oam.type);
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "oam.flags          :   0x%08X\n", p_info->oam.flags);
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "oam.mep_index      :   %d\n", p_info->oam.mep_index);
        if (CTC_FLAG_ISSET(p_info->oam.flags, CTC_PKT_OAM_FLAG_IS_DM)) {
            HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "oam.dm_ts_offset   :   %d\n",
                            p_info->oam.dm_ts_offset);
            HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "oam.dm_ts.sec      :   %d\n",
                            p_info->oam.dm_ts.seconds);
            HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "oam.dm_ts.ns       :   %d\n",
                            p_info->oam.dm_ts.nanoseconds);
        }
    }

    if (CTC_PKT_OPER_PTP == p_info->oper_type) {
        /* PTP */
        if (is_tx) {
            HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "ptp.oper           :   %d\n", p_info->ptp.oper);
            HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "ptp.seq_id         :   %d\n", p_info->ptp.seq_id);
        }

        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "ptp.ts.sec         :   %d\n", p_info->ptp.ts.seconds);
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "ptp.ts.ns          :   %d\n",
                        p_info->ptp.ts.nanoseconds);
    }

    if (is_tx) {
        /* TX */
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "nh_offset          :   %d\n", p_info->nh_offset);
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "hash               :   %d\n", p_info->hash);
    } else {
        /* RX */
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "reason             :   %d\n", p_info->reason);
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "vrfid              :   %d\n", p_info->vrfid);
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "packet_type        :   %d\n", p_info->packet_type);
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "src_chip           :   %d\n", p_info->src_chip);
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "payload_offset     :   %d\n", p_info->payload_offset);
    }

    return;
}

void hsl_ctc_dump_hex8(unsigned char *data, unsigned int len)
{
    uint32 cnt = 0;
    char line[256];
    char tmp[32];

    if (0 == len) {
        return;
    }

    for (cnt = 0; cnt < len; cnt++) {
        if ((cnt % 16) == 0) {
            if (cnt != 0) {
                HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "%s", line);
            }

            sal_memset(line, 0, sizeof(line));
            sal_snprintf(tmp, 32, "\n0x%04x:  ", cnt);
            sal_strcat(line, tmp);
        }

        sal_snprintf(tmp, 32, "%02x", data[cnt]);
        sal_strcat(line, tmp);

        if ((cnt % 2) == 1) {
            sal_strcat(line, " ");
        }
    }

    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "%s", line);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "\n");

    return;
}

static void hsl_ctc_dump_pktfromchip_raw(const ctc_pkt_rx_t * p_pkt_rx, uint8 * raw_pktdata)
{
    uint8 *p = NULL;
    uint16 data_len = 0;

    p = raw_pktdata;
    if (p_pkt_rx->eth_hdr_len) {
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "--ETH Header Length : %d\n", p_pkt_rx->eth_hdr_len);
        hsl_ctc_dump_hex8(p, p_pkt_rx->eth_hdr_len);
        p += p_pkt_rx->eth_hdr_len;
    }

    if (p_pkt_rx->pkt_hdr_len) {
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "--Packet Header Length : %d\n", p_pkt_rx->pkt_hdr_len);
        hsl_ctc_dump_hex8(p, p_pkt_rx->pkt_hdr_len);
        p += p_pkt_rx->pkt_hdr_len;
    }

    if (p_pkt_rx->stk_hdr_len) {
        HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "--Stacking Header Length : %d\n",
                        p_pkt_rx->stk_hdr_len);
        hsl_ctc_dump_hex8(p, p_pkt_rx->stk_hdr_len);
        p += p_pkt_rx->stk_hdr_len;
    }

    p = raw_pktdata + CTC_PKT_TOTAL_HDR_LEN(p_pkt_rx);
    data_len = p_pkt_rx->pkt_len - CTC_PKT_TOTAL_HDR_LEN(p_pkt_rx);

    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "Packet Data Length : %d\n", data_len);
    hsl_ctc_dump_hex8(p, data_len);

    return;
}



/*
 *    Dump.
 *    */
static void hsl_ctc_dump_pktfromchip(vendor_rx_chippkt_t * vpkt)
{
    unsigned int i;
    ctc_pkt_rx_t *cpkt = &vpkt->v_pkt;
    HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_INFO, "Rx Drop %d Count %d\n",
            p_hsl_ctc_pkt_master->rx.drop, p_hsl_ctc_pkt_master->rx.count);

    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "mode:            %u\n", cpkt->mode);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "pkt_len:         %u\n", cpkt->pkt_len);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "dma_chan:        %u\n", cpkt->dma_chan);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "eth_hdr_len:     %u\n", cpkt->eth_hdr_len);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "pkt_hdr_len:     %u\n", cpkt->pkt_hdr_len);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "stk_hdr_len:     %u\n", cpkt->stk_hdr_len);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "resv0:           %02x%02x\n", cpkt->resv0[0],
                    cpkt->resv0[1]);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "buf_count:       %u\n", cpkt->buf_count);
    HSL_DBG_PKT_OUT(HSL_DBG_PKT_LEVEL, "pkt_buf:         %p\n", cpkt->pkt_buf);

    hsl_ctc_dump_pktfromchip_info(&cpkt->rx_info, 0);

    hsl_ctc_dump_pktfromchip_raw((const ctc_pkt_rx_t *) cpkt, vpkt->data);

}



/************************************************
  * @Brief:
  * 	build packet to tx, fill struct ctc_pkt_tx_t with param.
  ************************************************/
static int32
hsl_ctc_tx2chip_build_pkt(const char *frame, uint32 frame_len, ctc_pkt_tx_t *p_pkt_tx, 
								ctc_pkt_mode_t tx_mode, bool is_ucast, bool is_agg, uint16 dest_id,
								bool has_hash, uint8 hash, 
								bool is_bypass, bool is_nhid, uint32 nh_offset_or_id,
								bool has_vlan, uint16 src_svid,
								bool use_src_port, uint16 src_port)
{
	int32 ret = 0;
	uint8 lchip = 0;
	unsigned char *p_ctc_skb_data = NULL;

	/* fill the packet info */
	if(tx_mode == CTC_PKT_MODE_DMA) {
		p_pkt_tx->mode = CTC_PKT_MODE_DMA;
	} else {
		p_pkt_tx->mode = CTC_PKT_MODE_ETH;
	}	
	
	ctc_get_local_chip_num(&lchip);
	p_pkt_tx->lchip = lchip;

	p_pkt_tx->tx_info.oper_type = CTC_PKT_OPER_NORMAL;
	p_pkt_tx->tx_info.is_critical = 1;

	if(is_ucast) {
		p_pkt_tx->tx_info.dest_gport = dest_id;
		if(is_agg && has_hash) {
			p_pkt_tx->tx_info.flags |= CTC_PKT_FLAG_HASH_VALID;
			p_pkt_tx->tx_info.hash = hash;
		}
	} else {
		p_pkt_tx->tx_info.flags |= CTC_PKT_FLAG_MCAST;
		p_pkt_tx->tx_info.dest_group_id = dest_id;
	}

	if(is_bypass) {
		p_pkt_tx->tx_info.flags |= CTC_PKT_FLAG_NH_OFFSET_BYPASS;
	} else {
		p_pkt_tx->tx_info.flags |= CTC_PKT_FLAG_NH_OFFSET_VALID;
		if(is_nhid) {
			ctc_nh_info_t dsnh = {0};
			ret = ctc_nh_get_nh_info(nh_offset_or_id, &dsnh);
			if(ret < 0) {
			    HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_INFO, "ctc_nh_get_nh_info err %s", ctc_get_error_desc(ret));
			}
			p_pkt_tx->tx_info.nh_offset = dsnh.dsnh_offset[0];
		} else {
			p_pkt_tx->tx_info.nh_offset = nh_offset_or_id;
		}
	}

	if(has_vlan) {
		p_pkt_tx->tx_info.flags |= CTC_PKT_FLAG_SRC_SVID_VALID;
		p_pkt_tx->tx_info.src_svid = src_svid;
	}

	if(use_src_port) {
		p_pkt_tx->tx_info.flags |= CTC_PKT_FLAG_SRC_PORT_VALID;
		p_pkt_tx->tx_info.src_svid = src_port;
	}
	
#define CTC_PKT_TTL_DFT	0
	p_pkt_tx->tx_info.ttl = (uint8)(CTC_PKT_TTL_DFT);

	/* add packet to ctc skb buffer */
	ctc_packet_skb_init(&(p_pkt_tx->skb));
	p_ctc_skb_data = ctc_packet_skb_put(&(p_pkt_tx->skb), frame_len);
	sal_memcpy (p_ctc_skb_data, frame, frame_len);
	
    return 0;
}




/************************************************
  * @Brief:
  * 	build packet to tx, fill struct ctc_pkt_tx_t with param.
  * @Param:
  *	zg - which module
  *	pkt_buf - packet data
  *	pkt_len - packet length
  * 	tx_mode - tx mode : DMA or ETH 
  * 	is_ucast - tx ucast packet or mcast packet
  *	is_agg - inf is agg or port, valid when is_ucast set
  *	dest_id - inf id or mcast group id
  *	has_hash - whether has hash, or generated by sdk
  *	hash - hash of agg for load balance
  *	is_bypass - wether bypass nexthop or bridge nexthop
  *	is_nhid - wether is nexthop id or dsnh, valid when is_bypass unset
  *	nh_offset_or_id - nexthop offset or nexthop id
  *	has_vlan - wether has vlan
  *	src_svid - source svlan id
  *	use_src_port - whether use src_port or use CTC_LPORT_CPU(62)
  *	src_port - source port
  *************************************************/
int32
hsl_ctc_tx2chip_generic(const char *frame, uint32 frame_len,
							ctc_pkt_mode_t tx_mode, bool is_ucast, bool is_agg, uint16 dest_id,
							bool has_hash, uint8 hash, 
							bool is_bypass, bool is_nhid, uint32 nh_offset_or_id,
							bool has_vlan, uint16 src_svid,
							bool use_src_port, uint16 src_port)
{
	int32 ret = 0;
	ctc_pkt_tx_t *p_ctc_pkt_tx;

	/* packet length check */
	if(frame_len > (CTC_PKT_MTU - CTC_PKT_HDR_ROOM)) {
        return -1;
    }
    p_ctc_pkt_tx = (ctc_pkt_tx_t *)sal_malloc(sizeof(ctc_pkt_tx_t));
    if (!p_ctc_pkt_tx) {
        return -1;
    }

	/* malloc and zero the packet struct */
	sal_memset(p_ctc_pkt_tx, 0, sizeof(ctc_pkt_tx_t));

	/* build the packet info */
	ret = hsl_ctc_tx2chip_build_pkt(frame, frame_len, p_ctc_pkt_tx, tx_mode,
								   is_ucast, is_agg, dest_id, has_hash, hash,
								   is_bypass, is_nhid, nh_offset_or_id,
								   has_vlan, src_svid, use_src_port, src_port);

	/* send packet */
	ret = ctc_packet_tx(p_ctc_pkt_tx);
	if (ret < 0) {
		HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_WARN, "ctc_packet_tx err %s", ctc_get_error_desc(ret));
	}
	sal_free(p_ctc_pkt_tx);
    return -1;
}





static int hsl_ctc_cp2chip_deinit(void);
static int hsl_ctc_cp2chip_init(void);

/*
  Initialize packet driver.
*/
int hsl_ctc_pkt_init()
{
    int ret;

    HSL_FN_ENTER();
    /* Set the aligned size of struct ctc_pkt_t so that we don;t calculate everytime. */
    aligned_sizeof_vendor_rx_chippkt_t = (sizeof(vendor_rx_chippkt_t) + ALIGN_TO - 1) & (-ALIGN_TO);

    /* Initialize master. */
    hsl_ctc_pkt_master_init();
    hsl_ctc_cp2chip_init();
    /* Initialize Rx. */
    ret = hsl_ctc_chip2cp_init();
    if (ret < 0) {
        HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Error initializing CPU Rx interface\n");
        goto ERR;
    }
    HSL_FN_EXIT(0);

  ERR:
    hsl_ctc_pkt_deinit();
    HSL_FN_EXIT(-1);
}

/*
  Deinitialize packet driver.
*/
int hsl_ctc_pkt_deinit()
{
    int ret;

    HSL_FN_ENTER();

    /* Deinitialize Rx. */
    ret = hsl_ctc_chip2cp_deinit();
    if (ret < 0) {
        HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_FATAL, "Error denitializing CPU Rx interface\n");
    }
    hsl_ctc_cp2chip_deinit();
    /* Deinitialize master. */
    hsl_ctc_pkt_master_deinit();

    HSL_FN_EXIT(0);
}



static sal_task_t *hsl_ctc_cp2chip_thread = NULL;
static struct sk_buff_head hsl_ctc_cp2chip_queue;
static ipi_sem_id hsl_ctc_cp2chip = NULL;
static volatile int hsl_ctc_cp2chip_thread_running;

/* Forward declarations. */
static void hsl_ctc_cp2chip_handler(void *notused);
static int hsl_ctc_cp2chip_deinit(void);
static int hsl_ctc_rx_cppkt (struct sk_buff * skb);



int hsl_ctc_cp2chip_data_skb_recv(struct sk_buff *skb, struct net_device *dev,
		  struct packet_type *ptype, struct net_device *orig_dev)
{
    int pkt_size;
	//int vnd_ifindex, pkt_size, data_size;
	//struct net_device *vnd_dev;
	//struct cp_send_hdr_s *cp2lc_hdr;
   
	pkt_size = skb->len + ETH_HLEN;
	if (pkt_size <= CP2LC_DATA_HDR_SIZE){
		goto no_dev;
	}
#if 0 

	cp2lc_hdr = (struct cp_send_hdr_s *)skb_mac_header(skb);
	vnd_ifindex = ntohs(cp2lc_hdr->ifindex);
	vnd_dev = dev_get_by_index(dev_net(dev), vnd_ifindex);
	if(vnd_dev == NULL){
		goto no_dev;
	}
	
	data_size = ntohs(cp2lc_hdr->length);
	if (data_size < vnd_dev->hard_header_len){
		printk("DROP: hsl recv from cp litter data size %d(%d)\n", 
			data_size, vnd_dev->hard_header_len);
		goto drop_skb;
	}

	if (pkt_size < data_size + CP2LC_DATA_HDR_SIZE){
		printk("DROP: hsl recv from cp error data size %d, pkt_size(%d)\n", data_size, pkt_size);
		goto drop_skb;
	}
#endif
    hsl_ctc_rx_cppkt(skb);
	return NET_RX_SUCCESS;

drop_skb:
	//vnd_dev->stats.rx_dropped++;
	//dev_put(vnd_dev);
no_dev:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static struct packet_type hsl_cp2chip_data_pkt_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_CP2LC_DATA),
	.func = hsl_ctc_cp2chip_data_skb_recv, /* CP2LC redir data packet receive method */
};



/* Initiailization. */
static int hsl_ctc_cp2chip_init(void)
{
    int ret = 0;

    HSL_FN_ENTER();

    ret = oss_sem_new("RxfromCP.Tx2chip sem", OSS_SEM_BINARY, 0, NULL, &hsl_ctc_cp2chip);
    if (ret < 0) {
        HSL_LOG(HSL_LOG_DEVDRV, HSL_LEVEL_ERROR,
                "Cannot create ethernet driver Tx synchronization semaphore\n");
        goto ERR;
    }

    hsl_ctc_cp2chip_thread_running = 1;
    skb_queue_head_init(&hsl_ctc_cp2chip_queue);
    
    /* Create thread for processing Tx. */
    ret = sal_task_create(&hsl_ctc_cp2chip_thread,
                          "zPktcp2chip", SAL_DEF_TASK_STACK_SIZE, 200, hsl_ctc_cp2chip_handler, NULL);
                          
    dev_add_pack(&hsl_cp2chip_data_pkt_type);
    HSL_FN_EXIT(0);
ERR:
    hsl_ctc_cp2chip_deinit();
    HSL_FN_EXIT(-1);
}

/* Deinitialization. */
static int hsl_ctc_cp2chip_deinit(void)
{
    struct sk_buff *skb;

    dev_remove_pack(&hsl_cp2chip_data_pkt_type);
    /* Cancel Tx thread. */
    if (hsl_ctc_cp2chip_thread) {
        hsl_ctc_cp2chip_thread = NULL;
    }
    
    /* Cancel Tx semaphore. */
    if (hsl_ctc_cp2chip) {
        oss_sem_delete(OSS_SEM_BINARY, hsl_ctc_cp2chip);
        hsl_ctc_cp2chip = NULL;
    }
    
    hsl_ctc_cp2chip_thread_running = 0;
    while ((skb = skb_dequeue(&hsl_ctc_cp2chip_queue)) != NULL)
        kfree_skb(skb);
    
    return 0;
}

/* Transmit a packet. */
static int hsl_ctc_rx_cppkt (struct sk_buff * skb)
{
    
    /* Post to tail. */
    skb_queue_tail (&hsl_ctc_cp2chip_queue, skb);
    
    /* Release semaphore. */
    oss_sem_unlock (OSS_SEM_BINARY, hsl_ctc_cp2chip);
    return 0;
}


//struct ctc_pkt_info_s
//{
//    uint32  flags;               /**< [GB] [RX,TX] flags of the packet, refer to ctc_pkt_flag_t */
//    uint16  dest_gport;          /**< [GB] [RX,TX] destination global port ID for unicast, include LinkAgg, valid if CTC_PKT_FLAG_MCAST is not set
//                                      Notice: if EthOAM Up MEP port is LinkAgg, should use an active member port ID but not LinkAgg port ID */
//    uint16  dest_group_id;       /**< [GB] [RX,TX] destination group ID for multicast, valid if CTC_PKT_FLAG_MCAST is set */
//    uint16  src_svid;            /**< [GB] [RX,TX] source S-VLAN ID */
//    uint16  src_cvid;            /**< [GB] [RX,TX] source C-VLAN ID */
//    uint16  src_port;            /**< [GB] [RX,TX] source port, valid for TX if CTC_PKT_FLAG_SRC_PORT_VALID is set, If c2c packet ,is stacking truck port*/
//    uint8   oper_type;           /**< [GB] [RX,TX] operation type, refer to ctc_pkt_oper_type_t */
//    uint8   priority;            /**< [GB] [RX,TX] priority of the packet, range is [0, 63] */
//    uint8   color;               /**< [GB] [RX,TX] color of the packet, refer to ctc_qos_color_t */
//    uint8   src_cos;             /**< [GB] [RX,TX] COS of the packet, range is [0, 7] */
//    uint8   ttl;                 /**< [GB] [RX,TX] TTL of the packet */
//    uint8   is_critical;         /**< [GB] [RX,TX] If set, indicate that the packet should not be droped in queue */
//    ctc_pkt_oam_info_t oam;      /**< [GB] [RX,TX] store OAM information, valid if oper_type is CTC_PKT_OPER_OAM */
//    ctc_pkt_ptp_info_t ptp;      /**< [GB] [RX,TX] store PTP information, valid if oper_type is CTC_PKT_OPER_PTP */
//    uint32  nh_offset;           /**< [GB] [TX] nexthop offset, valid if CTC_PKT_FLAG_NH_OFFSET_VALID flags is set */
//    uint8   hash;                /**< [GB] [TX] hash of LAG for load balance, valid if CTC_PKT_FLAG_HASH_VALID flags is set */
//    uint8   payload_offset;      /**< [GB] [RX] offset into the packet for start of payload */
//    uint8   resv0[2];            /**< [GB] Reserved for alignment */
//    ctc_pkt_cpu_reason_t reason; /**< [GB] [RX] packet to CPU reason */
//    uint16  vrfid;               /**< [GB] [RX] FID or VRFID */
//    uint8   packet_type;         /**< [GB] [RX] packet type, refer to ctc_parser_pkt_type_t */
//    uint8   src_chip;            /**< [GB] [RX] source chip ID */
//};
//typedef struct ctc_pkt_info_s ctc_pkt_info_t;

int hsl_ctc_tx2chip_vlan_flood(struct sk_buff *skb)
{
    cp_send_hdr_t *cp2lc_h;
    const char *frame;
    unsigned int frame_len;
    struct hsl_eth_header *eth;

	uint8 lchip = 0;
    uint8  gchip;
    uint8 has_hash=0;
    unsigned int gport=0;
	ctc_pkt_tx_t *p_ctc_pkt_tx = NULL;
	unsigned char *p_ctc_skb_data = NULL;
    int ret;
    uint16 member_port_total = 0;
    int txfailcnt = 0;
    uint16 vlan_id;
    unsigned int padding_len;
    struct hsl_eth_header *frame_ethhdr;
    struct hsl_eth_header *tx_ethhdr;
    
    if (!skb) {
        return -1;
    }

    cp2lc_h = (cp_send_hdr_t *)skb_mac_header(skb);
    frame = (const char *)skb_mac_header(skb) + CP2LC_DATA_HDR_SIZE;
    frame_len = ntohs(cp2lc_h->length);
    frame_ethhdr = (struct hsl_eth_header *)(frame);

    /* frame payload should not tagged, tag or not only depend cp2lc_h */
    if (frame_ethhdr->d.vlan.tag_type == HSL_ENET_8021Q_VLAN) {
        HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_WARN, "%s warn %s", __func__);
        return -1; 
    }
    p_ctc_pkt_tx = (ctc_pkt_tx_t *)sal_malloc(sizeof(ctc_pkt_tx_t));
    if (!p_ctc_pkt_tx) {
       return -1;
    }
	/* malloc and zero the packet struct */
	sal_memset(p_ctc_pkt_tx, 0, sizeof(ctc_pkt_tx_t));

	p_ctc_pkt_tx->mode = CTC_PKT_MODE_DMA;

	p_ctc_pkt_tx->tx_info.oper_type = CTC_PKT_OPER_NORMAL;
	p_ctc_pkt_tx->tx_info.is_critical = 1;
    if (VND_INDEX_VNETDEV_BASE <= cp2lc_h->ifindex 
      && cp2lc_h->ifindex  < VND_INDEX_VLAN_BASE) {/* phy if */
        vlan_id = HSL_DEFAULT_VID;
        return 0;
	} else {/* vlan if */
	    vlan_id = hsl_ctc_ifindex2vid(cp2lc_h->ifindex);
	    p_ctc_pkt_tx->tx_info.src_svid = vlan_id;
	    p_ctc_pkt_tx->tx_info.flags |= CTC_PKT_FLAG_SRC_SVID_VALID;
    }

    //p_ctc_pkt_tx->tx_info.flags |= CTC_PKT_FLAG_NH_OFFSET_BYPASS;

	p_ctc_pkt_tx->tx_info.ttl = 0;

    padding_len = 0;
    if((frame_len % 4) != 0) {
          padding_len = 4 - (frame_len % 4);
    }
    
	ctc_get_local_chip_num(&lchip);
	p_ctc_pkt_tx->lchip = lchip;
	ctc_get_gchip_id(lchip, &gchip);
	/* iter vlan members */
    {
        ctc_port_bitmap_t port_bitmap = {0};
        ctc_port_bitmap_t port_bitmap_tagged = {0};
        uint16 gport = 0;
        uint16 bit_cnt = 0;
        int value_link_up;
    
        ret = ctc_vlan_get_ports(vlan_id, gchip, port_bitmap);
        if (ret < 0) {
            HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_WARN, "%s err %s", __func__, ctc_get_error_desc(ret));
            goto ERROR_OUT;
        }
        ret = ctc_vlan_get_tagged_ports(vlan_id, gchip, port_bitmap_tagged);
        if (ret < 0) {
            HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_WARN, "%s err %s", __func__, ctc_get_error_desc(ret));
            goto ERROR_OUT;
        }
        for (bit_cnt = 0; bit_cnt < MAX_PORT_NUM_PER_CHIP; bit_cnt++) {
            gport = CTC_MAP_LPORT_TO_GPORT(gchip, bit_cnt);
            if (CTC_BMP_ISSET(port_bitmap, bit_cnt)) {
                p_ctc_pkt_tx->tx_info.dest_gport = gport;
                if(0 && has_hash) {
                    p_ctc_pkt_tx->tx_info.flags |= CTC_PKT_FLAG_HASH_VALID;
                }
                value_link_up = 0;
                ctc_port_get_mac_link_up(gport, &value_link_up);
                if (value_link_up == 0) {
                    continue;
                }
                if (CTC_BMP_ISSET(port_bitmap_tagged, bit_cnt)) { /* tagged */
                    //hsl_ctc_dump_pktfromchip_info(&p_ctc_pkt_tx->tx_info, 1);
                    /* upper layer ensure frame payload without tags */
                    ctc_packet_skb_init(&(p_ctc_pkt_tx->skb));
                    p_ctc_skb_data = ctc_packet_skb_put(&(p_ctc_pkt_tx->skb), frame_len + HSL_ETH_TAG_SIZE);
                    tx_ethhdr = (struct hsl_eth_header *)p_ctc_skb_data;
                    sal_memcpy ((char *)tx_ethhdr, frame_ethhdr->dmac, HSL_ETHER_ADDRLEN);
                    sal_memcpy ((char *)tx_ethhdr->smac, frame_ethhdr->smac, HSL_ETHER_ADDRLEN);
                    tx_ethhdr->d.vlan.tag_type = htons(0x8100);
                    tx_ethhdr->d.vlan.pri_cif_vid = HSL_ETH_VLAN_CTRL(0, 0, vlan_id);
                    tx_ethhdr->d.vlan.type = frame_ethhdr->d.type;
                    sal_memcpy (p_ctc_skb_data+HSL_ETH_UNTAGGED_HDR_LEN+HSL_ETH_TAG_SIZE,
                        frame+HSL_ETH_UNTAGGED_HDR_LEN, frame_len-HSL_ETH_UNTAGGED_HDR_LEN);
         

                    ret = ctc_packet_tx(p_ctc_pkt_tx); 
                    if(ret <0) {
                        txfailcnt++;
                        HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "ctc_packet_tx err %s", ctc_get_error_desc(ret));
                    }
                } else {/* Untagged */
                    //hsl_ctc_dump_pktfromchip_info(&p_ctc_pkt_tx->tx_info, 1);
                    ctc_packet_skb_init(&(p_ctc_pkt_tx->skb));
                    p_ctc_skb_data = ctc_packet_skb_put(&(p_ctc_pkt_tx->skb), frame_len);
                    sal_memcpy (p_ctc_skb_data, frame, frame_len);
                    ret = ctc_packet_tx(p_ctc_pkt_tx);
                    if(ret <0) {
                        txfailcnt++;
                        HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_ERROR, "ctc_packet_tx err %s", ctc_get_error_desc(ret));
                    }
                }
                member_port_total++;
            }
        }
    
    } /* iter vlan member end */
    if (txfailcnt > 0) {
        HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_WARN, "%s vlan%d flood %d pkts, %d failed",
            __func__, vlan_id, member_port_total, txfailcnt);
    }

ERROR_OUT:
    sal_free(p_ctc_pkt_tx);
    return 0;


}

int hsl_ctc_tx2chip_getdgport_by_skb(struct sk_buff *skb, unsigned short *dest_gport, int *is_hash)
{
    cp_send_hdr_t *cp2lc_h;
    const char *frame;
    unsigned int frame_len;
    struct hsl_eth_header *eth;

    int has_vlan;
	ctc_pkt_tx_t *p_ctc_pkt_tx;
	unsigned char *p_ctc_skb_data = NULL;
    int ret;

    fdb_search_type search_type;
    fdb_entry_t key_entry;
    fdb_entry_t fdb_entry;
    unsigned int vlan_id;
    
    if (!skb) {
        return -1;
    }

    cp2lc_h = (cp_send_hdr_t *)skb_mac_header(skb);
    frame = (const char *)skb_mac_header(skb) + CP2LC_DATA_HDR_SIZE;
    frame_len = ntohs(cp2lc_h->length);
    eth = (struct hsl_eth_header *)frame;
    
    if (VND_INDEX_VNETDEV_BASE <= cp2lc_h->ifindex 
      && cp2lc_h->ifindex  < VND_INDEX_VLAN_BASE) {/* phy if */
        has_vlan = 0;
        vlan_id = HSL_DEFAULT_VID;
        search_type = SEARCH_BY_MAC;
	} else {/* vlan if */
        has_vlan = 1;
        vlan_id = hsl_ctc_ifindex2vid(cp2lc_h->ifindex);
        search_type = SEARCH_BY_VLAN_MAC;
    }
    key_entry.vid = vlan_id;
    memcpy(key_entry.mac_addr, eth->dmac, HSL_ETHER_ADDRLEN);
    
    ret = hsl_get_fdb_entry(&fdb_entry, search_type, &key_entry);
    if (ret != STATUS_OK) {
        return -1;
    }
    
    *dest_gport = fdb_entry.port_no;
    *is_hash = 0; /* tobe fix */
    return 0;

}

int hsl_ctc_tx2chip_try_unicast(struct sk_buff *skb)
{
    cp_send_hdr_t *cp2lc_h;
    const char *frame;
    unsigned int frame_len;
    struct hsl_eth_header *frame_ethhdr;
    struct hsl_eth_header *tx_ethhdr;

	uint8 lchip = 0;
	uint8 gchip = 0;
	unsigned short dest_gport = 0;
    unsigned int lport;
    int is_hash= 0 ;
	ctc_pkt_tx_t *p_ctc_pkt_tx;
	unsigned char *p_ctc_skb_data = NULL;
    int ret;
    unsigned int padding_len;
    unsigned int vlan_id;
    ctc_port_bitmap_t port_bitmap_tagged = {0};
    
    if (!skb) {
        return HSL_CTC_TRY_TRY_UNICAST_FAIL;
    }

    cp2lc_h = (cp_send_hdr_t *)skb_mac_header(skb);
    frame = (const char *)skb_mac_header(skb) + CP2LC_DATA_HDR_SIZE;
    frame_len = ntohs(cp2lc_h->length);
    frame_ethhdr = (struct hsl_eth_header *)frame;
    

    p_ctc_pkt_tx = (ctc_pkt_tx_t *)sal_malloc(sizeof(ctc_pkt_tx_t));
    if (!p_ctc_pkt_tx) {
       return HSL_CTC_TRY_TRY_UNICAST_FAIL;
    }
	/* malloc and zero the packet struct */
	sal_memset(p_ctc_pkt_tx, 0, sizeof(ctc_pkt_tx_t));

	ctc_get_local_chip_num(&lchip);
	p_ctc_pkt_tx->lchip = lchip;

    if (VND_INDEX_VNETDEV_BASE <= cp2lc_h->ifindex 
      && cp2lc_h->ifindex  < VND_INDEX_VLAN_BASE) {/* phy if */
        vlan_id = HSL_DEFAULT_VID;
        dest_gport = IFINDEX_TO_GPORT(ntohs(cp2lc_h->ifindex));
        p_ctc_pkt_tx->tx_info.dest_gport = dest_gport;

	} else {/* vlan if */
        vlan_id = hsl_ctc_ifindex2vid(cp2lc_h->ifindex);
	    ret = hsl_ctc_tx2chip_getdgport_by_skb(skb, &dest_gport, &is_hash);
	    if (ret <0 ) {
            goto ERROR_OUT;
	    }
        p_ctc_pkt_tx->tx_info.dest_gport = dest_gport;
        p_ctc_pkt_tx->tx_info.flags |= CTC_PKT_FLAG_SRC_SVID_VALID;
        if(is_hash) {
            p_ctc_pkt_tx->tx_info.flags |= CTC_PKT_FLAG_HASH_VALID;
        }

    }

	p_ctc_pkt_tx->mode = CTC_PKT_MODE_DMA;
    
	p_ctc_pkt_tx->tx_info.oper_type = CTC_PKT_OPER_NORMAL;
	p_ctc_pkt_tx->tx_info.is_critical = 1;

    //p_ctc_pkt_tx->tx_info.flags |= CTC_PKT_FLAG_NH_OFFSET_BYPASS;

	p_ctc_pkt_tx->tx_info.ttl = 0;

    padding_len = 0;
    if((frame_len % 4)!= 0) {
          padding_len = 4 - (frame_len % 4);
    }
	ctc_get_local_chip_num(&lchip);
	ctc_get_gchip_id(lchip, &gchip);
    lport = CTC_MAP_GPORT_TO_LPORT(dest_gport); 

    ret = ctc_vlan_get_tagged_ports(vlan_id, gchip, port_bitmap_tagged);
    if (ret < 0) {
        HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_WARN, "%s err %s", __func__, ctc_get_error_desc(ret));
        goto ERROR_OUT;
    }
    if (CTC_BMP_ISSET(port_bitmap_tagged, lport)) {
        ctc_packet_skb_init(&(p_ctc_pkt_tx->skb));
        p_ctc_skb_data = ctc_packet_skb_put(&(p_ctc_pkt_tx->skb), frame_len + HSL_ETH_TAG_SIZE);
        tx_ethhdr = (struct hsl_eth_header *)p_ctc_skb_data;
        sal_memcpy ((char *)tx_ethhdr, frame_ethhdr->dmac, HSL_ETHER_ADDRLEN);
        sal_memcpy ((char *)tx_ethhdr->smac, frame_ethhdr->smac, HSL_ETHER_ADDRLEN);
        tx_ethhdr->d.vlan.tag_type = htons(0x8100);
        tx_ethhdr->d.vlan.pri_cif_vid = HSL_ETH_VLAN_CTRL(0, 0, vlan_id);
        tx_ethhdr->d.vlan.type = frame_ethhdr->d.type;
        sal_memcpy (p_ctc_skb_data+HSL_ETH_UNTAGGED_HDR_LEN+HSL_ETH_TAG_SIZE,
            frame+HSL_ETH_UNTAGGED_HDR_LEN, frame_len-HSL_ETH_UNTAGGED_HDR_LEN);
    } else {
	    /* add packet to ctc skb buffer */
	    ctc_packet_skb_init(&(p_ctc_pkt_tx->skb));
	    p_ctc_skb_data = ctc_packet_skb_put(&(p_ctc_pkt_tx->skb), frame_len);
	    sal_memcpy (p_ctc_skb_data, frame, frame_len);
    }
	
    ret = ctc_packet_tx(p_ctc_pkt_tx);
    if (ret < 0) {
        HSL_LOG(HSL_LOG_PLATFORM, HSL_LEVEL_WARN, "ctc_packet_tx err %s", ctc_get_error_desc(ret));
    }
    sal_free(p_ctc_pkt_tx);
    return HSL_CTC_TRY_TRY_UNICAST_OK;
 ERROR_OUT:
    sal_free(p_ctc_pkt_tx);
    return HSL_CTC_TRY_TRY_UNICAST_FAIL;  
}

/* Tx a skb out on a interface. */
int hsl_ctc_tx2chip_process(struct sk_buff *skb)
{
    cp_send_hdr_t *cp2lc_h;
    const char *frame;
    unsigned int frame_len;
    struct hsl_eth_header *eth;

    int try_unicast;
    
    if (!skb) {
        return -1;
    }

    /* 有待补充合法性检查, 长度 ifindex等检查 */
    cp2lc_h = (cp_send_hdr_t *)skb_mac_header(skb);
    frame = (const char *)skb_mac_header(skb) + CP2LC_DATA_HDR_SIZE;
    frame_len = ntohs(cp2lc_h->length);
    eth = (struct hsl_eth_header *)frame;

#if 0
    {
        printk("cp2lc hdr:\n");
        hsl_ctc_dump_hex8((unsigned char *)cp2lc_h, CP2LC_DATA_HDR_SIZE);
        printk("frame payload:\n");
        hsl_ctc_dump_hex8((unsigned char *)frame, frame_len);
    }
#endif


	/* packet length check */
	if(frame_len > (CTC_PKT_MTU - CTC_PKT_HDR_ROOM)) {
        goto err_out;
    }
    if (MACADDR_IS_MULTICAST(eth->dmac)) {
        hsl_ctc_tx2chip_vlan_flood(skb);
    } else {
        try_unicast = hsl_ctc_tx2chip_try_unicast(skb);
        if (try_unicast != HSL_CTC_TRY_TRY_UNICAST_OK) {
            hsl_ctc_tx2chip_vlan_flood(skb);
        }

    }
    
err_out:
    /* Free skb. */
    kfree_skb(skb);
    return 0;
}


/* Tx thread. */
void hsl_ctc_cp2chip_handler(void *notused)
{
    int ret = 0;

    struct sk_buff *skb;

    while (hsl_ctc_cp2chip_thread_running) {
        while ((skb = skb_dequeue(&hsl_ctc_cp2chip_queue)) != NULL) {
            ret = hsl_ctc_tx2chip_process(skb);
            if (ret < 0) {
                ;
            }
        }
        oss_sem_lock(OSS_SEM_BINARY, hsl_ctc_cp2chip, OSS_WAIT_FOREVER);
    }
    return;
}

