#include "config.h"
#include "hsl_os.h"

#include "hsl_types.h"

/* HAL includes. */
#include "hal_netlink.h"
#include "hal_msg.h"

/* HSL includes.*/
#include "hsl_logger.h"
#include "hsl_ether.h"
#include "hsl.h"
#include "hsl_ifmgr.h"
#include "hsl_if_hw.h"
#include "hsl_if_os.h"
#include "hsl_ctc_pkt.h"
#include "hsl_comm.h"
#include "hsl_msg.h"
#include "hsl_ctc_if.h"

//#include "stdio.h"
#include "hal/layer4/acl/access_list_rule.h"
#include "layer4/qos/qos.h"
#include "hal/layer4/qos/qos_rule.h"
#include "hal/layer4/hal_l4_api.h"
#include <linux/list.h>
#include <linux/types.h>
//#include "syslog.h"
#include "bcm_cap.h"
#include "layer4/qos/qos.h"
#include "layer4/ipcls.h"
#include "bcm_l4_debug.h"
#include "acl_build.h"
#include "qos_build.h"
#include "bcm_l4_debug.h"

#include "ctc_if_portmap.h"


#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, head, member)				\
	((pos)->member.next == (head))? NULL :  \
			list_entry((pos)->member.next, typeof(*pos), member)
#define        PORT_MAX_NUM        64

static u32 drr_weight_to_kbytes[FB_DRR_WEIGHT_MAX + 1] = {
    /* Weight         Kbytes    */
#if 0
    /*  0 */    0 * FB_DRR_KBYTES,  /*    0K bytes - pure priority scheduling */
    /*  1 */   10 * FB_DRR_KBYTES,  /*   10K bytes */
    /*  2 */   20 * FB_DRR_KBYTES,  /*   20K bytes */
    /*  3 */   40 * FB_DRR_KBYTES,  /*   40K bytes */
    /*  4 */   80 * FB_DRR_KBYTES,  /*   80K bytes */
    /*  5 */  160 * FB_DRR_KBYTES,  /*  160K bytes */
    /*  6 */  320 * FB_DRR_KBYTES,  /*  320K bytes */
    /*  7 */  640 * FB_DRR_KBYTES,  /*  640K bytes */
    /*  8 */ 1280 * FB_DRR_KBYTES,  /* 1280K bytes */
    /*  9 */ 2560 * FB_DRR_KBYTES,  /* 2560K bytes */
    /* 10 */ 5120 * FB_DRR_KBYTES,  /* 5120K bytes */
    /* 11 */   10 * FB_DRR_MBYTES,  /*   10M bytes */
    /* 12 */   20 * FB_DRR_MBYTES,  /*   20M bytes */
    /* 13 */   40 * FB_DRR_MBYTES,  /*   40M bytes */
    /* 14 */   80 * FB_DRR_MBYTES,  /*   80M bytes */
    /* 15 */  160 * FB_DRR_MBYTES   /*  160M bytes */
#endif
	/*  0 */   0 * FB_DRR_KBYTES,  /*    0K bytes - pure priority scheduling */
    /*  1 */   2 * FB_DRR_KBYTES,  /*   20K bytes */
    /*  2 */   4 * FB_DRR_KBYTES,  /*   40K bytes */
    /*  3 */   8 * FB_DRR_KBYTES,  /*   80K bytes */
    /*  4 */  16 * FB_DRR_KBYTES,  /*  160K bytes */
    /*  5 */  32 * FB_DRR_KBYTES,  /*  320K bytes */
    /*  6 */  64 * FB_DRR_KBYTES,  /*  640K bytes */
    /*  7 */ 128 * FB_DRR_KBYTES,  /* 1280K bytes */
    /*  8 */ 256 * FB_DRR_KBYTES,  /* 2560K bytes */
    /*  9 */ 512 * FB_DRR_KBYTES,  /* 5120K bytes */
    /* 10 */   1 * FB_DRR_MBYTES,  /*   10M bytes */
    /* 11 */   2 * FB_DRR_MBYTES,  /*   20M bytes */
    /* 12 */   4 * FB_DRR_MBYTES,  /*   40M bytes */
    /* 13 */   8 * FB_DRR_MBYTES,  /*   80M bytes */
    /* 14 */  16 * FB_DRR_MBYTES   /*  160M bytes */
	
};

struct qos_flowq_s {
	struct hal_qos_flowq_info_s flowq[MAX_BCM_FLOWQ];
};
struct qos_flowq_s qos_flowq[PORT_MAX_NUM];


int bcm_qos_weight_to_kbps(int weight)
{
	if (weight < 0 || weight > 15)
		return 0;

	return drr_weight_to_kbytes[weight];
}

/*
	计算一个acl里有几个permit的策略
*/
static int qos_acl_entry_num(struct entry_msg_s *acl,  int max_entry)
{
	int	count, i;
	struct access_entry_hdr	*ep;
	count = 0;
	
	for (i = 0; i < max_entry; i++) {
		ep = &acl->grp_entry[i].entry;
		if (ep->permit == ACL_PERMIT)
			count++;
	}
	
	return count;
}

/*
	构造一组ACL
*/
static int qos_build_acl_group(struct entry_msg_s *acl, 
		cap_sub_info_t *sub, struct list_head *cluster, int acl_entry_num)
{
#if 1
	int	rc, i;
	list_t	*node;
	uint32	eid;
	struct access_entry_hdr	*entry;
	ctc_acl_entry_t *ctc_entry;

	node = list_first_entry(cluster, list_t, list);

	for (i = 0; i < acl_entry_num; i++){
		entry = &acl->grp_entry[i].entry;
			
		if (entry->permit != ACL_PERMIT)
			continue;
		

		ctc_entry = (ctc_acl_entry_t *)node->data;
		ctc_entry->key.type = CTC_ACL_KEY_IPV4;
		
		switch (entry->type) {
		case ACCESS_ENTRY_TYPE_STD_IP:
			rc = ctc_build_acl_std(ctc_entry, (struct std_access_entry *)entry, sub);
			break;
		case ACCESS_ENTRY_TYPE_EXT_IP:
			rc = ctc_build_acl_ext_ip(ctc_entry, (struct ext_ip_access_entry *)entry, sub);
			break;
		case ACCESS_ENTRY_TYPE_EXT_UDP:
			rc = ctc_build_acl_udp(ctc_entry, (struct ext_udp_access_entry *)entry, sub);
			break;
		case ACCESS_ENTRY_TYPE_EXT_TCP:
			rc = ctc_build_acl_tcp(ctc_entry, (struct ext_tcp_access_entry *)entry, sub);
			break;
		case ACCESS_ENTRY_TYPE_EXT_ICMP:
			rc = ctc_build_acl_icmp(ctc_entry, (struct ext_icmp_access_entry *)entry, sub);
			break;
		default:
			HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "ipf_build_acl_for_slot(ACL %s), unknow acl entry type=%d, ignore\n\r", 
				acl->grp_entry[i].grp_id, entry->type);
			return ERROR;
		}
		if (rc != OK) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "qos_build_acl_group failed\n\r");
			return ERROR;
		}
	}
#endif	
	return OK;
}

#define CTC_IS_BIT_SET(flag, bit)   (((flag) & (1 << (bit))) ? 1 : 0)
#define CTC_BIT_SET(flag, bit)      ((flag) = (flag) | (1 << (bit)))
#define CTC_BIT_UNSET(flag, bit)    ((flag) = (flag) & (~(1 << (bit))))


struct list_head *qos_cap_alloc_cluster(cap_sub_info_t *sub, int num,
		bool dir_in, int lport, int *p_group_id, ctc_acl_group_info_t *ctc_group)
{
	int	rc;
	struct list_head	*list_h;
	list_t	*node;
	cap_info_t	*cap = sub->cap;
	l4_pbmp_t pbmp;
	int group_id;
	int block_id = -1;
#if 1
	printk("\n<%s>[%s]:%d\t", __FILE__, __FUNCTION__, __LINE__);
	if ((list_h = cap_alloc_entry_cluster(sub, num, &block_id)) == NULL)
		return NULL;

	/*构造端口位图*/
	
	memset(ctc_group, 0, sizeof(ctc_acl_group_info_t));
	printk("qos_cap_alloc_cluster, lport = %d\r\n", lport);
	CTC_BIT_SET(ctc_group->un.port_bitmap[lport /CTC_UINT32_BITS], (lport %CTC_UINT32_BITS));

	ctc_group->lchip = 0;
	ctc_group->dir = CTC_INGRESS;

	if (dir_in) {
		ctc_group->type = CTC_ACL_GROUP_TYPE_PORT_BITMAP;
		ctc_group->dir = CTC_INGRESS;		
	} else { /* dir out */
		ctc_group->type = CTC_ACL_GROUP_TYPE_PORT_BITMAP;		
		ctc_group->dir = CTC_EGRESS;		
	}
	
	group_id = group_id_create();
	*p_group_id = group_id;
	
#endif
	return list_h;

err:
	cap_free_entry_cluster(cap, list_h);
	return NULL;
}

struct list_head *qos_build_acl(
		struct entry_msg_s *acl, 
		cap_sub_info_t *sub,
		bool	dir_in,
		int lport,
		int acl_entry_num,
		int *group_id,
		ctc_acl_group_info_t *ctc_group)
{
	int	num;
	struct list_head	*cluster;

	
	printk("\n<%s>[%s]:%d\t", __FILE__, __FUNCTION__, __LINE__);
	num = qos_acl_entry_num(acl, acl_entry_num);
	if (num == 0) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "ACL have none entry\n\r");
		return NULL;// what to do??? 
	}
	cluster = qos_cap_alloc_cluster(sub, num, dir_in, lport, group_id, ctc_group);
	if (cluster == NULL) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "alloc %d entry failed\n\r", num);
		return NULL;
	}
	HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "alloc %d entry success\n\r", num);

	if (OK != qos_build_acl_group(acl, sub, cluster, acl_entry_num)) {
		cap_free_entry_cluster(sub->cap, cluster);
		return NULL;
	}

	return cluster;
}

/*
	return:
		= NULL: error
		other: ok
*/

struct list_head *qos_build_one_match_entry(
		cap_sub_info_t *sub,
		bool	dir_in,
		int lport,
		int *group_id,
		ctc_acl_group_info_t *ctc_group)
{
	struct list_head	*cluster;
	int	rc;

	cluster = qos_cap_alloc_cluster(sub, 1, dir_in, lport, group_id, ctc_group);
	if (cluster == NULL)
		return NULL;

	return cluster;

err:	
	/* free resource */
	cap_free_entry_cluster(sub->cap, cluster);
	return NULL;
}

int qualify_in_port(int eid, int lport, u8 no_use)
{	
	//return bcmx_field_qualify_InPort(eid, lport);
	return 0;
}

int qualify_in_vlan(int eid, u16 vid, u8 no_use)
{
	int rc;
	u16 vid_mask = 0x3FFF;
#if 0
	rc = bcmx_field_qualify_OuterVlan(eid, vid, vid_mask);
	if (rc != BCM_E_NONE){
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "bcm_field_qualify_OuterVlan(%d, %d, %d)failed, rc = %d.\r\n", 
			eid, vid, vid_mask, rc);
		return ERROR;
	}
#endif	
	return OK;
}

struct list_head *qos_build_class_map_internal(cap_sub_info_t *sub, int gport, 
	void *ptr, int type, bool dir_in, int acl_entry_num, int *group_id)
{
	int rc;
	struct list_head	*cluster;
	struct cm_match_dscp *dscp;
	struct cm_match_precedence	*prec;
	struct cm_match_protocol	*proto;
	struct cm_match_iif		*iif;
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;
	list_t	*node;
	ctc_acl_entry_t *ctc_entry;
	ctc_acl_group_info_t ctc_group;
#if 1
	uint32 in_lport;
	hsl_vid_t vid;
	cap_sub_info_t *ip6_sub;
	cap_info_t	*cap = sub->cap;

	if(cap == NULL)
		return NULL;
	
	cluster = NULL;
	
	switch (type) {
	case CM_MATCH_ACL:
		cluster = qos_build_acl((struct entry_msg_s *)ptr, sub, dir_in, gport, acl_entry_num, group_id, &ctc_group);
		break;
	case CM_MATCH_IIF:
		if (dir_in) {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "Build qos rule failed: not support 'match interface' on ingress directory\n\r");
			return NULL;
		}
		iif = ptr;
		
		/*add qualify vlan here*/
		ifp = hsl_ifmgr_lookup_by_index(iif->ifindex);
		
		if (iif->ifindex > HSL_L2_IFINDEX_START) {
			/* 物理接口 */
			bcmif = (struct hsl_bcm_if *)ifp->system_info;
			in_lport = bcmif->u.l2.lport;

			cluster = qos_build_one_match_entry(sub, dir_in, gport, group_id, &ctc_group);	
			ctc_group.type = CTC_ACL_GROUP_TYPE_PORT_BITMAP;
			ctc_group.dir = CTC_INGRESS;
			CTC_BIT_SET(ctc_group.un.port_bitmap[in_lport /CTC_UINT32_BITS], (in_lport %CTC_UINT32_BITS));			
		}
		if (iif->ifindex <= HSL_L2_IFINDEX_START) {
			/* vlan接口 */
			vid = ifp->u.ip.vid;
			cluster = qos_build_one_match_entry(sub, dir_in, gport, group_id, &ctc_group);
			node = list_first_entry(cluster, list_t, list);
			ctc_entry = (ctc_acl_entry_t *)node->data;
			ctc_entry->key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_SVLAN;
			ctc_entry->key.u.ipv4_key.svlan = vid;
			ctc_entry->key.u.ipv4_key.svlan_mask = 0x1fff;		
			
		}
		
		break;

	case CM_MATCH_DSCP:
		dscp = ptr;
		cluster = qos_build_one_match_entry(sub, dir_in, gport, group_id, &ctc_group);
		node = list_first_entry(cluster, list_t, list);
		ctc_entry = (ctc_acl_entry_t *)node->data;
		ctc_entry->key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_DSCP;
		ctc_entry->key.u.ipv4_key.dscp = dscp->value;
		ctc_entry->key.u.ipv4_key.dscp_mask = 0xfc;
		printk("TOS value = %#x, mask = %#x\r\n", dscp->value, 0xfc);


		break;
		
	case CM_MATCH_IPV6_DSCP:
		if (dir_in)
			ip6_sub = &cap->sub[CS_QOS_IPV6_IN];
		else
			ip6_sub = &cap->sub[CS_QOS_IPV6_OUT];
		dscp = ptr;
		cluster = qos_build_one_match_entry(ip6_sub, dir_in, gport, group_id, &ctc_group);
		break;	
		
	case CM_MATCH_PRECEDENCE:
		prec = ptr;
		cluster = qos_build_one_match_entry(sub, dir_in, gport, group_id, &ctc_group);
		break;
		
	case CM_MATCH_IPV6_PRECEDENCE:

		return NULL;
		if (dir_in)
			ip6_sub = &cap->sub[CS_QOS_IPV6_IN];
		else
			ip6_sub = &cap->sub[CS_QOS_IPV6_OUT];
		prec = ptr;
		cluster = qos_build_one_match_entry(ip6_sub, dir_in, gport, group_id, &ctc_group);
		break;
		
	case CM_MATCH_PROTOCOL:
		proto = ptr;
		cluster = qos_build_one_match_entry(sub, dir_in, gport, group_id, &ctc_group);
		node = list_first_entry(cluster, list_t, list);
		ctc_entry = (ctc_acl_entry_t *)node->data;
		ctc_entry->key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_L4_PROTOCOL;
		ctc_entry->key.u.ipv4_key.dscp = proto->value;
		ctc_entry->key.u.ipv4_key.dscp_mask = 0xff;
		printk("TOS value = %#x, mask = %#x\r\n", proto->value, 0xff);

		break;
		
	default: /* CLASS_DEFAULT or 'match any' */
		cluster = qos_build_one_match_entry(sub, dir_in, gport, group_id, &ctc_group);
		break;
	}

	rc = ctc_acl_create_group(*group_id, &ctc_group);
	if (CTC_E_NONE != rc) {
		printk("ctc_acl_create_group, rc = %d\r\n", rc);
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "ifp group create fail, ret = %d\n\r", rc);
		cap_free_entry_cluster(sub->cap, cluster);
		return NULL;
	}			

	/*保存该group id，重新构造时需要对已有的group进行清理*/
	if (-1 == group_id_list_add(cap, *group_id)) {
		printk("group_id_list_add fail\r\n");
		cap_free_entry_cluster(sub->cap, cluster);
		return NULL;
	}
	
#endif
	return cluster;
}

/*
	return:
		< 0: error
		>= 0: flowq number
	把队列0保留给默认队列
*/
static int qos_flowq_alloc(u32 ifindex, bool is_lls, bool is_default)
{
	int	fq; /* flowq */
	struct hal_qos_flowq_info_s *flowq;

	flowq = qos_flowq[ifindex - HSL_L2_IFINDEX_START].flowq;
	/* 默认流队列使用0;其它的如果是LLS流队列，从高优先级开始申请，其它的从低优先级开始申请 */
	if (is_default) {
		fq = 0;
	} else if (is_lls) {
		for (fq = MAX_BCM_FLOWQ - 1; fq > 0; fq--) {
			if (!(&flowq[fq])->used)
				break;
		}
		if (fq <= 0)
			return -1;
	} else {
		for (fq = 1; fq < MAX_BCM_FLOWQ; fq++) {
			if (!(&flowq[fq])->used)
				break;
		}
		if (fq >= MAX_BCM_FLOWQ)
			return -1;
	}

	(&flowq[fq])->used = TRUE;
	return fq;
}

void qos_flowq_free(u32 ifindex, int fq)
{
	struct hal_qos_flowq_info_s *flowq;

	flowq = qos_flowq[ifindex - HSL_L2_IFINDEX_START].flowq;
	
	(&flowq[fq])->used = FALSE;
	(&flowq[fq])->weight = 0;
}

static int qos_flowq_reset(u32 ifindex)
{
	int	rc, i;
	bool have_config;
	int	weight[MAX_BCM_FLOWQ];
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;

	ctc_qos_sched_t	sched_param;
	uint32 gport;
	struct hal_qos_flowq_info_s *flowq;
	int ifspeed;

	flowq = qos_flowq[ifindex - HSL_L2_IFINDEX_START].flowq;

	/* 检查之前在该接口配置过没有 */
	have_config = FALSE;
	for (i = 0; i < MAX_BCM_FLOWQ; i++) {
		if (flowq[i].used) {
			have_config = TRUE;
			break;
		}
	}
	memset(flowq, 0, sizeof(struct hal_qos_flowq_info_s) * MAX_BCM_FLOWQ);

	if (!have_config)
		return OK;

	ifp = hsl_ifmgr_lookup_by_index(ifindex);
	bcmif = (struct hsl_bcm_if *)ifp->system_info;
	gport = bcmif->u.l2.lport;
	ifspeed = ifp->u.l2_ethernet.speed;

	HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "reset %s flowq sched to SR\n\r", ifp->name);
	memset(&sched_param, 0, sizeof(sched_param));
	sched_param.type = CTC_QOS_SCHED_QUEUE;
    sched_param.sched.queue_sched.queue.queue_type = CTC_QUEUE_TYPE_NETWORK_EGRESS;
    sched_param.sched.queue_sched.queue.gport = gport;	
	for (i = 0; i < MAX_BCM_FLOWQ; i++){
		sched_param.sched.queue_sched.queue.queue_id = i;


		sched_param.sched.queue_sched.cfg_type = CTC_QOS_SCHED_CFG_CONFIRM_CLASS;		
        sched_param.sched.queue_sched.confirm_class = i;
		rc = ctc_qos_set_sched(&sched_param);
        if (rc < 0)
        {
            printk("%% ctc_qos_set_sched excrrd class  error, ret = %d\r\n", rc);
            return ERROR;
        }

		sched_param.sched.queue_sched.cfg_type = CTC_QOS_SCHED_CFG_EXCEED_CLASS;
        sched_param.sched.queue_sched.exceed_class = i;		
		rc = ctc_qos_set_sched(&sched_param);
        if (rc < 0)
        {
            printk("%% ctc_qos_set_sched excrrd class error, ret = %d\r\n", rc);
            return ERROR;
        }

		sched_param.sched.queue_sched.cfg_type = CTC_QOS_SCHED_CFG_CONFIRM_WEIGHT;
		sched_param.sched.queue_sched.confirm_weight = 1;
		rc = ctc_qos_set_sched(&sched_param);
        if (rc < 0)
        {
            printk("%% ctc_qos_set_sched confirm weight error, ret = %d\r\n", rc);
            return ERROR;
        }

		sched_param.sched.queue_sched.exceed_weight = 1;
		sched_param.sched.queue_sched.cfg_type = CTC_QOS_SCHED_CFG_EXCEED_WEIGHT;
		rc = ctc_qos_set_sched(&sched_param);
        if (rc < 0)
        {
            printk("%% ctc_qos_set_sched excrrd weight error, ret = %d\r\n", rc);
            return ERROR;
        }
		

	}

#if 0
	HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "  %s flowq reset to (0 - %d) before build out action.\n\r",
			ifp->name, ifspeed);
	for (i = 0; i < MAX_BCM_FLOWQ; i++){
		rc = bcmx_cosq_port_bandwidth_set(lport, i, 0, ifspeed, 0);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "bcm_cosq_port_bandwidth_set failed, rc=%d\n\r", rc);
			bcmx_lplist_free(&lplist);
			return ERROR;
		}
	}
#endif 

	return OK;
}
/*
	include filter and field
*/
static int qos_flowq_build(u32 ifindex)
{
	int rc, i, used;
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;

	ctc_qos_sched_t	sched_param;
	uint32 gport;
	struct hal_qos_flowq_info_s *flowq;

	flowq = qos_flowq[ifindex - HSL_L2_IFINDEX_START].flowq;


	ifp = hsl_ifmgr_lookup_by_index(ifindex);
	bcmif = (struct hsl_bcm_if *)ifp->system_info;
	gport = bcmif->u.l2.lport;


	memset(&sched_param, 0, sizeof(sched_param));
	sched_param.type = CTC_QOS_SCHED_QUEUE;
    sched_param.sched.queue_sched.queue.queue_type = CTC_QUEUE_TYPE_NETWORK_EGRESS;
    sched_param.sched.queue_sched.queue.gport = gport;


	for (i = 0, used = FALSE; i < MAX_BCM_FLOWQ; i++) {
		
		sched_param.sched.queue_sched.queue.queue_id = i;



		sched_param.sched.queue_sched.cfg_type = CTC_QOS_SCHED_CFG_CONFIRM_CLASS;
		/* 默认使用class 0 */
        sched_param.sched.queue_sched.confirm_class = 0;
		rc = ctc_qos_set_sched(&sched_param);
        if (rc < 0)
        {
            printk("%% ctc_qos_set_sched excrrd class  error, ret = %d\r\n", rc);
            return ERROR;
        }

		sched_param.sched.queue_sched.cfg_type = CTC_QOS_SCHED_CFG_EXCEED_CLASS;
		/* 默认使用class 0 */		
        sched_param.sched.queue_sched.exceed_class = 0;		
		rc = ctc_qos_set_sched(&sched_param);
        if (rc < 0)
        {
            printk("%% ctc_qos_set_sched excrrd class error, ret = %d\r\n", rc);
            return ERROR;
        }



		if (flowq[i].weight) {
			sched_param.sched.queue_sched.confirm_weight = flowq[i].weight;
			sched_param.sched.queue_sched.exceed_weight = flowq[i].weight;			
		} else {
			sched_param.sched.queue_sched.confirm_weight = 1;
			sched_param.sched.queue_sched.exceed_weight = 1;
		}
		
		printk("weigth = %#x\r\n", flowq[i].weight);
		sched_param.sched.queue_sched.cfg_type = CTC_QOS_SCHED_CFG_CONFIRM_WEIGHT;		
		rc = ctc_qos_set_sched(&sched_param);
        if (rc < 0)
        {
            printk("%% ctc_qos_set_sched confirm weight error, ret = %d\r\n", rc);
            return ERROR;
        }

		sched_param.sched.queue_sched.cfg_type = CTC_QOS_SCHED_CFG_EXCEED_WEIGHT;
		rc = ctc_qos_set_sched(&sched_param);
        if (rc < 0)
        {
            printk("%% ctc_qos_set_sched excrrd weight error, ret = %d\r\n", rc);
            return ERROR;
        }
	}



	return OK;
}


u32 qos_cal_bandwidth(bool is_percent, u32 ifspeed, int value)
{
	if (is_percent)
		return (ifspeed * value/100);
	else
		return value;
}



/*
	设置对三种颜色采取不同策略
*/
static int qos_set_color_action(ctc_qos_policer_t *p_policer, struct	pm_action action[], qos_set_dscp_t *dscp)
{
	int	rc = 0;
	struct	pm_action	*act;

	/* green */
	act = &action[PM_CONFORM_ACTION];
	switch (act->action) {
	case PM_ACTION_DROP:
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "drop clolor is green\n\r");
		p_policer->policer.drop_color = CTC_QOS_COLOR_GREEN;
		break;
	default:	/* PM_ACTION_TRANSMIT */
		break;
	}


	/* yellow */
	act = &action[PM_EXCEED_ACTION];
	switch (act->action) {
	case PM_ACTION_DROP:
		if (p_policer->policer.drop_color != CTC_QOS_COLOR_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "drop clolor is yellow\n\r");
			p_policer->policer.drop_color = CTC_QOS_COLOR_YELLOW;
		}
		break;

	default:	/* PM_ACTION_TRANSMIT */
		break;
	}

	/* red */
	act = &action[PM_VIOLATE_ACTION];
	switch (act->action) {
	case PM_ACTION_DROP:
		if (p_policer->policer.drop_color != CTC_QOS_COLOR_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "drop clolor is red\n\r");			
			p_policer->policer.drop_color = CTC_QOS_COLOR_RED;
		}		
		break;

	default:	/* PM_ACTION_TRANSMIT */
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "drop clolor is none\n\r");		
		break;
	}

	return OK;
}

/*
	unit: chip_num
	port; chip_port
*/
struct list_head *qos_build_class_map(u32 ifindex, void *ptr, 
	int type, int sub_type, bool dir_in, int acl_entry_num, int *group_id)
{
	int	slot;
	cap_info_t	*cap;
	cap_sub_info_t	*sub;
	struct list_head	*cluster;
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;
	int gport;
	printk("\n<%s>[%s]:%d\t", __FILE__, __FUNCTION__, __LINE__);

	ifp = hsl_ifmgr_lookup_by_index(ifindex);
	bcmif = (struct hsl_bcm_if *)ifp->system_info;
	gport = bcmif->u.l2.lport;

	slot = 0;
	if ((cap = cap_info_get(slot)) == NULL)
		return NULL;
	
	sub = &cap->sub[sub_type];

	cluster = qos_build_class_map_internal(sub, gport, ptr, type, dir_in, acl_entry_num, group_id);

	return cluster;
}

/*
	创建三色标记法使用的令牌桶
*/
static int qos_set_policer(cap_info_t *cap, u32 ifindex, struct pm_policer *policer, ctc_qos_policer_t **pp_policer, qos_set_dscp_t *dscp)
{
	int	rc;
	u32 ifmtu;
	u32	cir, cbs;
	u32 pir, pbs;
	struct hsl_if *ifp;
	u32 policer_id;
	ctc_qos_policer_t *p_policer = NULL;
	printk("\n<%s>[%s]:%d\t", __FILE__, __FUNCTION__, __LINE__);

	p_policer = (ctc_qos_policer_t *)oss_malloc(sizeof(ctc_qos_policer_t), OSS_MEM_HEAP);
	if (NULL == p_policer) {
		return -1;
	}
	memset(p_policer, 0,sizeof(ctc_qos_policer_t));

	policer_id = policer_id_create();
	if (-1 == policer_id) {
		oss_free(p_policer, OSS_MEM_HEAP);
		return -1;
	}
	p_policer->id.policer_id = policer_id;

	rc = policer_list_add(cap, policer_id, p_policer);
	if (rc) {
		oss_free(p_policer, OSS_MEM_HEAP);
		return -1;
	}

	/* 设置速率*/
	ifp = hsl_ifmgr_lookup_by_index(ifindex);
	if (ifp == NULL) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "hsl_ifmgr_lookup_by_index for ifindex=%u failed\n\r", ifindex);
		return ERROR;
	}

	ifmtu = ifp->u.l2_ethernet.mtu;
	cir = policer->cir;
	pir = policer->pir;
	if (policer->bc == 0)
		cbs = ifmtu * 3/2;	/* *1.5，用 *3/2 避免浮点运算 */
	else
		cbs = policer->bc;
	if (policer->be == 0)
		pbs = ifmtu * 2;
	else
		pbs = policer->be;
	/* byte ==> kbits */
	cbs /= 125;
	pbs /= 125;
	if (cbs < BCM_FIELD_METER_KBITS_BURST_MIN)
		cbs = BCM_FIELD_METER_KBITS_BURST_MIN;
	if (pbs < BCM_FIELD_METER_KBITS_BURST_MIN)
		pbs = BCM_FIELD_METER_KBITS_BURST_MIN;
	
	HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "cir=%u kbits/s, cbs=%u kbits, pir=%u kbits/s, pbs=%u kbits\n\r", 
		cir, cbs, pir, pbs);


	p_policer->policer.cir = cir;
	p_policer->policer.cbs = cbs;
	p_policer->policer.pbs = pbs;
	p_policer->policer.pir = pir;

	if (PM_srTCW_COLOR_BLIND == policer->type) {
		p_policer->policer.policer_mode = CTC_QOS_POLICER_MODE_RFC2697;/* single rate three colors mode */
		p_policer->policer.is_color_aware = 0;
	} else if (PM_srTCW_COLOR_AWARE == policer->type) {
		p_policer->policer.policer_mode = CTC_QOS_POLICER_MODE_RFC2697;/* single rate three colors mode */
		p_policer->policer.is_color_aware = 1;		
	} else if (PM_trTCW_COLOR_BLIND == policer->type) {
		p_policer->policer.policer_mode = CTC_QOS_POLICER_MODE_RFC2698;/* two rates three colors mode */
		p_policer->policer.is_color_aware = 0;		
	} else {
		p_policer->policer.policer_mode = CTC_QOS_POLICER_MODE_RFC2698;/* two rates three colors mode */
		p_policer->policer.is_color_aware = 1;		
	}
 	

	/* red = 1, yellow = 2, green = 3 */
	p_policer->policer.drop_color = 1;
	if (qos_set_color_action(p_policer, policer->pm_actions, dscp) != OK)
		return ERROR;


	
	*pp_policer = p_policer;

	return OK;
}


static int qos_set_dscp(ctc_acl_entry_t *ctc_entry, qos_set_dscp_t *dscp)
{
	int	rc;

	if (dscp->green_value >= 0) {
		if (dscp->green_is_dscp) {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "bcmFieldActionDscpNew for %u, value=%u\n\r", ctc_entry->entry_id, dscp->green_value);
			ctc_entry->action.flag |= CTC_ACL_ACTION_FLAG_DSCP;
			ctc_entry->action.dscp = dscp->green_value;
		} else {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "bcmFieldActionGpDscpNew for %u, value=%u\n\r", ctc_entry->entry_id, dscp->green_value);
			ctc_entry->action.flag |= CTC_ACL_ACTION_FLAG_DSCP;
			ctc_entry->action.dscp = (dscp->green_value << 3);/* dscp->green_value左移3位，便可以设置precedence字段 */
		}
	}
	
	return OK;
}

/*
	构造一条规则，把所有不匹配的数据转到默认流队列
*/
static int qos_build_out_default_action(u32 ifindex)
{
	int	rc, fq;

	struct list_head	*cluster;
	cap_info_t *cap;
	list_t	*node;
#if 0
	bcm_field_entry_t	eid;
	struct hal_qos_flowq_info_s *flowq;

	flowq = qos_flowq[ifindex - HSL_L2_IFINDEX_START].flowq;

	cluster = qos_build_class_map(ifindex, NULL, CM_MATCH_MAX, CS_QOS_IP_OUT, FALSE, 0);
	if (cluster == NULL)
		return ERROR;
	
	node = list_first_entry(cluster, list_t, list);
	eid = node->value;
	
	/* alloc default flowq */
	fq = qos_flowq_alloc(ifindex, FALSE, TRUE);
	(&flowq[fq])->weight = 1;
	rc = bcmx_field_action_add(eid, bcmFieldActionPrioIntNew, fq, 0);
	if (rc != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "bcm_field_action_add bcmFieldActionPrioIntNew failed, rc=%d\n\r", rc);
		goto err;
	}
#endif 
	return OK;
	
err:	
	/* free resource */
	cap = cap_info_get(0);
	cap_free_entry_cluster(cap, cluster);
	return ERROR;	
}

/*
	设置ingress方向的策略
*/
static int qos_build_in_action(cap_info_t *cap, u32 ifindex, struct list_head *cluster, struct pm_entry_s *pme, int group_id)
{
	int	rc;
	list_t	*node;

	ctc_acl_entry_t *ctc_entry;
	struct pm_policer *policer;
	qos_set_dscp_t	dscp;
	uint32 policer_id;
	ctc_qos_policer_t *p_policer = NULL;
	printk("\n<%s>[%s]:%d\t", __FILE__, __FUNCTION__, __LINE__);

	memset(&dscp, 0, sizeof(dscp));
	dscp.green_value = dscp.yellow_value = dscp.red_value = -1;
	
	if (pme->set_ip_type == PM_SET_IP_TYPE_DSCP) {
		dscp.green_is_dscp = dscp.yellow_is_dscp = dscp.red_is_dscp = TRUE;
		dscp.green_value = dscp.yellow_value = dscp.red_value = pme->set_ip_value;
		
	} else if (pme->set_ip_type == PM_SET_IP_TYPE_PRECEDENCE) {
		/* yellow and red not support change precedence */
		dscp.green_is_dscp = FALSE;
		dscp.green_value = pme->set_ip_value;
	}

	/* 创建令牌桶，只需要第一个条目创建，之后的共享 */
	if ((policer = &pme->policer) != NULL) {
		if (qos_set_policer(cap, ifindex, policer, &p_policer, &dscp) != OK)
			return ERROR;
	}
	p_policer->type = CTC_QOS_POLICER_TYPE_FLOW;
	p_policer->enable = TRUE;

	rc = ctc_qos_set_policer(p_policer);
	printk("ctc_qos_set_policer , ret = %d\r\n", rc);


	for (node = list_first_entry(cluster, list_t, list);
		node != NULL;
		node = list_next_entry(node, cluster, list))
	{
		ctc_entry = (ctc_acl_entry_t *)node->data;

		if (policer != NULL) {
			ctc_entry->action.flag |= CTC_ACL_ACTION_FLAG_MICRO_FLOW_POLICER;
			ctc_entry->action.micro_policer_id = p_policer->id.policer_id;
			printk("ctc_entry atatch , eid = %#x\r\n", ctc_entry->entry_id);
		}

		if (qos_set_dscp(ctc_entry, &dscp) != OK) {
			return ERROR;
		}
		

		rc = ctc_acl_add_entry(group_id, ctc_entry);
		if (CTC_E_NONE == rc) {
			printk("ctc_acl_add_entry, group_id = %#x, rc = %d\r\n", group_id, rc);
			return ERROR;
		}
				
	}

	return OK;
}

/*
	设置egress方向的策略，主要是要设置流队列
*/
static int qos_build_out_action(u32 ifindex, struct list_head *cluster, struct pm_entry_s *pme, 
	bool is_default, uint32 group_id)
{
#if 1
	int	fq, rc;
	u32	ifspeed, min_bw, max_bw;
	list_t	*node;
	uint32	eid;
	ctc_acl_entry_t *ctc_entry;
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;
	uint32 lport;	
	struct hal_qos_flowq_info_s *flowq;
	ctc_qos_shape_t shape;
	printk("\n<%s>[%s]:%d\t", __FILE__, __FUNCTION__, __LINE__);
	flowq = qos_flowq[ifindex - HSL_L2_IFINDEX_START].flowq;
	
	if ((pme->type_mask & (PM_SET_NLS_BIT|PM_SET_LLS_BIT|PM_SET_WFQ_BIT|PM_SET_PBS_BIT)) == 0)
		return OK;

	ifp = hsl_ifmgr_lookup_by_index(ifindex);
	if (ifp == NULL) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "hsl_ifmgr_lookup_by_index for ifindex=%u failed\n\r", ifindex);
		return ERROR;
	}
	ifspeed = ifp->u.l2_ethernet.speed;
	bcmif = (struct hsl_bcm_if *)ifp->system_info;
	lport = bcmif->u.l2.lport;

	/* 申请流队列 */
	if ((fq = qos_flowq_alloc(ifindex, (pme->type_mask & PM_SET_LLS_BIT), is_default)) < 0) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "%s build qos out rule failed: no flowq\n\r", ifp->name);
		return ERROR;
	}

	/* 设置内部优先级 */
	for (node = list_first_entry(cluster, list_t, list);
		node != NULL;
		node = list_next_entry(node, cluster, list))
	{
		eid = node->value;
		ctc_entry = (ctc_acl_entry_t *)node->data;
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "set flowq %d for %u\n\r", fq, eid);

		ctc_entry->action.flag |= CTC_ACL_ACTION_FLAG_PRIORITY_AND_COLOR;
		ctc_entry->action.priority = 8*fq;
		ctc_entry->action.color = CTC_QOS_COLOR_GREEN;	
		
		rc = ctc_acl_add_entry(group_id, ctc_entry);
		printk("ctc_acl_add_entry, group_id = %#x, rc = %d\r\n", group_id, rc);
	}	

	/* 限速 */
	if (pme->type_mask & (PM_SET_LLS_BIT|PM_SET_NLS_BIT|PM_SET_PBS_BIT)) {
		/* 先计算最小带宽和最大带宽，然后设置到流队列上 */
		min_bw = 0;
		max_bw = ifspeed;
		if (pme->type_mask & PM_SET_LLS_BIT) {
			/* low bandwidth */
			min_bw = qos_cal_bandwidth(pme->val_mask & PM_SET_LLS_BIT, ifspeed, pme->lls);
			max_bw = min_bw;
		} else {
			if (pme->type_mask & PM_SET_NLS_BIT) {
				/* low bandwidth */
				min_bw = qos_cal_bandwidth(pme->val_mask & PM_SET_NLS_BIT, ifspeed, pme->nls);
			} 
			if (pme->type_mask & PM_SET_PBS_BIT) {
				/* high bandwidth */
				max_bw = qos_cal_bandwidth(pme->val_mask & PM_SET_PBS_BIT, ifspeed, pme->pbs);
			}
		}

		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "  %s flowq %d, bandwidth low=%u kbps, high=%u kbps\n\r",
			ifp->name, fq, min_bw, max_bw);



		/* 配置端口上的队列 */
		memset(&shape, 0, sizeof(shape));
		shape.type = CTC_QOS_SHAPE_QUEUE;
		shape.shape.queue_shape.cir = min_bw;
		shape.shape.queue_shape.pir = max_bw;
		shape.shape.queue_shape.cbs = CTC_QOS_SHP_TOKE_THRD_DEFAULT;
		shape.shape.queue_shape.pbs = CTC_QOS_SHP_TOKE_THRD_DEFAULT;
		shape.shape.queue_shape.enable = 1;
		shape.shape.queue_shape.queue.gport = lport;
		shape.shape.queue_shape.queue.queue_id = fq;
		shape.shape.queue_shape.queue.queue_type = CTC_QUEUE_TYPE_NETWORK_EGRESS;
		
		rc = ctc_qos_set_shape(&shape);
		if (CTC_E_NONE != rc) {
			printk("qos set shape error, ret = %d\r\n", rc);
		}

	}

	/* 加权公平队列 */
	if (pme->type_mask & PM_SET_WFQ_BIT) {
		(&flowq[fq])->weight = pme->wfq;
	} else if ((pme->type_mask & PM_SET_LLS_BIT) == 0) { /* not lls */
		(&flowq[fq])->weight = 1;
	}
#endif
	return OK;
}

int hsl_qos_group_build(struct hal_msg_l4_qos_group_set *msg)
{
	int ifindex;       /*interface ifindex */
	int acl_entry_num;
	pm_group_msg_t *hal_qos_msg;
	struct pm_entry_s *pme;
	struct cm_entry_s *cme;

	int i, slot, sub_type;
	cap_info_t	*cap;
	cap_sub_info_t *sub;
	struct list_head *cluster;
	bool is_in, is_default;
	int rc;
	int group_id;

	ifindex = msg->ifindex;
	acl_entry_num = msg->acl_entry_num;
	hal_qos_msg = &msg->hal_qos_msg;
	pme = &msg->hal_qos_msg.pm_group.pme;
	cme = &msg->hal_qos_msg.pm_group.pme.cmp;

	

	cluster = NULL;
	slot = 0;
	is_in = hal_qos_msg->is_in;

	if ( (cap = cap_info_get(slot)) == NULL )
		return ERROR;
	
	sub_type = is_in ? CS_QOS_IP_IN : CS_QOS_IP_OUT;
	sub = is_in ? (&cap->sub[CS_QOS_IP_IN]) : (&cap->sub[CS_QOS_IP_OUT]);

	if (strcmp(pme->cm_id, CLASS_DEFAULT) == 0) { /* CLASS_DEFAULT总是放在规则最后 */
		is_default = TRUE;
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "build class default rule for entry.\n\r");
		cluster = qos_build_class_map(ifindex, NULL, CM_MATCH_MAX, sub_type, is_in, 0, &group_id);
		if(cluster == NULL) {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "qos_build_one_qmap failed\n\r");
			return ERROR;
		}

		/* build action for every entry */
		if (is_in)
			rc = qos_build_in_action(cap, ifindex, cluster, pme, group_id);
		else 
			rc = qos_build_out_action(ifindex, cluster, pme, is_default, group_id);
			
		if (rc != OK) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "qos_build_action failed.\r\n");
			goto err;
		}		
	} else {
		is_default = FALSE;
		/*有一个cluster 就构造一个*/
		if(cme->cm_match[CM_MATCH_IIF].match_type == CM_MATCH_IIF) {
			struct cm_match_iif		*iif;
			iif = &cme->cm_match[CM_MATCH_IIF].cm_match_union_u.match_iif;
			/*
			for (iif = cme->cm_match[CM_MATCH_IIF].cm_match_union.match_iif;
						iif != NULL; iif = iif->next) {
			*/
			{/* 暂时只处理一个接口匹配 */
				cluster = qos_build_class_map(ifindex, (void *)iif, 
					CM_MATCH_IIF, sub_type, is_in, 0, &group_id);
				if (cluster == NULL) {
					HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "qos_build_one_qmap failed\n\r");
				} else {

					/* build action for every entry */
					if (is_in)
						rc = qos_build_in_action(cap, ifindex, cluster, pme, group_id);
					else
						rc = qos_build_out_action(ifindex, cluster, pme, is_default, group_id);
					if (rc != OK) {
						HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "qos_build_action failed.\r\n");
					}
					
					/* 释放链表 */
					cap_free_list(cluster);
				}
			}
		}

		/*将指针赋值为空供下面判断*/
		cluster = NULL;

		/*除了input interface  之外的match  类型单独设置*/
		if (cme->mp_type == CM_MATCH_ANY) {	/* 'match any' rule */
			cluster = qos_build_class_map(ifindex, NULL, CM_MATCH_MAX, sub_type, is_in, 0, &group_id);
		}else{
			for (i = 1; i < CM_MATCH_MAX; i++) {
				/*跳过input interface  的匹配*/
				if (i == CM_MATCH_IIF)
					continue;					

				/*除了input  interface 之外只有一种匹配方式，找到即返回*/
				//if (&cme->cm_match[i].cm_match_union_u.match_acl != NULL) {
				//printk("cme->cm_match[%d].match_type = %d\r\n", i, cme->cm_match[i].match_type);
				if (cme->cm_match[i].match_type == i) {
					cluster = qos_build_class_map(ifindex, (void *)&cme->cm_match[i].cm_match_union_u.match_acl, i, 
								sub_type, is_in, acl_entry_num, &group_id);
					break;
				}
			}
		}
		
		if (cluster == NULL) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "no other qos_build_one_qmap except input interface.\n\r");
			return OK;
		}

		/* build action for every entry */
		if (is_in)
			rc = qos_build_in_action(cap, ifindex, cluster, pme, group_id);
		else
			rc = qos_build_out_action(ifindex, cluster, pme, is_default, group_id);
		if (rc != OK) {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "qos_build_action failed.\r\n");
			goto err;
		}
	}

	/* 释放链表 */
	cap_free_list(cluster);
	return OK;

err:
	/* destroy all entry for last QOS rule */
	//cap_reset_last_build(cap);
	if (cluster != NULL)
		cap_free_list(cluster);
	return ERROR;	
}


int hsl_msg_recv_qos_group_build (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	struct hal_msg_l4_qos_group_set *msg;
	msg = (struct hal_msg_l4_qos_group_set *)msgbuf;

	ret = hsl_qos_group_build(msg);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

	return 0;
}

int hsl_msg_recv_out_default_action (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	struct hal_msg_l4_out_default_action *msg;
	int ifindex;
#if 0
	msg = (struct hal_msg_l4_out_default_action *)msgbuf;
	ifindex = msg->ifindex;

	ret = qos_build_out_default_action(ifindex);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
#endif

	hsl_sock_post_ack ((sock), (hdr), 0, -1);	

	return 0;
}

int hsl_msg_recv_flowq_reset (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	struct hal_msg_l4_flowq_info *msg;
	int ifindex;

	msg = (struct hal_msg_l4_flowq_info *)msgbuf;
	ifindex = msg->ifindex;

	ret = qos_flowq_reset(ifindex);
	
	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
	return 0;
}

int hsl_msg_recv_flowq_build (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	struct hal_msg_l4_flowq_info *msg;
	int ifindex;

	msg = (struct hal_msg_l4_flowq_info *)msgbuf;
	ifindex = msg->ifindex;
	
	ret = qos_flowq_build(ifindex);
	
	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

	return 0;
}

int port_cos_bandwidth_set(int ifindex, int cos, u_int64_t bandwidth)
{
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;
	int lport;	
	int rc = 0;
	
	ifp = hsl_ifmgr_lookup_by_index(ifindex);
	bcmif = (struct hsl_bcm_if *)ifp->system_info;
	lport = bcmif->u.l2.lport;

	//rc = bcmx_cosq_port_bandwidth_set(lport, cos, bandwidth, bandwidth, 0);

	return rc;	
}

struct hsl_cos_info {
	int ifindex;
	int cos;
	u_int64_t bandwidth;
};
int hsl_msg_recv_port_cos_bandwidth_set(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	struct hsl_cos_info *msg;	
	int ifindex, cos;
    u_int64_t bandwidth;

#if 0

	msg = (struct hsl_cos_info *)msgbuf;
	ifindex = msg->ifindex;
	cos = msg->cos;
	bandwidth = msg->bandwidth;
	
	ret = port_cos_bandwidth_set(ifindex, cos, bandwidth);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
#endif
	hsl_sock_post_ack ((sock), (hdr), 0, -1);

	return 0;
}

