#include "config.h"
#include "hsl_os.h"

#include "hsl_types.h"

/* Broadcom includes. */
#include "bcm_incl.h"

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
#include "hsl_bcm_pkt.h"
#include "hsl_comm.h"
#include "hsl_msg.h"
#include "hsl_bcm_if.h"

//#include "stdio.h"
#include "hal/layer4/acl/access_list_rule.h"
#include "layer4/qos/qos.h"
#include "hal/layer4/qos/qos_rule.h"
#include "hal/layer4/hal_l4_api.h"
#include "bcm/field.h"
#include "bcm/types.h"
#include "bcm/error.h"
#include "bcm/cosq.h"
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
	int	rc, i;
	list_t	*node;
	bcm_field_entry_t	eid;
	struct access_entry_hdr	*entry;

	node = list_first_entry(cluster, list_t, list);

	for (i = 0; i < acl_entry_num; i++){
		entry = &acl->grp_entry[i].entry;
			
		if (entry->permit != ACL_PERMIT)
			continue;
		
		assert(node != NULL);
		eid = node->value;
		node = list_next_entry(node, cluster, list);/* 先这样写 */
		
		switch (entry->type) {
		case ACCESS_ENTRY_TYPE_STD_IP:
			rc = bcm_build_acl_std(eid, (struct std_access_entry *)entry, sub);
			break;
		case ACCESS_ENTRY_TYPE_EXT_IP:
			rc = bcm_build_acl_ext_ip(eid, (struct ext_ip_access_entry *)entry, sub);
			break;
		case ACCESS_ENTRY_TYPE_EXT_UDP:
			rc = bcm_build_acl_udp(eid, (struct ext_udp_access_entry *)entry, sub);
			break;
		case ACCESS_ENTRY_TYPE_EXT_TCP:
			rc = bcm_build_acl_tcp(eid, (struct ext_tcp_access_entry *)entry, sub);
			break;
		case ACCESS_ENTRY_TYPE_EXT_ICMP:
			rc = bcm_build_acl_icmp(eid, (struct ext_icmp_access_entry *)entry, sub);
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
	return OK;
}

struct list_head *qos_cap_alloc_cluster(cap_sub_info_t *sub, int num,
		bool dir_in, bcmx_lport_t lport)
{
	int	rc;
	struct list_head	*list_h;
	list_t	*node;

	cap_info_t	*cap = sub->cap;

	if ((list_h = cap_alloc_entry_cluster(sub, num)) == NULL)
		return NULL;
	
	if (dir_in) {
		for (node = list_first_entry(list_h, list_t, list); 
			node != NULL; 
			node = list_next_entry(node, list_h, list))
		{
			rc = bcmx_field_qualify_InPort(node->value, lport);
			if (rc != BCM_E_NONE) {
				HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "qos_cap_alloc_cluster, bcm_field_qualify_InPorts=%d\n\r", rc);
				goto err;
			}
			
		}
		
	} else { /* dir out */
		for (node = list_first_entry(list_h, list_t, list); 
			node != NULL; 
			node = list_next_entry(node, list_h, list))
		{
			
		}
	}

	return list_h;

err:
	cap_free_entry_cluster(cap, list_h);
	return NULL;
}

struct list_head *qos_build_acl(
		struct entry_msg_s *acl, 
		cap_sub_info_t *sub,
		bool	dir_in,
		bcmx_lport_t lport,
		int acl_entry_num)
{
	int	num;
	struct list_head	*cluster;

	num = qos_acl_entry_num(acl, acl_entry_num);
	if (num == 0) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "ACL have none entry\n\r");
		return NULL;// what to do??? 
	}
	cluster = qos_cap_alloc_cluster(sub, num, dir_in, lport);
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
		bcmx_lport_t lport,
		qualify_func func,
		u32	qualify_value,
		u8	qualify_mask)
{
	int	rc;
	bcm_field_entry_t	eid;
	struct list_head	*cluster;
	list_t *node;

	cluster = qos_cap_alloc_cluster(sub, 1, dir_in, lport);
	if (cluster == NULL)
		return NULL;
	node = list_first_entry(cluster, list_t, list);
	eid = node->value;

	/* add qualify */
	if (func != NULL) {
		rc = func(eid, qualify_value, qualify_mask);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "qos_build_one_match_entry qualify failed, rc = %d\n\r", rc);
			goto err;
		}
	}

	/* add input or output port info to entry */
	if (dir_in) {
		rc = bcmx_field_qualify_InPort(eid, lport);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "bcm_field_qualify_InPorts failed, rc = %d\n\r", rc);
			goto err;
		}
		
	} else {
		
	}
	return cluster;

err:	
	/* free resource */
	cap_free_entry_cluster(sub->cap, cluster);
	return NULL;
}

int qualify_in_port(bcm_field_entry_t eid, bcmx_lport_t lport, u8 no_use)
{	
	return bcmx_field_qualify_InPort(eid, lport);
}

int qualify_in_vlan(bcm_field_entry_t eid, u16 vid, u8 no_use)
{
	int rc;
	u16 vid_mask = 0x3FFF;
	
	rc = bcmx_field_qualify_OuterVlan(eid, vid, vid_mask);
	if (rc != BCM_E_NONE){
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "bcm_field_qualify_OuterVlan(%d, %d, %d)failed, rc = %d.\r\n", 
			eid, vid, vid_mask, rc);
		return ERROR;
	}
	return OK;
}

struct list_head *qos_build_class_map_internal(cap_sub_info_t *sub, bcmx_lport_t lport, 
	void *ptr, int type, bool dir_in, int acl_entry_num)
{
	struct list_head	*cluster;
	struct cm_match_dscp *dscp;
	struct cm_match_precedence	*prec;
	struct cm_match_protocol	*proto;
	struct cm_match_iif		*iif;
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;
	bcmx_lport_t in_lport;
	hsl_vid_t vid;

	cap_sub_info_t *ip6_sub;
		
	cap_info_t	*cap = sub->cap;

	if(cap == NULL)
		return NULL;
	
	cluster = NULL;
	
	switch (type) {
	case CM_MATCH_ACL:
		cluster = qos_build_acl((struct entry_msg_s *)ptr, sub, dir_in, lport, acl_entry_num);
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
			
			cluster = qos_build_one_match_entry(sub, dir_in, lport, 
					(qualify_func)qualify_in_port, in_lport, 0);
		}
		if (iif->ifindex <= HSL_L2_IFINDEX_START) {
			/* vlan接口 */
			vid = ifp->u.ip.vid;
			cluster = qos_build_one_match_entry(sub, dir_in, lport, 
					(qualify_func)qualify_in_vlan, vid, 0);
		}
		
		break;

	case CM_MATCH_DSCP:
		dscp = ptr;
		cluster = qos_build_one_match_entry(sub, dir_in, lport, 
				(qualify_func)bcmx_field_qualify_DSCP, dscp->value, 0xFC);
		break;
		
	case CM_MATCH_IPV6_DSCP:
		if (dir_in)
			ip6_sub = &cap->sub[CS_QOS_IPV6_IN];
		else
			ip6_sub = &cap->sub[CS_QOS_IPV6_OUT];
		dscp = ptr;
		cluster = qos_build_one_match_entry(ip6_sub, dir_in, lport, 
				(qualify_func)bcmx_field_qualify_Ip6TrafficClass, dscp->value, 0xFC);
		break;	
		
	case CM_MATCH_PRECEDENCE:
		prec = ptr;
		cluster = qos_build_one_match_entry(sub, dir_in, lport, 
				(qualify_func)bcmx_field_qualify_DSCP, prec->value, 0xE0);
		break;
		
	case CM_MATCH_IPV6_PRECEDENCE:
		if (dir_in)
			ip6_sub = &cap->sub[CS_QOS_IPV6_IN];
		else
			ip6_sub = &cap->sub[CS_QOS_IPV6_OUT];
		prec = ptr;
		cluster = qos_build_one_match_entry(ip6_sub, dir_in, lport, 
				(qualify_func)bcmx_field_qualify_Ip6TrafficClass, prec->value, 0xE0);
		break;
		
	case CM_MATCH_PROTOCOL:
		proto = ptr;
		cluster = qos_build_one_match_entry(sub, dir_in, lport,
				(qualify_func)bcmx_field_qualify_IpProtocol, proto->value, 0xFF);
		break;
		
	default: /* CLASS_DEFAULT or 'match any' */
		cluster = qos_build_one_match_entry(sub, dir_in, lport, NULL, 0, 0);
		break;
	}

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
	bcmx_lport_t lport;
	bcmx_lplist_t lplist;
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
	lport = bcmif->u.l2.lport;
	ifspeed = ifp->u.l2_ethernet.speed;

	memset(weight, 0, sizeof(weight));

	bcmx_lplist_init(&lplist, 0, 0);
	bcmx_lplist_add(&lplist, lport);

	HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "reset %s flowq sched to SR\n\r", ifp->name);
	rc = bcmx_cosq_port_sched_set(lplist, BCM_COSQ_STRICT, weight, 0);
	if (rc != OK) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "qos on %s egress, bcm_cosq_port_sched_set failed, rc=%d\n\r", ifp->name, rc);
		bcmx_lplist_free(&lplist);
		return ERROR;
	}

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

	bcmx_lplist_free(&lplist);
	return OK;
}
/*
	include filter and field
*/
static int qos_flowq_build(u32 ifindex)
{
	int rc, i, used;
	int	weight[MAX_BCM_FLOWQ];
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;
	bcmx_lport_t lport;
	bcmx_lplist_t lplist;
	struct hal_qos_flowq_info_s *flowq;

	flowq = qos_flowq[ifindex - HSL_L2_IFINDEX_START].flowq;


	ifp = hsl_ifmgr_lookup_by_index(ifindex);
	bcmif = (struct hsl_bcm_if *)ifp->system_info;
	lport = bcmif->u.l2.lport;

	bcmx_lplist_init(&lplist, 0, 0);
	bcmx_lplist_add(&lplist, lport);

	memset(weight, 0, sizeof(weight));

	for (i = 0, used = FALSE; i < MAX_BCM_FLOWQ; i++) {
		/* 偷偷地把class-default和其它没设置权重的流队列的权重设置成1 */
		weight[i] = drr_weight_to_kbytes[1];
		//weight[i] = 1;
		
		if (!flowq[i].used)
			continue;
		used = TRUE;
		weight[i] = drr_weight_to_kbytes[flowq[i].weight];
		//weight[i] = flowq[i].weight;
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "    %s flowq %d weight = %u\n\r", ifp->name, i, weight[i]);
	}

	if (!used) {
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "no flowq in use on %s\n\r", ifp->name);
		bcmx_lplist_free(&lplist);
		return OK;
	}	

	rc = bcmx_cosq_port_sched_set(lplist, BCM_COSQ_DEFICIT_ROUND_ROBIN, weight, 0);
	if (rc != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "qos on %s egress, bcmx_cosq_port_sched_set failed, rc=%d\n\r", ifp->name, rc);
		bcmx_lplist_free(&lplist);
		return ERROR;
	}
	bcmx_lplist_free(&lplist);
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
static int qos_set_color_action(bcm_field_entry_t eid, struct	pm_action action[], qos_set_dscp_t *dscp)
{
	int	rc = BCM_E_NONE;
	struct	pm_action	*act;
	
	/* green */
	act = &action[PM_CONFORM_ACTION];
	switch (act->action) {
	case PM_ACTION_DROP:
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "bcmFieldActionDrop for %u\n\r", eid);
		rc = bcmx_field_action_add(eid, bcmFieldActionGpDrop, 0, 0);
		break;
	case PM_ACTION_SET_DSCP_TRANSMIT:
		dscp->green_is_dscp = TRUE;
		dscp->green_value = act->value;
		break;
	case PM_ACTION_SET_PREC_TRANSMIT:
		dscp->green_is_dscp = FALSE;
		dscp->green_value = act->value;
		break;
	default:	/* PM_ACTION_TRANSMIT */
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "bcmFieldActionDropCancel for %u\n\r", eid);
		rc = bcmx_field_action_add(eid, bcmFieldActionGpDropCancel, 0, 0);
		break;
	}
	if (rc != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "qos_set_color_action set green action(%d) failed, rc=%d\n\r", act->action, rc);
		return ERROR;
	}

	/* yellow */
	act = &action[PM_EXCEED_ACTION];
	switch (act->action) {
	case PM_ACTION_DROP:
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "bcmFieldActionYpDrop for %u\n\r", eid);
		rc = bcmx_field_action_add(eid, bcmFieldActionYpDrop, 0, 0);
		break;
	case PM_ACTION_SET_DSCP_TRANSMIT:
		dscp->yellow_is_dscp = TRUE;
		dscp->yellow_value = act->value;
		break;
	case PM_ACTION_SET_PREC_TRANSMIT:
		/* not support */
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "not support set yellow precedence\n\r");
		break;
	default:	/* PM_ACTION_TRANSMIT */
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "bcmFieldActionYpDropCancel for %u\n\r", eid);
		rc = bcmx_field_action_add(eid, bcmFieldActionYpDropCancel, 0, 0);
		break;
	}
	if (rc != BCM_E_NONE) {
		printk("qos_set_color_action set yellow action failed, rc=%d\n\r", rc);
		return ERROR;
	}

	/* red */
	act = &action[PM_VIOLATE_ACTION];
	switch (act->action) {
	case PM_ACTION_DROP:
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "bcmFieldActionRpDrop for %u\n\r", eid);
		rc = bcmx_field_action_add(eid, bcmFieldActionRpDrop, 0, 0);
		break;
	case PM_ACTION_SET_DSCP_TRANSMIT:
		dscp->red_is_dscp = TRUE;
		dscp->red_value = act->value;
		break;
	case PM_ACTION_SET_PREC_TRANSMIT:
		/* not support */
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "not support set red precedence\n\r");
		break;
	default:	/* PM_ACTION_TRANSMIT */
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "bcmFieldActionRpDropCancel for %u\n\r", eid);
		rc = bcmx_field_action_add(eid, bcmFieldActionRpDropCancel, 0, 0);
		break;
	}
	if (rc != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "qos_set_color_action set red action failed, rc=%d\n\r", rc);
		return ERROR;
	}

	return OK;
}

/*
	unit: chip_num
	port; chip_port
*/
struct list_head *qos_build_class_map(u32 ifindex, void *ptr, 
	int type, int sub_type, bool dir_in, int acl_entry_num)
{
	int	slot;
	cap_info_t	*cap;
	cap_sub_info_t	*sub;
	struct list_head	*cluster;
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;
	bcmx_lport_t lport;

	ifp = hsl_ifmgr_lookup_by_index(ifindex);
	bcmif = (struct hsl_bcm_if *)ifp->system_info;
	lport = bcmif->u.l2.lport;

	slot = 0;
	if ((cap = cap_info_get(slot)) == NULL)
		return NULL;
	
	sub = &cap->sub[sub_type];

	cluster = qos_build_class_map_internal(sub, lport, ptr, type, dir_in, acl_entry_num);

	return cluster;
}

/*
	创建三色标记法使用的令牌桶
*/
static int qos_set_policer(u32 ifindex, bcm_field_entry_t eid, struct pm_policer *policer, bcm_policer_t *pid)
{
	int	rc;
	u32 ifmtu;
	u32	cir, cbs;
	u32 pir, pbs;
	struct hsl_if *ifp;
	bcm_policer_config_t pol_cfg;
    bcm_policer_t policer_id;

	bcm_policer_config_t_init(&pol_cfg);
    pol_cfg.flags |= BCM_POLICER_COLOR_BLIND;

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
	
	HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "eid %u, cir=%u kbits/s, cbs=%u kbits, pir=%u kbits/s, pbs=%u kbits\n\r", 
		eid, cir, cbs, pir, pbs);

    pol_cfg.ckbits_sec = cir; 
    pol_cfg.ckbits_burst = cbs;
    pol_cfg.pkbits_burst = pbs;
    pol_cfg.pkbits_sec = pir; 

	if ((policer->type == PM_trTCW_COLOR_BLIND) || (policer->type == PM_trTCW_COLOR_AWARE)) {
		pol_cfg.mode = bcmPolicerModeTrTcm; /* two rates three colors mode */
	} else {
		pol_cfg.mode = bcmPolicerModeSrTcm; /* single rate three colors mode */
	}

	rc = bcmx_policer_create(&pol_cfg, &policer_id);
    if (rc != BCM_E_NONE) {
        HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "Error in bcm_policer_create with policer_id %d\n", policer_id);
        return ERROR;
    }

	rc = bcmx_field_entry_policer_attach(eid, 0, policer_id);
    if (rc != BCM_E_NONE) {
        HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "Error in bcm_field_entry_policer_attach with policer_id %d\n", policer_id);
        return ERROR;
    }

	rc = bcmx_policer_set(policer_id, &pol_cfg);
	if (rc != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "bcm_policer_set failed, rc = %d\n\r", rc);
		return ERROR;
	}

	*pid = policer_id;
	return OK;
}


static int qos_set_dscp(bcm_field_entry_t eid, qos_set_dscp_t *dscp)
{
	int	rc;

	if (dscp->green_value >= 0) {
		if (dscp->green_is_dscp) {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "bcmFieldActionDscpNew for %u, value=%u\n\r", eid, dscp->green_value);
			rc = bcmx_field_action_add(eid, bcmFieldActionGpDscpNew, 
					dscp->green_value, 0);
			if (rc != BCM_E_NONE) {
				HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "bcm_field_action_add bcmFieldActionDscpNew rc=%d\n\r", rc);
				return ERROR;
			}
		} else {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "bcmFieldActionGpDscpNew for %u, value=%u\n\r", eid, dscp->green_value);
			rc = bcmx_field_action_add(eid, bcmFieldActionGpDscpNew, 
					(dscp->green_value << 3), 0);/* 使用 bcmFieldActionGpDscpNew ，dscp->green_value左移3位，便可以设置precedence字段 */
			if (rc != BCM_E_NONE) {
				HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "bcm_field_action_add bcmFieldActionGpDscpNew rc=%d\n\r", rc);
				return ERROR;
			}
		}
	}

	if (dscp->yellow_value >= 0) {
		if (dscp->yellow_is_dscp) {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "bcmFieldActionYpDscpNew for %u, value=%u\n\r", eid, dscp->yellow_value);
			rc = bcmx_field_action_add(eid, bcmFieldActionYpDscpNew, 
					dscp->yellow_value, 0);
			if (rc != BCM_E_NONE) {
				HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "bcm_field_action_add bcmFieldActionYpDscpNew rc=%d\n\r", rc);
				return ERROR;
			}
		} else {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "not support yellow tos new\n\r");
		}
	}

	if (dscp->red_value >= 0) {
		if (dscp->red_is_dscp) {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "bcmFieldActionRpDscpNew for %u, value=%u\n\r", eid, dscp->red_value);
			rc = bcmx_field_action_add(eid, bcmFieldActionRpDscpNew, 
					dscp->red_value, 0);
			if (rc != BCM_E_NONE) {
				HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "bcm_field_action_add bcmFieldActionRpDscpNew rc=%d\n\r", rc);
				return ERROR;
			}
		} else {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "not support red tos new\n\r");
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
	bcm_field_entry_t	eid;
	struct list_head	*cluster;
	cap_info_t *cap;
	list_t	*node;
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
static int qos_build_in_action(u32 ifindex, struct list_head *cluster, struct pm_entry_s *pme)
{
	int	rc;
	list_t	*node;
	bcm_field_entry_t	eid = 0;
	bcm_field_entry_t	first_eid = 0;
	struct pm_policer *policer;
	qos_set_dscp_t	dscp;
	bcm_policer_t policer_id;
	/* 创建令牌桶，只需要第一个条目创建，之后的共享 */
	if ((policer = &pme->policer) != NULL) {
		node = list_first_entry(cluster, list_t, list);
		first_eid = eid = node->value;
		if (qos_set_policer(ifindex, eid, policer, &policer_id) != OK)
			return ERROR;
	}

	for (node = list_first_entry(cluster, list_t, list);
		node != NULL;
		node = list_next_entry(node, cluster, list))
	{
		eid = node->value;
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

		if (policer != NULL) {
			if (eid != first_eid) {
				rc = bcmx_field_entry_policer_attach(eid, 0, policer_id);
			    if (rc != BCM_E_NONE) {
			        HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "Error in bcm_field_entry_policer_attach with policer_id %d\n", policer_id);
			        return ERROR;
			    }
			}
			if (qos_set_color_action(eid, policer->pm_actions, &dscp) != OK)
				return ERROR;
		}

		if (qos_set_dscp(eid, &dscp) != OK)
			return ERROR;
	}

	return OK;
}

/*
	设置egress方向的策略，主要是要设置流队列
*/
static int qos_build_out_action(u32 ifindex, struct list_head *cluster, struct pm_entry_s *pme, 
	bool is_default)
{
	int	fq, rc;
	u32	ifspeed, min_bw, max_bw;
	list_t	*node;
	bcm_field_entry_t	eid;
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;
	bcmx_lport_t lport;	
	struct hal_qos_flowq_info_s *flowq;

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
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "set flowq %d for %u\n\r", fq, eid);

		rc = bcmx_field_action_add(eid, bcmFieldActionPrioIntNew, fq, 0);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "bcm_field_action_add bcmFieldActionPrioIntNew failed, rc=%d\n\r", rc);
			return ERROR;
		}
	
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
		rc = bcmx_cosq_port_bandwidth_set(lport, fq, min_bw, max_bw, 0);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_QOS, "bcm_cosq_port_bandwidth_set failed, rc=%d\n\r", rc);
			return ERROR;
		}
	}

	/* 加权公平队列 */
	if (pme->type_mask & PM_SET_WFQ_BIT) {
		(&flowq[fq])->weight = pme->wfq;
	} else if ((pme->type_mask & PM_SET_LLS_BIT) == 0) { /* not lls */
		(&flowq[fq])->weight = 1;
	}

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
		cluster = qos_build_class_map(ifindex, NULL, CM_MATCH_MAX, sub_type, is_in, 0);
		if(cluster == NULL) {
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "qos_build_one_qmap failed\n\r");
			return ERROR;
		}

		/* build action for every entry */
		if (is_in)
			rc = qos_build_in_action(ifindex, cluster, pme);
		else 
			rc = qos_build_out_action(ifindex, cluster, pme, is_default);
			
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
					CM_MATCH_IIF, sub_type, is_in, 0);
				if (cluster == NULL) {
					HSL_DEBUG_IPCLS(DEBUG_LEVEL_QOS, "qos_build_one_qmap failed\n\r");
				} else {

					/* build action for every entry */
					if (is_in)
						rc = qos_build_in_action(ifindex, cluster, pme);
					else
						rc = qos_build_out_action(ifindex, cluster, pme, is_default);
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
			cluster = qos_build_class_map(ifindex, NULL, CM_MATCH_MAX, sub_type, is_in, 0);
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
								sub_type, is_in, acl_entry_num);
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
			rc = qos_build_in_action(ifindex, cluster, pme);
		else
			rc = qos_build_out_action(ifindex, cluster, pme, is_default);
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
	cap_reset_last_build(cap);
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

	msg = (struct hal_msg_l4_out_default_action *)msgbuf;
	ifindex = msg->ifindex;

	ret = qos_build_out_default_action(ifindex);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);
	
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
	bcmx_lport_t lport;	
	int rc;
	
	ifp = hsl_ifmgr_lookup_by_index(ifindex);
	bcmif = (struct hsl_bcm_if *)ifp->system_info;
	lport = bcmif->u.l2.lport;

	rc = bcmx_cosq_port_bandwidth_set(lport, cos, bandwidth, bandwidth, 0);

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

	msg = (struct hsl_cos_info *)msgbuf;
	ifindex = msg->ifindex;
	cos = msg->cos;
	bandwidth = msg->bandwidth;
	
	ret = port_cos_bandwidth_set(ifindex, cos, bandwidth);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

	return 0;
}

