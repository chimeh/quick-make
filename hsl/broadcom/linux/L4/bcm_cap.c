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

#include <linux/kernel.h>
#include "bcm/field.h"
#include "bcm/types.h"
#include "bcm/error.h"
#include "sal/core/sync.h"
#include <linux/list.h>
#include <linux/types.h>
#include "hsl_oss.h"
#include "bcm_cap.h"
#include "bcm_l4_debug.h"
#include "hal/layer4/hal_l4_config.h"
#include "layer4/pbmp.h"


cap_info_t chassis_cap_info[MAX_LC_NUM];
//pthread_mutex_t cap_info_mutex = PTHREAD_MUTEX_INITIALIZER;


/*
 * Function: get_bits_num
 *    
 * Purpose:
 *     get bits num.
 *     
 * Parameters:
 *     entry     - entry id.
 *
 * Returns:
 *     ret       - bits num.
 *
 */
int get_bits_num(int  entry) 
{
	int ret;
	switch(entry)
	{
		case 128:
			ret = 8;
			break;
		case 256:
			ret = 9;
			break;
		case 512:
			ret = 10;
			break;
		default:
			ret = 0;
	}
	
	return ret;
}

/*
 * Function: get_offset_mask
 *    
 * Purpose:
 *     get offset mask.
 *     
 * Parameters:
 *     entry     - entry id.
 *
 * Returns:
 *     ret       - offset mask.
 *
 */
int get_offset_mask(int  entry) 
{
	int ret;
	switch(entry)
	{
		case 128:
			ret = 0xFF;
			break;
		case 256:
			ret = 0x1FF;
			break;
		case 512:
			ret = 0x3FF;
			break;
		default:
			ret = 0;
	}
	
	return ret;
}

cap_sub_name_t cap_sub_name[] = {
	{CS_IFP_RULE, "ifp-rule"},
	{CS_DEFAULT_ACL, "default-acl"},
	{CS_IFP_VLAN_IP_ACL, "ifp-vlan-ip-acl"},
	{CS_IFP_IP_ACL, "ifp-ip-acl"},
	{CS_EFP_IP_ACL, "efp-ip-acl"},
	{CS_VFP_IP_ACL, "vfp-ip-acl"},
	{CS_IFP_MAC_ACL, "ifp-mac-acl"},
	{CS_QOS_IP_IN, "ip-qos-in"},
	{CS_QOS_IP_OUT, "ip-qos-out"},
	{CS_QOS_IPV6_IN, "ipv6-qos-in"},
	{CS_QOS_IPV6_OUT, "ipv6-qos-out"},
	{CS_MIRROR_RULE, "mirror-rule"},

	{CS_EFP_RULE, "efp-rule"},

	{CS_VFP_RULE, "vfp-rule"},
	{CS_VFP_QINQ_RULE, "vfp-qinq-rule"},

	{-1, NULL},
};

char *cap_sub_name_get(int sub_type)
{
	static char	unknow[16];
	cap_sub_name_t	*csnp;

	for (csnp = cap_sub_name; csnp->name != NULL; csnp++) {
		if (csnp->type == sub_type)
			return csnp->name;
	}

	sprintf(unknow, "%u", sub_type);

	return unknow;
}

/*
 * Function: cap_info_get
 *    
 * Purpose:
 *     get cap info.
 *     
 * Parameters:
 *     slot     - slot No.
 *
 * Returns:
 *    
 *
 */
cap_info_t *cap_info_get(int slot)
{
	//slot -= BEGIN_LC_NUM;
	
	if (slot < 0 || slot >= MAX_LC_NUM) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap_info_get(%d), out of range\n\r", slot);
		return NULL;
	}

	return &chassis_cap_info[slot];
}

cap_info_t *cap_info_get_by_ifindex(u16 ifindex)
{
	int	slot;
	
	slot = 0;

	return cap_info_get(slot);
}

static void cap_init_sub_qset(cap_sub_info_t	*sub)
{
	switch (sub->type) {
		case CS_DEFAULT_ACL:
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyTtl);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifySrcIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDstIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4SrcPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4DstPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpProtocol);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyEtherType);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyOuterVlan);
			break;
		case CS_IFP_VLAN_IP_ACL:
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpType);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyTos);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDSCP);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifySrcIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDstIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4SrcPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4DstPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpProtocol);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyRangeCheck);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyOuterVlan);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifySrcMac);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDstMac);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyEtherType);
			break;
		case CS_IFP_IP_ACL:
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyInPorts);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpType);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDSCP);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifySrcIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDstIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4SrcPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4DstPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpProtocol);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyRangeCheck);
			break;
		case CS_EFP_IP_ACL:
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyOutPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyStageEgress);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpType);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyTos);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDSCP);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifySrcIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDstIp);
			//BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyRangeCheck);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4SrcPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4DstPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpProtocol);
			break;
		case CS_VFP_IP_ACL:
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpType);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyTos);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDSCP);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifySrcIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDstIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4SrcPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4DstPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpProtocol);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyRangeCheck);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyOuterVlan);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifySrcMac);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDstMac);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyEtherType);		
			break;
		case CS_IFP_MAC_ACL:
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyInPorts);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpType);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifySrcMac);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDstMac);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyEtherType);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL3Routable);
			break;
		case CS_QOS_IP_IN:
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyInPorts);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyInPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpType);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDSCP);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifySrcIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDstIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4SrcPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4DstPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpProtocol);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyRangeCheck);
			break;
		case CS_QOS_IP_OUT:
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyInPorts);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyInPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDSCP);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifySrcIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDstIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4SrcPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4DstPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpProtocol);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyRangeCheck);
			break;
		case CS_QOS_IPV6_IN:
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyInPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyInPorts);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpType);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifySrcIp6);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDstIp6);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIp6NextHeader);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIp6TrafficClass);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIp6HopLimit);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIp6FlowLabel);
			break;
		case CS_QOS_IPV6_OUT:
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyInPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyInPorts);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpType);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifySrcIp6);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDstIp6);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIp6NextHeader);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIp6TrafficClass);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIp6HopLimit);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIp6FlowLabel);
			break;
		case CS_MIRROR_RULE:
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyOuterVlan);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpType);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyTos);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDSCP);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifySrcIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyDstIp);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4SrcPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyL4DstPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyIpProtocol);
			break;
		case CS_IFP_RULE:
		case CS_EFP_RULE:
		case CS_VFP_RULE:
			break;
			
		case CS_VFP_QINQ_RULE:
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyOuterVlanId);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyInPort);
			BCM_FIELD_QSET_ADD(sub->qset, bcmFieldQualifyStageLookup);
			

			break;
		default:
			printk("cap_init_sub_qset failed: unknow type=%d\n\r", sub->type);
			break;
	}
}
/*
int cap_info_lock(void)
{
	return pthread_mutex_lock(&cap_info_mutex);
}

int cap_info_unlock(void)
{
	return pthread_mutex_unlock(&cap_info_mutex);
}
*/
/*
 * Function: cap_init
 *    
 * Purpose:
 *     cap initialization.
 *     
 * Parameters:
 *     none
 *
 * Returns:
 *     ERROR    - failed.
 *     OK       - succeed.
 *
 */
int cap_init(void)
{
	int	slot, k, offset;
	cap_info_t	*cap;

	memset(chassis_cap_info, 0, (sizeof(cap_info_t) * MAX_LC_NUM));

	for (slot = 0; slot < MAX_LC_NUM; slot++) {
		cap = cap_info_get(slot);
		cap->slot = slot + BEGIN_LC_NUM;
		/* init CAP infomation */
		cap->unit = DEFAULT_UNIT;
		cap->ifp_max_slice = BCM_IFP_SLICE_PER_UNIT;
		cap->efp_max_slice = BCM_EFP_SLICE_PER_UNIT;
		cap->vfp_max_slice = BCM_VFP_SLICE_PER_UNIT;
		
		cap->entry_per_ifp_slice = BCM_ENTRY_PER_IFP_SLICE;
		cap->entry_per_efp_slice = BCM_ENTRY_PER_EFP_SLICE;
		cap->entry_per_vfp_slice = BCM_ENTRY_PER_VFP_SLICE;

		/* pbmp用于入端口，port_mask用于出端口  */
		
		BCM_PBMP_CLEAR(cap->pbmp_mask);
		cap->pbmp_mask.pbits[0] = BCM_PBMP_MASK;
		cap->pbmp_mask.pbits[1] = BCM_PBMP_MASK;
		cap->port_mask = BCM_PORT_MASK;

		//STLC_INIT_LIST_HEAD(&cap->last_build);
		((struct list_head *)&cap->last_build)->next = (struct list_head *)&cap->last_build;
		((struct list_head *)&cap->last_build)->prev = (struct list_head *)&cap->last_build;
				
		offset = 0;
		/* IFP */
		for (k = 0; k < BCM_IFP_SLICE_PER_UNIT; k++) {
			cap_group_t	*gp;
			gp = &cap->ifp_slice[k];
			gp->type = MAX_CAP_SUB;
			gp->pri = k;
			gp->gid = k + 1;
			gp->slice = k;
			gp->free_entry = BCM_ENTRY_PER_IFP_SLICE;
		}
		offset += k;
		/* EFP */
		for (k = 0; k < BCM_EFP_SLICE_PER_UNIT; k++) {
			cap_group_t	*gp;
			gp = &cap->efp_slice[k];
			gp->type = MAX_CAP_SUB;
			gp->pri = offset + k;
			gp->gid = offset + k + 1;
			gp->slice = k;
			gp->free_entry = BCM_ENTRY_PER_EFP_SLICE;
		}
		offset += k;
		/* VFP */
		for (k = 0; k < BCM_VFP_SLICE_PER_UNIT; k++) {
			cap_group_t	*gp;
			gp = &cap->vfp_slice[k];
			gp->type = MAX_CAP_SUB;
			gp->pri = offset + k;
			gp->gid = offset + k + 1;
			gp->slice = k;
			gp->free_entry = BCM_ENTRY_PER_VFP_SLICE;
		}
		for (k = 0; k < MAX_CAP_SUB; k++) {
			cap_sub_info_t	*sub = &cap->sub[k];
			sub->type = k;
			sub->cap = cap;
			cap_init_sub_qset(sub);
		}
		

		/* init field */
		/*
		if ( (rc = bcmx_field_init()) != BCM_E_NONE ) {
			printk("bcmx_field_init() failed, rc=%d\n\r", rc);
			return ERROR;
		}
		*/
		
	}

	return OK;
}

void
hsl_layer4_init(void)
{
	int ret;
	
	ret = cap_init();
	if (ret != OK)
		printk("bcm cap init failed.\r\n");
	else
		printk("bcm cap init ok.\r\n");
}

/*
 * Function: cap_add_last_build
 *    
 * Purpose:
 *     add one entry id to last_build list.
 *     
 * Parameters:
 *     cap      - ...
 *     eid      - entry id.
 *
 * Returns:
 *     OK       - succeed.
 *
 */
int cap_add_last_build(cap_info_t *cap, bcm_field_entry_t eid)
{
	 list_t *node = NULL;

	 node = (list_t *)oss_malloc(sizeof(list_t), OSS_MEM_HEAP);
	 if (!node)
	 	return ERROR;

	 node->value = eid;

	 list_add_tail(&(node->list), &cap->last_build);

	 return OK;	 
}

/*
 * Function: cap_reset_last_build
 *    
 * Purpose:
 *     reset last_build list.
 *     
 * Parameters:
 *     cap      - ...
 *
 * Returns:
 *     OK       - succeed.
 *
 */
int cap_reset_last_build(cap_info_t *cap)
{
	list_t *node = NULL;
	struct list_head *p;

	p = &cap->last_build;

	while(p->next != p && p->prev != p) {
		node = (list_t *)p->next;
		p->next->next->prev = p;
		p->next = p->next->next;

		oss_free(node, OSS_MEM_HEAP);
	}

	return OK;
}

int cap_clear_last_build(cap_info_t *cap)
{
	list_t *node = NULL;
	struct list_head *p;

	p = &cap->last_build;

	while(p->next != p && p->prev != p) {
		node = (list_t *)p->next;
		p->next->next->prev = p;
		p->next = p->next->next;
		cap_free_entry(cap, node->value);
		oss_free(node, OSS_MEM_HEAP);
	}

	return OK;
}

/*
 * Function: cap_free_entry
 *    
 * Purpose:
 *     free entry.
 *     
 * Parameters:
 *     cap      - ...
 *     eid      - entry id.
 *
 * Returns:
 *     none
 *
 */
void cap_free_entry(cap_info_t *cap, bcm_field_entry_t eid)
{
	int	slice = 0, rc = 0, offset = 0;
	cap_group_t	*g = NULL;
	list_t *node = NULL;
	struct list_head *p = NULL;
	int bcm_entry_per_slice = 0;

	if (eid >= IFP_EID_OFFSET && eid < EFP_EID_OFFSET) {
		slice = EID_TO_IFP_SLICE(eid);
		offset = EID_TO_IFP_OFFSET(eid);

		g = &cap->ifp_slice[slice];
		bcm_entry_per_slice = BCM_ENTRY_PER_IFP_SLICE;
	} else if (eid >= EFP_EID_OFFSET && eid < VFP_EID_OFFSET) {
		slice = EID_TO_EFP_SLICE(eid);
		offset = EID_TO_EFP_OFFSET(eid);

		g = &cap->efp_slice[slice];
		bcm_entry_per_slice = BCM_ENTRY_PER_EFP_SLICE;
	} else if (eid >= VFP_EID_OFFSET) {
		slice = EID_TO_VFP_SLICE(eid);
		offset = EID_TO_VFP_OFFSET(eid);

		g = &cap->vfp_slice[slice];
		bcm_entry_per_slice = BCM_ENTRY_PER_VFP_SLICE;
	}
	
	/* 销毁该条目 */
	rc = bcmx_field_entry_destroy( eid);
	if (rc != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap free entry failed: rc = %d\n\r", rc);
	}

	/* 把最后构造中的记录去掉 */
	p = &cap->last_build;
	while(p && (p->next != p && p->prev != p)) {
		node = (list_t *)p->next;
		p->next->next->prev = p;
		p->next = p->next->next;
		
		oss_free(node, OSS_MEM_HEAP);
	}

	if (!g->used[offset])
	{
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap free entry bug: slice=%d, offset=%d, eid=%u, not used\n\r",
			slice, offset, eid);
		return;
	}

	g->used[offset] = false;
	g->free_entry++;

		/* 检查是否要释放该group */
	if (g->free_entry == bcm_entry_per_slice)
	{
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap free entry  slice=%d, offset=%d, free group\n\r", slice, offset);
		bcmx_field_group_destroy( g->gid);
		g->type = MAX_CAP_SUB;
	}

}

/*
 * Function: cap_free_entry_cluster
 *    
 * Purpose:
 *     free list and free entry.
 *     
 * Parameters:
 *     cap      - ...
 *     list     - list head.
 *
 * Returns:
 *     none
 *
 */
void cap_free_entry_cluster(cap_info_t *cap, struct list_head  *list)
{
	list_t	*node;
	struct list_head *p;

	p = list;

	while(p && (p->next != p && p->prev != p)) {
		node = (list_t *)p->next;
		p->next->next->prev = p;
		p->next = p->next->next;

		cap_free_entry(cap, node->value);
		
		oss_free(node, OSS_MEM_HEAP);
	}
	
	oss_free(list, OSS_MEM_HEAP);
}

/*
 * Function: cap_free_list
 *    
 * Purpose:
 *     free list.
 *     
 * Parameters:
 *     list     - list head.
 *
 * Returns:
 *     none
 *
 */
void cap_free_list(struct list_head  *list)
{
	list_t	*node;
	struct list_head *p;

	p = list;

	while(p && (p->next != p && p->prev != p)) {
		node = (list_t *)p->next;
		p->next->next->prev = p;
		p->next = p->next->next;

		oss_free(node, OSS_MEM_HEAP);
	}
	
	oss_free(list, OSS_MEM_HEAP);
}

/*
 * Function: cap_clear_one
 *    
 * Purpose:
 *     clear entry.
 *     
 * Parameters:
 *     cap     - ...
 *
 * Returns:
 *     none
 *
 */
void cap_clear_one(cap_info_t *cap)
{
	int	i, k;
	cap_group_t	*g;
	
	/* clear all rule first */
	bcmx_field_entry_destroy_all();

	/* destroy IFP group */
	for (i = 0; i < cap->ifp_max_slice; i++) {
		g = &cap->ifp_slice[i];
		bcmx_field_group_destroy(g->gid);
		g->free_entry = BCM_ENTRY_PER_IFP_SLICE;
		for (k = 0; k < MAX_ENTRY_PER_SLICE; k++) {
			g->used[k] = false;
		}
		g->type = MAX_CAP_SUB;
	}

	/* destroy EFP group */
	for (i = 0; i < cap->efp_max_slice; i++) {
		g = &cap->efp_slice[i];
		bcmx_field_group_destroy(g->gid);
		g->free_entry = BCM_ENTRY_PER_EFP_SLICE;
		for (k = 0; k < MAX_ENTRY_PER_SLICE; k++) {
			g->used[k] = false;
		}
		g->type = MAX_CAP_SUB;
	}

	/* destroy VFP group */
	for (i = 0; i < cap->vfp_max_slice; i++) {
		g = &cap->vfp_slice[i];
		bcmx_field_group_destroy( g->gid);
		g->free_entry = BCM_ENTRY_PER_VFP_SLICE;
		for (k = 0; k < MAX_ENTRY_PER_SLICE; k++) {
			g->used[k] = false;
		}
		g->type = MAX_CAP_SUB;
	}

	cap_reset_last_build(cap);
	bcmx_field_init();
}

/*
 * Function: cap_clear_all
 *    
 * Purpose:
 *     clear all entry.
 *     
 * Parameters:
 *     none
 *
 * Returns:
 *     none
 *
 */
void cap_clear_all(void)
{
	int	slot, i;
	cap_info_t	*cap;
	
	for (i = 0; i < MAX_LC_NUM; i++) {
		slot = i;
		if ((cap = cap_info_get(slot)) == NULL)
			continue;
		cap_clear_one(cap);
	}
}

static bcm_field_entry_t cap_alloc_ifp_entry(cap_sub_info_t *sub)
{
	int	rc, slice, i;
	cap_group_t	*g;
	bcm_field_entry_t eid;
	cap_info_t	*cap = sub->cap;
	cap_group_t *tmp_g1 = NULL;

	for (slice = cap->ifp_max_slice - 1; slice >= 0; slice--) {		
		g = &cap->ifp_slice[slice];

		/*double mode*/
		if (sub->type == CS_IFP_VLAN_IP_ACL){
			if(slice % 2 != 0)
				continue;

			tmp_g1 = &cap->ifp_slice[slice + 1];
			if(tmp_g1->free_entry != cap->entry_per_ifp_slice && tmp_g1->type != sub->type)
				continue;
		}

		if (g->free_entry == 0)
			continue;
		
		/* if used part, check is it same type */
		if (g->free_entry != cap->entry_per_ifp_slice && g->type != sub->type)
			continue;

		break;
	}

	/* 没有空闲组了 */
	if (slice < 0){
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Not enough resource.\r\n");	
		return -1;
	}

	/* if new group, create */
	if (g->free_entry == cap->entry_per_ifp_slice) {

		if(sub->type == CS_IFP_VLAN_IP_ACL) {
			rc = bcmx_field_group_create_mode_id( sub->qset, g->pri, bcmFieldGroupModeDouble, g->gid);
			if (rc != BCM_E_NONE) {
				HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot%d L4 alloc ip group failed, cur slice=%d, rc=%d\n\r", 
					cap->slot, g->slice, rc);
				return -1;
			}
		} else {
			rc = bcmx_field_group_create_id( sub->qset, g->pri, g->gid);
			if (rc != BCM_E_NONE) {
				HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot%d L4 alloc group failed, cur slice=%d, rc=%d\n\r", 
					cap->slot, g->slice, rc);
				return -1;
			}
		}

		/* set type */
		g->type = sub->type;
		if(sub->type == CS_IFP_VLAN_IP_ACL){
			tmp_g1->type = CS_IFP_VLAN_IP_ACL;
		}
	}

	/* 创建条目 */
	g->free_entry--;
	if(sub->type == CS_IFP_VLAN_IP_ACL){
		tmp_g1->free_entry--;
	}
	for(i = BCM_ENTRY_PER_IFP_SLICE - 1; i >= 0; i--){
		eid = IFP_SLICE_TO_EID(g->slice, i);
		if(g->used[EID_TO_IFP_OFFSET(eid)] == false)
			break;
	}

	rc = bcmx_field_entry_create_id( g->gid, eid);
	if (rc != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot%d L4 alloc entry failed, cur slice=%d, entry=%d, rc=%d\n\r",
			cap->slot, g->slice, eid, rc);
		g->free_entry++;
		if(sub->type == CS_IFP_VLAN_IP_ACL){
			tmp_g1->free_entry++;
		}
		
		/* 如果是刚刚创建了的group，要销毁 */
		if (g->free_entry == cap->entry_per_ifp_slice)
			bcmx_field_group_destroy( g->gid);
		return -1;
	}

	/* 设置使用标志 */
	g->used[EID_TO_IFP_OFFSET(eid)] = true;
	if(sub->type == CS_IFP_VLAN_IP_ACL){
		tmp_g1->used[EID_TO_IFP_OFFSET(eid)] = true;
	}

	/* add to last build list */
	if (cap_add_last_build(cap, eid) != OK) {
		cap_free_entry(cap, eid);
		return -1;
	}
	
	return eid;
}

static bcm_field_entry_t cap_alloc_efp_entry(cap_sub_info_t *sub)
{
	int	rc, slice, i;
	cap_group_t	*g;
	bcm_field_entry_t eid;
	cap_info_t	*cap = sub->cap;

	for (slice = cap->efp_max_slice - 1; slice >= 0; slice--) {		
		g = &cap->efp_slice[slice];

		if (g->free_entry == 0)
			continue;
		
		/* if used part, check is it same type */
		if (g->free_entry != cap->entry_per_efp_slice && g->type != sub->type)
			continue;

		break;
	}

	/* 没有空闲组了 */
	if (slice < 0){
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Not enough resource.\r\n");	
		return ERROR;
	}

	/* if new group, create */
	if (g->free_entry == cap->entry_per_efp_slice) {

		rc = bcmx_field_group_create_id( sub->qset, g->pri, g->gid);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot%d L4 alloc group failed, cur slice=%d, rc=%d\n\r", 
				cap->slot, g->slice, rc);
			return ERROR;
		}

		/* set type */
		g->type = sub->type;
	}

	/* 创建条目 */
	g->free_entry--;
	for(i = BCM_ENTRY_PER_EFP_SLICE - 1; i >= 0; i--){
		eid = EFP_SLICE_TO_EID(g->slice, i);
		if(g->used[EID_TO_EFP_OFFSET(eid)] == false)
			break;
	}

	rc = bcmx_field_entry_create_id( g->gid, eid);
	if (rc != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot%d L4 alloc entry failed, cur slice=%d, entry=%d, rc=%d\n\r",
			cap->slot, g->slice, eid, rc);
		g->free_entry++;
		
		/* 如果是刚刚创建了的group，要销毁 */
		if (g->free_entry == cap->entry_per_efp_slice)
			bcmx_field_group_destroy( g->gid);
		return ERROR;
	}

	/* 设置使用标志 */
	g->used[EID_TO_EFP_OFFSET(eid)] = true;

	/* add to last build list */
	if (cap_add_last_build(cap, eid) != OK) {
		cap_free_entry(cap, eid);
		return -1;
	}
	
	return eid;
}

static bcm_field_entry_t cap_alloc_vfp_entry(cap_sub_info_t *sub)
{
	int	rc, slice, i;
	cap_group_t	*g;
	bcm_field_entry_t eid;
	cap_info_t	*cap = sub->cap;

	for (slice = cap->vfp_max_slice - 1; slice >= 0; slice--) {		
		g = &cap->vfp_slice[slice];

		if (g->free_entry == 0)
			continue;
		
		/* if used part, check is it same type */
		if (g->free_entry != cap->entry_per_vfp_slice && g->type != sub->type)
			continue;

		break;
	}

	/* 没有空闲组了 */
	if (slice < 0){
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Not enough resource.\r\n");	
		return -1;
	}

	/* if new group, create */
	if (g->free_entry == cap->entry_per_vfp_slice) {

		rc = bcmx_field_group_create_id( sub->qset, g->pri, g->gid);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot%d L4 alloc group failed, cur slice=%d, rc=%d\n\r", 
				cap->slot, g->slice, rc);
			return ERROR;
		}

		/* set type */
		g->type = sub->type;
	}

	/* 创建条目 */
	g->free_entry--;
	for(i = BCM_ENTRY_PER_VFP_SLICE - 1; i >= 0; i--){
		eid = VFP_SLICE_TO_EID(g->slice, i);
		if(g->used[EID_TO_VFP_OFFSET(eid)] == false)
			break;
	}

	rc = bcmx_field_entry_create_id( g->gid, eid);
	if (rc != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot%d L4 alloc entry failed, cur slice=%d, entry=%d, rc=%d\n\r",
			cap->slot, g->slice, eid, rc);
		g->free_entry++;
		
		/* 如果是刚刚创建了的group，要销毁 */
		if (g->free_entry == cap->entry_per_vfp_slice)
			bcmx_field_group_destroy( g->gid);
		return ERROR;
	}

	/* 设置使用标志 */
	g->used[EID_TO_VFP_OFFSET(eid)] = true;

	/* add to last build list */
	if (cap_add_last_build(cap, eid) != OK) {
		cap_free_entry(cap, eid);
		return -1;
	}
	
	return eid;
}

/*
 * Function: cap_alloc_entry
 *    
 * Purpose:
 *     alloc entry id.
 *     
 * Parameters:
 *     sub        - ...
 *
 * Returns:
 *     eid         - entry id.
 *     -1          - alloc failed.
 *
 */
bcm_field_entry_t cap_alloc_entry(cap_sub_info_t *sub)
{
	bcm_field_entry_t eid;
	switch (sub->type) {
		case CS_IFP_RULE:
		case CS_DEFAULT_ACL:
		case CS_IFP_IP_ACL:
		case CS_IFP_VLAN_IP_ACL:
		case CS_IFP_MAC_ACL:
		case CS_MIRROR_RULE:
			/* IFP */
			eid = cap_alloc_ifp_entry(sub);
			break;
		case CS_EFP_RULE:
		case CS_EFP_IP_ACL:
			/* EFP */
			eid = cap_alloc_efp_entry(sub);
			break;
		case CS_VFP_RULE:
		case CS_VFP_IP_ACL:
			/* VFP */
			eid = cap_alloc_vfp_entry(sub);
			break;
		default:
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "invalid type.\r\n");
			eid = -1;
	}

	return eid;
}

static struct list_head *cap_alloc_ifp_entry_cluster(cap_sub_info_t *sub, int num)
{
	int	rc, slice, i;
	cap_group_t	*g;
	bcm_field_entry_t	eid;
	cap_info_t	*cap = sub->cap;
	list_t *node = NULL;
	struct list_head *list = NULL;


	/* 如果要求的条目超过一组的最多容量，失败 */
	if (num > cap->entry_per_ifp_slice) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot %d create cluster failed: num=%d\n\r", cap->slot, num);		
		return NULL;
	}

	for (slice = cap->ifp_max_slice - 1; slice >= 0; slice--) {
		g = &cap->ifp_slice[slice];
		
		/* 如果是使用了部分，但类型不一致的，不能使用 */
		if (g->type != sub->type && g->free_entry != cap->entry_per_ifp_slice)
			continue;
		if (g->free_entry >= num)
			break;
	}

	if (slice < 0) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot %d alloc %u entry failed: no space\n\r", cap->slot, num);
		return NULL;
	}

	list = (struct list_head *)oss_malloc(sizeof(struct list_head), OSS_MEM_HEAP);
	if (list == NULL) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Out of memory\n\r");
		return NULL;
	}
	//STLC_INIT_LIST_HEAD(list);
	list->next = list;
	list->prev = list;

		/* if new group, create */
	if (g->free_entry == cap->entry_per_ifp_slice) {
		rc = bcmx_field_group_create_id( sub->qset, g->pri, g->gid);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot%d L4 create group failed, cur slice=%d, rc=%d\n\r", 
				cap->slot, g->slice, rc);
			goto err;
		}
		/* set type */
		g->type = sub->type;	
	}

		/* create all entry now */
	for (i = 0; i < num; i++) {
		g->free_entry--;
		eid = IFP_SLICE_TO_EID(g->slice, g->free_entry);
		rc = bcmx_field_entry_create_id( g->gid, eid);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot%d L4 alloc cluster entry failed, cur slice=%d, rc=%d\n\r",
				cap->slot, g->slice, rc);
			goto err;
		}
		g->used[EID_TO_IFP_OFFSET(eid)] = true;

		/* 保存最后构造记录 */
		if (cap_add_last_build(cap, eid) != OK) {
			cap_free_entry(cap, eid);
			goto err;
		}
		
		/* put to cluster list */
		node = (list_t *)oss_malloc(sizeof(list_t), OSS_MEM_HEAP);
		if (node == NULL) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Out of memory\n\r");
			goto err;
		}
		node->value = eid;
		list_add_tail(&(node->list), list);
	}

	return list;
err:
	cap_free_entry_cluster(cap, list);
	return NULL;
}

static struct list_head *cap_alloc_efp_entry_cluster(cap_sub_info_t *sub, int num)
{
	int	rc, slice, i;
	cap_group_t	*g;
	bcm_field_entry_t	eid;
	cap_info_t	*cap = sub->cap;
	list_t *node = NULL;
	struct list_head *list = NULL;


	/* 如果要求的条目超过一组的最多容量，失败 */
	if (num > cap->entry_per_efp_slice) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot %d create cluster failed: num=%d\n\r", cap->slot, num);		
		return NULL;
	}

	for (slice = cap->efp_max_slice - 1; slice >= 0; slice--) {
		g = &cap->efp_slice[slice];
		
		/* 如果是使用了部分，但类型不一致的，不能使用 */
		if (g->type != sub->type && g->free_entry != cap->entry_per_efp_slice)
			continue;
		if (g->free_entry >= num)
			break;
	}

	if (slice < 0) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot %d alloc %u entry failed: no space\n\r", cap->slot, num);
		return NULL;
	}

	list = (struct list_head *)oss_malloc(sizeof(struct list_head), OSS_MEM_HEAP);
	if (list == NULL) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Out of memory\n\r");
		return NULL;
	}
	//STLC_INIT_LIST_HEAD(list);
	list->next = list;
	list->prev = list;

		/* if new group, create */
	if (g->free_entry == cap->entry_per_efp_slice) {
		rc = bcmx_field_group_create_id( sub->qset, g->pri, g->gid);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot%d L4 create group failed, cur slice=%d, rc=%d\n\r", 
				cap->slot, g->slice, rc);
			goto err;
		}
		/* set type */
		g->type = sub->type;	
	}

		/* create all entry now */
	for (i = 0; i < num; i++) {
		g->free_entry--;
		eid = EFP_SLICE_TO_EID(g->slice, g->free_entry);
		rc = bcmx_field_entry_create_id( g->gid, eid);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot%d L4 alloc cluster entry failed, cur slice=%d, rc=%d\n\r",
				cap->slot, g->slice, rc);
			goto err;
		}
		g->used[EID_TO_EFP_OFFSET(eid)] = true;

		/* 保存最后构造记录 */
		if (cap_add_last_build(cap, eid) != OK) {
			cap_free_entry(cap, eid);
			goto err;
		}
		
		/* put to cluster list */
		node = (list_t *)oss_malloc(sizeof(list_t), OSS_MEM_HEAP);
		if (node == NULL) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Out of memory\n\r");
			goto err;
		}
		node->value = eid;
		list_add_tail(&(node->list), list);
	}

	return list;
err:
	cap_free_entry_cluster(cap, list);
	return NULL;
}

static struct list_head *cap_alloc_vfp_entry_cluster(cap_sub_info_t *sub, int num)
{
	int	rc, slice, i;
	cap_group_t	*g;
	bcm_field_entry_t	eid;
	cap_info_t	*cap = sub->cap;
	list_t *node = NULL;
	struct list_head *list = NULL;


	/* 如果要求的条目超过一组的最多容量，失败 */
	if (num > cap->entry_per_vfp_slice) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot %d create cluster failed: num=%d\n\r", cap->slot, num);		
		return NULL;
	}

	for (slice = cap->vfp_max_slice - 1; slice >= 0; slice--) {
		g = &cap->vfp_slice[slice];
		
		/* 如果是使用了部分，但类型不一致的，不能使用 */
		if (g->type != sub->type && g->free_entry != cap->entry_per_vfp_slice)
			continue;
		if (g->free_entry >= num)
			break;
	}

	if (slice < 0) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot %d alloc %u entry failed: no space\n\r", cap->slot, num);
		return NULL;
	}

	list = (struct list_head *)oss_malloc(sizeof(struct list_head), OSS_MEM_HEAP);
	if (list == NULL) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Out of memory\n\r");
		return NULL;
	}
	//STLC_INIT_LIST_HEAD(list);
	list->next = list;
	list->prev = list;

		/* if new group, create */
	if (g->free_entry == cap->entry_per_vfp_slice) {
		rc = bcmx_field_group_create_id( sub->qset, g->pri, g->gid);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot%d L4 create group failed, cur slice=%d, rc=%d\n\r", 
				cap->slot, g->slice, rc);
			goto err;
		}
		/* set type */
		g->type = sub->type;	
	}

		/* create all entry now */
	for (i = 0; i < num; i++) {
		g->free_entry--;
		eid = VFP_SLICE_TO_EID(g->slice, g->free_entry);
		rc = bcmx_field_entry_create_id( g->gid, eid);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot%d L4 alloc cluster entry failed, cur slice=%d, rc=%d\n\r",
				cap->slot, g->slice, rc);
			goto err;
		}
		g->used[EID_TO_VFP_OFFSET(eid)] = true;

		/* 保存最后构造记录 */
		if (cap_add_last_build(cap, eid) != OK) {
			cap_free_entry(cap, eid);
			goto err;
		}
		
		/* put to cluster list */
		node = (list_t *)oss_malloc(sizeof(list_t), OSS_MEM_HEAP);
		if (node == NULL) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Out of memory\n\r");
			goto err;
		}
		node->value = eid;
		list_add_tail(&(node->list), list);
	}

	return list;
err:
	cap_free_entry_cluster(cap, list);
	return NULL;
}


/*
 * Function: cap_alloc_entry_cluster
 *    
 * Purpose:
 *     alloc some entry id.
 *     
 * Parameters:
 *     sub        - ...
 *     num        - entry num.
 *
 * Returns:
 *     list         - entry id list.
 *     NULL         - alloc failed.
 *
 */
struct list_head *cap_alloc_entry_cluster(cap_sub_info_t *sub, int num)
{
	struct list_head *list;
	switch (sub->type) {
		case CS_IFP_RULE:
		case CS_QOS_IP_IN:
		case CS_QOS_IP_OUT:
		case CS_QOS_IPV6_IN:
		case CS_QOS_IPV6_OUT:
			/* IFP */
			list = cap_alloc_ifp_entry_cluster(sub, num);
			break;
		case CS_EFP_RULE:
			/* EFP */
			list = cap_alloc_efp_entry_cluster(sub, num);
			break;
		case CS_VFP_RULE:
		case CS_VFP_QINQ_RULE:	
			/* VFP */
			list = cap_alloc_vfp_entry_cluster(sub, num);
			break;
		default:
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "invalid type.\r\n");
			list = NULL;
	}
	return list;
}

/*
 * Function: cap_get_stat
 *    
 * Purpose:
 *     get stat info.
 *     
 * Parameters:
 *     slot       - slot No.
 *     s          - save stat info(out).
 *
 * Returns:
 *     OK         - succeed
 *
 */
int cap_get_stat(int slot, cap_stat_t *s)
{
	int	slice;
	cap_info_t	*cap;
	
	memset(s, 0, sizeof(cap_stat_t));

	if ((cap = cap_info_get(slot)) == NULL)
		return ERROR;
	
	for (slice = 0; slice < BCM_IFP_SLICE_PER_UNIT; slice++) {
		s->ifp_slice[slice].entry_free = cap->ifp_slice[slice].free_entry;
		s->ifp_slice[slice].entry_used = cap->entry_per_ifp_slice - cap->ifp_slice[slice].free_entry;
		s->ifp_slice[slice].type = cap->ifp_slice[slice].type;
	}

	for (slice = 0; slice < BCM_EFP_SLICE_PER_UNIT; slice++) {
		s->efp_slice[slice].entry_free = cap->efp_slice[slice].free_entry;
		s->efp_slice[slice].entry_used = cap->entry_per_efp_slice - cap->efp_slice[slice].free_entry;
		s->efp_slice[slice].type = cap->efp_slice[slice].type;
	}

	for (slice = 0; slice < BCM_VFP_SLICE_PER_UNIT; slice++) {
		s->vfp_slice[slice].entry_free = cap->vfp_slice[slice].free_entry;
		s->vfp_slice[slice].entry_used = cap->entry_per_vfp_slice - cap->vfp_slice[slice].free_entry;
		s->vfp_slice[slice].type = cap->vfp_slice[slice].type;
	}

	return OK;
}

/*
 * Function: bcm_rule_build_begin
 *    
 * Purpose:
 *     rule start build, clear all entry.
 *     
 * Parameters:
 *     none
 *
 * Returns:
 *     OK         - succeed
 *
 */
int bcm_rule_build_begin(void)
{
	HSL_DEBUG_IPCLS(DEBUG_LEVEL_IPCLS, "L4 build begin >>>>\n\r");
	
	cap_clear_all();

	bcm_default_acl_build();
	
	return OK;
}

/*
 * Function: bcm_rule_build_finish
 *    
 * Purpose:
 *     install rule
 *     
 * Parameters:
 *     none
 *
 * Returns:
 *     ERROR      - install failed
 *     OK         - install succeed
 *
 */
int bcm_rule_build_finish(void)
{
	int	rc, slot, eid, slice, offset, total, ret = ERROR;
	cap_info_t	*cap;

	for (slot = 0; slot < MAX_LC_NUM; slot++) {
		total = 0;

		cap = cap_info_get(slot);
		/* IFP */
		for (slice = 0; slice < cap->ifp_max_slice; slice++) {	
			if((cap->ifp_slice[slice].type == CS_IFP_VLAN_IP_ACL) && (slice % 2 != 0))
				continue;
			for (offset = cap->ifp_slice[slice].free_entry; offset < cap->entry_per_ifp_slice; offset++) {
				eid = IFP_SLICE_TO_EID(slice, offset);
				HSL_DEBUG_IPCLS(DEBUG_LEVEL_IPCLS, "install rule for entry %d.\r\n", eid);
				rc = bcmx_field_entry_install( eid);
				if (rc != BCM_E_NONE) {
					printk("Install rule slot%d, entry%d failed, rc=%d\n\r", cap->slot, eid, rc);
					cap_clear_all();
					goto done;
				}
				total++;
			}
		}
		/* EFP */
		for (slice = 0; slice < cap->efp_max_slice; slice++) {			
			for (offset = cap->efp_slice[slice].free_entry; offset < cap->entry_per_efp_slice; offset++) {
				eid = EFP_SLICE_TO_EID(slice, offset);
				HSL_DEBUG_IPCLS(DEBUG_LEVEL_IPCLS, "install rule for entry %d.\r\n", eid);
				rc = bcmx_field_entry_install( eid);
				if (rc != BCM_E_NONE) {
					printk("Install rule slot%d, entry%d failed, rc=%d\n\r", cap->slot, eid, rc);
					cap_clear_all();
					goto done;
				}
				total++;
			}
		}
		/* VFP */
		for (slice = 0; slice < cap->vfp_max_slice; slice++) {			
			for (offset = cap->vfp_slice[slice].free_entry; offset < cap->entry_per_vfp_slice; offset++) {
				eid = VFP_SLICE_TO_EID(slice, offset);
				HSL_DEBUG_IPCLS(DEBUG_LEVEL_IPCLS, "install rule for entry %d.\r\n", eid);
				rc = bcmx_field_entry_install( eid);
				if (rc != BCM_E_NONE) {
					printk("Install rule slot%d, entry%d failed, rc=%d\n\r", cap->slot, eid, rc);
					cap_clear_all();
					goto done;
				}
				total++;
			}
		}
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_IPCLS, "Slot%d L4 build finish, total entry=%d <<<<\n\r", cap->slot, total);
	}
	ret = OK;

done:	
	return ret;
}

int ifindexpbmp_2_lplist(l4_pbmp_t *ifindexpbmp,  bcmx_lplist_t *lplist)
{
	int i;
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;
	C_PBMP_ITER(*ifindexpbmp, i) {
		ifp = hsl_ifmgr_lookup_by_index(i + HSL_L2_IFINDEX_START);
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_IPCLS, "  add port ifindex %d to lplist.\r\n", i + HSL_L2_IFINDEX_START);
		bcmif = (struct hsl_bcm_if *)ifp->system_info;
		bcmx_lplist_add(lplist, bcmif->u.l2.lport);
	}
	return OK;
}

int vlanifindex_2_vid(int vlanifindex,  bcm_vlan_t *vid)
{
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;

	ifp = hsl_ifmgr_lookup_by_index(vlanifindex);
	if (ifp == NULL)
		return ERROR;
	bcmif = (struct hsl_bcm_if *)ifp->system_info;
	if (bcmif == NULL)
		return ERROR;

	*vid = bcmif->u.l3.vid;

	return OK;
}

int cap_check_free_ifp_entry(cap_sub_info_t *sub, int need_entry)
{
	cap_info_t	*cap = sub->cap;
	int	free_entry, slice;
	cap_group_t	*g;

	free_entry = 0;

	for (slice = 0; slice < BCM_IFP_SLICE_PER_UNIT; slice++) {
		g = &cap->ifp_slice[slice];
		if (g->free_entry == BCM_ENTRY_PER_IFP_SLICE || g->type == sub->type)
			free_entry += g->free_entry;
	}
	
	return ((free_entry >= need_entry) ? OK : ERROR);
}

int cap_check_vlan_ip_acl_free_entry(cap_sub_info_t *sub, int need_entry)
{
	cap_info_t	*cap = sub->cap;
	int	free_entry, slice;
	cap_group_t	*g;

	free_entry = 0;

	for (slice = 0; slice < BCM_IFP_SLICE_PER_UNIT; slice++) {
		if(slice % 2 != 0)
			continue;

		g = &cap->ifp_slice[slice];
		if (g->free_entry == BCM_ENTRY_PER_IFP_SLICE || g->type == sub->type)
			free_entry += g->free_entry;
	}
	
	return ((free_entry >= need_entry) ? OK : ERROR);
}

int cap_check_ipmac_acl_free_entry(cap_sub_info_t *sub, int need_entry)
{
	cap_info_t	*cap = sub->cap;
	int	free_entry, slice;
	cap_group_t	*g;

	free_entry = 0;

	for (slice = 0; slice < BCM_IFP_SLICE_PER_UNIT; slice++) {
		if(slice % 2 != 0)
			continue;

		g = &cap->ifp_slice[slice];
		if (g->free_entry == BCM_ENTRY_PER_IFP_SLICE || g->type == sub->type)
			free_entry += g->free_entry;
	}
	
	return ((free_entry >= need_entry) ? OK : ERROR);
}

