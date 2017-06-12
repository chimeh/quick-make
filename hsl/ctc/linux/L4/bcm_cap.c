#include "config.h"
#include "hsl_os.h"

#include "hsl_types.h"

/* Broadcom includes. */
//#include "bcm_incl.h"

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

#include <linux/kernel.h>
//#include "bcm/field.h"
//#include "bcm/types.h"
//#include "bcm/error.h"
//#include "sal/core/sync.h"
#include <linux/list.h>
#include <linux/types.h>
#include "hsl_oss.h"
#include "bcm_cap.h"
#include "bcm_l4_debug.h"
#include "hal/layer4/hal_l4_config.h"
#include "layer4/pbmp.h"
#include "ctc_api.h"
#include "ctc_if_portmap.h"
#include "auth_rule_build.h"

typedef struct hsl_ctc_acl_group_s{
	int used;
	int group_id;
}hsl_ctc_acl_group_t;

hsl_ctc_acl_group_t hsl_ctc_acl_group[CTC_ACL_BOLCK_PER_UNIT];
  
cap_info_t chassis_cap_info[MAX_LC_NUM];
static int group_id = 0xffff0003;
static int policer_id = 0;



#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, head, member)				\
	((pos)->member.next == (head))? NULL :  \
			list_entry((pos)->member.next, typeof(*pos), member)


int policer_id_create(void)
{
	policer_id++;

	printk("policer_id_create, policer_id = %#x\r\n", policer_id);
	return policer_id;
}

void policer_id_reset(void)
{
	policer_id = 0;
}


int group_id_create(void)
{
	
	if (group_id > CTC_ACL_GROUP_ID_MAX)
		return -1;

	group_id++;

	printk("group_id_create, group_id = %#x\r\n", group_id);
	return group_id;
}

int eap_group_id_get(unsigned int eid)
{
	int block_id;
	int group_id;
	int offset;

	block_id = EID_TO_IFP_BLOCK(eid);
	offset = EID_TO_IFP_OFFSET(eid);

	group_id = 0xffff0003 + (block_id-1)*offset;

	//printk("eid = %#x, block_id = %d, offset = %d, group_id = %#x\r\n", eid, block_id, offset, group_id);

	if (group_id <= CTC_ACL_EAP_GROUP_BEGIN || group_id >= CTC_ACL_EAP_GROUP_END) {
		printk("group_id = %#x, CTC_ACL_EAP_GROUP_BEGIN = %#x, CTC_ACL_EAP_GROUP_END = %#x\r\n",
							group_id,
							CTC_ACL_EAP_GROUP_BEGIN,
							CTC_ACL_EAP_GROUP_END);
		return -1;
	}

	return group_id;
}

/*note: group id 前面的一段保留给eap认证使用*/
void group_id_reset(void)
{
	group_id = 0xffff0003 + (EAP_RULE_BLOCK_NUMBER * CTC_ENTRY_PER_BLOCK) + 1;
	printk("group id reset to %#x\r\n", group_id);
}

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

	{CS_EAP_ACL, "eap-rule"},	

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
		cap->ifp_max_slice = CTC_ACL_BOLCK_PER_UNIT;
		cap->entry_per_ifp_slice = CTC_ENTRY_PER_BLOCK;

		((struct list_head *)&cap->last_build)->next = (struct list_head *)&cap->last_build;
		((struct list_head *)&cap->last_build)->prev = (struct list_head *)&cap->last_build;

		/*acl group 管理链表*/
		((struct list_head *)&cap->group_id)->next = (struct list_head *)&cap->group_id;
		((struct list_head *)&cap->group_id)->prev = (struct list_head *)&cap->group_id;

		/*policer 管理链表*/
		((struct list_head *)&cap->policer)->next = (struct list_head *)&cap->policer;
		((struct list_head *)&cap->policer)->prev = (struct list_head *)&cap->policer;		

		for (k = 0; k < CTC_ACL_BOLCK_PER_UNIT; k++) {
			hsl_ctc_acl_group[k].used = 0;
			hsl_ctc_acl_group[k].group_id = k + 0xffff0003;
		}
				
		offset = 0;
		/* IFP */
		for (k = 0; k < CTC_ACL_BOLCK_PER_UNIT; k++) {
			cap_group_t	*gp;
			gp = &cap->ifp_slice[k];
			gp->type = MAX_CAP_SUB;
			gp->pri = k;
			gp->gid = k + 0xffff0003;
			gp->slice = k;
			gp->free_entry = CTC_ENTRY_PER_BLOCK;
		}
		offset += k;

		
		for (k = 0; k < MAX_CAP_SUB; k++) {
			cap_sub_info_t	*sub = &cap->sub[k];
			sub->type = k;
			sub->cap = cap;
		}
	
		
	}

	return OK;
}



int
hsl_layer4_init(void)
{
	int ret;
	
	ret = cap_init();
	if (ret != OK) {
		return ERROR;
	}

	ret = hsl_eap_rule_init();
	if (ret != 0) {
		return ERROR;		
	}

	return OK;	
}




int policer_list_add(cap_info_t *cap, uint32 val, void *data)
{
	list_t	*node;
	struct list_head *list;


	list = &(cap->policer);

	/* put to cluster list */
	node = (list_t *)oss_malloc(sizeof(list_t), OSS_MEM_HEAP);
	if (node == NULL) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Out of memory\n\r");
		return -1;
	}
	node->value = val;
	node->data = data;
	list_add_tail(&(node->list), list);

	return 0;
}

int policer_list_clear(struct list_head *list)
{
	list_t	*node;
	struct list_head *p;

	p = list;

	while(p && (p->next != p && p->prev != p)) {
		node = (list_t *)p->next;
		p->next->next->prev = p;
		p->next = p->next->next;
		if (node->data) {
			oss_free(node->data, OSS_MEM_HEAP);	
		}

		oss_free(node, OSS_MEM_HEAP);
	}
}



int group_id_list_add(cap_info_t *cap, uint32 group_id)
{
	list_t	*node;
	struct list_head *list;


	list = &(cap->group_id);

	/* put to cluster list */
	node = (list_t *)oss_malloc(sizeof(list_t), OSS_MEM_HEAP);
	if (node == NULL) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Out of memory\n\r");
		return -1;
	}
	node->value = group_id;
	list_add_tail(&(node->list), list);

	return 0;
}

int group_id_list_clear(struct list_head *list)
{
	list_t	*node;
	struct list_head *p;

	p = list;

	while(p && (p->next != p && p->prev != p)) {
		node = (list_t *)p->next;
		p->next->next->prev = p;
		p->next = p->next->next;
		if (node->data) {
			oss_free(node->data, OSS_MEM_HEAP);	
		}

		oss_free(node, OSS_MEM_HEAP);
	}
}


/*
 * Function: cap_free_entry_id
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
void cap_free_entry_id(cap_info_t *cap, uint32 eid)
{
	int	slice = 0, rc = 0, offset = 0;
	int i;
	cap_group_t	*g = NULL;
	list_t *node = NULL;
	struct list_head *p = NULL;
	int bcm_entry_per_slice = 0;

	if (NULL == cap) {
		return -1;
	}

	slice = EID_TO_IFP_BLOCK(eid);
	offset = EID_TO_IFP_OFFSET(eid);

	g = &cap->ifp_slice[slice];
	bcm_entry_per_slice = CTC_ENTRY_PER_BLOCK;

	if (!g->used[offset])
	{
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap free entry bug: slice=%d, offset=%d, eid=%u, not used\n\r",
			slice, offset, eid);
		return;
	}

	g->used[offset] = false;
	g->free_entry++;

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
void cap_free_entry(cap_info_t *cap, uint32 eid)
{
	int	slice = 0, rc = 0, offset = 0;
	int i;
	cap_group_t	*g = NULL;
	list_t *node = NULL;
	struct list_head *p = NULL;
	int bcm_entry_per_slice = 0;

	slice = EID_TO_IFP_BLOCK(eid);
	offset = EID_TO_IFP_OFFSET(eid);

	g = &cap->ifp_slice[slice];
	bcm_entry_per_slice = CTC_ENTRY_PER_BLOCK;

	/* 销毁该条目 */
	rc = ctc_acl_uninstall_entry(eid);
	if (rc != CTC_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap uninstall entry failed: rc = %d\n\r", rc);
	}

	rc = ctc_acl_remove_entry(eid);
	if (rc != CTC_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "cap remove entry failed: rc = %d\n\r", rc);
	}

	/* 把最后构造中的记录去掉 */
	p = &cap->last_build;
	while(p && (p->next != p && p->prev != p)) {
		node = (list_t *)p->next;
		p->next->next->prev = p;
		p->next = p->next->next;
		if (node->data) {
			oss_free(node->data, OSS_MEM_HEAP);	
		}
		
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
		if (node->data) {
			oss_free(node->data, OSS_MEM_HEAP);	
		}
		
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
		if (node->data) {
			oss_free(node->data, OSS_MEM_HEAP);	
		}

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
    int eid;
	cap_group_t	*g;
	uint32 group_id;
	list_t	*node;
	struct list_head *group = &(cap->group_id);
	struct list_head *policer = &(cap->policer);	
	
	/* destroy IFP group */
	for (i = 0; i < cap->ifp_max_slice; i++) {
		g = &cap->ifp_slice[i];
		g->free_entry = CTC_ENTRY_PER_BLOCK;
		for (k = 0; k < CTC_ENTRY_PER_BLOCK; k++) {
            if (g->used[k] == true) {
   				eid = IFP_BLOCK_TO_EID(i, k);
   				ctc_acl_uninstall_entry( eid);
				ctc_acl_remove_entry (eid);
			    g->used[k] = false;
            }
		}
		//ctc_acl_uninstall_group (g->gid);
		//ctc_acl_destroy_group (g->gid);	
		g->type = MAX_CAP_SUB;
		hsl_ctc_acl_group[i].used = 0;
	}

	for (node = list_first_entry(group, list_t, list);
		node != NULL;
		node = list_next_entry(node, group, list))
	{
		group_id  = node->value;
		ctc_acl_uninstall_group (group_id);
		ctc_acl_destroy_group (group_id);	
	}	
	group_id_list_clear(group);

	for (node = list_first_entry(policer, list_t, list);
		node != NULL;
		node = list_next_entry(node, policer, list))
	{
		group_id  = node->value;
		ctc_acl_uninstall_group (group_id);
		ctc_acl_destroy_group (group_id);	
	}

	group_id_list_clear(policer);

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

static uint32 cap_alloc_ifp_entry(cap_sub_info_t *sub, int *block_id)
{
	int	rc, slice, i;
	cap_group_t	*g = NULL;
	uint32 eid;
	cap_info_t	*cap = sub->cap;

	if (NULL == block_id) {
		return -1;
	}

	printk("cap_alloc_ifp_entry\r\n");
	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "cap_alloc_ifp_entry, slice = %d, i = %d\n\r", g->slice, i);	

	/*选择一个有空闲表项的block， 从低优先级开始,但是最后两个slice留给eap使用*/
	for (i = CTC_ACL_DEFAULT_BLOCK_END; i >= CTC_ACL_DEFAULT_BLOCK_BEGIN; i--) {
		if (0 != cap->ifp_slice[i].free_entry) {
			g = &cap->ifp_slice[i];
			*block_id = i;
			printk("block_id = %d\r\n", *block_id);
			break;
		}
	}

	if (NULL == g) {
		return -1;
	}

	/* 创建条目 */
	g->free_entry--;
	for(i = CTC_ENTRY_PER_BLOCK - 1; i >= 0; i--){
		eid = IFP_BLOCK_TO_EID(g->slice, i);
		if(g->used[EID_TO_IFP_OFFSET(eid)] == false)
			break;
	}

	/* 设置使用标志 */
	g->used[EID_TO_IFP_OFFSET(eid)] = true;

	return eid;
}


static uint32 cap_alloc_eap_entry(cap_sub_info_t *sub, int *block_id)
{
	int	rc, slice, i;
	cap_group_t	*g = NULL;
	uint32 eid;
	cap_info_t	*cap = sub->cap;

	if (NULL == block_id) {
		return -1;
	}

	//printk("cap_alloc_ifp_entry\r\n");
	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "cap_alloc_ifp_entry, slice = %d, i = %d\n\r", g->slice, i);	

	if (CTC_ACL_BOLCK_PER_UNIT <= EAP_RULE_BLOCK_NUMBER) {
		printk("eap block error\r\n", *block_id);
		return -1;
	}

	/*选择一个有空闲表项的block， 从低优先级开始,*/
	for (i = CTC_ACL_EAP_BLOCK_END; i >= CTC_ACL_EAP_BLOCK_BEGIN; i--) {
		if (0 != cap->ifp_slice[i].free_entry) {
			g = &cap->ifp_slice[i];
			*block_id = i;
			printk("block_id = %d\r\n", *block_id);
			break;
		}
	}

	if (NULL == g) {
		return -1;
	}

	/* 创建条目 */
	g->free_entry--;
	for(i = CTC_ENTRY_PER_BLOCK - 1; i >= 0; i--){
		eid = IFP_BLOCK_TO_EID(g->slice, i);
		if(g->used[EID_TO_IFP_OFFSET(eid)] == false)
			break;
	}

	/* 设置使用标志 */
	g->used[EID_TO_IFP_OFFSET(eid)] = true;

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
uint32 cap_alloc_entry(cap_sub_info_t *sub, int *block_id)
{
	uint32 eid;
	switch (sub->type) {
		case CS_IFP_RULE:
		case CS_DEFAULT_ACL:
		case CS_IFP_IP_ACL:
		case CS_IFP_VLAN_IP_ACL:
		case CS_IFP_MAC_ACL:
		case CS_MIRROR_RULE:
		case CS_EFP_RULE:
		case CS_EFP_IP_ACL:
		case CS_VFP_RULE:
		case CS_VFP_IP_ACL:		
			eid = cap_alloc_ifp_entry(sub, block_id);
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "cap_alloc_entry, eid = %#x, block_id = %#x\n\r", eid, *block_id);
			break;
		case CS_EAP_ACL:				
			eid = cap_alloc_eap_entry(sub, block_id);
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "cap_alloc_entry, eid = %#x, block_id = %#x\n\r", eid, *block_id);
			break;			
		default:
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "invalid type.\r\n");
			eid = -1;
	}

	return eid;
}

uint32 cap_alloc_group(int num)
{
	int group_id = -1;
	int i;

	for (i = CTC_ACL_BOLCK_PER_UNIT -1; i >= 0; i--) {
		if (!hsl_ctc_acl_group[i].used) {
			group_id = hsl_ctc_acl_group[i].group_id;
			hsl_ctc_acl_group[i].used = 1;
			break;
		}
	}

	return group_id;
}




static struct list_head *cap_alloc_ifp_entry_cluster(cap_sub_info_t *sub, int num, int *block_id)
{
	int	rc, slice, i, j;
	cap_group_t	*g;
	uint32 eid;	
	cap_info_t	*cap = sub->cap;
	list_t *node = NULL;
	ctc_acl_entry_t *data;
	struct list_head *list = NULL;

	if (NULL == block_id || NULL == sub) {
		return NULL;
	}

	/* 如果要求的条目超过一组的最多容量，失败 */
	if (num > cap->entry_per_ifp_slice) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "slot %d create cluster failed: num=%d\n\r", cap->slot, num);		
		return NULL;
	}

	/*选择一个有空闲表项的block， 从低优先级开始*/
	for (i = CTC_ACL_BOLCK_PER_UNIT -1; i >= 0; i--) {
		if (cap->ifp_slice[i].free_entry >= num) {
			g = &cap->ifp_slice[i];
			*block_id = i;
			printk("block_id = %d\r\n", *block_id);
			break;
		}
	}


	list = (struct list_head *)oss_malloc(sizeof(struct list_head), OSS_MEM_HEAP);
	if (list == NULL) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Out of memory\n\r");
		return NULL;
	}
	//STLC_INIT_LIST_HEAD(list);
	list->next = list;
	list->prev = list;

	/*定位到第一个未使用的条目*/
	for(j = CTC_ENTRY_PER_BLOCK - 1; j >= 0; j--){
		eid = IFP_BLOCK_TO_EID(g->slice, j);
		if(g->used[EID_TO_IFP_OFFSET(eid)] == false)
			break;
	}

		/* create all entry now */
	for (i = 0; i < num; i++) {
		/* 创建条目 */
		g->free_entry--;
		eid = IFP_BLOCK_TO_EID(g->slice, j);
		j--;

		/* 设置使用标志 */
		g->used[EID_TO_IFP_OFFSET(eid)] = true;

		/* put to cluster list */
		node = (list_t *)oss_malloc(sizeof(list_t), OSS_MEM_HEAP);
		if (node == NULL) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Out of memory\n\r");
			goto err;
		}
		data = (list_t *)oss_malloc(sizeof(ctc_acl_entry_t), OSS_MEM_HEAP);
		if (node == NULL) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_IPCLS, "Out of memory\n\r");
			goto err;
		}
		memset(data, 0, sizeof(ctc_acl_entry_t));
		data->entry_id = eid;
		
		node->value = eid;
		node->data = data;
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
struct list_head *cap_alloc_entry_cluster(cap_sub_info_t *sub, int num, int *group_id)
{
	struct list_head *list;
	switch (sub->type) {
		case CS_IFP_RULE:
		case CS_QOS_IP_IN:
		case CS_QOS_IP_OUT:
		case CS_QOS_IPV6_IN:
		case CS_QOS_IPV6_OUT:
		case CS_EFP_RULE:
		case CS_VFP_RULE:
		case CS_VFP_QINQ_RULE:	
			/* IFP */
			list = cap_alloc_ifp_entry_cluster(sub, num, group_id);			
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

	for (slice = 0; slice < CTC_ACL_BOLCK_PER_UNIT; slice++) {
		s->ifp_slice[slice].entry_free = cap->ifp_slice[slice].free_entry;
		s->ifp_slice[slice].entry_used = cap->entry_per_ifp_slice - cap->ifp_slice[slice].free_entry;
		s->ifp_slice[slice].type = cap->ifp_slice[slice].type;
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

	//bcm_default_acl_build();
	
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
		HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "bcm_rule_build_finish, slot = %d.\r\n", slot);
		/* IFP */
		for (slice = 0; slice < cap->ifp_max_slice; slice++) {	
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "bcm_rule_build_finish, slice = %d, free entry = %d\r\n", slice, cap->ifp_slice[slice].free_entry);
			for (offset = cap->ifp_slice[slice].free_entry; offset < cap->entry_per_ifp_slice; offset++) {
				HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "bcm_rule_build_finish, offset = %d.\r\n", offset);		
				eid = IFP_BLOCK_TO_EID(slice, offset);
				HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "install rule for entry %d.\r\n", eid);
				rc = ctc_acl_install_entry(eid);
				printk("install rule for entry %d.\r\n", eid);
				if (rc != CTC_E_NONE) {
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
#define CTC_IS_BIT_SET(flag, bit)   (((flag) & (1 << (bit))) ? 1 : 0)
#define CTC_BIT_SET(flag, bit)      ((flag) = (flag) | (1 << (bit)))
#define CTC_BIT_UNSET(flag, bit)    ((flag) = (flag) & (~(1 << (bit))))

int ifindexpbmp_2_gportmap(l4_pbmp_t *ifindexpbmp,  ctc_port_bitmap_t *port_map)
{
	int i;
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;
	unsigned short gport;
	C_PBMP_ITER(*ifindexpbmp, i) {
		gport =  IFINDEX_TO_GPORT(i + HSL_L2_IFINDEX_START);
		printk("ifindexpbmp_2_gportmap, ifindex = %d, gport = %#x\r\n", i + HSL_L2_IFINDEX_START, gport);
		CTC_BIT_SET((*port_map)[gport /CTC_UINT32_BITS], (gport %CTC_UINT32_BITS));
		printk("ifindexpbmp_2_gportmap---------------------------\r\n");
	}
	return OK;
}


int vlanifindex_2_vid(int vlanifindex,  uint16 *vid)
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

	for (slice = 0; slice < CTC_ACL_BOLCK_PER_UNIT; slice++) {
		g = &cap->ifp_slice[slice];
		if (g->free_entry == CTC_ENTRY_PER_BLOCK || g->type == sub->type)
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

	for (slice = 0; slice < CTC_ACL_BOLCK_PER_UNIT; slice++) {
		g = &cap->ifp_slice[slice];
		if (g->free_entry == CTC_ENTRY_PER_BLOCK || g->type == sub->type)
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

	for (slice = 0; slice < CTC_ACL_BOLCK_PER_UNIT; slice++) {


		g = &cap->ifp_slice[slice];
		if (g->free_entry == CTC_ENTRY_PER_BLOCK || g->type == sub->type)
			free_entry += g->free_entry;
	}
	
	return ((free_entry >= need_entry) ? OK : ERROR);
}

