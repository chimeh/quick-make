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


#include "hal/layer4/acl/access_list_rule.h"
#include "layer4/qos/qos.h"
#include "hal/layer4/qos/qos_rule.h"
#include "hal/layer4/hal_l4_api.h"
//#include "bcm/field.h"
//#include "bcm/types.h"
//#include "bcm/error.h"
#include "layer4/acl/cli_acl.h"
#include "layer4/pbmp.h"
#include "bcm_cap.h"
#include "acl_build.h"
#include "bcm_l4_debug.h"
#include "ctc_api.h"


#if 0
extern int bcm_cosq_port_bandwidth_set(
	int unit, 
	bcm_port_t port, 
	bcm_cos_queue_t cosq, 
	uint32 kbits_sec_min, 
    uint32 kbits_sec_max, 
    uint32 flags);
#endif

struct hal_msg_l4_acl_group_set;

#if 0
int bcm_unit_local(int unit)
{
    return (BCM_UNIT_VALID(unit) && BCM_IS_LOCAL(unit));
}

int bcm_cpu_port_get(int unit)
{
	if (bcm_unit_local(unit)) {
		return CMIC_PORT(unit);
	}
	return -1;
}

#endif

bool is_qos_sub_type(int sub_type)
{
	if (CS_QOS_IP_IN == sub_type || CS_QOS_IP_OUT == sub_type
		|| CS_QOS_IPV6_IN == sub_type|| CS_QOS_IPV6_OUT == sub_type) 
	{
		return TRUE;
	}

	return FALSE;
}

static int ipf_build_acl_ext_base(cap_info_t *cap, 
			ctc_acl_entry_t *ctc_entry, struct ext_ip_hdr_info *iph)
{
	int	rc;
	u32	ip, mask;


	/* src addr */
	mask = ~(iph->src.mask);
	ip = iph->src.addr & mask;



	ctc_entry->key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_IP_SA;
	ctc_entry->key.u.ipv4_key.ip_sa = ip;
	ctc_entry->key.u.ipv4_key.ip_sa_mask = mask;	



	/* dst addr */
	mask = ~(iph->dst.mask);
	ip = iph->dst.addr & mask;
	ctc_entry->key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_IP_DA;
	ctc_entry->key.u.ipv4_key.ip_da = ip;
	ctc_entry->key.u.ipv4_key.ip_da_mask = mask;	




	/* tos */
	ctc_entry->key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_DSCP;
	ctc_entry->key.u.ipv4_key.dscp = iph->tos.value;
	ctc_entry->key.u.ipv4_key.dscp_mask = 0xFC;
	printk("TOS value = %#x, mask = %#x\r\n", iph->tos.value, 0xFC);
	
	/* protocol */	
	if (iph->proto != IPPROTO_ANY) {
		ctc_entry->key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_L4_PROTOCOL;
		ctc_entry->key.u.ipv4_key.l4_protocol = iph->proto;
		ctc_entry->key.u.ipv4_key.l4_protocol_mask = 0xFF;
	}

	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "ext acl for %u: %u.%u.%u.%u/%u.%u.%u.%u, TOS %u/%u, PROTO %u/%u\n\r",
		ctc_entry->entry_id, NIPQUAD(ip), NIPQUAD(mask), iph->tos.value, iph->tos.mask, 
		iph->proto == IPPROTO_ANY ? 0 : iph->proto, iph->proto == IPPROTO_ANY ? 0 : 0xFF);

	return OK;
}

/*
	构造TCP/UDP的源端口和目的端口
*/
static int ipf_build_l4_port(cap_info_t *cap, ctc_acl_entry_t *ctc_entry,
		struct port_info *src_port, struct port_info *dst_port, bool is_tcp)
{
	int	rc;
	bool	warning = FALSE;

	if(src_port->op == OP_EQ) {
		ctc_entry->key.u.ipv4_key.sub_flag |= CTC_ACL_IPV4_KEY_SUB_FLAG_L4_SRC_PORT;
		ctc_entry->key.u.ipv4_key.l4_src_port_use_mask = 1;
		ctc_entry->key.u.ipv4_key.l4_src_port_0 = src_port->lower;
		ctc_entry->key.u.ipv4_key.l4_src_port_1 = 0xFFFF;
				
	}else if(src_port->op == OP_RANGE){ //range关键字
		ctc_entry->key.u.ipv4_key.sub_flag |= CTC_ACL_IPV4_KEY_SUB_FLAG_L4_SRC_PORT;
		ctc_entry->key.u.ipv4_key.l4_src_port_0 = src_port->lower;
		ctc_entry->key.u.ipv4_key.l4_src_port_1 = src_port->upper;

	}else if(src_port->op == OP_GT)	{ //gt关键字
		ctc_entry->key.u.ipv4_key.sub_flag |= CTC_ACL_IPV4_KEY_SUB_FLAG_L4_SRC_PORT;
		ctc_entry->key.u.ipv4_key.l4_src_port_0 = src_port->lower + 1;
		ctc_entry->key.u.ipv4_key.l4_src_port_1 = MAX_BCM_L4_PORT;

	}	else if(src_port->op == OP_LT)	{ //lt关键字
		ctc_entry->key.u.ipv4_key.sub_flag |= CTC_ACL_IPV4_KEY_SUB_FLAG_L4_SRC_PORT;
		ctc_entry->key.u.ipv4_key.l4_src_port_0 = MIN_BCM_L4_PORT;
		ctc_entry->key.u.ipv4_key.l4_src_port_1 = src_port->lower - 1;

	}	else if (src_port->op != OP_NONE) {
		warning = TRUE;
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "unsupport l4 port type (op=%d)\n\r", src_port->op);
	}

	if(dst_port->op == OP_EQ) {
		ctc_entry->key.u.ipv4_key.sub_flag |= CTC_ACL_IPV4_KEY_SUB_FLAG_L4_DST_PORT;
		ctc_entry->key.u.ipv4_key.l4_dst_port_use_mask = 1;
		ctc_entry->key.u.ipv4_key.l4_dst_port_0 = dst_port->lower;
		ctc_entry->key.u.ipv4_key.l4_dst_port_1 = 0xFFFF;
		
	} else if(dst_port->op == OP_RANGE){
		ctc_entry->key.u.ipv4_key.sub_flag |= CTC_ACL_IPV4_KEY_SUB_FLAG_L4_DST_PORT;
		ctc_entry->key.u.ipv4_key.l4_dst_port_0 = dst_port->lower;
		ctc_entry->key.u.ipv4_key.l4_dst_port_1 = dst_port->upper;
	
	}else if(dst_port->op == OP_GT)	{ //gt关键字
		ctc_entry->key.u.ipv4_key.sub_flag |= CTC_ACL_IPV4_KEY_SUB_FLAG_L4_DST_PORT;
		ctc_entry->key.u.ipv4_key.l4_dst_port_0 = dst_port->lower + 1;
		ctc_entry->key.u.ipv4_key.l4_dst_port_1 = MAX_BCM_L4_PORT;	

	}	else if(dst_port->op == OP_LT)	{ //lt关键字
		ctc_entry->key.u.ipv4_key.sub_flag |= CTC_ACL_IPV4_KEY_SUB_FLAG_L4_SRC_PORT;
		ctc_entry->key.u.ipv4_key.l4_dst_port_0 = MIN_BCM_L4_PORT;
		ctc_entry->key.u.ipv4_key.l4_dst_port_1 = dst_port->lower - 1;
	
	}else if (dst_port->op != OP_NONE) {
		warning = TRUE;
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "unsupport l4 port type (op=%d)\n\r", dst_port->op);
	}

	if (warning) {
		printk("\n\r%%ACL with unsupport l4port type  on Ethernet Interface. Ignore it.\n\r"
			"Please refer to the Software Configuration Guide for all the supported keywords.\n\r\n\r");
	}

	return OK;
}

int acl_build_action(cap_info_t *cap, ctc_acl_entry_t *ctc_entry, bool permit)
{
	int	rc;
	
	if (!permit) {
		ctc_entry->action.flag |= CTC_ACL_ACTION_FLAG_DISCARD;
	}

	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "%s for %u\n\r", permit ? "bcmFieldActionDropCancel" : "bcmFieldActionDrop", ctc_entry->entry_id);
	return OK;
}

int ctc_build_acl_std(	ctc_acl_entry_t *ctc_entry, 
			struct std_access_entry *entry, cap_sub_info_t *sub)
{
	int	rc;
	u32	ip, mask;
	cap_info_t *cap = sub->cap;

	/* FPF2 FIELD SET */
	mask = ~(entry->iph.src.mask);
	ip = entry->iph.src.addr & mask;
	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "std acl for %u: %u.%u.%u.%u/%u.%u.%u.%u\n\r", ctc_entry->entry_id, NIPQUAD(ip), NIPQUAD(mask));

	ctc_entry->key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_IP_SA;
	ctc_entry->key.u.ipv4_key.ip_sa = ip;
	ctc_entry->key.u.ipv4_key.ip_sa_mask = mask;

	/* action */
 	if ( ! is_qos_sub_type(sub->type) ) 	{
		if (acl_build_action(cap, ctc_entry, entry->hdr.permit) != OK)
			goto err;
	}

	return OK;

err:
	return ERROR;
}

int ctc_build_acl_ext_ip(ctc_acl_entry_t *ctc_entry,
	struct ext_ip_access_entry *entry, cap_sub_info_t *sub)
{
	struct ext_ip_hdr_info *iph;
	cap_info_t *cap = sub->cap;

	iph = &entry->iph;
	
	/* FPF2 FIELD SET */
	if (ipf_build_acl_ext_base(cap, ctc_entry, iph) != OK)
		goto err;

	/* action */
 	if ( ! is_qos_sub_type(sub->type) ) 	{
		if (acl_build_action(cap, ctc_entry, entry->hdr.permit) != OK)
			goto err;
	}

	return OK;
	
err:
	return ERROR;
}

int ctc_build_acl_udp(ctc_acl_entry_t *ctc_entry, 
	struct ext_udp_access_entry *entry, cap_sub_info_t *sub)
{
	struct ext_ip_hdr_info *iph;
	struct udp_hdr_info *udph;
	cap_info_t *cap = sub->cap;
	int tmp_proto;



	iph = &entry->iph;
	udph = &(entry->udph);
	tmp_proto = iph->proto; /*暂时记录proto的值*/
#if 1
	/* FPF2 FIELD SET */
	iph->proto = PROTOCOL_UDP;
	if (ipf_build_acl_ext_base(cap, ctc_entry, iph) != OK){
		iph->proto = tmp_proto;
		goto err;
	}
	iph->proto = tmp_proto;
#endif

#if 1
	/* udp src port & dst port */
	if (ipf_build_l4_port(cap, ctc_entry, &udph->src_port, &udph->dst_port, FALSE) != OK)
		goto err;

	/* action */
 	if ( ! is_qos_sub_type(sub->type) ) 	{
		if (acl_build_action(cap, ctc_entry, entry->hdr.permit) != OK)
			goto err;
	}
#endif
	return OK;
	
err:
	return ERROR;
}

int ctc_build_acl_tcp(ctc_acl_entry_t *ctc_entry, 
	struct ext_tcp_access_entry *entry, cap_sub_info_t *sub)
{
	struct ext_ip_hdr_info *iph;
	struct tcp_hdr_info *tcph;
	cap_info_t *cap = sub->cap;
	int tmp_proto;
	
	iph = &entry->iph;
	tcph = &(entry->tcph);
	tmp_proto = iph->proto; /*暂时记录proto的值*/

	/* FPF2 FIELD SET */
	iph->proto = PROTOCOL_TCP;
	if (ipf_build_acl_ext_base(cap, ctc_entry, iph) != OK){
		iph->proto = tmp_proto;
		goto err;
	}
	iph->proto = tmp_proto;

	if (tcph->estab){
		printk("\n\r%%TCP ACL with 'SYNC' keyword is not supported on Ethernet Interface. Ignore it.\n\r"
			"Please refer to the Software Configuration Guide for all the supported keywords.\n\r\n\r");

	}

	/* tcp src port & dst port */
	if (ipf_build_l4_port(cap, ctc_entry, &tcph->src_port, &tcph->dst_port, TRUE) != OK)
		goto err;

	/* action */
 	if ( ! is_qos_sub_type(sub->type) ) 	{
		if (acl_build_action(cap, ctc_entry, entry->hdr.permit) != OK)
			goto err;
	}

	return OK;
	
err:
	return ERROR;
}

int ctc_build_acl_icmp(ctc_acl_entry_t *ctc_entry, 
	struct ext_icmp_access_entry *entry, cap_sub_info_t *sub)
{
	struct ext_ip_hdr_info *iph;
	struct icmp_hdr_info *icmph;
	cap_info_t *cap = sub->cap;
	int tmp_proto;

	iph = &entry->iph;
	icmph = &(entry->icmph);
	tmp_proto = iph->proto; /*暂时记录proto的值*/

	/* FPF2 FIELD SET */
	iph->proto = PROTOCOL_ICMP;
	if (ipf_build_acl_ext_base(cap, ctc_entry, iph) != OK){
		iph->proto = tmp_proto;
		goto err;
	}
	iph->proto = tmp_proto;
	
	/* action */
 	if ( ! is_qos_sub_type(sub->type) ) 	{
		if (acl_build_action(cap, ctc_entry, entry->hdr.permit) != OK)
			goto err;
	}
	
	if (icmph->flags != FLAGS_NOT_SET) {
		printk("\n\r%%ACL with 'icmp type/icmp code' keyword is not supported on Ethernet Interface. Ignore it.\n\r"
			"Please refer to the Software Configuration Guide for all the supported keywords.\n\r\n\r");
	}

	return OK;
	
err:
	return ERROR;
}

int hsl_ifp_vlan_acl_group_build(struct hal_msg_l4_acl_group_set *msg)
{
	int ifindex;
	entry_msg_t *acl_msg;
	int msg_size, i, slot, rc = 0;
	cap_info_t	*cap;
	cap_sub_info_t	*sub;
	struct access_entry_hdr	*entry;
	uint32 eid;
	ctc_acl_entry_t ctc_entry;
	ctc_acl_group_info_t ctc_group;
	ctc_port_bitmap_t port_map;
	char *gid;
	uint32 group_id = -1;
	uint32 block_id = -1;
	uint32 new_block_id = -1;	
	uint16 vid;
	
	ifindex = msg->ifindex;
	acl_msg = &msg->hal_acl_msg;
	msg_size = msg->msg_size;

	slot = 0;
	cap = cap_info_get(slot);
	sub = &cap->sub[CS_IFP_VLAN_IP_ACL];
	//cap_reset_last_build(cap);

	memset(&ctc_group, 0, sizeof(ctc_group));
	ctc_group.type = CTC_ACL_GROUP_TYPE_GLOBAL;
	ctc_group.dir = CTC_INGRESS;
	ctc_group.lchip = 0;

	if (vlanifindex_2_vid(ifindex, &vid) != OK) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "vlanifindex_2_vid fail. ifindex %d, vid %d.\r\n",
			ifindex, vid);
		return ERROR;
	}

	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "Install ip ACL %s to vlan %d(ifindex %d)\r\n",
			acl_msg->grp_entry[0].grp_id, vid, ifindex);

	if (cap_check_vlan_ip_acl_free_entry(sub, msg_size) != OK) {
		printk("Install vlan ip ACL %s to slot1 failed: no more entry\r\n",	acl_msg->grp_entry[0].grp_id);
		return ERROR;
	}
	
	for (i = 0; i < msg_size; i++) {
		entry = &acl_msg->grp_entry[i].entry;
		gid = acl_msg->grp_entry[i].grp_id;
		eid = cap_alloc_entry(sub, &new_block_id);
		printk("new_block_id = %d, block_id = %d\r\n", new_block_id, block_id);

		/*如果已经分配到下一个block的entry，则创建新的group*/
		if (block_id != new_block_id) {
			block_id = new_block_id;			
			ctc_group.priority = new_block_id;
			group_id = group_id_create();
			rc = ctc_acl_create_group(group_id, &ctc_group);
			if (CTC_E_NONE != rc) {
				printk("ctc_acl_create_group, rc = %d\r\n", rc);
				HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "ifp group create fail, ret = %d\n\r", rc);
				return ERROR;
			}		

		/*保存该group id，重新构造时需要对已有的group进行清理*/
			if (-1 == group_id_list_add(cap, group_id)) {
				printk("group_id_list_add fail\r\n");
				return ERROR;
			}
		}
		memset(&ctc_entry, 0, sizeof(ctc_entry));
		ctc_entry.entry_id = eid;		
		ctc_entry.key.type = CTC_ACL_KEY_IPV4;
		
		ctc_entry.key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_IPV4_PACKET;
		ctc_entry.key.u.ipv4_key.ipv4_packet = 1;

		ctc_entry.key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_SVLAN;
		ctc_entry.key.u.ipv4_key.svlan = vid;
		ctc_entry.key.u.ipv4_key.svlan_mask = 0x1fff;		
		
		switch (entry->type) {
			case ACCESS_ENTRY_TYPE_STD_IP:
				rc = ctc_build_acl_std(&ctc_entry, (struct std_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_IP:
				rc = ctc_build_acl_ext_ip(&ctc_entry, (struct ext_ip_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_UDP:
				rc = ctc_build_acl_udp(&ctc_entry, (struct ext_udp_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_TCP:
				rc = ctc_build_acl_tcp(&ctc_entry, (struct ext_tcp_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_ICMP:
				rc = ctc_build_acl_icmp(&ctc_entry, (struct ext_icmp_access_entry *)entry, sub);
				break;
			default:
				HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "ipf_build_acl_for_slot(ACL %s, slot%d), unknow acl entry type=%d, ignore\n\r", 
					gid, cap->slot, entry->type);
				rc = ERROR;
				break;
			}
		rc = ctc_acl_add_entry(group_id, &ctc_entry);		
	}

	return rc;
	
}

int hsl_ifp_acl_group_build(struct hal_msg_l4_acl_group_set *msg)
{
	l4_pbmp_t pbmp;
	entry_msg_t *acl_msg;
	int msg_size, i, slot, rc = 0;
	cap_info_t	*cap;
	cap_sub_info_t	*sub;
	struct access_entry_hdr	*entry;
	uint32 eid;
	ctc_acl_entry_t ctc_entry;
	ctc_acl_group_info_t ctc_group;
	ctc_port_bitmap_t port_map;
	char *gid;
	uint32 group_id = -1;
	uint32 block_id = -1;
	uint32 new_block_id = -1;


	C_PBMP_CLEAR(pbmp);
	C_PBMP_OR(pbmp, msg->pbmp);

	acl_msg = &msg->hal_acl_msg;
	msg_size = msg->msg_size;

	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "Install ip ACL %s to pbmp[0x%08x%08x%08x%08x%08x].\r\n",
			acl_msg->grp_entry[0].grp_id, pbmp.pbits[4], pbmp.pbits[3], pbmp.pbits[2], pbmp.pbits[1], pbmp.pbits[0]);

	slot = 0;
	cap = cap_info_get(slot);
	sub = &cap->sub[CS_IFP_IP_ACL];


	memset(&ctc_group, 0, sizeof(ctc_group));
	ifindexpbmp_2_gportmap(&pbmp, &(ctc_group.un.port_bitmap));
	ctc_group.type = CTC_ACL_GROUP_TYPE_PORT_BITMAP;
	ctc_group.dir = CTC_INGRESS;
	ctc_group.lchip = 0;

	/*检查所有的block，是否有有足够的空闲表项*/
	if (cap_check_free_ifp_entry(sub, msg_size) != OK) {
		printk("Install ip ACL %s to slot1 failed: no more entry\r\n", acl_msg->grp_entry[0].grp_id);
		return ERROR;
	}
	
	for (i = 0; i < msg_size; i++) {
		entry = &acl_msg->grp_entry[i].entry;
		gid = acl_msg->grp_entry[i].grp_id;
		eid = cap_alloc_entry(sub, &new_block_id);
		printk("new_block_id = %d, block_id = %d\r\n", new_block_id, block_id);

		/*如果已经分配到下一个block的entry，则创建新的group*/
		if (block_id != new_block_id) {
			block_id = new_block_id;
			ctc_group.priority = new_block_id;
			group_id = group_id_create();
			rc = ctc_acl_create_group(group_id, &ctc_group);
			if (CTC_E_NONE != rc) {
				printk("ctc_acl_create_group, rc = %d\r\n", rc);
				HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "ifp group create fail, ret = %d\n\r", rc);
				return ERROR;
			}		

		/*保存该group id，重新构造时需要对已有的group进行清理*/
			if (-1 == group_id_list_add(cap, group_id)) {
				printk("group_id_list_add fail\r\n");
				return ERROR;
			}
		}

		memset(&ctc_entry, 0, sizeof(ctc_entry));
		ctc_entry.entry_id = eid;
		ctc_entry.key.type = CTC_ACL_KEY_IPV4;
	
		
		switch (entry->type) {
			case ACCESS_ENTRY_TYPE_STD_IP:
				rc = ctc_build_acl_std(&ctc_entry, (struct std_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_IP:
				rc = ctc_build_acl_ext_ip(&ctc_entry, (struct ext_ip_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_UDP:
				rc = ctc_build_acl_udp(&ctc_entry, (struct ext_udp_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_TCP:
				rc = ctc_build_acl_tcp(&ctc_entry, (struct ext_tcp_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_ICMP:
				rc = ctc_build_acl_icmp(&ctc_entry, (struct ext_icmp_access_entry *)entry, sub);
				break;
			default:
				HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "ipf_build_acl_for_slot(ACL %s, slot%d), unknow acl entry type=%d, ignore\n\r", 
					gid, cap->slot, entry->type);
				rc = ERROR;
				break;
			}

		rc = ctc_acl_add_entry(group_id, &ctc_entry);
		printk("ctc_acl_add_entry, group_id = %#x, rc = %d\r\n", group_id, rc);
	}

	printk("hsl_ifp_acl_group_build--------------------1\r\n");

	return rc;
	
}

int hsl_efp_acl_group_build(struct hal_msg_l4_acl_group_set *msg)
{
	l4_pbmp_t pbmp;
	entry_msg_t *acl_msg;
	int msg_size, i, slot, rc = 0;
	cap_info_t	*cap;
	cap_sub_info_t	*sub;
	struct access_entry_hdr	*entry;
	uint32 eid;
	ctc_acl_entry_t ctc_entry;
	ctc_acl_group_info_t ctc_group;
	ctc_port_bitmap_t port_map;
	char *gid;
	uint32 group_id = -1;
	uint32 block_id = -1;
	uint32 new_block_id = -1;
	
	C_PBMP_CLEAR(pbmp);
	C_PBMP_OR(pbmp, msg->pbmp);
	acl_msg = &msg->hal_acl_msg;
	msg_size = msg->msg_size;
	
	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "Install ip ACL %s to pbmp[0x%08x%08x%08x%08x%08x].\r\n",
			acl_msg->grp_entry[0].grp_id, pbmp.pbits[4], pbmp.pbits[3], pbmp.pbits[2], pbmp.pbits[1], pbmp.pbits[0]);

	slot = 0;
	cap = cap_info_get(slot);
	sub = &cap->sub[CS_EFP_IP_ACL];
	//cap_reset_last_build(cap);

	memset(&ctc_group, 0, sizeof(ctc_group));
	ifindexpbmp_2_gportmap(&pbmp, &(ctc_group.un.port_bitmap));
	ctc_group.type = CTC_ACL_GROUP_TYPE_PORT_BITMAP;
	ctc_group.dir = CTC_EGRESS;
	ctc_group.lchip = 0;

	/*检查所有的block，是否有有足够的空闲表项*/
	if (cap_check_free_ifp_entry(sub, msg_size) != OK) {
		printk("Install ip ACL %s to slot1 failed: no more entry\r\n", acl_msg->grp_entry[0].grp_id);
		return ERROR;
	}

	for (i = 0; i < msg_size; i++) {
		entry = &acl_msg->grp_entry[i].entry;
		gid = acl_msg->grp_entry[i].grp_id;
		eid = cap_alloc_entry(sub, &new_block_id);
		printk("new_block_id = %d, block_id = %d\r\n", new_block_id, block_id);

		/*如果已经分配到下一个block的entry，则创建新的group*/
		if (block_id != new_block_id) {
			block_id = new_block_id;			
			ctc_group.priority = new_block_id;
			group_id = group_id_create();
			rc = ctc_acl_create_group(group_id, &ctc_group);
			if (CTC_E_NONE != rc) {
				printk("ctc_acl_create_group, rc = %d\r\n", rc);
				HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "ifp group create fail, ret = %d\n\r", rc);
				return ERROR;
			}		

		/*保存该group id，重新构造时需要对已有的group进行清理*/
			if (-1 == group_id_list_add(cap, group_id)) {
				printk("group_id_list_add fail\r\n");
				return ERROR;
			}
		}

		
		memset(&ctc_entry, 0, sizeof(ctc_entry));
		ctc_entry.entry_id = eid;
		ctc_entry.key.type = CTC_ACL_KEY_IPV4;

		ctc_entry.key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_IPV4_PACKET;
		ctc_entry.key.u.ipv4_key.ipv4_packet = 1;
		
		switch (entry->type) {
			case ACCESS_ENTRY_TYPE_STD_IP:
				rc = ctc_build_acl_std(&ctc_entry, (struct std_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_IP:
				rc = ctc_build_acl_ext_ip(&ctc_entry, (struct ext_ip_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_UDP:
				rc = ctc_build_acl_udp(&ctc_entry, (struct ext_udp_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_TCP:
				rc = ctc_build_acl_tcp(&ctc_entry, (struct ext_tcp_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_ICMP:
				rc = ctc_build_acl_icmp(&ctc_entry, (struct ext_icmp_access_entry *)entry, sub);
				break;
			default:
				HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "ipf_build_acl_for_slot(ACL %s, slot%d), unknow acl entry type=%d, ignore\n\r", 
					gid, cap->slot, entry->type);
				rc = ERROR;
				break;
			}

		rc = ctc_acl_add_entry(group_id, &ctc_entry);		
	}

	return rc;
	
}

int hsl_vfp_acl_group_build(struct hal_msg_l4_acl_group_set *msg)
{
	int vlanifindex;
	entry_msg_t *acl_msg;
	int msg_size, i, slot, rc = 0;
	cap_info_t	*cap;
	cap_sub_info_t	*sub;
	struct access_entry_hdr	*entry;
	uint32 eid;
	ctc_acl_entry_t ctc_entry;
	ctc_acl_group_info_t ctc_group;	
	uint16 vid;
	char *gid;
	uint32 group_id = -1;
	uint32 block_id = -1;
	uint32 new_block_id = -1;
	
	vlanifindex = msg->ifindex;
	acl_msg = &msg->hal_acl_msg;
	msg_size = msg->msg_size;

	slot = 0;
	cap = cap_info_get(slot);
	sub = &cap->sub[CS_VFP_IP_ACL];
	//cap_reset_last_build(cap);

	ctc_group.type = CTC_ACL_GROUP_TYPE_GLOBAL;
	ctc_group.dir = CTC_INGRESS;
	ctc_group.lchip = 0;

	if (vlanifindex_2_vid(vlanifindex, &vid) != OK) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "vlanifindex_2_vid fail. ifindex %d, vid %d.\r\n",
			vlanifindex, vid);
		return ERROR;
	}

	/*检查所有的block，是否有有足够的空闲表项*/
	if (cap_check_free_ifp_entry(sub, msg_size) != OK) {
		printk("Install ip ACL %s to slot1 failed: no more entry\r\n", acl_msg->grp_entry[0].grp_id);
		return ERROR;
	}
	
	
	for (i = 0; i < msg_size; i++) {
		entry = &acl_msg->grp_entry[i].entry;
		gid = acl_msg->grp_entry[i].grp_id;
		eid = cap_alloc_entry(sub, &new_block_id);
		printk("new_block_id = %d, block_id = %d\r\n", new_block_id, block_id);

		/*如果已经分配到下一个block的entry，则创建新的group*/
		if (block_id != new_block_id) {
			block_id = new_block_id;			
			ctc_group.priority = new_block_id;
			group_id = group_id_create();
			rc = ctc_acl_create_group(group_id, &ctc_group);
			if (CTC_E_NONE != rc) {
				printk("ctc_acl_create_group, rc = %d\r\n", rc);
				HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "ifp group create fail, ret = %d\n\r", rc);
				return ERROR;
			}		

		/*保存该group id，重新构造时需要对已有的group进行清理*/
			if (-1 == group_id_list_add(cap, group_id)) {
				printk("group_id_list_add fail\r\n");
				return ERROR;
			}
		}
		
		memset(&ctc_entry, 0, sizeof(ctc_entry));
		ctc_entry.entry_id = eid;
		ctc_entry.key.type = CTC_ACL_KEY_IPV4;

		ctc_entry.key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_IPV4_PACKET;
		ctc_entry.key.u.ipv4_key.ipv4_packet = 1;

		ctc_entry.key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_SVLAN;
		ctc_entry.key.u.ipv4_key.svlan = vid;
		ctc_entry.key.u.ipv4_key.svlan_mask = 0x1fff;			
		
		switch (entry->type) {
			case ACCESS_ENTRY_TYPE_STD_IP:
				rc = ctc_build_acl_std(&ctc_entry, (struct std_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_IP:
				rc = ctc_build_acl_ext_ip(&ctc_entry, (struct ext_ip_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_UDP:
				rc = ctc_build_acl_udp(&ctc_entry, (struct ext_udp_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_TCP:
				rc = ctc_build_acl_tcp(&ctc_entry, (struct ext_tcp_access_entry *)entry, sub);
				break;
			case ACCESS_ENTRY_TYPE_EXT_ICMP:
				rc = ctc_build_acl_icmp(&ctc_entry, (struct ext_icmp_access_entry *)entry, sub);
				break;
			default:
				HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "ipf_build_acl_for_slot(ACL %s, slot%d), unknow acl entry type=%d, ignore\n\r", 
					gid, cap->slot, entry->type);
				rc = ERROR;
				break;
			}
		
		rc = ctc_acl_add_entry(group_id, &ctc_entry);		
	}

	return rc;
	
}

int hsl_msg_recv_ifp_vlan_acl_group_build (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	struct hal_msg_l4_acl_group_set *msg;
	printk("hsl_msg_recv_ifp_vlan_acl_group_build\r\n");
	msg = (struct hal_msg_l4_acl_group_set *)msgbuf;

	ret = hsl_ifp_vlan_acl_group_build (msg);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

	return 0;
}

int hsl_msg_recv_ifp_acl_group_build (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	struct hal_msg_l4_acl_group_set *msg;
	printk("hsl_msg_recv_ifp_acl_group_build\r\n");
	msg = (struct hal_msg_l4_acl_group_set *)msgbuf;

	ret = hsl_ifp_acl_group_build (msg);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

	return 0;
}

int hsl_msg_recv_efp_acl_group_build (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	struct hal_msg_l4_acl_group_set *msg;
	printk("hsl_msg_recv_efp_acl_group_build");
	msg = (struct hal_msg_l4_acl_group_set *)msgbuf;

	ret = hsl_efp_acl_group_build (msg);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

	return 0;
}

int hsl_msg_recv_vfp_acl_group_build (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	struct hal_msg_l4_acl_group_set *msg;
	printk("hsl_msg_recv_vfp_acl_group_build");
	msg = (struct hal_msg_l4_acl_group_set *)msgbuf;

	ret = hsl_vfp_acl_group_build (msg);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

	return 0;
}


//////////////////////////////////////////////////////////
int hsl_msg_recv_l4_build_start (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	printk("hsl_msg_recv_l4_build_start\r\n");
	ret = bcm_rule_build_begin();

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

	return 0;
}

int hsl_msg_recv_l4_build_finish (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	printk("hsl_msg_recv_l4_build_finish\r\n");
	ret = bcm_rule_build_finish();

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

	return 0;
}


#if 0
/*
	port_num: L4端口号
	flag: TCP报文 or UDP报文
	prio: 映射的地址
*/
int __bcm_cpu_data_qualify_l4port(
		cap_info_t *cap, int port_num, int flag, int prio)
{
	int	rc;
	u8	ip_proto;
	bcm_field_entry_t eid;
	cap_sub_info_t	*sub;

	sub = &cap->sub[CS_DEFAULT_ACL];

	/*匹配TCP ip协议号*/
	if(flag == TCP_PACKET){
		ip_proto = PROTOCOL_TCP;
	} else {
		/*匹配UDP ip协议号*/
		ip_proto = PROTOCOL_UDP;
	}

	/*申请一个eid来匹配SRCPORT*/
	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配ip协议号*/
	if ((rc = bcm_field_qualify_IpProtocol(cap->unit, eid, ip_proto, 0xff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_IpProtocol failed: rc=%d\n\r", rc);
		goto err;
	}

	/*匹配以太协议号*/
	if ((rc = bcm_field_qualify_EtherType(cap->unit, eid, 0x0800, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType failed: rc=%d\n\r", rc);
		goto err;
	}

	/*匹配源端口号*/
	if ((rc = bcm_field_qualify_L4SrcPort(cap->unit, eid, port_num, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_L4SrcPort failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, prio, 0)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	/*再申请一个eid来匹配DSTPORT*/
	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配ip协议号*/
	if ((rc = bcm_field_qualify_IpProtocol(cap->unit, eid, ip_proto, 0xff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_IpProtocol failed: rc=%d\n\r", rc);
		goto err;
	}

	/*匹配以太协议号*/
	if ((rc = bcm_field_qualify_EtherType(cap->unit, eid, 0x0800, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType failed: rc=%d\n\r", rc);
		goto err;
	}

	/*匹配目的端口号*/
	if ((rc = bcm_field_qualify_L4DstPort(cap->unit, eid, port_num, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_L4SrcPort failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, prio, 0)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}
	
	return OK;
err:
	cap_clear_last_build(cap);
	return ERROR;
}

int __bcm_cpu_data_qualify_general_l4port(
		cap_info_t *cap, int port_num, int flag, int prio)
{
	int	rc;
	u8	ip_proto;
	bcm_field_entry_t eid;
	cap_sub_info_t	*sub;

	sub = &cap->sub[CS_DEFAULT_ACL];

	/*匹配TCP ip协议号*/
	if(flag == TCP_PACKET){
		ip_proto = PROTOCOL_TCP;
	} else {
		/*匹配UDP ip协议号*/
		ip_proto = PROTOCOL_UDP;
	}

	/*申请一个eid来匹配SRCPORT*/
	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配ip协议号*/
	if ((rc = bcm_field_qualify_IpProtocol(cap->unit, eid, ip_proto, 0xff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_IpProtocol failed: rc=%d\n\r", rc);
		goto err;
	}

	/*匹配源端口号*/
	if ((rc = bcm_field_qualify_L4SrcPort(cap->unit, eid, port_num, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_L4SrcPort failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, prio, 0)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	/*再申请一个eid来匹配DSTPORT*/
	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配ip协议号*/
	if ((rc = bcm_field_qualify_IpProtocol(cap->unit, eid, ip_proto, 0xff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_IpProtocol failed: rc=%d\n\r", rc);
		goto err;
	}

	/*匹配目的端口号*/
	if ((rc = bcm_field_qualify_L4DstPort(cap->unit, eid, port_num, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_L4SrcPort failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, prio, 0)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}
	
	return OK;
err:
	cap_clear_last_build(cap);
	return ERROR;
}
#endif
#if 0
/*
	为CPU数据设置不同优先级
	BPDU -------------------------------->cos7
	OSPF && BGP ------------------------->cos6
	VRRP -------------------------------->cos5
	telnet ssh snmp ping trace ---------->cos4
	DNS DHCP ARP ------------------------>cos3
	PIM MSDP  --------------------------->cos2
	multicast data  --------------------->cos1
	ip packet --------------------------->cos0

*/
int bcm_cpu_data_classify_for_slot(cap_info_t *cap)
{
	int	rc;
	bcm_field_entry_t	eid;
	cap_sub_info_t	*sub;

	/* record the begin entry of this rule */
	cap_reset_last_build(cap);
	sub = &cap->sub[CS_DEFAULT_ACL];

	/*for bpdu priority 7*/
	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配以太协议类型为0x4242*/
	if ((rc = bcm_field_qualify_EtherType(cap->unit, eid, 0x4242, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 7, 7)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	/*for loop dectction priority 6*/
	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配以太协议类型为0x4040*/
	if ((rc = bcm_field_qualify_EtherType(cap->unit, eid, 0x4040, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCopyToCpu, 0, 0)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 6, 6)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}


	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配以太协议类型为0x4242*/
	if ((rc = bcm_field_qualify_EtherType(cap->unit, eid, 0x888e, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCopyToCpu, 0, 0)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCopyToCpu, rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 7, 7)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配L4端口号为4444*/
	HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "Build cpu packet for radius auth packet cos %d.\r\n", 7);
	if ((rc = bcm_field_qualify_L4SrcPort(cap->unit, eid, 4444, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType for 1x packet failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 7, 7)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}


	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配L4端口号为1812*/
	HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "Build cpu packet for radius auth packet cos %d.\r\n", 5);
	if ((rc = bcm_field_qualify_L4SrcPort(cap->unit, eid, 1812, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType for 1x packet failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 5, 5)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配L4端口号为1813*/
	HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "Build cpu packet for radius auth packet cos %d.\r\n", 5);
	if ((rc = bcm_field_qualify_L4SrcPort(cap->unit, eid, 1813, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType for 1x packet failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 5, 5)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}


	/*for ospf hello priority 6, 包含ip6的报文*/
	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}
	
	if ((rc = bcm_field_qualify_IpProtocol(cap->unit, eid, 0x59, 0xff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_IpProtocol failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 6, 6)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}


	/* 匹配bgp TCP协议号为6 包括ipv6 */
	if (__bcm_cpu_data_qualify_general_l4port(cap, 179, TCP_PACKET, 6) != OK)
	{
		printk("__bcm_cpu_data_qualify_general_l4port failed: \n\r");
		return ERROR;
	}

	if (__bcm_cpu_data_qualify_general_l4port(cap, 179, UDP_PACKET, 6) != OK)
	{
		printk("__bcm_cpu_data_qualify_general_l4port failed: \n\r");
		return ERROR;
	}
	

	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配vrrp IP协议类型为112, cos 5*/
	if ((rc = bcm_field_qualify_IpProtocol(cap->unit, eid, 112, 0xff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_IpProtocol failed: rc=%d\n\r", rc);
		goto err;
	}

	if ((rc = bcm_field_qualify_EtherType(cap->unit, eid, 0x0800, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 5, 5)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	/* 匹配ldp, COS值是5 */
	if (__bcm_cpu_data_qualify_general_l4port(cap, 646, TCP_PACKET, 5) != OK)
	{
		printk("__bcm_cpu_data_qualify_general_l4port failed: \n\r");
		return ERROR;
	}

	if (__bcm_cpu_data_qualify_general_l4port(cap, 646, UDP_PACKET, 5) != OK)
	{
		printk("__bcm_cpu_data_qualify_general_l4port failed: \n\r");
		return ERROR;
	}

	/*给MPLS 报文分类，COS值是5*/
	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配以太协议类型为0x8847*/
	if ((rc = bcm_field_qualify_EtherType(cap->unit, eid, 0x8847, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType failed: rc=%d\n\r", rc);
		goto err;
	}
/*
	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCopyToCpu, 0, 0)) != BCM_E_NONE ) {
		logMsg("acl_build_action failed, bcmFieldActionCopyToCpu, rc=%d\n\r", rc);
		goto err;
	}
*/
	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 5, 5)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	/*给LACP报文分类，COS值是6*/
	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配以太协议类型为0x8809*/
	if ((rc = bcm_field_qualify_EtherType(cap->unit, eid, 0x8809, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 6, 6)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}
	

	/*匹配telnet TCP协议号为6*/
	if (__bcm_cpu_data_qualify_l4port(cap, 23, TCP_PACKET, 4) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	if (__bcm_cpu_data_qualify_l4port(cap, 23, UDP_PACKET, 4) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	/*匹配ssh TCP协议号为6*/
	if (__bcm_cpu_data_qualify_l4port(cap, 22, TCP_PACKET, 4) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	if (__bcm_cpu_data_qualify_l4port(cap, 22, UDP_PACKET, 4) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	/*匹配snmp TCP协议号为6*/
	if (__bcm_cpu_data_qualify_l4port(cap, 161, TCP_PACKET, 4) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	if (__bcm_cpu_data_qualify_l4port(cap, 161, UDP_PACKET, 4) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配icmp IP协议号为1*/
	if ((rc = bcm_field_qualify_IpProtocol(cap->unit, eid, 1, 0xff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_IpProtocol failed: rc=%d\n\r", rc);
		goto err;
	}

	if ((rc = bcm_field_qualify_EtherType(cap->unit, eid, 0x0800, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType failed: rc=%d\n\r", rc);
		goto err;
	}


	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 4, 4)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}


	/*for DNS && DHCP && ARP priority 3*/

	/*匹配DNS TCP协议号为6*/
	if (__bcm_cpu_data_qualify_l4port(cap, 53, TCP_PACKET, 3) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	if (__bcm_cpu_data_qualify_l4port(cap, 53, UDP_PACKET, 3) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	/*匹配DHCP TCP协议号为6*/
	if (__bcm_cpu_data_qualify_l4port(cap, 67, TCP_PACKET, 3) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	if (__bcm_cpu_data_qualify_l4port(cap, 67, UDP_PACKET, 3) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	/*匹配DHCP TCP协议号为6*/
	if (__bcm_cpu_data_qualify_l4port(cap, 68, TCP_PACKET, 3) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	if (__bcm_cpu_data_qualify_l4port(cap, 68, UDP_PACKET, 3) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配ARP报文以太协议类型为0x0806*/
	if ((rc = bcm_field_qualify_EtherType(cap->unit, eid, 0x0806, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 3, 3)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	/*for PIM && IGMP && MSDP priority 2*/
	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*IGMP 224.0.0.1*/
	if ((rc = bcm_field_qualify_DstIp(cap->unit, eid, 0xe0000001, 0xffffffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_DstIp failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 2, 2)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*IGMP 224.0.0.2*/
	if ((rc = bcm_field_qualify_DstIp(cap->unit, eid, 0xe0000002, 0xffffffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_DstIp failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 2, 2)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*IGMP 224.0.0.13*/
	if ((rc = bcm_field_qualify_DstIp(cap->unit, eid, 0xe000000d, 0xffffffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_DstIp failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 2, 2)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*IGMP report packet*/
	if ((rc = bcm_field_qualify_IpProtocol(cap->unit, eid, 2, 0xff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_IpProtocol failed: rc=%d\n\r", rc);
		goto err;
	}

	if ((rc = bcm_field_qualify_EtherType(cap->unit, eid, 0x0800, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 2, 2)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}

	/*匹配PIM报文协议号为103*/
	if ((rc = bcm_field_qualify_IpProtocol(cap->unit, eid, 103, 0xff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_IpProtocol failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 2, 2)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}
		
	/*匹配MSDP TCP协议号为6*/
	if (__bcm_cpu_data_qualify_l4port(cap, 639, TCP_PACKET, 2) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	if (__bcm_cpu_data_qualify_l4port(cap, 639, UDP_PACKET, 2) != OK)
	{
		printk("__bcm_cpu_data_qualify_l4port failed: \n\r");
		return ERROR;
	}

	/*for multicast priority 1*/
	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}
	if ((rc = bcm_field_qualify_DstIp(cap->unit, eid, 0xe0000000, 0xf0000000)) != BCM_E_NONE) {
		printk("bcm_field_qualify_DstIp failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 1, 1)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	/*for ip packet priority 0*/
	/*
	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}
	if ((rc = bcm_field_qualify_EtherType(cap->unit, eid, 0x0800, 0xffff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_EtherType failed: rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 0, 0)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}
	*/

	HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "Build CPU data packet to new priority success.\n\r");
	return OK;
err:
	cap_clear_last_build(cap);
	return ERROR;
}
#endif

#if 0

int bcm_copy_ttl1_build_for_slot(cap_info_t *cap)
{
	int	rc;
	bcm_field_entry_t	eid;
	cap_sub_info_t	*sub;
	int cpu_port;
	bcm_pbmp_t pbmp;

	/* record the begin entry of this rule */
	cap_reset_last_build(cap);

	sub = &cap->sub[CS_DEFAULT_ACL];
	if ( (eid = cap_alloc_entry(sub)) < 0 ) {
		printk("alloc entry failed\n\r");
		return ERROR;
	}
	if ((rc = bcm_field_qualify_Ttl(cap->unit, eid, 1, 0xff)) != BCM_E_NONE) {
		printk("bcm_field_qualify_Ttl failed: rc=%d\n\r", rc);
		goto err;
	}

	cpu_port = bcm_cpu_port_get(cap->unit);
	BCM_PBMP_CLEAR(pbmp);
	BCM_PBMP_PORT_ADD(pbmp, cpu_port);

	if ( (rc = bcm_field_action_ports_add(cap->unit, eid, bcmFieldActionRedirectPbmp, pbmp)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionRedirectPort, rc=%d\n\r", rc);
		goto err;
	}

	if ( (rc = bcm_field_action_add(cap->unit, eid, bcmFieldActionCosQCpuNew, 6, 6)) != BCM_E_NONE ) {
		printk("acl_build_action failed, bcmFieldActionCosQCpuNew, rc=%d\n\r", rc);
		goto err;
	}

	HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "Build redirect TTL1 packet to CPU(cpu port %d) success.\n\r", cpu_port);
	
	return OK;

err:
	cap_clear_last_build(cap);
	return ERROR;

}


/*
  *	CPU分类线速设置
  *    cap为L4 规则数据结构
  */
int bcm_cpu_data_rate_limit_for_slot(cap_info_t *cap)
{
    int rc;
	int cpu_port = -1;
    int pps = 0;

	cpu_port = bcm_cpu_port_get(cap->unit);
	if (cpu_port == -1)
		return ERROR;


	/*CPU口基于数据报数量来限速*/
	/*set for cos 7(BPDU) max bandwidth: 512pps*/
	rc = bcm_tr_cosq_port_pps_set(cap->unit,
		cpu_port, COS7, 512);
	if (rc != BCM_E_NONE) {
		printk ("bcm_tr_cosq_port_pps_set for cos7 failed, rc=%d\n\r", rc);
		return ERROR;
	}

/*
    rc = bcm_tr_cosq_port_pps_get(cap->unit,
        cpu_port, COS7, &pps);

    printk("COS7 rc=%d, pps=%d\r\n", rc, pps);
*/


	/*set for cos 6(ospf & BGP) max bandwidth: 1024pps*/
	rc = bcm_tr_cosq_port_pps_set(cap->unit,
		cpu_port, COS6, 1024);
	if (rc != BCM_E_NONE) {
		printk ("bcm_tr_cosq_port_pps_set for cos6 failed, rc=%d\n\r", rc);
		return ERROR;
	}

/*
    rc = bcm_tr_cosq_port_pps_get(cap->unit,
        cpu_port, COS6, &pps);

    printk("COS6 rc=%d, pps=%d\r\n", rc, pps);
*/



	/*set for cos 5(vrrp) max bandwidth: 512pps*/
	rc = bcm_tr_cosq_port_pps_set(cap->unit,
		cpu_port, COS5,512);
	if (rc != BCM_E_NONE) {
		printk ("bcm_tr_cosq_port_pps_set for cos5 failed, rc=%d\n\r", rc);
		return ERROR;
	}

/*
    rc = bcm_tr_cosq_port_pps_get(cap->unit,
        cpu_port, COS5, &pps);

    printk("COS5 rc=%d, pps=%d\r\n", rc, pps);
*/


	/*set for cos 4(telnet & ssh & snmp etc..) max bandwidth: 160pps*/
	rc = bcm_tr_cosq_port_pps_set(cap->unit,
		cpu_port, COS4, 160);
	if (rc != BCM_E_NONE) {
		printk ("bcm_tr_cosq_port_pps_set for cos4 failed, rc=%d\n\r", rc);
		return ERROR;
	}

/*
    rc = bcm_tr_cosq_port_pps_get(cap->unit,
        cpu_port, COS4, &pps);

    printk("COS4 rc=%d, pps=%d\r\n", rc, pps);
*/



	/*set for cos 3(DNS & DHCP & ARP ) max bandwidth: 512pps*/
	rc = bcm_tr_cosq_port_pps_set(cap->unit,
		cpu_port, COS3, 512);
	if (rc != BCM_E_NONE) {
		printk ("bcm_tr_cosq_port_pps_set for cos3 failed, rc=%d\n\r", rc);
		return ERROR;
	}

/*
    rc = bcm_tr_cosq_port_pps_get(cap->unit,
        cpu_port, COS3, &pps);

    printk("COS3 rc=%d, pps=%d\r\n", rc, pps);
*/


	/*set for cos 2(PIM & MSDP) max bandwidth: 512pps*/
	rc = bcm_tr_cosq_port_pps_set(cap->unit,
		cpu_port, COS2, 512);
	if (rc != BCM_E_NONE) {
		printk ("bcm_tr_cosq_port_pps_set for cos2 failed, rc=%d\n\r", rc);
		return ERROR;
	}

/*
    rc = bcm_tr_cosq_port_pps_get(cap->unit,
        cpu_port, COS2, &pps);

    printk("COS2 rc=%d, pps=%d\r\n", rc, pps);
*/

	/*set for cos 1(multicast data packet) max bandwidth: 160pps*/
	rc = bcm_tr_cosq_port_pps_set(cap->unit,
		cpu_port, COS1, 160);
	if (rc != BCM_E_NONE) {
		printk ("bcm_tr_cosq_port_pps_set for cos1 failed, rc=%d\n\r", rc);
		return ERROR;
	}

/*
    rc = bcm_tr_cosq_port_pps_get(cap->unit,
        cpu_port, COS1, &pps);

    printk("COS1 rc=%d, pps=%d\r\n", rc, pps);
*/


	/*set for cos 0(other ) max bandwidth: 50pps*/
	rc = bcm_tr_cosq_port_pps_set(cap->unit,
		cpu_port, COS0, 50);
	if (rc != BCM_E_NONE) {
		printk ("bcm_tr_cosq_port_pps_set for cos0 failed, rc=%d\n\r", rc);
		return ERROR;
	}
  
/*
    rc = bcm_tr_cosq_port_pps_get(cap->unit,
        cpu_port, COS0, &pps);

    printk("COS0 rc=%d, pps=%d\r\n", rc, pps);
*/


	return OK;
}
#endif

#if 0

/*
  *	CPU分类线速设置
  *    cap为L4 规则数据结构
  */
int bcm_cpu_data_rate_limit_for_slot(cap_info_t *cap)
{
	int rc;
	int cpu_port = -1;
	cpu_port = bcm_cpu_port_get(cap->unit);

	if (cpu_port == -1)
		return ERROR;
	
	/*set for cos 7(BPDU) max bandwidth: 512Kbps*/
	rc = bcm_cosq_port_bandwidth_set(cap->unit,
		cpu_port, COS7, 0, 512, 0);
	if (rc != BCM_E_NONE) {
		printk("bcm_cosq_port_bandwidth_set for cos7 failed, rc=%d\n\r", rc);
		return ERROR;
	}

	/*set for cos 6(ospf & BGP) max bandwidth: 512Kbps*/
	rc = bcm_cosq_port_bandwidth_set(cap->unit,
		cpu_port, COS6, 0, 512, 0);
	if (rc != BCM_E_NONE) {
		printk("bcm_cosq_port_bandwidth_set for cos6 failed, rc=%d\n\r", rc);
		return ERROR;
	}

	/*set for cos 5(vrrp) max bandwidth: 512Kbps*/
	rc = bcm_cosq_port_bandwidth_set(cap->unit,
		cpu_port, COS5, 0, 512, 0);
	if (rc != BCM_E_NONE) {
		printk("bcm_cosq_port_bandwidth_set for cos5 failed, rc=%d\n\r", rc);
		return ERROR;
	}

	/*set for cos 4(telnet & ssh & snmp etc..) max bandwidth: 160Kbps*/
	rc = bcm_cosq_port_bandwidth_set(cap->unit,
		cpu_port, COS4, 0, 160, 0);
	if (rc != BCM_E_NONE) {
		printk("bcm_cosq_port_bandwidth_set for cos4 failed, rc=%d\n\r", rc);
		return ERROR;
	}

	/*set for cos 3(DNS & DHCP & ARP ) max bandwidth: 100Kbps*/
	rc = bcm_cosq_port_bandwidth_set(cap->unit,
		cpu_port, COS3, 0, 100, 0);
	if (rc != BCM_E_NONE) {
		printk("bcm_cosq_port_bandwidth_set for cos3 failed, rc=%d\n\r", rc);
		return ERROR;
	}
	
	/*set for cos 2(PIM & MSDP) max bandwidth: 512Kbps*/
	rc = bcm_cosq_port_bandwidth_set(cap->unit,
		cpu_port, COS2, 0, 512, 0);
	if (rc != BCM_E_NONE) {
		printk("bcm_cosq_port_bandwidth_set for cos2 failed, rc=%d\n\r", rc);
		return ERROR;
	}
	
	/*set for cos 1(multicast data packet) max bandwidth: 160Kbps*/
	rc = bcm_cosq_port_bandwidth_set(cap->unit,
		cpu_port, COS1, 0, 160, 0);
	if (rc != BCM_E_NONE) {
		printk("bcm_cosq_port_bandwidth_set for cos1 failed, rc=%d\n\r", rc);
		return ERROR;
	}
	
	/*set for cos 0() max bandwidth: 100Kbps*/
	rc = bcm_cosq_port_bandwidth_set(cap->unit,
		cpu_port, COS0, 0, 100, 0);
	if (rc != BCM_E_NONE) {
		printk("bcm_cosq_port_bandwidth_set for cos0 failed, rc=%d\n\r", rc);
		return ERROR;
	}

	return OK;
}

#endif



/* edit by xiachao */
#if 0
int bcm_default_acl_build(void)
{
	/* if new default acl need to add, insert here */
	int slot, i;
	int ret = OK;
	cap_info_t	*cap;
	int index;
    static int init_done = 0;

    /*该函数只执行一遍*/
    if (init_done == 1) {
        return 0;
    }

    init_done = 0;

	slot = 0;
	cap = cap_info_get(slot);

	HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "default access-list build finish for slot%d <<<<\n\r", slot);
	/*送CPU数据分类*/
	if (bcm_cpu_data_classify_for_slot(cap) != OK) {
		printk("bcm_cpu_data_classify_for_slot on slot %d, failed.\r\n", slot);
		ret = ERROR;
	}

	/*
	if (bcm_copy_ttl1_build_for_slot(cap) != OK) {
		printk("Failed to build rule for copy TTL1 to CPU on slot%d\n\r", slot);
		ret = ERROR;
	}
	*/
	/*送CPU数据限速*/
	if (bcm_cpu_data_rate_limit_for_slot(cap) != OK) {
		printk("bcm_cpu_data_rate_limit_for_slot on slot %d, failed.\r\n", slot);
		ret = ERROR;
	}
	
	return ret;
}
#endif


