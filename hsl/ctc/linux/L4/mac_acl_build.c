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
#include "layer4/acl/cli_acl.h"
#include "layer4/pbmp.h"
#include "bcm_cap.h"
#include "mac_acl_build.h"
#include "bcm_l4_debug.h"

extern int ifindexpbmp_2_gportmap(l4_pbmp_t *ifindexpbmp,  ctc_port_bitmap_t *port_map);
extern int acl_build_action(cap_info_t *cap, ctc_acl_entry_t *ctc_entry, bool permit);

int bcm_build_mac_acl(ctc_acl_entry_t *ctc_entry, macl_entry_t *ep, cap_sub_info_t *sub)
{	
	int	rc;
	cap_info_t *cap = sub->cap;
	
	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "mac entry(%s): %02X:%02X:%02X:%02X:%02X:%02X/%02X:%02X:%02X:%02X:%02X:%02X, "
		"%02X:%02X:%02X:%02X:%02X:%02X/%02X:%02X:%02X:%02X:%02X:%02X, %04X/%04X\n\r",
			ep->permit ? "permit" : "deny", 
			MAC_MB(ep->src_mac), MAC_MB(ep->src_mask),
			MAC_MB(ep->dst_mac), MAC_MB(ep->dst_mask),
			ep->proto, ep->proto_mask);


	ctc_entry->key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_MAC_SA;
	memcpy(ctc_entry->key.u.ipv4_key.mac_sa, ep->src_mac, 6);
	memcpy(ctc_entry->key.u.ipv4_key.mac_sa_mask, ep->src_mask, 6);

	ctc_entry->key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_MAC_DA;
	memcpy(ctc_entry->key.u.ipv4_key.mac_da, ep->dst_mac, 6);
	memcpy(ctc_entry->key.u.ipv4_key.mac_da_mask, ep->dst_mask, 6);

	ctc_entry->key.u.ipv4_key.flag |= CTC_ACL_IPV4_KEY_FLAG_MAC_DA;
	ctc_entry->key.u.ipv4_key.eth_type = ep->proto;
	ctc_entry->key.u.ipv4_key.eth_type_mask = ep->proto_mask;

	/* action */
	if (acl_build_action(cap, ctc_entry, ep->permit) != OK)
		goto err;

	return OK;
err:
	return ERROR;
}

int hsl_ifp_mac_acl_group_build(struct hal_msg_l4_mac_acl_group_set *msg)
{
	l4_pbmp_t pbmp;
	mac_entry_msg_t *acl_msg;
	int msg_size, i, slot, rc = 0;
	cap_info_t	*cap;
	cap_sub_info_t	*sub;
	macl_entry_t	*entry;
	char *gid;
	uint32 eid;	
	ctc_acl_entry_t ctc_entry;
	ctc_acl_group_info_t ctc_group;
	ctc_port_bitmap_t port_map;
	uint32 group_id = -1;
	uint32 block_id = -1;
	uint32 new_block_id = -1;

	
	C_PBMP_CLEAR(pbmp);
	C_PBMP_OR(pbmp, msg->pbmp);
	acl_msg = &msg->hal_acl_msg;
	msg_size = msg->msg_size;

	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "Install mac ACL %s to pbmp[0x%08x%08x%08x%08x%08x].\r\n",
			acl_msg->mac_grp_entry[0].grp_id, pbmp.pbits[4], pbmp.pbits[3], pbmp.pbits[2], pbmp.pbits[1], pbmp.pbits[0]);

	slot = 0;
	cap = cap_info_get(slot);
	sub = &cap->sub[CS_IFP_IP_ACL];

	memset(&ctc_group, 0, sizeof(ctc_group));
	ifindexpbmp_2_gportmap(&pbmp, &(ctc_group.un.port_bitmap));
	ctc_group.type = CTC_ACL_GROUP_TYPE_PORT_BITMAP;
	ctc_group.dir = CTC_INGRESS;
	ctc_group.lchip = 0;


	if (cap_check_free_ifp_entry(sub, msg_size) != OK) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "Install mac ACL %s to slot1 failed: no more entry\r\n",
			acl_msg->mac_grp_entry[0].grp_id);
		return ERROR;
	}
	for (i = 0; i < msg_size; i++) {
		entry = &acl_msg->mac_grp_entry[i].entry;
		gid = acl_msg->mac_grp_entry[i].grp_id;
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
		
		rc = bcm_build_mac_acl(&ctc_entry, entry, sub);
		if (rc != OK) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcm_build_mac_acl rc = %d\r\n", rc);
			break;
		}
		rc = ctc_acl_add_entry(group_id, &ctc_entry);	
	}

	return rc;
	
}

int hsl_msg_recv_ifp_mac_acl_group_build (struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	struct hal_msg_l4_mac_acl_group_set *msg;

	msg = (struct hal_msg_l4_mac_acl_group_set *)msgbuf;

	ret = hsl_ifp_mac_acl_group_build (msg);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

	return 0;
}

