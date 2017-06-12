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


#include "hal/layer4/acl/access_list_rule.h"
#include "layer4/qos/qos.h"
#include "hal/layer4/qos/qos_rule.h"
#include "hal/layer4/hal_l4_api.h"
#include "bcm/field.h"
#include "bcm/types.h"
#include "bcm/error.h"
#include "layer4/acl/cli_acl.h"
#include "layer4/pbmp.h"
#include "bcm_cap.h"
#include "mac_acl_build.h"
#include "bcm_l4_debug.h"

int bcm_build_mac_acl(bcm_field_entry_t eid, macl_entry_t *ep, cap_sub_info_t *sub)
{	
	int	rc;
	cap_info_t *cap = sub->cap;
	
	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "mac entry(%s): %02X:%02X:%02X:%02X:%02X:%02X/%02X:%02X:%02X:%02X:%02X:%02X, "
		"%02X:%02X:%02X:%02X:%02X:%02X/%02X:%02X:%02X:%02X:%02X:%02X, %04X/%04X\n\r",
			ep->permit ? "permit" : "deny", 
			MAC_MB(ep->src_mac), MAC_MB(ep->src_mask),
			MAC_MB(ep->dst_mac), MAC_MB(ep->dst_mask),
			ep->proto, ep->proto_mask);

	/* src mac */
	if ((rc = bcmx_field_qualify_SrcMac(eid, ep->src_mac, ep->src_mask)) != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcmx_field_qualify_SrcMac failed: rc=%d\n\r", rc);
		goto err;
	}
	/* dst mac */
	if ((rc = bcmx_field_qualify_DstMac(eid, ep->dst_mac, ep->dst_mask)) != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcmx_field_qualify_DstMac failed: rc=%d\n\r", rc);
		goto err;
	}
	/* ether protocol */
	if ((rc = bcmx_field_qualify_EtherType(eid, ep->proto, ep->proto_mask)) != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcmx_field_qualify_DstMac failed: rc=%d\n\r", rc);
		goto err;
	}

	/* action */
	if (acl_build_action(cap, eid, ep->permit) != OK)
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
	bcm_field_entry_t eid;
	bcmx_lplist_t lplist;
	char *gid;
	
	C_PBMP_CLEAR(pbmp);
	C_PBMP_OR(pbmp, msg->pbmp);
	acl_msg = &msg->hal_acl_msg;
	msg_size = msg->msg_size;

	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "Install mac ACL %s to pbmp[0x%08x%08x%08x%08x%08x].\r\n",
			acl_msg->mac_grp_entry[0].grp_id, pbmp.pbits[4], pbmp.pbits[3], pbmp.pbits[2], pbmp.pbits[1], pbmp.pbits[0]);

	slot = 0;
	cap = cap_info_get(slot);
	sub = &cap->sub[CS_IFP_MAC_ACL];
	cap_reset_last_build(cap);

	bcmx_lplist_init(&lplist, 0, 0);
	ifindexpbmp_2_lplist(&pbmp, &lplist);

	if (cap_check_free_ifp_entry(sub, msg_size) != OK) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "Install mac ACL %s to slot1 failed: no more entry\r\n",
			acl_msg->mac_grp_entry[0].grp_id);
		return ERROR;
	}
	
	for (i = 0; i < msg_size; i++) {
		entry = &acl_msg->mac_grp_entry[i].entry;
		gid = acl_msg->mac_grp_entry[i].grp_id;
		eid = cap_alloc_entry(sub);
		/*
		rc = bcmx_field_qualify_IpType(eid, bcmFieldIpTypeIpv4Any);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcmx_field_qualify_IpType rc = %d\r\n", rc);
			break;
		}
		*/
		
		rc = bcmx_field_qualify_InPorts(eid, lplist);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcmx_field_qualify_InPorts rc = %d\r\n", rc);
			break;
		}

		rc = bcm_build_mac_acl(eid, entry, sub);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcm_build_mac_acl rc = %d\r\n", rc);
			break;
		}
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

