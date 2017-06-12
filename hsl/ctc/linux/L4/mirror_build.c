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


#include "hal/layer4/acl/access_list_rule.h"
#include "layer4/qos/qos.h"
#include "hal/layer4/qos/qos_rule.h"
#include "hal/layer4/hal_l4_api.h"
#include "bcm/field.h"
#include "bcm/types.h"
#include "bcm/error.h"
#include "layer4/acl/cli_acl.h"
#include "layer4/mirror/cli_mirror.h"
#include "layer4/pbmp.h"
#include "bcm_cap.h"
#include "acl_build.h"
#include "bcm_l4_debug.h"

static int _bcm_build_mirror_acl_ext_base(cap_info_t *cap, 
			bcm_field_entry_t eid, struct ext_ip_hdr_info *iph)
{
	int	rc;
	u32	ip, mask;

	/* src addr */
	mask = ~(iph->src.mask);
	ip = iph->src.addr & mask;
	if ((rc = bcmx_field_qualify_SrcIp(eid, ip, mask)) != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcm_field_qualify_SrcIp failed: rc=%d\n\r", rc);
		return ERROR;
	}
	/* dst addr */
	mask = ~(iph->dst.mask);
	ip = iph->dst.addr & mask;
	if ((rc = bcmx_field_qualify_DstIp(eid, ip, mask)) != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcm_field_qualify_DstIp failed: rc=%d\n\r", rc);
		return ERROR;
	}

	/* tos */
	if ((rc = bcmx_field_qualify_DSCP(eid, iph->tos.value, iph->tos.mask)) != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcm_field_qualify_DSCP failed: rc=%d\n\r", rc);
		return ERROR;
	}

	/* protocol */
	if (iph->proto != IPPROTO_ANY) {
		if ((rc = bcmx_field_qualify_IpProtocol(eid, iph->proto, 0xFF)) != BCM_E_NONE) 
		{
			HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcm_field_qualify_IpProtocol failed: rc=%d\n\r", rc);
			return ERROR;
		}
	}

	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "ext acl for %u: %u.%u.%u.%u/%u.%u.%u.%u, TOS %u/%u, PROTO %u/%u\n\r",
		eid, NIPQUAD(ip), NIPQUAD(mask), iph->tos.value, iph->tos.mask, 
		iph->proto == IPPROTO_ANY ? 0 : iph->proto, iph->proto == IPPROTO_ANY ? 0 : 0xFF);

	return OK;
}

/*
	构造TCP/UDP的源端口和目的端口
*/
static int _bcm_build_mirror_l4_port(cap_info_t *cap, bcm_field_entry_t eid,
		struct port_info *src_port, struct port_info *dst_port)
{
	int	rc;
	bool	warning = FALSE;

	if(src_port->op == OP_EQ) {
		rc = bcmx_field_qualify_L4SrcPort(eid, src_port->lower, 0xFFFF);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcm_field_qualify_L4SrcPort failed, rc=%d\n\r", rc);
			return ERROR;
		}
	} else if (src_port->op != OP_NONE) {
		warning = TRUE;
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "TCP/DUP port only support eq, not support others(op=%d)\n\r", src_port->op);
	}

	if(dst_port->op == OP_EQ) {
		rc = bcmx_field_qualify_L4DstPort(eid, dst_port->lower, 0xFFFF);
		if (rc != BCM_E_NONE) {
			HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcm_field_qualify_L4DstPort failed, rc=%d\n\r", rc);
			return ERROR;
		}
	} else if (dst_port->op != OP_NONE) {
		warning = TRUE;
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "TCP/DUP port only support eq, not support others(op=%d)\n\r", dst_port->op);
	}

	if (warning) {
		printk("\n\r%%ACL with 'rang/gt/lt' keyword is not supported on Ethernet Interface. Ignore it.\n\r"
			"Please refer to the Software Configuration Guide for all the supported keywords.\n\r\n\r"
			);
	}

	return OK;
}

static int _bcm_build_mirror_acl_std(	bcm_field_entry_t eid, 
			struct std_access_entry *entry, cap_sub_info_t *sub)
{
	int	rc;
	u32	ip, mask;
	cap_info_t *cap = sub->cap;

	/* FPF2 FIELD SET */
	mask = ~(entry->iph.src.mask);
	ip = entry->iph.src.addr & mask;
	HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "std acl for %u: %u.%u.%u.%u/%u.%u.%u.%u\n\r", eid, NIPQUAD(ip), NIPQUAD(mask));
	if ((rc = bcmx_field_qualify_SrcIp(eid, ip, mask)) != BCM_E_NONE) {
		HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcm_field_qualify_SrcIp failed: rc=%d\n\r", rc);
		goto err;
	}
	return OK;

err:
	return ERROR;
}

static int _bcm_build_mirror_acl_ext_ip(bcm_field_entry_t eid,
	struct ext_ip_access_entry *entry, cap_sub_info_t *sub)
{
	struct ext_ip_hdr_info *iph;
	cap_info_t *cap = sub->cap;

	iph = &entry->iph;
	
	/* FPF2 FIELD SET */
	if (_bcm_build_mirror_acl_ext_base(cap, eid, iph) != OK)
		goto err;
	return OK;
	
err:
	return ERROR;
}

static int _bcm_build_mirror_acl_udp(bcm_field_entry_t eid, 
	struct ext_udp_access_entry *entry, cap_sub_info_t *sub)
{
	struct ext_ip_hdr_info *iph;
	struct udp_hdr_info *udph;
	cap_info_t *cap = sub->cap;
	int tmp_proto;

	iph = &entry->iph;
	udph = &(entry->udph);
	tmp_proto = iph->proto; /*暂时记录proto的值*/
	
	/* FPF2 FIELD SET */
	iph->proto = PROTOCOL_UDP;
	if (_bcm_build_mirror_acl_ext_base(cap, eid, iph) != OK){
		iph->proto = tmp_proto;
		goto err;
	}
	iph->proto = tmp_proto;
	
	/* udp src port & dst port */
	if (_bcm_build_mirror_l4_port(cap, eid, &udph->src_port, &udph->dst_port) != OK)
		goto err;
	return OK;
	
err:
	return ERROR;
}

static int _bcm_build_mirror_acl_tcp(bcm_field_entry_t eid, 
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
	if (_bcm_build_mirror_acl_ext_base(cap, eid, iph) != OK){
		iph->proto = tmp_proto;
		goto err;
	}
	iph->proto = tmp_proto;

	if (tcph->estab){
		printk("\n\r%%TCP ACL with 'SYNC' keyword is not supported on Ethernet Interface. Ignore it.\n\r"
			"Please refer to the Software Configuration Guide for all the supported keywords.\n\r\n\r");

	}
	/* tcp src port & dst port */
	if (_bcm_build_mirror_l4_port(cap, eid, &tcph->src_port, &tcph->dst_port) != OK)
		goto err;
	return OK;
	
err:
	return ERROR;
}

static int _bcm_build_mirror_acl_icmp(bcm_field_entry_t eid, 
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
	if (_bcm_build_mirror_acl_ext_base(cap, eid, iph) != OK){
		iph->proto = tmp_proto;
		goto err;
	}
	iph->proto = tmp_proto;
	if (icmph->flags != FLAGS_NOT_SET) {
		printk("\n\r%%ACL with 'icmp type/icmp code' keyword is not supported on Ethernet Interface. Ignore it.\n\r"
			"Please refer to the Software Configuration Guide for all the supported keywords.\n\r\n\r"
			);
	}

	return OK;
	
err:
	return ERROR;
}

int mirror_rule_entry_build(struct hal_msg_l4_mirror_set *mirror_entry)
{
	int i, slot, rc = 0;
	cap_info_t	*cap;
	cap_sub_info_t	*sub;
	struct access_entry_hdr	*entry;
	bcm_field_entry_t eid;
	int         unit = -1;
	int 		modid = -1;
    bcm_port_t  port = -1;
	char *gid;

	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;

	slot = 0;
	cap = cap_info_get(slot);
	sub = &cap->sub[CS_MIRROR_RULE];
	cap_reset_last_build(cap);
	
	ifp = hsl_ifmgr_lookup_by_index(mirror_entry->hal_mirror_msg.mirror_entry.target_ifindex);
	bcmif = (struct hsl_bcm_if *)ifp->system_info;
	bcmx_lport_to_unit_port(bcmif->u.l2.lport, &unit, &port);
	modid = bcmx_lport_modid(bcmif->u.l2.lport);
	
	if (mirror_entry->hal_mirror_msg.mirror_entry.mirror_type == MIRROR_TYPE_VLAN) {
		if (mirror_entry->hal_mirror_msg.mirror_entry.mirror_ingress) {
			eid = cap_alloc_entry(sub);
			if ((rc = bcmx_field_qualify_OuterVlan(eid, mirror_entry->hal_mirror_msg.mirror_entry.vid, 0x1FFF)) != BCM_E_NONE) {
				return ERROR;
			}
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "bcmFieldActionMirrorIngress eid %d vlan %d, port %d(%s)\r\n",eid,  mirror_entry->hal_mirror_msg.mirror_entry.vid, 
				port, ifp->name);
			rc = bcmx_field_action_add(eid, bcmFieldActionMirrorIngress, modid, port);
			if (rc != BCM_E_NONE) {
				HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcm_filter_action_match bcmFieldActionMirrorIngress failed, rc=%d\n\r", rc);
			}
		}

		if (mirror_entry->hal_mirror_msg.mirror_entry.mirror_egress) {
			eid = cap_alloc_entry(sub);
			if ((rc = bcmx_field_qualify_OuterVlan(eid, mirror_entry->hal_mirror_msg.mirror_entry.vid, 0x1FFF)) != BCM_E_NONE) {
				return ERROR;
			}
			HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "bcmFieldActionMirrorEgress eid %d vlan %d, port %d(%s)\r\n",eid,  mirror_entry->hal_mirror_msg.mirror_entry.vid, 
				port, ifp->name);
			rc = bcmx_field_action_add(eid, bcmFieldActionMirrorEgress, modid, port);
			if (rc != BCM_E_NONE) {
				HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcm_filter_action_match bcmFieldActionMirrorEgress failed, rc=%d\n\r", rc);
			}
		}
	}

	if (mirror_entry->hal_mirror_msg.mirror_entry.mirror_type == MIRROR_TYPE_ACL) {
		if (mirror_entry->hal_mirror_msg.mirror_entry.mirror_ingress) {
			if (cap_check_free_ifp_entry(sub, mirror_entry->acl_num) != OK) {
				printk("Install ip ACL %s to slot1 failed: no more entry\r\n", mirror_entry->hal_mirror_msg.mirror_entry.access_group_id);
				return ERROR;
			}
			
			for (i = 0; i < mirror_entry->acl_num; i++) {
				entry = &mirror_entry->hal_mirror_msg.grp_entry[i].entry;
				gid = mirror_entry->hal_mirror_msg.grp_entry[i].grp_id;
				eid = cap_alloc_entry(sub);

				rc = bcmx_field_qualify_IpType(eid, bcmFieldIpTypeIpv4Any);
				if (rc != BCM_E_NONE) {
					HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcmx_field_qualify_IpType rc = %d\r\n", rc);
					break;
				}
				
				switch (entry->type) {
					case ACCESS_ENTRY_TYPE_STD_IP:
						rc = _bcm_build_mirror_acl_std(eid, (struct std_access_entry *)entry, sub);
						break;
					case ACCESS_ENTRY_TYPE_EXT_IP:
						rc = _bcm_build_mirror_acl_ext_ip(eid, (struct ext_ip_access_entry *)entry, sub);
						break;
					case ACCESS_ENTRY_TYPE_EXT_UDP:
						rc = _bcm_build_mirror_acl_udp(eid, (struct ext_udp_access_entry *)entry, sub);
						break;
					case ACCESS_ENTRY_TYPE_EXT_TCP:
						rc = _bcm_build_mirror_acl_tcp(eid, (struct ext_tcp_access_entry *)entry, sub);
						break;
					case ACCESS_ENTRY_TYPE_EXT_ICMP:
						rc = _bcm_build_mirror_acl_icmp(eid, (struct ext_icmp_access_entry *)entry, sub);
						break;
					default:
						HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "ipf_build_acl_for_slot(ACL %s, slot%d), unknow acl entry type=%d, ignore\n\r", 
							gid, cap->slot, entry->type);
						rc = ERROR;
						break;
					}
				
				HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "bcmFieldActionMirrorIngress eid %d to port %d(%s).\n\r", eid, port, ifp->name);
				rc = bcmx_field_action_add(eid, bcmFieldActionMirrorIngress, modid, port);
				if (rc != BCM_E_NONE) {
					HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcm_filter_action_match bcmFieldActionMirrorIngress failed, rc=%d\n\r", rc);
				}
			}
		}

		if (mirror_entry->hal_mirror_msg.mirror_entry.mirror_egress) {
			if (cap_check_free_ifp_entry(sub, mirror_entry->acl_num) != OK) {
				printk("Install ip ACL %s to slot1 failed: no more entry\r\n", mirror_entry->hal_mirror_msg.mirror_entry.access_group_id);
				return ERROR;
			}
			
			for (i = 0; i < mirror_entry->acl_num; i++) {
				entry = &mirror_entry->hal_mirror_msg.grp_entry[i].entry;
				gid = mirror_entry->hal_mirror_msg.grp_entry[i].grp_id;
				eid = cap_alloc_entry(sub);

				rc = bcmx_field_qualify_IpType(eid, bcmFieldIpTypeIpv4Any);
				if (rc != BCM_E_NONE) {
					HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcmx_field_qualify_IpType rc = %d\r\n", rc);
					break;
				}
				
				switch (entry->type) {
					case ACCESS_ENTRY_TYPE_STD_IP:
						rc = _bcm_build_mirror_acl_std(eid, (struct std_access_entry *)entry, sub);
						break;
					case ACCESS_ENTRY_TYPE_EXT_IP:
						rc = _bcm_build_mirror_acl_ext_ip(eid, (struct ext_ip_access_entry *)entry, sub);
						break;
					case ACCESS_ENTRY_TYPE_EXT_UDP:
						rc = _bcm_build_mirror_acl_udp(eid, (struct ext_udp_access_entry *)entry, sub);
						break;
					case ACCESS_ENTRY_TYPE_EXT_TCP:
						rc = _bcm_build_mirror_acl_tcp(eid, (struct ext_tcp_access_entry *)entry, sub);
						break;
					case ACCESS_ENTRY_TYPE_EXT_ICMP:
						rc = _bcm_build_mirror_acl_icmp(eid, (struct ext_icmp_access_entry *)entry, sub);
						break;
					default:
						HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "ipf_build_acl_for_slot(ACL %s, slot%d), unknow acl entry type=%d, ignore\n\r", 
							gid, cap->slot, entry->type);
						rc = ERROR;
						break;
					}
				HSL_DEBUG_IPCLS(DEBUG_LEVEL_ACL, "bcmFieldActionMirrorEgress eid %d to port %d(%s).\n\r", eid, port, ifp->name);
				rc = bcmx_field_action_add(eid, bcmFieldActionMirrorEgress, modid, port);
				if (rc != BCM_E_NONE) {
					HSL_DEBUG_IPCLS(DEBUG_ERROR_ACL, "bcm_filter_action_match bcmFieldActionMirrorEgress failed, rc=%d\n\r", rc);
				}
			}
		}
	}
	return rc;
}

int hsl_msg_recv_mirror_entry_set(struct socket *sock, struct hal_nlmsghdr *hdr, char *msgbuf)
{
	int ret;
	struct hal_msg_l4_mirror_set *msg;

	msg = (struct hal_msg_l4_mirror_set *)msgbuf;
	
	ret = mirror_rule_entry_build(msg);

	HSL_MSG_PROCESS_RETURN (sock, hdr, ret);

	return 0;
}
