#include "config.h"
#include "hsl_os.h"

#include "hsl_types.h"
#include "openflow.h"
#include "ofp_basic.h"

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
#include "hsl_bcm_if.h"
#include "hsl_bcm_pkt.h"
#include "hsl_comm.h"
#include "hsl_msg.h"
#include "openflow.h"
#include "ofp_basic.h"
#include "hsl_of.h"

#include "bcm/field.h"
#include "bcm/types.h"
#include "bcm/error.h"
#include "layer4/pbmp.h"
#include "bcm_cap.h"
#include "bcm_l4_debug.h"

#define HSL_OFP_VFP_TABLE_SIZE (1024*2)

typedef struct hsl_bcm_ofp_flow_s{
    int vfp_flow_id;
    int vfp_eid;
    int ifp_eid;
    int ifp_stat_id;
    int egress_obj;
    int intf_obj;
    hsl_ofp_flow_entry_t    *flow;
    struct hsl_bcm_ofp_flow_s *next;
    struct hsl_bcm_ofp_flow_s *prev;
    
}hsl_bcm_ofp_flow_t;

static l4_pbmp_t portlist;
static u8 vfp_id_bitmap[(HSL_OFP_VFP_TABLE_SIZE+7)/8];
static int vfp_group = -1;
static int ifp_group = -1;
static hsl_bcm_ofp_flow_t *bcm_flow_head = NULL;

static int hsl_ofp_get_phy_port(int port_no, int *unit, int *phy_port)
{
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;

    if (unit == NULL || phy_port == NULL) {
        return -1;
    }
    
	ifp = hsl_ifmgr_lookup_by_index(port_no);
	bcmif = (struct hsl_bcm_if *)ifp->system_info;

    printk("portno:%d to lport:%x\n",port_no, bcmif->u.l2.lport);

    return bcmx_lport_to_unit_port(bcmif->u.l2.lport, unit, phy_port);
}

bcmx_lport_t hsl_ofp_get_lport(int port_no)
{
	struct hsl_if *ifp;
	struct hsl_bcm_if *bcmif;

	ifp = hsl_ifmgr_lookup_by_index(port_no);
    if (ifp == NULL) {
        return -1;
    }
    
	bcmif = (struct hsl_bcm_if *)ifp->system_info;
    if (bcmif == NULL) {
        return -1;
    }

    return bcmif->u.l2.lport;
}

int hsl_ofp_is_need_vfp(hsl_ofp_flow_entry_t *flow)
{
    if (flow == NULL) {
        return 0;
    }

    if (flow->match.filed_bitmap 
        & ((1 << OFPXMT_OFB_ETH_DST) 
            | (1<<OFPXMT_OFB_ETH_SRC) )){
        return 1;
    }


    return 0;
}

int hsl_ofp_build_portlist(int eid, hsl_ofp_flow_entry_t *flow,l4_pbmp_t *portlist)
{
    int ret;
    bcmx_lplist_t lplist;
    l4_pbmp_t match_portlist;
    
    if (flow == NULL || portlist == NULL) {
        return -1;
    }

	C_PBMP_CLEAR(match_portlist);
    
	bcmx_lplist_init(&lplist, 0, 0);

    if (flow->match.filed_bitmap & ((1 << OFPXMT_OFB_IN_PORT) | (1 << OFPXMT_OFB_IN_PHY_PORT))){
        if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_IN_PORT)){
            if (flow->match.data.in_port < PBMP_PORT_MAX) {
                C_PBMP_PORT_ADD(match_portlist, flow->match.data.in_port);
            } else if (flow->match.data.in_port == OFPP_ANY) {
               	C_PBMP_OR(match_portlist, *portlist);
            }
        }
        
        if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_IN_PHY_PORT)){
            if (flow->match.data.in_phy_port < PBMP_PORT_MAX) {
                C_PBMP_PORT_ADD(match_portlist, flow->match.data.in_phy_port);
            } else if (flow->match.data.in_phy_port == OFPP_ANY) {
               	C_PBMP_OR(match_portlist, *portlist);
            }
        }
    } else {
    	C_PBMP_OR(match_portlist, *portlist);

    }

	ifindexpbmp_2_lplist(&match_portlist, &lplist);
    ret = bcmx_field_qualify_InPorts(eid, lplist);
    HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d, ret:%d\n",__FUNCTION__,__LINE__,ret);

    return ret;    
    
}

bool hsl_ofp_vfp_is_flow_id_used(int flow_id)
{
    int base;
    int offset;

    base = flow_id / 8;
    offset = flow_id % 8;
    return vfp_id_bitmap[base] & (1 << offset) ? true : false;
}

void hsl_ofp_vfp_set_flow_id_used(int flow_id)
{
    int base;
    int offset;

    base = flow_id / 8;
    offset = flow_id % 8;
    vfp_id_bitmap[base] |= (1 << offset);
}

void hsl_ofp_vfp_clr_flow_id_used(int flow_id)
{
    int base;
    int offset;

    if (flow_id > HSL_OFP_VFP_TABLE_SIZE || flow_id < 0) {
        printk("flow id is wrong. flow_id:%d",flow_id);
        dump_stack();
        return;
    }

    base = flow_id / 8;
    offset = flow_id % 8;
    vfp_id_bitmap[base] &= ~(1 << offset);
}

int hsl_ofp_vfp_alloc_flow_id(void)
{
    static int vfp_flow_id = 0;
    int count = HSL_OFP_VFP_TABLE_SIZE;

    while (count--) {
        vfp_flow_id++;
        vfp_flow_id &= (HSL_OFP_VFP_TABLE_SIZE -1);
        if (!hsl_ofp_vfp_is_flow_id_used(vfp_flow_id)) {
            break;
        }
    }

    if (count == 0) {
        return -1;
    }

    hsl_ofp_vfp_set_flow_id_used(vfp_flow_id);    
    
    return vfp_flow_id;
}

int hsl_ofp_vfp_get_group(void)
{
    int     ret;
   	bcm_field_qset_t	qset;
   
    if (vfp_group != -1) {
        return vfp_group;
    }

    memset(&qset, 0, sizeof(qset));
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyStageLookup);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifySrcMac);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyDstMac);
	ret = bcmx_field_group_create(qset, BCM_FIELD_GROUP_PRIO_ANY, &vfp_group);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d, ret:%d\n",__FUNCTION__,__LINE__,ret);
        return -1;
    }

    return vfp_group;

}

int hsl_ofp_vfp_build_field(int eid, hsl_ofp_flow_entry_t *flow)
{
    int ret;
    
    if (flow == NULL) {
        return -1;
    }

    ret = 0;
    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_ETH_DST)){
        ret |= bcmx_field_qualify_DstMac(eid, flow->match.data.eth_dst,flow->match.mask.eth_dst);
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d, ret:%d\n",__FUNCTION__,__LINE__,ret);
    }

    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_ETH_SRC)){
        ret |= bcmx_field_qualify_SrcMac(eid, flow->match.data.eth_src,flow->match.mask.eth_src);
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d, ret:%d\n",__FUNCTION__,__LINE__,ret);
    }

    return ret;
}

int hsl_ofp_vfp_build_instruction(int eid,hsl_ofp_flow_entry_t *flow)
{
    int ret;
    hsl_bcm_ofp_flow_t *bcm_flow;
    
    if (flow == NULL) {
        return -1;
    }

    bcm_flow = (hsl_bcm_ofp_flow_t*)flow->priv;
    if (bcm_flow == NULL) {
        return -1;
    }

    ret = bcmx_field_action_add(eid, bcmFieldActionClassDestSet, bcm_flow->vfp_flow_id & 0x3f, 0);
    HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d, ret:%d\n",__FUNCTION__,__LINE__,ret);

    ret |= bcmx_field_action_add(eid, bcmFieldActionClassSourceSet, (bcm_flow->vfp_flow_id >> 6) & 0x3f, 0);
    HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d, ret:%d\n",__FUNCTION__,__LINE__,ret);

    return ret;
    
}

int hsl_ofp_vfp_create_entry(hsl_ofp_flow_entry_t *flow)
{
    int flow_id;
    int eid;
    hsl_bcm_ofp_flow_t *bcm_flow;
    int ret;
    
    if (flow == NULL) {
        return -1;
    }

    flow_id = hsl_ofp_vfp_alloc_flow_id();
    if (flow_id < 0) {
        return -1;
    }

    if ((ret = bcmx_field_entry_create(hsl_ofp_vfp_get_group(), &eid)) < 0) {
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d, ret:%d\n",__FUNCTION__,__LINE__,ret);
        return -1;
    }

    bcm_flow = (hsl_bcm_ofp_flow_t *) flow->priv;
    if (bcm_flow == NULL) {
        return -1;
    }

    bcm_flow->vfp_eid = eid;
    bcm_flow->vfp_flow_id = flow_id;   

    return eid;
}
int hsl_ofp_vfp_entry_build(hsl_ofp_flow_entry_t *flow,l4_pbmp_t *portlist)
{
    int eid;
    int ret;
    
    if (flow == NULL || portlist == NULL) {
        return -1;
    }
    HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d\n",__FUNCTION__,__LINE__);

    eid = hsl_ofp_vfp_create_entry(flow);
    if (eid < 0) {
        return OFP_ERROR_NO_RESOURCE;
    }
   
    ret = hsl_ofp_vfp_build_field(eid, flow);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
        return -1;
    }
    
    ret = hsl_ofp_vfp_build_instruction(eid, flow);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
        return -1;
    }
    
    bcmx_field_entry_prio_set(eid, flow->pri);

    ret = bcmx_field_entry_install(eid);
    HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);

    return ret;
}


int hsl_ofp_ifp_get_group(void)
{
    int     ret;
   	bcm_field_qset_t	qset;
    
    if (ifp_group != -1) {
        return ifp_group;
    }

    memset(&qset, 0, sizeof(qset));
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyStageIngress);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyDstClassField);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifySrcClassField);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyInPorts);
  	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyEtherType);
    BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyOuterVlanId);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyOuterVlanPri);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyOuterVlanCfi);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyIpType);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyTos);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifySrcIp);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyDstIp);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyL4SrcPort);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyL4DstPort);
	BCM_FIELD_QSET_ADD(qset, bcmFieldQualifyIpProtocol);
    
	ret = bcmx_field_group_create(qset, BCM_FIELD_GROUP_PRIO_ANY, &ifp_group);
    if (ret < 0) {
        return -1;
    }

    return ifp_group;

}

int hsl_ofp_ifp_build_classid_field(int eid, hsl_ofp_flow_entry_t *flow)
{
    hsl_bcm_ofp_flow_t *bcm_flow;
    int ret;
    
    if (flow == NULL || (bcm_flow = (hsl_bcm_ofp_flow_t*)flow->priv) == NULL) {
        return -1;
    }

    if (bcm_flow->vfp_flow_id == -1) {
        return 0;
    }

    ret = bcmx_field_qualify_DstClassField(eid, bcm_flow->vfp_flow_id & 0x3f, 0x3f);
    ret |= bcmx_field_qualify_SrcClassField(eid, (bcm_flow->vfp_flow_id >> 6) & 0x3f, 0x3f);

    return ret;    
}

int hsl_ofp_ifp_build_stat(int eid)
{
    int stat_id;
    bcm_field_stat_t stat_arr[2] = {bcmFieldStatBytes, bcmFieldStatPackets};
    
    bcmx_field_stat_create(hsl_ofp_ifp_get_group(), sizeof(stat_arr)/sizeof(bcm_field_stat_t),
                       stat_arr, &stat_id);

    bcmx_field_entry_stat_attach(eid, stat_id);

    return stat_id;                      
}

int hsl_ofp_ifp_attach_meter(int eid, int meter_id)
{
    int ret;
    hsl_ofp_meter_entry_t *meter;

    meter = hsl_ofp_meter_hash_get(meter_id);

	ret = bcmx_field_action_add(eid, bcmFieldActionRpDrop, 0, 0);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
        return ret;
    }

  	ret = bcmx_field_entry_policer_attach(eid, 0, meter->plicer_id);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
        return ret;
    }    

    return 0;                      
}


int hsl_ofp_ifp_deattach_meter(int eid, int meter_id)
{
    int ret;

  	ret = bcmx_field_entry_policer_detach(eid, 0);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
        return ret;
    }    

    return 0;                      
}



int hsl_ofp_ifp_build_field(int eid, hsl_ofp_flow_entry_t *flow)
{
    int ret;
    
    if (flow == NULL) {
        return -1;
    }

    ret = 0;

    ret = hsl_ofp_ifp_build_classid_field(eid, flow);

    
    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_ETH_TYPE)){
        ret = bcmx_field_qualify_EtherType(eid, flow->match.data.eth_type,flow->match.mask.eth_type);
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d, ret:%d\n",__FUNCTION__,__LINE__,ret);
    }
    
    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_VLAN_VID)){
        ret = bcmx_field_qualify_OuterVlanId(eid, flow->match.data.vlan_vid & 0xfff,flow->match.mask.vlan_vid & 0xfff);
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d, ret:%d\n",__FUNCTION__,__LINE__,ret);

        ret = bcmx_field_qualify_OuterVlanCfi(eid, flow->match.data.vlan_vid >> 12,flow->match.mask.vlan_vid >> 12);
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d, ret:%d\n",__FUNCTION__,__LINE__,ret);
    }

    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_VLAN_PCP)){
        ret = bcmx_field_qualify_OuterVlanPri(eid, flow->match.data.vlan_pcp,flow->match.mask.vlan_pcp);
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d, ret:%d\n",__FUNCTION__,__LINE__,ret);
    }    
    
    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_IPV4_DST)){
        ret = bcmx_field_qualify_DstIp(eid, flow->match.data.ip_dst,flow->match.mask.ip_dst);
    }

    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_IPV4_SRC)){
        ret = bcmx_field_qualify_SrcIp(eid, flow->match.data.ip_src,flow->match.mask.ip_src);
    }

    if (flow->match.filed_bitmap & ((1 << OFPXMT_OFB_IP_DSCP) | (1 << OFPXMT_OFB_IP_ECN))){
        int tos;
        int tos_mask;

        tos = 0;
        tos_mask = 0;
        if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_IP_DSCP)) {
            tos      |= (flow->match.data.ip_dscp & 0x3f) << 2;
            tos_mask |= (flow->match.mask.ip_dscp & 0x3f) << 2;
        }

        if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_IP_ECN)) {
            tos      |= (flow->match.data.ip_ecn & 0x3);
            tos_mask |= (flow->match.mask.ip_ecn & 0x3);
        }
        
        ret = bcmx_field_qualify_Tos(eid, tos,tos_mask);
    }
    
    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_IP_PROTO)){
        ret = bcmx_field_qualify_IpProtocol(eid, flow->match.data.ip_proto,flow->match.mask.ip_proto);
    }

    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_TCP_SRC)){
        ret = bcmx_field_qualify_L4SrcPort(eid, flow->match.data.tcp_src,flow->match.mask.tcp_src);
    }

    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_TCP_DST)){
        ret = bcmx_field_qualify_L4DstPort(eid, flow->match.data.tcp_dst,flow->match.mask.tcp_dst);
    }

    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_UDP_SRC)){
        ret = bcmx_field_qualify_L4SrcPort(eid, flow->match.data.udp_src,flow->match.mask.udp_src);
    }

    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_UDP_DST)){
        ret = bcmx_field_qualify_L4DstPort(eid, flow->match.data.udp_dst,flow->match.mask.udp_dst);
    }

    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_SCTP_SRC)){
        ret = bcmx_field_qualify_L4SrcPort(eid, flow->match.data.sctp_src,flow->match.mask.sctp_src);
    }

    if (flow->match.filed_bitmap & (1 << OFPXMT_OFB_SCTP_DST)){
        ret = bcmx_field_qualify_L4DstPort(eid, flow->match.data.sctp_dst,flow->match.mask.sctp_dst);
    }

    return ret;
}

int hsl_ofp_ifp_build_set_field(int eid, hsl_ofp_set_filed_t *set_field, int out_port, hsl_bcm_ofp_flow_t *bcm_flow)
{
    int ret;
   	bcmx_l3_egress_t egress_object;
    bcmx_l3_intf_t  intf;
    bcm_if_t        intf_id = 0;
	bcm_if_t object_id;
	int egress_flags;

    
    if (set_field == NULL || bcm_flow == NULL) {
        return -1;
    }
    
    ret = 0;
    if ((set_field->filed_bitmap & (1 << OFPXMT_OFB_ETH_DST))
        && (set_field->filed_bitmap & (1 << OFPXMT_OFB_ETH_SRC)) 
        &&(set_field->filed_bitmap & (1 << OFPXMT_OFB_VLAN_VID))) {
        
        bcmx_l3_intf_t_init (&intf);
        /* Set VID. */
        intf.l3a_vid = set_field->val.vlan_vid;
        /* Set MAC. */
        memcpy (intf.l3a_mac_addr, set_field->val.eth_src, HSL_ETHER_ALEN);

        if ((ret = bcmx_l3_intf_create(&intf)) < 0) {
            HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
            return ret;
        }

        intf_id = intf.l3a_intf_id;   
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,intf_id:%d\n",__FUNCTION__,__LINE__,intf_id);
        HSL_LOG (HSL_LOG_OPENFLOW,HSL_LEVEL_DEBUG,"lport:%x\n",egress_object.lport );

        bcmx_l3_egress_t_init(&egress_object);
        memcpy (egress_object.mac_addr, set_field->val.eth_dst, HSL_ETHER_ALEN);

        egress_object.vlan = set_field->val.vlan_vid;
        egress_object.lport = hsl_ofp_get_lport(out_port);
        egress_object.intf = intf_id;

	    egress_flags = egress_object.flags;
	    ret = bcmx_l3_egress_create(egress_flags, &egress_object, &object_id);
        if (ret < 0) {
            HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
            return ret;
        }

        ret = bcmx_field_action_add(eid, bcmFieldActionL3Switch, object_id, 0);
        if (ret < 0) {
            HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
            return ret;
        } 
        bcm_flow->intf_obj = intf_id;
        bcm_flow->egress_obj = object_id;
      
    } else {
        if (set_field->filed_bitmap & (1 << OFPXMT_OFB_ETH_DST)) {
            ret = bcmx_field_action_mac_add(eid, bcmFieldActionDstMacNew, set_field->val.eth_dst);
            if (ret < 0) {
                HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
                return ret;
            }
        }

        if (set_field->filed_bitmap & (1 << OFPXMT_OFB_VLAN_VID)) {
            ret = bcmx_field_action_add(eid, bcmFieldActionOuterVlanNew, set_field->val.vlan_vid, 0);
            if (ret < 0) {
                HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
                return ret;
            }
        }
    }

    if (set_field->filed_bitmap & (1 << OFPXMT_OFB_VLAN_PCP)) {
        ret = bcmx_field_action_add(eid, bcmFieldActionPrioPktAndIntNew, set_field->val.vlan_pcp, 0);
        if (ret < 0) {
            HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
            return ret;
        }
    }

    if (set_field->filed_bitmap & (1 << OFPXMT_OFB_IP_DSCP)) {
        ret = bcmx_field_action_add(eid, bcmFieldActionDscpNew, set_field->val.ip_dscp, 0);
        if (ret < 0) {
            HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
            return ret;
        }
    }

    return ret;    
}

int hsl_ofp_ifp_build_drop_action(int eid)
{
    return bcmx_field_action_add(eid, bcmFieldActionDrop, 0, 0);
}
int hsl_ofp_ifp_build_action(int eid, hsl_ofp_action_t *action, hsl_ofp_flow_entry_t *flow)
{
    int ret;
    hsl_bcm_ofp_flow_t *bcm_flow;
    
    if (action == NULL || flow == NULL) {
        return -1;
    }

    bcm_flow = flow->priv;
    if (bcm_flow == NULL) {
        return -1;
    }

    ret = 0;
    if (action->action_bitmap & (1 << OFPAT_OUTPUT)) {

        /*当要修改源mac地址时，不能使用redirect action*/
        if (!((action->action_bitmap & (1 << OFPAT_SET_FIELD)) 
            && (action->set_field.filed_bitmap & (1 << OFPXMT_OFB_ETH_SRC)))) {

            switch (action->output_port) {
            case OFPP_CONTROLLER:
                /*table miss*/
                if (flow->pri == 0) {
                    ret = bcmx_field_action_add(eid, bcmFieldActionCopyToCpu, 1, OFP_REASON_TABLE_MISS);
                } else {
                    ret = bcmx_field_action_add(eid, bcmFieldActionCopyToCpu, 1, OFP_REASON_CONTROLLER);
                }
                ret = bcmx_field_action_add(eid, bcmFieldActionDrop, 0, 0);
                break;
            case OFPP_LOCAL:
                ret = bcmx_field_action_add(eid, bcmFieldActionCopyToCpu, 1, OFP_REASON_LOCAL);
                ret = bcmx_field_action_add(eid, bcmFieldActionDrop, 0, 0);
                break;
            case OFPP_NORMAL:
                ret = bcmx_field_action_add(eid, bcmFieldActionDropCancel, 0, 0);
                break;
            case OFPP_ALL:
            case OFPP_FLOOD:
                //ret = bcmx_field_action_add(eid, bcmFieldActionDropCancel, 0, 0);
                break;
            default:
            {
                bcmx_lport_t lport;

                lport = hsl_ofp_get_lport(action->output_port);
                if (lport == -1) {
                    ret = bcmx_field_action_add(eid, bcmFieldActionDrop, 0, 0);
                } else {
                    ret = bcmx_field_action_add(eid, bcmFieldActionRedirectPort, lport, 0);
                }
            }
                break;
            }
        }
    }

    if (action->action_bitmap & (1 << OFPAT_SET_QUEUE)) {
        ret |= bcmx_field_action_add(eid, bcmFieldActionCosQNew, action->queue_id, 0);
    }

    if (action->action_bitmap & (1 << OFPAT_SET_FIELD)) {
        ret |= hsl_ofp_ifp_build_set_field(eid, &action->set_field, action->output_port, bcm_flow);
    }

    /*drop action*/
    if (!(action->action_bitmap & (1 << OFPAT_OUTPUT)) && !(action->action_bitmap & (1 << OFPAT_GROUP))) {
        return hsl_ofp_ifp_build_drop_action(eid);
    }

    return ret;
}

int hsl_ofp_ifp_build_instruction(int eid,hsl_ofp_flow_entry_t *flow)
{
    int ret;
    hsl_bcm_ofp_flow_t *bcm_flow;
    int stat_id;
    
    if (flow == NULL) {
        return -1;
    }

    bcm_flow = (hsl_bcm_ofp_flow_t*)flow->priv;
    if (bcm_flow == NULL) {
        return -1;
    }

    ret = 0;
    if (flow->instruct.instruction_bitmap & ( 1 << OFPIT_APPLY_ACTIONS)) {
        ret = hsl_ofp_ifp_build_action(eid, flow->instruct.apply_action, flow);
        if (ret < 0) {
            HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
            return ret;
        }
    }

    if (flow->instruct.instruction_bitmap & ( 1 << OFPIT_WRITE_ACTIONS)) {
        ret = hsl_ofp_ifp_build_action(eid, flow->instruct.write_action, flow);
        if (ret < 0) {
            HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
            return ret;
        }
    } 

    if (flow->instruct.instruction_bitmap & ( 1 << OFPIT_CLEAR_ACTIONS)) {
        hsl_ofp_ifp_build_drop_action(eid);
    }

    if (flow->instruct.instruction_bitmap & ( 1 << OFPIT_METER)) {
        ret = hsl_ofp_ifp_attach_meter(eid, flow->instruct.meter_id); 
        if (ret < 0) {
            HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
            return ret;
        }
    }

    ret = stat_id = hsl_ofp_ifp_build_stat(eid);
    bcm_flow->ifp_stat_id = stat_id;
    
    return ret;
    
}

int hsl_ofp_ifp_create_entry(hsl_ofp_flow_entry_t *flow)
{
    int eid;
    hsl_bcm_ofp_flow_t *bcm_flow;
    
    if (flow == NULL) {
        return -1;
    }

    if (bcmx_field_entry_create(hsl_ofp_ifp_get_group(), &eid) < 0) {
        return -1;
    }

    bcm_flow = (hsl_bcm_ofp_flow_t *) flow->priv;
    if (bcm_flow == NULL) {
        return -1;
    }

    bcm_flow->ifp_eid = eid;

    return eid;
}

int hsl_ofp_ifp_entry_build(hsl_ofp_flow_entry_t *flow, l4_pbmp_t *portlist)
{
    int eid;
    int ret;

    if (flow == NULL || portlist == NULL) {
        return -1;
    }

    eid = hsl_ofp_ifp_create_entry(flow);
    if (eid < 0) {
        return -1;
    }

    ret = hsl_ofp_build_portlist(eid, flow, portlist);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
        return -1;
    }

    ret = hsl_ofp_ifp_build_field(eid, flow);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
        return -1;
    }
    
    ret = hsl_ofp_ifp_build_instruction(eid, flow);
    if (ret < 0) {
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);
        return -1;
    }

    bcmx_field_entry_prio_set(eid, flow->pri);

    ret = bcmx_field_entry_install(eid);
    HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG,"%s,%d,ret:%d\n",__FUNCTION__,__LINE__,ret);

    return ret;   
    
}


int hsl_ofp_create_bcm_flow(hsl_ofp_flow_entry_t *flow)
{
    hsl_bcm_ofp_flow_t *bcm_flow;
    
    if (flow == NULL) {
        return -1;
    }

    bcm_flow = oss_malloc(sizeof(hsl_bcm_ofp_flow_t), OSS_MEM_HEAP);
    if (bcm_flow == NULL) {
        return -1;
    }
    memset(bcm_flow, 0xff, sizeof(hsl_bcm_ofp_flow_t));
    flow->priv = (void*)bcm_flow;
    bcm_flow->next = NULL;
    bcm_flow->prev = NULL;

    /*insert list*/
    if (bcm_flow_head == NULL) {
        bcm_flow_head = bcm_flow;
    } else {
        bcm_flow_head->prev = bcm_flow;
        bcm_flow->next = bcm_flow_head;
        bcm_flow_head = bcm_flow;
    }

    bcm_flow->flow = flow;

    return 0;
}

int hsl_ofp_acl_create(hsl_ofp_flow_entry_t *flow)
{
    int ret;
   
    if (flow == NULL) {
        return -1;
    }

    HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG, "%s,%d. table id:%d,entry:%d\n", __FUNCTION__,__LINE__,flow->table_id, flow->entry_id);

    if (hsl_ofp_create_bcm_flow(flow) < 0) {
        return OFP_ERROR_OTHER;
    }
    
    if (hsl_ofp_is_need_vfp(flow)) {
        ret = hsl_ofp_vfp_entry_build(flow, &portlist);
        if (ret < 0) {
            return ret;
        }
    }

    return hsl_ofp_ifp_entry_build(flow, &portlist);
}

int hsl_ofp_acl_delete(hsl_ofp_flow_entry_t *flow)
{
    hsl_bcm_ofp_flow_t *bcm_flow;

    if (flow == NULL || (bcm_flow = flow->priv) == NULL) {
        return -1;
    }

    if (bcm_flow->vfp_eid != -1) {
        bcmx_field_entry_destroy(bcm_flow->vfp_eid);
        hsl_ofp_vfp_clr_flow_id_used(bcm_flow->vfp_flow_id);

        bcm_flow->vfp_eid = -1;
    }

    if (flow->instruct.instruction_bitmap & (1 << OFPIT_METER)) {
        hsl_ofp_ifp_deattach_meter(bcm_flow->ifp_eid, flow->instruct.meter_id);
    }

    if (bcm_flow->egress_obj != -1) {
        bcmx_l3_egress_destroy(bcm_flow->egress_obj);           
    }

    if (bcm_flow->intf_obj != -1) {
        bcmx_l3_intf_t intf;

        memset(&intf, 0, sizeof(intf));
        intf.l3a_intf_id = bcm_flow->intf_obj; 
        bcmx_l3_intf_delete(&intf);
    }

    bcmx_field_entry_stat_detach(bcm_flow->ifp_eid, bcm_flow->ifp_stat_id);
    bcmx_field_stat_destroy(bcm_flow->ifp_stat_id);

    bcmx_field_entry_destroy(bcm_flow->ifp_eid);

    /*remove from list*/
    if (bcm_flow->prev) {
        bcm_flow->prev->next = bcm_flow->next;
    } else {
        bcm_flow_head = bcm_flow->next;
    }

    if (bcm_flow->next) {
        bcm_flow->next->prev = bcm_flow->prev;
    }

    bcm_flow->prev = NULL;
    bcm_flow->next = NULL;

    bcm_flow->flow = NULL;
    flow->priv = NULL;

    oss_free(bcm_flow, OSS_MEM_HEAP);

    return 0;
}

int hsl_ofp_acl_show(hsl_ofp_flow_entry_t *flow)
{
    hsl_bcm_ofp_flow_t *bcm_flow;
    
    unsigned long long flow_byte = 0; 
    unsigned long long flow_packet = 0; 

    if (flow == NULL || (bcm_flow = (hsl_bcm_ofp_flow_t*)flow->priv) == NULL) {
        return -1;
    }

    printk("Phy info=====:\n");
    printk("Vfp flow id:0x%x vfp group id:0x%x vfp eid:0x%x, ifp group id:0x%x ifp eid:0x%x, ifp stat id:0x%x\n", 
        bcm_flow->vfp_flow_id, 
        vfp_group,
        bcm_flow->vfp_eid, 
        ifp_group,
        bcm_flow->ifp_eid,
        bcm_flow->ifp_stat_id);

    bcmx_field_stat_get(bcm_flow->ifp_stat_id, bcmFieldStatBytes,   &flow_byte);
    bcmx_field_stat_get(bcm_flow->ifp_stat_id, bcmFieldStatPackets, &flow_packet);

    printk("flow stat: byte:%llu, packet:%llu. bcm:0x%llx,next:0x%llx, prev:0x%llx\n",flow_byte, flow_packet, bcm_flow,bcm_flow->next, bcm_flow->prev);
    
    return 0;
}

void hsl_ofp_acl_set_vlan_filter(int port_no, HSL_BOOL state)
{
    bcmx_lport_t lport;
    u32 flags;
    
    lport = hsl_ofp_get_lport(port_no);
    if (lport == -1) {
        return;
    }

    flags = 0;    
    bcmx_port_vlan_member_get(lport, &flags);

    if (state) {
        flags &= ~(BCM_PORT_VLAN_MEMBER_EGRESS);
    } else {
        flags |= BCM_PORT_VLAN_MEMBER_EGRESS;
    }

    bcmx_port_vlan_member_set(lport, flags);  
}
int hsl_ofp_acl_port_set(int table_id, int port_no, HSL_BOOL state)
{
    hsl_bcm_ofp_flow_t *bcm_flow;

    hsl_ofp_acl_set_vlan_filter(port_no, state);

    if (state) {
        C_PBMP_PORT_ADD(portlist, port_no - HSL_L2_IFINDEX_START);
    } else {
        C_PBMP_PORT_REMOVE(portlist, port_no - HSL_L2_IFINDEX_START);
    }

    bcm_flow = bcm_flow_head;
    while(bcm_flow) {

        if (bcm_flow->ifp_eid != -1) {
            hsl_ofp_build_portlist(bcm_flow->ifp_eid, bcm_flow->flow, &portlist);
            bcmx_field_entry_reinstall(bcm_flow->ifp_eid);
        }
        bcm_flow = bcm_flow->next;
    }
    
    return 0;        
}

int hsl_ofp_acl_flow_get_stat(hsl_ofp_flow_entry_t *flow, ofp_flow_statis_reply_t *stat)
{
    hsl_bcm_ofp_flow_t *bcm_flow;
    unsigned long long flow_byte = 0; 
    unsigned long long flow_packet = 0; 

    if (flow == NULL || stat == NULL) {
        return -1;
    }

    bcm_flow = (hsl_bcm_ofp_flow_t *)flow->priv;
    if (bcm_flow == NULL) {
        return -1;
    }

    bcmx_field_stat_get(bcm_flow->ifp_stat_id, bcmFieldStatBytes,   &flow_byte);
    bcmx_field_stat_get(bcm_flow->ifp_stat_id, bcmFieldStatPackets, &flow_packet);   

    stat->byte_count    = flow_byte;
    stat->packet_count  = flow_packet;

    HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG, "%s,%d. byte :%llu, packet:%llu\n", __FUNCTION__,__LINE__,flow_byte, flow_packet);

    return 0;        
}


int hsl_ofp_acl_check(hsl_ofp_flow_entry_t *flow)
{
    HSL_BOOL set_src_mac;
    HSL_BOOL set_vlan;
    HSL_BOOL set_dst_mac;
    HSL_BOOL outport;
    
    if (flow == NULL) {
        return -1;
    }

    set_src_mac = HSL_FALSE;
    set_vlan    = HSL_FALSE;
    set_dst_mac = HSL_FALSE;
    outport     = HSL_FALSE;
    
    if (flow->instruct.instruction_bitmap & (1 << OFPIT_WRITE_ACTIONS) ) {
        if (flow->instruct.write_action) {
            if (flow->instruct.write_action->action_bitmap & (1 << OFPAT_SET_FIELD)) {
                if (flow->instruct.write_action->set_field.filed_bitmap & (1 << OFPXMT_OFB_ETH_DST)) {
                   set_dst_mac = HSL_TRUE;
                }

                if (flow->instruct.write_action->set_field.filed_bitmap & (1 << OFPXMT_OFB_ETH_SRC)) {
                   set_src_mac = HSL_TRUE;
                }

                if (flow->instruct.write_action->set_field.filed_bitmap & (1 << OFPXMT_OFB_VLAN_VID)) {
                   set_vlan= HSL_TRUE;
                }
            }

            if (flow->instruct.write_action->action_bitmap & (1 << OFPAT_OUTPUT)) {
                outport = HSL_TRUE;                
            }
        }
    }


    if (flow->instruct.instruction_bitmap & (1 << OFPIT_APPLY_ACTIONS) ) {
        if (flow->instruct.apply_action) {
            if (flow->instruct.apply_action->action_bitmap & (1 << OFPAT_SET_FIELD)) {
                if (flow->instruct.apply_action->set_field.filed_bitmap & (1 << OFPXMT_OFB_ETH_DST)) {
                   set_dst_mac = HSL_TRUE;
                }

                if (flow->instruct.apply_action->set_field.filed_bitmap & (1 << OFPXMT_OFB_ETH_SRC)) {
                   set_src_mac = HSL_TRUE;
                }

                if (flow->instruct.apply_action->set_field.filed_bitmap & (1 << OFPXMT_OFB_VLAN_VID)) {
                   set_vlan= HSL_TRUE;
                }
            }

            if (flow->instruct.apply_action->action_bitmap & (1 << OFPAT_OUTPUT)) {
                outport = HSL_TRUE;                
            }
        }
    }

    /*如果修改源mac，必须同时修改目的mac与vlan id；如果不修改源mac，不能同时修改目的mac与vlan id*/
    if (set_src_mac) {
        if (!set_dst_mac || !set_vlan) {
            return OFP_ERROR_CAN_NOT_SUPPORT;
        }
    }

    if (flow->instruct.write_action && flow->instruct.write_action->action_bitmap & (1 << OFPAT_SET_QUEUE)) {
        if (flow->instruct.write_action->action_bitmap & (1 << OFPAT_SET_FIELD)) {
            /*不能同时设置queue，与pcp*/
            if (flow->instruct.write_action->set_field.filed_bitmap & (1 << OFPXMT_OFB_VLAN_PCP)) {
                //flow->instruct.write_action->set_field.filed_bitmap &= ~(1 << OFPXMT_OFB_VLAN_PCP);
                return OFP_ERROR_CAN_NOT_SUPPORT;
            }
        }
     }
  

    return OFP_ERROR_NONE;
    
}

static hsl_ofp_flow_table_ops_t acl_ops = {
    .tbl_add = hsl_ofp_acl_create,
    .tbl_delete = hsl_ofp_acl_delete,
    .tbl_show = hsl_ofp_acl_show,
    .tbl_port_set = hsl_ofp_acl_port_set,
    .tbl_check = hsl_ofp_acl_check,
    .tbl_get_flow_stat = hsl_ofp_acl_flow_get_stat,
};
int hsl_ofp_acl_table_init(void)
{
    hsl_ofp_flow_reg(0, &acl_ops);
    return 0;
}


int hsl_ofp_acl_meter_create(hsl_ofp_meter_entry_t *meter)
{
    int ret;
    bcmx_policer_config_t pol_cfg;
    bcm_policer_t         policer_id;
   
    if (meter == NULL) {
        return -1;
    }

    HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG, "%s,%d. meter id:%d\n", __FUNCTION__,__LINE__,meter->entry.meter_id);

    bcmx_policer_config_t_init(&pol_cfg);

    if (meter->entry.meter_flag & (1 << OFPMF_PKTPS)) {
        pol_cfg.flags |= BCM_POLICER_MODE_PACKETS;
    } else {
        pol_cfg.flags |= BCM_POLICER_MODE_BYTES;
    }

    pol_cfg.flags |= BCM_POLICER_COLOR_BLIND;
    pol_cfg.ckbits_sec = meter->entry.drop.rate; 
    if (meter->entry.meter_flag & (1 << OFPMF_BURST)) {
        pol_cfg.ckbits_burst = meter->entry.drop.burst_size;
    } else {
        pol_cfg.ckbits_burst = pol_cfg.ckbits_sec * 2;
    }
	pol_cfg.mode = bcmPolicerModeCommitted; /* flow mode */

    ret = bcmx_policer_create(&pol_cfg, &policer_id);
    if (ret < 0) {
        return ret;
    }

    meter->plicer_id = policer_id;

    return 0;
}

int hsl_ofp_acl_meter_delete(hsl_ofp_meter_entry_t *meter)
{
    if (meter == NULL) {
        return -1;
    }

    return bcmx_policer_destroy(meter->plicer_id);
}

int hsl_ofp_acl_meter_modify(hsl_ofp_meter_entry_t *meter)
{
    int ret;
    bcmx_policer_config_t pol_cfg;
   
    if (meter == NULL) {
        return -1;
    }

    HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG, "%s,%d. meter id:%d\n", __FUNCTION__,__LINE__,meter->entry.meter_id);

    bcmx_policer_config_t_init(&pol_cfg);

    pol_cfg.flags |= BCM_POLICER_COLOR_BLIND | BCM_POLICER_MODE_BYTES;
    pol_cfg.ckbits_sec = meter->entry.drop.rate; 
    pol_cfg.ckbits_burst = meter->entry.drop.burst_size;
	pol_cfg.mode = bcmPolicerModeCommitted; /* flow mode */

    ret = bcmx_policer_set(meter->entry.meter_id, &pol_cfg);
    if (ret < 0){
        HSL_LOG (HSL_LOG_OPENFLOW, HSL_LEVEL_DEBUG, "%s,%d. meter id:%d, ret:%d\n", __FUNCTION__,__LINE__,meter->entry.meter_id, ret);
    }
    
    return ret;
}

int hsl_ofp_acl_meter_show(hsl_ofp_meter_entry_t *meter)
{
    if (meter == NULL) {
        return -1;
    }

    printk("Phy info=====:\n");
    printk("meter plicer id:%d\n", meter->plicer_id);
    
    return 0;
}

static hsl_ofp_meter_table_ops_t meter_ops = {
    .tbl_add = hsl_ofp_acl_meter_create,
    .tbl_delete = hsl_ofp_acl_meter_delete,
    .tbl_modify = hsl_ofp_acl_meter_modify,
    .tbl_show = hsl_ofp_acl_meter_show,
};

int hsl_ofp_meter_table_init(void)
{
    hsl_ofp_meter_reg(&meter_ops);
    return 0;
}

