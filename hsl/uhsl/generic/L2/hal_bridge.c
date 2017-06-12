/* Copyright (C) 2004-2017 SZFORWARD, Inc. All Rights Reserved. */
#include "hal_types.h"
#include "hal_if.h"
#include "hal_vlan.h"
#include "hal_bridge.h"
#include "hal.h"
#include "hal_slot.h"

int hal_bridge_init (void)
{
	int ret;
	if (HAL_OPS_CB_CHECK(hal_bridge_ops, bridge_init)) {
		ret = HAL_OPS_CB_CALL(hal_bridge_ops, bridge_init) (HAL_FWD_SLOT_MASK_ALL);
		return (ret == 0) ? 0 : -1;
	}

	return 0;
}
int hal_bridge_deinit (void)
{
	int ret;
	if (HAL_OPS_CB_CHECK(hal_bridge_ops, bridge_init)) {
		ret = HAL_OPS_CB_CALL(hal_bridge_ops, bridge_init) (HAL_FWD_SLOT_MASK_ALL);
		return (ret == 0) ? 0 : -1;
	}
    return 0;
}

int hal_bridge_add (char *name, unsigned int is_vlan_aware,
                 enum hal_bridge_type type, unsigned char edge,
                 unsigned char beb, unsigned char *mac)
{
	int ret;
	if (HAL_OPS_CB_CHECK(hal_bridge_ops, bridge_add)) {
		ret = HAL_OPS_CB_CALL(hal_bridge_ops, bridge_add) (name, is_vlan_aware, type, edge, beb, mac, HAL_FWD_SLOT_MASK_ALL);
		return (ret == 0) ? 0 : -1;
	}

	return 0;
}

int hal_bridge_delete (char *name)
{
	int ret;
	if (HAL_OPS_CB_CHECK(hal_bridge_ops, bridge_delete)) {
		ret = HAL_OPS_CB_CALL(hal_bridge_ops, bridge_delete) (name, HAL_FWD_SLOT_MASK_ALL);
		return (ret == 0) ? 0 : -1;
	}
    return 0;
}

int hal_bridge_add_instance (char *name, int instance)
{
    return 0;
}
int hal_bridge_add_port (char *name, unsigned int ifindex)
{
    int ret;
	if (HAL_OPS_CB_CHECK(hal_bridge_ops, bridge_add_port)) {
		ret = HAL_OPS_CB_CALL(hal_bridge_ops, bridge_add_port) (name, ifindex, HAL_FWD_SLOT_MASK_ALL);
		return (ret == 0) ? 0 : -1;
	}

	return 0;
}
int hal_bridge_add_vlan_to_instance (char *name, int instance,
                                 unsigned short vid)
{
    return 0;
}
int hal_bridge_change_vlan_type (char *name, int is_vlan_aware, u_int8_t type)
{
    return 0;
}


int hal_bridge_delete_instance (char *name, int instance)
{
    return 0;
}
int hal_bridge_delete_port (char *name, int ifindex)
{
	int ret;
	if (HAL_OPS_CB_CHECK(hal_bridge_ops, bridge_delete_port)) {
		ret = HAL_OPS_CB_CALL(hal_bridge_ops, bridge_delete_port) (name, ifindex, HAL_FWD_SLOT_MASK_ALL);
		return (ret == 0) ? 0 : -1;
	}
    return 0;
}
int hal_bridge_delete_vlan_from_instance (char *name, int instance,
                                      unsigned short vid)
{
    return 0;
}
int hal_bridge_disable_ageing (char *name)
{
    return 0;
}

int hal_bridge_set_ageing_time (char *name, u_int32_t ageing_time)
{
    return 0;
}
int hal_bridge_set_learn_fwd (const char *const bridge_name, const int ifindex,
                          const int instance, const int learn,
                          const int forward)
{
    return 0;
}
int hal_bridge_set_learning (char *name, int learning)
{
    return 0;
}
int hal_bridge_set_port_state (char *bridge_name,
                           int ifindex, int instance, int state)
{
    return 0;
}
int hal_bridge_set_proto_process_port (const char *const bridge_name,
                                   const int ifindex,
                                   enum hal_l2_proto proto,
                                   enum hal_l2_proto_process process,
                                   u_int16_t vid)
{
    return 0;
}
int hal_bridge_set_state (char *name, u_int16_t enable)
{
    return 0;
}

int hal_l2_get_index_by_mac_vid_svid (char *bridge_name, int *ifindex, char *mac,
                                  u_int16_t vid, u_int16_t svid)
{
    return 0;
}
int hal_l2_qos_set_cos_preserve (const int ifindex,
                             u_int16_t vid, u_int8_t preserve_ce_cos)
{
    return 0;
}
int hal_pbb_dispatch_service_cbp (char *br_name, unsigned int ifindex,
                              unsigned short bvid, unsigned int e_isid,
                              unsigned int l_isid,
                              unsigned char *default_dst_bmac,
                              unsigned char srv_type)
{
    return 0;
}
int hal_pbb_dispatch_service_cnp (char *br_name, unsigned int ifindex,
                              unsigned isid, unsigned short svid_h,
                              unsigned short svid_l, unsigned char srv_type)
{
    return 0;
}
int hal_pbb_dispatch_service_pip (char *br_name, unsigned int ifindex,
                              unsigned isid)
{
    return 0;
}
int hal_pbb_dispatch_service_vip (char *br_name, unsigned int ifindex,
                              unsigned isid, unsigned char *macaddr,
                              unsigned char srv_type)
{
    return 0;
}
int hal_pbb_remove_service (char *br_name, unsigned int ifindex, unsigned isid)
{
    return 0;
}

