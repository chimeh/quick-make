/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HSL_L2_HW_H_
#define _HSL_L2_HW_H_

#include "hsl_vlan.h"
#include "hal_msg.h"

/*
  Layer2 bridging, vlan hardware callbacks.
*/
struct hsl_l2_hw_callbacks
{
  /* Bridge init. */
  int (*bridge_init) (struct hsl_bridge *b);

  /* Bridge deinit. */
  int (*bridge_deinit) (struct hsl_bridge *b);

  /* Set L2 ageing timer. */
  int (*set_age_timer) (struct hsl_bridge *b, int);

  /* Learning set. */
  int (*set_learning) (struct hsl_bridge *b, int);

  int (*set_if_mac_learning) (struct hsl_if *b, int);

  /* Set STP port state. */
  int (*set_stp_port_state) (struct hsl_bridge *b, struct hsl_bridge_port *port, int instance, int state);

  /* Add instance. */
  int (*add_instance) (struct hsl_bridge *b, int instance);

  /* Delete instance. */
  int (*delete_instance) (struct hsl_bridge *b, int instance);

#ifdef HAVE_VLAN
  /* Add VID to instance. */
  int (*add_vlan_to_instance) (struct hsl_bridge *b, int instance, hsl_vid_t vid);

  /* Delete VID from instance. */
  int (*delete_vlan_from_instance) (struct hsl_bridge *b, int instance, hsl_vid_t vid);

  /* Add VLAN. */
  int (*add_vlan) (struct hsl_bridge *b, struct hsl_vlan_port *v);

  /* Delete VLAN. */
  int (*delete_vlan) (struct hsl_bridge *b, struct hsl_vlan_port *v);

  /* Set acceptable frame type. */
  int (*set_vlan_port_type) (struct hsl_bridge *b, struct hsl_bridge_port *port, enum hal_vlan_port_type port_type, enum hal_vlan_acceptable_frame_type acceptable_frame_types, u_int16_t enable_ingress_filter);

  /* Set default PVID. */
  int (*set_default_pvid) (struct hsl_bridge *b, struct hsl_port_vlan *port_vlan, int egress);

  /* Add VID to port. */
  int (*add_vlan_to_port) (struct hsl_bridge *b, struct hsl_port_vlan *port_vlan, hsl_vid_t vid, enum hal_vlan_egress_type type);

  /* Delete VID from port. */
  int (*delete_vlan_from_port) (struct hsl_bridge *b, struct hsl_port_vlan *port_vlan, hsl_vid_t vid);

#ifdef HAVE_PVLAN
  int (*set_pvlan_vlan_type) (struct hsl_bridge *bridge, struct hsl_vlan_port *vlan, enum hal_pvlan_type vlan_type);
  int (*add_pvlan_vlan_association) (struct hsl_bridge *bridge, struct hsl_vlan_port *prim_vlan, struct hsl_vlan_port *second_vlan);  
  int (*del_pvlan_vlan_association) (struct hsl_bridge *bridge, struct hsl_vlan_port *prim_vlan, struct hsl_vlan_port *second_vlan);  
  int (*add_pvlan_port_association) (struct hsl_bridge *bridge, struct hsl_port_vlan *port_vlan, struct hsl_vlan_port *prim_vlan, struct hsl_vlan_port *second_vlan);  
  int (*del_pvlan_port_association) (struct hsl_bridge *bridge, struct hsl_port_vlan *port_vlan, struct hsl_vlan_port *prim_vlan, struct hsl_vlan_port *second_vlan);  
  int (*set_pvlan_port_mode) (struct hsl_bridge *bridge, struct hsl_bridge_port *port, enum hal_pvlan_port_mode port_mode);
#endif /* HAVE_PVLAN */  
#endif /* HAVE_VLAN */

  /* Enable IGMP snooping. */
  int (*enable_igmp_snooping) (struct hsl_bridge *b);

  /* Disable IGMP snooping. */
  int (*disable_igmp_snooping) (struct hsl_bridge *b);
  
  /* Enable IGMP snooping on port. */
  int (*enable_igmp_snooping_port) (struct hsl_bridge *b, struct hsl_if *ifp);

  /* Disable IGMP snooping on port. */
  int (*disable_igmp_snooping_port) (struct hsl_bridge *b, struct hsl_if *ifp);
  
  /* Enable MLD snooping. */
  int (*enable_mld_snooping) (struct hsl_bridge *b);

  /* Disable MLD snooping. */
  int (*disable_mld_snooping) (struct hsl_bridge *b);

  /* Ratelimiting for bcast. */
  int (*ratelimit_bcast) (struct hsl_if *ifp, int level, int fraction);
  
  /* Ratelimiting for mcast. */
  int (*ratelimit_mcast) (struct hsl_if *ifp, int level, int fraction);
  
  /* Ratelimiting for dlf bcast. */
  int (*ratelimit_dlf_bcast) (struct hsl_if *ifp, int level, int fraction);
  
  /* Get bcast discards. */
  int (*ratelimit_bcast_discards_get) (struct hsl_if *ifp,  int *discards);
  
  /* Get mcast discards. */
  int (*ratelimit_mcast_discards_get) (struct hsl_if *ifp,  int *discards);
  
  /* Get dlf bcast discards. */
  int (*ratelimit_dlf_bcast_discards_get) (struct hsl_if *ifp,  int *discards);

  int (*storm_ctl_set) (bool ifindex_or_vlan, unsigned int ifindex, unsigned int vlan, 
					bool enable, unsigned int type, unsigned int mode,unsigned int threshold_num, bool is_discard_to_cpu);
  
  /* Set flowcontrol. */
  int (*set_flowcontrol) (struct hsl_if *ifp, u_char direction);

  /* Get flowcontrol stats. */
  int (*get_flowcontrol_statistics) (struct hsl_if *ifp, u_char *direction,
				     int *rxpause, int *txpause);
  /* Add FDB entry. */
  int (*add_fdb) (struct hsl_bridge *b, struct hsl_if *ifp, u_char *mac, int len, hsl_vid_t vid, u_char flags, int is_forward);

  /* Delete FDB entry. */
  int (*delete_fdb) (struct hsl_bridge *b, struct hsl_if *ifp, u_char *mac, int len, hsl_vid_t vid, u_char flags);

  /* Get unicast FDB entries. */
  int (*get_uni_fdb) (struct hal_msg_l2_fdb_entry_req *req,
                      struct hal_msg_l2_fdb_entry_resp *resp);

  /* Flush FDB for port. */
  int (*flush_port_fdb) (struct hsl_bridge *b, struct hsl_if *ifp, hsl_vid_t vid);

  /* Flush FDB for mac. */
  int (*flush_fdb_by_mac) (struct hsl_bridge *b, u_char *mac, int len, int flag);
#ifdef HAVE_VLAN_CLASS
  /* Add Mac based vlan classifier. */  
  int (*vlan_mac_classifier_add) (u_int16_t vlan_id, u_char *mac, 
                                  u_int32_t ifindex,
                                  u_int32_t refcount);

  /* Add Subnet based vlan classifier. */  
  int (*vlan_ipv4_classifier_add) (u_int16_t vlan_id, u_int32_t addr, 
                                   u_int32_t masklen, u_int32_t ifindex,
                                   u_int32_t refcount);

  /* Add protocol based vlan classifier. */
  int (*vlan_proto_classifier_add)(u_int16_t vlan_id,
                                   u_int16_t ether_type,
                                   u_int32_t encaps,
                                   u_int32_t ifindex,
                                   u_int32_t refcount);

  /* Remove Mac based vlan classifier. */  
  int (*vlan_mac_classifier_delete) (u_int16_t vlan_id, u_char *mac, 
                                     u_int32_t ifindex, u_int32_t refcount);

  /* Remove Subnet based vlan classifier. */  
  int (*vlan_ipv4_classifier_delete) (u_int16_t vlan_id, 
                                      u_int32_t addr, u_int32_t masklen, 
                                     u_int32_t ifindex, u_int32_t refcount);
   
  /* Remove protocol based vlan classifier. */
  int (*vlan_proto_classifier_delete)(u_int16_t vlan_id,
                                      u_int16_t ether_type,
                                      u_int32_t encaps,
                                      u_int32_t ifindex,
                                      u_int32_t refcount);

#endif /* HAVE_VLAN_CLASS */
};
#endif /* _HSL_L2_HW_H_ */
