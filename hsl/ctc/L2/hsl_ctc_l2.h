/* Copyright (C) 2004 IP Infusion, Inc. All Rights Reserved. */

#ifndef _HSL_CTC_L2_H_
#define _HSL_CTC_L2_H_

#define HSL_CTC_STG_MAX_INSTANCES                64

/* Typedefs for setting filters */
#define DEST_MAC_OUI_1             0x00 /* Offset: 802.3 DA[5] */
#define DEST_MAC_OUI_2             0x01 /* Offset: 802.3 DA[4] */
#define DEST_MAC_OUI_3             0x02 /* Offset: 802.3 DA[3] */

/* First three bytes in the DA of a IGMP frame. */
#define IGMP_MAC_OUI_1             0x01 /* DA[5] */
#define IGMP_MAC_OUI_2             0x00 /* DA[4] */
#define IGMP_MAC_OUI_3             0x5e /* DA[3] */

/* Defines for IGMP filter. */
#define IGMP_PROTOCOL              2  /* Protocol type for IGMP. */
#define IP_PROTOCOL_OFFSET         27 /* Where protocol ID is in the IP pkt.*/
#define IGMP_MSG_OFFSET            38 /* Where IGMP msg data is in packet. */

#define ROUTER_ALERT_IGMP_OFFSET   42

/* IGMP message defines. */
#define IGMP_QUERY                 0x11
#define IGMP_V1_REPORT             0x12
#define IGMP_V2_REPORT             0x16
#define IGMP_LEAVE                 0x17
#define IGMP_V3_REPORT             0x22

#ifdef HAVE_MLD_SNOOP
/* First two bytes in the DA of a MLD frame. */
#define MLD_MAC_OUI_1             0x33 /* DA[5] */
#define MLD_MAC_OUI_2             0x33 /* DA[4] */

#define IPV6_PROTOCOL_OFFSET      (18 + sizeof (struct hal_in6_header))/* Where protocol ID is in the IP pkt.*/
#define ICMPV6_PROTOCOL           0x3a
#define MLD_OFFSET                (IPV6_PROTOCOL_OFFSET + 8)
#define MLD_MESSAGE_TYPE_OFFSET   (8)

#define MLD_LISTENER_QUERY        130
#define MLD_LISTENER_REPORT       131
#define MLD_LISTENER_DONE         132
#define MLDV2_LISTENER_REPORT     143
#endif

/* 
   BCM Bridge structure. 
*/
struct hsl_ctc_bridge
{
  int stg[HSL_CTC_STG_MAX_INSTANCES];    //���ڴ��instance״̬
};

/* 
   Function prototypes.
*/
int hsl_ctc_stg_init (void);
int hsl_ctc_bridge_init (struct hsl_bridge *b);
int hsl_ctc_bridge_deinit (struct hsl_bridge *b);
int hsl_ctc_set_age_timer (struct hsl_bridge *b, int age);
int hsl_ctc_set_learning (struct hsl_bridge *b, int learn);
int hsl_ctc_set_if_mac_learning (struct hsl_if *ifp, int disable);
int hsl_ctc_set_stp_port_state (struct hsl_bridge *b, struct hsl_bridge_port *port, int instance, int state);
int hsl_ctc_add_instance (struct hsl_bridge *b, int instance);
int hsl_ctc_delete_instance (struct hsl_bridge *b, int instance);
#ifdef HAVE_VLAN
int hsl_ctc_add_vlan_to_instance (struct hsl_bridge *b, int instance, hsl_vid_t vid);
int hsl_ctc_delete_vlan_from_instance (struct hsl_bridge *b, int instance, hsl_vid_t vid);
int hsl_ctc_add_vlan (struct hsl_bridge *b, struct hsl_vlan_port *v);
int hsl_ctc_delete_vlan (struct hsl_bridge *b, struct hsl_vlan_port *v);
int hsl_ctc_set_vlan_port_type (struct hsl_bridge *b, struct hsl_bridge_port *port, enum hal_vlan_port_type port_type, enum hal_vlan_acceptable_frame_type acceptable_frame_types, u_int16_t enable_ingress_filter);
int hsl_ctc_set_default_pvid (struct hsl_bridge *b, struct hsl_port_vlan *port_vlan, int egress);
int hsl_ctc_add_vlan_to_port (struct hsl_bridge *b, struct hsl_port_vlan *port_vlan, hsl_vid_t vid, enum hal_vlan_egress_type egress);
int hsl_ctc_delete_vlan_from_port (struct hsl_bridge *b, struct hsl_port_vlan *port_vlan, hsl_vid_t vid);
#endif /* HAVE_VLAN */  

int hsl_ctc_init_igmp_snooping (void);
int hsl_ctc_deinit_igmp_snooping (void);
int hsl_ctc_enable_igmp_snooping (struct hsl_bridge *b);
int hsl_ctc_disable_igmp_snooping (struct hsl_bridge *b);
int hsl_ctc_enable_igmp_snooping_port (struct hsl_bridge *b, struct hsl_if *ifp);
int hsl_ctc_disable_igmp_snooping_port (struct hsl_bridge *b, struct hsl_if *ifp);
int hsl_ctc_igmp_snooping_set (int enable_flag);

int hsl_ctc_init_mld_snooping (void);
int hsl_ctc_deinit_mld_snooping (void);
int hsl_ctc_enable_mld_snooping (struct hsl_bridge *b);
int hsl_ctc_disable_mld_snooping (struct hsl_bridge *b);

int hsl_ctc_ratelimit_init (void);
int hsl_ctc_ratelimit_deinit (void);
int hsl_ctc_ratelimit_bcast (struct hsl_if *ifp, int level, int fraction);
int hsl_ctc_ratelimit_get_bcast_discards (struct hsl_if *, int *discards);
int hsl_ctc_ratelimit_mcast (struct hsl_if *ifp, int level, int fraction);
int hsl_ctc_ratelimit_get_mcast_discards (struct hsl_if *ifp, int *discards);
int hsl_ctc_ratelimit_dlf_bcast (struct hsl_if *ifp, int level, int fraction);
int hsl_ctc_ratelimit_get_dlf_bcast_discards (struct hsl_if *ifp, 
                                              int *discards);
int hsl_ctc_flowcontrol_init (void);
int hsl_ctc_flowcontrol_deinit (void);
int hsl_ctc_set_flowcontrol (struct hsl_if *ifp, u_char direction);
int hsl_ctc_flowcontrol_statistics (struct hsl_if *ifp, u_char *direction, int *rxpause, int *txpause);
int hsl_ctc_fdb_init (void);
int hsl_ctc_fdb_deinit (void);
int hsl_ctc_add_fdb (struct hsl_bridge *b, struct hsl_if *ifp, u_char *mac, int len, hsl_vid_t vid, u_char flags, int is_forward);
int hsl_ctc_delete_fdb (struct hsl_bridge *b, struct hsl_if *ifp, u_char *mac, int len, hsl_vid_t vid, u_char flags);
int hsl_ctc_unicast_get_fdb (struct hal_msg_l2_fdb_entry_req *req,
                             struct hal_msg_l2_fdb_entry_resp *resp);

int hsl_storm_ctl_set(bool ifindex_or_vlan, unsigned int ifindex, unsigned int vlan, 
					bool enable, unsigned int type, unsigned int mode,unsigned int threshold_num, bool is_discard_to_cpu);

#ifdef HAVE_VLAN_STACK
int hsl_ctc_vlan_stacking_enable (u_int32_t ifindex, u_int16_t tpid, int mode);
int hsl_ctc_vlan_stacking_disable (u_int32_t ifindex);
int hsl_ctc_vlan_stacking_ether_set (u_int32_t ifindex, u_int16_t tpid);
#endif /* HAVE_VLAN_STACK */

#endif /* _HSL_CTC_L2_H_ */
